<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Admin\AdminAuth;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Config\ConfigStore;
use Funnypot\App\Http\CorporateController;
use Funnypot\App\Http\DashboardController;
use Funnypot\App\Http\HomeController;
use Funnypot\App\Http\HoneypotController;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use Funnypot\App\Http\Router;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0242b — the load-bearing security property (spec §7.6, plan T-ISO-1): the admin panel and EVERY
 * mutating admin endpoint appear ONLY on the hidden dashboard path, never the scanner-swept decoy
 * surface. A `?admin=` on any non-dashboard path must fall to the honeypot, never reach
 * DashboardController::admin()/loginForm() and never write a config row.
 *
 * DashboardController/HoneypotController are final (unmockable), so we prove isolation by real
 * dispatch + observable side effects: on a decoy path the config store stays empty AND the honeypot
 * logs the probe AND no login attempt is recorded; on the dashboard path the SAME query DOES reach the
 * admin surface (the positive control). A static assertion on the Router source (the spec's grep) pins
 * that the honeypot catch-all branches contain no admin dispatch.
 */
final class AdminSurfaceIsolationTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        putenv('FUNNYPOT_MODE=stealth');   // dashboard at the hidden /__fp/
        putenv('FUNNYPOT_STYLE');
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $suf) {
                @unlink($f . $suf);
            }
            @unlink(dirname($f) . '/config.gen');
        }
        $this->tmp = [];
        putenv('FUNNYPOT_MODE');
        putenv('FUNNYPOT_STYLE');
        unset($_GET, $_POST, $_COOKIE[AdminAuth::COOKIE]);
        $_GET = [];
        $_POST = [];
    }

    private function path(string $tag): string
    {
        $p = sys_get_temp_dir() . '/fp_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /** @return array{0:Router,1:ConfigStore,2:AdminAuth,3:SqliteHitStore} */
    private function wiring(): array
    {
        $config = AppConfig::fromEnv(sys_get_temp_dir());
        self::assertSame('stealth', $config->mode);
        $store = new SqliteHitStore($this->path('hit'));
        $geo = new \Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid());
        $decoys = dirname(__DIR__, 3) . '/demo/decoys';
        $assets = dirname(__DIR__, 3) . '/demo/assets';
        $cfg = new ConfigStore($this->path('cfg'));
        $auth = new AdminAuth($this->path('auth'));
        $auth->createOrResetUser('admin', 'operator-secret-pw');

        $honeypot = new HoneypotController($store, $geo, $config, $decoys, IdentityTestSupport::coreConfigFactory());
        $dashboard = new DashboardController($store, $geo, $config, $assets, null, null, $store, $auth, $cfg);
        $corporate = new CorporateController($store, $geo, $config, $assets);
        $home = new HomeController($store, $geo, $config, $assets);
        $router = new Router($config, $honeypot, $dashboard, $corporate, $home);

        return [$router, $cfg, $auth, $store];
    }

    private function dispatch(Router $router, string $method, string $path): void
    {
        ob_start();
        @$router->dispatch(new RequestContext($method, $path), '198.51.100.7', 'off');
        ob_end_clean();
    }

    /**
     * The core T-ISO-1: a decoy-path POST carrying ?admin=config-set + a full POST body is handled by
     * the honeypot, never the admin surface — no config row is written.
     */
    public function test_decoy_path_admin_config_set_never_writes_and_hits_the_honeypot(): void
    {
        foreach (['/.git/config', '/wp-login.php', '/vendor/autoload.php', '/actuator/env'] as $decoy) {
            [$router, $cfg, $auth, $store] = $this->wiring();
            $_GET = ['admin' => 'config-set'];
            $_POST = ['key' => 'style', 'value' => 'taunt', 'csrf' => 'anything'];

            $this->dispatch($router, 'POST', $decoy);

            self::assertSame([], $cfg->stored(), "decoy path {$decoy}: no config override may be written");
            self::assertSame('realistic', $cfg->get('style', 'FUNNYPOT_STYLE', 'realistic'), "decoy path {$decoy}: style unchanged");
            self::assertSame([], $cfg->audits(5), "decoy path {$decoy}: no config audit row");
            self::assertNotEmpty($store->delta(0)['rows'], "decoy path {$decoy}: the honeypot must have logged the probe");
        }
    }

    /**
     * The new GET ?admin=login knock (Router #5) must ALSO be off the decoy surface: a decoy-path
     * ?admin=login must not reach AdminAuth::login (no login_attempts row) or mint a session — it is
     * the one un-authenticated, state-mutating admin path (reviewer SHOULD-FIX #1).
     */
    public function test_decoy_path_admin_login_never_reaches_the_auth(): void
    {
        foreach (['GET', 'POST'] as $method) {
            [$router, $cfg, $auth, $store] = $this->wiring();
            $_GET = ['admin' => 'login'];
            $_POST = $method === 'POST' ? ['user' => 'admin', 'pass' => 'operator-secret-pw'] : [];

            $this->dispatch($router, $method, '/.git/config');

            self::assertSame([], $auth->attempts(10), "{$method} decoy ?admin=login must record no auth attempt");
            self::assertNotEmpty($store->delta(0)['rows'], "{$method} decoy ?admin=login must hit the honeypot");
        }
    }

    /**
     * Positive control: the SAME ?admin=config-set POST ON the dashboard path DOES reach admin() — it
     * is denied (no session) rather than falling to the honeypot. Proves the isolation is the path
     * guard, not an accident, and that the boundary is exactly at the dashboard path.
     */
    public function test_dashboard_path_reaches_the_admin_surface(): void
    {
        [$router, $cfg, $auth, $store] = $this->wiring();
        $_GET = ['admin' => 'config-set'];
        $_POST = ['key' => 'style', 'value' => 'taunt'];

        ob_start();
        @$router->dispatch(new RequestContext('POST', '/__fp/'), '198.51.100.7', 'off');
        $body = (string) ob_get_clean();

        $json = json_decode($body, true);
        self::assertSame('forbidden', $json['error'] ?? null, 'admin() ran (and denied the unauth write)');
        self::assertSame([], $cfg->stored(), 'still no write — the gate is fail-closed');
        self::assertSame([], $store->delta(0)['rows'], 'the honeypot did NOT handle a dashboard-path request');

        // And the login-form knock is reachable on the dashboard path.
        $_GET = ['admin' => 'login'];
        $_POST = [];
        ob_start();
        @$router->dispatch(new RequestContext('GET', '/__fp/'), '198.51.100.7', 'off');
        $form = (string) ob_get_clean();
        self::assertStringContainsString('id=lf', $form, 'the dashboard path serves the login form');
    }

    /**
     * The spec's static grep: the Router honeypot catch-all branches call no admin surface. `->admin(`
     * and `->loginForm(` each appear exactly twice (the two guarded dashboard-path dispatches), and no
     * line that dispatches to the honeypot catch-all also names an admin call. A regression that wired a
     * `?admin=` handler onto the decoy surface would change these counts / placement.
     */
    public function test_router_source_has_no_admin_dispatch_on_the_catch_all(): void
    {
        $src = (string) file_get_contents(dirname(__DIR__, 3) . '/src/App/Http/Router.php');

        self::assertSame(2, substr_count($src, '->admin('), 'exactly the two guarded dashboard-path admin() dispatches');
        self::assertSame(2, substr_count($src, '->loginForm('), 'exactly the two guarded dashboard-path loginForm() dispatches');

        foreach (explode("\n", $src) as $line) {
            if (strpos($line, 'honeypot->handle') !== false) {
                self::assertStringNotContainsString('admin', $line, 'a honeypot catch-all line must not name an admin dispatch');
                self::assertStringNotContainsString('loginForm', $line);
            }
        }
    }
}
