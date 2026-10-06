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
use Funnypot\App\Http\PolluterController;
use Funnypot\App\Http\Router;
use Funnypot\App\Llm\LlmClient;
use Funnypot\App\Llm\LlmFakeResponder;
use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\App\Llm\LlmResponseProfiles;
use Funnypot\App\Llm\ProbeClassifier;
use Funnypot\App\Llm\ProbeGate;
use Funnypot\App\Llm\VelocityTracker;
use Funnypot\App\Render\PageShellRenderer;
use Funnypot\App\Render\SkinSet;
use Funnypot\App\Render\Skins\AdminLteSkin;
use Funnypot\App\Render\Skins\GrafanaSkin;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\Chrome\GenericSkin;
use Funnypot\Core\Support\Chrome\PhpMyAdminSkin;
use Funnypot\Core\Support\Chrome\WordpressSkin;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php'; // global \Geo (not autoloaded)

/**
 * FP-0049 (code-review REJECT fix): the bare-IP admin-panel landing must be reached THROUGH the Router.
 * `GET /` is short-circuited to home/corporate before the honeypot catch-all, so this drives
 * `Router::dispatch()` (not `handle()` directly) to prove a bare-IP `/` reaches the panel while a named
 * host still gets the home/corporate decoy — the gap the controller-only tests missed.
 */
final class RouterBareIpPanelTest extends TestCase
{
    private const PEER = '9.9.9.9';
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/fp-rbip-' . uniqid();
        @mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        putenv('FUNNYPOT_MODE');
    }

    private function p(string $n): string
    {
        return $this->dir . '/' . $n;
    }

    private function router(string $mode, SqliteHitStore $store): Router
    {
        putenv('FUNNYPOT_MODE=' . $mode);
        $config = AppConfig::fromEnv($this->p('base'));
        $geo = new \Geo($this->p('geo') . '.csv');
        $decoys = dirname(__DIR__, 3) . '/demo/decoys';
        $assets = dirname(__DIR__, 3) . '/demo/assets';

        $skins = new SkinSet(
            [new WordpressSkin(), new PhpMyAdminSkin(), new GrafanaSkin(), new AdminLteSkin()],
            new GenericSkin()
        );
        $llmFakes = new LlmFakeResponder(
            new ProbeGate(new ProbeClassifier(), new VelocityTracker(), $store),
            new LlmFakeCache($this->p('cache') . '.sqlite'),
            new LlmClient('http://sidecar/completion', 1500, 320, null, fn (): array => ['status' => 200, 'body' => '{}']),
            new LlmOutputSanitizer(),
            $store,
            new LlmResponseProfiles('nginx', 'root ::= "<"', 'root ::= "{"', new PageShellRenderer($skins), 'root ::= "{"'),
            'v1',
            4,
            7,
            'a1',
        );

        $honeypot = new HoneypotController(
            $store, $geo, $config, $decoys, IdentityTestSupport::coreConfigFactory(),
            null, null, null, $llmFakes, new AttackClassifier(),
        );
        $dashboard = new DashboardController($store, $geo, $config, $assets, null, null, $store, new AdminAuth($this->p('auth')), new ConfigStore($this->p('cfg')));
        $corporate = new CorporateController($store, $geo, $config, $assets, null, null);
        $home = new HomeController($store, $geo, $config, $assets, null, null);
        $budget = new TarpitBudget($this->p('tarpit'), true, 4, 1, 64 * 1024 * 1024, 120 * 1000, 1024 * 1024 * 1024, 2000, 15, static fn (): int => 1_000_000);
        $polluter = new PolluterController($store, $geo, $budget, 4242, 8);

        return new Router($config, $honeypot, $dashboard, $corporate, $home, null, null, null, null, null, $polluter, null);
    }

    /** @return array<int,array<string,mixed>> */
    private function panelRowsAtRoot(SqliteHitStore $store): array
    {
        return array_values(array_filter(
            $store->delta(0)['rows'],
            static fn (array $r): bool => ($r['path'] ?? '') === '/' && ($r['event'] ?? '') === 'panel'
        ));
    }

    private function dispatch(Router $router, RequestContext $ctx): void
    {
        ob_start();
        @$router->dispatch($ctx, self::PEER, 'off');
        ob_get_clean();
    }

    public function test_public_bare_ip_root_lands_in_panel(): void
    {
        $store = new SqliteHitStore($this->p('hit') . '.sqlite');
        $router = $this->router('public', $store);
        $this->dispatch($router, new RequestContext('GET', '/')); // host '' = bare
        $panel = $this->panelRowsAtRoot($store);
        self::assertCount(1, $panel, 'public: a bare-IP GET / must reach the panel via the Router');
    }

    public function test_public_named_host_root_is_home_not_panel(): void
    {
        $store = new SqliteHitStore($this->p('hit') . '.sqlite');
        $router = $this->router('public', $store);
        $this->dispatch($router, new RequestContext(method: 'GET', path: '/', host: 'admin.metrictower.com'));
        self::assertSame([], $this->panelRowsAtRoot($store), 'public: a named-host GET / stays on the home decoy, not the panel');
    }

    public function test_stealth_bare_ip_root_lands_in_panel(): void
    {
        $store = new SqliteHitStore($this->p('hit') . '.sqlite');
        $router = $this->router('stealth', $store);
        $this->dispatch($router, new RequestContext('GET', '/')); // bare
        self::assertCount(1, $this->panelRowsAtRoot($store), 'stealth: a bare-IP GET / must reach the panel via the Router');
    }

    public function test_stealth_named_host_root_is_corporate_not_panel(): void
    {
        $store = new SqliteHitStore($this->p('hit') . '.sqlite');
        $router = $this->router('stealth', $store);
        $this->dispatch($router, new RequestContext(method: 'GET', path: '/', host: 'admin.metrictower.com'));
        self::assertSame([], $this->panelRowsAtRoot($store), 'stealth: a named-host GET / stays on the corporate disguise, not the panel');
    }
}
