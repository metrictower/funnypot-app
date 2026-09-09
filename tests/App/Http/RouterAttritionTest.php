<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Admin\AdminAuth;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Config\ConfigStore;
use Funnypot\App\Http\AttritionController;
use Funnypot\App\Http\CorporateController;
use Funnypot\App\Http\DashboardController;
use Funnypot\App\Http\HomeController;
use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Http\PolluterController;
use Funnypot\App\Http\Router;
use Funnypot\App\Storage\SqliteAttritionStore;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\Tarpit\Attrition\AttritionArtifactRenderer;
use Funnypot\App\Tarpit\Attrition\AttritionLimits;
use Funnypot\App\Tarpit\Attrition\AttritionTokenCodec;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use Funnypot\Core\RequestContext;
use Geo;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0272 §6.1 — Router wiring: both tables reserve all three prefixes when the controller is present
 * (method-agnostic), the reserved paths fall through unchanged when it is null, and the pre-existing
 * polluter export paths are never claimed by attrition.
 */
final class RouterAttritionTest extends TestCase
{
    private const NOW = 1757000000;
    private const KEY = 'router-attrition-test-key-0000000';
    private const PEER = '203.0.113.11';

    /** @var string[] */
    private array $tmp = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
        putenv('FUNNYPOT_MODE');
    }

    private function path(string $tag): string
    {
        $p = sys_get_temp_dir() . '/fp_rattr_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    private function codec(): AttritionTokenCodec
    {
        return new AttritionTokenCodec(substr(hash('sha256', self::KEY, true), 0, 32));
    }

    private function router(string $mode, bool $withAttrition): Router
    {
        putenv('FUNNYPOT_MODE=' . $mode);
        $config = AppConfig::fromEnv(sys_get_temp_dir());
        $store = new SqliteHitStore($this->path('hit'));
        $geo = new Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid());
        $decoys = dirname(__DIR__, 3) . '/demo/decoys';
        $assets = dirname(__DIR__, 3) . '/demo/assets';

        $honeypot = new HoneypotController($store, $geo, $config, $decoys, IdentityTestSupport::coreConfigFactory());
        $dashboard = new DashboardController($store, $geo, $config, $assets, null, null, $store, new AdminAuth($this->path('auth')), new ConfigStore($this->path('cfg')));
        $corporate = new CorporateController($store, $geo, $config, $assets, null, null);
        $home = new HomeController($store, $geo, $config, $assets, null, null);

        $budget = new TarpitBudget($this->path('tarpit'), true, 4, 1, 64 * 1024 * 1024, 120 * 1000, 1024 * 1024 * 1024, 2000, 15, static fn (): int => self::NOW);
        $polluter = new PolluterController($store, $geo, $budget, 4242, 8);
        $attrition = null;
        if ($withAttrition) {
            $attritionStore = new SqliteAttritionStore($this->path('attr'), new AttritionLimits(21600, 32, 64, 50000, 64), static fn (): int => self::NOW);
            $attrition = new AttritionController($attritionStore, $this->codec(), new AttritionArtifactRenderer(), $budget, 4242, null, null, static fn (): int => self::NOW);
        }

        return new Router($config, $honeypot, $dashboard, $corporate, $home, null, null, null, null, null, $polluter, $attrition);
    }

    /** @return array{status:int,body:string} */
    private function fetch(Router $router, string $method, string $path): array
    {
        ob_start();
        @$router->dispatch(new RequestContext($method, $path), self::PEER, 'off');
        $body = (string) ob_get_clean();

        return ['status' => http_response_code() ?: 200, 'body' => $body];
    }

    private function entryToken(): string
    {
        return $this->codec()->issueEntry('/admin/audit-archive/page-000002', self::PEER, self::NOW, 21600);
    }

    public function test_matches_claims_only_the_three_prefixes(): void
    {
        $store = new SqliteAttritionStore($this->path('m'), new AttritionLimits(21600, 32, 64, 50000, 64));
        $budget = new TarpitBudget($this->path('b'), true);
        $c = new AttritionController($store, $this->codec(), new AttritionArtifactRenderer(), $budget, 4242);
        self::assertTrue($c->matches('/admin/export/jobs/x'));
        self::assertTrue($c->matches('/admin/export/manifests/x'));
        self::assertTrue($c->matches('/admin/export/artifacts/x'));
        self::assertTrue($c->matches('/admin/export/jobs/x?q=1'));
        // The pre-existing polluter export files and unrelated paths are NOT claimed.
        foreach ([PolluterController::CONFIG_PATH, PolluterController::LOG_PATH, PolluterController::HOSTILE_PATH, PolluterController::SHADOW_PATH, '/admin/export/jobs', '/admin/export/', '/admin/audit-archive/page-000002', '/'] as $p) {
            self::assertFalse($c->matches($p), "{$p} must not be claimed by attrition");
        }
    }

    public function test_both_modes_route_a_valid_create_to_attrition(): void
    {
        foreach (['public', 'stealth'] as $mode) {
            $r = $this->router($mode, true);
            $res = $this->fetch($r, 'POST', AttritionController::JOBS_PREFIX . $this->entryToken());
            $doc = json_decode(rtrim($res['body'], "\n"), true);
            self::assertIsArray($doc, "{$mode}: attrition returned JSON");
            self::assertSame('audit-export-job/v1', $doc['schema'] ?? null, "{$mode}: routed to attrition");
        }
    }

    public function test_when_absent_the_reserved_paths_fall_through(): void
    {
        foreach (['public', 'stealth'] as $mode) {
            $r = $this->router($mode, false);
            $res = $this->fetch($r, 'POST', AttritionController::JOBS_PREFIX . $this->entryToken());
            $doc = json_decode(rtrim($res['body'], "\n"), true);
            self::assertNotSame('audit-export-job/v1', is_array($doc) ? ($doc['schema'] ?? null) : null, "{$mode}: no attrition response when the controller is null");
        }
    }

    public function test_wrong_method_on_an_owned_path_is_claimed_by_attrition(): void
    {
        $r = $this->router('public', true);
        // A PUT to an owned path is method-agnostically claimed and returns the ordinary 404 (not a JSON body).
        $res = $this->fetch($r, 'PUT', AttritionController::JOBS_PREFIX . $this->entryToken());
        self::assertStringContainsString('404 Not Found', $res['body']);
        self::assertStringNotContainsString('audit-export-job/v1', $res['body']);
    }
}
