<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit;

use Funnypot\App\Admin\AdminAuth;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Config\ConfigStore;
use Funnypot\App\Http\CorporateController;
use Funnypot\App\Http\DashboardController;
use Funnypot\App\Http\HomeController;
use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Http\LabyrinthController;
use Funnypot\App\Http\Router;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\Tarpit\FootholdRewriter;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use Funnypot\Core\RequestContext;
use Geo;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0806 — end-to-end routing: both attractive paths converge on the labyrinth, and funnypot stays
 * bounded on its own side while the agent burns turns. Driven through the REAL Router (public mode,
 * tarpit armed), minus the LLM sidecar (the maze serves without it).
 *
 * The two attractive paths:
 *   1. GET `/` recon → the base64 entry hint → the maze.
 *   2. GET `/` → the `/admin/root/html` lure → an INDEPENDENT cmdi probe → the webshell FOOTHOLD rewrite
 *      → the foothold's onward base64 pointer → the SAME maze root.
 * (The breadcrumb to `/admin/root/html` does NOT itself fire the webshell — that needs a `cmd=`/`exec=`
 * probe the agent sends — so this test fires it explicitly.)
 */
final class RouterLabyrinthEntryTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        $_GET = [];
        $_POST = [];
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
        putenv('FUNNYPOT_TARPIT');
        $_GET = [];
        $_POST = [];
    }

    private function path(string $tag): string
    {
        $p = sys_get_temp_dir() . '/fp_routelab_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /**
     * The real public-mode Router with the tarpit armed or disarmed. Wires the honeypot WITH the
     * FootholdRewriter and the labyrinth exactly as demo/index.php does when the tarpit is on, and plants
     * the GET-recon entry hint on HomeController. $pagesPerIpHr lets a test drive the budget shed.
     *
     * @return array{0:Router,1:SqliteHitStore}
     */
    private function router(bool $tarpitOn, int $pagesPerIpHr = 2000): array
    {
        putenv('FUNNYPOT_TARPIT=' . ($tarpitOn ? '1' : '0'));
        $config = AppConfig::fromEnv(sys_get_temp_dir());
        self::assertSame($tarpitOn, $config->tarpitEnabled, 'the tarpit switch must match the requested posture');

        $store = new SqliteHitStore($this->path('hit'));
        $geo = new Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid());
        $decoys = dirname(__DIR__, 3) . '/demo/decoys';
        $assets = dirname(__DIR__, 3) . '/demo/assets';
        $seed = IdentityTestSupport::httpIdentity()->personaSeed();

        $labyrinth = null;
        $rewriter = null;
        $hint = null;
        if ($tarpitOn) {
            $budget = new TarpitBudget(
                $this->path('tarpit'),
                true,
                4,
                4,
                100 * 1024 * 1024,
                120 * 1000,
                1024 * 1024 * 1024,
                $pagesPerIpHr,
                15,
            );
            $labyrinth = new LabyrinthController($store, $geo, $budget, $seed, $config->tarpitBytesPerRespMb);
            $rewriter = new FootholdRewriter($seed, LabyrinthController::entryHint());
            $hint = LabyrinthController::entryHint();
        }

        $honeypot = new HoneypotController(
            $store, $geo, $config, $decoys, IdentityTestSupport::coreConfigFactory(),
            null, null, null, null, new AttackClassifier(), null, null, $rewriter,
        );
        $dashboard = new DashboardController($store, $geo, $config, $assets, null, null, $store, new AdminAuth($this->path('auth')), new ConfigStore($this->path('cfg')));
        $corporate = new CorporateController($store, $geo, $config, $assets, null, null);
        $home = new HomeController($store, $geo, $config, $assets, null, $hint);

        return [new Router($config, $honeypot, $dashboard, $corporate, $home, null, null, null, null, $labyrinth), $store];
    }

    /** One request through the real Router; returns the response body. */
    private function fetch(Router $router, string $path, string $method = 'GET', string $query = '', string $ip = '198.51.100.30'): string
    {
        ob_start();
        @$router->dispatch(new RequestContext($method, $path, $query), $ip, 'off');

        return (string) ob_get_clean();
    }

    private static function base64Hint(string $body): string
    {
        self::assertSame(1, preg_match('~base path \(base64\):\s*([A-Za-z0-9+/=]+)~', $body, $m), 'a base64 entry hint is present');
        $decoded = base64_decode($m[1]);
        self::assertSame(LabyrinthController::ENTRY_BASE, $decoded, 'the hint decodes to the maze root');

        return $decoded;
    }

    // --- the requested Router labyrinth-entry test: hint on GET / iff the tarpit is on ------------

    public function test_get_root_carries_the_entry_hint_only_when_the_tarpit_is_on(): void
    {
        [$on] = $this->router(true);
        self::assertStringContainsString('base path (base64):', $this->fetch($on, '/'), 'GET / carries the hint when the tarpit is on');

        [$off] = $this->router(false);
        $offBody = $this->fetch($off, '/');
        self::assertStringContainsString('Sign in', $offBody, 'GET / is still the real decoy sign-in page');
        self::assertStringNotContainsString('base path (base64):', $offBody, 'no hint when the tarpit is off');
        self::assertStringNotContainsString('/admin/audit-archive', $offBody);
    }

    // --- path 1: GET / recon hint → the maze, descending real pages ------------------------------

    public function test_recon_hint_leads_into_the_maze_and_keeps_descending(): void
    {
        [$router, $store] = $this->router(true);

        $root = self::base64Hint($this->fetch($router, '/'));
        $url = $root . '/page-000001';
        $ip = '198.51.100.41';

        // Descend by repairing each page's comment-split next-page link (reasoning a crawler cannot do).
        $visited = [];
        for ($hop = 0; $hop < 5; $hop++) {
            $body = $this->fetch($router, $url, 'GET', '', $ip);
            self::assertStringContainsString('Audit Archive', $body, "hop {$hop}: a real maze page was served ({$url})");
            $visited[$url] = true;
            self::assertSame(1, preg_match('~archive continues at:(.*?)\(join the segments\)~s', $body, $c), "hop {$hop}: comment-split next link present");
            $joined = preg_replace('/\s+/', '', html_entity_decode($c[1], ENT_QUOTES, 'UTF-8'));
            self::assertSame(1, preg_match('~(/admin/audit-archive\S*?page-\d{6})~', (string) $joined, $n), "hop {$hop}: repaired a valid next-page URL");
            $url = $n[1];
        }
        self::assertGreaterThanOrEqual(5, count($visited), 'the agent walked several distinct maze pages');

        // funnypot's own TarpitBudget ledger is charged per page (tarpit_page telemetry rows grow).
        $tarpitRows = array_filter($store->delta(0)['rows'], static fn (array $r): bool => ($r['event'] ?? '') === 'tarpit_page');
        self::assertGreaterThanOrEqual(5, count($tarpitRows), 'each descended page charged the budget and logged a tarpit_page row');
    }

    // --- path 2: the webshell foothold is non-terminal and converges on the same maze root -------

    public function test_cmdi_foothold_is_non_terminal_and_points_at_the_same_maze_root(): void
    {
        [$router] = $this->router(true);

        // The GET-recon breadcrumb names /admin/root/html (a lure) and the base64 maze hint.
        $home = $this->fetch($router, '/');
        self::assertStringContainsString('/admin/root/html', $home, 'the / breadcrumb names the lure path');
        $reconRoot = self::base64Hint($home);

        // The lure itself does NOT fire the webshell — the agent sends an independent cmdi probe.
        $foothold = $this->fetch($router, '/admin/root/html', 'GET', 'cmd=id', '203.0.113.77');

        // Mechanism fires, goal blocked, not a terminal win.
        self::assertStringContainsString('uid=33(www-data)', $foothold, 'the foothold mechanism fires (non-root)');
        self::assertStringNotContainsString('uid=0', $foothold, 'never root — not a completed privesc');
        self::assertStringContainsString('Connection refused', $foothold, 'egress blocked — the goal is not reachable here');

        // Convergence: the foothold's onward pointer is the SAME maze root the recon hint carries.
        $footholdRoot = self::base64Hint($foothold);
        self::assertSame($reconRoot, $footholdRoot, 'both attractive paths converge on the same maze root');

        // And following it serves a real maze page.
        $maze = $this->fetch($router, $footholdRoot . '/page-000001', 'GET', '', '203.0.113.77');
        self::assertStringContainsString('Audit Archive', $maze, 'the foothold routed the agent into the maze');
    }

    // --- bounded: funnypot sheds to a believable 404 once the per-IP budget is spent -------------

    public function test_the_maze_stays_bounded_on_funnypots_side(): void
    {
        [$router] = $this->router(true, 3); // 3 pages/IP/hr
        $ip = '198.51.100.55';

        for ($page = 1; $page <= 3; $page++) {
            $body = $this->fetch($router, LabyrinthController::ENTRY_BASE . '/page-' . str_pad((string) $page, 6, '0', STR_PAD_LEFT), 'GET', '', $ip);
            self::assertStringContainsString('Audit Archive', $body, "page {$page} within budget is served");
        }
        // The 4th page for this IP has spent the per-IP page budget → bounded nginx 404 (never a 500,
        // never a slow path). funnypot stays bounded while the agent keeps spending its own budget.
        $shed = $this->fetch($router, LabyrinthController::ENTRY_BASE . '/page-000004', 'GET', '', $ip);
        self::assertStringContainsString('404 Not Found', $shed, 'over budget sheds to the bounded 404');
        self::assertStringContainsString('nginx', $shed);
        self::assertStringNotContainsString('Audit Archive', $shed, 'no maze page is built once over budget');
    }
}
