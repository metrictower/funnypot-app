<?php
declare(strict_types=1);
namespace Funnypot\Tests\App;
use Funnypot\App\Render\Skins\AdminLteSkin;
use Funnypot\Support\Chrome\PageSlots;
use Funnypot\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class AdminLteSkinTest extends TestCase
{
    public function test_matches_admin_paths(): void
    {
        $s = new AdminLteSkin();
        self::assertTrue($s->matches('/admin/index.php'));
        self::assertTrue($s->matches('/dashboard'));
        self::assertTrue($s->matches('/manage/users'));
        self::assertTrue($s->matches('/panel/logs'));      // panel subtree stays in one skin
        self::assertTrue($s->matches('/console/'));
        self::assertFalse($s->matches('/hr/portal'));
    }

    public function test_debug_mode_banner_explains_public_exposure(): void
    {
        // A dev/debug pretext banner on every page makes the panel's public reachability read as a
        // misconfiguration ("bound to 0.0.0.0, auth off"), not a trap. Framework-agnostic (a named
        // framework's debug bar would be its own fingerprint), inert, deterministic per seed.
        $s = new AdminLteSkin();
        $a = $s->render(PageSlots::fromArray([]), VisualPersona::fromSeed(7), '/admin/bank', '/admin/bank');
        $b = $s->render(PageSlots::fromArray([]), VisualPersona::fromSeed(7), '/admin/bank', '/admin/bank');
        self::assertSame($a, $b, 'banner must be byte-identical per seed');
        self::assertStringContainsString('DEBUG MODE ENABLED', $a);
        self::assertMatchesRegularExpression('/0\.0\.0\.0:\d+/', $a);
        self::assertStringContainsString('alte-debug-banner', $a);
        self::assertDoesNotMatchRegularExpression('/laravel|django|werkzeug|symfony|flask/i', $a);
    }

    public function test_dashboard_is_business_metrics_only_no_secrets(): void
    {
        // T1: the loudest tell — a password_hash column on the landing — must be gone. The dashboard is
        // now business/ops metrics (stat tiles + a benign recent-sign-ins table), no secrets.
        $s = new AdminLteSkin();
        $slots = PageSlots::fromArray(['app_name' => 'OneControl']);
        $a = $s->render($slots, VisualPersona::fromSeed(77), '/panel/dashboard', '/panel/dashboard');
        $b = $s->render($slots, VisualPersona::fromSeed(77), '/panel/dashboard', '/panel/dashboard');
        self::assertSame($a, $b, 'enrichment must be byte-identical per seed (cache-safe)');
        self::assertStringContainsString('fp-tiles', $a);                   // business stat tiles
        self::assertStringContainsString('Recent sign-ins', $a);            // benign activity summary
        self::assertStringContainsString('Employees', $a);
        self::assertStringNotContainsString('password_hash', $a);           // the tell is gone (T1)
    }

    public function test_backup_links_preserve_archive_ext_and_stay_in_panel(): void
    {
        $html = (new AdminLteSkin())->render(
            PageSlots::fromArray([]),
            VisualPersona::fromSeed(9), '/panel/backups', '/panel/backups'
        );
        // A backup link under the panel prefix, keeping its archive extension so it routes to the
        // decoy-archive handler (the download rabbit-hole).
        self::assertSame(1, preg_match('#href="(/panel/backups/[A-Za-z0-9._-]+\.(?:tar\.gz|sql\.gz|zip))"#', $html));
        self::assertStringNotContainsString('javascript:', $html);
    }

    public function test_users_loot_is_one_drilldown_deep_with_persona_domain(): void
    {
        // The password_hash loot still exists as bait — but one drill-down deep (the users table Browse),
        // never the landing. Emails use the persona domain so the loot stays coherent with the host.
        $persona = VisualPersona::fromSeed(123);
        $html = (new AdminLteSkin())->render(
            PageSlots::fromArray([]), $persona, '/panel/users', '/panel/users'
        );
        self::assertStringContainsString('password_hash', $html);
        self::assertStringContainsString('@' . $persona->domain(), $html);
        self::assertMatchesRegularExpression('/of [\d,]+ rows/', $html);   // bottomless loot count
    }

    public function test_databases_landing_lists_tables_without_secrets(): void
    {
        // The Databases landing is a schema catalogue — no password_hash. Drilling into the users table
        // is where the loot lives.
        $html = (new AdminLteSkin())->render(
            PageSlots::fromArray([]), VisualPersona::fromSeed(5), '/panel/databases', '/panel/databases'
        );
        self::assertStringContainsString('appdb', $html);
        self::assertStringContainsString('Browse', $html);
        self::assertStringNotContainsString('password_hash', $html);
        // And the drill-down link into the users table Browse is reachable.
        self::assertStringContainsString('href="/panel/databases/users"', $html);
    }

    /**
     * Each sidebar link leads to a different bait section, now selected by PanelRoute's positional module
     * slot (not the path's last segment). The needles are section-specific.
     *
     * @dataProvider panelViews
     */
    public function test_path_selects_the_matching_section(string $path, string $needle): void
    {
        $html = (new AdminLteSkin())->render(PageSlots::fromArray([]), VisualPersona::fromSeed(42), $path, $path);
        self::assertStringContainsString($needle, $html);
    }

    /** @return array<string,array{0:string,1:string}> */
    public static function panelViews(): array
    {
        return [
            'logs' => ['/panel/logs', 'auth.log'],
            'cron' => ['/panel/cron', 'Scheduled Tasks'],
            'processes' => ['/panel/processes', 'Miner detected'],
            'api-keys' => ['/panel/api-keys', '.env'],
            'files' => ['/panel/files', 'file manager'],
            'system' => ['/panel/system-info', 'Service tag'],
            'backups' => ['/panel/backups', 'Keep last 7'],
            'users' => ['/panel/users', 'password_hash'],
            'databases' => ['/panel/databases', 'appdb'],
            // A deep leaf still resolves its module (was collapsed to the last segment before PanelRoute).
            'deep-leaf' => ['/panel/system/host/detail', 'Service tag'],
        ];
    }

    public function test_every_view_has_breadcrumbs(): void
    {
        foreach (['/panel', '/panel/system', '/panel/logs', '/panel/users', '/panel/databases'] as $path) {
            $html = (new AdminLteSkin())->render(PageSlots::fromArray([]), VisualPersona::fromSeed(3), $path, $path);
            self::assertStringContainsString('fp-breadcrumb', $html, "breadcrumb missing on $path");
        }
    }

    public function test_grouped_sidebar_links_route_under_the_mount(): void
    {
        $html = (new AdminLteSkin())->render(PageSlots::fromArray([]), VisualPersona::fromSeed(1), '/panel', '/panel');
        self::assertStringContainsString('alte-nav-group-title', $html);         // grouped headers
        self::assertStringContainsString('href="/panel/logs"', $html);          // links rooted at mount
        self::assertStringContainsString('href="/panel/databases"', $html);
    }

    public function test_unknown_module_falls_back_to_dashboard(): void
    {
        $html = (new AdminLteSkin())->render(
            PageSlots::fromArray([]), VisualPersona::fromSeed(8), '/panel/nonsense-module', '/panel/nonsense-module'
        );
        self::assertStringContainsString('Recent sign-ins', $html);              // dashboard, not a 404
        self::assertStringNotContainsString('password_hash', $html);
    }

    public function test_key_is_adminlte(): void
    {
        self::assertSame('adminlte', (new AdminLteSkin())->key());
    }

    public function test_resembles_adminlte_and_escapes(): void
    {
        $html = (new AdminLteSkin())->render(
            PageSlots::fromArray([
                'heading' => '<x onerror=1>',
                'app_name' => 'Ops Console',
            ]),
            VisualPersona::fromSeed(4), '/admin/index.php'
        );
        self::assertStringStartsWith('<!doctype html>', $html);
        self::assertStringContainsString('sidebar', strtolower($html)); // resemblance marker
        self::assertStringNotContainsString('<x onerror', $html);       // escaping holds
    }
}
