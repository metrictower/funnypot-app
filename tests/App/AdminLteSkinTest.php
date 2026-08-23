<?php
declare(strict_types=1);
namespace Funnypot\Tests\App;
use Funnypot\App\Render\Skins\AdminLteSkin;
use Funnypot\App\Render\{PageSlots, VisualPersona};
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

    public function test_renders_deterministic_server_enrichment(): void
    {
        $s = new AdminLteSkin();
        $slots = PageSlots::fromArray(['heading' => 'Dashboard', 'app_name' => 'Control Panel']);
        $a = $s->render($slots, VisualPersona::fromSeed(77), '/panel/dashboard', '/panel/dashboard');
        $b = $s->render($slots, VisualPersona::fromSeed(77), '/panel/dashboard', '/panel/dashboard');
        self::assertSame($a, $b, 'enrichment must be byte-identical per seed (cache-safe)');
        self::assertStringContainsString('alte-stats', $a);            // stat cards
        self::assertStringContainsString('System Information', $a);
        self::assertStringContainsString('Backups', $a);
        self::assertMatchesRegularExpression('/of [\d,]+ rows/', $a);   // bottomless loot count
    }

    public function test_backup_links_preserve_archive_ext_and_stay_in_panel(): void
    {
        $html = (new AdminLteSkin())->render(
            PageSlots::fromArray(['heading' => 'Dashboard']),
            VisualPersona::fromSeed(9), '/panel/dashboard', '/panel/dashboard'
        );
        // A backup link under the panel prefix, keeping its archive extension so it routes to the
        // decoy-archive handler (the download rabbit-hole).
        self::assertSame(1, preg_match('#href="(/panel/backups/[A-Za-z0-9._-]+\.(?:tar\.gz|sql\.gz|zip))"#', $html));
        self::assertStringNotContainsString('javascript:', $html);
    }

    public function test_loot_emails_use_the_persona_domain(): void
    {
        $persona = VisualPersona::fromSeed(123);
        $html = (new AdminLteSkin())->render(
            PageSlots::fromArray(['heading' => 'Users']),
            $persona, '/panel/users', '/panel/users'
        );
        self::assertStringContainsString('@' . $persona->domain(), $html); // loot coherent with host identity
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
                'nav_items' => ['Dashboard', 'Users'],
                'table' => ['cols' => ['id', 'user'], 'rows' => [['1', 'bob']]],
            ]),
            VisualPersona::fromSeed(4), '/admin/index.php'
        );
        self::assertStringStartsWith('<!doctype html>', $html);
        self::assertStringContainsString('sidebar', strtolower($html)); // resemblance marker
        self::assertStringNotContainsString('<x onerror', $html);       // escaping holds
    }
}
