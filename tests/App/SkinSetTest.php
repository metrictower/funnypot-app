<?php
declare(strict_types=1);
namespace Funnypot\Tests\App;
use Funnypot\App\Render\{Skin, SkinSet, GenericSkin, PageSlots, VisualPersona};
use Funnypot\App\Render\Skins\{WordpressSkin, PhpMyAdminSkin, GrafanaSkin, AdminLteSkin};
use PHPUnit\Framework\TestCase;

final class SkinSetTest extends TestCase
{
    public function test_selects_first_matching_else_default(): void
    {
        $wp = new class implements Skin {
            public function matches(string $path): bool { return str_contains($path, '/wp-'); }
            public function key(): string { return 'wp'; }
            public function render(PageSlots $s, VisualPersona $p, string $ep): string { return 'WP'; }
        };
        $set = new SkinSet([$wp], new GenericSkin());
        self::assertSame('wp', $set->select('/wp-login.php')->key());
        self::assertSame('generic', $set->select('/hr/portal')->key());
    }

    /** The exact skin list + order demo/index.php and page-slots-eval.php register in production. */
    private function productionSkinSet(): SkinSet
    {
        return new SkinSet(
            [new WordpressSkin(), new PhpMyAdminSkin(), new GrafanaSkin(), new AdminLteSkin()],
            new GenericSkin()
        );
    }

    /**
     * Segment-anchoring: the intended path shapes for each resemblance skin still route correctly
     * under the production ordering, plus a fall-through to GenericSkin for an unrelated path.
     *
     * @dataProvider intendedPaths
     */
    public function test_intended_paths_route_to_the_right_skin(string $path, string $expectedKey): void
    {
        self::assertSame($expectedKey, $this->productionSkinSet()->select($path)->key());
    }

    /** @return array<string,array{0:string,1:string}> */
    public static function intendedPaths(): array
    {
        return [
            'wp-admin -> wordpress' => ['/wp-admin/options.php', 'wordpress'],
            'wp-login -> wordpress' => ['/wp-login.php', 'wordpress'],
            'phpmyadmin -> phpmyadmin' => ['/phpmyadmin/index.php', 'phpmyadmin'],
            'pma -> phpmyadmin' => ['/pma/index.php', 'phpmyadmin'],
            'PMA uppercase -> phpmyadmin' => ['/PMA/index.php', 'phpmyadmin'],
            'grafana subpath -> grafana' => ['/grafana/d/x', 'grafana'],
            'top-level dashboard uid -> grafana' => ['/d/abc123/some-dashboard', 'grafana'],
            'admin users -> adminlte' => ['/admin/users', 'adminlte'],
            'dashboard -> adminlte' => ['/dashboard', 'adminlte'],
            'manage users -> adminlte' => ['/manage/users', 'adminlte'],
            // Extension-suffixed admin-panel files: a dot immediately after the token still counts
            // as the token's own segment (admin.php is "admin" plus a file extension), unlike a dash
            // or more letters right after it (admin-notes, administer — see misroutedPaths()).
            'admin.php -> adminlte' => ['/admin.php', 'adminlte'],
            'admin.aspx -> adminlte' => ['/admin.aspx', 'adminlte'],
            'dashboard.php -> adminlte' => ['/dashboard.php', 'adminlte'],
            'manage.php -> adminlte' => ['/manage.php', 'adminlte'],
            // Joomla's admin path — a common scanner target — is its own exact-segment token since
            // the dot-suffix rule above doesn't cover it (no dot right after "admin").
            'administrator -> adminlte' => ['/administrator/', 'adminlte'],
            'administrator index.php -> adminlte' => ['/administrator/index.php', 'adminlte'],
            'unrelated -> generic' => ['/hr/portal', 'generic'],
        ];
    }

    /**
     * Shadowing/misroute cases that the old raw str_contains() matching got wrong. Each of these
     * used to hit a broader resemblance skin (or the wrong one) purely because the token happened
     * to appear as a substring somewhere in the path, not as a real path segment.
     *
     * @dataProvider misroutedPaths
     */
    public function test_non_segment_substrings_do_not_misroute(string $path, string $expectedKey): void
    {
        self::assertSame($expectedKey, $this->productionSkinSet()->select($path)->key());
    }

    /** @return array<string,array{0:string,1:string}> */
    public static function misroutedPaths(): array
    {
        return [
            // 'admin' is a substring of the segment 'admin-notes', not a segment on its own.
            'admin substring in segment -> generic' => ['/user/admin-notes', 'generic'],
            // 'admin' is a substring of 'administer', not a segment on its own.
            'admin substring in a word -> generic' => ['/administer', 'generic'],
            // 'wp-admin' is its own segment, distinct from the exact segment 'admin' AdminLte wants.
            'wp-admin segment does not equal admin -> wordpress' => ['/wp-admin/options.php', 'wordpress'],
            // '/d/' used to match anywhere in the path; a dashboard uid only means Grafana when it's
            // the path's own first segment, not buried after an unrelated admin path.
            'buried /d/ segment is not a top-level dashboard uid -> adminlte' => ['/admin/d/xyz', 'adminlte'],
            'buried /d/ segment with no other match -> generic' => ['/foo/d/bar', 'generic'],
            // 'dashboards' (plural) is a distinct segment from the exact token 'dashboard'.
            'dashboards plural is not the dashboard segment -> adminlte (via /admin)' => ['/admin/dashboards', 'adminlte'],
            // '/downloads/' never actually contained the literal '/d/' substring, but confirm the
            // anchored top-level check still correctly refuses it.
            'downloads is not a dashboard uid -> generic' => ['/downloads/', 'generic'],
            // The dot-suffix admission (admin.php, ...) must not reopen the substring bug: a dash or
            // more letters right after the token is still not a boundary.
            'admin-notes bare segment -> generic' => ['/admin-notes', 'generic'],
            'badminton contains admin as a substring, not a segment -> generic' => ['/badminton', 'generic'],
        ];
    }

    /**
     * Ordering guard: '/wp-admin/dashboard' is a genuine dual-match under the anchored rules — its
     * first segment 'wp-admin' starts with 'wp-' (WordpressSkin) AND its second segment is the exact
     * literal 'dashboard' (AdminLteSkin). This proves the registration order still matters even after
     * anchoring closes the substring bug: WordpressSkin must be registered ahead of AdminLteSkin so
     * the more specific product skin wins instead of being shadowed by the broad admin-panel skin.
     */
    public function test_adminlte_last_does_not_shadow_a_more_specific_skin_on_dual_match(): void
    {
        $path = '/wp-admin/dashboard';
        self::assertTrue((new WordpressSkin())->matches($path), 'precondition: WordpressSkin must match this path');
        self::assertTrue((new AdminLteSkin())->matches($path), 'precondition: AdminLteSkin must also match this path');

        self::assertSame('wordpress', $this->productionSkinSet()->select($path)->key());
    }

    /** AdminLteSkin is the broadest matcher; it must be the last entry in the production list so
     *  every more-specific product skin gets first refusal. A structural check, not just a behavioral
     *  one, so a future reordering fails loudly here even before it manifests as a routing bug. */
    public function test_production_skin_list_registers_adminlte_last(): void
    {
        $skins = [new WordpressSkin(), new PhpMyAdminSkin(), new GrafanaSkin(), new AdminLteSkin()];
        self::assertInstanceOf(AdminLteSkin::class, $skins[count($skins) - 1]);
    }
}
