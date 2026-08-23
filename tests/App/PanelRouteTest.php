<?php
declare(strict_types=1);
namespace Funnypot\Tests\App;

use Funnypot\App\Render\PanelRoute;
use PHPUnit\Framework\TestCase;

/**
 * PanelRoute::parse turns a deep panel path into positional slots so the skin can render real depth
 * instead of routing on the last segment. Covers mount stripping, positional mapping, trailing-pN
 * page peel, slug safety on adversarial input, and empty/degenerate paths.
 */
final class PanelRouteTest extends TestCase
{
    public function test_empty_path_yields_defaults(): void
    {
        self::assertSame(
            ['module' => '', 'section' => '', 'entity' => '', 'subtab' => '',
             'action' => '', 'arg' => '', 'page' => 1, 'filter' => ''],
            PanelRoute::parse('')
        );
    }

    public function test_root_mount_only_yields_defaults(): void
    {
        $r = PanelRoute::parse('/admin');
        self::assertSame('', $r['module']);
        self::assertSame('', $r['section']);
        self::assertSame(1, $r['page']);
    }

    public function test_mount_is_stripped_and_slots_are_positional(): void
    {
        $r = PanelRoute::parse('/admin/hvac/vav-03/history');
        self::assertSame('hvac', $r['module']);
        self::assertSame('vav-03', $r['section']);
        self::assertSame('history', $r['entity']);
        self::assertSame('', $r['subtab']);
    }

    public function test_full_control_leaf_maps_all_slots(): void
    {
        $r = PanelRoute::parse('/admin/access/door-b2-srv/detail/schedule/unlock/momentary');
        self::assertSame('access', $r['module']);
        self::assertSame('door-b2-srv', $r['section']);
        self::assertSame('detail', $r['entity']);
        self::assertSame('schedule', $r['subtab']);
        self::assertSame('unlock', $r['action']);
        self::assertSame('momentary', $r['arg']);
    }

    public function test_every_mount_token_is_stripped(): void
    {
        foreach (['admin', 'dashboard', 'manage', 'panel', 'console', 'cp', 'administrator'] as $mount) {
            $r = PanelRoute::parse('/' . $mount . '/finance/ap');
            self::assertSame('finance', $r['module'], "mount '$mount' should be stripped");
            self::assertSame('ap', $r['section']);
        }
    }

    public function test_mount_with_file_extension_is_stripped(): void
    {
        $r = PanelRoute::parse('/admin.php/hr/employees');
        self::assertSame('hr', $r['module']);
        self::assertSame('employees', $r['section']);
    }

    public function test_first_mount_wins_when_mount_is_not_leading(): void
    {
        $r = PanelRoute::parse('/x/admin/hr/employees');
        self::assertSame('hr', $r['module']);
        self::assertSame('employees', $r['section']);
    }

    public function test_only_first_mount_is_stripped(): void
    {
        // `dashboard` after the admin mount is content (a module), not a second mount to strip.
        $r = PanelRoute::parse('/admin/dashboard');
        self::assertSame('dashboard', $r['module']);
        self::assertSame('', $r['section']);
    }

    public function test_trailing_pN_peels_into_page(): void
    {
        $r = PanelRoute::parse('/admin/hr/employees/p7');
        self::assertSame('hr', $r['module']);
        self::assertSame('employees', $r['section']);
        self::assertSame('', $r['entity']);
        self::assertSame(7, $r['page']);
    }

    public function test_pN_peels_after_a_filter_segment(): void
    {
        $r = PanelRoute::parse('/admin/hr/employees/dept-finance/p2');
        self::assertSame('hr', $r['module']);
        self::assertSame('employees', $r['section']);
        self::assertSame('dept-finance', $r['entity']);
        self::assertSame('dept-finance', $r['filter']);
        self::assertSame(2, $r['page']);
    }

    public function test_missing_page_defaults_to_one(): void
    {
        self::assertSame(1, PanelRoute::parse('/admin/hr/employees')['page']);
    }

    public function test_non_page_p_segment_is_not_peeled(): void
    {
        // `p-3` (not p<digits>) is a normal slot, page stays default.
        $r = PanelRoute::parse('/admin/hr/employees/p-3');
        self::assertSame('p-3', $r['entity']);
        self::assertSame(1, $r['page']);
    }

    public function test_filter_mirrors_entity_slot(): void
    {
        $r = PanelRoute::parse('/admin/hr/employees/emp-1047');
        self::assertSame('emp-1047', $r['entity']);
        self::assertSame('emp-1047', $r['filter']);
    }

    public function test_slots_are_slugified_to_lowercase_dashes(): void
    {
        $r = PanelRoute::parse('/admin/HR/Employees/Emp 1047');
        self::assertSame('hr', $r['module']);
        self::assertSame('employees', $r['section']);
        self::assertSame('emp-1047', $r['entity']);
    }

    public function test_script_and_quote_injection_is_slugged_inert(): void
    {
        $r = PanelRoute::parse('/admin/hvac/<script>alert(1)</script>/"onmouseover=x"');
        foreach ($r as $key => $val) {
            if ($key === 'page') {
                continue;
            }
            self::assertMatchesRegularExpression('/^[a-z0-9-]*$/', $val, "slot '$key' must be a bare slug");
            self::assertStringNotContainsString('<', $val);
            self::assertStringNotContainsString('"', $val);
            self::assertStringNotContainsString(':', $val);
        }
    }

    public function test_traversal_and_symbol_segments_are_dropped(): void
    {
        // `..` and `!!!` slug to '' and drop, so positions stay aligned to meaningful slots.
        $r = PanelRoute::parse('/admin/finance/../ap/!!!/p2');
        self::assertSame('finance', $r['module']);
        self::assertSame('ap', $r['section']);
        self::assertSame(2, $r['page']);
    }

    public function test_query_string_does_not_route(): void
    {
        $r = PanelRoute::parse('/admin/hvac/vav-03?temp=94&x=<script>');
        self::assertSame('hvac', $r['module']);
        self::assertSame('vav-03', $r['section']);
        self::assertSame('', $r['entity']);
    }

    public function test_protocol_relative_host_cannot_survive_a_slot(): void
    {
        $r = PanelRoute::parse('/admin/hvac//evil.example.com/x');
        foreach (['module', 'section', 'entity', 'subtab'] as $key) {
            self::assertStringNotContainsString('//', $r[$key]);
            self::assertStringNotContainsString('.', $r[$key]);
        }
    }
}
