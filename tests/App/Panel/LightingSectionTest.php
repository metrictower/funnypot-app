<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Lighting;
use Funnypot\App\Render\Panel\LightingSection;
use Funnypot\Core\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class LightingSectionTest extends TestCase
{
    /** Anything outside RFC1918 10.x is a leak of real routable space (SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    /** @return array{module:string,section:string,entity:string,subtab:string,action:string,arg:string,page:int,filter:string} */
    private function route(string $section = '', string $entity = '', string $subtab = '', string $action = '', int $page = 1): array
    {
        return [
            'module' => 'lighting', 'section' => $section, 'entity' => $entity, 'subtab' => $subtab,
            'action' => $action, 'arg' => '', 'page' => $page, 'filter' => $entity,
        ];
    }

    // --- generator: determinism, coherence, safety ---

    public function test_generator_is_deterministic(): void
    {
        $a = Lighting::fromSeed(11);
        $b = Lighting::fromSeed(11);
        self::assertSame($a->groups(), $b->groups());
        self::assertSame($a->covers(), $b->covers());
        self::assertSame($a->scenes(), $b->scenes());
        self::assertSame($a->summary(), $b->summary());
        self::assertSame($a->brightnessTrend($a->groups()[0]), $b->brightnessTrend($b->groups()[0]));
    }

    public function test_different_seeds_differ(): void
    {
        self::assertNotSame(Lighting::fromSeed(1)->groups(), Lighting::fromSeed(2)->groups());
    }

    public function test_group_lookup_matches_list_row(): void
    {
        $lx = Lighting::fromSeed(7);
        foreach ($lx->groups() as $g) {
            self::assertSame($g, $lx->group($g['id']), 'group() must be byte-identical to its groups() row');
            self::assertMatchesRegularExpression('/^[a-z0-9-]+$/', $g['id'], 'group id must be a slug');
        }
    }

    public function test_cover_lookup_matches_list_row(): void
    {
        $lx = Lighting::fromSeed(7);
        foreach ($lx->covers() as $c) {
            self::assertSame($c, $lx->cover($c['id']), 'cover() must be byte-identical to its covers() row');
            self::assertMatchesRegularExpression('/^[a-z0-9-]+$/', $c['id'], 'cover id must be a slug');
        }
    }

    public function test_unknown_group_still_renders_a_group_not_a_404(): void
    {
        // Spec D.4: a fuzzed slug must still produce a plausible detail, never fall off the edge.
        $g = Lighting::fromSeed(3)->group('lgt-does-not-exist');
        self::assertSame('lgt-does-not-exist', $g['id']);
        self::assertArrayHasKey('brightnessPct', $g);
        self::assertArrayHasKey('controllerIp', $g);
    }

    public function test_unknown_cover_still_renders_a_cover(): void
    {
        $c = Lighting::fromSeed(3)->cover('cov-nope');
        self::assertSame('cov-nope', $c['id']);
        self::assertArrayHasKey('position', $c);
    }

    public function test_off_group_draws_no_power_and_zero_brightness(): void
    {
        foreach (Lighting::fromSeed(5)->groups() as $g) {
            if ($g['state'] === 'off') {
                self::assertSame(0, $g['wattage'], 'an off group draws ~0 W');
                self::assertSame(0, $g['brightnessPct'], 'an off group reports 0 % brightness');
            }
        }
    }

    public function test_group_lives_in_a_real_building_room(): void
    {
        // Cross-coherence: every group names a room id that Building actually produces on that floor.
        $seed = 4;
        $lx = Lighting::fromSeed($seed);
        $bld = \Funnypot\App\Render\Fake\Building::fromSeed($seed);
        $roomIds = [];
        foreach ($bld->floors() as $f) {
            foreach ($bld->roomsFor($f['code']) as $r) {
                $roomIds[$r['id']] = $r['floor'];
            }
        }
        foreach ($lx->groups() as $g) {
            self::assertArrayHasKey($g['roomId'], $roomIds, "group {$g['id']} must reference a real room");
            self::assertSame($roomIds[$g['roomId']], $g['floor'], 'group floor must match its room floor');
        }
    }

    public function test_server_room_goose_chase_groups_exist_and_are_off(): void
    {
        $lx = Lighting::fromSeed(4);
        $seen = [];
        foreach ($lx->groups() as $g) {
            if ($g['special'] !== '') {
                $seen[] = $g['special'];
                if ($g['special'] === 'uv') {
                    self::assertSame('off', $g['state'], 'the UV steriliser lure must read off/interlocked');
                    self::assertSame(0, $g['wattage']);
                }
            }
        }
        self::assertContains('uv', $seen, 'the server-room UV steriliser lure must exist');
        self::assertContains('datacenter', $seen, 'the datacenter row lure must exist');
    }

    public function test_physical_access_covers_exist(): void
    {
        $lx = Lighting::fromSeed(2);
        $types = [];
        foreach ($lx->covers() as $c) {
            if ($c['access']) {
                $types[] = $c['type'];
            }
        }
        self::assertContains('loading-dock', $types, 'loading-dock bait must exist');
        self::assertContains('parking-barrier', $types, 'parking-barrier bait must exist');
    }

    public function test_generator_leaks_no_public_ip(): void
    {
        for ($seed = 0; $seed < 12; $seed++) {
            $lx = Lighting::fromSeed($seed);
            $blob = json_encode([$lx->groups(), $lx->covers(), $lx->scenes(), $lx->summary()]);
            self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, (string) $blob, "seed $seed");
        }
    }

    public function test_summary_counts_reconcile(): void
    {
        $lx = Lighting::fromSeed(6);
        $s = $lx->summary();
        self::assertSame(count($lx->groups()), $s['groups']);
        self::assertSame($s['groups'], $s['on'] + $s['off'] + $s['fault']);
        self::assertSame(count($lx->covers()), $s['covers']);
    }

    // --- section: rendering, depth, escaping, inertness ---

    public function test_landing_is_byte_identical_per_seed(): void
    {
        $s = new LightingSection();
        $p = VisualPersona::fromSeed(42);
        $a = $s->render($this->route(), $p, '/panel');
        $b = $s->render($this->route(), $p, '/panel');
        self::assertSame($a, $b, 'must be cache-safe (byte-identical per seed)');
    }

    public function test_landing_shows_groups_scenes_covers_master_and_breadcrumb(): void
    {
        $html = (new LightingSection())->render($this->route(), VisualPersona::fromSeed(8), '/panel');
        self::assertStringContainsString('fp-breadcrumb', $html);
        self::assertStringContainsString('Luminaire groups', $html);
        self::assertStringContainsString('Scenes', $html);
        self::assertStringContainsString('Master control', $html);
        // A group link routes deeper under the mount.
        self::assertSame(1, preg_match('#href="/panel/lighting/lgt-[a-z0-9-]+"#', $html));
        self::assertStringContainsString('href="/panel/lighting/master/off"', $html);
        self::assertStringContainsString('href="/panel/lighting/scenes/apply/', $html);
        self::assertStringContainsString('href="/panel/lighting/covers"', $html);
    }

    public function test_group_detail_has_subtabs_gauges_and_controls(): void
    {
        $lx = Lighting::fromSeed(9);
        $id = $lx->groups()[0]['id'];
        $html = (new LightingSection())->render($this->route($id), VisualPersona::fromSeed(9), '/panel');
        self::assertStringContainsString('fp-gauge', $html);
        self::assertStringContainsString('alte-tabs', $html);
        self::assertStringContainsString('href="/panel/lighting/' . $id . '/wiring"', $html);
        self::assertStringContainsString('href="/panel/lighting/' . $id . '/bright/', $html);
        self::assertStringContainsString('href="/panel/lighting/' . $id . '/cct/', $html);
        self::assertStringContainsString('href="/panel/lighting/' . $id . '/power/off"', $html);
    }

    public function test_history_subtab_has_sparkline(): void
    {
        $lx = Lighting::fromSeed(9);
        $id = $lx->groups()[0]['id'];
        $html = (new LightingSection())->render($this->route($id, 'history'), VisualPersona::fromSeed(9), '/panel');
        self::assertStringContainsString('fp-sparkline', $html);
        self::assertStringContainsString('History', $html);
    }

    public function test_brightness_leaf_is_an_inert_queued_receipt(): void
    {
        $lx = Lighting::fromSeed(1);
        $id = $lx->groups()[0]['id'];
        // entity = action ('bright'), subtab = arg ('75')
        $html = (new LightingSection())->render($this->route($id, 'bright', '75'), VisualPersona::fromSeed(1), '/panel');
        self::assertStringContainsString('Queued', $html);
        self::assertStringContainsString('Fixtures', $html);
        self::assertStringContainsString('next DALI poll', $html);
        self::assertStringNotContainsString('applied at', $html);   // never "done"
    }

    public function test_floor_apply_leaf_fans_out_across_the_floor(): void
    {
        $lx = Lighting::fromSeed(1);
        $g = $lx->groups()[0];
        $html = (new LightingSection())->render($this->route($g['id'], 'floor', 'apply'), VisualPersona::fromSeed(1), '/panel');
        self::assertStringContainsString('Floor apply queued', $html);
        self::assertStringContainsString('All groups on', $html);
    }

    public function test_scene_apply_leaf_is_inert_receipt(): void
    {
        $html = (new LightingSection())->render($this->route('scenes', 'apply', 'all-off'), VisualPersona::fromSeed(3), '/panel');
        self::assertStringContainsString('Scene applied', $html);
        self::assertStringContainsString('Queued', $html);
        self::assertStringContainsString('Groups', $html);
    }

    public function test_master_control_is_a_canned_inert_confirmation(): void
    {
        $html = (new LightingSection())->render($this->route('master', 'off'), VisualPersona::fromSeed(3), '/panel');
        self::assertStringContainsString('all OFF', $html);
        self::assertStringContainsString('Queued', $html);
        // The scary "kill everything" lever never claims to have done it.
        self::assertStringNotContainsString('applied at', $html);
        self::assertStringContainsString('emergency lighting circuits are excluded', $html);
    }

    public function test_covers_list_and_detail_render_with_controls(): void
    {
        $lx = Lighting::fromSeed(2);
        $listHtml = (new LightingSection())->render($this->route('covers'), VisualPersona::fromSeed(2), '/panel');
        self::assertStringContainsString('Blinds &amp; shades', $listHtml);
        self::assertSame(1, preg_match('#href="/panel/lighting/covers/cov-[a-z0-9-]+"#', $listHtml));

        $id = $lx->covers()[0]['id'];
        $detail = (new LightingSection())->render($this->route('covers', $id), VisualPersona::fromSeed(2), '/panel');
        self::assertStringContainsString('Cover state', $detail);
        self::assertStringContainsString('href="/panel/lighting/covers/' . $id . '/open/100"', $detail);
        self::assertStringContainsString('href="/panel/lighting/covers/' . $id . '/pos/', $detail);
    }

    public function test_cover_control_leaf_is_inert_receipt(): void
    {
        $lx = Lighting::fromSeed(2);
        $id = $lx->covers()[0]['id'];
        // section=covers, entity=coverId, subtab=action(open), action=arg(100)
        $html = (new LightingSection())->render($this->route('covers', $id, 'open', '100'), VisualPersona::fromSeed(2), '/panel');
        self::assertStringContainsString('Open queued', $html);
        self::assertStringContainsString('Queued', $html);
    }

    public function test_control_arg_is_escaped_defense_in_depth(): void
    {
        $lx = Lighting::fromSeed(1);
        $id = $lx->groups()[0]['id'];
        $html = (new LightingSection())->render(
            $this->route($id, 'scene', '<script>alert(1)</script>'),
            VisualPersona::fromSeed(1), '/panel'
        );
        self::assertStringNotContainsString('<script>alert(1)', $html);
    }

    public function test_deep_list_page_renders_that_pages_slice_with_reachable_pager(): void
    {
        $lx = Lighting::fromSeed(2);
        $groups = $lx->groups();
        self::assertGreaterThan(50, count($groups), 'seed 2 must have >2 pages of groups for this test');

        $p2 = (new LightingSection())->render($this->route('', '', '', '', 2), VisualPersona::fromSeed(2), '/panel');

        // Page 2 shows the 26th..50th group, not the first-page rows.
        self::assertStringContainsString('href="/panel/lighting/' . $groups[25]['id'] . '"', $p2);
        self::assertStringNotContainsString('href="/panel/lighting/' . $groups[0]['id'] . '"', $p2);

        // The pager on a deep page is reachable both ways: prev -> p1, next -> p3.
        self::assertStringContainsString('href="/panel/lighting/p1"', $p2);
        self::assertStringContainsString('href="/panel/lighting/p3"', $p2);
        self::assertStringContainsString('page 2 / ', $p2);
    }

    public function test_no_public_ip_in_rendered_pages(): void
    {
        $s = new LightingSection();
        $lx = Lighting::fromSeed(3);
        $gid = $lx->groups()[0]['id'];
        $cid = $lx->covers()[0]['id'];
        $routes = [
            $this->route(),
            $this->route($gid),
            $this->route($gid, 'wiring'),
            $this->route($gid, 'bright', '50'),
            $this->route('scenes'),
            $this->route('covers'),
            $this->route('covers', $cid),
            $this->route('master', 'off'),
        ];
        foreach ($routes as $r) {
            $html = $s->render($r, VisualPersona::fromSeed(3), '/panel');
            self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $html);
        }
    }

    public function test_no_undefined_key_warnings_across_the_ladder(): void
    {
        set_error_handler(static function (int $severity, string $message): bool {
            throw new \RuntimeException('PHP warning/notice: ' . $message);
        });
        try {
            $s = new LightingSection();
            $lx = Lighting::fromSeed(4);
            $gid = $lx->groups()[0]['id'];
            $cid = $lx->covers()[0]['id'];
            foreach ([
                $this->route(),
                $this->route($gid),
                $this->route($gid, 'schedule'),
                $this->route($gid, 'history'),
                $this->route($gid, 'energy'),
                $this->route($gid, 'wiring'),
                $this->route($gid, 'cct', '4000'),
                $this->route('scenes'),
                $this->route('scenes', 'apply', 'evening'),
                $this->route('covers'),
                $this->route('covers', $cid),
                $this->route('covers', $cid, 'pos', '40'),
                $this->route('master', 'on'),
            ] as $r) {
                $html = $s->render($r, VisualPersona::fromSeed(4), '/panel');
                self::assertNotSame('', $html);
            }
        } finally {
            restore_error_handler();
        }
    }
}
