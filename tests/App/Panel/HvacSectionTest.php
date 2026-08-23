<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Hvac;
use Funnypot\App\Render\Panel\HvacSection;
use Funnypot\App\Render\VisualPersona;
use PHPUnit\Framework\TestCase;

final class HvacSectionTest extends TestCase
{
    /** Anything outside RFC1918 10.x is a leak of real routable space (SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    /** @return array{module:string,section:string,entity:string,subtab:string,action:string,arg:string,page:int,filter:string} */
    private function route(string $section = '', string $entity = '', string $subtab = '', int $page = 1): array
    {
        return [
            'module' => 'hvac', 'section' => $section, 'entity' => $entity, 'subtab' => $subtab,
            'action' => '', 'arg' => '', 'page' => $page, 'filter' => $section,
        ];
    }

    // --- generator: determinism, coherence, safety ---

    public function test_generator_is_deterministic(): void
    {
        $a = Hvac::fromSeed(11);
        $b = Hvac::fromSeed(11);
        self::assertSame($a->zones(), $b->zones());
        self::assertSame($a->cracUnits(), $b->cracUnits());
        self::assertSame($a->summary(), $b->summary());
        self::assertSame($a->points($a->zones()[0]), $b->points($b->zones()[0]));
        self::assertSame($a->tempTrend($a->zones()[0]), $b->tempTrend($b->zones()[0]));
    }

    public function test_different_seeds_differ(): void
    {
        self::assertNotSame(Hvac::fromSeed(1)->zones(), Hvac::fromSeed(2)->zones());
    }

    public function test_zone_lookup_matches_list_row(): void
    {
        $hvac = Hvac::fromSeed(7);
        foreach ($hvac->zones() as $z) {
            self::assertSame($z, $hvac->zone($z['id']), 'zone() must be byte-identical to its zones() row');
            self::assertMatchesRegularExpression('/^[a-z0-9-]+$/', $z['id'], 'zone id must be a slug');
        }
    }

    public function test_unknown_zone_still_renders_a_zone_not_a_404(): void
    {
        // Spec D.4: a fuzzed slug must still produce a plausible detail, never fall off the edge.
        $z = Hvac::fromSeed(3)->zone('zone-does-not-exist');
        self::assertSame('zone-does-not-exist', $z['id']);
        self::assertArrayHasKey('setpoint', $z);
        self::assertArrayHasKey('controllerIp', $z);
    }

    public function test_zone_action_agrees_with_temperature_delta(): void
    {
        foreach (Hvac::fromSeed(5)->zones() as $z) {
            $delta = round((float) $z['currentTemp'] - (float) $z['setpoint'], 1);
            if ($z['hvacMode'] === 'cool' || $z['hvacMode'] === 'auto' || $z['hvacMode'] === 'heat_cool') {
                if ($delta > 0.4) {
                    self::assertSame('cooling', $z['hvacAction']);
                } elseif ($delta < -0.4) {
                    self::assertSame('heating', $z['hvacAction']);
                }
            }
        }
    }

    public function test_crac_serves_and_cross_links_a_real_room(): void
    {
        $hvac = Hvac::fromSeed(4);
        $cracs = $hvac->cracUnits();
        self::assertNotEmpty($cracs, 'the flagship CRAC lure must always exist');
        foreach ($cracs as $c) {
            self::assertStringStartsWith('crac-', $c['id']);
            self::assertNotSame('', $c['servesRoomId']);
            self::assertMatchesRegularExpression('/^[a-z0-9-]+$/', $c['servesRoomId']);
        }
    }

    public function test_anomaly_budget_is_at_most_the_one_crac(): void
    {
        for ($seed = 0; $seed < 25; $seed++) {
            $anom = 0;
            foreach (Hvac::fromSeed($seed)->cracUnits() as $c) {
                if ($c['anomaly'] !== '') {
                    $anom++;
                    self::assertSame('crac-01', $c['id'], "seed $seed: only the first CRAC may carry an anomaly");
                    self::assertNotSame('', $c['workOrder'], 'an anomaly must reference a work order');
                }
            }
            self::assertLessThanOrEqual(1, $anom, "seed $seed anomaly budget");
        }
    }

    public function test_points_host_is_rfc1918_bacnet(): void
    {
        $hvac = Hvac::fromSeed(6);
        foreach ($hvac->points($hvac->zones()[0]) as $p) {
            self::assertStringContainsString(':' . Hvac::BACNET_PORT, $p['host']);
            self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $p['host']);
        }
    }

    public function test_generator_leaks_no_public_ip(): void
    {
        for ($seed = 0; $seed < 12; $seed++) {
            $hvac = Hvac::fromSeed($seed);
            $blob = json_encode([$hvac->zones(), $hvac->cracUnits(), $hvac->controllers()]);
            self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, (string) $blob, "seed $seed");
        }
    }

    // --- section: rendering, depth, escaping, inertness ---

    public function test_landing_is_byte_identical_per_seed(): void
    {
        $s = new HvacSection();
        $p = VisualPersona::fromSeed(42);
        $a = $s->render($this->route(), $p, '/panel');
        $b = $s->render($this->route(), $p, '/panel');
        self::assertSame($a, $b, 'must be cache-safe (byte-identical per seed)');
    }

    public function test_landing_shows_zones_crac_and_breadcrumb(): void
    {
        $html = (new HvacSection())->render($this->route(), VisualPersona::fromSeed(8), '/panel');
        self::assertStringContainsString('fp-breadcrumb', $html);
        self::assertStringContainsString('Climate zones', $html);
        self::assertStringContainsString('Precision cooling (CRAC)', $html);
        // A zone link routes deeper under the mount.
        self::assertSame(1, preg_match('#href="/panel/hvac/zone-[a-z0-9-]+"#', $html));
        self::assertSame(1, preg_match('#href="/panel/hvac/crac-[0-9]+"#', $html));
    }

    public function test_zone_detail_has_subtabs_gauges_and_setpoint_control(): void
    {
        $hvac = Hvac::fromSeed(9);
        $id = $hvac->zones()[0]['id'];
        $html = (new HvacSection())->render($this->route($id), VisualPersona::fromSeed(9), '/panel');
        self::assertStringContainsString('fp-gauge', $html);                          // gauge widget
        self::assertStringContainsString('fp-sparkline', $html);                      // 24h trend
        self::assertStringContainsString('alte-tabs', $html);                         // sub-tab strip
        self::assertStringContainsString('href="/panel/hvac/' . $id . '/points"', $html);
        self::assertStringContainsString('href="/panel/hvac/' . $id . '/set/', $html); // setpoint control leaf
    }

    public function test_points_subtab_lists_bacnet_points(): void
    {
        $hvac = Hvac::fromSeed(2);
        $id = $hvac->zones()[0]['id'];
        $html = (new HvacSection())->render($this->route($id, 'points'), VisualPersona::fromSeed(2), '/panel');
        self::assertStringContainsString('BACnet points', $html);
        self::assertStringContainsString('Zone Setpoint', $html);
        self::assertStringContainsString(':' . Hvac::BACNET_PORT, $html);
    }

    public function test_zone_setpoint_leaf_is_an_inert_queued_receipt(): void
    {
        $hvac = Hvac::fromSeed(1);
        $id = $hvac->zones()[0]['id'];
        // entity = action ('set'), subtab = arg ('23')
        $html = (new HvacSection())->render($this->route($id, 'set', '23'), VisualPersona::fromSeed(1), '/panel');
        self::assertStringContainsString('Queued', $html);
        self::assertStringContainsString('next BACnet poll', $html);
        self::assertStringNotContainsString('applied', $html);   // never "done"
    }

    public function test_crac_control_is_a_guarded_soft_deny_never_done(): void
    {
        // The scary verb (cooling the servers) must degrade to a dual-auth / interlock denial, not "done".
        $html = (new HvacSection())->render($this->route('crac-01', 'set', '30'), VisualPersona::fromSeed(4), '/panel');
        self::assertStringContainsString('DENIED', $html);
        self::assertStringContainsString('dual-authorization', $html);
        self::assertStringContainsString('interlock', strtolower($html));
    }

    public function test_control_arg_is_escaped_defense_in_depth(): void
    {
        // PanelRoute slugifies slots in production, but the receipt must still escape the arg it echoes.
        $hvac = Hvac::fromSeed(1);
        $id = $hvac->zones()[0]['id'];
        $html = (new HvacSection())->render(
            $this->route($id, 'set', '<script>alert(1)</script>'),
            VisualPersona::fromSeed(1), '/panel'
        );
        self::assertStringNotContainsString('<script>alert(1)', $html);
    }

    public function test_crac_points_tab_renders_without_undefined_key_warnings(): void
    {
        // C1: a CRAC record lacks the office-zone-only keys (co2/damper/valve). The points tab must render
        // a CRAC-specific point list with filled cells and raise no "Undefined array key" warning.
        set_error_handler(static function (int $severity, string $message): bool {
            throw new \RuntimeException('PHP warning/notice: ' . $message);
        });
        try {
            $hvac = Hvac::fromSeed(4);
            $c = $hvac->crac('crac-01');
            // The generator itself must not touch missing keys.
            $points = $hvac->points($c);
            self::assertNotEmpty($points);
            foreach ($points as $p) {
                self::assertNotSame('', $p['value'], 'every CRAC point must have a present value');
                self::assertStringContainsString(':' . Hvac::BACNET_PORT, $p['host']);
            }
            // And the rendered points tab must show them.
            $html = (new HvacSection())->render($this->route('crac-01', 'points'), VisualPersona::fromSeed(4), '/panel');
            self::assertStringContainsString('BACnet points', $html);
            self::assertStringContainsString('Supply Air Temperature', $html);
            self::assertStringContainsString('Unit Setpoint', $html);
        } finally {
            restore_error_handler();
        }
    }

    public function test_crac_detail_cross_links_the_server_room(): void
    {
        $html = (new HvacSection())->render($this->route('crac-01'), VisualPersona::fromSeed(4), '/panel');
        self::assertStringContainsString('CRAC state', $html);
        self::assertStringContainsString('href="/panel/access"', $html);   // physical access cross-link
        self::assertStringContainsString('href="/panel/system"', $html);   // server hosts cross-link
    }

    public function test_no_public_ip_in_rendered_pages(): void
    {
        $s = new HvacSection();
        $hvac = Hvac::fromSeed(3);
        $id = $hvac->zones()[0]['id'];
        foreach ([$this->route(), $this->route($id), $this->route($id, 'points'), $this->route('crac-01')] as $r) {
            $html = $s->render($r, VisualPersona::fromSeed(3), '/panel');
            self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $html);
        }
    }
}
