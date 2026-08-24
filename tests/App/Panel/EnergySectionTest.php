<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Building;
use Funnypot\App\Render\Fake\Energy;
use Funnypot\App\Render\Panel\EnergySection;
use Funnypot\App\Render\VisualPersona;
use PHPUnit\Framework\TestCase;

final class EnergySectionTest extends TestCase
{
    /** Anything outside RFC1918 10.x is a leak of real routable space (SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    /** @return array{module:string,section:string,entity:string,subtab:string,action:string,arg:string,page:int,filter:string} */
    private function route(string $section = '', string $entity = '', string $subtab = '', string $action = '', int $page = 1): array
    {
        return [
            'module' => 'energy', 'section' => $section, 'entity' => $entity, 'subtab' => $subtab,
            'action' => $action, 'arg' => '', 'page' => $page, 'filter' => $entity,
        ];
    }

    // --- generator: determinism, coherence, safety ---

    public function test_generator_is_deterministic(): void
    {
        $a = Energy::fromSeed(11);
        $b = Energy::fromSeed(11);
        self::assertSame($a->meters(), $b->meters());
        self::assertSame($a->summary(), $b->summary());
        self::assertSame($a->upsFleet(), $b->upsFleet());
        self::assertSame($a->generators(), $b->generators());
        self::assertSame($a->solarStrings(), $b->solarStrings());
        self::assertSame($a->plant(), $b->plant());
        self::assertSame($a->boards(), $b->boards());
        self::assertSame($a->loadTrend(), $b->loadTrend());
    }

    public function test_different_seeds_differ(): void
    {
        self::assertNotSame(Energy::fromSeed(1)->meters(), Energy::fromSeed(2)->meters());
    }

    public function test_meter_lookup_matches_list_row_case_insensitive(): void
    {
        // Ids display uppercase (MTR-G-01) but PanelRoute slugifies to lowercase; lookup must reconcile.
        $energy = Energy::fromSeed(7);
        foreach ($energy->meters() as $m) {
            self::assertSame($m, $energy->meter($m['id']), 'meter() must be byte-identical to its row');
            self::assertSame($m, $energy->meter(strtolower($m['id'])), 'a slugified id must still resolve');
        }
    }

    public function test_unknown_meter_still_renders_a_meter_not_a_404(): void
    {
        $m = Energy::fromSeed(3)->meter('mtr-does-not-exist');
        self::assertSame('mtr-does-not-exist', $m['id']);
        self::assertArrayHasKey('kw', $m);
        self::assertArrayHasKey('controllerIp', $m);
    }

    public function test_summary_reconciles_with_the_meters(): void
    {
        $energy = Energy::fromSeed(5);
        $expected = 0.0;
        $fails = 0;
        foreach ($energy->meters() as $m) {
            if ($m['scope'] === 'incomer' && $m['comms'] === 'OK') {
                $expected += (float) $m['kw'];
            }
            if ($m['comms'] === 'FAIL') {
                $fails++;
            }
        }
        $s = $energy->summary();
        self::assertSame(round($expected, 1), $s['loadKw'], 'headline load must equal the summed incomers');
        self::assertSame($fails, $s['commsFails']);
        self::assertSame($fails + ($energy->solarSummary()['faultString'] === '' ? 0 : 1), $s['activeAlarms']);
    }

    public function test_anomaly_budget_meters_and_solar(): void
    {
        for ($seed = 0; $seed < 25; $seed++) {
            $energy = Energy::fromSeed($seed);
            $fails = 0;
            foreach ($energy->meters() as $m) {
                if ($m['comms'] === 'FAIL') {
                    $fails++;
                }
            }
            self::assertGreaterThanOrEqual(2, $fails, "seed $seed comms-fail budget floor");
            self::assertLessThanOrEqual(3, $fails, "seed $seed comms-fail budget ceiling");

            $faults = 0;
            foreach ($energy->solarStrings() as $st) {
                if ($st['fault'] !== '') {
                    $faults++;
                }
            }
            self::assertSame(1, $faults, "seed $seed must plant exactly one solar fault");
        }
    }

    public function test_plant_and_ups_anchor_to_real_building_topology(): void
    {
        $seed = 4;
        $energy = Energy::fromSeed($seed);
        $bld = Building::fromSeed($seed);
        $floorCodes = [];
        foreach ($bld->floors() as $f) {
            $floorCodes[] = $f['code'];
        }
        foreach ($energy->plant() as $p) {
            self::assertContains($p['floor'], $floorCodes, 'plant must live on a real Building floor');
        }
        // UPS units protect real server/comms rooms carried in the fleet room name.
        self::assertNotEmpty($energy->upsFleet());
        foreach ($energy->upsFleet() as $u) {
            self::assertNotSame('', $u['room']);
            self::assertContains($u['floor'], $floorCodes, 'a UPS must sit on a real Building floor');
        }
    }

    public function test_generator_leaks_no_public_ip(): void
    {
        for ($seed = 0; $seed < 12; $seed++) {
            $energy = Energy::fromSeed($seed);
            $blob = json_encode([
                $energy->meters(), $energy->boards(), $energy->upsFleet(), $energy->generators(),
                $energy->solarStrings(), $energy->plant(), $energy->utilities(),
            ]);
            self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, (string) $blob, "seed $seed");
        }
    }

    public function test_ot_fabric_is_rfc1918(): void
    {
        self::assertStringStartsWith('10.20.31.', Energy::FC_SUBNET);
        self::assertSame('10.20.99.7', Energy::SNMP_TRAP_IP);
    }

    // --- section: rendering, depth, escaping, inertness ---

    public function test_landing_is_byte_identical_per_seed(): void
    {
        $s = new EnergySection();
        $p = VisualPersona::fromSeed(42);
        self::assertSame(
            $s->render($this->route(), $p, '/panel'),
            $s->render($this->route(), $p, '/panel'),
            'must be cache-safe (byte-identical per seed)'
        );
    }

    public function test_landing_shows_tiles_diagram_and_categories(): void
    {
        $html = (new EnergySection())->render($this->route(), VisualPersona::fromSeed(8), '/panel');
        self::assertStringContainsString('fp-breadcrumb', $html);
        self::assertStringContainsString('Building load', $html);
        self::assertStringContainsString('Electrical single-line', $html);
        self::assertStringContainsString('kWh', $html);
        self::assertStringContainsString('kg', $html);                       // carbon tile
        self::assertStringContainsString('fp-gauge', $html);
        self::assertStringContainsString('fp-sparkline', $html);
        self::assertSame(1, preg_match('#href="/panel/energy/meters"#', $html));
        self::assertSame(1, preg_match('#href="/panel/energy/ups"#', $html));
    }

    public function test_meters_list_paginates_searches_and_links(): void
    {
        $html = (new EnergySection())->render($this->route('meters'), VisualPersona::fromSeed(2), '/panel');
        self::assertStringContainsString('Sub-meters', $html);
        self::assertStringContainsString('energy-meter-search', $html);
        self::assertStringContainsString('page 1 /', $html);
        self::assertSame(1, preg_match('#href="/panel/energy/meters/MTR-[A-Z0-9-]+"#', $html));
    }

    public function test_meter_detail_has_subtabs(): void
    {
        $energy = Energy::fromSeed(9);
        $id = $energy->meters()[0]['id'];
        $html = (new EnergySection())->render($this->route('meters', $id), VisualPersona::fromSeed(9), '/panel');
        self::assertStringContainsString('alte-tabs', $html);
        self::assertStringContainsString('href="/panel/energy/meters/' . $id . '/trend"', $html);
        self::assertStringContainsString('href="/panel/energy/meters/' . $id . '/comms"', $html);
    }

    public function test_breaker_toggle_is_guarded_never_done(): void
    {
        $energy = Energy::fromSeed(3);
        $boardId = $energy->boards()[0]['id'];
        $html = (new EnergySection())->render($this->route('breakers', $boardId, 'toggle', '14'), VisualPersona::fromSeed(3), '/panel');
        self::assertStringContainsString('Denied', $html);
        self::assertStringContainsString('second', strtolower($html));       // awaiting second operator
        self::assertStringNotContainsString('applied', $html);
        self::assertStringNotContainsString('OPEN — done', $html);
    }

    public function test_breaker_arg_is_escaped_defense_in_depth(): void
    {
        $energy = Energy::fromSeed(1);
        $boardId = $energy->boards()[0]['id'];
        $html = (new EnergySection())->render(
            $this->route('breakers', $boardId, 'toggle', '<script>alert(1)</script>'),
            VisualPersona::fromSeed(1), '/panel'
        );
        self::assertStringNotContainsString('<script>alert(1)', $html);
    }

    public function test_generator_self_test_is_canned_and_start_is_pin_soft_deny(): void
    {
        $s = new EnergySection();
        $selfTest = $s->render($this->route('generator', 'GEN-01', 'self-test'), VisualPersona::fromSeed(4), '/panel');
        self::assertStringContainsString('Queued', $selfTest);
        self::assertStringNotContainsString('applied', $selfTest);

        $start = $s->render($this->route('generator', 'GEN-01', 'start'), VisualPersona::fromSeed(4), '/panel');
        self::assertStringContainsString('DENIED', $start);
        self::assertStringContainsString('PIN', $start);
        self::assertStringContainsString('HMI', $start);
    }

    public function test_ups_snmp_tab_exposes_the_hidden_trap_receiver(): void
    {
        $html = (new EnergySection())->render($this->route('ups', 'UPS-01', 'snmp'), VisualPersona::fromSeed(6), '/panel');
        self::assertStringContainsString('SNMP', $html);
        self::assertStringContainsString(Energy::SNMP_TRAP_IP, $html);       // the lone hidden-VLAN lure
    }

    public function test_solar_fault_links_a_work_order(): void
    {
        $energy = Energy::fromSeed(4);
        $faultId = $energy->solarSummary()['faultString'];
        self::assertNotSame('', $faultId);
        $html = (new EnergySection())->render($this->route('solar', $faultId), VisualPersona::fromSeed(4), '/panel');
        self::assertStringContainsString('Fault', $html);
        self::assertSame(1, preg_match('#href="/panel/facilities/work-orders/WO-2026-[0-9]+"#', $html));
    }

    public function test_gas_shutoff_is_break_glass_soft_deny(): void
    {
        $html = (new EnergySection())->render($this->route('utilities', 'gas', 'shutoff'), VisualPersona::fromSeed(7), '/panel');
        self::assertStringContainsString('DENIED', $html);
        self::assertStringContainsString('break-glass', $html);
    }

    public function test_demand_response_shed_denies_and_simulate_reports(): void
    {
        $s = new EnergySection();
        $shed = $s->render($this->route('demand-response', 'shed'), VisualPersona::fromSeed(5), '/panel');
        self::assertStringContainsString('HELD', $shed);
        self::assertStringNotContainsString('applied', $shed);

        $sim = $s->render($this->route('demand-response', 'simulate'), VisualPersona::fromSeed(5), '/panel');
        self::assertStringContainsString('simulation', strtolower($sim));
        self::assertStringContainsString('None', $sim);                      // no dispatch, nothing shed
    }

    public function test_plant_detail_cross_links_hvac(): void
    {
        $energy = Energy::fromSeed(3);
        $id = $energy->plant()[0]['id'];
        $html = (new EnergySection())->render($this->route('plant', $id), VisualPersona::fromSeed(3), '/panel');
        self::assertStringContainsString('href="/panel/hvac"', $html);
    }

    public function test_downloads_all_end_in_zip(): void
    {
        $s = new EnergySection();
        foreach (['bills', 'trends'] as $section) {
            $html = $s->render($this->route($section), VisualPersona::fromSeed(2), '/panel');
            preg_match_all('#href="/panel/energy/' . $section . '/download/([^"]+)"#', $html, $m);
            self::assertNotEmpty($m[1], "$section must offer downloads");
            foreach ($m[1] as $file) {
                self::assertStringEndsWith('.zip', $file, "$section download must end .zip");
            }
        }
    }

    public function test_no_public_ip_in_rendered_pages(): void
    {
        $s = new EnergySection();
        $energy = Energy::fromSeed(3);
        $meterId = $energy->meters()[0]['id'];
        $routes = [
            $this->route(),
            $this->route('meters'),
            $this->route('meters', $meterId, 'comms'),
            $this->route('breakers', $energy->boards()[0]['id']),
            $this->route('ups', 'UPS-01', 'snmp'),
            $this->route('generator', 'GEN-01'),
            $this->route('solar'),
            $this->route('bess'),
            $this->route('utilities', 'gas'),
            $this->route('plant'),
            $this->route('demand-response'),
            $this->route('alarms'),
        ];
        foreach ($routes as $r) {
            $html = $s->render($r, VisualPersona::fromSeed(3), '/panel');
            self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $html, 'route ' . $r['section']);
        }
    }
}
