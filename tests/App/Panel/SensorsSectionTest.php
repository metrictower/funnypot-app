<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Sensors;
use Funnypot\App\Render\Panel\SensorsSection;
use Funnypot\Core\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class SensorsSectionTest extends TestCase
{
    /** Anything outside RFC1918 10.x is a leak of real routable space (SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    /** @return array{module:string,section:string,entity:string,subtab:string,action:string,arg:string,page:int,filter:string} */
    private function route(string $section = '', string $entity = '', int $page = 1): array
    {
        return [
            'module' => 'sensors', 'section' => $section, 'entity' => $entity, 'subtab' => '',
            'action' => '', 'arg' => '', 'page' => $page, 'filter' => $entity,
        ];
    }

    // --- generator: determinism, coherence, safety ---

    public function test_generator_is_deterministic(): void
    {
        $a = Sensors::fromSeed(11);
        $b = Sensors::fromSeed(11);
        self::assertSame($a->sensors(), $b->sensors());
        self::assertSame($a->summary(), $b->summary());
        self::assertSame($a->history($a->sensors()[0]), $b->history($b->sensors()[0]));
        self::assertSame($a->points($a->sensors()[0]), $b->points($b->sensors()[0]));
    }

    public function test_different_seeds_differ(): void
    {
        self::assertNotSame(Sensors::fromSeed(1)->sensors(), Sensors::fromSeed(2)->sensors());
    }

    public function test_estate_is_genuinely_hundreds_of_entities(): void
    {
        // The whole point of this module is cheap breadth — every seed should yield hundreds of rows.
        for ($seed = 0; $seed < 8; $seed++) {
            self::assertGreaterThan(150, count(Sensors::fromSeed($seed)->sensors()), "seed $seed breadth");
        }
    }

    public function test_sensor_lookup_matches_list_row(): void
    {
        $sensors = Sensors::fromSeed(7);
        foreach (array_slice($sensors->sensors(), 0, 40) as $s) {
            self::assertSame($s, $sensors->sensor($s['id']), 'sensor() must be byte-identical to its sensors() row');
            self::assertMatchesRegularExpression('/^sn-[a-z0-9-]+$/', $s['id'], 'sensor id must be a slug');
        }
    }

    public function test_unknown_sensor_still_renders_a_sensor_not_a_404(): void
    {
        // Spec D.4: a fuzzed slug must still produce a plausible detail, never fall off the edge.
        $s = Sensors::fromSeed(3)->sensor('sn-temp-does-not-exist');
        self::assertSame('sn-temp-does-not-exist', $s['id']);
        self::assertArrayHasKey('value', $s);
        self::assertArrayHasKey('controllerIp', $s);
    }

    public function test_every_sensor_binds_to_a_real_building_room(): void
    {
        // Cross-coherence: each sensor names a real room id + zone + a BMS controller on the OT fabric.
        $sensors = Sensors::fromSeed(9);
        foreach ($sensors->sensors() as $s) {
            self::assertMatchesRegularExpression('/^room-[a-z0-9-]+$/', $s['roomId'], 'room id must be a Building slug');
            self::assertContains($s['zone'], ['N', 'E', 'S', 'W', 'Core']);
            self::assertStringStartsWith('BMS-CTRL-', $s['controller']);
            self::assertStringStartsWith('10.0.50.', $s['controllerIp']);
        }
    }

    public function test_entity_ids_are_unique_per_floor(): void
    {
        // HA entity_ids are unique by definition — two sensors sharing one would unmask the page. The
        // id must stay distinct within a floor (where floor+zone+class alone used to collide across rooms).
        for ($seed = 0; $seed < 6; $seed++) {
            $byFloor = [];
            foreach (Sensors::fromSeed($seed)->sensors() as $s) {
                $byFloor[$s['floor']][] = $s['entityId'];
            }
            foreach ($byFloor as $floor => $ids) {
                self::assertSame(
                    count($ids),
                    count(array_unique($ids)),
                    "seed $seed floor $floor has duplicate entity_ids"
                );
            }
        }
    }

    public function test_numeric_units_match_device_class(): void
    {
        $sensors = Sensors::fromSeed(5);
        $want = ['temperature' => '°C', 'humidity' => '%', 'carbon-dioxide' => 'ppm',
                 'pm25' => 'µg/m³', 'illuminance' => 'lx', 'power' => 'W'];
        foreach ($sensors->sensors() as $s) {
            if (isset($want[$s['class']])) {
                self::assertSame($want[$s['class']], $s['unit'], $s['class'] . ' unit');
                self::assertStringContainsString($want[$s['class']], (string) $s['value']);
            }
        }
    }

    public function test_leak_budget_is_at_most_one_wet_and_smoke_never_fires(): void
    {
        for ($seed = 0; $seed < 25; $seed++) {
            $wet = 0;
            foreach (Sensors::fromSeed($seed)->sensors() as $s) {
                if ($s['class'] === 'moisture' && $s['value'] === 'Wet') {
                    $wet++;
                    self::assertSame('Server-Comms', $s['roomType'], "seed $seed: a wet leak must be the planted server-room one");
                    self::assertNotSame('', $s['workOrder'], 'a planted leak must reference a work order');
                }
                // Smoke is read-only here and must never read as a live alarm (Fire module owns that).
                if ($s['class'] === 'smoke') {
                    self::assertSame('Clear', $s['value'], "seed $seed: smoke must never fire in the sensor plane");
                }
            }
            self::assertLessThanOrEqual(1, $wet, "seed $seed leak budget");
        }
    }

    public function test_generator_leaks_no_public_ip(): void
    {
        for ($seed = 0; $seed < 12; $seed++) {
            $sensors = Sensors::fromSeed($seed);
            $blob = json_encode($sensors->sensors());
            self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, (string) $blob, "seed $seed");
        }
    }

    // --- section: rendering, depth, escaping, read-only ---

    public function test_landing_is_byte_identical_per_seed(): void
    {
        $s = new SensorsSection();
        $p = VisualPersona::fromSeed(42);
        $a = $s->render($this->route(), $p, '/panel');
        $b = $s->render($this->route(), $p, '/panel');
        self::assertSame($a, $b, 'must be cache-safe (byte-identical per seed)');
    }

    public function test_landing_shows_tiles_gauges_chips_and_list(): void
    {
        $html = (new SensorsSection())->render($this->route(), VisualPersona::fromSeed(8), '/panel');
        self::assertStringContainsString('fp-breadcrumb', $html);
        self::assertStringContainsString('fp-gauge', $html);                       // summary gauge widget
        self::assertStringContainsString('All sensors', $html);
        self::assertStringContainsString('href="/panel/sensors/class/temperature"', $html);  // class filter chip
        self::assertSame(1, preg_match('#href="/panel/sensors/sn-[a-z0-9-]+"#', $html));      // a row links deeper
    }

    public function test_class_filter_lists_only_that_class(): void
    {
        $html = (new SensorsSection())->render($this->route('class', 'humidity'), VisualPersona::fromSeed(4), '/panel');
        self::assertStringContainsString('Humidity sensors', $html);
        self::assertStringContainsString('fp-breadcrumb', $html);
        // Deep pagination link stays under the filter base.
        self::assertSame(1, preg_match('#href="/panel/sensors/class/humidity/p2"#', $html));
    }

    public function test_floor_filter_lists_only_that_floor(): void
    {
        $sensors = Sensors::fromSeed(6);
        $floor = strtolower((string) $sensors->sensors()[0]['floor']);
        $html = (new SensorsSection())->render($this->route('floor', $floor), VisualPersona::fromSeed(6), '/panel');
        self::assertStringContainsString('sensors', $html);
        self::assertStringContainsString('fp-breadcrumb', $html);
    }

    public function test_numeric_detail_has_gauge_history_and_subtabs(): void
    {
        $sensors = Sensors::fromSeed(9);
        $id = $this->firstOfKind($sensors, 'numeric');
        $html = (new SensorsSection())->render($this->route($id), VisualPersona::fromSeed(9), '/panel');
        self::assertStringContainsString('fp-gauge', $html);
        self::assertStringContainsString('fp-sparkline', $html);                   // 24h trend on overview
        self::assertStringContainsString('alte-tabs', $html);
        self::assertStringContainsString('href="/panel/sensors/' . $id . '/history"', $html);
        self::assertStringContainsString('href="/panel/sensors/' . $id . '/points"', $html);
    }

    public function test_binary_detail_shows_a_state_pill_not_a_gauge(): void
    {
        $sensors = Sensors::fromSeed(9);
        $id = $this->firstOfKind($sensors, 'binary');
        $html = (new SensorsSection())->render($this->route($id), VisualPersona::fromSeed(9), '/panel');
        self::assertStringContainsString('fp-pill', $html);
        self::assertStringContainsString('Sensor state', $html);
    }

    public function test_history_subtab_renders_sparkline_and_readings(): void
    {
        $sensors = Sensors::fromSeed(2);
        $id = $this->firstOfKind($sensors, 'numeric');
        $html = (new SensorsSection())->render($this->route($id, 'history'), VisualPersona::fromSeed(2), '/panel');
        self::assertStringContainsString('fp-sparkline', $html);
        self::assertStringContainsString('Hourly readings', $html);
    }

    public function test_points_subtab_lists_bms_points_on_rfc1918_host(): void
    {
        $sensors = Sensors::fromSeed(2);
        $id = $this->firstOfKind($sensors, 'numeric');
        $html = (new SensorsSection())->render($this->route($id, 'points'), VisualPersona::fromSeed(2), '/panel');
        self::assertStringContainsString('BMS points', $html);
        self::assertStringContainsString(':' . Sensors::BACNET_PORT, $html);
        self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $html);
    }

    public function test_detail_is_read_only_no_control_leaf(): void
    {
        // Read-only module: no control verb should ever appear as a link target.
        $sensors = Sensors::fromSeed(3);
        $id = $this->firstOfKind($sensors, 'numeric');
        $html = (new SensorsSection())->render($this->route($id), VisualPersona::fromSeed(3), '/panel');
        self::assertStringNotContainsString('/set/', $html);
        self::assertStringNotContainsString('Queued', $html);
        self::assertStringNotContainsString('controlResult', $html);
    }

    public function test_unknown_slug_renders_detail_defense_in_depth_escaping(): void
    {
        // PanelRoute slugifies in production, but the detail must still escape any echoed id/value.
        $html = (new SensorsSection())->render(
            $this->route('sn-temp-<script>alert(1)</script>'),
            VisualPersona::fromSeed(1), '/panel'
        );
        self::assertStringNotContainsString('<script>alert(1)', $html);
    }

    public function test_planted_leak_surfaces_a_banner_and_work_order(): void
    {
        // Find a seed whose building plants the server-room leak, then assert the lure renders.
        $seed = $this->seedWithLeak();
        if ($seed === -1) {
            self::markTestSkipped('no leak-planting seed in the scanned range');
        }
        $html = (new SensorsSection())->render($this->route(), VisualPersona::fromSeed($seed), '/panel');
        self::assertStringContainsString('Water leak', $html);
        self::assertSame(1, preg_match('#href="/panel/facilities/work-orders/WO-2026-[0-9]{6}"#', $html));
    }

    public function test_no_public_ip_in_rendered_pages(): void
    {
        $s = new SensorsSection();
        $sensors = Sensors::fromSeed(3);
        $id = $sensors->sensors()[0]['id'];
        foreach ([$this->route(), $this->route($id), $this->route($id, 'points'), $this->route('class', 'power')] as $r) {
            $html = $s->render($r, VisualPersona::fromSeed(3), '/panel');
            self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $html);
        }
    }

    // --- helpers ---

    private function firstOfKind(Sensors $sensors, string $kind): string
    {
        foreach ($sensors->sensors() as $s) {
            if ($s['kind'] === $kind) {
                return (string) $s['id'];
            }
        }
        self::fail("no $kind sensor in estate");
    }

    private function seedWithLeak(): int
    {
        for ($seed = 0; $seed < 40; $seed++) {
            foreach (Sensors::fromSeed($seed)->sensors() as $s) {
                if ($s['class'] === 'moisture' && $s['value'] === 'Wet') {
                    return $seed;
                }
            }
        }
        return -1;
    }
}
