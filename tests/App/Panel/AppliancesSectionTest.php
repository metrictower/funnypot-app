<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Appliances;
use Funnypot\App\Render\Fake\Building;
use Funnypot\App\Render\Panel\AppliancesSection;
use Funnypot\Core\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class AppliancesSectionTest extends TestCase
{
    /** Anything outside RFC1918 10.x is a leak of real routable space (SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    /** @return array{module:string,section:string,entity:string,subtab:string,action:string,arg:string,page:int,filter:string} */
    private function route(string $section = '', string $entity = '', string $subtab = '', string $action = '', int $page = 1): array
    {
        return [
            'module' => 'appliances', 'section' => $section, 'entity' => $entity, 'subtab' => $subtab,
            'action' => $action, 'arg' => '', 'page' => $page, 'filter' => $entity,
        ];
    }

    // --- generator: determinism, coherence, safety -------------------------

    public function test_generator_is_deterministic(): void
    {
        $a = Appliances::fromSeed(11);
        $b = Appliances::fromSeed(11);
        self::assertSame($a->coffeeMachines(), $b->coffeeMachines());
        self::assertSame($a->vendingMachines(), $b->vendingMachines());
        self::assertSame($a->kitchenAppliances(), $b->kitchenAppliances());
        self::assertSame($a->elevatorCars(), $b->elevatorCars());
        self::assertSame($a->signageScreens(), $b->signageScreens());
        self::assertSame($a->paZones(), $b->paZones());
        self::assertSame($a->summary(), $b->summary());
    }

    public function test_different_seeds_differ(): void
    {
        self::assertNotSame(Appliances::fromSeed(1)->coffeeMachines(), Appliances::fromSeed(2)->coffeeMachines());
    }

    public function test_lookup_is_byte_identical_to_list_row(): void
    {
        $a = Appliances::fromSeed(7);
        foreach ($a->coffeeMachines() as $m) {
            self::assertSame($m, $a->coffee($m['id']), 'coffee() must equal its list row');
            self::assertMatchesRegularExpression('/^[a-z0-9-]+$/', $m['id']);
        }
        foreach ($a->elevatorCars() as $c) {
            self::assertSame($c, $a->car($c['id']), 'car() must equal its list row');
            self::assertMatchesRegularExpression('/^[a-z0-9-]+$/', $c['id']);
        }
        foreach ($a->vendingMachines() as $v) {
            self::assertSame($v, $a->vending($v['id']));
        }
    }

    public function test_unknown_entity_still_renders_a_detail_not_a_404(): void
    {
        // Spec D.4: a fuzzed slug must still produce a plausible detail, never fall off the edge.
        $a = Appliances::fromSeed(3);
        self::assertSame('coffee-nope', $a->coffee('coffee-nope')['id']);
        self::assertSame('car-99', $a->car('car-99')['id']);
        self::assertArrayHasKey('setpoint', $a->coffee('coffee-nope'));
    }

    public function test_coffee_and_kitchen_live_in_a_real_building_room(): void
    {
        // Cross-coherence spine: every kitchen appliance names a real Building room id + floor code.
        for ($seed = 0; $seed < 6; $seed++) {
            $a = Appliances::fromSeed($seed);
            $b = Building::fromSeed($seed);
            $roomIds = [];
            $floorCodes = [];
            foreach ($b->floors() as $f) {
                $floorCodes[$f['code']] = true;
                foreach ($b->roomsFor($f['code']) as $r) {
                    $roomIds[$r['id']] = true;
                }
            }
            foreach ($a->coffeeMachines() as $m) {
                self::assertArrayHasKey($m['kitchenId'], $roomIds, "seed $seed coffee kitchenId is a real room");
                self::assertArrayHasKey($m['floor'], $floorCodes);
            }
            foreach ($a->elevatorCars() as $c) {
                self::assertArrayHasKey($c['currentFloor'], $floorCodes, "seed $seed car floor is a real floor code");
            }
        }
    }

    public function test_coffee_setpoint_is_within_range(): void
    {
        foreach (Appliances::fromSeed(5)->coffeeMachines() as $m) {
            self::assertGreaterThanOrEqual($m['tempMin'], $m['setpoint']);
            self::assertLessThanOrEqual($m['tempMax'], $m['setpoint']);
        }
    }

    public function test_flagship_entities_always_exist(): void
    {
        for ($seed = 0; $seed < 10; $seed++) {
            $a = Appliances::fromSeed($seed);
            self::assertNotEmpty($a->coffeeMachines(), "seed $seed coffee lure");
            self::assertNotEmpty($a->vendingMachines(), "seed $seed vending lure");
            self::assertNotEmpty($a->elevatorCars(), "seed $seed elevator lure");
            self::assertNotEmpty($a->signageScreens(), "seed $seed signage lure");
            // Every car carries the elevator-music player (the operator's named whimsy).
            foreach ($a->elevatorCars() as $c) {
                self::assertArrayHasKey('music', $c);
                self::assertNotSame('', $c['music']['nowTrack']);
            }
        }
    }

    public function test_generator_leaks_no_public_ip(): void
    {
        for ($seed = 0; $seed < 12; $seed++) {
            $a = Appliances::fromSeed($seed);
            $blob = json_encode([
                $a->coffeeMachines(), $a->vendingMachines(), $a->kitchenAppliances(),
                $a->elevatorCars(), $a->signageScreens(), $a->paZones(),
            ]);
            self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, (string) $blob, "seed $seed");
        }
    }

    // --- section: rendering, depth, escaping, inertness --------------------

    public function test_landing_is_byte_identical_per_seed(): void
    {
        $s = new AppliancesSection();
        $p = VisualPersona::fromSeed(42);
        self::assertSame($s->render($this->route(), $p, '/panel'), $s->render($this->route(), $p, '/panel'));
    }

    public function test_landing_shows_categories_and_breadcrumb(): void
    {
        $html = (new AppliancesSection())->render($this->route(), VisualPersona::fromSeed(8), '/panel');
        self::assertStringContainsString('fp-breadcrumb', $html);
        self::assertStringContainsString('Coffee machines', $html);
        self::assertStringContainsString('Elevator bank', $html);
        self::assertStringContainsString('Now playing', $html);
        self::assertSame(1, preg_match('#href="/panel/appliances/coffee/coffee-[a-z0-9-]+"#', $html));
        self::assertSame(1, preg_match('#href="/panel/appliances/elevators/car-[0-9]+"#', $html));
    }

    public function test_coffee_detail_has_gauges_setpoint_and_subtabs(): void
    {
        $a = Appliances::fromSeed(9);
        $id = $a->coffeeMachines()[0]['id'];
        $html = (new AppliancesSection())->render($this->route('coffee', $id), VisualPersona::fromSeed(9), '/panel');
        self::assertStringContainsString('fp-gauge', $html);
        self::assertStringContainsString('alte-tabs', $html);
        self::assertStringContainsString('Brew-boiler setpoint', $html);
        self::assertStringContainsString('href="/panel/appliances/coffee/' . $id . '/temp/', $html);
    }

    public function test_coffee_setpoint_leaf_is_an_inert_queued_receipt(): void
    {
        $a = Appliances::fromSeed(1);
        $id = $a->coffeeMachines()[0]['id'];
        $html = (new AppliancesSection())->render($this->route('coffee', $id, 'temp', '92'), VisualPersona::fromSeed(1), '/panel');
        self::assertStringContainsString('Queued', $html);
        self::assertStringContainsString('92', $html);
        self::assertStringNotContainsString('applied', $html);
    }

    public function test_elevator_music_tab_is_deep_and_inert(): void
    {
        $a = Appliances::fromSeed(4);
        $id = $a->elevatorCars()[0]['id'];
        $html = (new AppliancesSection())->render($this->route('elevators', $id, 'music'), VisualPersona::fromSeed(4), '/panel');
        self::assertStringContainsString('Now playing', $html);
        self::assertStringContainsString('href="/panel/appliances/elevators/' . $id . '/vol/', $html);
        self::assertStringContainsString('href="/panel/appliances/elevators/' . $id . '/skip/next"', $html);
        // The playlist export decoy preserves its extension so it routes to the decoy-archive handler.
        self::assertStringContainsString('.m3u.zip', $html);
    }

    public function test_elevator_music_volume_leaf_is_canned(): void
    {
        $a = Appliances::fromSeed(2);
        $id = $a->elevatorCars()[0]['id'];
        $html = (new AppliancesSection())->render($this->route('elevators', $id, 'vol', '45'), VisualPersona::fromSeed(2), '/panel');
        self::assertStringContainsString('Queued', $html);
        self::assertStringContainsString('Music volume', $html);
    }

    public function test_signage_message_and_pa_broadcast_are_canned_and_do_not_reflect(): void
    {
        $s = new AppliancesSection();
        $signHtml = $s->render($this->route('signage', 'all', 'message'), VisualPersona::fromSeed(6), '/panel');
        self::assertStringContainsString('Message pushed', $signHtml);
        self::assertStringContainsString('screens', $signHtml);
        $paHtml = $s->render($this->route('pa', 'broadcast'), VisualPersona::fromSeed(6), '/panel');
        self::assertStringContainsString('Page queued', $paHtml);
    }

    public function test_vending_payment_shows_masked_test_card_only(): void
    {
        $a = Appliances::fromSeed(3);
        $id = $a->vendingMachines()[0]['id'];
        $html = (new AppliancesSection())->render($this->route('vending', $id, 'payment'), VisualPersona::fromSeed(3), '/panel');
        self::assertStringContainsString('4242', $html);
        self::assertStringContainsString('Cashless payment', $html);
        // A masked pan is only ever the last four — no full card number reaches the page.
        self::assertSame(0, preg_match('/\b\d{13,16}\b/', $html), 'no full PAN in the payment tab');
    }

    public function test_control_arg_is_escaped_defense_in_depth(): void
    {
        // PanelRoute slugifies slots in production, but the receipt must still escape the arg it echoes.
        $a = Appliances::fromSeed(1);
        $id = $a->coffeeMachines()[0]['id'];
        $html = (new AppliancesSection())->render(
            $this->route('coffee', $id, 'temp', '<script>alert(1)</script>'),
            VisualPersona::fromSeed(1), '/panel'
        );
        self::assertStringNotContainsString('<script>alert(1)', $html);
    }

    public function test_no_public_ip_in_rendered_pages(): void
    {
        $s = new AppliancesSection();
        $a = Appliances::fromSeed(3);
        $coffee = $a->coffeeMachines()[0]['id'];
        $car = $a->elevatorCars()[0]['id'];
        $vend = $a->vendingMachines()[0]['id'];
        $sign = $a->signageScreens()[0]['id'];
        $routes = [
            $this->route(),
            $this->route('coffee'),
            $this->route('coffee', $coffee),
            $this->route('vending', $vend, 'planogram'),
            $this->route('vending', $vend, 'payment'),
            $this->route('kitchen'),
            $this->route('elevators', $car),
            $this->route('elevators', $car, 'music'),
            $this->route('signage', $sign),
            $this->route('pa'),
        ];
        foreach ($routes as $r) {
            $html = $s->render($r, VisualPersona::fromSeed(3), '/panel');
            self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $html, 'route ' . $r['section'] . '/' . $r['entity'] . '/' . $r['subtab']);
        }
    }

    public function test_elevator_trip_floors_are_all_real_building_floors(): void
    {
        $s = new AppliancesSection();
        foreach ([1, 2, 3, 7, 15] as $seed) {
            $appl = Appliances::fromSeed($seed);
            $valid = $appl->floorCodes();
            self::assertNotEmpty($valid, "seed $seed must have a floor stack");
            foreach ($appl->elevatorCars() as $car) {
                $html = $s->render($this->route('elevators', $car['id'], 'trips'), VisualPersona::fromSeed($seed), '/panel');
                self::assertStringContainsString('Recent trips', $html);
                preg_match_all('/call (\S+) → (\S+) /u', $html, $m);
                $floors = array_merge($m[1], $m[2]);
                self::assertNotEmpty($floors, "seed $seed car {$car['id']} must log trips");
                foreach ($floors as $f) {
                    self::assertContains($f, $valid, "seed $seed: elevator trip names floor '$f' which is not in the building's floor stack");
                }
            }
        }
    }

    public function test_deep_pages_render_without_php_warnings(): void
    {
        set_error_handler(static function (int $severity, string $message): bool {
            throw new \RuntimeException('PHP warning/notice: ' . $message);
        });
        try {
            $s = new AppliancesSection();
            $a = Appliances::fromSeed(4);
            $car = $a->elevatorCars()[0]['id'];
            foreach ([
                $this->route(),
                $this->route('coffee', $a->coffeeMachines()[0]['id'], 'maintenance'),
                $this->route('elevators', $car, 'trips'),
                $this->route('elevators', $car, 'maintenance'),
                $this->route('kitchen', $a->kitchenAppliances()[0]['id']),
                $this->route('signage'),
                $this->route('pa', $a->paZones()[1]['id']),
            ] as $r) {
                self::assertNotSame('', $s->render($r, VisualPersona::fromSeed(4), '/panel'));
            }
        } finally {
            restore_error_handler();
        }
    }
}
