<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Building;
use Funnypot\App\Render\Fake\Facilities;
use Funnypot\App\Render\Fake\Org;
use Funnypot\App\Render\Panel\FacilitiesSection;
use Funnypot\App\Render\PanelRoute;
use Funnypot\App\Render\VisualPersona;
use PHPUnit\Framework\TestCase;

final class FacilitiesSectionTest extends TestCase
{
    /** Any address outside RFC1918 10.x is a leak of real routable space (spec SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    /** Render a panel path through the section exactly as the skin would (parse -> render). */
    private function render(string $path, int $seed = 7): string
    {
        $route = PanelRoute::parse($path);
        return (new FacilitiesSection())->render($route, VisualPersona::fromSeed($seed), '/admin');
    }

    // --- routing / depth ---

    public function test_hub_shows_tiles_floorplan_and_jump_links(): void
    {
        $html = $this->render('/admin/facilities');
        self::assertStringContainsString('Facilities', $html);
        self::assertStringContainsString('Open work orders', $html);
        self::assertStringContainsString('Building map', $html);
        // The hub embeds a floorplan SVG whose room rects link into rooms.
        self::assertStringContainsString('<svg', $html);
        self::assertStringContainsString('href="/admin/facilities/rooms/room-', $html);
    }

    public function test_floorplan_view_renders_selector_and_room_rects(): void
    {
        $html = $this->render('/admin/facilities/floorplan');
        self::assertStringContainsString('<svg', $html);
        self::assertStringContainsString('<rect', $html);
        self::assertStringContainsString('href="/admin/facilities/rooms/room-', $html);
        // A specific floor is reachable and still renders a map.
        $g = $this->render('/admin/facilities/floorplan/g');
        self::assertStringContainsString('<svg', $g);
    }

    public function test_rooms_list_uses_pager(): void
    {
        $html = $this->render('/admin/facilities/rooms');
        self::assertStringContainsString('page 1 /', $html);
        self::assertStringContainsString('href="/admin/facilities/rooms/room-', $html);
    }

    public function test_room_detail_subtabs_render(): void
    {
        // A real Building room on the ground-ish first floor.
        $roomId = Building::fromSeed(7)->roomsFor(Building::fromSeed(7)->floors()[0]['code'])[0]['id'];
        foreach (['', '/devices'] as $sub) {
            $html = $this->render('/admin/facilities/rooms/' . $roomId . $sub);
            self::assertStringContainsString('alte-card', $html, "subtab $sub");
            self::assertNotSame('', trim($html), "subtab $sub non-empty");
        }
    }

    public function test_bare_rooms_link_serves_room_detail(): void
    {
        // Sensors/CCTV emit `$navBase/rooms/<id>` — the deferred link this module closes.
        $roomId = Building::fromSeed(7)->roomsFor(Building::fromSeed(7)->floors()[0]['code'])[0]['id'];
        $html = $this->render('/admin/rooms/' . $roomId);
        self::assertStringContainsString('alte-card', $html);
        self::assertStringContainsString('Room id', $html);
    }

    public function test_unknown_room_slug_still_renders_a_plausible_detail(): void
    {
        // A fuzzed slug must not dead-end (a 404 inside a deep panel is a tell).
        $html = $this->render('/admin/facilities/rooms/room-does-not-exist-9999');
        self::assertStringContainsString('alte-card', $html);
        self::assertStringContainsString('Raise work order', $html);
    }

    public function test_bookings_landing_and_calendar_render(): void
    {
        $landing = $this->render('/admin/facilities/bookings');
        self::assertStringContainsString('Meeting rooms', $landing);
        // Pick a bookable room and render its calendar.
        $mr = Facilities::fromSeed(7)->meetingRooms();
        self::assertNotSame([], $mr, 'a building has at least one bookable room');
        $cal = $this->render('/admin/facilities/bookings/' . $mr[0]['id']);
        self::assertStringContainsString('Bookings', $cal);
        self::assertStringContainsString('Time', $cal);          // calendar grid header
    }

    public function test_work_orders_list_paginates(): void
    {
        $p1 = $this->render('/admin/facilities/work-orders');
        $p2 = $this->render('/admin/facilities/work-orders/p2');
        self::assertStringContainsString('page 1 /', $p1);
        self::assertStringContainsString('page 2 /', $p2);
        self::assertNotSame($p1, $p2, 'different pages render different rows');
        self::assertStringContainsString('href="/admin/facilities/work-orders/wo-2026-', $p1);
    }

    public function test_work_order_detail_from_deferred_link_renders(): void
    {
        // HVAC/sensors/energy emit `$navBase/facilities/work-orders/WO-2026-######`.
        $html = $this->render('/admin/facilities/work-orders/WO-2026-004821');
        self::assertStringContainsString('WO-2026-004821', $html);
        self::assertStringContainsString('Linked asset', $html);
        self::assertStringContainsString('See also', $html);
        // Notes thread + attachments.
        self::assertStringContainsString('<pre', $html);
        self::assertStringContainsString('.pdf.zip', $html);
    }

    public function test_work_order_id_reconciles_regardless_of_case(): void
    {
        // The same WO id renders identically whether reached upper- or lower-cased (coherence: a fault
        // link from another module and the list must resolve to the same order).
        $a = Facilities::fromSeed(7)->workOrder('WO-2026-004821');
        $b = Facilities::fromSeed(7)->workOrder('wo-2026-004821');
        self::assertSame($a, $b);
        self::assertSame('WO-2026-004821', $a['id']);
    }

    // --- inert-control behaviour ---

    public function test_room_controls_are_canned_queues(): void
    {
        $roomId = Facilities::fromSeed(7)->meetingRooms()[0]['id'];
        foreach (['raise-wo', 'book'] as $verb) {
            $html = $this->render('/admin/facilities/rooms/' . $roomId . '/' . $verb);
            self::assertStringContainsString('Queued', $html, $verb);
            self::assertStringContainsString('FAC-CMD-', $html, $verb);
        }
    }

    public function test_work_order_controls_are_canned_queues(): void
    {
        foreach (['add-note', 'reassign', 'close'] as $verb) {
            $html = $this->render('/admin/facilities/work-orders/wo-2026-004821/' . $verb);
            self::assertStringContainsString('Queued', $html, $verb);
            self::assertStringContainsString('FAC-CMD-', $html, $verb);
        }
    }

    public function test_no_control_path_emits_a_raw_script_injection(): void
    {
        // Slugging strips angle brackets before routing; nothing reflected can break out of HTML.
        $html = $this->render('/admin/facilities/rooms/%3Cscript%3Ealert(1)%3C%2Fscript%3E');
        self::assertStringNotContainsString('<script>alert', $html);
    }

    // --- determinism + safety invariants ---

    public function test_same_url_is_byte_identical(): void
    {
        $paths = [
            '/admin/facilities',
            '/admin/facilities/floorplan/g',
            '/admin/facilities/rooms',
            '/admin/facilities/work-orders/p3',
            '/admin/facilities/work-orders/wo-2026-004821',
            '/admin/facilities/bookings',
        ];
        foreach ($paths as $p) {
            self::assertSame($this->render($p, 11), $this->render($p, 11), "stable: $p");
        }
    }

    public function test_no_public_ip_in_any_view(): void
    {
        $mr = Facilities::fromSeed(3)->meetingRooms();
        $roomId = $mr === [] ? 'room-g-01' : $mr[0]['id'];
        $paths = [
            '/admin/facilities',
            '/admin/facilities/floorplan',
            '/admin/facilities/rooms',
            '/admin/facilities/rooms/' . $roomId,
            '/admin/facilities/rooms/' . $roomId . '/devices',
            '/admin/facilities/bookings/' . $roomId,
            '/admin/facilities/work-orders',
            '/admin/facilities/work-orders/wo-2026-004821',
        ];
        for ($seed = 0; $seed < 8; $seed++) {
            foreach ($paths as $p) {
                self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $this->render($p, $seed), "seed $seed path $p");
            }
        }
    }

    // --- cross-coherence with the Building/Org spines ---

    public function test_room_devices_reconcile_with_building(): void
    {
        $building = Building::fromSeed(7);
        // Find a device and confirm the room's device list + the rendered detail agree with Building.
        $device = $building->devices()[0];
        $fac = Facilities::fromSeed(7);
        $ids = array_column($fac->devicesInRoom($device['room']), 'id');
        self::assertContains($device['id'], $ids, 'a Building device appears in its room');

        $html = $this->render('/admin/facilities/rooms/' . $device['room'] . '/devices');
        $module = ['climate' => 'hvac', 'light' => 'lighting', 'cover' => 'lighting',
                   'sensor' => 'sensors', 'lock' => 'access', 'camera' => 'cctv'][$device['domain']] ?? 'sensors';
        self::assertStringContainsString('href="/admin/' . $module . '/' . $device['id'] . '"', $html,
            'device cross-links into its domain module');
    }

    public function test_booking_organiser_is_an_org_person(): void
    {
        $fac = Facilities::fromSeed(7);
        $org = Org::fromSeed(7, VisualPersona::fromSeed(7)->domain());
        $names = array_column($org->people($org->headcount()), 'name');

        $mr = $fac->meetingRooms();
        self::assertNotSame([], $mr);
        $bookings = $fac->bookings($mr[0]['id']);
        self::assertNotSame([], $bookings);
        foreach ($bookings as $b) {
            // Interview titles carry a candidate name; the organiser is always a roster member.
            self::assertContains($b['organizer'], $names, 'organiser is on the Org roster');
        }
    }

    public function test_floorplan_room_hrefs_are_real_building_rooms(): void
    {
        $building = Building::fromSeed(7);
        $floor = $building->floors()[0]['code'];
        $realIds = array_column($building->roomsFor($floor), 'id');
        $html = $this->render('/admin/facilities/floorplan/' . strtolower($floor));
        foreach ($realIds as $id) {
            self::assertStringContainsString('/admin/facilities/rooms/' . $id . '"', $html, "map links room $id");
        }
    }

    public function test_work_order_assignee_and_asset_are_coherent(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $fac = Facilities::fromSeed($seed);
            $wo = $fac->workOrder('WO-2026-004821');
            self::assertContains($wo['priority'], ['P1', 'P2', 'P3', 'P4'], "seed $seed priority");
            self::assertMatchesRegularExpression('/^[a-z0-9-]+$/', $wo['assetRoomId'], "seed $seed asset room id is a slug");
            self::assertStringStartsWith('FM-', $wo['seeAlso'], "seed $seed see-also cross-ref");
        }
    }

    public function test_generator_is_deterministic(): void
    {
        $a = Facilities::fromSeed(5);
        $b = Facilities::fromSeed(5);
        self::assertSame($a->summary(), $b->summary());
        self::assertSame($a->workOrderPage(0, 20), $b->workOrderPage(0, 20));
        self::assertSame($a->roomsPage(0, 20), $b->roomsPage(0, 20));
    }

    public function test_fault_room_work_order_names_that_same_room(): void
    {
        // The room detail claims "Open fault on this room — work order WO-…"; the linked order derives its
        // room from its id alone, so the order chosen for a fault room must resolve back to that room.
        $seenFault = false;
        for ($seed = 0; $seed < 8; $seed++) {
            $fac = Facilities::fromSeed($seed);
            foreach ($fac->floors() as $f) {
                foreach ($fac->roomsOnFloor($f['code']) as $r) {
                    if ($r['status'] !== 'fault') {
                        continue;
                    }
                    $seenFault = true;
                    $wo = $fac->workOrderForRoom($r['id']);
                    self::assertSame($r['id'], $wo['assetRoomId'], "seed $seed WO for {$r['id']} names that room");
                }
            }
        }
        self::assertTrue($seenFault, 'at least one fault room must exist across the sampled seeds');
    }

    public function test_work_order_list_ids_are_all_distinct(): void
    {
        // workOrderIdAt() must be injective — duplicate ids across list rows would be an obvious tell.
        for ($seed = 0; $seed < 4; $seed++) {
            $fac = Facilities::fromSeed($seed);
            $total = $fac->workOrderCount();
            $ids = [];
            foreach ($fac->workOrderPage(0, $total) as $row) {
                $ids[$row['id']] = true;
            }
            self::assertCount($total, $ids, "seed $seed work-order ids all distinct");
        }
    }
}
