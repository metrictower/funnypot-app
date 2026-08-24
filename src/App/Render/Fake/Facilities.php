<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT facilities view for the deep office panel — the spatial index (floors/rooms),
 * meeting-room bookings and the maintenance work-order backlog. Like Access it is a VIEW over the two
 * coherence spines rather than a new fabric: rooms and their devices/controllers come from `Building`
 * (a room names the same floor/zone/type and its devices name the same `10.0.x` controllers seen in the
 * HVAC/lighting/access/CCTV modules), and booking organisers + work-order assignees come from the `Org`
 * roster, so the same room, device and person appear identically wherever facilities cross-references them.
 *
 * Work orders are the fault-chain hub: a planted anomaly elsewhere (a leak sensor, a dirty filter, a dead
 * sub-meter, a solar-string fault) mints a `WO-YYYY-NNNNNN` id that links here. workOrder() derives a
 * work order purely from that id's number, so the SAME id renders a byte-identical detail whether the
 * attacker reaches it from the sensor module or from the work-order list — and most such orders read one
 * step short ("awaiting parts / awaiting contractor") with a "see also FM-####" cross-ref that leads on
 * to another order, a small seeded graph you can walk for a long time without ever closing the loop.
 *
 * Design rules (deep-admin dashboard spec §C.1/§C.9 + adversarial critique):
 *  - DETERMINISTIC per seed: every value is hash(seed+slot) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); all civil dates/ages derive from the one FrozenClock epoch, so a
 *    static reload is byte-identical and never a tell.
 *  - COHERENT: rooms/devices reconcile to the Building topology; organisers/assignees to the Org roster.
 *  - SAFE: all controller addressing RFC1918 (via Building); people fabricated; vendor firms invented,
 *    never a real trademark; no scanner-signature strings (invented ids only).
 *  - ANOMALY BUDGET: only a small minority of rooms read "fault" and only a slice of work orders sit in
 *    an "awaiting" state; most render clean — a buffet of faults reads as staged.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf, no enums/promotion/str_contains/named-args) so a fact
 *    can promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders, masks and escapes it.
 */
final class Facilities
{
    /** Frozen "now" for ages/dates so a static reload is not a tell. Matches Building/Org/Access. */
    const DEPLOY_EPOCH = FrozenClock::EPOCH;

    /** All-time work-order backlog size the list paginates over (seeded per deploy, within scale). */
    const WORKORDER_TOTAL_MIN = 240;
    const WORKORDER_TOTAL_MAX = 900;

    /** @var int */
    private $seed;

    /** @var Building */
    private $building;

    /** @var Org */
    private $org;

    /** @var array<int,array>|null cached roster chunk so bookings/assignees stay cheap */
    private $rosterCache = null;

    private function __construct(int $seed, string $personaDomain)
    {
        $this->seed = $seed;
        $this->building = Building::fromSeed($seed);
        $this->org = Org::fromSeed($seed, $personaDomain);
    }

    public static function fromSeed(int $seed, string $personaDomain = ''): self
    {
        return new self($seed, $personaDomain);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|fac|' . $salt), 0, 15));
    }

    /** @param list<string> $options */
    private function pick(array $options, string $salt): string
    {
        return $options[$this->h($salt) % count($options)];
    }

    private function intIn(int $min, int $max, string $salt): int
    {
        return $min + ($this->h($salt) % (($max - $min) + 1));
    }

    /** Seeded "N ago" string off DEPLOY_EPOCH — deterministic, never time()/date(). */
    private function ageAgo(string $salt): string
    {
        $sec = $this->intIn(60, 172800, $salt);          // 1 min .. 2 days
        if ($sec < 5400) {
            return (int) round($sec / 60) . ' min ago';
        }
        if ($sec < 172800) {
            return (int) round($sec / 3600) . ' h ago';
        }
        return (int) round($sec / 86400) . ' d ago';
    }

    /** A YYYY-MM-DD $days days before the frozen "today" (deterministic, integer arithmetic). */
    private function daysAgoYmd(int $days): string
    {
        return FrozenClock::ymdFromDays(FrozenClock::nowDays() - $days);
    }

    /** The roster chunk booking organisers / assignees are drawn from (bounded, cached). */
    private function roster(): array
    {
        if ($this->rosterCache === null) {
            $n = $this->org->headcount();
            $this->rosterCache = $this->org->people($n < 80 ? $n : 80);
        }
        return $this->rosterCache;
    }

    /** One roster person keyed by an arbitrary salt (wraps to the chunk). */
    private function personFor(string $salt): array
    {
        $roster = $this->roster();
        return $roster[$this->h($salt) % count($roster)];
    }

    // --- site + facilities dashboard ---

    /** Passthrough to the Building site identity (name/address/floors/rooms/design occupancy). */
    public function site(): array
    {
        return $this->building->site();
    }

    /** @return list<array{code:string,label:string,index:int,zones:list<string>,capacity:int}> */
    public function floors(): array
    {
        return $this->building->floors();
    }

    /**
     * Reconciled facilities headline counts for the dashboard tiles. Occupancy is summed from the same
     * per-room status the floorplan paints, so the tile and the map never disagree.
     *
     * @return array{occupied:int,occupancyDesign:int,zonesTotal:int,zonesInComfort:int,openWorkOrders:int,activeAlarms:int,energyKw:int,doorsUnsecured:int,camerasOnline:int,camerasTotal:int,roomsFree:int,meetingTotal:int}
     */
    public function summary(): array
    {
        $site = $this->site();
        $occupied = 0;
        $meetingTotal = 0;
        $roomsFree = 0;
        $devicesCamera = 0;
        foreach ($this->floors() as $f) {
            foreach ($this->roomsOnFloor($f['code']) as $r) {
                $occupied += $r['occupants'];
                if ($r['bookable']) {
                    $meetingTotal++;
                    if ($r['status'] !== 'occupied') {
                        $roomsFree++;
                    }
                }
            }
        }
        foreach ($this->building->devices() as $d) {
            if ($d['domain'] === 'camera') {
                $devicesCamera++;
            }
        }
        $zonesTotal = 0;
        foreach ($this->floors() as $f) {
            $zonesTotal += count($f['zones']);
        }
        $zonesFault = $this->intIn(0, 3, 'zonesfault');
        $camerasDown = $this->h('camdown') % 4 === 0 ? 1 : 0;

        return [
            'occupied' => $occupied,
            'occupancyDesign' => $site['occupancyDesign'],
            'zonesTotal' => $zonesTotal,
            'zonesInComfort' => $zonesTotal - $zonesFault,
            'openWorkOrders' => $this->openWorkOrderCount(),
            'activeAlarms' => $this->intIn(0, 4, 'activealarms'),
            'energyKw' => $this->intIn(90, 320, 'energykw'),
            'doorsUnsecured' => $this->intIn(0, 2, 'doorsunsec'),
            'camerasOnline' => $devicesCamera - $camerasDown,
            'camerasTotal' => $devicesCamera,
            'roomsFree' => $roomsFree,
            'meetingTotal' => $meetingTotal,
        ];
    }

    // --- rooms (spatial index) ---

    /** Bookable room types (meeting-room booking calendars only apply to these). */
    private function isBookable(string $type): bool
    {
        return $type === 'Meeting' || $type === 'Exec' || $type === 'Focus';
    }

    /**
     * The rooms on one floor, each decorated with a seeded occupancy status + occupant count. Vacant is
     * the common case; "fault" is budgeted small (it is what links a room to a work order on the map).
     *
     * @return list<array{id:string,name:string,floor:string,zone:string,type:string,capacity:int,areaSqm:int,status:string,occupants:int,bookable:bool}>
     */
    public function roomsOnFloor(string $floorCode): array
    {
        $out = [];
        foreach ($this->building->roomsFor($floorCode) as $r) {
            $out[] = $this->decorateRoom($r);
        }
        return $out;
    }

    /** Add occupancy status/occupants/bookable to a raw Building room record. */
    private function decorateRoom(array $r): array
    {
        $type = $r['type'];
        $unmanned = in_array($type, ['Server-Comms', 'Plant', 'Store'], true);
        $roll = $this->h('roomstatus|' . $r['id']) % 100;
        if ($this->h('roomfault|' . $r['id']) % 40 === 0) {
            $status = 'fault';
        } elseif (!$unmanned && $roll < 45) {
            $status = 'occupied';
        } else {
            $status = 'vacant';
        }
        $cap = $r['capacity'] > 0 ? $r['capacity'] : 1;
        $occupants = $status === 'occupied' ? $this->intIn(1, $cap, 'occupants|' . $r['id']) : 0;

        $r['status'] = $status;
        $r['occupants'] = $occupants;
        $r['bookable'] = $this->isBookable($type);
        return $r;
    }

    /** Total room count across the building (for the rooms-list pager). */
    public function roomCount(): int
    {
        return $this->site()['rooms'];
    }

    /**
     * A flat, stably-ordered slice of rooms across all floors (bottom floor first, in Building order),
     * for the paginated rooms list.
     *
     * @return list<array>
     */
    public function roomsPage(int $offset, int $limit): array
    {
        if ($offset < 0) {
            $offset = 0;
        }
        $flat = [];
        foreach ($this->floors() as $f) {
            foreach ($this->roomsOnFloor($f['code']) as $r) {
                $flat[] = $r;
            }
        }
        return array_slice($flat, $offset, $limit);
    }

    /**
     * One room by id. A known Building room is returned decorated; an unknown/fuzzed slug still yields a
     * plausible decorated room keyed by the slug, so a crawl never falls off the edge (a 404 inside a
     * deep panel is a tell). Floor is recovered from the `room-<floor>-NN` id shape when possible.
     */
    public function room(string $id): array
    {
        // Try the real topology first: recover the floor code from the id and match within it.
        $floorCode = $this->floorCodeFromRoomId($id);
        if ($floorCode !== null) {
            foreach ($this->building->roomsFor($floorCode) as $r) {
                if ($r['id'] === $id) {
                    return $this->decorateRoom($r);
                }
            }
        }
        // Fall back to a synthesised-but-plausible room for a slug we do not host.
        $types = ['Meeting', 'Focus', 'Open-plan', 'Exec', 'Lab', 'Server-Comms',
                  'Kitchen', 'Reception', 'Wellness', 'Store', 'Plant'];
        $zones = ['N', 'E', 'S', 'W', 'Core'];
        $type = $types[$this->h('synthtype|' . $id) % count($types)];
        $synth = [
            'id' => $id,
            'name' => $this->pick(['Annex', 'Bay', 'Suite', 'Room', 'Space'], 'synthname|' . $id)
                . ' ' . sprintf('%02d', 1 + $this->h('synthno|' . $id) % 40),
            'floor' => $floorCode !== null ? strtoupper($floorCode) : (string) $this->intIn(1, 8, 'synthfloor|' . $id),
            'zone' => $zones[$this->h('synthzone|' . $id) % count($zones)],
            'type' => $type,
            'capacity' => $this->intIn(1, 24, 'synthcap|' . $id),
            'areaSqm' => $this->intIn(9, 140, 'syntharea|' . $id),
        ];
        return $this->decorateRoom($synth);
    }

    /** Recover a floor code from a `room-<floorslug>-NN` id, or null when the shape does not match. */
    private function floorCodeFromRoomId(string $id): ?string
    {
        if (strpos($id, 'room-') !== 0) {
            return null;
        }
        $rest = substr($id, 5);
        $dash = strrpos($rest, '-');
        if ($dash === false) {
            return null;
        }
        $floorSlug = substr($rest, 0, $dash);
        foreach ($this->floors() as $f) {
            if (strtolower($f['code']) === $floorSlug) {
                return $f['code'];
            }
        }
        return null;
    }

    /**
     * The Building devices located in a room, each carrying the panel module its domain lives under so
     * the section can cross-link a room's kit into HVAC/lighting/access/CCTV/sensors.
     *
     * @return list<array{id:string,type:string,domain:string,module:string,controller:string,state:string,lastSeen:string}>
     */
    public function devicesInRoom(string $roomId): array
    {
        $domainModule = [
            'climate' => 'hvac', 'light' => 'lighting', 'cover' => 'lighting',
            'sensor' => 'sensors', 'lock' => 'access', 'camera' => 'cctv',
        ];
        $out = [];
        foreach ($this->building->devices() as $d) {
            if ($d['room'] !== $roomId) {
                continue;
            }
            $module = isset($domainModule[$d['domain']]) ? $domainModule[$d['domain']] : 'sensors';
            $out[] = [
                'id' => $d['id'],
                'type' => $d['type'],
                'domain' => $d['domain'],
                'module' => $module,
                'controller' => $d['controller'],
                'state' => $d['state'],
                'lastSeen' => $d['lastSeen'],
            ];
        }
        return $out;
    }

    // --- meeting-room bookings ---

    /**
     * The bookable rooms across the building (meeting/exec/focus), for the bookings landing.
     *
     * @return list<array>
     */
    public function meetingRooms(): array
    {
        $out = [];
        foreach ($this->floors() as $f) {
            foreach ($this->roomsOnFloor($f['code']) as $r) {
                if ($r['bookable']) {
                    $out[] = $r;
                }
            }
        }
        return $out;
    }

    /**
     * This week's bookings for a room — organisers reference the Org roster, so a title/organiser leak
     * is a real cross-reference an attacker can chase into the directory. Deterministic per room.
     *
     * @return list<array{day:int,start:int,end:int,title:string,organizer:string,organizerEmail:string}>
     */
    public function bookings(string $roomId): array
    {
        $titles = [
            'Board Review', 'M&A — Project Falcon', 'Layoffs planning', 'Budget FY27',
            'Security review', 'Sprint planning', 'Vendor call', 'All-hands',
            'Design critique', 'Incident post-mortem', 'Legal — NDA review', 'Pricing strategy',
            'Roadmap sync', 'Weekly 1:1', 'Interview',
        ];
        $count = $this->intIn(3, 9, 'bkcount|' . $roomId);
        $out = [];
        $used = [];
        for ($i = 0; $i < $count; $i++) {
            $day = $this->h('bkday|' . $roomId . '|' . $i) % 5;               // Mon-Fri
            $start = 8 + $this->h('bkstart|' . $roomId . '|' . $i) % 9;       // 08:00-16:00
            $dur = 1 + $this->h('bkdur|' . $roomId . '|' . $i) % 2;           // 1-2h
            $key = $day . ':' . $start;
            if (isset($used[$key])) {
                continue;                                                     // no overlapping start
            }
            $used[$key] = true;
            $title = $titles[$this->h('bktitle|' . $roomId . '|' . $i) % count($titles)];
            $person = $this->personFor('bkorg|' . $roomId . '|' . $i);
            if ($title === 'Interview') {
                $cand = $this->personFor('bkcand|' . $roomId . '|' . $i);
                $title = 'Interview: ' . $cand['name'];
            }
            $out[] = [
                'day' => $day,
                'start' => $start,
                'end' => $start + $dur,
                'title' => $title,
                'organizer' => $person['name'],
                'organizerEmail' => $person['email'],
            ];
        }
        return $out;
    }

    /** Monday of the frozen "now" week as YYYY-MM-DD, so calendar column dates are deterministic. */
    public function weekMondayYmd(): string
    {
        return FrozenClock::ymdFromDays($this->weekMondayDays());
    }

    /** A day column's date (0 = Monday) as YYYY-MM-DD. */
    public function weekdayYmd(int $day): string
    {
        return FrozenClock::ymdFromDays($this->weekMondayDays() + $day);
    }

    /** Whole-day count for Monday of the frozen week (Unix day 0 was a Thursday). */
    private function weekMondayDays(): int
    {
        $days = FrozenClock::nowDays();
        $dow = ($days + 4) % 7;                 // 0 = Sunday .. 6 = Saturday
        $mondayOffset = $dow === 0 ? 6 : $dow - 1;
        return $days - $mondayOffset;
    }

    // --- work orders (the fault-chain hub) ---

    /** All-time backlog size the work-order list paginates over. */
    public function workOrderCount(): int
    {
        return $this->intIn(self::WORKORDER_TOTAL_MIN, self::WORKORDER_TOTAL_MAX, 'wototal');
    }

    /** The "open" subset shown as a dashboard tile (a small live slice of the backlog). */
    public function openWorkOrderCount(): int
    {
        return $this->intIn(6, 28, 'woopen');
    }

    /**
     * A stable slice of the work-order backlog as summary rows. Each row's fields come from workOrder()
     * on the same id, so a list row and its detail page never disagree.
     *
     * @return list<array{id:string,title:string,priority:string,status:string,assignee:string,category:string,opened:string,sla:string}>
     */
    public function workOrderPage(int $offset, int $limit): array
    {
        if ($offset < 0) {
            $offset = 0;
        }
        $out = [];
        for ($i = 0; $i < $limit; $i++) {
            $idx = $offset + $i;
            if ($idx >= $this->workOrderCount()) {
                break;
            }
            $wo = $this->workOrder($this->workOrderIdAt($idx));
            $out[] = [
                'id' => $wo['id'],
                'title' => $wo['title'],
                'priority' => $wo['priority'],
                'status' => $wo['status'],
                'assignee' => $wo['assignee'],
                'category' => $wo['category'],
                'opened' => $wo['opened'],
                'sla' => $wo['sla'],
            ];
        }
        return $out;
    }

    /**
     * The work-order id at a list index — a fabricated `WO-2026-NNNNNN` stable per deploy. The number is
     * an injective map of the index (stride 2237 is coprime to 6000, plus a per-seed offset), so no two
     * list rows collide onto one id while the sequence still varies across deploys (never a fingerprint).
     */
    private function workOrderIdAt(int $i): string
    {
        $offset = $this->h('woidbase') % 6000;
        return 'WO-2026-' . sprintf('%06d', 4000 + ((($i * 2237) + $offset) % 6000));
    }

    /**
     * One work order, derived purely from its id number so the SAME id renders identically wherever it
     * is reached (list here, or a planted-fault link from sensors/hvac/energy). An unknown/fuzzed slug
     * still yields a coherent order — a 404 inside a deep panel is a tell.
     *
     * @return array{id:string,title:string,priority:string,status:string,category:string,assignee:string,assigneeKind:string,assigneeEmail:string,vendor:string,assetLabel:string,assetRoomId:string,opened:string,slaDays:int,sla:string,seeAlso:string,description:string}
     */
    public function workOrder(string $slug): array
    {
        $norm = $this->normalizeWoId($slug);
        $id = $norm[0];
        $key = $norm[1];                         // canonical salt base (the id itself)

        $categories = [
            'HVAC', 'Electrical', 'Plumbing', 'Lifts', 'Fire & life-safety',
            'Access control', 'CCTV', 'Fabric / building', 'Cleaning', 'Grounds', 'Pest control',
        ];
        $category = $categories[$this->h($key . '|cat') % count($categories)];
        $titles = [
            'HVAC' => ['Zone running warm — dirty filter', 'VAV box not modulating', 'CRAC high head pressure', 'Thermostat unresponsive'],
            'Electrical' => ['Sub-meter not reporting', 'Breaker nuisance trip', 'Lighting circuit fault', 'UPS on bypass'],
            'Plumbing' => ['Leak detected under floor', 'WC blocked', 'Water heater no output', 'Dripping tap reported'],
            'Lifts' => ['Car 2 out of service', 'Door sensor intermittent', 'Overdue statutory inspection', 'Levelling out of tolerance'],
            'Fire & life-safety' => ['Detector in fault', 'Exit sign luminaire out', 'Sounder silenced — investigate', 'Overdue damper drop test'],
            'Access control' => ['Reader offline', 'Door held-open alarm', 'REX not releasing', 'Controller comms fault'],
            'CCTV' => ['Camera no signal', 'NVR storage low', 'PTZ preset drift', 'Timecode overlay wrong'],
            'Fabric / building' => ['Ceiling tile damaged', 'Window seal failed', 'Door closer adjustment', 'Wall repair after knock'],
            'Cleaning' => ['Spill response required', 'Consumables restock', 'Deep-clean requested', 'Bin room overflow'],
            'Grounds' => ['Irrigation valve stuck', 'Car-park barrier fault', 'Signage light out', 'Landscaping trim due'],
            'Pest control' => ['Bait station check', 'Reported sighting — inspect', 'Sealing gap in plant room', 'Routine treatment'],
        ];
        $catTitles = $titles[$category];
        $title = $catTitles[$this->h($key . '|title') % count($catTitles)];

        $priority = 'P' . (1 + $this->h($key . '|prio') % 4);
        // Status is biased toward "one step short" so a followed fault-chain rarely closes cleanly.
        $statuses = [
            'Awaiting parts', 'Awaiting contractor', 'In progress', 'On hold',
            'Scheduled', 'Awaiting parts', 'In progress', 'Open',
        ];
        $status = $statuses[$this->h($key . '|status') % count($statuses)];

        // Assignee: mostly an in-house engineer from the roster; a slice sits with an external vendor.
        $vendors = [
            'Apex Mechanical Services', 'Northgate Lift Co', 'BrightSpark Electrical', 'CoolAir HVAC',
            'SecureFire Ltd', 'CleanCo Facilities', 'Vertex Plumbing', 'Greenleaf Grounds',
        ];
        $isVendor = $this->h($key . '|assignkind') % 100 < 32;
        if ($isVendor) {
            $vendor = $vendors[$this->h($key . '|vendor') % count($vendors)];
            $assignee = $vendor;
            $assigneeKind = 'vendor';
            $assigneeEmail = '';
        } else {
            $person = $this->personFor('woassign|' . $key);
            $vendor = '';
            $assignee = $person['name'];
            $assigneeKind = 'in-house';
            $assigneeEmail = $person['email'];
        }

        // Linked asset: a real room from the topology, so the order points back into the spatial index.
        $rooms = $this->building->roomsFor($this->pickFloorCode($key));
        $room = $rooms[$this->h($key . '|room') % count($rooms)];
        $assetLabel = $room['name'] . ' (' . strtoupper($room['floor']) . ' · ' . $room['type'] . ')';

        $openedDays = 1 + $this->h($key . '|opened') % 45;
        $slaDays = array('P1' => 1, 'P2' => 3, 'P3' => 7, 'P4' => 14);
        $sla = $slaDays[$priority];
        $slaDue = $this->daysAgoYmd($openedDays - $sla);   // due = opened + sla (may be past = overdue)

        // "one step short" cross-ref onto another maintenance record the attacker can keep chasing.
        $seeAlso = 'FM-' . sprintf('%04d', 2000 + $this->h($key . '|seealso') % 6000);

        $description = $title . ' reported on ' . $assetLabel . '. Triaged ' . strtolower($category)
            . '; ' . strtolower($status) . '. Cross-ref ' . $seeAlso . '.';

        return array(
            'id' => $id,
            'title' => $title,
            'priority' => $priority,
            'status' => $status,
            'category' => $category,
            'assignee' => $assignee,
            'assigneeKind' => $assigneeKind,
            'assigneeEmail' => $assigneeEmail,
            'vendor' => $vendor,
            'assetLabel' => $assetLabel,
            'assetRoomId' => $room['id'],
            'opened' => $this->daysAgoYmd($openedDays),
            'slaDays' => $sla,
            'sla' => $slaDue . ' (' . $sla . 'd)',
            'seeAlso' => $seeAlso,
            'description' => $description,
        );
    }

    /**
     * A work order whose linked room IS this room, found by a bounded, seeded, deterministic scan over the
     * id space (workOrder() derives its room from the id alone, so the section cannot just mint an id and
     * claim a room). Lets a "fault on this room" cross-link resolve to an order that names the same room.
     * Falls back to a plain seeded id-derived order if the scan finds none, so it never dead-ends.
     */
    public function workOrderForRoom(string $roomId): array
    {
        for ($i = 0; $i < 4096; $i++) {
            $cand = 'WO-2026-' . sprintf('%06d', 4000 + ($this->h('woroom|' . $roomId . '|' . $i) % 6000));
            if ($this->derivedRoomId($cand) === $roomId) {
                return $this->workOrder($cand);
            }
        }
        return $this->workOrder('WO-2026-' . sprintf('%06d', 4000 + ($this->h('woroom|' . $roomId) % 6000)));
    }

    /** The room id workOrder() would derive for a canonical WO id — cheap, so the scan stays bounded. */
    private function derivedRoomId(string $woId): string
    {
        $rooms = $this->building->roomsFor($this->pickFloorCode($woId));
        if ($rooms === []) {
            return '';
        }
        return $rooms[$this->h($woId . '|room') % count($rooms)]['id'];
    }

    /**
     * The notes thread on a work order — a short seeded conversation between the raiser and the
     * assignee, ending on the "awaiting" beat. Each line is a plain log string (the section escapes it).
     *
     * @return list<string>
     */
    public function workOrderNotes(string $slug): array
    {
        $wo = $this->workOrder($slug);
        $key = $this->normalizeWoId($slug)[1];
        $raiser = $this->personFor('woraise|' . $key);
        $lines = array();
        $lines[] = $this->daysAgoYmd(1 + $this->h($key . '|opened') % 45) . '  ' . $raiser['name']
            . ' (Facilities helpdesk): logged — ' . $wo['title'] . ' at ' . $wo['assetLabel'] . '.';
        $lines[] = $this->daysAgoYmd($this->intIn(1, 20, $key . '|n2')) . '  '
            . ($wo['assigneeKind'] === 'vendor' ? $wo['assignee'] : $wo['assignee'])
            . ': attended site, inspected. ' . $this->pick(
                array('Confirmed fault, ordered replacement part.',
                      'Isolated affected circuit, made safe.',
                      'Temporary measure in place pending permanent fix.',
                      'Requires specialist contractor to complete.'),
                $key . '|n2text'
            );
        $lines[] = $this->daysAgoYmd($this->intIn(0, 6, $key . '|n3')) . '  System: status set to '
            . $wo['status'] . '. See also ' . $wo['seeAlso'] . '.';
        return $lines;
    }

    /**
     * Normalise a URL slug into a canonical `WO-YYYY-NNNNNN` id + a stable salt key. A genuine
     * `wo-2026-004821` slug reconstructs exactly (so it matches the same order minted elsewhere);
     * anything else derives a stable id from the slug hash. @return array{0:string,1:string} [id, key]
     */
    private function normalizeWoId(string $slug): array
    {
        $lower = strtolower($slug);
        if (preg_match('/^wo-(\d{4})-(\d{1,6})$/', $lower, $m) === 1) {
            $id = 'WO-' . $m[1] . '-' . sprintf('%06d', (int) $m[2]);
            return array($id, $id);
        }
        $id = 'WO-2026-' . sprintf('%06d', $this->h('woslug|' . $lower) % 1000000);
        return array($id, $id);
    }

    /** A floor code chosen deterministically from a salt, for anchoring a work order's linked room. */
    private function pickFloorCode(string $salt): string
    {
        $floors = $this->floors();
        return $floors[$this->h($salt . '|floorpick') % count($floors)]['code'];
    }
}
