<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT lighting + covers plane for the deep office/BMS panel. Sits on top of Building
 * (the coherence spine): every luminaire group and every roller blind lives in a real room, on a real
 * floor+zone, and is driven by a real BMS controller on the 10.0.50.x OT fabric — so "turn the lights
 * on/off in the building" the operator promises reconciles with the same rooms every other module shows.
 *
 * Design rules (deep-admin dashboard spec §C.2 lighting/cover + adversarial critique):
 *  - DETERMINISTIC per seed: every reading is hash(seed+id+field) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); a group's facts are derived from its id alone, so group($id) is
 *    byte-identical to that group's row in groups() and reproducible standalone.
 *  - COHERENT: groups/covers derive from Building floors/rooms; a group's controller is a real BMS
 *    controller id; brightness/state/wattage agree (an off group draws ~0 W and reports 0 % brightness).
 *  - SAFE: controllers are BMS on RFC1918 10.0.50.x:47808 only; bus addresses are DALI/KNX dialect
 *    (invented instances), never a routable IP or a scanner-signature string.
 *  - GOOSE-CHASE, BUDGETED: the flagship server-room lures (a UV steriliser + a datacenter row the
 *    attacker fantasises about killing) and a small lighting-fault minority — never a whole-estate
 *    blackout. Master "all building lights" is a lever that only ever queues, never acts.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/number_format, no enums/named-args/str_contains/
 *    constructor promotion) so a fact can promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders and escapes it.
 */
final class Lighting
{
    /** Frozen "now" so a static reload is not a tell (spec E11). Matches Building/Hvac. A const can't
     *  call FrozenClock::epoch(), so this is a runtime accessor, not a class const. */
    public static function deployEpoch(): int
    {
        return FrozenClock::epoch();
    }

    /** BACnet/IP port every BMS controller answers on (matches Building's BMS controllers). */
    public const BACNET_PORT = 47808;

    /** Rated lamp life every luminaire group is measured against (lamp-hours x/50,000). */
    public const LAMP_RATED_HOURS = 50000;

    /** @var int */
    private $seed;

    /** @var Building */
    private $bld;

    private function __construct(int $seed)
    {
        $this->seed = $seed;
        $this->bld = Building::fromSeed($seed);
    }

    public static function fromSeed(int $seed): self
    {
        return new self($seed);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|light|' . $salt), 0, 15));
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

    /** Seeded "N ago" string — pure hash(seed+slot), deterministic, never time()/date(). */
    private function ageAgo(string $salt): string
    {
        $sec = $this->intIn(3, 172800, $salt);           // 3 s .. 2 days
        if ($sec < 90) {
            return $sec . ' s ago';
        }
        if ($sec < 5400) {
            return (int) round($sec / 60) . ' min ago';
        }
        if ($sec < 172800) {
            return (int) round($sec / 3600) . ' h ago';
        }
        return (int) round($sec / 86400) . ' d ago';
    }

    // --- BMS controllers this plane addresses (a subset of Building's controllers) ---

    /** BMS controller ids only, stable order — the pool groups bind to. @return list<string> */
    private function controllerIds(): array
    {
        $ids = [];
        foreach ($this->bld->controllers() as $c) {
            if ($c['kind'] === 'BMS') {
                $ids[] = $c['id'];
            }
        }
        if ($ids === []) {
            $ids[] = 'BMS-CTRL-01';
        }
        return $ids;
    }

    /** IP of a BMS controller id; '10.0.50.11' fallback keeps it RFC1918. */
    public function controllerIp(string $id): string
    {
        foreach ($this->bld->controllers() as $c) {
            if ($c['id'] === $id) {
                return $c['ip'];
            }
        }
        return '10.0.50.11';
    }

    // --- luminaire groups (one per room; server rooms add the flagship goose-chase groups) ---

    /**
     * Every luminaire group, derived from Building rooms so counts reconcile with the site. One group
     * per room, then the budgeted server-room goose-chase groups appended. Order is stable (floor
     * stack, then room order within a floor, then the special groups).
     *
     * @return list<array<string,mixed>>
     */
    public function groups(): array
    {
        $ctrl = $this->controllerIds();
        $out = [];
        $seq = [];
        foreach ($this->bld->floors() as $f) {
            $floorCode = $f['code'];
            $floorSlug = strtolower($floorCode);
            foreach ($this->bld->roomsFor($floorCode) as $r) {
                if (!isset($seq[$floorSlug])) {
                    $seq[$floorSlug] = 0;
                }
                $seq[$floorSlug]++;
                $id = 'lgt-' . $floorSlug . '-' . sprintf('%02d', $seq[$floorSlug]);
                $out[] = $this->buildGroup($id, $f['label'], $r, $ctrl);
            }
        }
        foreach ($this->specialGroups($ctrl) as $g) {
            $out[] = $g;
        }
        return $out;
    }

    /**
     * One group by id. Returns the real group for a known id; for an unknown/fuzzed slug it synthesises
     * a plausible group attached to the ground-floor Core so cross-links still resolve (spec D.4 — a 404
     * inside a deep panel is a tell). Never null.
     *
     * @return array<string,mixed>
     */
    public function group(string $id): array
    {
        foreach ($this->groups() as $g) {
            if ($g['id'] === $id) {
                return $g;
            }
        }
        $room = ['id' => 'room-g-01', 'name' => 'Ground Core', 'floor' => 'G', 'zone' => 'Core',
                 'type' => 'Open-plan', 'capacity' => 0, 'areaSqm' => 60];
        return $this->buildGroup($id, 'Ground', $room, $this->controllerIds());
    }

    /**
     * @param array{id:string,name:string,floor:string,zone:string,type:string,capacity:int,areaSqm:int} $r
     * @param list<string> $ctrl
     * @return array<string,mixed>
     */
    private function buildGroup(string $id, string $floorLabel, array $r, array $ctrl): array
    {
        $state = $this->stateFor($id, $r['type']);
        $bright = $state === 'on' ? $this->intIn(15, 100, $id . '|bright') : ($state === 'fault' ? $this->intIn(0, 100, $id . '|bright') : 0);
        $raw = (int) round($bright / 100 * 255);
        // Warmer amenity spaces, cooler work/lab spaces — CCT tracks the room's use.
        $cct = $this->cctFor($id, $r['type']);
        $fixtures = $this->fixturesFor($r['type'], $r['areaSqm'], $id);
        $wattPer = $this->intIn(6, 22, $id . '|wpf');
        $watt = $state === 'off' ? 0 : (int) round($fixtures * $wattPer * $bright / 100);
        $controller = $ctrl[$this->h($id . '|ctrl') % count($ctrl)];
        $rgbCapable = $this->rgbCapable($r['type']);
        $bus = $this->pick(['DALI', 'DALI', 'KNX'], $id . '|bustype');
        $lampUsed = $this->intIn(200, 49200, $id . '|lamp');

        return [
            'id' => $id,
            'name' => $floorLabel . ' — ' . $r['name'] . ' ' . $this->roomLightLabel($r['type']),
            'haEntity' => $this->haEntity($r, $id),
            'floor' => $r['floor'],
            'floorLabel' => $floorLabel,
            'zone' => $r['zone'],
            'roomId' => $r['id'],
            'roomName' => $r['name'],
            'roomType' => $r['type'],
            'state' => $state,
            'brightnessPct' => $bright,
            'brightnessRaw' => $raw,
            'colorTempK' => $cct,
            'rgbCapable' => $rgbCapable,
            'rgbHex' => $rgbCapable ? $this->rgbHex($id) : '',
            'effect' => $rgbCapable ? $this->pick(['none', 'none', 'none', 'colorloop', 'candle', 'daylight'], $id . '|fx') : 'none',
            'scene' => $this->pick(['default', 'default', 'work', 'evening', 'presentation', 'cleaning', 'away'], $id . '|scene'),
            'fixtures' => $fixtures,
            'wattage' => $watt,
            'occupancyLinked' => ($this->h($id . '|occ') % 100) < 68,
            'daylightHarvest' => ($this->h($id . '|dh') % 100) < 40,
            'busType' => $bus,
            'busAddress' => $this->busAddress($bus, $id),
            'lampUsed' => $lampUsed,
            'lampRated' => self::LAMP_RATED_HOURS,
            'controller' => $controller,
            'controllerIp' => $this->controllerIp($controller),
            'lastChanged' => $this->ageAgo($id . '|changed'),
            'special' => '',
        ];
    }

    /** On mostly, a small Off/Fault minority; plant rooms (Store/Plant/Server-Comms) skew Off. */
    private function stateFor(string $id, string $type): string
    {
        $r = $this->h($id . '|state') % 100;
        if ($type === 'Server-Comms' || $type === 'Plant' || $type === 'Store') {
            // Utility spaces are mostly dark, occasionally on for a visit.
            if ($r < 6) {
                return 'fault';
            }
            return $r < 30 ? 'on' : 'off';
        }
        if ($r < 4) {
            return 'fault';
        }
        return $r < 62 ? 'on' : 'off';
    }

    private function cctFor(string $id, string $type): int
    {
        // 50 K steps across the HA 2200-6500 K range; amenity spaces warmer, work/lab cooler.
        if ($type === 'Reception' || $type === 'Wellness' || $type === 'Exec' || $type === 'Kitchen') {
            $k = 2700 + ($this->h($id . '|cct') % 13) * 50; // 2700-3300
        } elseif ($type === 'Lab' || $type === 'Server-Comms' || $type === 'Plant') {
            $k = 4500 + ($this->h($id . '|cct') % 41) * 50; // 4500-6500
        } else {
            $k = 3500 + ($this->h($id . '|cct') % 25) * 50; // 3500-4700
        }
        if ($k < 2200) {
            $k = 2200;
        }
        if ($k > 6500) {
            $k = 6500;
        }
        return $k;
    }

    private function fixturesFor(string $type, int $areaSqm, string $salt): int
    {
        // Roughly one luminaire per 6 m2, clamped to a sane per-room range by room use.
        $n = (int) round($areaSqm / 6);
        if ($n < 2) {
            $n = 2;
        }
        if ($type === 'Open-plan') {
            $n += $this->intIn(6, 40, $salt . '|fixextra');
        }
        if ($n > 220) {
            $n = 220;
        }
        return $n;
    }

    private function rgbCapable(string $type): bool
    {
        return $type === 'Reception' || $type === 'Wellness' || $type === 'Exec' || $type === 'Meeting';
    }

    /** A seeded RGB hex for tunable groups — [0-9a-f] only, so it is inert as an inline SVG fill. */
    private function rgbHex(string $id): string
    {
        return '#' . substr(hash('sha256', $this->seed . '|lightrgb|' . $id), 0, 6);
    }

    private function roomLightLabel(string $type): string
    {
        if ($type === 'Open-plan') {
            return 'open-plan lighting';
        }
        if ($type === 'Server-Comms') {
            return 'row lighting';
        }
        return 'lighting';
    }

    /** HA-style entity_id, e.g. light.f3_east_open_plan — slug-safe [a-z0-9_.] by construction. */
    private function haEntity(array $r, string $id): string
    {
        $floor = strtolower((string) $r['floor']);
        $zone = strtolower((string) $r['zone']);
        $type = strtolower(str_replace('-', '_', (string) $r['type']));
        $tail = substr($id, 4); // drop 'lgt-'
        $slug = preg_replace('/[^a-z0-9]+/', '_', $floor . '_' . $zone . '_' . $type . '_' . $tail);
        return 'light.' . trim((string) $slug, '_');
    }

    private function busAddress(string $bus, string $id): string
    {
        if ($bus === 'KNX') {
            return 'KNX ' . $this->intIn(0, 15, $id . '|ka') . '/' . $this->intIn(0, 7, $id . '|kb') . '/' . $this->intIn(0, 255, $id . '|kc');
        }
        // DALI: line + short address (0-63) + group (0-15).
        return 'DALI line ' . $this->intIn(1, 4, $id . '|dl') . ' · A' . $this->intIn(0, 63, $id . '|da') . ' · grp ' . $this->intIn(0, 15, $id . '|dg');
    }

    /**
     * The budgeted server-room goose-chase groups (spec §C.2): a UV steriliser and a datacenter row the
     * attacker fantasises about killing. Anchored to a real server room; both inert like every other
     * group. One pair per server room, capped so it never becomes noise.
     *
     * @param list<string> $ctrl
     * @return list<array<string,mixed>>
     */
    private function specialGroups(array $ctrl): array
    {
        $rooms = $this->serverRooms();
        $out = [];
        $n = 0;
        foreach ($rooms as $room) {
            if ($n >= 2) {
                break;
            }
            $n++;
            $uvId = 'lgt-uv-' . sprintf('%02d', $n);
            $uv = $this->buildGroup($uvId, $this->floorLabel($room['floor']), [
                'id' => $room['id'], 'name' => $room['name'], 'floor' => $room['floor'],
                'zone' => 'Core', 'type' => 'Server-Comms', 'capacity' => 0, 'areaSqm' => 40,
            ], $ctrl);
            $uv['name'] = $room['name'] . ' — UV steriliser';
            $uv['haEntity'] = 'light.server_room_uv_sterilizer' . ($n > 1 ? '_' . $n : '');
            $uv['state'] = 'off';
            $uv['brightnessPct'] = 0;
            $uv['brightnessRaw'] = 0;
            $uv['wattage'] = 0;
            $uv['special'] = 'uv';
            $out[] = $uv;

            $rowId = 'lgt-dcrow-' . sprintf('%02d', $n);
            $row = $this->buildGroup($rowId, $this->floorLabel($room['floor']), [
                'id' => $room['id'], 'name' => $room['name'], 'floor' => $room['floor'],
                'zone' => 'Core', 'type' => 'Server-Comms', 'capacity' => 0, 'areaSqm' => 60,
            ], $ctrl);
            $row['name'] = $room['name'] . ' — datacenter row A';
            $row['haEntity'] = 'light.datacenter_row_a' . ($n > 1 ? '_' . $n : '');
            $row['special'] = 'datacenter';
            $out[] = $row;
        }
        return $out;
    }

    private function floorLabel(string $floorCode): string
    {
        foreach ($this->bld->floors() as $f) {
            if ($f['code'] === $floorCode) {
                return $f['label'];
            }
        }
        return 'Ground';
    }

    /**
     * Server rooms across the building; falls back to a Core room so the flagship lure always exists.
     *
     * @return list<array{id:string,name:string,floor:string}>
     */
    private function serverRooms(): array
    {
        $out = [];
        foreach ($this->bld->floors() as $f) {
            foreach ($this->bld->roomsFor($f['code']) as $r) {
                if ($r['type'] === 'Server-Comms') {
                    $out[] = ['id' => $r['id'], 'name' => $r['name'], 'floor' => $r['floor']];
                }
            }
        }
        if ($out !== []) {
            return $out;
        }
        foreach ($this->bld->floors() as $f) {
            foreach ($this->bld->roomsFor($f['code']) as $r) {
                if ($r['zone'] === 'Core') {
                    return [['id' => $r['id'], 'name' => $r['name'], 'floor' => $r['floor']]];
                }
            }
        }
        return [['id' => 'room-g-01', 'name' => 'Ground Core', 'floor' => 'G']];
    }

    // --- scenes (building-wide apply leaves) ---

    /**
     * The building scene catalogue — the "all-on / all-off / evening / presentation" levers the operator
     * asked for, plus the irresistible after-hours / lockdown fantasy scenes. Each carries a stable
     * member count (how many groups it touches) so an apply receipt reads authentically. All inert.
     *
     * @return list<array{id:string,name:string,desc:string,members:int}>
     */
    public function scenes(): array
    {
        $total = count($this->groups());
        $catalog = [
            ['id' => 'all-on', 'name' => 'All on', 'desc' => 'Every controllable luminaire to 100 %'],
            ['id' => 'all-off', 'name' => 'All off', 'desc' => 'Every controllable luminaire off'],
            ['id' => 'evening', 'name' => 'Evening', 'desc' => 'Warm dim, amenity + circulation only'],
            ['id' => 'presentation', 'name' => 'Presentation', 'desc' => 'Front-of-room down, screens lifted'],
            ['id' => 'cleaning', 'name' => 'Cleaning', 'desc' => 'Full brightness, cool CCT, all floors'],
            ['id' => 'after-hours', 'name' => 'After-hours', 'desc' => 'Occupancy-only, circulation at 20 %'],
            ['id' => 'maintenance-override', 'name' => 'Maintenance override', 'desc' => 'Manual control, schedules suspended'],
        ];
        $out = [];
        foreach ($catalog as $s) {
            $members = $s['id'] === 'all-off' || $s['id'] === 'all-on'
                ? $total
                : $this->intIn((int) ($total * 0.3), max(1, (int) ($total * 0.8)), 'scenemembers|' . $s['id']);
            $out[] = [
                'id' => $s['id'],
                'name' => $s['name'],
                'desc' => $s['desc'],
                'members' => $members,
            ];
        }
        return $out;
    }

    /**
     * One scene by id; unknown slug synthesises a plausible scene so a fuzzed apply path never 404s.
     *
     * @return array{id:string,name:string,desc:string,members:int}
     */
    public function scene(string $id): array
    {
        foreach ($this->scenes() as $s) {
            if ($s['id'] === $id) {
                return $s;
            }
        }
        return ['id' => $id, 'name' => ucfirst(str_replace('-', ' ', $id)), 'desc' => 'Custom scene',
                'members' => $this->intIn(1, max(1, count($this->groups())), 'scenemembers|' . $id)];
    }

    // --- covers (blinds / shades / physical-access covers) ---

    /**
     * Roller/venetian/blackout blinds on windowed office rooms, plus the site's physical-access covers
     * (loading dock, garage, parking barrier, skylights) — the loading-dock + parking-gate rows are the
     * physical-access bait. current_position 0-100, tilt (venetian only), wind-lockout, battery %.
     *
     * @return list<array<string,mixed>>
     */
    public function covers(): array
    {
        $out = [];
        $seq = 0;
        foreach ($this->bld->floors() as $f) {
            $floorCode = $f['code'];
            // Basements/roof carry no window blinds; upper/ground office floors do.
            $hasWindows = $floorCode !== 'Roof' && ($floorCode === '' || $floorCode[0] !== 'B');
            foreach ($this->bld->roomsFor($floorCode) as $r) {
                if (!$hasWindows) {
                    continue;
                }
                if ($r['zone'] === 'Core') {
                    continue; // core rooms have no external glazing
                }
                // Only perimeter office/amenity rooms get a blind, and only a seeded subset.
                if (($this->h('coverhas|' . $r['id']) % 100) >= 62) {
                    continue;
                }
                $seq++;
                $id = 'cov-' . strtolower($floorCode) . '-' . sprintf('%02d', $seq);
                $out[] = $this->buildCover($id, $f['label'], $r);
            }
        }
        foreach ($this->siteCovers() as $c) {
            $out[] = $c;
        }
        return $out;
    }

    /**
     * One cover by id; unknown slug synthesises a plausible roller blind on the ground North zone.
     *
     * @return array<string,mixed>
     */
    public function cover(string $id): array
    {
        foreach ($this->covers() as $c) {
            if ($c['id'] === $id) {
                return $c;
            }
        }
        $room = ['id' => 'room-g-02', 'name' => 'Ground North', 'floor' => 'G', 'zone' => 'N',
                 'type' => 'Open-plan', 'capacity' => 0, 'areaSqm' => 60];
        return $this->buildCover($id, 'Ground', $room);
    }

    /**
     * @param array{id:string,name:string,floor:string,zone:string,type:string,capacity:int,areaSqm:int} $r
     * @return array<string,mixed>
     */
    private function buildCover(string $id, string $floorLabel, array $r): array
    {
        $type = $this->pick(['roller', 'roller', 'roller', 'venetian', 'blackout', 'skylight'], $id . '|ctype');
        $pos = $this->intIn(0, 100, $id . '|pos');
        return [
            'id' => $id,
            'name' => $floorLabel . ' — ' . $r['name'] . ' ' . $this->coverLabel($type),
            'haEntity' => 'cover.' . strtolower((string) $r['floor']) . '_' . strtolower((string) $r['zone']) . '_' . $type . '_' . substr($id, 4),
            'type' => $type,
            'floor' => $r['floor'],
            'floorLabel' => $floorLabel,
            'zone' => $r['zone'],
            'roomId' => $r['id'],
            'roomName' => $r['name'],
            'position' => $pos,
            'state' => $this->coverState($pos),
            'tilt' => $type === 'venetian' ? $this->intIn(0, 100, $id . '|tilt') : -1,
            'windLockout' => ($this->h($id . '|wind') % 100) < 8,
            'battery' => $this->intIn(58, 100, $id . '|bat'),
            'access' => false,
        ];
    }

    /**
     * The site's physical-access covers — loading dock, garage door, parking barrier, atrium skylights.
     * These are the physical-access bait; still inert. Anchored to plausible ground/basement rooms.
     *
     * @return list<array<string,mixed>>
     */
    private function siteCovers(): array
    {
        $catalog = [
            ['id' => 'cov-dock-01', 'name' => 'Loading dock door — Bay 1', 'type' => 'loading-dock', 'floor' => 'G', 'zone' => 'S'],
            ['id' => 'cov-dock-02', 'name' => 'Loading dock door — Bay 2', 'type' => 'loading-dock', 'floor' => 'G', 'zone' => 'S'],
            ['id' => 'cov-gate-01', 'name' => 'Car park barrier — Entry', 'type' => 'parking-barrier', 'floor' => 'G', 'zone' => 'W'],
            ['id' => 'cov-gate-02', 'name' => 'Car park barrier — Exit', 'type' => 'parking-barrier', 'floor' => 'G', 'zone' => 'W'],
            ['id' => 'cov-garage-01', 'name' => 'Fleet garage roller door', 'type' => 'garage', 'floor' => 'G', 'zone' => 'W'],
            ['id' => 'cov-sky-01', 'name' => 'Atrium skylight — North', 'type' => 'operable-window', 'floor' => 'Roof', 'zone' => 'Core'],
        ];
        $out = [];
        foreach ($catalog as $c) {
            $pos = $this->intIn(0, 100, $c['id'] . '|pos');
            $out[] = [
                'id' => $c['id'],
                'name' => $c['name'],
                'haEntity' => 'cover.' . str_replace('-', '_', substr($c['id'], 4)),
                'type' => $c['type'],
                'floor' => $c['floor'],
                'floorLabel' => $this->floorLabel($c['floor']),
                'zone' => $c['zone'],
                'roomId' => '',
                'roomName' => 'Site perimeter',
                'position' => $pos,
                'state' => $this->coverState($pos),
                'tilt' => -1,
                'windLockout' => ($this->h($c['id'] . '|wind') % 100) < 15,
                'battery' => 100, // mains-powered gates report full
                'access' => true,
            ];
        }
        return $out;
    }

    private function coverLabel(string $type): string
    {
        switch ($type) {
            case 'venetian':
                return 'venetian blind';
            case 'blackout':
                return 'blackout blind';
            case 'skylight':
                return 'skylight shade';
            default:
                return 'roller blind';
        }
    }

    private function coverState(int $pos): string
    {
        if ($pos <= 2) {
            return 'closed';
        }
        if ($pos >= 98) {
            return 'open';
        }
        return 'partial';
    }

    // --- reconciled headline counts for the landing ---

    /**
     * @return array{groups:int,on:int,off:int,fault:int,kw:float,covers:int,coversOpen:int,scenes:int,controllers:int}
     */
    public function summary(): array
    {
        $on = 0;
        $off = 0;
        $fault = 0;
        $watt = 0;
        foreach ($this->groups() as $g) {
            if ($g['state'] === 'on') {
                $on++;
            } elseif ($g['state'] === 'fault') {
                $fault++;
            } else {
                $off++;
            }
            $watt += (int) $g['wattage'];
        }
        $covers = $this->covers();
        $coversOpen = 0;
        foreach ($covers as $c) {
            if ($c['state'] !== 'closed') {
                $coversOpen++;
            }
        }
        $bms = 0;
        foreach ($this->bld->controllers() as $c) {
            if ($c['kind'] === 'BMS') {
                $bms++;
            }
        }
        return [
            'groups' => $on + $off + $fault,
            'on' => $on,
            'off' => $off,
            'fault' => $fault,
            'kw' => round($watt / 1000, 1),
            'covers' => count($covers),
            'coversOpen' => $coversOpen,
            'scenes' => count($this->scenes()),
            'controllers' => $bms,
        ];
    }

    /** Seeded "last DALI poll" freshness for the landing — varies per deploy, never time() (spec E11). */
    public function lastPollAge(): string
    {
        return $this->intIn(8, 45, 'dalipoll') . ' s ago';
    }

    /**
     * 24 hourly brightness readings for a group's history sparkline — a seeded diurnal curve, never
     * time(). An off group reads a flat low line; an on group swings with the working day.
     *
     * @param array<string,mixed> $g a group() record
     * @return list<float>
     */
    public function brightnessTrend(array $g): array
    {
        $base = (float) $g['brightnessPct'];
        $id = (string) $g['id'];
        $out = [];
        for ($i = 0; $i < 24; $i++) {
            if ($g['state'] === 'off') {
                $out[] = (float) (($this->h($id . '|t|' . $i) % 4)); // near-dark
                continue;
            }
            $day = ($i >= 8 && $i <= 18) ? 0.0 : -35.0;
            $jitter = ($this->h($id . '|t|' . $i) % 11 - 5);
            $v = $base + $day + $jitter;
            if ($v < 0) {
                $v = 0.0;
            }
            if ($v > 100) {
                $v = 100.0;
            }
            $out[] = round($v, 1);
        }
        return $out;
    }
}
