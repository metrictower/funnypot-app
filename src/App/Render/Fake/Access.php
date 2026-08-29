<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT physical-access estate for the deep office panel — doors/readers, badge events,
 * the cardholder roster, schedules and anti-passback. It is a VIEW over the two coherence spines rather
 * than a new fabric: doors hang off `Building` rooms/controllers (a door names a real floor/zone/room
 * and a real `ACS-CTRL-0x` on `10.0.60.x`), and cardholders are the `Org` roster plus its contractors,
 * so the same person, badge, controller and IP appear identically wherever access cross-references them.
 *
 * Design rules (deep-admin dashboard spec §C.3 + adversarial critique):
 *  - DETERMINISTIC per seed: every value is hash(seed+slot) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); clock strings are formatted by integer arithmetic off one frozen
 *    deployEpoch(), so a static reload is byte-identical and never a tell.
 *  - COHERENT: doors reconcile to Building topology + ACS controllers; cardholder magnitude derives from
 *    Org's count-ratio table (N + contractors), never an out-of-scale 50,000.
 *  - SAFE: all controller addressing RFC1918 (10.0.60.x); badge ids masked, PINs never exposed; every
 *    person fabricated. No real product/brand, no scanner-signature string (invented ids only).
 *  - ANOMALY BUDGET: hash(seed) plants 0-2 access anomalies (a forced/held door, a master/lost badge);
 *    most render clean — a buffet of honeytokens reads as staged.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf, no enums/promotion/str_contains) so a fact can promote
 *    into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders, masks and escapes it.
 */
final class Access
{
    use SeededInstanceCache;

    /** Frozen "now" for ages/clock so a static reload is not a tell (spec E11). Matches Building/Org. A
     *  const can't call FrozenClock::epoch(), so this is a runtime accessor, not a class const. */
    public static function deployEpoch(): int
    {
        return FrozenClock::epoch();
    }

    /** Access levels a badge can carry; MASTER is the planted all-doors bait (budgeted). */
    private const LEVELS = ['Employee', 'Contractor', 'Executive', 'Facilities', 'SERVER-ROOM', 'MASTER'];

    /** @var int */
    private $seed;

    /** @var Building */
    private $building;

    /** @var Org */
    private $org;

    /** @var array<int,array>|null cached roster so deep cardholder pages stay cheap */
    private $rosterCache = null;

    /** @var array<int,array>|null cached door list (finalised, anomalies applied) */
    private $doorsCache = null;

    private function __construct(int $seed)
    {
        $this->seed = $seed;
        $this->building = Building::fromSeed($seed);
        $this->org = Org::fromSeed($seed);
    }

    public static function fromSeed(int $seed): self
    {
        return self::seededInstance(
            (string) $seed,
            static function () use ($seed): self {
                return new self($seed);
            }
        );
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|acs|' . $salt), 0, 15));
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

    /** Seeded "N ago" string off deployEpoch() — deterministic, never time()/date(). */
    private function ageAgo(string $salt): string
    {
        $sec = $this->intIn(4, 172800, $salt);           // 4 s .. 2 days
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

    /** HH:MM:SS for an absolute epoch, by integer arithmetic only (no date()/gmdate). */
    private function clock(int $epoch): string
    {
        $s = $epoch % 86400;
        if ($s < 0) {
            $s += 86400;
        }
        return sprintf('%02d:%02d:%02d', intdiv($s, 3600), intdiv($s % 3600, 60), $s % 60);
    }

    /** Badge id shown with only its last four digits — a roster never exposes the full card number. */
    private function maskBadge(string $badge): string
    {
        return '••' . substr($badge, -4);
    }

    // --- controllers + topology helpers (read from the Building spine) ---

    /** @return list<array{id:string,ip:string}> the ACS controllers doors loop onto (never empty). */
    private function acsControllers(): array
    {
        $out = [];
        foreach ($this->building->controllers() as $c) {
            if ($c['kind'] === 'ACS') {
                $out[] = ['id' => $c['id'], 'ip' => $c['ip']];
            }
        }
        if ($out === []) {
            $out[] = ['id' => 'ACS-CTRL-01', 'ip' => '10.0.60.11'];
        }
        return $out;
    }

    /** Server/Comms rooms across the building, in floor order — the high-security door anchors. */
    private function serverRooms(): array
    {
        $out = [];
        foreach ($this->building->floors() as $f) {
            foreach ($this->building->roomsFor($f['code']) as $r) {
                if ($r['type'] === 'Server-Comms') {
                    $out[] = ['room' => $r, 'floor' => $f];
                }
            }
        }
        return $out;
    }

    /** The Ground floor code if present, else the first floor — an anchor for lobby-level doors. */
    private function groundCode(array $floors): string
    {
        foreach ($floors as $f) {
            if ($f['code'] === 'G') {
                return 'G';
            }
        }
        return $floors[0]['code'];
    }

    /** The topmost occupied (non-Roof) floor — where the executive suite sits. */
    private function execFloorCode(array $floors): string
    {
        for ($i = count($floors) - 1; $i >= 0; $i--) {
            if ($floors[$i]['code'] !== 'Roof') {
                return $floors[$i]['code'];
            }
        }
        return $floors[0]['code'];
    }

    // --- doors / readers ---

    /**
     * The addressable door estate: flagship named doors (entrance, loading dock, server room, MDF, vault,
     * exec suite) plus per-floor stair-lobby doors and one door per Server/Comms room. Each reconciles to
     * a real floor/zone/room (where applicable) and a real ACS controller. 0-2 anomalies are planted
     * within budget; every other door reads Secured.
     *
     * @return list<array{id:string,name:string,type:string,area:string,floor:string,zone:string,room:string,controller:string,controllerIp:string,mode:string,state:string,secured:bool,highSecurity:bool,lastEvent:string,lastSeen:string}>
     */
    public function doors(): array
    {
        if ($this->doorsCache !== null) {
            return $this->doorsCache;
        }

        $acs = $this->acsControllers();
        $floors = $this->building->floors();
        $ground = $this->groundCode($floors);
        $lowest = $floors[0]['code'];
        $exec = $this->execFloorCode($floors);
        $servers = $this->serverRooms();

        // [id, name, type, highSec, floorCode, zone, roomId]
        $defs = [];
        $defs[] = ['door-main-entrance', 'Main Entrance', 'turnstile', false, $ground, 'Core', ''];
        $defs[] = ['door-loading-dock', 'Loading Dock', 'barrier', false, $lowest, 'Core', ''];

        $usedRooms = array();
        if (isset($servers[0])) {
            $sr = $servers[0];
            $defs[] = ['door-srv-a', 'Server Room A — ' . $sr['room']['name'], 'maglock', true,
                       $sr['floor']['code'], $sr['room']['zone'], $sr['room']['id']];
            $usedRooms[$sr['room']['id']] = true;
        } else {
            $defs[] = ['door-srv-a', 'Server Room A', 'maglock', true, $ground, 'Core', ''];
        }
        if (isset($servers[1])) {
            $sr = $servers[1];
            $defs[] = ['door-mdf', 'MDF / Comms Room — ' . $sr['room']['name'], 'maglock', true,
                       $sr['floor']['code'], $sr['room']['zone'], $sr['room']['id']];
            $usedRooms[$sr['room']['id']] = true;
        } else {
            $defs[] = ['door-mdf', 'MDF / Comms Room', 'maglock', true, $ground, 'Core', ''];
        }
        $defs[] = ['door-records-vault', 'Records Vault', 'maglock', true, $exec, 'Core', ''];
        $defs[] = ['door-exec-suite', 'Executive Suite', 'mortise', false, $exec, 'Core', ''];

        // Per-floor: a stair-lobby door + one door for each remaining Server/Comms room.
        foreach ($floors as $f) {
            $code = $f['code'];
            if ($code === 'Roof') {
                continue;
            }
            $slug = strtolower($code);
            $defs[] = ['door-' . $slug . '-entry', $f['label'] . ' — Stair Lobby', 'strike', false,
                       $code, 'Core', ''];
            foreach ($this->building->roomsFor($code) as $r) {
                if ($r['type'] === 'Server-Comms' && !isset($usedRooms[$r['id']])) {
                    $doorId = 'door-' . substr($r['id'], strlen('room-'));
                    $defs[] = [$doorId, $r['name'] . ' (Comms)', 'maglock', true,
                               $code, $r['zone'], $r['id']];
                    $usedRooms[$r['id']] = true;
                }
            }
        }

        $out = [];
        foreach ($defs as $i => $d) {
            $out[] = $this->finaliseDoor($d, $acs[$i % count($acs)], $i);
        }
        $this->doorsCache = $this->applyDoorAnomalies($out);
        return $this->doorsCache;
    }

    /** Turn a door definition into a full row: controller loop, mode, a clean (Secured) baseline state. */
    private function finaliseDoor(array $d, array $ctrl, int $i): array
    {
        $id = $d[0];
        $name = $d[1];
        $type = $d[2];
        $highSec = $d[3];
        $floor = $d[4];
        $zone = $d[5];
        $room = $d[6];

        $floorLabel = $this->floorLabel($floor);
        $area = $floorLabel . ' · ' . $this->zoneName($zone);
        if ($room !== '') {
            $area .= ' · ' . $room;
        }

        if ($highSec) {
            $mode = 'Card+PIN';
        } elseif ($id === 'door-main-entrance') {
            $mode = 'Unlocked office-hours';
        } elseif (strpos($id, '-entry') !== false) {
            $mode = 'Free-egress';
        } elseif ($id === 'door-loading-dock') {
            $mode = 'Card+PIN';
        } else {
            $mode = $this->pick(['Card only', 'Card+PIN', 'Unlocked office-hours'], 'mode|' . $id);
        }

        $holder = $this->rosterName($this->h('lastevt|' . $id) % $this->org->headcount());
        return array(
            'id' => $id,
            'name' => $name,
            'type' => $type,
            'area' => $area,
            'floor' => $floor,
            'zone' => $zone,
            'room' => $room,
            'controller' => $ctrl['id'],
            'controllerIp' => $ctrl['ip'],
            'mode' => $mode,
            'state' => 'Secured',
            'secured' => true,
            'highSecurity' => $highSec,
            'lastEvent' => 'GRANTED — ' . $holder,
            'lastSeen' => $this->ageAgo('lastseen|' . $id),
        );
    }

    /**
     * Plant 0-2 door anomalies within budget: a forced loading dock and a held-open exec door — the two
     * baits the incident narrative ties together. The server room / vault never render unsecured (a wide-
     * open crown jewel is the tell the whole design avoids). Everything else stays Secured.
     */
    private function applyDoorAnomalies(array $doors): array
    {
        $budget = $this->h('dooranom') % 3;                 // 0, 1 or 2
        if ($budget === 0) {
            return $doors;
        }
        $plan = array(
            array('door-loading-dock', 'Forced', '02:41 forced-open alarm'),
            array('door-exec-suite', 'Held-open', 'held open > 5 min'),
        );
        $applied = 0;
        foreach ($plan as $p) {
            if ($applied >= $budget) {
                break;
            }
            foreach ($doors as $idx => $door) {
                if ($door['id'] === $p[0]) {
                    $doors[$idx]['state'] = $p[1];
                    $doors[$idx]['secured'] = false;
                    $doors[$idx]['lastEvent'] = $p[2];
                    $doors[$idx]['lastSeen'] = $this->ageAgo('anomseen|' . $p[0]);
                    $applied++;
                    break;
                }
            }
        }
        return $doors;
    }

    /**
     * One door by id. A known id returns its exact doors() row; an unknown/fuzzed slug returns a plausible
     * seeded ordinary door so a crawl never falls off the edge (a 404 inside the panel is a tell). The
     * synthetic door is never high-security, so probing a made-up slug yields a canned queue, not the
     * guarded soft-deny reserved for the real crown-jewel doors.
     */
    public function door(string $id): array
    {
        foreach ($this->doors() as $d) {
            if ($d['id'] === $id) {
                return $d;
            }
        }
        $acs = $this->acsControllers();
        $ctrl = $acs[$this->h('synctrl|' . $id) % count($acs)];
        $type = $this->pick(['strike', 'maglock', 'mortise', 'turnstile'], 'syntype|' . $id);
        $floors = $this->building->floors();
        $floor = $floors[$this->h('synfloor|' . $id) % count($floors)]['code'];
        $holder = $this->rosterName($this->h('synevt|' . $id) % $this->org->headcount());
        return array(
            'id' => $id,
            'name' => $this->prettyName($id),
            'type' => $type,
            'area' => $this->floorLabel($floor) . ' · Core',
            'floor' => $floor,
            'zone' => 'Core',
            'room' => '',
            'controller' => $ctrl['id'],
            'controllerIp' => $ctrl['ip'],
            'mode' => $this->pick(['Card only', 'Card+PIN'], 'synmode|' . $id),
            'state' => 'Secured',
            'secured' => true,
            'highSecurity' => false,
            'lastEvent' => 'GRANTED — ' . $holder,
            'lastSeen' => $this->ageAgo('synseen|' . $id),
        );
    }

    /** Headline door counts for the landing stat tiles — all derived from doors() so nothing contradicts.
     *  @return array{total:int,secured:int,unsecured:int,highSecurity:int,readersOnline:int,readersTotal:int,alarms:int} */
    public function summary(): array
    {
        $doors = $this->doors();
        $total = count($doors);
        $secured = 0;
        $high = 0;
        $alarms = 0;
        foreach ($doors as $d) {
            if ($d['secured']) {
                $secured++;
            }
            if ($d['highSecurity']) {
                $high++;
            }
            if ($d['state'] === 'Forced') {
                $alarms++;
            }
        }
        $offline = $this->h('readeroff') % 2;               // 0-1 reader offline
        return array(
            'total' => $total,
            'secured' => $secured,
            'unsecured' => $total - $secured,
            'highSecurity' => $high,
            'readersOnline' => $total - $offline,
            'readersTotal' => $total,
            'alarms' => $alarms,
        );
    }

    // --- badge events (per door) + global access-event log ---

    /**
     * Recent transactions at one door, newest first. Row $i's time is a strictly-backward walk off
     * deployEpoch() (a seeded positive gap subtracted per step, cumulative — not an independent draw per
     * row), so the scroll never jumps forward and row 0 is never later than "now" (spec E11). Badges are
     * masked; a high-security door skews toward more DENIED lines (schedule / access-level). Each row
     * prints the full civil date alongside the time — a door open long enough to cross local midnight must
     * not read as the clock jumping backward with no date to explain it.
     *
     * @return list<array{time:string,result:string,badge:string,holder:string,reason:string}>
     */
    public function badgeEventsFor(string $doorId, int $count): array
    {
        $door = $this->door($doorId);
        $n = $this->org->headcount();
        $out = [];
        $epoch = self::deployEpoch();
        for ($i = 0; $i < $count; $i++) {
            $salt = 'evt|' . $doorId . '|' . $i;
            $epoch -= $this->intIn(70, 900, $salt . '|gap');
            $person = $this->rosterAt($this->h($salt . '|who') % $n);
            $roll = $this->h($salt . '|res') % 100;
            $denyCut = $door['highSecurity'] ? 34 : 12;
            if ($roll < $denyCut) {
                $result = 'DENIED';
                $reason = $this->pick(['schedule', 'access-level', 'anti-passback', 'expired badge'], $salt . '|why');
            } else {
                $result = 'GRANTED';
                $reason = $door['name'];
            }
            $out[] = array(
                'time' => FrozenClock::ymd($epoch) . ' ' . $this->clock($epoch),
                'result' => $result,
                'badge' => $this->maskBadge($person['badgeId']),
                'holder' => $person['name'],
                'reason' => $reason,
            );
        }
        return $out;
    }

    /**
     * The building-wide access-event scroll as preformatted lines (aligned columns), newest first, each
     * carrying its ACS controller's RFC1918 source. Row $i's time is a strictly-backward walk off
     * deployEpoch() (a seeded positive gap subtracted per step, cumulative — not an independent draw per
     * row), so the scroll never jumps forward and row 0 is never later than "now" (spec E11). One
     * off-hours GRANTED to a server room is buried in when the budget allows — the thread the incident
     * view reconstructs; its slot is pulled back to the nearest earlier off-hours instant without breaking
     * the walk's strict ordering, and the rows after it continue the walk from there. Deterministic per
     * seed+page. Every row prints the full civil date alongside the time (spec E11): a scroll long enough
     * to cross local midnight must not read as the clock jumping backward with no date to explain it.
     *
     * @return list<string>
     */
    public function accessEventLog(int $count): array
    {
        $doors = $this->doors();
        $n = $this->org->headcount();
        $plantOffHours = ($this->h('offhours') % 3) === 0;
        $out = [];
        $epoch = self::deployEpoch();
        for ($i = 0; $i < $count; $i++) {
            $salt = 'log|' . $i;
            $epoch -= $this->intIn(40, 400, $salt . '|gap');
            $door = $doors[$this->h($salt . '|door') % count($doors)];
            $person = $this->rosterAt($this->h($salt . '|who') % $n);

            $roll = $this->h($salt . '|res') % 100;
            if ($plantOffHours && $i === 3) {
                // The buried off-hours server-room grant — the anomaly the alerts module narrates. Pulled
                // back to the nearest earlier off-hours instant (never later than the walk already
                // reached), so the scroll still reads strictly newest-first around it.
                $result = 'GRANTED';
                $srv = $this->firstHighSecDoor($doors);
                $door = $srv !== null ? $srv : $door;
                $epoch = $this->offHoursEpoch($salt, $epoch);
            } elseif ($roll < 8) {
                $result = 'FORCED';
            } elseif ($roll < 22) {
                $result = 'DENIED';
            } else {
                $result = 'GRANTED';
            }

            $out[] = FrozenClock::ymd($epoch) . ' ' . $this->clock($epoch)
                . '  ' . str_pad($result, 8)
                . ' ' . str_pad($this->maskBadge($person['badgeId']), 8)
                . ' ' . str_pad($this->truncate($person['name'], 20), 20)
                . ' ' . str_pad($door['id'], 22)
                . ' src ' . $door['controllerIp'];
        }
        return $out;
    }

    /** A deterministic second-of-day inside the off-hours window (22:00–05:00) for the planted grant. */
    private function offHoursSecond(string $salt): int
    {
        // 7-hour window: 00:00–05:00 (5 h) then 22:00–24:00 (2 h).
        $r = $this->h($salt . '|offhrs') % (7 * 3600);
        return $r < 5 * 3600 ? $r : (22 * 3600 + ($r - 5 * 3600));
    }

    /**
     * The most recent occurrence of the planted off-hours second-of-day that is still strictly earlier
     * than $ceiling (the walk's own epoch reaching this row), as an absolute epoch. The time-of-day alone
     * (offHoursSecond) has no date; pairing it with $ceiling's calendar day would read as a future/
     * simultaneous event whenever the off-hours second lands at or after $ceiling, so this rolls the date
     * back a day at a time until it doesn't — keeping the walk strictly newest-first (spec E11) whatever
     * point in the walk it is spliced into.
     */
    private function offHoursEpoch(string $salt, int $ceiling): int
    {
        $secOfDay = $this->offHoursSecond($salt);
        $midnightOfCeiling = $ceiling - ($ceiling % 86400);
        $epoch = $midnightOfCeiling + $secOfDay;
        while ($epoch >= $ceiling) {
            $epoch -= 86400;
        }
        return $epoch;
    }

    private function firstHighSecDoor(array $doors): ?array
    {
        foreach ($doors as $d) {
            if ($d['highSecurity']) {
                return $d;
            }
        }
        return null;
    }

    // --- cardholders / badges (the Org roster + its contractors) ---

    /** Total cardholders = the Org count-ratio (headcount + contractors); never an out-of-scale number. */
    public function cardholderCount(): int
    {
        return $this->org->magnitudes()['cardholders'];
    }

    /**
     * One page of the cardholder roster by absolute offset, so page 40 renders identically and instantly.
     * Employees (index < N) are the Org roster; the tail are fabricated contractors — the split reconciles
     * to the count-ratio table. Badges masked, PINs never rendered.
     *
     * @return list<array{badge:string,holder:string,dept:string,level:string,status:string,lastDoor:string,lastSeen:string,pin:string}>
     */
    public function cardholderPage(int $offset, int $limit): array
    {
        $total = $this->cardholderCount();
        if ($offset < 0) {
            $offset = 0;
        }
        $out = [];
        for ($k = 0; $k < $limit; $k++) {
            $i = $offset + $k;
            if ($i >= $total) {
                break;
            }
            $out[] = $this->cardholderAt($i);
        }
        return $out;
    }

    /** One cardholder by absolute roster index (0-based). */
    private function cardholderAt(int $i): array
    {
        $n = $this->org->headcount();
        $doors = $this->doors();
        $lastDoor = $doors[$this->h('chdoor|' . $i) % count($doors)]['id'];
        $lastSeen = $this->ageAgo('chseen|' . $i);

        if ($i < $n) {
            $person = $this->rosterAt($i);
            $level = $this->levelForPerson($person);
            $status = $this->statusForEmployee($person);
            $badge = $person['badgeId'];
            $holder = $person['name'];
            $dept = $person['dept'];
        } else {
            // Contractor tail — fabricated, badge numbering continues past the employee block.
            $j = $i - $n;
            $fore = $this->pick(['Sam', 'Alex', 'Jo', 'Robin', 'Casey', 'Drew', 'Lee', 'Morgan'], 'cfore|' . $j);
            $sur = $this->pick(['Doyle', 'Hart', 'Ford', 'Beck', 'Cole', 'Frost', 'Nash', 'Reed'], 'csur|' . $j);
            $holder = $fore . ' ' . $sur;
            $dept = $this->pick(['Cleaning Co.', 'FM Contractor', 'Security Services', 'Catering', 'AV Vendor'], 'cvend|' . $j);
            $level = 'Contractor';
            $status = ($this->h('cstat|' . $j) % 10) < 8 ? 'Active' : 'Expired';
            $badge = sprintf('%06d', 8000 + $j);
        }

        // Budgeted badge baits: a single MASTER all-doors badge and a lost-but-active badge.
        if ($i === 0 && ($this->h('masterbadge') % 3) === 0) {
            $level = 'MASTER';
            $badge = '000001';
        } elseif ($i === 1 && ($this->h('lostbadge') % 3) === 0) {
            $status = 'Lost (active)';
        }

        return array(
            'badge' => $this->maskBadge($badge),
            'holder' => $holder,
            'dept' => $dept,
            'level' => $level,
            'status' => $status,
            'lastDoor' => $lastDoor,
            'lastSeen' => $lastSeen,
            'pin' => '••••',
        );
    }

    private function levelForPerson(array $person): string
    {
        if ($person['band'] === 'EX' || $person['band'] === 'M5') {
            return 'Executive';
        }
        if ($person['dept'] === 'Facilities') {
            return 'Facilities';
        }
        if ($person['dept'] === 'IT' || $person['dept'] === 'Security') {
            return 'SERVER-ROOM';
        }
        return 'Employee';
    }

    private function statusForEmployee(array $person): string
    {
        if ($person['status'] === 'Notice') {
            return 'Expiring';
        }
        return 'Active';
    }

    /**
     * Who-has-access at a door: for a high-security door only elevated levels, for an ordinary door a broad
     * employee set. Names come from the roster so the list agrees with the directory.
     *
     * @return list<array{holder:string,dept:string,level:string,lastSeen:string}>
     */
    public function whoHasAccess(string $doorId, int $count): array
    {
        $door = $this->door($doorId);
        $n = $this->org->headcount();
        $allowed = $door['highSecurity']
            ? array('Executive', 'Facilities', 'SERVER-ROOM', 'MASTER')
            : array('Employee', 'Executive', 'Facilities', 'SERVER-ROOM', 'MASTER');
        $out = [];
        $scanned = 0;
        $i = $this->h('whoa|' . $doorId) % $n;
        while (count($out) < $count && $scanned < $n) {
            $person = $this->rosterAt($i % $n);
            $level = $this->levelForPerson($person);
            if (in_array($level, $allowed, true)) {
                $out[] = array(
                    'holder' => $person['name'],
                    'dept' => $person['dept'],
                    'level' => $level,
                    'lastSeen' => $this->ageAgo('whoseen|' . $doorId . '|' . $i),
                );
            }
            $i++;
            $scanned++;
        }
        return $out;
    }

    /**
     * The auto-unlock schedule for a door. High-security doors stay Card+PIN around the clock; ordinary
     * doors auto-unlock through office hours.
     *
     * @return list<array{days:string,window:string,mode:string}>
     */
    public function scheduleFor(string $doorId): array
    {
        $door = $this->door($doorId);
        if ($door['highSecurity']) {
            return array(
                array('days' => 'Mon–Sun', 'window' => '00:00–24:00', 'mode' => 'Card+PIN (no auto-unlock)'),
            );
        }
        $open = sprintf('%02d:00', $this->intIn(6, 8, 'schopen|' . $doorId));
        $close = sprintf('%02d:00', $this->intIn(18, 20, 'schclose|' . $doorId));
        return array(
            array('days' => 'Mon–Fri', 'window' => $open . '–' . $close, 'mode' => 'Unlocked office-hours'),
            array('days' => 'Mon–Fri', 'window' => $close . '–' . $open, 'mode' => 'Card only'),
            array('days' => 'Sat–Sun', 'window' => '00:00–24:00', 'mode' => 'Card only'),
        );
    }

    /**
     * Anti-passback configuration for a door — enabled on high-security readers, off on stair lobbies.
     *
     * @return list<array{0:string,1:string}>
     */
    public function antiPassbackFor(string $doorId): array
    {
        $door = $this->door($doorId);
        $enabled = $door['highSecurity'] || ($this->h('apb|' . $doorId) % 2) === 0;
        return array(
            array('Anti-passback', $enabled ? 'Enabled' : 'Disabled'),
            array('Mode', $enabled ? ($door['highSecurity'] ? 'Hard' : 'Soft') : '—'),
            array('Reset timeout', $enabled ? $this->intIn(4, 12, 'apbto|' . $doorId) . ' h' : '—'),
            array('Area (in)', $door['area']),
            array('Area (out)', $enabled ? 'Public / Egress' : '—'),
        );
    }

    // --- roster helpers (one lookup into Org, cached) ---

    /** One roster person by 0-based index (< headcount). */
    private function rosterAt(int $i): array
    {
        if ($this->rosterCache === null) {
            $this->rosterCache = $this->org->people($this->org->headcount());
        }
        return $this->rosterCache[$i];
    }

    private function rosterName(int $i): string
    {
        return $this->rosterAt($i)['name'];
    }

    // --- small string/format helpers ---

    private function floorLabel(string $code): string
    {
        foreach ($this->building->floors() as $f) {
            if ($f['code'] === $code) {
                return $f['label'];
            }
        }
        return 'Level ' . $code;
    }

    private function zoneName(string $zone): string
    {
        $names = array('N' => 'North', 'E' => 'East', 'S' => 'South', 'W' => 'West', 'Core' => 'Core');
        return isset($names[$zone]) ? $names[$zone] : $zone;
    }

    /** Human title from a door slug for a synthetic (unknown-id) door. */
    private function prettyName(string $id): string
    {
        $base = strpos($id, 'door-') === 0 ? substr($id, strlen('door-')) : $id;
        $words = explode('-', $base);
        $out = array();
        foreach ($words as $w) {
            if ($w !== '') {
                $out[] = ucfirst($w);
            }
        }
        return $out === array() ? 'Door' : implode(' ', $out);
    }

    private function truncate(string $s, int $len): string
    {
        return strlen($s) > $len ? substr($s, 0, $len - 1) . '…' : $s;
    }
}
