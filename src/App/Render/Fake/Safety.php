<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT fire & life-safety plane for the deep office panel — the fire alarm control
 * panel (FACP), gaseous/water suppression per protected space, the sprinkler zones, the SLC detector
 * loops, emergency lighting and the incident buffer. This is flagship lure #2: it must LOOK lethal and
 * do ABSOLUTELY NOTHING. The section that renders this never returns real success on a life-safety verb.
 *
 * Design rules (deep-admin dashboard spec §C.4 + adversarial critique):
 *  - COHERENT with Building: gaseous suppression anchors on the site's real Server-Comms rooms (shared
 *    Fake\Building topology) so the same server room is a suppression zone here, an HVAC CRAC zone, an
 *    access door and a camera elsewhere. Fixed special spaces (records vault, kitchen, parking) round it out.
 *  - DETERMINISTIC per seed: every value is hash(seed+slot) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); ages/timestamps derive from one frozen DEPLOY_EPOCH. Same seed ->
 *    byte-identical panel (a shifting fire panel is itself a tell).
 *  - SAFE: FACP addressing is RFC1918 only (fire OT segment 10.0.80.x). Invented panel/loop ids only,
 *    never a scanner-signature string. Panel status is always NORMAL — no live alarm to "acknowledge".
 *  - ANOMALY BUDGET (E2/T2): hash(seed) plants 0-2 benign faults (a detector in fault, an isolated zone,
 *    a luminaire out) — never the fifty-honeytoken buffet.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/number_format, no enums/named-args/str_contains/
 *    constructor promotion) so a fact can promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders and escapes it.
 */
final class Safety
{
    /** Frozen "now" for ages/timestamps so a static reload is not a tell. Matches Building/Org. */
    public const DEPLOY_EPOCH = FrozenClock::EPOCH;

    /** SLC detector devices across the loops — a long inert address list (spec §C.4). */
    public const DETECTOR_TOTAL = 512;

    /** Incident buffer depth reported by the panel (only page N is ever rendered). */
    public const INCIDENT_TOTAL = 8640;

    /** @var int */
    private $seed;

    private function __construct(int $seed)
    {
        $this->seed = $seed;
    }

    public static function fromSeed(int $seed): self
    {
        return new self($seed);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|safety|' . $salt), 0, 15));
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

    /** Seeded "N ago" off DEPLOY_EPOCH — deterministic, never time()/date(). */
    private function ageAgo(string $salt): string
    {
        $sec = $this->intIn(60, 2592000, $salt);        // 1 min .. 30 days
        if ($sec < 5400) {
            return (int) round($sec / 60) . ' min ago';
        }
        if ($sec < 172800) {
            return (int) round($sec / 3600) . ' h ago';
        }
        return (int) round($sec / 86400) . ' d ago';
    }

    // --- the fire alarm control panel (FACP) ---

    /**
     * Panel headline status. Always NORMAL (no live alarm to acknowledge); AC present, battery healthy,
     * dual loops. A budgeted single "trouble" (supervisory, benign) may be present (E2).
     *
     * @return array{id:string,model:string,status:string,loops:int,devicesTotal:int,devicesOnline:int,batteryVolts:string,mainsVolts:string,ac:string,ip:string,protocol:string,firmware:string,trouble:string}
     */
    public function panel(): array
    {
        $devTotal = self::DETECTOR_TOTAL;
        $faults = $this->faultAddresses();
        $trouble = '';
        // Budget: sometimes a single benign supervisory trouble (a detector on the fault list surfaced).
        if ($faults !== [] && ($this->h('paneltrouble') % 2) === 0) {
            $trouble = 'Supervisory: device fault on loop ' . $faults[0]['loop'] . ' (' . $faults[0]['address'] . ')';
        }
        return [
            'id' => 'FACP-01',
            'model' => $this->pick(['Sentinel FX-4', 'Guardian LP-8', 'Aegis 4000', 'Vanguard C4'], 'panelmodel'),
            'status' => 'NORMAL',
            'loops' => 4,
            'devicesTotal' => $devTotal,
            'devicesOnline' => $devTotal - count($faults),
            'batteryVolts' => number_format(26.4 + $this->h('batt') % 12 / 10, 1) . ' V',
            'mainsVolts' => (230 + $this->h('mains') % 8) . ' V',
            'ac' => 'present',
            'ip' => '10.0.80.' . $this->intIn(10, 14, 'panelip'),
            'protocol' => 'FACP loop / IP gateway',
            'firmware' => 'v' . $this->intIn(3, 7, 'pfa') . '.' . $this->intIn(0, 20, 'pfb') . '.' . $this->intIn(0, 40, 'pfc'),
            'trouble' => $trouble,
        ];
    }

    // --- suppression zones (gaseous + water per protected space) ---

    /**
     * Suppression per protected space. Server-Comms rooms from the shared Building topology take clean
     * gaseous agent (so the same server room reconciles across HVAC/access/CCTV); fixed special spaces
     * (records vault, kitchen, parking, comms riser) round out the set. Status is Armed by default; the
     * anomaly budget may isolate exactly ONE zone for works (never a buffet of disarmed suppression).
     *
     * @return list<array{id:string,name:string,space:string,floor:string,room:string,agent:string,status:string,cylinders:string,agentKg:string,controller:string,controllerIp:string,loop:int,releaseMode:string}>
     */
    public function zones(): array
    {
        $rows = [];

        // All rooms across the building, flat — the pool every protected space anchors to, so a suppression
        // zone always names a real floor + room (same-rooms-everywhere coherence, never a phantom B1 vault).
        $bld = Building::fromSeed($this->seed);
        $allRooms = array();
        foreach ($bld->floors() as $f) {
            foreach ($bld->roomsFor($f['code']) as $r) {
                $allRooms[] = $r;
            }
        }
        $used = array();

        // Anchor on the real server rooms of the building (up to 3), clean-agent protected.
        $serverRooms = array();
        foreach ($allRooms as $r) {
            if ($r['type'] === 'Server-Comms') {
                $serverRooms[] = $r;
            }
        }
        $take = count($serverRooms) < 3 ? count($serverRooms) : 3;
        for ($i = 0; $i < $take; $i++) {
            $r = $serverRooms[$i];
            $used[$r['id']] = true;
            $rows[] = $this->zoneRow(
                'srv-' . strtolower($r['floor']) . '-' . sprintf('%02d', $i + 1),
                $r['name'] . ' (Server Room)',
                'Floor ' . $r['floor'] . ' · ' . $r['name'],
                $r['floor'],
                $r['id'],
                $this->pick(['FM-200 (HFC-227ea)', 'Novec 1230', 'IG-541 inert gas'], 'srvagent|' . $i),
                'gaseous',
                $i
            );
        }

        // Fixed special spaces, always present so the crown-jewel list reads complete — but each anchored to
        // a REAL room of a fitting type (with fallbacks), never a hardcoded floor/room the topology lacks.
        $fixed = array(
            array('records-vault', 'Records Vault', array('Store', 'Server-Comms'), 'Novec 1230', 'gaseous'),
            array('main-kitchen', 'Main Kitchen', array('Kitchen'), 'Wet chemical (K-class)', 'wet-chem'),
            array('parking-preaction', 'Parking / Loading', array('Plant', 'Store'), 'Pre-action (water)', 'preaction'),
            array('comms-riser', 'Comms Riser Stack', array('Server-Comms', 'Plant', 'Store'), 'CO2 total flood', 'gaseous'),
        );
        $n = 1;
        foreach ($fixed as $fx) {
            $room = $this->pickSpaceRoom($allRooms, $used, $fx[2]);
            $rows[] = $this->zoneRow(
                $fx[0],
                $fx[1],
                'Floor ' . $room['floor'] . ' · ' . $room['name'],
                $room['floor'],
                $room['id'],
                $fx[3],
                $fx[4],
                $take + $n
            );
            $n++;
        }

        // Anomaly budget: isolate exactly one zone for works, sometimes (E2).
        if ($rows !== [] && ($this->h('zoneanom') % 3) === 0) {
            $idx = $this->h('zoneanomidx') % count($rows);
            $rows[$idx]['status'] = 'Isolated (works)';
        }

        return $rows;
    }

    /**
     * Pick a real building room for a fixed protected space: the first unused room of a preferred type,
     * else the first unused room of any type, else any room; marks the chosen room used so two special
     * spaces never collide. Falls back to a slug-safe synthetic only if the building has no rooms at all.
     *
     * @param list<array<string,mixed>> $allRooms
     * @param array<string,bool> $used
     * @param list<string> $preferredTypes
     * @return array<string,mixed>
     */
    private function pickSpaceRoom(array $allRooms, array &$used, array $preferredTypes): array
    {
        foreach ($preferredTypes as $type) {
            foreach ($allRooms as $r) {
                if ($r['type'] === $type && !isset($used[$r['id']])) {
                    $used[$r['id']] = true;
                    return $r;
                }
            }
        }
        foreach ($allRooms as $r) {
            if (!isset($used[$r['id']])) {
                $used[$r['id']] = true;
                return $r;
            }
        }
        if ($allRooms !== array()) {
            return $allRooms[0];
        }
        return array('id' => 'room-g-01', 'name' => 'Core', 'floor' => 'G', 'zone' => 'Core', 'type' => 'Store');
    }

    /** @return array<string,mixed> one suppression zone row */
    private function zoneRow(string $key, string $name, string $space, string $floor, string $room, string $agent, string $class, int $i): array
    {
        $cyl = $this->intIn(1, 4, 'cyl|' . $key);
        $ctrl = ($i % 2) === 0 ? 'FACP-01' : 'FACP-02';
        return array(
            'id' => 'zone-' . $key,
            'name' => $name,
            'space' => $space,
            'floor' => $floor,
            'room' => $room,
            'agent' => $agent,
            'status' => 'Armed',
            'cylinders' => $cyl . '/' . $cyl,
            'agentKg' => $class === 'gaseous' ? number_format(18 + $this->h('kg|' . $key) % 620 / 10, 1) . ' kg' : 'n/a',
            'controller' => $ctrl,
            'controllerIp' => '10.0.80.' . (($i % 2) === 0 ? '11' : '12'),
            'loop' => 1 + ($i % 4),
            'releaseMode' => $class === 'gaseous' ? 'Automatic + manual (double-knock)' : ($class === 'preaction' ? 'Pre-action (interlocked)' : 'Manual + thermal link'),
        );
    }

    /** One suppression zone by id (zone-...), or null if the id is not one this seed produced. */
    public function zone(string $id): ?array
    {
        foreach ($this->zones() as $z) {
            if ($z['id'] === $id) {
                return $z;
            }
        }
        return null;
    }

    // --- SLC detector loops (the long inert address list) ---

    /**
     * A page of the SLC detector estate (spec §C.4: 255+ addresses = long inert list). Addresses are
     * loop-and-device numbered; type is a real detector device class; state is Normal but for the
     * budgeted fault list. Deterministic per (offset,limit) so any page renders byte-identical.
     *
     * @return list<array{address:string,loop:int,type:string,zone:string,state:string,lastTest:string}>
     */
    public function detectors(int $offset, int $limit): array
    {
        if ($offset < 0) {
            $offset = 0;
        }
        if ($limit < 0) {
            $limit = 0;
        }
        $end = $offset + $limit;
        if ($end > self::DETECTOR_TOTAL) {
            $end = self::DETECTOR_TOTAL;
        }
        $types = array('Optical smoke', 'Heat (A1R)', 'Multi-sensor', 'Duct smoke', 'Manual call point', 'Beam detector', 'Aspirating (VESDA)');
        $faultAddrs = array();
        foreach ($this->faultAddresses() as $fa) {
            $faultAddrs[$fa['address']] = $fa['state'];
        }
        $out = [];
        for ($i = $offset; $i < $end; $i++) {
            $loop = 1 + ($i % 4);
            $dev = 1 + (int) ($i / 4);
            $addr = 'L' . $loop . '-D' . sprintf('%03d', $dev);
            $out[] = array(
                'address' => $addr,
                'loop' => $loop,
                'type' => $types[$this->h('dtype|' . $i) % count($types)],
                'zone' => 'Z' . sprintf('%02d', 1 + $this->h('dzone|' . $i) % 24),
                'state' => isset($faultAddrs[$addr]) ? $faultAddrs[$addr] : 'Normal',
                'lastTest' => $this->ageAgo('dtest|' . $i),
            );
        }
        return $out;
    }

    /**
     * The budgeted detector faults (0-2), each an SLC address in the estate. This is the single source
     * the panel trouble line and the detector list both read, so they never disagree.
     *
     * @return list<array{address:string,loop:int,state:string}>
     */
    private function faultAddresses(): array
    {
        $count = $this->h('nfaults') % 3;              // 0, 1 or 2
        $out = [];
        for ($k = 0; $k < $count; $k++) {
            $i = $this->h('faultidx|' . $k) % self::DETECTOR_TOTAL;
            $loop = 1 + ($i % 4);
            $dev = 1 + (int) ($i / 4);
            $out[] = array(
                'address' => 'L' . $loop . '-D' . sprintf('%03d', $dev),
                'loop' => $loop,
                'state' => $this->pick(array('Fault', 'Dirty — service due'), 'faultstate|' . $k),
            );
        }
        return $out;
    }

    // --- sprinkler zones ---

    /**
     * Wet/dry/pre-action sprinkler zones with supervised pressure and flow-switch state. Each zone
     * anchors to a floor the shared Building topology actually has (never a hardcoded B1/level-8 the
     * seed's stack may lack): parking rides the deepest basement (ground if none), server pre-action
     * the floor of a real Server-Comms room, office wet the top upper level, deluge the roof.
     *
     * @return list<array{id:string,name:string,type:string,status:string,pressurePsi:int,flowSwitch:string,floor:string}>
     */
    public function sprinklerZones(): array
    {
        $bld = Building::fromSeed($this->seed);
        $ground = 'G';
        $roof = 'Roof';
        $basement = '';        // deepest basement code, if the stack has one
        $topOffice = $ground;  // highest numbered upper level, else ground
        foreach ($bld->floors() as $f) {
            $code = $f['code'];
            if ($code !== '' && $code[0] === 'B' && ($basement === '' || $code > $basement)) {
                $basement = $code;                       // 'B2' > 'B1' lexically -> deepest
            }
            if (ctype_digit($code) && ($topOffice === $ground || (int) $code > (int) $topOffice)) {
                $topOffice = $code;
            }
        }
        // Server / comms pre-action rides the floor of a real Server-Comms room, else ground.
        $serverFloor = $ground;
        foreach ($bld->floors() as $f) {
            foreach ($bld->roomsFor($f['code']) as $r) {
                if ($r['type'] === 'Server-Comms') {
                    $serverFloor = $r['floor'];
                    break 2;
                }
            }
        }
        $parkingFloor = $basement !== '' ? $basement : $ground;

        $defs = array(
            array('sz-office-wet', 'Office floors (wet)', 'Wet pipe', $topOffice),
            array('sz-parking-dry', 'Parking / loading (dry)', 'Dry pipe', $parkingFloor),
            array('sz-server-preaction', 'Server / comms (pre-action)', 'Pre-action', $serverFloor),
            array('sz-plant-deluge', 'Roof plant (deluge)', 'Deluge', $roof),
            array('sz-atrium-wet', 'Atrium & reception (wet)', 'Wet pipe', $ground),
        );
        $out = [];
        foreach ($defs as $d) {
            $out[] = array(
                'id' => $d[0],
                'name' => $d[1],
                'type' => $d[2],
                'status' => 'Supervised',
                'pressurePsi' => $this->intIn(48, 92, 'psi|' . $d[0]),
                'flowSwitch' => 'No flow',
                'floor' => $d[3],
            );
        }
        return $out;
    }

    // --- emergency lighting ---

    /**
     * Emergency lighting summary: maintained exit signs + non-maintained luminaires on test, with a
     * budgeted small number of luminaires in fault (E2).
     *
     * @return array{exitSignsTotal:int,exitSignsOk:int,luminairesTotal:int,luminairesOk:int,luminairesFault:int,lastDurationTest:string,nextDurationTest:string}
     */
    public function emergencyLighting(): array
    {
        $exit = $this->intIn(28, 64, 'exitsigns');
        $lum = $this->intIn(120, 340, 'lumtotal');
        $fault = ($this->h('lumanom') % 3) === 0 ? $this->intIn(1, 2, 'lumfault') : 0;
        return array(
            'exitSignsTotal' => $exit,
            'exitSignsOk' => $exit,
            'luminairesTotal' => $lum,
            'luminairesOk' => $lum - $fault,
            'luminairesFault' => $fault,
            'lastDurationTest' => $this->ageAgo('ellast'),
            'nextDurationTest' => 'in ' . $this->intIn(20, 160, 'elnext') . ' d',
        );
    }

    // --- incident buffer ---

    /**
     * A page of the incident buffer — benign life-safety operations (tests, isolations, cleared faults),
     * never a live fire. Row $i's timestamp is a strictly-backward walk off DEPLOY_EPOCH (a seeded positive
     * gap subtracted per step, absolute-index-keyed so any page recomputes the same date+time for the same
     * row): newest-first, never in the future, and the printed date advances exactly when the walk crosses
     * midnight. Each incident is located in a real Building room (never an invented floor/room the topology
     * lacks), so the location reconciles with the suppression zones and every space referenced elsewhere.
     *
     * @return list<array{ref:string,time:string,type:string,location:string,floor:string,room:string,severity:string,status:string}>
     */
    public function incidents(int $offset, int $limit): array
    {
        if ($offset < 0) {
            $offset = 0;
        }
        if ($limit < 0) {
            $limit = 0;
        }
        $types = array(
            'Weekly bell test', 'Detector fault cleared', 'Zone isolated for works',
            'Battery load test — pass', 'Sprinkler flow-switch test', 'Manual call point reset',
            'Panel walk-test', 'Supervisory restored', 'Drill — occupants NOT notified (test mode)',
        );
        $sev = array('Info', 'Info', 'Info', 'Low', 'Low');

        // Real building rooms — an incident always names a space the topology actually has.
        $bld = Building::fromSeed($this->seed);
        $rooms = array();
        foreach ($bld->floors() as $f) {
            foreach ($bld->roomsFor($f['code']) as $r) {
                $rooms[] = $r;
            }
        }
        if ($rooms === array()) {
            $rooms[] = array('id' => 'room-g-01', 'name' => 'Core', 'floor' => 'G');
        }

        // Strictly-descending epochs for every row up to this page, walked backward from DEPLOY_EPOCH so
        // paging never repeats a date or reverses the clock, and row 0 is never later than "now".
        $end = $offset + $limit;
        $epoch = self::DEPLOY_EPOCH;
        $epochs = array();
        for ($k = 0; $k < $end; $k++) {
            $epoch -= $this->intIn(60, 900, 'incgap|' . $k);
            $epochs[$k] = $epoch;
        }

        $out = [];
        for ($k = 0; $k < $limit; $k++) {
            $i = $offset + $k;
            $room = $rooms[$this->h('incroom|' . $i) % count($rooms)];
            $rowEpoch = $epochs[$i];
            $out[] = array(
                'ref' => 'FIRE-2026-' . sprintf('%05d', self::INCIDENT_TOTAL - $i),
                'time' => FrozenClock::ymd($rowEpoch) . ' ' . FrozenClock::clock($rowEpoch),
                'type' => $types[$this->h('inctype|' . $i) % count($types)],
                'location' => $room['name'] . ' (Floor ' . $room['floor'] . ')',
                'floor' => $room['floor'],
                'room' => $room['id'],
                'severity' => $sev[$this->h('incsev|' . $i) % count($sev)],
                'status' => 'Closed',
            );
        }
        return $out;
    }

    /**
     * A deterministic command id for an inert control leaf (hash(seed+path)); the section echoes it so a
     * "queued" / interlock-denied receipt looks like a real ticketed operation. Never a real handle.
     */
    public function commandId(string $path): string
    {
        return 'CMD-' . substr(hash('sha256', $this->seed . '|safetycmd|' . $path), 0, 8);
    }
}
