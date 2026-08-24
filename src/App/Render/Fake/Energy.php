<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT electrical / power / BMS-energy plane for the deep office panel (spec §C.8,
 * SCADA-flavoured). Sits on top of Building (the coherence spine): sub-meters, breaker boards, UPS,
 * generators, solar strings and HVAC plant all anchor to real floors and real Plant/Server-Comms rooms,
 * so an attacker who cross-references the energy console against HVAC/access finds one consistent estate.
 *
 * Design rules (spec §C.8 + adversarial critique):
 *  - DETERMINISTIC per seed: every reading is hash(seed+slot) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); a meter's facts derive from its id alone, so meter($id) is
 *    byte-identical to that meter's row in meters() and reproducible standalone. Ages are seeded
 *    "N ago" strings, never time().
 *  - COHERENT + RECONCILED: building load = sum of sub-meter kW; today's kWh, cost and carbon derive from
 *    that one load via seeded factors; active alarms = the counted meter comms-fails plus the one solar
 *    fault. A 6-floor site never shows a mismatch between its headline and its rows.
 *  - SAFE: the electrical OT fabric is RFC1918 only — field controllers on 10.20.31.x, the lone SNMP
 *    trap-receiver on 10.20.99.7 (the "hidden VLAN" itch, appears nowhere else). Invented board/model ids
 *    only (never a scanner-signature string).
 *  - ANOMALY BUDGET (E2): 2-3 sub-meters read Comms FAIL and exactly one solar string carries a fault;
 *    everything else reads clean. Not the fifty-honeytoken buffet.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/number_format, no enums/named-args/str_contains/
 *    constructor promotion) so a fact can promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders and escapes it.
 */
final class Energy
{
    /** Frozen "now" so a static reload is not a tell (spec E11). Matches Building/Hvac. */
    public const DEPLOY_EPOCH = FrozenClock::EPOCH;

    /** Field-controller (breaker/board) OT subnet — RFC1918, distinct from the BMS 10.0.50.x fabric. */
    public const FC_SUBNET = '10.20.31.';

    /** The lone SNMP trap-receiver the UPS fleet points at — appears on no other page (the hidden-VLAN lure). */
    public const SNMP_TRAP_IP = '10.20.99.7';

    /** SNMP port the UPS network cards answer on. */
    public const SNMP_PORT = 161;

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
        return (int) hexdec(substr(hash('sha256', $this->seed . '|energy|' . $salt), 0, 15));
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

    /** One decimal in [min,max], deterministic per salt. */
    private function decIn(float $min, float $max, string $salt): float
    {
        $steps = (int) round(($max - $min) * 10);
        if ($steps < 1) {
            $steps = 1;
        }
        return round($min + ($this->h($salt) % ($steps + 1)) / 10, 1);
    }

    /** vN.N firmware string, frozen per component. */
    private function firmware(string $salt): string
    {
        return 'v' . $this->intIn(1, 5, $salt . '|fa') . '.' . $this->intIn(0, 30, $salt . '|fb');
    }

    /** Seeded "N ago" string — pure hash(seed+slot), deterministic, never time()/date(). */
    private function ageAgo(string $salt): string
    {
        $sec = $this->intIn(3, 172800, $salt);
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

    /** @return list<int> k distinct indices in [0,$n) chosen deterministically from $salt. */
    private function pickIndices(int $n, int $k, string $salt): array
    {
        if ($n <= 0 || $k <= 0) {
            return [];
        }
        $out = [];
        $i = 0;
        while (count($out) < $k && $i < $n * 4) {
            $idx = $this->h($salt . '|' . $i) % $n;
            if (!in_array($idx, $out, true)) {
                $out[] = $idx;
            }
            $i++;
        }
        sort($out);
        return $out;
    }

    // --- tariff / carbon identity (frozen per deploy) ---

    /** Currency symbol + code keyed off the site timezone so cost reads with the building's locale. */
    private function currency(): array
    {
        $tz = $this->bld->site()['timezone'];
        if ($tz === 'Europe/London') {
            return ['sym' => '£', 'code' => 'GBP'];
        }
        if (strpos($tz, 'America/') === 0) {
            return ['sym' => '$', 'code' => 'USD'];
        }
        return ['sym' => '€', 'code' => 'EUR'];
    }

    // --- sub-meters (per floor / circuit) ---

    /** Circuit types a floor's distribution is broken down into. */
    private function circuitVocab(): array
    {
        return ['Lighting', 'Small Power', 'HVAC', 'Mechanical', 'Kitchen', 'Server Room', 'Chiller Plant'];
    }

    /**
     * Every sub-meter across the building, plus the two main incomers at the MSB. Order is stable (MSB
     * first, then floor stack, then circuit order within a floor). Comms status carries the budgeted 2-3
     * FAIL rows (spec §C.8 — the dead-sub-meter chase); everything else reads OK.
     *
     * @return list<array{id:string,label:string,scope:string,floor:string,floorLabel:string,circuit:string,kw:float,kwhToday:float,pf:float,voltage:int,current:float,controller:string,controllerIp:string,firmware:string,comms:string,lastSeen:string}>
     */
    public function meters(): array
    {
        $raw = [];
        // Main incomers at the main switchboard (utility metering point).
        for ($m = 1; $m <= 2; $m++) {
            $raw[] = ['scope' => 'incomer', 'floor' => 'MSB', 'floorLabel' => 'Main Switchboard', 'circuit' => 'Incomer ' . $m, 'n' => $m];
        }
        foreach ($this->bld->floors() as $f) {
            $circuits = $this->circuitsForFloor($f['code']);
            $n = 0;
            foreach ($circuits as $c) {
                $n++;
                $raw[] = ['scope' => 'circuit', 'floor' => $f['code'], 'floorLabel' => $f['label'], 'circuit' => $c, 'n' => $n];
            }
        }

        // Budgeted comms-fail rows: 2-3 meters across the estate read FAIL, the rest OK.
        $failIdx = $this->pickIndices(count($raw), $this->intIn(2, 3, 'commsfailk'), 'commsfail');

        $out = [];
        foreach ($raw as $i => $r) {
            $id = 'MTR-' . strtoupper($r['floor']) . '-' . sprintf('%02d', $r['n']);
            $out[] = $this->buildMeter($id, $r['scope'], $r['floor'], $r['floorLabel'], $r['circuit'], in_array($i, $failIdx, true));
        }
        return $out;
    }

    /** Circuit breakdown for a floor — a seeded 3-5 slice of the circuit vocab, Kitchen only where present. */
    private function circuitsForFloor(string $floorCode): array
    {
        $vocab = ['Lighting', 'Small Power', 'HVAC', 'Mechanical'];
        // Server rooms / plant floors carry an extra dedicated circuit.
        $hasServer = false;
        $hasPlant = false;
        foreach ($this->bld->roomsFor($floorCode) as $r) {
            if ($r['type'] === 'Server-Comms') {
                $hasServer = true;
            }
            if ($r['type'] === 'Plant') {
                $hasPlant = true;
            }
        }
        if ($hasServer) {
            $vocab[] = 'Server Room';
        }
        if ($hasPlant || $floorCode === 'Roof' || $floorCode[0] === 'B') {
            $vocab[] = 'Chiller Plant';
        }
        return $vocab;
    }

    /**
     * @return array{id:string,label:string,scope:string,floor:string,floorLabel:string,circuit:string,kw:float,kwhToday:float,pf:float,voltage:int,current:float,controller:string,controllerIp:string,firmware:string,comms:string,lastSeen:string}
     */
    private function buildMeter(string $id, string $scope, string $floor, string $floorLabel, string $circuit, bool $failed): array
    {
        // Incomers carry the site load; circuit meters a fraction of it.
        $kw = $scope === 'incomer'
            ? $this->decIn(60.0, 180.0, $id . '|kw')
            : $this->decIn(1.5, 42.0, $id . '|kw');
        $pf = $this->decIn(0.86, 0.99, $id . '|pf');
        $voltage = $this->pick(['230', '400', '400', '415'], $id . '|v');
        // I = P / (sqrt3 * V * pf) for a 3-phase circuit; single number reading is fine for the mirror.
        $current = round(($kw * 1000) / (1.732 * (float) $voltage * max($pf, 0.5)), 1);
        $fc = $this->fieldController($floor);

        return [
            'id' => $id,
            'label' => $floorLabel . ' — ' . $circuit,
            'scope' => $scope,
            'floor' => $floor,
            'floorLabel' => $floorLabel,
            'circuit' => $circuit,
            'kw' => $failed ? 0.0 : $kw,
            'kwhToday' => $failed ? 0.0 : round($kw * $this->decIn(6.0, 13.0, $id . '|hrs'), 1),
            'pf' => $failed ? 0.0 : $pf,
            'voltage' => (int) $voltage,
            'current' => $failed ? 0.0 : $current,
            'controller' => $fc['id'],
            'controllerIp' => $fc['ip'],
            'firmware' => $this->firmware('mtrfw|' . $id),
            'comms' => $failed ? 'FAIL' : 'OK',
            'lastSeen' => $failed ? $this->intIn(2, 40, $id . '|failage') . ' h ago' : $this->ageAgo('mtrseen|' . $id),
        ];
    }

    /** The field controller a floor's boards report through — id keyed by floor, IP on the FC subnet. */
    private function fieldController(string $floor): array
    {
        $slug = strtolower($floor);
        $host = 40 + ($this->h('fc|' . $floor) % 60); // 40-99, RFC1918
        return ['id' => 'FC-' . strtoupper($floor), 'ip' => self::FC_SUBNET . $host];
    }

    /**
     * One sub-meter by id (known -> real; unknown/fuzzed -> synthesised, never a 404 inside the panel).
     *
     * @return array<string,mixed>
     */
    public function meter(string $id): array
    {
        foreach ($this->meters() as $m) {
            if (strcasecmp($m['id'], $id) === 0) {
                return $m;
            }
        }
        return $this->buildMeter($id, 'circuit', 'G', 'Ground', 'Small Power', false);
    }

    /**
     * 24 hourly kW readings for a meter — a gentle seeded diurnal load curve (never time()).
     *
     * @param array<string,mixed> $m a meter() record
     * @return list<float>
     */
    public function meterTrend(array $m): array
    {
        $base = (float) $m['kw'];
        $id = (string) $m['id'];
        $out = [];
        for ($i = 0; $i < 24; $i++) {
            // Daytime occupancy ramp; overnight base load. FAIL meters read a flat zero.
            if ($base <= 0.0) {
                $out[] = 0.0;
                continue;
            }
            $shape = ($i >= 8 && $i <= 19) ? 1.0 : 0.45;
            $jitter = ($this->h($id . '|trend|' . $i) % 21 - 10) / 100.0;
            $out[] = round($base * ($shape + $jitter), 1);
        }
        return $out;
    }

    // --- headline power dashboard (reconciled from the meters) ---

    /**
     * @return array{loadKw:float,kwhToday:float,peakKw:float,costToday:float,currencySym:string,currencyCode:string,
     *   carbonToday:float,tariffRate:float,carbonFactor:float,pvKw:float,pvYieldToday:float,bessSoc:int,
     *   powerFactor:float,activeAlarms:int,meterCount:int,commsFails:int}
     */
    public function summary(): array
    {
        // Building load = sum of the incomer meters (the utility metering point), so the headline
        // reconciles with the meter list a click away.
        $loadKw = 0.0;
        $commsFails = 0;
        foreach ($this->meters() as $m) {
            if ($m['scope'] === 'incomer' && $m['comms'] === 'OK') {
                $loadKw += (float) $m['kw'];
            }
            if ($m['comms'] === 'FAIL') {
                $commsFails++;
            }
        }
        $loadKw = round($loadKw, 1);
        $tariff = $this->decIn(0.14, 0.34, 'tariff');
        $carbonFactor = $this->decIn(0.05, 0.28, 'carbonf'); // kg CO2 per kWh (grid mix)
        $kwhToday = round($loadKw * $this->decIn(7.0, 13.0, 'kwhfactor'), 1);
        $solar = $this->solarSummary();
        $cur = $this->currency();
        $solarFault = $this->solarFaultCount();

        return [
            'loadKw' => $loadKw,
            'kwhToday' => $kwhToday,
            'peakKw' => round($loadKw * $this->decIn(1.12, 1.4, 'peak'), 1),
            'costToday' => round($kwhToday * $tariff, 2),
            'currencySym' => $cur['sym'],
            'currencyCode' => $cur['code'],
            'carbonToday' => round($kwhToday * $carbonFactor, 1),
            'tariffRate' => $tariff,
            'carbonFactor' => $carbonFactor,
            'pvKw' => $solar['outputKw'],
            'pvYieldToday' => $solar['yieldToday'],
            'bessSoc' => $this->bess()['soc'],
            'powerFactor' => $this->decIn(0.9, 0.98, 'sitepf'),
            'activeAlarms' => $commsFails + $solarFault,
            'meterCount' => count($this->meters()),
            'commsFails' => $commsFails,
        ];
    }

    /**
     * 24 hourly building-load readings for the landing sparkline (seeded diurnal curve, never time()).
     *
     * @return list<float>
     */
    public function loadTrend(): array
    {
        $base = $this->summary()['loadKw'];
        $out = [];
        for ($i = 0; $i < 24; $i++) {
            $shape = ($i >= 8 && $i <= 19) ? 1.0 : 0.5;
            $jitter = ($this->h('siteload|' . $i) % 15 - 7) / 100.0;
            $out[] = round($base * ($shape + $jitter), 1);
        }
        return $out;
    }

    // --- breaker schedule (distribution boards + breakers) ---

    /**
     * Distribution boards across the building, each with a breaker schedule. Board id `DB-<floor>-<letter>`,
     * breaker `DB-<floor>-<letter>/<way>`. Reports through the floor's field controller (spec §C.8 toggle
     * copy: "queued to FC-3F (10.20.31.44) - awaiting second operator").
     *
     * @return list<array{id:string,floor:string,floorLabel:string,controller:string,controllerIp:string,ways:int,fedFrom:string}>
     */
    public function boards(): array
    {
        $out = [];
        foreach ($this->bld->floors() as $f) {
            $letters = $this->intIn(1, 3, 'boards|' . $f['code']);
            $fc = $this->fieldController($f['code']);
            for ($b = 0; $b < $letters; $b++) {
                $letter = chr(65 + $b); // A, B, C
                $out[] = [
                    'id' => 'DB-' . strtoupper($f['code']) . '-' . $letter,
                    'floor' => $f['code'],
                    'floorLabel' => $f['label'],
                    'controller' => $fc['id'],
                    'controllerIp' => $fc['ip'],
                    'ways' => $this->intIn(8, 24, 'ways|' . $f['code'] . '|' . $letter),
                    'fedFrom' => 'MSB',
                ];
            }
        }
        return $out;
    }

    /**
     * One board by id (known -> real; unknown -> synthesised), never null.
     *
     * @return array<string,mixed>
     */
    public function board(string $id): array
    {
        foreach ($this->boards() as $b) {
            if (strcasecmp($b['id'], $id) === 0) {
                return $b;
            }
        }
        $fc = $this->fieldController('G');
        return ['id' => $id, 'floor' => 'G', 'floorLabel' => 'Ground', 'controller' => $fc['id'],
                'controllerIp' => $fc['ip'], 'ways' => 12, 'fedFrom' => 'MSB'];
    }

    /**
     * The breaker schedule for a board — one row per way, each a real load with rating, phase and state.
     *
     * @param array<string,mixed> $board a board() record
     * @return list<array{way:string,id:string,load:string,ratingA:int,phase:string,curveType:string,state:string,loadPct:int}>
     */
    public function breakers(array $board): array
    {
        $loads = ['Lighting', 'Ring main', 'Radial', 'HVAC FCU', 'AHU', 'Lift supply', 'Kitchen',
                  'Server rack', 'UPS bypass', 'Comms rack', 'Water heater', 'Fan coil'];
        $curves = ['B', 'C', 'C', 'D'];
        $ratings = [6, 10, 16, 20, 32, 40, 63];
        $id = (string) $board['id'];
        $ways = (int) $board['ways'];
        // One tripped breaker per board occasionally (still within the plant-noise budget, cosmetic only).
        $trippedWay = ($this->h($id . '|trip') % 5 === 0) ? (1 + $this->h($id . '|tripway') % $ways) : -1;

        $out = [];
        for ($w = 1; $w <= $ways; $w++) {
            $salt = $id . '|way|' . $w;
            $state = $w === $trippedWay ? 'TRIPPED' : ($this->h($salt . '|st') % 12 === 0 ? 'OFF' : 'ON');
            $out[] = [
                'way' => (string) $w,
                'id' => $id . '/' . $w,
                'load' => $this->pick($loads, $salt . '|load'),
                'ratingA' => $ratings[$this->h($salt . '|rat') % count($ratings)],
                'phase' => $this->pick(['L1', 'L2', 'L3'], $salt . '|ph'),
                'curveType' => $this->pick($curves, $salt . '|cv'),
                'state' => $state,
                'loadPct' => $state === 'ON' ? $this->intIn(5, 92, $salt . '|lp') : 0,
            ];
        }
        return $out;
    }

    // --- UPS fleet ---

    /**
     * UPS units protecting the server/comms rooms and life-safety loads. Each names a real room and a
     * battery string count; the fleet points its SNMP traps at the lone hidden trap-receiver.
     *
     * @return list<array{id:string,model:string,room:string,floor:string,capacityKva:int,loadPct:int,
     *   battRuntimeMin:int,battSoc:int,strings:int,mode:string,ip:string,firmware:string,status:string}>
     */
    public function upsFleet(): array
    {
        $rooms = $this->serverRooms();
        $models = ['PowerVault PR-4000', 'PowerVault PR-6000', 'CoreGuard 3P-10', 'CoreGuard 3P-20'];
        $out = [];
        $n = 0;
        foreach ($rooms as $room) {
            $n++;
            $id = 'UPS-' . sprintf('%02d', $n);
            $loadPct = $this->intIn(28, 74, $id . '|load');
            $onBattery = $this->h($id . '|mode') % 12 === 0;
            $out[] = [
                'id' => $id,
                'model' => $this->pick($models, $id . '|model'),
                'room' => $room['name'],
                'floor' => $room['floor'],
                'capacityKva' => $this->pick(['10', '20', '30', '40'], $id . '|kva') + 0,
                'loadPct' => $loadPct,
                'battRuntimeMin' => $this->intIn(14, 95, $id . '|rt'),
                'battSoc' => $onBattery ? $this->intIn(40, 88, $id . '|soc') : 100,
                'strings' => $this->intIn(1, 4, $id . '|str'),
                'mode' => $onBattery ? 'On battery' : 'Online (double-conversion)',
                'ip' => self::FC_SUBNET . (100 + $n),
                'firmware' => $this->firmware('upsfw|' . $id),
                'status' => $onBattery ? 'warn' : 'ok',
            ];
        }
        return $out;
    }

    /**
     * One UPS by id (known -> real; unknown -> synthesised against the first server room), never null.
     *
     * @return array<string,mixed>
     */
    public function ups(string $id): array
    {
        foreach ($this->upsFleet() as $u) {
            if (strcasecmp($u['id'], $id) === 0) {
                return $u;
            }
        }
        $fleet = $this->upsFleet();
        if ($fleet !== []) {
            $u = $fleet[0];
            $u['id'] = $id;
            return $u;
        }
        $room = $this->serverRooms()[0];
        return ['id' => $id, 'model' => 'PowerVault PR-4000', 'room' => $room['name'], 'floor' => $room['floor'],
                'capacityKva' => 20, 'loadPct' => 40, 'battRuntimeMin' => 30, 'battSoc' => 100, 'strings' => 2,
                'mode' => 'Online (double-conversion)', 'ip' => self::FC_SUBNET . '101',
                'firmware' => $this->firmware('upsfw|' . $id), 'status' => 'ok'];
    }

    /**
     * Battery strings for a UPS — per-string voltage, temperature and health.
     *
     * @param array<string,mixed> $u a ups() record
     * @return list<array{id:string,cells:int,voltage:float,tempC:int,health:string,installed:string}>
     */
    public function upsStrings(array $u): array
    {
        $count = (int) $u['strings'];
        $id = (string) $u['id'];
        $out = [];
        for ($s = 1; $s <= $count; $s++) {
            $salt = $id . '|bs|' . $s;
            // One aged string reads "Replace" occasionally; the rest are healthy.
            $health = $this->h($salt . '|h') % 9 === 0 ? 'Replace' : 'Good';
            $out[] = [
                'id' => $id . '-S' . $s,
                'cells' => $this->pick(['32', '40', '40', '48'], $salt . '|cells') + 0,
                'voltage' => $this->decIn(432.0, 546.0, $salt . '|v'),
                'tempC' => $this->intIn(19, 31, $salt . '|t'),
                'health' => $health,
                'installed' => (2018 + ($this->h($salt . '|yr') % 7)) . '-' . sprintf('%02d', 1 + $this->h($salt . '|mo') % 12),
            ];
        }
        return $out;
    }

    // --- standby generators (gensets) ---

    /**
     * Standby diesel gensets — status, fuel %, runtime, next test. One anchors to a basement/roof plant
     * area. Self-test is a canned control; start + load-transfer is the PIN-at-local-HMI soft-deny.
     *
     * @return list<array{id:string,model:string,ratingKva:int,fuelPct:int,runtimeHours:int,status:string,
     *   mode:string,lastTest:string,nextTest:string,coolantC:int,batteryV:float,location:string,statusPill:string}>
     */
    public function generators(): array
    {
        $models = ['Helios GS-500', 'Helios GS-800', 'TitanPower TP-1000', 'TitanPower TP-1500'];
        $count = $this->intIn(1, 2, 'gensetcount');
        $loc = $this->plantLocation();
        $out = [];
        for ($g = 1; $g <= $count; $g++) {
            $id = 'GEN-' . sprintf('%02d', $g);
            $fuel = $this->intIn(34, 98, $id . '|fuel');
            $status = $fuel < 40 ? 'Standby — low fuel' : 'Standby — ready';
            $out[] = [
                'id' => $id,
                'model' => $this->pick($models, $id . '|model'),
                'ratingKva' => $this->pick(['500', '800', '1000', '1500'], $id . '|kva') + 0,
                'fuelPct' => $fuel,
                'runtimeHours' => $this->intIn(120, 5200, $id . '|rt'),
                'status' => $status,
                'mode' => 'Auto (mains-fail start)',
                'lastTest' => $this->intIn(2, 27, $id . '|lt') . ' d ago',
                'nextTest' => 'in ' . $this->intIn(1, 6, $id . '|nt') . ' d',
                'coolantC' => $this->intIn(18, 42, $id . '|cool'),
                'batteryV' => $this->decIn(12.4, 13.8, $id . '|batt'),
                'location' => $loc,
                'statusPill' => $fuel < 40 ? 'warn' : 'ok',
            ];
        }
        return $out;
    }

    /**
     * One genset by id (known -> real; unknown -> synthesised), never null.
     *
     * @return array<string,mixed>
     */
    public function generator(string $id): array
    {
        foreach ($this->generators() as $g) {
            if (strcasecmp($g['id'], $id) === 0) {
                return $g;
            }
        }
        $g = $this->generators()[0];
        $g['id'] = $id;
        return $g;
    }

    // --- solar PV array ---

    /**
     * PV strings on the roof — per-string output and today's yield. Exactly one string (S7 if present,
     * else the last) carries a fault that leads to the electrician ticket chain (spec §C.8, E2 budget).
     *
     * @return list<array{id:string,panels:int,outputKw:float,yieldToday:float,voltageDc:int,currentA:float,
     *   status:string,statusPill:string,fault:string}>
     */
    public function solarStrings(): array
    {
        $count = $this->intIn(6, 10, 'pvstrings');
        $faultId = 'S' . ($count >= 7 ? 7 : $count);
        $out = [];
        for ($s = 1; $s <= $count; $s++) {
            $id = 'S' . $s;
            $isFault = ($id === $faultId);
            $panels = $this->intIn(14, 24, $id . '|panels');
            $out[] = [
                'id' => $id,
                'panels' => $panels,
                'outputKw' => $isFault ? 0.0 : $this->decIn(2.0, 7.5, $id . '|kw'),
                'yieldToday' => $isFault ? round($this->decIn(0.5, 3.0, $id . '|part'), 1) : $this->decIn(9.0, 38.0, $id . '|yld'),
                'voltageDc' => $isFault ? 0 : $this->intIn(560, 780, $id . '|vdc'),
                'currentA' => $isFault ? 0.0 : $this->decIn(4.0, 10.5, $id . '|adc'),
                'status' => $isFault ? 'Fault — isolation low, string offline' : 'Producing',
                'statusPill' => $isFault ? 'crit' : 'ok',
                'fault' => $isFault ? 'PV-ISO-LOW' : '',
            ];
        }
        return $out;
    }

    /** One PV string by id (known -> real; unknown -> synthesised), never null. @return array<string,mixed> */
    public function solarString(string $id): array
    {
        foreach ($this->solarStrings() as $s) {
            if (strcasecmp($s['id'], $id) === 0) {
                return $s;
            }
        }
        $s = $this->solarStrings()[0];
        $s['id'] = $id;
        return $s;
    }

    /** @return array{outputKw:float,yieldToday:float,strings:int,faultString:string} */
    public function solarSummary(): array
    {
        $kw = 0.0;
        $yield = 0.0;
        $fault = '';
        $strings = $this->solarStrings();
        foreach ($strings as $s) {
            $kw += (float) $s['outputKw'];
            $yield += (float) $s['yieldToday'];
            if ($s['fault'] !== '') {
                $fault = $s['id'];
            }
        }
        return ['outputKw' => round($kw, 1), 'yieldToday' => round($yield, 1), 'strings' => count($strings), 'faultString' => $fault];
    }

    private function solarFaultCount(): int
    {
        return $this->solarSummary()['faultString'] !== '' ? 1 : 0;
    }

    /** The electrician work-order id for the solar fault chain (spec §C.8), or '' when no fault. */
    public function solarWorkOrder(): string
    {
        if ($this->solarFaultCount() === 0) {
            return '';
        }
        return 'WO-2026-' . sprintf('%06d', 5000 + ($this->h('solarwo') % 4000));
    }

    // --- BESS (battery storage) ---

    /**
     * @return array{soc:int,capacityKwh:int,powerKw:float,mode:string,cycles:int,tempC:int,statusPill:string}
     */
    public function bess(): array
    {
        $soc = $this->intIn(35, 95, 'besssoc');
        $chg = $this->h('bessmode') % 3;
        $mode = $chg === 0 ? 'Charging' : ($chg === 1 ? 'Discharging' : 'Idle (grid support)');
        return [
            'soc' => $soc,
            'capacityKwh' => $this->pick(['100', '150', '200', '250'], 'besscap') + 0,
            'powerKw' => $mode === 'Idle (grid support)' ? 0.0 : $this->decIn(8.0, 48.0, 'besspwr'),
            'mode' => $mode,
            'cycles' => $this->intIn(180, 2400, 'besscyc'),
            'tempC' => $this->intIn(19, 33, 'besstemp'),
            'statusPill' => $soc < 40 ? 'warn' : 'ok',
        ];
    }

    // --- utility meters (water / gas / waste) ---

    /**
     * Water / gas / waste utility meters — reading + today's consumption. Gas carries the emergency
     * shut-off lure (break-glass at the riser) handled as a soft-deny in the section.
     *
     * @return list<array{id:string,kind:string,reading:string,today:string,unit:string,meterId:string,statusPill:string,note:string}>
     */
    public function utilities(): array
    {
        return [
            [
                'id' => 'water', 'kind' => 'Water (potable)',
                'reading' => number_format($this->intIn(180000, 940000, 'waterr')) . ' L',
                'today' => number_format($this->intIn(1800, 9400, 'watert')) . ' L',
                'unit' => 'L', 'meterId' => 'WM-01',
                'statusPill' => 'ok', 'note' => 'Incoming main, riser B1',
            ],
            [
                'id' => 'gas', 'kind' => 'Natural gas',
                'reading' => number_format($this->intIn(40000, 260000, 'gasr')) . ' m³',
                'today' => number_format($this->intIn(120, 840, 'gast')) . ' m³',
                'unit' => 'm³', 'meterId' => 'GM-01',
                'statusPill' => 'ok', 'note' => 'Boiler plant — emergency shut-off at riser B1',
            ],
            [
                'id' => 'waste', 'kind' => 'Waste / effluent',
                'reading' => number_format($this->intIn(60000, 380000, 'waster')) . ' L',
                'today' => number_format($this->intIn(900, 6200, 'wastet')) . ' L',
                'unit' => 'L', 'meterId' => 'EM-01',
                'statusPill' => 'ok', 'note' => 'Trade-effluent discharge point',
            ],
        ];
    }

    /** One utility meter by id, never null. @return array<string,mixed> */
    public function utility(string $id): array
    {
        foreach ($this->utilities() as $u) {
            if (strcasecmp($u['id'], $id) === 0) {
                return $u;
            }
        }
        return $this->utilities()[0];
    }

    // --- HVAC plant (chillers / boilers / AHUs, anchored to Building floors + plant rooms) ---

    /**
     * The mechanical plant that drives the building's energy: chillers and boilers in the plant rooms,
     * air-handling units per occupied floor. Each names a real floor and (where possible) a real Plant
     * room, and reports through a BMS controller — so the energy console reconciles with HVAC/Building.
     *
     * @return list<array{id:string,type:string,model:string,floor:string,floorLabel:string,room:string,
     *   loadPct:int,powerKw:float,status:string,statusPill:string,controller:string,runtimeHours:int}>
     */
    public function plant(): array
    {
        $out = [];
        $plantRoom = $this->plantRoomName();
        $bmsIds = $this->bmsControllerIds();
        $ci = 0;

        // Chillers + boilers in the central plant.
        $chillers = $this->intIn(1, 3, 'chillers');
        for ($c = 1; $c <= $chillers; $c++) {
            $id = 'CH-' . sprintf('%02d', $c);
            $out[] = $this->buildPlant($id, 'Chiller', ['Frost XC-450', 'Frost XC-700', 'AquaCool 350'],
                $plantRoom['floor'], $plantRoom['floorLabel'], $plantRoom['name'], 12.0, 130.0, $bmsIds, $ci++);
        }
        $boilers = $this->intIn(1, 2, 'boilers');
        for ($b = 1; $b <= $boilers; $b++) {
            $id = 'BL-' . sprintf('%02d', $b);
            $out[] = $this->buildPlant($id, 'Boiler', ['ThermaMax B-200', 'ThermaMax B-350', 'CaloriQ 300'],
                $plantRoom['floor'], $plantRoom['floorLabel'], $plantRoom['name'], 4.0, 40.0, $bmsIds, $ci++);
        }
        // One AHU per occupied floor (skip basements/roof for the AHU count itself).
        foreach ($this->bld->floors() as $f) {
            if ($f['code'] === 'Roof' || $f['code'][0] === 'B') {
                continue;
            }
            $id = 'AHU-' . strtoupper($f['code']);
            $out[] = $this->buildPlant($id, 'AHU', ['AeroFlow AH-10', 'AeroFlow AH-16', 'VentPro 12'],
                $f['code'], $f['label'], $f['label'] . ' plant', 2.0, 22.0, $bmsIds, $ci++);
        }
        return $out;
    }

    private function buildPlant(string $id, string $type, array $models, string $floor, string $floorLabel, string $room, float $kwMin, float $kwMax, array $bmsIds, int $ci): array
    {
        $load = $this->intIn(0, 96, $id . '|load');
        $running = $load > 5;
        return [
            'id' => $id,
            'type' => $type,
            'model' => $this->pick($models, $id . '|model'),
            'floor' => $floor,
            'floorLabel' => $floorLabel,
            'room' => $room,
            'loadPct' => $load,
            'powerKw' => $running ? round($kwMin + ($kwMax - $kwMin) * $load / 100, 1) : 0.0,
            'status' => $running ? 'Running' : 'Off (no demand)',
            'statusPill' => $running ? 'ok' : 'idle',
            'controller' => $bmsIds[$ci % count($bmsIds)],
            'runtimeHours' => $this->intIn(2000, 48000, $id . '|rt'),
        ];
    }

    /** One plant item by id, never null. @return array<string,mixed> */
    public function plantItem(string $id): array
    {
        foreach ($this->plant() as $p) {
            if (strcasecmp($p['id'], $id) === 0) {
                return $p;
            }
        }
        $p = $this->plant()[0];
        $p['id'] = $id;
        return $p;
    }

    // --- shared building anchors ---

    /** BMS controller ids from the shared Building fabric (the pool plant binds to). @return list<string> */
    private function bmsControllerIds(): array
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

    /**
     * Server / comms rooms across the building (the loads UPS units protect). Falls back to a core room
     * so the fleet always has something to anchor to.
     *
     * @return list<array{id:string,name:string,floor:string}>
     */
    private function serverRooms(): array
    {
        $out = [];
        foreach ($this->bld->floors() as $f) {
            foreach ($this->bld->roomsFor($f['code']) as $r) {
                if ($r['type'] === 'Server-Comms') {
                    $out[] = ['id' => $r['id'], 'name' => $r['name'] . ' (Server/Comms)', 'floor' => $r['floor']];
                }
            }
        }
        if ($out !== []) {
            return $out;
        }
        foreach ($this->bld->floors() as $f) {
            foreach ($this->bld->roomsFor($f['code']) as $r) {
                if ($r['zone'] === 'Core') {
                    return [['id' => $r['id'], 'name' => $r['name'] . ' (Server/Comms)', 'floor' => $r['floor']]];
                }
            }
        }
        return [['id' => 'room-g-01', 'name' => 'Server/Comms Core', 'floor' => 'G']];
    }

    /** The central plant room (a real Plant-type room, else the lowest floor's core). @return array{name:string,floor:string,floorLabel:string} */
    private function plantRoomName(): array
    {
        foreach ($this->bld->floors() as $f) {
            foreach ($this->bld->roomsFor($f['code']) as $r) {
                if ($r['type'] === 'Plant') {
                    return ['name' => $r['name'] . ' (Plant)', 'floor' => $r['floor'], 'floorLabel' => $f['label']];
                }
            }
        }
        $floors = $this->bld->floors();
        $f = $floors[0];
        return ['name' => $f['label'] . ' plant', 'floor' => $f['code'], 'floorLabel' => $f['label']];
    }

    /** Where the standby generators sit — a plant room label for the genset location line. */
    private function plantLocation(): string
    {
        $pr = $this->plantRoomName();
        return $pr['floorLabel'] . ' — ' . $pr['name'];
    }

    // --- alarms console (generic plant-speak, never scanner strings) ---

    /**
     * The energy alarm buffer — a seeded slice of recent plant alarms, reconciled with the planted
     * meter comms-fails and solar fault so the console agrees with the rest of the module.
     *
     * @return list<string>
     */
    public function alarmLines(): array
    {
        $lines = [];
        foreach ($this->meters() as $m) {
            if ($m['comms'] === 'FAIL') {
                $lines[] = $m['lastSeen'] . '  MINOR  ' . $m['id'] . ' (' . $m['label'] . ') — communications lost to ' . $m['controller'];
            }
        }
        $solar = $this->solarSummary();
        if ($solar['faultString'] !== '') {
            $lines[] = '2 h ago  MAJOR  PV string ' . $solar['faultString'] . ' — insulation resistance low, string isolated';
        }
        // A little benign background plant chatter so the console is never empty.
        $benign = [
            'demand within contracted capacity — no action',
            'power factor corrected — capacitor bank step 2 engaged',
            'off-peak tariff window active',
            'BESS state-of-charge nominal',
            'weekly generator test completed — pass',
        ];
        foreach ($benign as $i => $b) {
            $lines[] = $this->ageAgo('alarm|' . $i) . '  INFO   ' . $b;
        }
        return $lines;
    }

    /** The seeded total the alarms console counts against (generic, never a signature). */
    public function alarmTotal(): int
    {
        return 1000 + ($this->h('alarmtotal') % 900);
    }

    /** Seeded "last poll" freshness for the landing — varies per deploy, never time(). */
    public function lastPollAge(): string
    {
        return $this->intIn(10, 50, 'poll') . ' s ago';
    }
}
