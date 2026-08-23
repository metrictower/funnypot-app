<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT HVAC / climate plane for the deep office/BMS panel. Sits on top of Building (the
 * coherence spine): every climate zone maps to a real floor+zone, every point host is a real BMS
 * controller on the 10.0.50.x OT fabric, and each CRAC unit cools a real Server-Comms room — so the
 * "the BMS controls the temperature of the servers" cross-link the attacker chases actually reconciles.
 *
 * Design rules (deep-admin dashboard spec §C.2 + adversarial critique):
 *  - DETERMINISTIC per seed: every reading is hash(seed+zoneId+field) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); a zone's facts are derived from its id alone, so zone($id) is
 *    byte-identical to that zone's row in zones() and reproducible standalone.
 *  - COHERENT: zones derive from Building floors/zones; a zone's controller is a real BMS controller id;
 *    a CRAC serves a real room id. currentTemperature tracks setpoint + hvacAction agrees with the delta.
 *  - SAFE: point hosts are BMS controllers on RFC1918 10.0.50.x:47808 only. Invented object/instance ids
 *    (BACnet AI/AV/BV/AO/BI/MV), never a scanner-signature string.
 *  - ANOMALY BUDGET: at most the one flagship CRAC anomaly (dirty filter OR controller comms-fail),
 *    present roughly half of seeds, that leads to a work order one step short (E2/T2). Zones read clean.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/number_format, no enums/named-args/str_contains/
 *    constructor promotion) so a fact can promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders and escapes it.
 */
final class Hvac
{
    /** Frozen "now" so a static reload is not a tell (spec E11). Matches Building/Org. */
    public const DEPLOY_EPOCH = 1756000000;

    /** BACnet/IP port every BMS controller answers on (matches Building's BMS controllers). */
    public const BACNET_PORT = 47808;

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
        return (int) hexdec(substr(hash('sha256', $this->seed . '|hvac|' . $salt), 0, 15));
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

    // --- BMS controllers this plane addresses (a subset of Building's controllers) ---

    /** @return list<array{id:string,ip:string,protocol:string,port:int,firmware:string,health:string}> */
    public function controllers(): array
    {
        $out = [];
        foreach ($this->bld->controllers() as $c) {
            if ($c['kind'] === 'BMS') {
                $out[] = [
                    'id' => $c['id'],
                    'ip' => $c['ip'],
                    'protocol' => $c['protocol'],
                    'port' => $c['port'],
                    'firmware' => $c['firmware'],
                    'health' => $c['health'],
                ];
            }
        }
        return $out;
    }

    /** BMS controller ids only, stable order — the pool zones/CRACs bind to. @return list<string> */
    private function controllerIds(): array
    {
        $ids = [];
        foreach ($this->controllers() as $c) {
            $ids[] = $c['id'];
        }
        if ($ids === []) {
            $ids[] = 'BMS-CTRL-01';
        }
        return $ids;
    }

    /** IP of a BMS controller id (for point host:port); '10.0.50.11' fallback keeps it RFC1918. */
    public function controllerIp(string $id): string
    {
        foreach ($this->controllers() as $c) {
            if ($c['id'] === $id) {
                return $c['ip'];
            }
        }
        return '10.0.50.11';
    }

    // --- zones (floor+zone climate loops) ---

    /**
     * Every climate zone, derived from Building floors/zones so counts reconcile with the site. Order is
     * stable (floor stack, then zone order within a floor).
     *
     * @return list<array<string,mixed>>
     */
    public function zones(): array
    {
        $out = [];
        foreach ($this->bld->floors() as $f) {
            foreach ($this->bld->zonesFor($f['code']) as $z) {
                $id = 'zone-' . strtolower($f['code']) . '-' . strtolower($z['zone']);
                $out[] = $this->buildZone($id, $f['code'], $f['label'], $z['zone'], $z['name']);
            }
        }
        return $out;
    }

    /**
     * One zone by id. Returns the real zone for a known id; for an unknown/fuzzed slug it synthesises a
     * plausible zone keyed by the slug so a crawler never falls off the edge (spec D.4 — a 404 inside a
     * deep panel is a tell). Never null.
     *
     * @return array<string,mixed>
     */
    public function zone(string $id): array
    {
        foreach ($this->zones() as $z) {
            if ($z['id'] === $id) {
                return $z;
            }
        }
        // Synthesised: attach to the ground floor Core so cross-links still resolve to real topology.
        return $this->buildZone($id, 'G', 'Ground', 'Core', 'Core');
    }

    /**
     * @return array{id:string,name:string,kind:string,floor:string,floorLabel:string,zone:string,
     *   currentTemp:float,setpoint:float,hvacMode:string,hvacAction:string,fanMode:string,
     *   presetMode:string,humidity:int,co2:int,damperPct:int,valvePct:int,filterStatus:string,
     *   runtimeHours:int,controller:string,controllerIp:string}
     */
    private function buildZone(string $id, string $floorCode, string $floorLabel, string $zoneCode, string $zoneName): array
    {
        $setpoint = $this->decIn(20.0, 23.0, $id . '|sp');
        // Current tracks setpoint within a small band; the sign drives hvacAction so they never disagree.
        $delta = $this->decIn(-1.5, 1.5, $id . '|delta');
        $current = round($setpoint + $delta, 1);
        $mode = $this->pick(['cool', 'heat_cool', 'auto', 'auto', 'cool', 'fan_only', 'dry'], $id . '|mode');
        $ctrl = $this->controllerIds();
        $controller = $ctrl[$this->h($id . '|ctrl') % count($ctrl)];

        return [
            'id' => $id,
            'name' => $floorLabel . ' — ' . $zoneName,
            'kind' => 'zone',
            'floor' => $floorCode,
            'floorLabel' => $floorLabel,
            'zone' => $zoneName,
            'currentTemp' => $current,
            'setpoint' => $setpoint,
            'hvacMode' => $mode,
            'hvacAction' => $this->actionFor($mode, $delta),
            'fanMode' => $this->pick(['auto', 'auto', 'low', 'medium', 'high'], $id . '|fan'),
            'presetMode' => $this->pick(['none', 'none', 'comfort', 'eco', 'boost', 'away'], $id . '|preset'),
            'humidity' => $this->intIn(32, 58, $id . '|rh'),
            'co2' => $this->co2For($id),
            'damperPct' => $this->intIn(15, 95, $id . '|damper'),
            'valvePct' => $this->intIn(0, 90, $id . '|valve'),
            'filterStatus' => $this->pick(['OK', 'OK', 'OK', 'Monitor'], $id . '|filter'),
            'runtimeHours' => $this->intIn(1200, 41000, $id . '|runtime'),
            'controller' => $controller,
            'controllerIp' => $this->controllerIp($controller),
        ];
    }

    /** hvac_action that agrees with mode + the current-vs-setpoint delta (HA semantics). */
    private function actionFor(string $mode, float $delta): string
    {
        if ($mode === 'off') {
            return 'off';
        }
        if ($mode === 'fan_only') {
            return 'fan';
        }
        if ($mode === 'dry') {
            return 'drying';
        }
        if ($delta > 0.4) {
            return 'cooling';
        }
        if ($delta < -0.4) {
            return 'heating';
        }
        return 'idle';
    }

    /** CO2 ppm: mostly comfortable, a budgeted minority stuffy (>1000) as recon bait. */
    private function co2For(string $id): int
    {
        $r = $this->h($id . '|co2r') % 100;
        if ($r < 82) {
            return $this->intIn(430, 950, $id . '|co2lo');
        }
        return $this->intIn(1000, 1400, $id . '|co2hi');
    }

    // --- BACnet points (recon bait: raw object list per zone) ---

    /**
     * The BACnet point list for a zone OR a CRAC unit — object type + instance + name + present value +
     * unit, each addressed at the unit's BMS controller host:port. Values reconcile with the record's own
     * readings. A CRAC record carries different fields to an office zone (no CO2/damper/valve), so it gets
     * its own point list rather than reading keys it does not have.
     *
     * @param array<string,mixed> $z a zone() or crac() record
     * @return list<array{object:string,name:string,value:string,unit:string,host:string}>
     */
    public function points(array $z): array
    {
        if (isset($z['kind']) && $z['kind'] === 'crac') {
            return $this->cracPoints($z);
        }
        $host = ((string) $z['controllerIp']) . ':' . self::BACNET_PORT;
        $id = (string) $z['id'];
        $ai = $this->intIn(1, 60, $id . '|ai');
        $av = $this->intIn(1, 40, $id . '|av');
        $ao = $this->intIn(1, 40, $id . '|ao');
        $bv = $this->intIn(1, 30, $id . '|bv');
        $bi = $this->intIn(1, 30, $id . '|bi');
        $mv = $this->intIn(1, 20, $id . '|mv');
        $occupied = ($this->h($id . '|occ') % 100) < 70;
        return [
            ['object' => 'AI:' . $ai, 'name' => 'Zone Temperature', 'value' => number_format((float) $z['currentTemp'], 1), 'unit' => '°C', 'host' => $host],
            ['object' => 'AV:' . $av, 'name' => 'Zone Setpoint', 'value' => number_format((float) $z['setpoint'], 1), 'unit' => '°C', 'host' => $host],
            ['object' => 'AI:' . ($ai + 1), 'name' => 'Zone Humidity', 'value' => (string) $z['humidity'], 'unit' => '%', 'host' => $host],
            ['object' => 'AI:' . ($ai + 2), 'name' => 'Zone CO2', 'value' => (string) $z['co2'], 'unit' => 'ppm', 'host' => $host],
            ['object' => 'AO:' . $ao, 'name' => 'Damper Command', 'value' => (string) $z['damperPct'], 'unit' => '%', 'host' => $host],
            ['object' => 'AO:' . ($ao + 1), 'name' => 'Reheat Valve Command', 'value' => (string) $z['valvePct'], 'unit' => '%', 'host' => $host],
            ['object' => 'BV:' . $bv, 'name' => 'Occupancy', 'value' => $occupied ? 'Active' : 'Inactive', 'unit' => '', 'host' => $host],
            ['object' => 'BI:' . $bi, 'name' => 'Filter Status', 'value' => $z['filterStatus'] === 'OK' ? 'Normal' : 'Alarm', 'unit' => '', 'host' => $host],
            ['object' => 'MV:' . $mv, 'name' => 'Occupancy Mode', 'value' => $occupied ? 'Occupied' : 'Standby', 'unit' => '', 'host' => $host],
        ];
    }

    /**
     * The BACnet point list for a CRAC / precision-cooling unit. Points reconcile with the CRAC record's
     * own supply/return/setpoint/humidity/compressor/filter readings — no office-zone-only fields.
     *
     * @param array<string,mixed> $c a crac() record
     * @return list<array{object:string,name:string,value:string,unit:string,host:string}>
     */
    private function cracPoints(array $c): array
    {
        $host = ((string) $c['controllerIp']) . ':' . self::BACNET_PORT;
        $id = (string) $c['id'];
        $ai = $this->intIn(1, 60, $id . '|ai');
        $av = $this->intIn(1, 40, $id . '|av');
        $mv = $this->intIn(1, 20, $id . '|mv');
        $bi = $this->intIn(1, 30, $id . '|bi');
        $bv = $this->intIn(1, 30, $id . '|bv');
        return [
            ['object' => 'AI:' . $ai, 'name' => 'Supply Air Temperature', 'value' => number_format((float) $c['supplyTemp'], 1), 'unit' => '°C', 'host' => $host],
            ['object' => 'AI:' . ($ai + 1), 'name' => 'Return Air Temperature', 'value' => number_format((float) $c['returnTemp'], 1), 'unit' => '°C', 'host' => $host],
            ['object' => 'AV:' . $av, 'name' => 'Unit Setpoint', 'value' => number_format((float) $c['setpoint'], 1), 'unit' => '°C', 'host' => $host],
            ['object' => 'AI:' . ($ai + 2), 'name' => 'Return Humidity', 'value' => (string) $c['humidity'], 'unit' => '%', 'host' => $host],
            ['object' => 'MV:' . $mv, 'name' => 'Compressor Stage', 'value' => (string) $c['compressor'], 'unit' => '', 'host' => $host],
            ['object' => 'BI:' . $bi, 'name' => 'Filter Status', 'value' => $c['filterStatus'] === 'OK' ? 'Normal' : 'Alarm', 'unit' => '', 'host' => $host],
            ['object' => 'BV:' . $bv, 'name' => 'Unit Enable', 'value' => 'Active', 'unit' => '', 'host' => $host],
        ];
    }

    /** Seeded "last BMS poll" freshness for the landing — varies per deploy, never time() (spec E11). */
    public function lastPollAge(): string
    {
        return $this->intIn(15, 55, 'bmspoll') . ' s ago';
    }

    // --- 24h temperature trend (sparkline) ---

    /**
     * 24 hourly temperature readings around the zone's setpoint — deterministic per zone (never time()).
     *
     * @param array<string,mixed> $z a zone() record
     * @return list<float>
     */
    public function tempTrend(array $z): array
    {
        $sp = (float) $z['setpoint'];
        $id = (string) $z['id'];
        $out = [];
        for ($i = 0; $i < 24; $i++) {
            // Warmer mid-afternoon, cooler overnight — a gentle seeded diurnal swing about the setpoint.
            $swing = ($i >= 8 && $i <= 18) ? 1.2 : -0.6;
            $jitter = ($this->h($id . '|trend|' . $i) % 11 - 5) / 10.0;
            $out[] = round($sp + $swing + $jitter, 1);
        }
        return $out;
    }

    // --- CRAC units (server-room cooling — the flagship cross-link) ---

    /**
     * CRAC / precision cooling units, one per Server-Comms room (the flagship cross-link into the server
     * room shared with Access/System). If the building has no Server-Comms room this seed, one unit still
     * anchors to a plausible core room so the lure always exists.
     *
     * @return list<array<string,mixed>>
     */
    public function cracUnits(): array
    {
        $rooms = $this->serverRooms();
        $ctrl = $this->controllerIds();
        $out = [];
        $n = 0;
        foreach ($rooms as $room) {
            $n++;
            $id = 'crac-' . sprintf('%02d', $n);
            $out[] = $this->buildCrac($id, $room, $ctrl);
        }
        return $out;
    }

    /**
     * One CRAC by id (known -> real; unknown -> synthesised against the first server room), never null.
     *
     * @return array<string,mixed>
     */
    public function crac(string $id): array
    {
        foreach ($this->cracUnits() as $c) {
            if ($c['id'] === $id) {
                return $c;
            }
        }
        $rooms = $this->serverRooms();
        return $this->buildCrac($id, $rooms[0], $this->controllerIds());
    }

    /**
     * @param array{id:string,name:string,floor:string} $room
     * @param list<string> $ctrl
     * @return array{id:string,name:string,kind:string,floor:string,servesRoomId:string,servesRoomName:string,
     *   currentTemp:float,setpoint:float,returnTemp:float,supplyTemp:float,hvacMode:string,hvacAction:string,
     *   fanMode:string,humidity:int,compressor:string,filterStatus:string,runtimeHours:int,controller:string,
     *   controllerIp:string,anomaly:string,workOrder:string}
     */
    private function buildCrac(string $id, array $room, array $ctrl): array
    {
        // Server rooms hold a tight cool setpoint (18-22 °C), unlike office comfort zones.
        $setpoint = $this->decIn(18.0, 22.0, $id . '|sp');
        $delta = $this->decIn(-0.8, 1.6, $id . '|delta');
        $current = round($setpoint + $delta, 1);
        $controller = $ctrl[$this->h($id . '|ctrl') % count($ctrl)];
        $anom = $this->cracAnomaly($id);

        return [
            'id' => $id,
            'name' => 'CRAC ' . strtoupper(substr($id, 5)) . ' — ' . $room['name'],
            'kind' => 'crac',
            'floor' => $room['floor'],
            'servesRoomId' => $room['id'],
            'servesRoomName' => $room['name'],
            'currentTemp' => $current,
            'setpoint' => $setpoint,
            'returnTemp' => round($current + $this->decIn(2.0, 6.0, $id . '|ret'), 1),
            'supplyTemp' => round($setpoint - $this->decIn(1.0, 3.0, $id . '|sup'), 1),
            'hvacMode' => 'cool',
            'hvacAction' => $delta > 0.3 ? 'cooling' : 'idle',
            'fanMode' => 'high',
            'humidity' => $this->intIn(40, 55, $id . '|rh'),
            'compressor' => $anom === 'comms-fail' ? 'unknown' : $this->pick(['Stage 1', 'Stage 1', 'Stage 2'], $id . '|comp'),
            'filterStatus' => $anom === 'dirty-filter' ? 'Replace' : $this->pick(['OK', 'OK', 'Monitor'], $id . '|filter'),
            'runtimeHours' => $this->intIn(8000, 52000, $id . '|runtime'),
            'controller' => $controller,
            'controllerIp' => $this->controllerIp($controller),
            'anomaly' => $anom,
            'workOrder' => $anom === '' ? '' : 'WO-2026-' . sprintf('%06d', 4000 + ($this->h($id . '|wo') % 5000)),
        ];
    }

    /**
     * The budgeted flagship anomaly on the FIRST CRAC only (spec E2/T2): dirty filter OR controller
     * comms-fail, present roughly half of seeds; every other CRAC reads clean. '' = no anomaly.
     */
    private function cracAnomaly(string $id): string
    {
        if ($id !== 'crac-01') {
            return '';
        }
        $r = $this->h('cracanom') % 4;
        if ($r === 0) {
            return 'dirty-filter';
        }
        if ($r === 1) {
            return 'comms-fail';
        }
        return '';
    }

    /**
     * Server rooms to cool: real Server-Comms rooms across the building, else a plausible core room so the
     * flagship server-room lure always exists.
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
        // Fallback: anchor to the first Core-zone room on the lowest occupied floor.
        foreach ($this->bld->floors() as $f) {
            foreach ($this->bld->roomsFor($f['code']) as $r) {
                if ($r['zone'] === 'Core') {
                    return [['id' => $r['id'], 'name' => $r['name'] . ' (Server/Comms)', 'floor' => $r['floor']]];
                }
            }
        }
        // Last resort — a synthetic id that is still slug-safe.
        return [['id' => 'room-g-01', 'name' => 'Server/Comms Core', 'floor' => 'G']];
    }

    // --- reconciled headline counts for the landing ---

    /**
     * @return array{zones:int,inComfort:int,filtersDue:int,cracUnits:int,controllers:int,activeAlarms:int,avgSetpoint:float}
     */
    public function summary(): array
    {
        $zones = $this->zones();
        $inComfort = 0;
        $filtersDue = 0;
        $spSum = 0.0;
        foreach ($zones as $z) {
            if ($z['hvacAction'] === 'idle' && $z['co2'] < 1000) {
                $inComfort++;
            }
            if ($z['filterStatus'] !== 'OK') {
                $filtersDue++;
            }
            $spSum += (float) $z['setpoint'];
        }
        $cracs = $this->cracUnits();
        $alarms = 0;
        foreach ($cracs as $c) {
            if ($c['anomaly'] !== '') {
                $alarms++;
                if ($c['filterStatus'] !== 'OK') {
                    $filtersDue++;
                }
            }
        }
        return [
            'zones' => count($zones),
            'inComfort' => $inComfort,
            'filtersDue' => $filtersDue,
            'cracUnits' => count($cracs),
            'controllers' => count($this->controllers()),
            'activeAlarms' => $alarms,
            'avgSetpoint' => count($zones) > 0 ? round($spSum / count($zones), 1) : 0.0,
        ];
    }
}
