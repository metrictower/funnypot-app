<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT sensor / environment plane for the deep office/BMS panel — the HA device-class
 * long tail (spec §C.2). Sits on Building (the coherence spine): every sensor is bound to a real room on
 * a real floor+zone, polled by a real BMS controller on the 10.0.50.x OT fabric. Breadth is the point —
 * a handful of sensor classes across every room in the building yields hundreds of coherent read-only
 * rows (Netdata-style scroll), the cheapest deception surface to grow.
 *
 * Read-only by design: nothing here has a control. Fire suppression / smoke response is the Fire module;
 * smoke detectors surface here as read-only state only and always read Clear (a Detected here would be a
 * live fire, out of budget). The one planted anomaly is a single Server-Comms leak reading Wet, which
 * references a work order (spec §C.2, one budgeted `binary_sensor.server_room_leak = Wet`).
 *
 * Design rules (deep-admin dashboard spec §C.2 + adversarial critique):
 *  - DETERMINISTIC per seed: every reading is hash(seed+id+field) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); a sensor's facts derive from its id alone, so sensor($id) is
 *    byte-identical to that sensor's row in sensors() and reproducible standalone. "last seen" is an
 *    offset off FrozenClock::EPOCH, never time().
 *  - COHERENT: sensors derive from Building floors/rooms/zones; a sensor's controller is a real BMS
 *    controller id; numeric HA units match the device class (°C/%/ppm/µg·m⁻³/lx/W).
 *  - SAFE: point hosts are BMS controllers on RFC1918 10.0.50.x:47808 only. Invented ids only, never a
 *    scanner-signature string.
 *  - ANOMALY BUDGET: at most the one planted Server-Comms leak (Wet) that leads to a work order one step
 *    short; every other leak reads Dry, every smoke reads Clear.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/number_format, no enums/named-args/str_contains/
 *    constructor promotion) so a fact can promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders and escapes it.
 */
final class Sensors
{
    /** Frozen "now" so a static reload is not a tell (spec E11). Matches Building/Hvac. */
    public const DEPLOY_EPOCH = FrozenClock::EPOCH;

    /** BACnet/IP port every BMS controller answers on (matches Building's BMS controllers). */
    public const BACNET_PORT = 47808;

    /** @var int */
    private $seed;

    /** @var Building */
    private $bld;

    /** @var list<array<string,mixed>>|null memoised sensor estate (built once per instance) */
    private $cache = null;

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
        return (int) hexdec(substr(hash('sha256', $this->seed . '|sens|' . $salt), 0, 15));
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

    private function firmware(string $salt): string
    {
        return 'v' . $this->intIn(1, 4, $salt . '|fa')
            . '.' . $this->intIn(0, 18, $salt . '|fb')
            . '.' . $this->intIn(0, 40, $salt . '|fc');
    }

    // --- device-class catalog (the HA long tail this plane mines) ---

    /**
     * The device classes surfaced here, each with its HA unit and render kind. `idslug` seeds the entity
     * id; `dc` is the device_class filter slug used in the URL. `numeric` classes carry a gauge, `binary`
     * classes an on/off state pill. Order is the natural reading order on a detail page.
     *
     * @return array<string,array{label:string,kind:string,unit:string,idslug:string,domain:string,dc:string}>
     */
    private function catalog(): array
    {
        return [
            'temperature'    => ['label' => 'Temperature',     'kind' => 'numeric', 'unit' => '°C',    'idslug' => 'temp', 'domain' => 'sensor',        'dc' => 'temperature'],
            'humidity'       => ['label' => 'Humidity',        'kind' => 'numeric', 'unit' => '%',     'idslug' => 'rh',   'domain' => 'sensor',        'dc' => 'humidity'],
            'carbon-dioxide' => ['label' => 'CO₂',             'kind' => 'numeric', 'unit' => 'ppm',   'idslug' => 'co2',  'domain' => 'sensor',        'dc' => 'carbon-dioxide'],
            'pm25'           => ['label' => 'PM2.5',           'kind' => 'numeric', 'unit' => 'µg/m³', 'idslug' => 'pm25', 'domain' => 'sensor',        'dc' => 'pm25'],
            'illuminance'    => ['label' => 'Light level',     'kind' => 'numeric', 'unit' => 'lx',    'idslug' => 'lux',  'domain' => 'sensor',        'dc' => 'illuminance'],
            'power'          => ['label' => 'Power',           'kind' => 'numeric', 'unit' => 'W',     'idslug' => 'pwr',  'domain' => 'sensor',        'dc' => 'power'],
            'occupancy'      => ['label' => 'Occupancy',       'kind' => 'binary',  'unit' => '',      'idslug' => 'occ',  'domain' => 'binary_sensor', 'dc' => 'occupancy'],
            'motion'         => ['label' => 'Motion',          'kind' => 'binary',  'unit' => '',      'idslug' => 'mot',  'domain' => 'binary_sensor', 'dc' => 'motion'],
            'door'           => ['label' => 'Door contact',    'kind' => 'binary',  'unit' => '',      'idslug' => 'door', 'domain' => 'binary_sensor', 'dc' => 'door'],
            'window'         => ['label' => 'Window contact',  'kind' => 'binary',  'unit' => '',      'idslug' => 'win',  'domain' => 'binary_sensor', 'dc' => 'window'],
            'moisture'       => ['label' => 'Leak',            'kind' => 'binary',  'unit' => '',      'idslug' => 'leak', 'domain' => 'binary_sensor', 'dc' => 'moisture'],
            'smoke'          => ['label' => 'Smoke',           'kind' => 'binary',  'unit' => '',      'idslug' => 'smk',  'domain' => 'binary_sensor', 'dc' => 'smoke'],
        ];
    }

    /** Ordered list of the device_class slugs (filter chips + detail order). @return list<string> */
    public function classes(): array
    {
        return array_keys($this->catalog());
    }

    /** Human label for a device_class slug (falls back to the slug for an unknown one). */
    public function classLabel(string $class): string
    {
        $cat = $this->catalog();
        return isset($cat[$class]) ? $cat[$class]['label'] : $class;
    }

    /**
     * Which device classes live in a room, keyed by room type + zone. Every room carries the ambient
     * quartet + a door + smoke; occupiable rooms add air-quality + presence; perimeter rooms add a window;
     * back-of-house rooms add power sub-metering + a leak detector. Coherent, and the fan-out is what
     * turns a modest building into hundreds of rows.
     *
     * @param array{type:string,zone:string} $room
     * @return list<string>
     */
    private function classesForRoom(array $room): array
    {
        $type = $room['type'];
        $zone = $room['zone'];
        $out = ['temperature', 'humidity', 'illuminance', 'occupancy', 'door', 'smoke'];

        $occupiable = in_array($type, ['Meeting', 'Open-plan', 'Exec', 'Focus', 'Reception', 'Wellness', 'Lab'], true);
        if ($occupiable) {
            $out[] = 'carbon-dioxide';
            $out[] = 'pm25';
            $out[] = 'motion';
        }
        if ($zone === 'N' || $zone === 'E' || $zone === 'S' || $zone === 'W') {
            $out[] = 'window';
        }
        if (in_array($type, ['Server-Comms', 'Plant', 'Kitchen', 'Store'], true)) {
            $out[] = 'power';
            $out[] = 'moisture';
        }
        return $out;
    }

    // --- BMS controllers this plane polls (a subset of Building's controllers) ---

    /** BMS controller ids only, stable order — the pool sensors bind to. @return list<string> */
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

    // --- the sensor estate ---

    /**
     * Every sensor across the building, stable order (floor stack -> room order -> class order). Built
     * once and memoised. The planted Server-Comms leak (if any) is resolved in a single pass so exactly
     * one leak reads Wet.
     *
     * @return list<array<string,mixed>>
     */
    public function sensors(): array
    {
        if ($this->cache !== null) {
            return $this->cache;
        }
        $ctrl = $this->controllerIds();
        $leakTarget = $this->plantedLeakId();
        $seq = [];
        $out = [];
        foreach ($this->bld->floors() as $f) {
            foreach ($this->bld->roomsFor($f['code']) as $r) {
                foreach ($this->classesForRoom($r) as $class) {
                    $cat = $this->catalog()[$class];
                    $slug = $cat['idslug'];
                    if (!isset($seq[$slug])) {
                        $seq[$slug] = 0;
                    }
                    $seq[$slug]++;
                    $id = 'sn-' . $slug . '-' . sprintf('%04d', $seq[$slug]);
                    $out[] = $this->buildSensor($id, $class, $cat, $f, $r, $ctrl, $id === $leakTarget);
                }
            }
        }
        $this->cache = $out;
        return $out;
    }

    /**
     * The id of the single planted leak sensor: the moisture sensor of the first Server-Comms room in
     * building order. Computed the same way sensors() assigns ids, so the two always agree. '' when the
     * building has no Server-Comms room this seed (then no leak is planted — budget respected either way).
     */
    private function plantedLeakId(): string
    {
        $seq = 0;
        foreach ($this->bld->floors() as $f) {
            foreach ($this->bld->roomsFor($f['code']) as $r) {
                foreach ($this->classesForRoom($r) as $class) {
                    if ($class !== 'moisture') {
                        continue;
                    }
                    $seq++;
                    if ($r['type'] === 'Server-Comms') {
                        return 'sn-leak-' . sprintf('%04d', $seq);
                    }
                }
            }
        }
        return '';
    }

    /**
     * One sensor by id. Returns the real sensor for a known id; for an unknown/fuzzed slug it synthesises
     * a plausible sensor keyed by the slug so a crawler never falls off the edge (spec D.4 — a 404 inside
     * a deep panel is a tell). Never null.
     *
     * @return array<string,mixed>
     */
    public function sensor(string $id): array
    {
        foreach ($this->sensors() as $s) {
            if ($s['id'] === $id) {
                return $s;
            }
        }
        // Synthesised: class inferred from the id's slug prefix, attached to the Ground Core room so
        // cross-links still resolve to real topology.
        $class = $this->classFromId($id);
        $cat = $this->catalog()[$class];
        $floor = ['code' => 'G', 'label' => 'Ground'];
        $room = ['id' => 'room-g-01', 'name' => 'Core', 'floor' => 'G', 'zone' => 'Core', 'type' => 'Server-Comms'];
        return $this->buildSensor($id, $class, $cat, $floor, $room, $this->controllerIds(), false);
    }

    /** Best-effort device class for a synthesised id, matched on the `sn-<slug>-` prefix. */
    private function classFromId(string $id): string
    {
        foreach ($this->catalog() as $class => $cat) {
            if (strpos($id, 'sn-' . $cat['idslug'] . '-') === 0) {
                return $class;
            }
        }
        return 'temperature';
    }

    /**
     * @param array{code:string,label:string} $floor
     * @param array{id:string,name:string,floor:string,zone:string,type:string} $room
     * @param list<string> $ctrl
     * @return array<string,mixed>
     */
    private function buildSensor(string $id, string $class, array $cat, array $floor, array $room, array $ctrl, bool $plantedLeak): array
    {
        $floorSlug = strtolower($floor['code']);
        $zoneSlug = strtolower($room['zone']);
        $controller = $ctrl[$this->h($id . '|ctrl') % count($ctrl)];
        $reading = $this->reading($id, $class, $room, $plantedLeak);

        // Health: overwhelmingly online, a small budgeted fault/offline minority (spec E2). A wired class
        // (power/smoke) is mains-powered; everything else is a battery device with a seeded charge level.
        $r = $this->h($id . '|status') % 100;
        $status = $r < 97 ? 'online' : ($r < 99 ? 'fault' : 'offline');
        $wired = in_array($class, ['power', 'smoke'], true);
        $battery = $wired ? -1 : $this->intIn(8, 100, $id . '|batt');

        $offset = $this->intIn(4, 7200, $id . '|seen');            // 4 s .. 2 h since last poll
        $lastSeenEpoch = self::DEPLOY_EPOCH - $offset;

        return [
            'id' => $id,
            'entityId' => $cat['domain'] . '.' . $floorSlug . '_' . $zoneSlug . '_' . $cat['idslug'],
            'class' => $class,
            'classLabel' => $cat['label'],
            'kind' => $cat['kind'],
            'unit' => $cat['unit'],
            'name' => $floor['label'] . ' ' . $room['name'] . ' — ' . $cat['label'],
            'value' => $reading['value'],          // display string (with unit for numeric, state word for binary)
            'valueNum' => $reading['num'],          // float|int for numeric (0 for binary)
            'gaugePct' => $reading['pct'],          // 0-100 for numeric (0 for binary)
            'severity' => $reading['sev'],          // ok|warn|crit|info|idle — pill / dot colour
            'status' => $status,                    // online|fault|offline
            'floor' => $floor['code'],
            'floorLabel' => $floor['label'],
            'zone' => $room['zone'],
            'roomId' => $room['id'],
            'roomName' => $room['name'],
            'roomType' => $room['type'],
            'controller' => $controller,
            'controllerIp' => $this->controllerIp($controller),
            'firmware' => $this->firmware($id . '|fw'),
            'battery' => $battery,                  // -1 = mains
            'signal' => -$this->intIn(38, 92, $id . '|sig'),   // dBm
            'lastSeenEpoch' => $lastSeenEpoch,
            'lastSeen' => $this->relAge($offset),
            'plantedLeak' => $plantedLeak,
            'workOrder' => $plantedLeak ? 'WO-2026-' . sprintf('%06d', 4000 + ($this->h($id . '|wo') % 5000)) : '',
        ];
    }

    /**
     * The present reading for a sensor: display string, numeric value, gauge percent, severity band. A
     * numeric class reads within its comfortable range with a small budgeted excursion; a binary class
     * resolves to a state word. The planted leak forces Wet; smoke never fires.
     *
     * @param array{type:string,zone:string} $room
     * @return array{value:string,num:float,pct:int,sev:string}
     */
    private function reading(string $id, string $class, array $room, bool $plantedLeak): array
    {
        switch ($class) {
            case 'temperature':
                $v = $this->decIn(19.0, 24.5, $id . '|v');
                return ['value' => number_format($v, 1) . ' °C', 'num' => $v, 'pct' => $this->clampPct((int) round(($v - 15.0) / 15.0 * 100)),
                        'sev' => ($v < 18.0 || $v > 26.0) ? 'warn' : 'ok'];
            case 'humidity':
                $v = $this->intIn(32, 58, $id . '|v');
                return ['value' => $v . ' %', 'num' => (float) $v, 'pct' => $this->clampPct($v),
                        'sev' => ($v < 30 || $v > 65) ? 'warn' : 'ok'];
            case 'carbon-dioxide':
                $v = $this->co2($id);
                $sev = $v >= 1400 ? 'crit' : ($v >= 1000 ? 'warn' : 'ok');
                return ['value' => $v . ' ppm', 'num' => (float) $v, 'pct' => $this->clampPct((int) round($v / 2000 * 100)), 'sev' => $sev];
            case 'pm25':
                $v = ($this->h($id . '|pmr') % 100) < 90 ? $this->intIn(2, 22, $id . '|vlo') : $this->intIn(30, 60, $id . '|vhi');
                $sev = $v >= 55 ? 'crit' : ($v >= 35 ? 'warn' : 'ok');
                return ['value' => $v . ' µg/m³', 'num' => (float) $v, 'pct' => $this->clampPct((int) round($v / 60 * 100)), 'sev' => $sev];
            case 'illuminance':
                $v = in_array($room['type'], ['Store', 'Plant', 'Server-Comms'], true)
                    ? $this->intIn(0, 140, $id . '|v')
                    : $this->intIn(120, 640, $id . '|v');
                return ['value' => $v . ' lx', 'num' => (float) $v, 'pct' => $this->clampPct((int) round($v / 800 * 100)), 'sev' => 'info'];
            case 'power':
                $v = in_array($room['type'], ['Server-Comms', 'Plant'], true)
                    ? $this->intIn(320, 1850, $id . '|v')
                    : $this->intIn(20, 260, $id . '|v');
                return ['value' => $v . ' W', 'num' => (float) $v, 'pct' => $this->clampPct((int) round($v / 2000 * 100)),
                        'sev' => $v > 1600 ? 'warn' : 'ok'];
            case 'occupancy':
                $on = ($this->h($id . '|st') % 100) < 34;
                return ['value' => $on ? 'Detected' : 'Clear', 'num' => 0.0, 'pct' => 0, 'sev' => $on ? 'info' : 'idle'];
            case 'motion':
                $on = ($this->h($id . '|st') % 100) < 24;
                return ['value' => $on ? 'Motion' : 'No motion', 'num' => 0.0, 'pct' => 0, 'sev' => $on ? 'info' : 'idle'];
            case 'door':
                $on = ($this->h($id . '|st') % 100) < 10;
                return ['value' => $on ? 'Open' : 'Closed', 'num' => 0.0, 'pct' => 0, 'sev' => $on ? 'warn' : 'ok'];
            case 'window':
                $on = ($this->h($id . '|st') % 100) < 8;
                return ['value' => $on ? 'Open' : 'Closed', 'num' => 0.0, 'pct' => 0, 'sev' => $on ? 'warn' : 'ok'];
            case 'moisture':
                return $plantedLeak
                    ? ['value' => 'Wet', 'num' => 0.0, 'pct' => 0, 'sev' => 'crit']
                    : ['value' => 'Dry', 'num' => 0.0, 'pct' => 0, 'sev' => 'ok'];
            case 'smoke':
            default:
                // Smoke is read-only here and never fires (a live alarm is the Fire module's domain).
                return ['value' => 'Clear', 'num' => 0.0, 'pct' => 0, 'sev' => 'ok'];
        }
    }

    /** CO2 ppm: mostly comfortable, a budgeted minority stuffy (recon bait), same shape as Hvac. */
    private function co2(string $id): int
    {
        $r = $this->h($id . '|co2r') % 100;
        if ($r < 84) {
            return $this->intIn(430, 950, $id . '|co2lo');
        }
        if ($r < 96) {
            return $this->intIn(1000, 1350, $id . '|co2mid');
        }
        return $this->intIn(1400, 1800, $id . '|co2hi');
    }

    private function clampPct(int $pct): int
    {
        return $pct < 0 ? 0 : ($pct > 100 ? 100 : $pct);
    }

    /** Seeded "N ago" from a second offset — pure arithmetic, never time()/date(). */
    private function relAge(int $sec): string
    {
        if ($sec < 90) {
            return $sec . ' s ago';
        }
        if ($sec < 5400) {
            return (int) round($sec / 60) . ' min ago';
        }
        return (int) round($sec / 3600) . ' h ago';
    }

    // --- per-sensor history (computed on demand, not stored on the list row) ---

    /**
     * 24 hourly history readings for a sensor's sparkline — deterministic per sensor id (never time()).
     * A numeric class swings gently about its present value with a seeded diurnal shape; a binary class
     * is a 0/1 step series so the sparkline reads as state changes over the day.
     *
     * @param array<string,mixed> $s a sensors()/sensor() record
     * @return list<float>
     */
    public function history(array $s): array
    {
        $id = (string) $s['id'];
        $out = [];
        if ($s['kind'] === 'numeric') {
            $base = (float) $s['valueNum'];
            $amp = $base > 0 ? max(0.5, $base * 0.06) : 1.0;
            for ($i = 0; $i < 24; $i++) {
                $swing = ($i >= 8 && $i <= 18) ? 1.0 : -0.5;
                $jitter = ($this->h($id . '|hist|' . $i) % 21 - 10) / 10.0;
                $out[] = round($base + $swing * $amp + $jitter * ($amp / 2), 2);
            }
            return $out;
        }
        // Binary: a seeded on/off walk; the present state anchors the last sample.
        $on = ($s['sev'] === 'info' || $s['sev'] === 'warn' || $s['sev'] === 'crit') ? 1 : 0;
        for ($i = 0; $i < 24; $i++) {
            $out[] = ($this->h($id . '|hb|' . $i) % 100) < 18 ? 1.0 : 0.0;
        }
        $out[23] = (float) $on;
        return $out;
    }

    /**
     * Statistics over a numeric sensor's 24 h history (min/max/avg/current). Returns null for a binary
     * sensor (which has no numeric distribution).
     *
     * @param array<string,mixed> $s
     * @return array{min:float,max:float,avg:float,current:float,unit:string}|null
     */
    public function statistics(array $s): ?array
    {
        if ($s['kind'] !== 'numeric') {
            return null;
        }
        $h = $this->history($s);
        return [
            'min' => round(min($h), 1),
            'max' => round(max($h), 1),
            'avg' => round(array_sum($h) / count($h), 1),
            'current' => (float) $s['valueNum'],
            'unit' => (string) $s['unit'],
        ];
    }

    /**
     * The BMS object mapping for one sensor (recon bait: object id + host:port), addressed at the
     * sensor's BMS controller. Numeric classes mirror as an Analog Input; binary classes as a Binary
     * Input. Invented instance ids only.
     *
     * @param array<string,mixed> $s
     * @return list<array{object:string,name:string,value:string,host:string}>
     */
    public function points(array $s): array
    {
        $host = ((string) $s['controllerIp']) . ':' . self::BACNET_PORT;
        $id = (string) $s['id'];
        $obj = $s['kind'] === 'numeric'
            ? 'AI:' . $this->intIn(1, 240, $id . '|ai')
            : 'BI:' . $this->intIn(1, 120, $id . '|bi');
        return [
            ['object' => $obj, 'name' => (string) $s['classLabel'] . ' Present Value', 'value' => (string) $s['value'], 'host' => $host],
            ['object' => 'MSV:' . $this->intIn(1, 40, $id . '|msv'), 'name' => 'Reliability', 'value' => $s['status'] === 'online' ? 'no-fault-detected' : 'unreliable-other', 'host' => $host],
        ];
    }

    // --- reconciled headline counts for the landing ---

    /**
     * @return array{total:int,online:int,faults:int,offline:int,lowBattery:int,alarms:int,classes:int,
     *   avgTemp:float,avgCo2:int,avgPm25:int,leaks:int}
     */
    public function summary(): array
    {
        $sensors = $this->sensors();
        $online = 0;
        $faults = 0;
        $offline = 0;
        $lowBattery = 0;
        $alarms = 0;
        $leaks = 0;
        $tSum = 0.0;
        $tN = 0;
        $cSum = 0;
        $cN = 0;
        $pSum = 0;
        $pN = 0;
        foreach ($sensors as $s) {
            if ($s['status'] === 'online') {
                $online++;
            } elseif ($s['status'] === 'fault') {
                $faults++;
            } else {
                $offline++;
            }
            if ($s['battery'] >= 0 && $s['battery'] < 20) {
                $lowBattery++;
            }
            if ($s['severity'] === 'warn' || $s['severity'] === 'crit') {
                $alarms++;
            }
            if ($s['class'] === 'moisture' && $s['value'] === 'Wet') {
                $leaks++;
            }
            if ($s['class'] === 'temperature') {
                $tSum += (float) $s['valueNum'];
                $tN++;
            } elseif ($s['class'] === 'carbon-dioxide') {
                $cSum += (int) $s['valueNum'];
                $cN++;
            } elseif ($s['class'] === 'pm25') {
                $pSum += (int) $s['valueNum'];
                $pN++;
            }
        }
        return [
            'total' => count($sensors),
            'online' => $online,
            'faults' => $faults,
            'offline' => $offline,
            'lowBattery' => $lowBattery,
            'alarms' => $alarms,
            'classes' => count($this->catalog()),
            'avgTemp' => $tN > 0 ? round($tSum / $tN, 1) : 0.0,
            'avgCo2' => $cN > 0 ? (int) round($cSum / $cN) : 0,
            'avgPm25' => $pN > 0 ? (int) round($pSum / $pN) : 0,
            'leaks' => $leaks,
        ];
    }

    /** Seeded "last BMS poll" freshness for the landing — varies per deploy, never time() (spec E11). */
    public function lastPollAge(): string
    {
        return $this->intIn(12, 55, 'bmspoll') . ' s ago';
    }
}
