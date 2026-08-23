<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT building topology for the deep office/BMS panel — the coherence spine every
 * building-side module (facilities, HVAC, lighting, access, CCTV, energy, sensors) reads from so the
 * same floor, zone, room and controller appear identically wherever they are cross-referenced.
 *
 * Design rules (deep-admin dashboard spec §C.1 + adversarial critique):
 *  - DETERMINISTIC per seed: every value is hash(seed+slot) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); ages derive from one frozen DEPLOY_EPOCH. Same seed -> identical
 *    topology across cache regenerations (a shifting building is itself a tell).
 *  - COHERENT: floors -> zones -> rooms -> devices -> controllers all reconcile. A device names a real
 *    floor code, a real room on that floor, the zone that room belongs to, and a real controller id.
 *  - SAFE: controller addressing is RFC1918 only (BMS 10.0.50.x, ACS 10.0.60.x, NVR 10.0.70.x per the
 *    §C.1 spine). Invented model/controller ids only, never a scanner-signature string.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/number_format, no enums/named-args/str_contains/
 *    constructor promotion) so a fact can promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the skins render and escape it.
 */
final class Building
{
    /** Frozen "now" for ages/last-seen so a static reload is not a tell (spec E11). */
    public const DEPLOY_EPOCH = 1756000000;

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
        return (int) hexdec(substr(hash('sha256', $this->seed . '|bld|' . $salt), 0, 15));
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

    private function hex(int $len, string $salt): string
    {
        return substr(hash('sha256', $this->seed . '|bldhex|' . $salt), 0, $len);
    }

    /** vN.N.N firmware string, frozen per component. */
    private function firmware(string $salt): string
    {
        return 'v' . $this->intIn(1, 6, $salt . '|fa')
            . '.' . $this->intIn(0, 20, $salt . '|fb')
            . '.' . $this->intIn(0, 40, $salt . '|fc');
    }

    /** Seeded "N ago" string off DEPLOY_EPOCH — deterministic, never time()/date(). */
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

    // --- site identity (frozen) ---

    /** Invented campus/building name — resemblance only, never a real trademark (spec E7). */
    public function buildingName(): string
    {
        $place = $this->pick(
            ['Meridian', 'Northgate', 'Harbour Point', 'Kingsway', 'Silverbrook', 'Ashfield',
             'Grandview', 'Riverside', 'Oakmont', 'Brightwater', 'Fairhaven', 'Crownhill'],
            'bname'
        );
        $suffix = $this->pick(['House', 'Tower', 'Centre', 'Plaza', 'Works', 'Campus'], 'bsuffix');
        return $place . ' ' . $suffix;
    }

    /**
     * Site-wide identity + reconciled headline counts (design occupancy = sum of zone capacities).
     *
     * @return array{name:string,code:string,street:string,city:string,timezone:string,grossAreaSqm:int,floors:int,rooms:int,occupancyDesign:int}
     */
    public function site(): array
    {
        $floors = $this->floors();
        $rooms = 0;
        $occ = 0;
        foreach ($floors as $f) {
            $rooms += count($this->roomsFor($f['code']));
            foreach ($this->zonesFor($f['code']) as $z) {
                $occ += $z['capacity'];
            }
        }
        $streetNo = $this->intIn(1, 240, 'streetno');
        $streetName = $this->pick(
            ['Kestrel Way', 'Maple Avenue', 'Cedar Street', 'Union Road', 'Elm Boulevard',
             'Harbour Lane', 'Foundry Street', 'Willow Crescent', 'Granary Row', 'Station Approach'],
            'streetname'
        );
        // Doc-safe placeholder locality; no real postal identity.
        $city = $this->pick(['Fairport', 'Westbridge', 'Lakehaven', 'Northmoor', 'Ashcombe', 'Redhill Vale'], 'city');
        $tz = $this->pick(['Europe/Dublin', 'Europe/London', 'Europe/Amsterdam', 'America/New_York', 'America/Chicago'], 'tz');
        return [
            'name' => $this->buildingName(),
            'code' => 'SITE-01',
            'street' => $streetNo . ' ' . $streetName,
            'city' => $city,
            'timezone' => $tz,
            'grossAreaSqm' => count($floors) * $this->intIn(900, 2200, 'floorarea'),
            'floors' => count($floors),
            'rooms' => $rooms,
            'occupancyDesign' => $occ,
        ];
    }

    // --- floors / zones / rooms ---

    /**
     * Ordered floor stack bottom-to-top: 0-2 basements, Ground, optional Mezzanine, 2-9 upper levels,
     * Roof — total 4-14 (spec §C.1). Codes are slug-safe when lower-cased (B2, G, M, 1.., Roof).
     *
     * @return list<array{code:string,label:string,index:int,zones:list<string>,capacity:int}>
     */
    public function floors(): array
    {
        $basements = $this->intIn(0, 2, 'basements');
        $mezz = ($this->h('mezz') % 2) === 1;
        $upper = $this->intIn(2, 9, 'upper');

        $stack = [];
        for ($b = $basements; $b >= 1; $b--) {
            $stack[] = ['code' => 'B' . $b, 'label' => 'Basement ' . $b];
        }
        $stack[] = ['code' => 'G', 'label' => 'Ground'];
        if ($mezz) {
            $stack[] = ['code' => 'M', 'label' => 'Mezzanine'];
        }
        for ($u = 1; $u <= $upper; $u++) {
            $stack[] = ['code' => (string) $u, 'label' => 'Level ' . $u];
        }
        $stack[] = ['code' => 'Roof', 'label' => 'Roof'];

        $out = [];
        foreach ($stack as $i => $f) {
            $zoneCodes = $this->zoneCodesFor($f['code']);
            $cap = 0;
            foreach ($this->zonesFor($f['code']) as $z) {
                $cap += $z['capacity'];
            }
            $out[] = [
                'code' => $f['code'],
                'label' => $f['label'],
                'index' => $i,
                'zones' => $zoneCodes,
                'capacity' => $cap,
            ];
        }
        return $out;
    }

    /** Zone codes present on a floor — basements/roof/mezzanine carry a reduced set. */
    private function zoneCodesFor(string $floorCode): array
    {
        if ($floorCode === 'Roof') {
            return ['Core'];
        }
        if ($floorCode[0] === 'B') {
            return ['Core', 'N', 'S'];
        }
        if ($floorCode === 'M') {
            return ['N', 'S', 'Core'];
        }
        return ['N', 'E', 'S', 'W', 'Core'];
    }

    /**
     * Zones on a floor with a design capacity each — the occupancy spine site() sums.
     *
     * @return list<array{zone:string,name:string,capacity:int,areaSqm:int}>
     */
    public function zonesFor(string $floorCode): array
    {
        $names = ['N' => 'North', 'E' => 'East', 'S' => 'South', 'W' => 'West', 'Core' => 'Core'];
        $out = [];
        foreach ($this->zoneCodesFor($floorCode) as $z) {
            $out[] = [
                'zone' => $z,
                'name' => $names[$z],
                'capacity' => $z === 'Core' ? $this->intIn(4, 30, 'zcap|' . $floorCode . '|' . $z)
                    : $this->intIn(12, 70, 'zcap|' . $floorCode . '|' . $z),
                'areaSqm' => $this->intIn(120, 620, 'zarea|' . $floorCode . '|' . $z),
            ];
        }
        return $out;
    }

    /**
     * Rooms on a floor (8-40, spec §C.1). Naming scheme is chosen once per building
     * (mountains/rivers/cities/grid-codes) so the whole site reads from one convention.
     *
     * @return list<array{id:string,name:string,floor:string,zone:string,type:string,capacity:int,areaSqm:int}>
     */
    public function roomsFor(string $floorCode): array
    {
        $count = $this->intIn(8, 40, 'roomcount|' . $floorCode);
        $zones = $this->zoneCodesFor($floorCode);
        $types = ['Meeting', 'Focus', 'Open-plan', 'Exec', 'Lab', 'Server-Comms',
                  'Kitchen', 'Reception', 'Wellness', 'Store', 'Plant'];
        $scheme = $this->pick(['mountains', 'rivers', 'cities', 'grid'], 'roomscheme');
        $floorSlug = strtolower($floorCode);

        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $zone = $zones[$this->h('rzone|' . $floorCode . '|' . $i) % count($zones)];
            $type = $types[$this->h('rtype|' . $floorCode . '|' . $i) % count($types)];
            $out[] = [
                'id' => 'room-' . $floorSlug . '-' . sprintf('%02d', $i + 1),
                'name' => $this->roomName($scheme, $floorCode, $zone, $i),
                'floor' => $floorCode,
                'zone' => $zone,
                'type' => $type,
                'capacity' => $this->roomCapacity($type, $floorCode . '|' . $i),
                'areaSqm' => $this->intIn(9, 140, 'rarea|' . $floorCode . '|' . $i),
            ];
        }
        return $out;
    }

    private function roomName(string $scheme, string $floorCode, string $zone, int $i): string
    {
        if ($scheme === 'grid') {
            return strtoupper($floorCode) . '-' . $zone . '-' . sprintf('%02d', $i + 1);
        }
        $vocab = $this->nameVocab($scheme);
        $word = $vocab[$i % count($vocab)];
        // Wrap with a suffix once the vocab is exhausted so names stay distinct per floor.
        return $i < count($vocab) ? $word : $word . ' ' . (1 + (int) ($i / count($vocab)));
    }

    /** @return list<string> */
    private function nameVocab(string $scheme): array
    {
        if ($scheme === 'rivers') {
            return ['Shannon', 'Liffey', 'Severn', 'Thames', 'Danube', 'Rhine', 'Loire', 'Ebro',
                    'Douro', 'Tiber', 'Volga', 'Oder', 'Elbe', 'Tagus', 'Marne', 'Aire',
                    'Clyde', 'Tyne', 'Boyne', 'Nore', 'Barrow', 'Slaney', 'Suir', 'Lee',
                    'Moy', 'Erne', 'Bann', 'Foyle', 'Dee', 'Exe', 'Ouse', 'Trent',
                    'Wye', 'Avon', 'Medway', 'Kennet', 'Cam', 'Wear', 'Tees', 'Nene'];
        }
        if ($scheme === 'cities') {
            return ['Oslo', 'Turin', 'Ghent', 'Porto', 'Malmo', 'Bruges', 'Cork', 'Leeds',
                    'Nantes', 'Bergen', 'Aarhus', 'Rijeka', 'Kaunas', 'Tampere', 'Graz', 'Linz',
                    'Bilbao', 'Vigo', 'Reims', 'Lille', 'Salem', 'Fresno', 'Boise', 'Akron',
                    'Tulsa', 'Reno', 'Mesa', 'Provo', 'Ogden', 'Bend', 'Waco', 'Ames',
                    'Erie', 'Gary', 'Utica', 'Selma', 'Kent', 'Perth', 'Cairns', 'Darwin'];
        }
        // mountains
        return ['Denali', 'Rainier', 'Hood', 'Shasta', 'Whitney', 'Elbert', 'Baker', 'Adams',
                'Logan', 'Robson', 'Blanc', 'Eiger', 'Jungfrau', 'Nevis', 'Snowdon', 'Slieve',
                'Errigal', 'Carrauntoohil', 'Lugnaquilla', 'Galtymore', 'Brandon', 'Mangerton',
                'Nephin', 'Croagh', 'Muckish', 'Bennevis', 'Scafell', 'Helvellyn', 'Skiddaw',
                'Cairngorm', 'Lomond', 'Torridon', 'Etna', 'Vesuvius', 'Teide', 'Olympus',
                'Ida', 'Pindus', 'Rila', 'Tatra'];
    }

    private function roomCapacity(string $type, string $salt): int
    {
        switch ($type) {
            case 'Open-plan':
                return $this->intIn(20, 60, 'rcap|' . $salt);
            case 'Meeting':
                return $this->intIn(4, 16, 'rcap|' . $salt);
            case 'Reception':
            case 'Wellness':
                return $this->intIn(6, 24, 'rcap|' . $salt);
            case 'Exec':
            case 'Focus':
                return $this->intIn(1, 4, 'rcap|' . $salt);
            case 'Lab':
                return $this->intIn(4, 20, 'rcap|' . $salt);
            default: // Server-Comms, Kitchen, Store, Plant
                return $this->intIn(0, 6, 'rcap|' . $salt);
        }
    }

    // --- controllers + devices (the addressable estate) ---

    /**
     * Building controllers on the RFC1918 OT fabric (spec §C.1 spine): BMS on 10.0.50.x, ACS on
     * 10.0.60.x, NVR on 10.0.70.x. Health is mostly ok with a budgeted degraded/offline (spec E2).
     *
     * @return list<array{id:string,kind:string,ip:string,protocol:string,port:int,firmware:string,health:string}>
     */
    public function controllers(): array
    {
        $out = [];
        $bms = $this->intIn(4, 6, 'bmscount');
        for ($i = 1; $i <= $bms; $i++) {
            $out[] = $this->controllerRow('BMS-CTRL-' . sprintf('%02d', $i), 'BMS', '10.0.50.', 10 + $i, 'BACnet/IP', 47808, $i);
        }
        for ($i = 1; $i <= 2; $i++) {
            $out[] = $this->controllerRow('ACS-CTRL-' . sprintf('%02d', $i), 'ACS', '10.0.60.', 10 + $i, 'OSDP', 4070, $i);
        }
        for ($i = 1; $i <= 2; $i++) {
            $out[] = $this->controllerRow('NVR-' . sprintf('%02d', $i), 'NVR', '10.0.70.', 20 + $i, 'ONVIF/RTSP', 554, $i);
        }
        // Budget: 0-1 controller reads degraded, none-to-rarely offline (never a whole-estate outage).
        $anomalies = $this->h('ctrlanom') % 3 === 0 ? 1 : 0;
        if ($anomalies === 1) {
            $idx = $this->h('ctrlanomidx') % count($out);
            $out[$idx]['health'] = $this->pick(['degraded', 'comms-fail'], 'ctrlanomstate');
        }
        return $out;
    }

    private function controllerRow(string $id, string $kind, string $prefix, int $host, string $protocol, int $port, int $n): array
    {
        return [
            'id' => $id,
            'kind' => $kind,
            'ip' => $prefix . $host,
            'protocol' => $protocol,
            'port' => $port,
            'firmware' => $this->firmware('ctrlfw|' . $id),
            'health' => 'ok',
        ];
    }

    /** @return array{BMS:list<string>,ACS:list<string>,NVR:list<string>} */
    private function controllersByKind(): array
    {
        $map = ['BMS' => [], 'ACS' => [], 'NVR' => []];
        foreach ($this->controllers() as $c) {
            $map[$c['kind']][] = $c['id'];
        }
        return $map;
    }

    /**
     * The addressable device estate — 1-3 devices per room, so total scales with the building and
     * reconciles: every device names a real floor code, a real room on that floor, that room's zone,
     * and a real controller id of the kind its domain implies (climate/light/cover/sensor -> BMS,
     * lock/reader -> ACS, camera -> NVR). Bus address follows the controller's protocol.
     *
     * @return list<array{id:string,type:string,domain:string,floor:string,zone:string,room:string,controller:string,busAddress:string,firmware:string,lastSeen:string,state:string}>
     */
    public function devices(): array
    {
        $byKind = $this->controllersByKind();
        // [type, typeSlug, domain, controllerKind]
        $catalog = [
            ['Thermostat', 'tstat', 'climate', 'BMS'],
            ['VAV box', 'vav', 'climate', 'BMS'],
            ['Light group', 'light', 'light', 'BMS'],
            ['Roller blind', 'blind', 'cover', 'BMS'],
            ['Occupancy sensor', 'occ', 'sensor', 'BMS'],
            ['CO2 sensor', 'co2', 'sensor', 'BMS'],
            ['Sub-meter', 'mtr', 'sensor', 'BMS'],
            ['Door controller', 'door', 'lock', 'ACS'],
            ['Card reader', 'reader', 'lock', 'ACS'],
            ['Camera', 'cam', 'camera', 'NVR'],
        ];
        $states = ['online', 'online', 'online', 'online', 'online', 'fault', 'offline'];
        $seq = [];
        $out = [];

        foreach ($this->floors() as $f) {
            $floorCode = $f['code'];
            $floorSlug = strtolower($floorCode);
            foreach ($this->roomsFor($floorCode) as $r) {
                $n = $this->intIn(1, 3, 'devn|' . $floorCode . '|' . $r['id']);
                for ($d = 0; $d < $n; $d++) {
                    $salt = 'dev|' . $r['id'] . '|' . $d;
                    $cat = $catalog[$this->h($salt . '|cat') % count($catalog)];
                    $kind = $cat[3];
                    $pool = $byKind[$kind];
                    $controller = $pool[$this->h($salt . '|ctrl') % count($pool)];
                    $slug = $cat[1];
                    if (!isset($seq[$slug])) {
                        $seq[$slug] = 0;
                    }
                    $seq[$slug]++;
                    $out[] = [
                        'id' => $slug . '-' . $floorSlug . '-' . sprintf('%02d', $seq[$slug]),
                        'type' => $cat[0],
                        'domain' => $cat[2],
                        'floor' => $floorCode,
                        'zone' => $r['zone'],
                        'room' => $r['id'],
                        'controller' => $controller,
                        'busAddress' => $this->busAddress($kind, $salt),
                        'firmware' => $this->firmware('devfw|' . $salt),
                        'lastSeen' => $this->ageAgo('devseen|' . $salt),
                        'state' => $states[$this->h($salt . '|state') % count($states)],
                    ];
                }
            }
        }
        return $out;
    }

    /** Bus address in the controller protocol's own dialect (invented instances, never a signature). */
    private function busAddress(string $kind, string $salt): string
    {
        if ($kind === 'ACS') {
            return 'OSDP addr ' . $this->intIn(1, 126, $salt . '|osdp');
        }
        if ($kind === 'NVR') {
            return 'ch' . $this->intIn(1, 32, $salt . '|ch');
        }
        $obj = $this->pick(['AV', 'AI', 'BV', 'BI', 'AO'], $salt . '|objt');
        return 'BACnet ' . $obj . ':' . $this->intIn(1, 400, $salt . '|objn');
    }
}
