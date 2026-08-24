<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT network / VPN / VoIP estate for the deep office panel — the lateral-movement
 * intel surface (spec §C.7). It is a VIEW that reuses the `Org` roster (VPN users, VoIP extensions,
 * call/voicemail parties render at the host persona domain) and the `Building` topology (every device
 * sits in a real room on a real floor), so the wiring an attacker maps here reconciles with the people
 * and rooms shown elsewhere on the host.
 *
 * Design rules (deep-admin dashboard spec §C.7 + §E + adversarial critique):
 *  - DETERMINISTIC per seed: every value is hash(seed+slot) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); dates come from FrozenClock. A static reload is byte-identical
 *    (a diffable page is a tell).
 *  - ONE IP FABRIC, RFC1918/TEST-NET only: device management on the Mgmt VLAN (10.0.50.x), service
 *    hosts on 10.0.5.x (syslog .30, ntp .10, tacacs .11, radius .12, smtp-relay .25, dns .1/.2), the
 *    VLAN plan (10 Servers .. 99 Quarantine) and VPN tunnel pool 10.20.x.x are all private; a VPN
 *    session's "public" source is a TEST-NET-1/2/3 documentation address, never real routable space.
 *  - COHERENT: a device names a real Building floor + room; an access switch uplinks to a core switch
 *    that exists; an LLDP neighbour is another device or an Org employee's VLAN host; a VoIP extension
 *    is an Org person's own `ext`; a VPN user is an Org person (plus one MFA-off service account bait).
 *  - SAFE: management/SNMP/TACACS/RADIUS secrets in a running-config are MASKED, never a real key;
 *    external phone numbers are the reserved fictional 555-01xx range; no real vendor/model trademark,
 *    no scanner-signature string. Every control is inert (config/inventory downloads are decoy zips;
 *    ping/traceroute execute nothing; a device reboot is a guarded soft-denial).
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/intdiv, no enums/promotion/str_contains) so a fact can
 *    promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders, masks and escapes it.
 */
final class Network
{
    /** Shared service fabric on 10.0.5.x (spec §C.7) — one set of infrastructure hosts everywhere. */
    private const SVC = [
        'syslog' => '10.0.5.30',
        'ntp' => '10.0.5.10',
        'tacacs' => '10.0.5.11',
        'radius' => '10.0.5.12',
        'smtp' => '10.0.5.25',
        'dns1' => '10.0.5.1',
        'dns2' => '10.0.5.2',
    ];

    /** @var int */
    private $seed;

    /** @var string the host persona domain roster-derived emails render at. */
    private $personaDomain;

    /** @var Org */
    private $org;

    /** @var Building */
    private $building;

    /** @var list<array>|null cached device estate (order is stable) */
    private $deviceCache = null;

    private function __construct(int $seed, string $personaDomain)
    {
        $this->seed = $seed;
        $this->personaDomain = $personaDomain;
        $this->org = Org::fromSeed($seed, $personaDomain);
        $this->building = Building::fromSeed($seed);
    }

    /**
     * Build the network estate for a seed. The section MUST pass the host persona domain so roster
     * emails (VPN users, call parties) never contradict the one domain shown elsewhere on the host.
     */
    public static function fromSeed(int $seed, string $personaDomain = ''): self
    {
        return new self($seed, $personaDomain);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|net|' . $salt), 0, 15));
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

    /** vN.N.N firmware string, frozen per component. */
    private function firmware(string $salt): string
    {
        return $this->intIn(1, 9, $salt . '|fa')
            . '.' . $this->intIn(0, 24, $salt . '|fb')
            . '.' . $this->intIn(0, 60, $salt . '|fc');
    }

    /** Seeded uptime "N d H h" — pure hash(seed+slot), deterministic, never time()/date(). */
    private function uptime(string $salt): string
    {
        $days = $this->intIn(1, 640, $salt . '|upd');
        $hrs = $this->intIn(0, 23, $salt . '|uph');
        return $days . ' d ' . $hrs . ' h';
    }

    /** A frozen absolute epoch $salt-seconds before the frozen "now" (bounded 0..$maxSec). */
    private function epochAgo(string $salt, int $maxSec): int
    {
        return FrozenClock::EPOCH - $this->intIn(30, $maxSec, $salt);
    }

    // --- device estate ---

    /**
     * The addressable network device estate, order stable: edge router, firewall, two core switches,
     * then per-floor access switches and access points. Every device names a real Building floor + room
     * and a management IP on the Mgmt VLAN; access switches uplink to a core switch that exists.
     *
     * @return list<array{id:string,hostname:string,kind:string,role:string,model:string,mgmtIp:string,floor:string,floorLabel:string,room:string,portCount:int,uptime:string,firmware:string,serial:string,health:string,uplink:string}>
     */
    public function devices(): array
    {
        if ($this->deviceCache !== null) {
            return $this->deviceCache;
        }
        $out = [];

        // Core estate — the always-present spine. Fixed low mgmt hosts (Building BMS sits on .11-.16,
        // so the network gear deliberately claims .1-.9 / .254 and never those).
        $out[] = $this->deviceRow('rtr-01', 'Router', 'Edge router', '10.0.50.254', $this->coreRoom(0), 4, '');
        $out[] = $this->deviceRow('fw-01', 'Firewall', 'Perimeter firewall', '10.0.50.1', $this->coreRoom(0), 8, 'rtr-01');
        $out[] = $this->deviceRow('sw-core-01', 'Core switch', 'Core distribution', '10.0.50.2', $this->coreRoom(0), 48, 'fw-01');
        $out[] = $this->deviceRow('sw-core-02', 'Core switch', 'Core distribution', '10.0.50.3', $this->coreRoom(1), 48, 'fw-01');

        // Access layer — access switches + APs per floor, addressed off distinct host ranges.
        $accHost = 20;
        $apHost = 100;
        foreach ($this->building->floors() as $f) {
            $floorCode = $f['code'];
            $floorSlug = $this->slug($floorCode);
            $room = $this->floorRoom($floorCode);
            $core = ($this->h('coreuplink|' . $floorCode) % 2) === 0 ? 'sw-core-01' : 'sw-core-02';

            $accN = $this->intIn(1, 2, 'accn|' . $floorCode);
            for ($a = 1; $a <= $accN && $accHost <= 90; $a++) {
                $ports = $this->pick(['24', '48'], 'accports|' . $floorCode . '|' . $a) === '24' ? 24 : 48;
                $out[] = $this->deviceRow(
                    'sw-acc-' . $floorSlug . '-' . sprintf('%02d', $a),
                    'Access switch',
                    'Access switch',
                    '10.0.50.' . $accHost,
                    $room,
                    $ports,
                    $core
                );
                $accHost++;
            }

            $apN = $this->intIn(2, 4, 'apn|' . $floorCode);
            for ($p = 1; $p <= $apN && $apHost <= 200; $p++) {
                $out[] = $this->deviceRow(
                    'ap-' . $floorSlug . '-' . sprintf('%02d', $p),
                    'Access point',
                    'Wi-Fi access point',
                    '10.0.50.' . $apHost,
                    $room,
                    2,
                    'sw-acc-' . $floorSlug . '-01'
                );
                $apHost++;
            }
        }

        // Anomaly budget: 0-1 device reads degraded, never a whole-estate outage (spec E2).
        if ($this->h('netanom') % 2 === 0) {
            $idx = $this->h('netanomidx') % count($out);
            $out[$idx]['health'] = $this->pick(['degraded', 'flapping'], 'netanomstate');
        }

        $this->deviceCache = $out;
        return $out;
    }

    private function deviceRow(string $id, string $kind, string $role, string $mgmtIp, array $room, int $ports, string $uplink): array
    {
        $models = [
            'Router' => ['MX-240', 'MX-480', 'RTR-9000'],
            'Firewall' => ['SecGate-3100', 'SecGate-5200', 'FW-880'],
            'Core switch' => ['CX-9300-48', 'CX-9500-48', 'DS-7700'],
            'Access switch' => ['CX-4800-48P', 'CX-4200-24P', 'AS-2960X'],
            'Access point' => ['AP-635', 'AP-515', 'WAP-7200'],
        ];
        $pool = isset($models[$kind]) ? $models[$kind] : ['GEN-1000'];
        return [
            'id' => $id,
            'hostname' => $id,
            'kind' => $kind,
            'role' => $role,
            'model' => $this->pick($pool, 'model|' . $id),
            'mgmtIp' => $mgmtIp,
            'floor' => $room['floor'],
            'floorLabel' => $room['floorLabel'],
            'room' => $room['room'],
            'portCount' => $ports,
            'uptime' => $this->uptime('up|' . $id),
            'firmware' => $this->firmware('fw|' . $id),
            'serial' => strtoupper(substr(hash('sha256', $this->seed . '|netserial|' . $id), 0, 4))
                . sprintf('%07d', $this->intIn(1000000, 9999999, 'sn|' . $id)),
            'health' => 'ok',
            'uplink' => $uplink,
        ];
    }

    /** A core-room descriptor for the equipment spine — a Server-Comms room on the ground floor. */
    private function coreRoom(int $which): array
    {
        return $this->floorRoom($which === 0 ? 'G' : 'B1');
    }

    /**
     * Resolve a floor to a comms/plant room descriptor (prefers a Server-Comms room, else the first
     * room, else a synthesised riser) so a device always names a real place on a real floor.
     *
     * @return array{floor:string,floorLabel:string,room:string}
     */
    private function floorRoom(string $floorCode): array
    {
        $label = $floorCode;
        foreach ($this->building->floors() as $f) {
            if ($f['code'] === $floorCode) {
                $label = $f['label'];
                break;
            }
        }
        $rooms = $this->building->roomsFor($floorCode);
        $chosen = '';
        foreach ($rooms as $r) {
            if ($r['type'] === 'Server-Comms') {
                $chosen = $r['name'] . ' (' . $r['id'] . ')';
                break;
            }
        }
        if ($chosen === '' && $rooms !== []) {
            $r = $rooms[0];
            $chosen = $r['name'] . ' (' . $r['id'] . ')';
        }
        if ($chosen === '') {
            $chosen = 'Comms riser ' . strtoupper($this->slug($floorCode));
        }
        return ['floor' => $floorCode, 'floorLabel' => $label, 'room' => $chosen];
    }

    public function deviceCount(): int
    {
        return count($this->devices());
    }

    /**
     * A page of the device estate.
     *
     * @return list<array>
     */
    public function devicePage(int $offset, int $limit): array
    {
        if ($offset < 0) {
            $offset = 0;
        }
        if ($limit < 1) {
            $limit = 1;
        }
        return array_slice($this->devices(), $offset, $limit);
    }

    /**
     * One device by its id slug. A fuzzed/unknown slug resolves to the first device so a detail page
     * never dead-ends (a 404 inside a deep panel is a tell).
     *
     * @return array
     */
    public function deviceBySlug(string $slug): array
    {
        $devices = $this->devices();
        foreach ($devices as $d) {
            if ($d['id'] === $slug) {
                return $d;
            }
        }
        return $devices[0];
    }

    // --- per-device running-config (inert, masked, RFC1918) ---

    /**
     * A vendor-neutral running-config for a device: hostname, clock/NTP, MASKED SNMP/TACACS/RADIUS
     * secrets pointed at the service fabric, the VLAN plan, and interfaces whose descriptions ARE the
     * cabling map (they match interfaces()). Nothing here is a live secret or a scanner signature.
     *
     * @return list<string>
     */
    public function runningConfig(array $device): array
    {
        $id = $device['id'];
        $lines = [];
        $lines[] = '! running-config for ' . $id . ' (' . $device['model'] . ')';
        $lines[] = '! last written by netops · config revision '
            . strtoupper(substr(hash('sha256', $this->seed . '|cfgrev|' . $id), 0, 8));
        $lines[] = '!';
        $lines[] = 'hostname ' . $id;
        $lines[] = 'clock timezone UTC 0';
        $lines[] = 'ntp server ' . self::SVC['ntp'];
        $lines[] = 'ip name-server ' . self::SVC['dns1'] . ' ' . self::SVC['dns2'];
        $lines[] = '!';
        $lines[] = 'snmp-server community <masked> RO';
        $lines[] = 'snmp-server host ' . self::SVC['syslog'] . ' version 2c <masked>';
        $lines[] = 'logging host ' . self::SVC['syslog'];
        $lines[] = 'logging trap informational';
        $lines[] = '!';
        $lines[] = 'aaa new-model';
        $lines[] = 'aaa authentication login default group tacacs+ local';
        $lines[] = 'tacacs-server host ' . self::SVC['tacacs'] . ' key <masked>';
        $lines[] = 'radius-server host ' . self::SVC['radius'] . ' key <masked>';
        $lines[] = 'username netadmin privilege 15 secret <masked>';
        $lines[] = '!';
        foreach ($this->vlans() as $v) {
            $lines[] = 'vlan ' . $v['id'];
            $lines[] = ' name ' . str_replace(' ', '_', $v['name']);
        }
        $lines[] = '!';
        foreach ($this->interfaces($device) as $if) {
            $lines[] = 'interface ' . $if['port'];
            if ($if['desc'] !== '') {
                $lines[] = ' description ' . $if['desc'];
            }
            if ($if['mode'] === 'trunk') {
                $lines[] = ' switchport mode trunk';
            } else {
                $lines[] = ' switchport access vlan ' . $if['vlan'];
                $lines[] = ' switchport mode access';
            }
            if ($if['admin'] === 'down') {
                $lines[] = ' shutdown';
            }
            $lines[] = '!';
        }
        $lines[] = 'ip default-gateway 10.0.50.1';
        $lines[] = 'line vty 0 4';
        $lines[] = ' transport input ssh';
        $lines[] = ' access-class MGMT-ONLY in';
        $lines[] = '!';
        $lines[] = 'end';
        return $lines;
    }

    // --- per-device interface / port table (the cabling map) ---

    /**
     * The port table for a device: uplinks trunk to the device's uplink neighbour; the remaining ports
     * are access ports, a few carrying an LLDP neighbour (a downstream device or an Org employee's VLAN
     * host) so the table reads as a real cabling map. Capped so a huge switch still renders one screen.
     *
     * @return list<array{port:string,admin:string,oper:string,mode:string,vlan:string,speed:string,neighbor:string,desc:string}>
     */
    public function interfaces(array $device): array
    {
        $ports = $device['portCount'];
        if ($ports < 1) {
            $ports = 1;
        }
        $shown = $ports > 16 ? 16 : $ports;
        $accessVlans = ['20', '30', '10', '60', '70'];
        $out = [];
        for ($i = 1; $i <= $shown; $i++) {
            $salt = 'if|' . $device['id'] . '|' . $i;
            $port = ($device['kind'] === 'Router' || $device['kind'] === 'Firewall')
                ? 'Ge0/' . $i
                : 'Gi1/0/' . $i;

            // First one or two ports are the uplink trunk to this device's parent.
            if ($i <= ($device['kind'] === 'Access point' ? 1 : 2) && $device['uplink'] !== '') {
                $out[] = [
                    'port' => $port,
                    'admin' => 'up',
                    'oper' => 'up',
                    'mode' => 'trunk',
                    'vlan' => 'trunk',
                    'speed' => $device['kind'] === 'Access point' ? '1G' : '10G',
                    'neighbor' => $device['uplink'] . ' (uplink)',
                    'desc' => 'uplink to ' . $device['uplink'],
                ];
                continue;
            }

            $vlan = $accessVlans[$this->h($salt . '|vl') % count($accessVlans)];
            $adminDown = $this->h($salt . '|ad') % 9 === 0;
            $hasNeighbor = !$adminDown && $this->h($salt . '|nb') % 3 === 0;
            $neighbor = '';
            $desc = '';
            if ($hasNeighbor) {
                if ($this->h($salt . '|nt') % 2 === 0) {
                    // A downstream Org employee's VLAN host (cross-ref with the people fabric).
                    $person = $this->org->people($this->org->headcount());
                    if ($person !== []) {
                        $p = $person[$this->h($salt . '|pi') % count($person)];
                        $neighbor = $p['ip'] . ' (' . $p['id'] . ')';
                        $desc = 'edge port · ' . $p['id'];
                    }
                } else {
                    // A downstream access point or comms drop.
                    $neighbor = 'ap-' . $this->slug($device['floor']) . '-'
                        . sprintf('%02d', ($this->h($salt . '|ap') % 3) + 1);
                    $desc = 'AP drop';
                }
            }
            $out[] = [
                'port' => $port,
                'admin' => $adminDown ? 'down' : 'up',
                'oper' => $adminDown ? 'down' : ($hasNeighbor || $this->h($salt . '|op') % 4 !== 0 ? 'up' : 'down'),
                'mode' => 'access',
                'vlan' => $vlan,
                'speed' => $adminDown ? '—' : '1G',
                'neighbor' => $neighbor,
                'desc' => $desc,
            ];
        }
        return $out;
    }

    // --- VLAN plan (the one fabric, spec §C.7) ---

    /**
     * The site VLAN plan — a fixed, coherent table (id -> name -> subnet -> gateway), all RFC1918.
     *
     * @return list<array{id:string,name:string,subnet:string,gateway:string}>
     */
    public function vlans(): array
    {
        return [
            ['id' => '10', 'name' => 'Servers', 'subnet' => '10.0.10.0/24', 'gateway' => '10.0.10.1'],
            ['id' => '20', 'name' => 'Employees', 'subnet' => '10.0.20.0/23', 'gateway' => '10.0.20.1'],
            ['id' => '30', 'name' => 'Voice', 'subnet' => '10.0.30.0/24', 'gateway' => '10.0.30.1'],
            ['id' => '40', 'name' => 'Guest', 'subnet' => '10.0.40.0/24', 'gateway' => '10.0.40.1'],
            ['id' => '50', 'name' => 'Mgmt', 'subnet' => '10.0.50.0/24', 'gateway' => '10.0.50.1'],
            ['id' => '60', 'name' => 'CCTV', 'subnet' => '10.0.60.0/24', 'gateway' => '10.0.60.1'],
            ['id' => '70', 'name' => 'BMS/OT', 'subnet' => '10.0.70.0/24', 'gateway' => '10.0.70.1'],
            ['id' => '99', 'name' => 'Quarantine', 'subnet' => '10.0.99.0/24', 'gateway' => '10.0.99.1'],
        ];
    }

    /** Canned, inert traceroute output toward a target — a fixed RFC1918 hop path, executes nothing. */
    public function tracerouteHops(): array
    {
        return [
            ['1', 'gw-mgmt (10.0.50.1)', '0.4 ms'],
            ['2', 'sw-core-01 (10.0.50.2)', '0.9 ms'],
            ['3', 'fw-01 (10.0.50.1)', '1.3 ms'],
            ['4', 'rtr-01 (10.0.50.254)', '2.1 ms'],
        ];
    }

    // --- VPN ---

    /**
     * VPN account roster: every Org person as a VPN user, plus one MFA-off `svc-backup` service account
     * (the standing bait). Emails render at the host persona domain. Paged by the section.
     *
     * @return list<array{user:string,name:string,email:string,group:string,mfa:string,lastConnect:string,status:string}>
     */
    public function vpnUsers(int $offset, int $limit): array
    {
        $rows = $this->vpnUserRows();
        if ($offset < 0) {
            $offset = 0;
        }
        if ($limit < 1) {
            $limit = 1;
        }
        return array_slice($rows, $offset, $limit);
    }

    public function vpnUserCount(): int
    {
        return count($this->vpnUserRows());
    }

    /** @return list<array> the full VPN account list, order stable (service account first). */
    private function vpnUserRows(): array
    {
        $out = [];
        // The MFA-off service account — a real bait row that the never-authenticating login dead-ends.
        $out[] = [
            'user' => 'svc-backup',
            'name' => 'Backup service account',
            'email' => 'svc-backup@' . $this->org->domain(),
            'group' => 'Service-Accounts',
            'mfa' => 'off',
            'lastConnect' => FrozenClock::ymd($this->epochAgo('svcvpn', 86400 * 3)),
            'status' => 'enabled',
        ];
        $groups = ['Employees', 'IT-Admins', 'Contractors', 'Remote-Sales'];
        foreach ($this->org->people($this->org->headcount()) as $p) {
            $i = (int) substr($p['id'], 4);
            $out[] = [
                'user' => $this->localPart($p['email']),
                'name' => $p['name'],
                'email' => $p['email'],
                'group' => $p['dept'] === 'IT' ? 'IT-Admins' : $groups[$this->h('vgrp|' . $p['id']) % count($groups)],
                'mfa' => $this->h('vmfa|' . $p['id']) % 20 === 0 ? 'off' : 'on',
                'lastConnect' => FrozenClock::ymd($this->epochAgo('vlast|' . $i, 86400 * 40)),
                'status' => $p['status'] === 'Notice' ? 'disabled' : 'enabled',
            ];
        }
        return $out;
    }

    /**
     * The currently-connected VPN sessions — a small live subset of the roster on the 10.20.x.x tunnel
     * pool, each from a TEST-NET documentation "public" source (never real routable space).
     *
     * @return list<array{user:string,tunnelIp:string,sourceIp:string,sourceGeo:string,since:string,rx:string,tx:string}>
     */
    public function vpnSessions(): array
    {
        $people = $this->org->people($this->org->headcount());
        if ($people === []) {
            return [];
        }
        $count = $this->intIn(6, 18, 'vpnsesscount');
        if ($count > count($people)) {
            $count = count($people);
        }
        $geos = ['IE · AS64500', 'GB · AS64501', 'NL · AS64502', 'DE · AS64503', 'US · AS64504', 'ES · AS64505'];
        // Three TEST-NET blocks stand in for "public" client addresses (RFC 5737 documentation space).
        $testNets = ['192.0.2.', '198.51.100.', '203.0.113.'];
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $p = $people[$this->h('vsess|' . $i . '|pi') % count($people)];
            $net = $testNets[$this->h('vsess|' . $i . '|net') % count($testNets)];
            $since = $this->epochAgo('vsess|' . $i . '|since', 3600 * 9);
            $out[] = [
                'user' => $this->localPart($p['email']),
                'tunnelIp' => '10.20.' . $this->intIn(0, 40, 'vsess|' . $i . '|t3') . '.' . $this->intIn(2, 254, 'vsess|' . $i . '|t4'),
                'sourceIp' => $net . $this->intIn(1, 254, 'vsess|' . $i . '|src'),
                'sourceGeo' => $geos[$this->h('vsess|' . $i . '|geo') % count($geos)],
                'since' => FrozenClock::ymd($since) . ' ' . FrozenClock::clock($since),
                'rx' => $this->intIn(2, 980, 'vsess|' . $i . '|rx') . ' MB',
                'tx' => $this->intIn(1, 420, 'vsess|' . $i . '|tx') . ' MB',
            ];
        }
        return $out;
    }

    // --- VoIP / telephony ---

    /**
     * The extension directory — every Org person's own `ext`, on the Voice VLAN, plus device kind and
     * registration state. Paged by the section.
     *
     * @return list<array{ext:string,name:string,dept:string,device:string,ip:string,status:string}>
     */
    public function extensions(int $offset, int $limit): array
    {
        $rows = $this->extensionRows();
        if ($offset < 0) {
            $offset = 0;
        }
        if ($limit < 1) {
            $limit = 1;
        }
        return array_slice($rows, $offset, $limit);
    }

    public function extensionCount(): int
    {
        return count($this->extensionRows());
    }

    /** @return list<array> */
    private function extensionRows(): array
    {
        $out = [];
        foreach ($this->org->people($this->org->headcount()) as $p) {
            $i = (int) substr($p['id'], 4);
            $device = $this->pick(['Desk phone', 'Softphone', 'DECT handset', 'Conference unit'], 'voipdev|' . $p['id']);
            $out[] = [
                'ext' => $p['ext'],
                'name' => $p['name'],
                'dept' => $p['dept'],
                'device' => $device,
                // Voice VLAN host, RFC1918; spreads onto 10.0.30.0/24.
                'ip' => '10.0.30.' . (2 + ($i % 250)),
                'status' => $this->h('voipreg|' . $p['id']) % 12 === 0 ? 'unregistered' : 'registered',
            ];
        }
        return $out;
    }

    /**
     * A call-detail-record (CDR) scroll, newest first: internal extensions and reserved-range external
     * numbers, walked back from the frozen "now". A pure log tail — no audio, nothing dialable.
     *
     * @return list<string>
     */
    public function callLog(int $count): array
    {
        if ($count < 1) {
            $count = 1;
        }
        $exts = $this->extensionRows();
        $lines = [];
        $cursor = FrozenClock::EPOCH;
        for ($i = 0; $i < $count; $i++) {
            $cursor -= $this->intIn(20, 900, 'cdrgap|' . $i);
            $stamp = FrozenClock::ymd($cursor) . ' ' . FrozenClock::clock($cursor);
            $inbound = $this->h('cdrdir|' . $i) % 2 === 0;
            $ext = $exts !== [] ? $exts[$this->h('cdrext|' . $i) % count($exts)]['ext'] : sprintf('%04d', 2000 + $i);
            // Reserved fictional external number (555-01xx) — never dialable, never real.
            $ext2 = '+1-555-01' . sprintf('%02d', $this->h('cdrpstn|' . $i) % 100);
            $durSec = $this->intIn(0, 1800, 'cdrdur|' . $i);
            $dur = sprintf('%02d:%02d', intdiv($durSec, 60), $durSec % 60);
            $disp = $durSec === 0
                ? $this->pick(['no-answer', 'busy', 'missed'], 'cdrdisp|' . $i)
                : 'answered';
            $dir = $inbound ? ($ext2 . ' -> ext ' . $ext) : ('ext ' . $ext . ' -> ' . $ext2);
            $lines[] = $stamp . '  ' . ($inbound ? 'IN ' : 'OUT') . '  ' . $dir . '  ' . $dur . '  ' . $disp;
        }
        return $lines;
    }

    public function callLogCount(): int
    {
        // Reconciles with the extension count so the "of N" claim scales with the company.
        return $this->extensionCount() * 26 + ($this->h('cdrtotal') % 900);
    }

    /**
     * The voicemail box: sender (reserved external number or an internal ext), recipient (an Org
     * person), duration and a transcript snippet. No audio is ever served — transcript text only.
     *
     * @return list<array{id:string,from:string,to:string,toName:string,received:string,duration:string,transcript:string,new:bool}>
     */
    public function voicemail(int $count): array
    {
        if ($count < 1) {
            $count = 1;
        }
        $people = $this->org->people($this->org->headcount());
        if ($people === []) {
            return [];
        }
        $snippets = [
            'Hi, please call the bank back regarding the pending wire — they need confirmation today.',
            'This is facilities, the access reader on the third floor is offline again, can you check.',
            'Following up on the invoice approval, the vendor is asking about payment status.',
            'It is the helpdesk, your VPN certificate is expiring, please renew before Friday.',
            'Quick one about the server room temperature alert overnight, call me back.',
            'Reminder about the change window tonight, confirm the maintenance ticket is approved.',
        ];
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $to = $people[$this->h('vm|' . $i . '|to') % count($people)];
            $external = $this->h('vm|' . $i . '|ext') % 2 === 0;
            $from = $external
                ? '+1-555-01' . sprintf('%02d', $this->h('vm|' . $i . '|num') % 100)
                : 'ext ' . $people[$this->h('vm|' . $i . '|fromp') % count($people)]['ext'];
            $durSec = $this->intIn(8, 210, 'vm|' . $i . '|dur');
            $recv = $this->epochAgo('vm|' . $i . '|recv', 86400 * 6);
            $out[] = [
                'id' => 'vm-' . sprintf('%04d', $i + 1),
                'from' => $from,
                'to' => 'ext ' . $to['ext'],
                'toName' => $to['name'],
                'received' => FrozenClock::ymd($recv) . ' ' . FrozenClock::clock($recv),
                'duration' => sprintf('%d:%02d', intdiv($durSec, 60), $durSec % 60),
                'transcript' => $snippets[$this->h('vm|' . $i . '|snip') % count($snippets)],
                'new' => $this->h('vm|' . $i . '|new') % 3 === 0,
            ];
        }
        return $out;
    }

    // --- shared helpers ---

    /** The email local part (before '@'), for a login/username column. */
    private function localPart(string $email): string
    {
        $at = strpos($email, '@');
        return $at === false ? $email : substr($email, 0, $at);
    }

    /** The slug rule the router/nav helpers use, so an id built here is always a safe path segment. */
    private function slug(string $seg): string
    {
        return trim((string) preg_replace('/[^a-z0-9]+/', '-', strtolower($seg)), '-');
    }
}
