<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT integrations / device-endpoint registry for the deep office panel — the densest
 * per-byte lateral-movement lure (spec §C.7 / §F.3 #15). Every row is a protocol endpoint as host:port
 * on the RFC1918 fabric: MQTT 1883, BACnet/IP 47808, SNMP 161, Modbus TCP 502, REST APIs 443/8080, plus
 * the building controllers themselves and the core network services — the map an attacker reads to plan
 * the next hop.
 *
 * Sits on Building (the BACnet/OSDP/ONVIF endpoints ARE the real BMS/ACS/NVR controllers, so this
 * registry reconciles with every building module) and scales its network/OT rows off the floor stack, so
 * a bigger building shows a bigger fabric.
 *
 * Design rules (deep-admin dashboard spec §C.7 + §C.0 + adversarial critique):
 *  - DETERMINISTIC per seed: every value is hash(seed+id+field) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); an endpoint's facts derive from its id, so endpoint($id) is
 *    byte-identical to its row in endpoints() and reproducible standalone. Ages are offsets off
 *    FrozenClock::epoch().
 *  - SAFE: every host is RFC1918 (10.x) only — the whole point of a leaked internal endpoint is that it
 *    is internal. Credentials are masked, fabricated and non-validating (community strings, MQTT users,
 *    API keys); no OID is rendered as a dotted-numeric quad (that would read as an IP). No real
 *    trademark, no scanner-signature string. Nothing here transacts or changes state.
 *  - ANOMALY BUDGET: 0-2 endpoints read degraded/down; the rest are up. A whole-fabric outage, or a
 *    buffet of dead endpoints, reads as staged.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/intdiv, no enums/named-args/str_contains/promotion) so a
 *    fact can promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders, masks and escapes it.
 */
final class Integrations
{
    /** @var int */
    private $seed;

    /** @var Building */
    private $bld;

    /** @var list<array<string,mixed>>|null memoised endpoint registry (built once per instance) */
    private $cache = null;

    /** @var array<string,int>|null id -> registry index */
    private $index = null;

    /** @var Network|null lazily built so switch refs come from the one Network estate (no phantoms) */
    private $net = null;

    private function __construct(int $seed)
    {
        $this->seed = $seed;
        $this->bld = Building::fromSeed($seed);
    }

    public static function fromSeed(int $seed): self
    {
        return new self($seed);
    }

    /** The Network estate, so the SNMP switch rows reference switches that actually exist there. */
    private function net(): Network
    {
        if ($this->net === null) {
            $this->net = Network::fromSeed($this->seed);
        }
        return $this->net;
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|intg|' . $salt), 0, 15));
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
        return substr(hash('sha256', $this->seed . '|intghex|' . $salt), 0, $len);
    }

    private function ageAgo(int $sec): string
    {
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

    private function firmware(string $salt): string
    {
        return 'v' . $this->intIn(1, 6, $salt . '|fa')
            . '.' . $this->intIn(0, 20, $salt . '|fb')
            . '.' . $this->intIn(0, 40, $salt . '|fc');
    }

    // --- credential-shaped bait (all masked, fabricated, non-validating) ---

    /** A masked SNMP community — a tail only, never a working string. */
    private function communityMasked(string $salt): string
    {
        return '••••' . substr($this->hex(3, 'comm|' . $salt), 0, 3);
    }

    /** A masked API key in the right shape — an EXAMPLE-tailed dummy, never a live key. */
    private function apiKeyMasked(string $salt): string
    {
        return 'ak_live_' . substr($this->hex(8, 'ak|' . $salt), 0, 8) . '••••EXAMPLE';
    }

    /** A fabricated broker/service username. */
    private function svcUser(string $salt): string
    {
        return $this->pick(['svc-mqtt', 'svc-bms', 'svc-telemetry', 'iot-bridge', 'svc-integrations'], 'user|' . $salt);
    }

    // --- the registry (built once, reconciles with Building) ---

    /**
     * The full endpoint registry, memoised. Rows come from: the Building controllers (BACnet/OSDP/ONVIF —
     * so the registry IS the real building fabric), per-floor SNMP-managed access switches and Modbus OT
     * meters (scaling the fabric with the building), and fixed sets of MQTT brokers, REST APIs and core
     * network services on the 10.0.5.x / 10.0.10.x service space.
     *
     * @return list<array<string,mixed>>
     */
    public function endpoints(): array
    {
        if ($this->cache !== null) {
            return $this->cache;
        }
        $rows = [];

        // 1) Building controllers -> BACnet/IP (BMS), OSDP (ACS), ONVIF (NVR). Same host:port the BMS
        //    modules show, so the registry never contradicts them.
        foreach ($this->bld->controllers() as $c) {
            if ($c['kind'] === 'BMS') {
                $proto = 'BACnet/IP';
                $transport = 'udp';
                $category = 'Building / OT';
            } elseif ($c['kind'] === 'ACS') {
                $proto = 'OSDP';
                $transport = 'tcp';
                $category = 'Building / OT';
            } else {
                $proto = 'ONVIF';
                $transport = 'tcp';
                $category = 'Building / OT';
            }
            $id = strtolower($c['id']);
            $rows[] = $this->baseRow(
                $id,
                $c['id'],
                $proto,
                $c['ip'],
                $c['port'],
                $transport,
                $category,
                'controller',
                $c['id'],
                $c['firmware']
            );
        }

        // 2) Per-floor SNMP-managed access switches + Modbus OT sub-meters — the fabric scales with the
        //    building, and the switch ids match the CMDB switch-port naming (sw-acc-<floor>-NN).
        foreach ($this->bld->floors() as $f) {
            $fslug = strtolower($f['code']);
            // Access switches come straight from the Network estate so this SNMP registry never names a
            // switch that isn't in Network Devices (the CMDB cabling map keys off the same source).
            foreach ($this->net()->accessSwitchIdsForFloor((string) $f['code']) as $swId) {
                $rows[] = $this->baseRow(
                    'snmp-' . $swId,
                    $swId,
                    'SNMP',
                    '10.0.50.' . (100 + $this->h('swip|' . $swId) % 140),
                    161,
                    'udp',
                    'Network',
                    'switch',
                    '',
                    $this->firmware('swfw|' . $swId)
                );
            }
            $meters = $this->intIn(1, 2, 'mbn|' . $f['code']);
            for ($m = 1; $m <= $meters; $m++) {
                $id = 'modbus-mtr-' . $fslug . '-' . sprintf('%02d', $m);
                $rows[] = $this->baseRow(
                    $id,
                    'MTR-' . strtoupper($fslug) . '-' . sprintf('%02d', $m),
                    'Modbus TCP',
                    '10.0.70.' . (10 + $this->h('mbip|' . $f['code'] . '|' . $m) % 200),
                    502,
                    'tcp',
                    'Building / OT',
                    'meter',
                    '',
                    $this->firmware('mbfw|' . $f['code'] . '|' . $m)
                );
            }
        }

        // 3) MQTT brokers (the IoT nerve centre).
        foreach (['mqtt-broker-01' => 'MQTT Broker (primary)', 'mqtt-broker-02' => 'MQTT Broker (standby)', 'mqtt-iot-bridge' => 'IoT Bridge'] as $id => $name) {
            $rows[] = $this->baseRow(
                $id,
                $name,
                'MQTT',
                '10.0.5.' . (40 + $this->h('mqip|' . $id) % 40),
                1883,
                'tcp',
                'IoT',
                'broker',
                '',
                $this->firmware('mqfw|' . $id)
            );
        }

        // 4) Internal REST API integrations (the app-layer pivot surface).
        $apis = [
            'api-bms-gateway' => 'BMS Gateway API',
            'api-badge-sync' => 'Badge Sync API',
            'api-hr-connector' => 'HR Connector API',
            'api-telemetry' => 'Telemetry Ingest API',
            'api-cmdb-sync' => 'CMDB Sync API',
            'api-energy-export' => 'Energy Export API',
            'api-booking' => 'Room Booking API',
            'api-visitor' => 'Visitor Management API',
            'api-print-release' => 'Print Release API',
            'api-alerting' => 'Alerting Webhook',
            'api-identity' => 'Identity Provider (SCIM)',
            'api-asset-intake' => 'Asset Intake API',
        ];
        foreach ($apis as $id => $name) {
            $rows[] = $this->baseRow(
                $id,
                $name,
                'REST API',
                '10.0.10.' . (20 + $this->h('apiip|' . $id) % 200),
                (int) $this->pick(['443', '8080', '8443'], 'apiport|' . $id),
                'tcp',
                'API',
                'api',
                '',
                $this->firmware('apifw|' . $id)
            );
        }

        // 5) Core network services on the 10.0.5.x service space (the fabric spec §C.7 names).
        $svc = [
            'svc-dns-01' => ['DNS (primary)', 'DNS', 53, 'udp', '10.0.5.1'],
            'svc-dns-02' => ['DNS (secondary)', 'DNS', 53, 'udp', '10.0.5.2'],
            'svc-ntp-01' => ['NTP', 'NTP', 123, 'udp', '10.0.5.10'],
            'svc-tacacs-01' => ['TACACS+', 'TACACS+', 49, 'tcp', '10.0.5.11'],
            'svc-radius-01' => ['RADIUS', 'RADIUS', 1812, 'udp', '10.0.5.12'],
            'svc-smtp-relay' => ['SMTP Relay', 'SMTP', 25, 'tcp', '10.0.5.25'],
            'svc-syslog-01' => ['Syslog Collector', 'Syslog', 514, 'udp', '10.0.5.30'],
        ];
        foreach ($svc as $id => $d) {
            $rows[] = $this->baseRow(
                $id,
                $d[0],
                $d[1],
                $d[4],
                $d[2],
                $d[3],
                'Directory / Services',
                'service',
                '',
                $this->firmware('svcfw|' . $id)
            );
        }

        // Anomaly budget: 0-2 endpoints read degraded/down; the rest up.
        $rows = $this->applyAnomalies($rows);

        $index = [];
        foreach ($rows as $k => $r) {
            $index[$r['id']] = $k;
        }
        $this->cache = $rows;
        $this->index = $index;
        return $rows;
    }

    /** Assemble one endpoint row with its seeded per-endpoint facts (status default up). */
    private function baseRow(string $id, string $name, string $proto, string $host, int $port, string $transport, string $category, string $role, string $linkedController, string $firmware): array
    {
        $salt = $id;
        return [
            'id' => $id,
            'name' => $name,
            'protocol' => $proto,
            'protocolSlug' => $this->protoSlug($proto),
            'host' => $host,
            'port' => $port,
            'transport' => $transport,
            'endpoint' => $host . ':' . $port . '/' . $transport,
            'category' => $category,
            'role' => $role,
            'linkedController' => $linkedController,
            'firmware' => $firmware,
            'authMode' => $this->authModeFor($proto, $salt),
            'credential' => $this->credentialFor($proto, $salt),
            'status' => 'up',
            'lastSeen' => $this->ageAgo($this->intIn(3, 1200, 'seen|' . $salt)),   // fresh when up
            'latencyMs' => $this->intIn(1, 40, 'lat|' . $salt),
            'tls' => in_array($proto, ['REST API', 'ONVIF'], true) ? ($this->h('tls|' . $salt) % 100) >= 15 : false,
        ];
    }

    /** Auth mode vocab per protocol (realistic, never a live scheme). */
    private function authModeFor(string $proto, string $salt): string
    {
        switch ($proto) {
            case 'SNMP':
                return $this->pick(['SNMP v2c (community)', 'SNMP v3 (authPriv)'], 'auth|' . $salt);
            case 'MQTT':
                return $this->pick(['username / password', 'client certificate', 'username / password'], 'auth|' . $salt);
            case 'REST API':
                return $this->pick(['API key', 'OAuth2 client credentials', 'API key'], 'auth|' . $salt);
            case 'BACnet/IP':
            case 'Modbus TCP':
                return 'none (network-segmented)';
            case 'OSDP':
                return 'secure channel (SCBK)';
            case 'RADIUS':
            case 'TACACS+':
                return 'shared secret';
            default:
                return 'none';
        }
    }

    /** Credential-shaped bait per protocol — masked, fabricated, non-validating; '' when auth is none. */
    private function credentialFor(string $proto, string $salt): string
    {
        switch ($proto) {
            case 'SNMP':
                return $this->communityMasked($salt);
            case 'MQTT':
                return $this->svcUser($salt) . ' / ••••••';
            case 'REST API':
                return $this->apiKeyMasked($salt);
            case 'RADIUS':
            case 'TACACS+':
                return 'secret ••••' . substr($this->hex(3, 'sec|' . $salt), 0, 3);
            default:
                return '';
        }
    }

    /** Plant 0-2 degraded/down endpoints; the rest stay up. Down rows get a longer last-seen. */
    private function applyAnomalies(array $rows): array
    {
        $n = count($rows);
        if ($n === 0) {
            return $rows;
        }
        $count = $this->h('anomcount') % 3;                    // 0, 1 or 2
        for ($a = 1; $a <= $count; $a++) {
            $idx = $this->h('anomidx|' . $a) % $n;
            $state = $this->pick(['degraded', 'down'], 'anomstate|' . $a);
            $rows[$idx]['status'] = $state;
            if ($state === 'down') {
                $rows[$idx]['lastSeen'] = $this->ageAgo($this->intIn(7200, 604800, 'anomseen|' . $a)); // 2 h .. 7 d
                $rows[$idx]['latencyMs'] = -1;                 // no response
            } else {
                $rows[$idx]['latencyMs'] = $this->intIn(200, 900, 'anomlat|' . $a);
            }
        }
        return $rows;
    }

    /** One page of the registry by absolute offset. */
    public function endpointsPage(int $offset, int $limit): array
    {
        $all = $this->endpoints();
        if ($offset < 0) {
            $offset = 0;
        }
        return array_slice($all, $offset, $limit);
    }

    public function endpointCount(): int
    {
        return count($this->endpoints());
    }

    /**
     * One endpoint by id. A known id returns its exact row; an unknown/fuzzed slug returns a plausible
     * seeded endpoint (keyed by the slug) so a crawl never dead-ends.
     */
    public function endpoint(string $id): array
    {
        $this->endpoints();
        if ($this->index !== null && isset($this->index[$id])) {
            return $this->cache[$this->index[$id]];
        }
        // Synthetic endpoint from a fuzzed slug: a REST API on the service space keyed by the slug.
        return $this->baseRow(
            $id,
            $id,
            'REST API',
            '10.0.10.' . (20 + $this->h('synip|' . $id) % 200),
            (int) $this->pick(['443', '8080'], 'synport|' . $id),
            'tcp',
            'API',
            'api',
            '',
            $this->firmware('synfw|' . $id)
        );
    }

    // --- registry-wide summary ---

    /**
     * @return array{total:int,up:int,degraded:int,down:int,byProtocol:array<string,int>}
     */
    public function summary(): array
    {
        $up = 0;
        $deg = 0;
        $down = 0;
        $byProto = [];
        foreach ($this->endpoints() as $e) {
            if ($e['status'] === 'up') {
                $up++;
            } elseif ($e['status'] === 'degraded') {
                $deg++;
            } else {
                $down++;
            }
            $p = $e['protocol'];
            $byProto[$p] = ($byProto[$p] ?? 0) + 1;
        }
        return [
            'total' => $this->endpointCount(),
            'up' => $up,
            'degraded' => $deg,
            'down' => $down,
            'byProtocol' => $byProto,
        ];
    }

    /** Distinct protocols present, in first-seen order (for filter chips). @return list<string> */
    public function protocols(): array
    {
        $seen = [];
        $out = [];
        foreach ($this->endpoints() as $e) {
            if (!isset($seen[$e['protocol']])) {
                $seen[$e['protocol']] = true;
                $out[] = $e['protocol'];
            }
        }
        return $out;
    }

    /** Slug for a protocol label, matching PanelRoute's slug rule so a chip href round-trips. */
    public function protoSlug(string $proto): string
    {
        return trim((string) preg_replace('/[^a-z0-9]+/', '-', strtolower($proto)), '-');
    }
}
