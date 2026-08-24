<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT asset inventory / CMDB for the deep office panel — the IT estate an attacker
 * mines to map endpoints, owners and stale, unpatched boxes (spec §C.7). Sits on the two coherence
 * spines: Org (every personal device is assigned to a real roster member, at that member's own email
 * domain) and Building (every asset is located in a real room on a real floor+zone). Counts scale off
 * the one Org headcount (magnitudes()['assets']) so a 200-person company never shows 50,000 laptops.
 *
 * Design rules (deep-admin dashboard spec §C.7 + §C.0 + adversarial critique):
 *  - DETERMINISTIC per seed: every field is hash(seed+id+field) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); an asset's facts derive from its id alone, so asset($id) is
 *    byte-identical to that asset's row in assets() and reproducible standalone. Ages/dates are offsets
 *    off FrozenClock::EPOCH, never time().
 *  - COHERENT: assignee is a real Org person (id + name + email at the one host domain); location is a
 *    real Building room (id + name + floor + zone); servers sit in a Server-Comms room and stay
 *    unassigned (owned by the IT function, not a person).
 *  - SAFE: every last-IP is RFC1918 (endpoints 10.0.20-21.x / voice 10.0.30.x / servers 10.0.10.x);
 *    serials, MACs (locally-administered 02: prefix — never a real vendor OUI), hostnames and models are
 *    fabricated; no real trademark, no scanner-signature string. Nothing here transacts or changes state.
 *  - ANOMALY BUDGET: a small, budgeted minority read as bait (unencrypted / large patch-gap / out of
 *    warranty); most render clean — a buffet of red flags reads as staged.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/intdiv, no enums/named-args/str_contains/promotion) so a
 *    fact can promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders, masks and escapes it.
 */
final class Cmdb
{
    /** @var int */
    private $seed;

    /** @var string the host persona domain the assignee email renders at (one host = one domain). */
    private $personaDomain;

    /** @var Org */
    private $org;

    /** @var Building */
    private $bld;

    /** @var Network|null network estate, built lazily — the source of truth for wired switch refs. */
    private $net = null;

    /** @var list<array<string,mixed>>|null memoised asset estate (built once per instance) */
    private $cache = null;

    /** @var array<string,int>|null id -> estate index, built alongside the estate */
    private $index = null;

    /** @var list<array{id:string,name:string,floor:string,floorLabel:string,zone:string,type:string}>|null */
    private $roomsCache = null;

    /** @var list<array<string,mixed>>|null the full Org roster, built once (its dedup is O(n^2)). */
    private $peopleCache = null;

    private function __construct(int $seed, string $personaDomain)
    {
        $this->seed = $seed;
        $this->personaDomain = $personaDomain;
        $this->org = Org::fromSeed($seed, $personaDomain);
        $this->bld = Building::fromSeed($seed);
    }

    /**
     * Build the CMDB for a seed. The section MUST pass the host persona domain so the assignee emails never
     * contradict the one domain shown elsewhere on the host.
     */
    public static function fromSeed(int $seed, string $personaDomain = ''): self
    {
        return new self($seed, $personaDomain);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|cmdb|' . $salt), 0, 15));
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
        return substr(hash('sha256', $this->seed . '|cmdbhex|' . $salt), 0, $len);
    }

    private function firmware(string $salt): string
    {
        return 'v' . $this->intIn(1, 6, $salt . '|fa')
            . '.' . $this->intIn(0, 20, $salt . '|fb')
            . '.' . $this->intIn(0, 40, $salt . '|fc');
    }

    /** Seeded "N ago" string — pure hash(seed+slot), deterministic, never time()/date(). */
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

    /** Short host prefix derived from the persona domain stem (fabricated, upper-case, [A-Z]). */
    private function hostPrefix(): string
    {
        $stem = strtoupper((string) preg_replace('/[^a-z]/', '', strtolower($this->org->domain())));
        $stem = substr($stem, 0, 3);
        return $stem !== '' ? $stem : 'COR';
    }

    // --- asset-type catalog (the field wall's shape per class) ---

    /**
     * The asset classes surfaced here. `prefix` seeds the id/tag; `vlan` picks the last-IP VLAN; `wired`
     * decides whether a switch-port is shown; `personal` decides whether it gets a roster assignee.
     *
     * @return array<string,array{label:string,prefix:string,vlan:string,wired:bool,personal:bool,weight:int}>
     */
    private function catalog(): array
    {
        return [
            'laptop'  => ['label' => 'Laptop',   'prefix' => 'LT', 'vlan' => 'emp',    'wired' => true,  'personal' => true,  'weight' => 40],
            'monitor' => ['label' => 'Monitor',  'prefix' => 'MN', 'vlan' => 'none',   'wired' => false, 'personal' => true,  'weight' => 22],
            'phone'   => ['label' => 'Phone',    'prefix' => 'PH', 'vlan' => 'voice',  'wired' => false, 'personal' => true,  'weight' => 14],
            'desktop' => ['label' => 'Desktop',  'prefix' => 'DT', 'vlan' => 'emp',    'wired' => true,  'personal' => true,  'weight' => 10],
            'tablet'  => ['label' => 'Tablet',   'prefix' => 'TB', 'vlan' => 'emp',    'wired' => false, 'personal' => true,  'weight' => 8],
            'server'  => ['label' => 'Server',   'prefix' => 'SV', 'vlan' => 'server', 'wired' => true,  'personal' => false, 'weight' => 6],
        ];
    }

    /** Weighted type buckets expanded to a flat pick table (index -> type slug). @return list<string> */
    private function typeBuckets(): array
    {
        $out = [];
        foreach ($this->catalog() as $slug => $c) {
            for ($k = 0; $k < $c['weight']; $k++) {
                $out[] = $slug;
            }
        }
        return $out;
    }

    /** Invented (never-real-trademark) model string per asset type. */
    private function model(string $type, string $salt): string
    {
        $vendor = $this->pick(
            ['Vantage', 'Meridian', 'Northwind', 'Ironclad', 'Beacon', 'Sterling', 'Aureus', 'Halcyon'],
            'vendor|' . $salt
        );
        switch ($type) {
            case 'server':
                return $vendor . ' ' . $this->pick(['RackServer 2U', 'PowerNode 1U', 'EdgeServer 1U', 'DataNode 2U'], 'srvline|' . $salt);
            case 'phone':
                return $vendor . ' ' . $this->pick(['Handset', 'Phone', 'Mobile'], 'phline|' . $salt) . ' ' . $this->intIn(8, 14, 'phgen|' . $salt);
            case 'monitor':
                return $vendor . ' Display ' . $this->pick(['24', '27', '32', '34'], 'mnsize|' . $salt) . '"';
            case 'tablet':
                return $vendor . ' Tab ' . $this->intIn(9, 13, 'tbgen|' . $salt);
            case 'desktop':
                return $vendor . ' ' . $this->pick(['Tower', 'MiniPC', 'WorkDesk', 'Compact'], 'dtline|' . $salt);
            default:
                return $vendor . ' ' . $this->pick(['UltraBook', 'ProBook', 'CoreBook', 'FlexBook'], 'ltline|' . $salt)
                    . ' ' . $this->pick(['13', '14', '15', '16'], 'ltsize|' . $salt);
        }
    }

    /** Generic platform string per type (factual environment data, not a logo/markup). */
    private function os(string $type, string $salt): string
    {
        switch ($type) {
            case 'server':
                return $this->pick(['Ubuntu Server 22.04 LTS', 'Debian 12', 'Windows Server 2022', 'Rocky Linux 9'], 'os|' . $salt);
            case 'phone':
                return $this->pick(['iOS 17', 'iOS 16', 'Android 14', 'Android 13'], 'os|' . $salt);
            case 'tablet':
                return $this->pick(['iPadOS 17', 'Android 14', 'iPadOS 16'], 'os|' . $salt);
            case 'monitor':
                return '—';
            default:
                return $this->pick(['Windows 11 Pro 23H2', 'Windows 10 Pro 22H2', 'Ubuntu 22.04 LTS', 'macOS 14 Sonoma'], 'os|' . $salt);
        }
    }

    /** Last-IP on the right RFC1918 VLAN for the type, or '—' for an unnetworked monitor. */
    private function lastIp(string $vlan, string $salt): string
    {
        if ($vlan === 'none') {
            return '—';
        }
        if ($vlan === 'server') {
            return '10.0.10.' . $this->intIn(10, 240, 'ip|' . $salt);
        }
        if ($vlan === 'voice') {
            return '10.0.30.' . $this->intIn(10, 240, 'ip|' . $salt);
        }
        // Employee VLAN spreads onto 10.0.20.0/23 so a big fleet still lands on the employee space.
        $third = 20 + ($this->h('ipthird|' . $salt) % 2);
        return '10.0.' . $third . '.' . $this->intIn(2, 240, 'ip|' . $salt);
    }

    /** Locally-administered MAC (02: prefix — never a real vendor OUI, so it resolves to nothing). */
    private function mac(string $salt): string
    {
        $h = $this->hex(10, 'mac|' . $salt);
        return '02:' . substr($h, 0, 2) . ':' . substr($h, 2, 2) . ':' . substr($h, 4, 2)
            . ':' . substr($h, 6, 2) . ':' . substr($h, 8, 2);
    }

    // --- magnitude + rooms (both from the shared spines) ---

    /** Asset total, from the one Org ratio table so it reconciles with HR / MDM (~headcount * 1.3). */
    public function assetCount(): int
    {
        return $this->org->magnitudes()['assets'];
    }

    /** The whole building's rooms, flattened once, in building order. */
    private function rooms(): array
    {
        if ($this->roomsCache !== null) {
            return $this->roomsCache;
        }
        $out = [];
        foreach ($this->bld->floors() as $f) {
            foreach ($this->bld->roomsFor($f['code']) as $r) {
                $out[] = [
                    'id' => $r['id'],
                    'name' => $r['name'],
                    'floor' => $r['floor'],
                    'floorLabel' => $f['label'],
                    'zone' => $r['zone'],
                    'type' => $r['type'],
                ];
            }
        }
        if ($out === []) {
            // Defensive: a building always has rooms, but never divide by zero downstream.
            $out[] = ['id' => 'room-g-01', 'name' => 'Ground 1', 'floor' => 'G', 'floorLabel' => 'Ground', 'zone' => 'Core', 'type' => 'Open-plan'];
        }
        $this->roomsCache = $out;
        return $out;
    }

    /** Server-Comms rooms only (where servers live), falling back to every room if a seed has none. */
    private function serverRooms(): array
    {
        $out = [];
        foreach ($this->rooms() as $r) {
            if ($r['type'] === 'Server-Comms') {
                $out[] = $r;
            }
        }
        return $out === [] ? $this->rooms() : $out;
    }

    // --- estate (paginated) ---

    /**
     * The full asset estate, memoised. Index i's type comes from a weighted bucket; a per-type sequence
     * number makes the id/tag human-readable and unique, and the record cross-references Org + Building.
     *
     * @return list<array<string,mixed>>
     */
    public function assets(): array
    {
        if ($this->cache !== null) {
            return $this->cache;
        }
        $total = $this->assetCount();
        $buckets = $this->typeBuckets();
        $rooms = $this->rooms();
        $serverRooms = $this->serverRooms();
        $headcount = $this->org->headcount();

        $seq = [];
        $out = [];
        $index = [];
        for ($i = 0; $i < $total; $i++) {
            $type = $buckets[$this->h('type|' . $i) % count($buckets)];
            $cat = $this->catalog()[$type];
            $prefix = $cat['prefix'];
            if (!isset($seq[$prefix])) {
                $seq[$prefix] = 0;
            }
            $seq[$prefix]++;
            $tag = $prefix . '-' . sprintf('%05d', $seq[$prefix]);
            $id = strtolower($prefix) . '-' . sprintf('%05d', $seq[$prefix]);

            $out[] = $this->recordFor($id, $tag, $type, $i, $rooms, $serverRooms, $headcount);
            $index[$id] = $i;
        }
        $this->cache = $out;
        $this->index = $index;
        return $out;
    }

    /** One page of the estate by absolute offset, so a deep page renders identically and instantly. */
    public function assetsPage(int $offset, int $limit): array
    {
        $all = $this->assets();
        if ($offset < 0) {
            $offset = 0;
        }
        return array_slice($all, $offset, $limit);
    }

    /**
     * One asset by id. A known id returns its exact estate row; an unknown/fuzzed slug returns a plausible
     * seeded asset (keyed by the slug) so a crawl never dead-ends (a 404 inside the panel is a tell).
     */
    public function asset(string $id): array
    {
        $this->assets();
        if ($this->index !== null && isset($this->index[$id])) {
            return $this->cache[$this->index[$id]];
        }
        // Synthetic asset from a fuzzed slug: derive a stable type + pseudo-index from the slug itself.
        $type = $this->typeForSlug($id);
        $pseudo = $this->h('synidx|' . $id) % 100000;
        $rec = $this->recordFor($id, strtoupper($id), $type, $pseudo, $this->rooms(), $this->serverRooms(), $this->org->headcount());
        return $rec;
    }

    /** Recover the type from a slug prefix (lt-/dt-/sv-/ph-/mn-/tb-), defaulting to laptop. */
    private function typeForSlug(string $id): string
    {
        foreach ($this->catalog() as $slug => $c) {
            if (strpos($id, strtolower($c['prefix']) . '-') === 0) {
                return $slug;
            }
        }
        return 'laptop';
    }

    /** Build a full asset record from its id/tag/type/index. Pure per (seed, id). */
    private function recordFor(string $id, string $tag, string $type, int $i, array $rooms, array $serverRooms, int $headcount): array
    {
        $cat = $this->catalog()[$type];
        $salt = $id;

        // Assignee: personal devices belong to a real roster member; servers stay unassigned (IT-owned).
        if ($cat['personal'] && $headcount > 0) {
            if ($this->peopleCache === null) {
                $this->peopleCache = $this->org->people($headcount);
            }
            $person = $this->peopleCache[$this->h('assignee|' . $salt) % $headcount];
            $assigneeId = $person['id'];
            $assigneeName = $person['name'];
            $assigneeEmail = $person['email'];
            $assigneeDept = $person['dept'];
        } else {
            $assigneeId = '';
            $assigneeName = 'Unassigned (IT-managed)';
            $assigneeEmail = '';
            $assigneeDept = 'IT';
        }

        // Location: servers sit in a Server-Comms room; everything else in any room.
        $pool = $type === 'server' ? $serverRooms : $rooms;
        $room = $pool[$this->h('room|' . $salt) % count($pool)];

        // Dates: purchased 1 month .. ~5 years ago; warranty runs 12/24/36 months from purchase.
        $ageDays = $this->intIn(30, 1800, 'purchase|' . $salt);
        $purchaseEpoch = FrozenClock::EPOCH - $ageDays * 86400;
        $warrantyMonths = (int) $this->pick(['12', '24', '36'], 'wmon|' . $salt);
        $warrantyEndEpoch = $purchaseEpoch + $warrantyMonths * 30 * 86400;
        $daysToExpiry = intdiv($warrantyEndEpoch, 86400) - FrozenClock::nowDays();
        if ($daysToExpiry < 0) {
            $warrantyStatus = 'Expired';
        } elseif ($daysToExpiry <= 60) {
            $warrantyStatus = 'Expiring';
        } else {
            $warrantyStatus = 'In warranty';
        }

        // Last check-in: 3 s .. 45 d ago; the "state" reads from that age (stale = a pivot bait).
        $checkinSec = $this->intIn(3, 3888000, 'checkin|' . $salt);
        $checkinEpoch = FrozenClock::EPOCH - $checkinSec;
        $state = $checkinSec > 1209600 ? 'stale' : 'active';    // >14 d without a check-in = stale

        // Encryption + patch-gap bait, both on a budget so most assets read clean.
        $encrypted = $type === 'monitor' ? true : ($this->h('enc|' . $salt) % 100) >= 8;   // ~8% unencrypted
        $patchGap = $this->patchGapDays($type, $salt);
        $mdmEnrolled = $type === 'monitor' ? false : ($this->h('mdm|' . $salt) % 100) >= 6; // ~6% not enrolled

        $vlanIp = $this->lastIp($cat['vlan'], $salt);
        // The cabling map points at a switch that actually exists in the Network estate for this floor, so
        // "maps to the access switch in Network Devices" always resolves (never a phantom suffix).
        $switchPort = $cat['wired']
            ? $this->accessSwitchFor($room, $salt)
                . ' Gi1/0/' . (1 + ($this->h('port|' . $salt) % 48))
            : '—';

        return [
            'id' => $id,
            'tag' => $tag,
            'type' => $type,
            'typeLabel' => $cat['label'],
            'serial' => strtoupper(substr($this->hex(3, 'sn1|' . $salt), 0, 3)) . sprintf('%07d', $this->intIn(0, 9999999, 'sn2|' . $salt)),
            'model' => $this->model($type, $salt),
            'os' => $this->os($type, $salt),
            'hostname' => $type === 'monitor' ? '—' : $this->hostPrefix() . '-' . $tag,
            'mac' => $type === 'monitor' ? '—' : $this->mac($salt),
            'lastIp' => $vlanIp,
            'switchPort' => $switchPort,
            'assigneeId' => $assigneeId,
            'assigneeName' => $assigneeName,
            'assigneeEmail' => $assigneeEmail,
            'assigneeDept' => $assigneeDept,
            'roomId' => $room['id'],
            'roomName' => $room['name'],
            'floor' => $room['floor'],
            'floorLabel' => $room['floorLabel'],
            'zone' => $room['zone'],
            'firmware' => $this->firmware('fw|' . $salt),
            'purchaseDate' => FrozenClock::ymd($purchaseEpoch),
            'warrantyEnd' => FrozenClock::ymd($warrantyEndEpoch),
            'warrantyStatus' => $warrantyStatus,
            'daysToExpiry' => $daysToExpiry,
            'lastCheckin' => $this->ageAgo($checkinSec),
            'lastCheckinEpoch' => $checkinEpoch,
            'state' => $state,
            'encrypted' => $encrypted,
            'patchGapDays' => $patchGap,
            'mdmEnrolled' => $mdmEnrolled,
        ];
    }

    /** The Network estate, built lazily and memoised (its cabling refs must resolve against this). */
    private function net(): Network
    {
        if ($this->net === null) {
            $this->net = Network::fromSeed($this->seed, $this->personaDomain);
        }
        return $this->net;
    }

    /**
     * Pick a real access switch for a wired asset's room: prefer one on the asset's own floor, fall back
     * to any access switch in the estate, and finally to the core switch — so a referenced switch always
     * exists in Network Devices.
     */
    private function accessSwitchFor(array $room, string $salt): string
    {
        $switches = $this->net()->accessSwitchIdsForFloor((string) $room['floor']);
        if ($switches === []) {
            $switches = $this->net()->accessSwitchIds();
        }
        if ($switches === []) {
            return 'sw-core-01';
        }
        return $switches[$this->h('sw|' . $salt) % count($switches)];
    }

    /** Patch-gap in days: most current, a budgeted minority far behind (the stale-box bait). */
    private function patchGapDays(string $type, string $salt): int
    {
        if ($type === 'monitor') {
            return 0;
        }
        $roll = $this->h('patchroll|' . $salt) % 100;
        if ($roll < 70) {
            return $this->intIn(0, 7, 'patch|' . $salt);      // patched within the week
        }
        if ($roll < 92) {
            return $this->intIn(8, 45, 'patch|' . $salt);     // a month or so behind
        }
        return $this->intIn(90, 420, 'patch|' . $salt);       // badly behind — the bait
    }

    // --- estate-wide summary (aggregated, so tiles reconcile to a full walk of the list) ---

    /**
     * @return array{total:int,byType:array<string,int>,unencrypted:int,staleCheckin:int,outOfWarranty:int,patchBehind:int,notEnrolled:int}
     */
    public function summary(): array
    {
        $byType = [];
        foreach (array_keys($this->catalog()) as $t) {
            $byType[$t] = 0;
        }
        $unencrypted = 0;
        $stale = 0;
        $oow = 0;
        $behind = 0;
        $notEnrolled = 0;
        foreach ($this->assets() as $a) {
            $byType[$a['type']]++;
            if (!$a['encrypted']) {
                $unencrypted++;
            }
            if ($a['state'] === 'stale') {
                $stale++;
            }
            if ($a['warrantyStatus'] === 'Expired') {
                $oow++;
            }
            if ($a['patchGapDays'] > 30) {
                $behind++;
            }
            if (!$a['mdmEnrolled']) {
                $notEnrolled++;
            }
        }
        return [
            'total' => $this->assetCount(),
            'byType' => $byType,
            'unencrypted' => $unencrypted,
            'staleCheckin' => $stale,
            'outOfWarranty' => $oow,
            'patchBehind' => $behind,
            'notEnrolled' => $notEnrolled,
        ];
    }

    /** Human label for a type slug (for filter chips / headings). */
    public function typeLabel(string $type): string
    {
        $cat = $this->catalog();
        return isset($cat[$type]) ? $cat[$type]['label'] : ucfirst($type);
    }

    /** The type slugs in reading order (for filter chips). @return list<string> */
    public function types(): array
    {
        return array_keys($this->catalog());
    }
}
