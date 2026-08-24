<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT global activity timeline for the deep office panel — the one reverse-chronological
 * feed that stitches every module's events into a single stream: sign-ins, config changes, door/badge
 * events, work orders, pending approvals, payroll runs, certificate expiries and fire/sensor alarms.
 *
 * It is a VIEW over the existing coherence spines, never a new fabric: every event names a real `Org`
 * person as its actor and (where the domain has one) a real `Building` room / `Access` door as its
 * subject, and carries a relative deep link back into the module that owns it. So an attacker who follows
 * a feed row lands on the same door / employee / meter it names, and the counts and people never contradict
 * what the other modules show.
 *
 * Design rules (deep-admin dashboard spec §B / §C.0 + adversarial critique):
 *  - DETERMINISTIC per seed: every value is hash(seed+slot) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); all clock strings come from one frozen FrozenClock::EPOCH by integer
 *    arithmetic, so a static reload is byte-identical and never a tell.
 *  - MONOTONIC: event i sits at EPOCH - i*STEP - jitter with jitter in [0, STEP-1], so timestamps are
 *    strictly descending in i by construction (and any type-filtered subsequence stays strictly descending).
 *  - COHERENT: actors are the Org roster; subjects are Building rooms / Access doors; magnitudes derive
 *    from one seeded total via a fixed per-type weight table, so a filter's page count is honest.
 *  - SAFE: source addresses are RFC1918 (employee VLAN 10.0.20.x) or documentation TEST-NET
 *    (198.51.100.0/24, 203.0.113.0/24) only; people are fabricated; ids are invented, never a signature.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf, no enums/promotion/str_contains) so a fact can promote
 *    into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders, links and escapes it.
 */
final class Activity
{
    /** Frozen "now" every event ages from — shared with Building/Org/Access so the clocks agree. */
    public const DEPLOY_EPOCH = FrozenClock::EPOCH;

    /** Nominal seconds between adjacent events; the per-event jitter stays inside [0, STEP-1] so the
     *  gap between two events is always at least 1 s (strictly monotonic) and at most 2*STEP-1. */
    private const STEP = 47;

    /**
     * Per-type share of the stream (sums to 100). Sign-ins and door events dominate a real building's
     * log; payroll/cert/alarm are rare. A filter's total is total() * weight / 100, so a claimed page
     * of a filtered view is always reachable.
     */
    private const WEIGHTS = [
        'signin' => 34,
        'door' => 26,
        'config' => 14,
        'workorder' => 8,
        'approval' => 7,
        'alarm' => 5,
        'cert' => 3,
        'payroll' => 3,
    ];

    /** @var int */
    private $seed;

    /** @var string persona domain (for certificate common names); '' -> a seeded fallback. */
    private $domain;

    /** @var Org */
    private $org;

    /** @var Building */
    private $building;

    /** @var Access */
    private $access;

    /** @var array<int,array>|null cached roster so deep feed pages stay cheap */
    private $rosterCache = null;

    /** @var list<array>|null cached flat room list */
    private $roomsCache = null;

    /** @var list<array>|null cached door list */
    private $doorsCache = null;

    private function __construct(int $seed, string $domain)
    {
        $this->seed = $seed;
        $this->domain = $domain;
        $this->org = Org::fromSeed($seed, $domain);
        $this->building = Building::fromSeed($seed);
        $this->access = Access::fromSeed($seed);
    }

    public static function fromSeed(int $seed, string $domain = ''): self
    {
        return new self($seed, $domain);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|act|' . $salt), 0, 15));
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

    /** Lowercase slug of an id/label so a composed deep link can only ever be another sibling path. */
    private function slug(string $s): string
    {
        return trim((string) preg_replace('/[^a-z0-9]+/', '-', strtolower($s)), '-');
    }

    // --- public shape: types, totals, feed ---

    /** The type slugs in display order (also the valid filter tokens). @return list<string> */
    public function typeSlugs(): array
    {
        return array_keys(self::WEIGHTS);
    }

    /** Human label for a type slug (falls back to the slug itself for an unknown token). */
    public function typeLabel(string $slug): string
    {
        $map = [
            'signin' => 'Sign-in',
            'door' => 'Access',
            'config' => 'Config change',
            'workorder' => 'Work order',
            'approval' => 'Approval',
            'alarm' => 'Alarm',
            'cert' => 'Certificate',
            'payroll' => 'Payroll',
        ];
        return isset($map[$slug]) ? $map[$slug] : ucfirst($slug);
    }

    /** The whole-stream event count — a big seeded constant, stable per deploy. */
    public function total(): int
    {
        return $this->intIn(6000, 15000, 'total');
    }

    /** Total events for a filter ('' -> the whole stream), derived from the fixed weight table so a
     *  filtered pager never claims an unreachable page. */
    public function count(string $filter): int
    {
        if ($filter === '' || !isset(self::WEIGHTS[$filter])) {
            return $this->total();
        }
        $n = (int) round($this->total() * self::WEIGHTS[$filter] / 100);
        return $n < 1 ? 1 : $n;
    }

    /** Per-type counts for the filter bar. @return list<array{slug:string,label:string,count:int}> */
    public function typeCounts(): array
    {
        $out = [];
        foreach ($this->typeSlugs() as $slug) {
            $out[] = ['slug' => $slug, 'label' => $this->typeLabel($slug), 'count' => $this->count($slug)];
        }
        return $out;
    }

    /**
     * One page of the feed, newest first. For the unfiltered stream a page maps straight to the master
     * window [offset, offset+limit); for a type filter the master stream is scanned from the newest event
     * collecting matches, so the page is deterministic and its timestamps stay strictly descending.
     *
     * @return array{events:list<array>,page:int,totalPages:int,total:int,from:int,to:int}
     */
    public function feed(int $page, int $limit, string $filter): array
    {
        if ($limit < 1) {
            $limit = 1;
        }
        if ($filter !== '' && !isset(self::WEIGHTS[$filter])) {
            $filter = '';
        }
        $total = $this->count($filter);
        $totalPages = (int) ceil($total / $limit);
        if ($totalPages < 1) {
            $totalPages = 1;
        }
        if ($page < 1) {
            $page = 1;
        }
        if ($page > $totalPages) {
            $page = $totalPages;
        }
        $offset = ($page - 1) * $limit;

        $events = $filter === ''
            ? $this->window($offset, $limit)
            : $this->filteredWindow($filter, $offset, $limit);

        $from = $events === [] ? 0 : $offset + 1;
        $to = $offset + count($events);
        return [
            'events' => $events,
            'page' => $page,
            'totalPages' => $totalPages,
            'total' => $total,
            'from' => $from,
            'to' => $to,
        ];
    }

    /** The unfiltered window [offset, offset+limit) of the master stream. @return list<array> */
    private function window(int $offset, int $limit): array
    {
        $total = $this->total();
        $out = [];
        for ($k = 0; $k < $limit; $k++) {
            $i = $offset + $k;
            if ($i >= $total) {
                break;
            }
            $out[] = $this->eventAt($i);
        }
        return $out;
    }

    /**
     * The window [offset, offset+limit) of the subsequence of master events whose type is $filter. The
     * master stream is walked from the newest event; the scan is bounded by the master total, so a deep
     * filtered page costs at most one pass and never loops unbounded.
     *
     * @return list<array>
     */
    private function filteredWindow(string $filter, int $offset, int $limit): array
    {
        $masterTotal = $this->total();
        $matched = 0;
        $out = [];
        for ($i = 0; $i < $masterTotal && count($out) < $limit; $i++) {
            if ($this->typeAt($i) !== $filter) {
                continue;
            }
            if ($matched >= $offset) {
                $out[] = $this->eventAt($i);
            }
            $matched++;
        }
        return $out;
    }

    // --- master stream ---

    /** The frozen epoch of master event $i: strictly descending in $i (gap always >= 1 s). */
    private function epochAt(int $i): int
    {
        $jitter = $this->h('jit|' . $i) % self::STEP;   // [0, STEP-1]
        return self::DEPLOY_EPOCH - ($i * self::STEP) - $jitter;
    }

    /** The type of master event $i, drawn from the fixed weight table. */
    private function typeAt(int $i): string
    {
        $roll = $this->h('type|' . $i) % 100;
        $acc = 0;
        foreach (self::WEIGHTS as $slug => $w) {
            $acc += $w;
            if ($roll < $acc) {
                return $slug;
            }
        }
        return 'signin';
    }

    /**
     * One fully-resolved feed event. Common fields (time, actor) are shared; the per-type builder supplies
     * the subject, severity, summary sentence and the relative deep link back into the owning module.
     *
     * @return array{i:int,epoch:int,datetime:string,ago:string,type:string,typeLabel:string,severity:string,actorId:string,actor:string,summary:string,entityKind:string,entityId:string,link:string}
     */
    public function eventAt(int $i): array
    {
        $epoch = $this->epochAt($i);
        $type = $this->typeAt($i);
        $person = $this->personAt($this->h('who|' . $i) % $this->headcount());

        switch ($type) {
            case 'door':
                $d = $this->buildDoor($i, $person);
                break;
            case 'config':
                $d = $this->buildConfig($i, $person);
                break;
            case 'workorder':
                $d = $this->buildWorkorder($i, $person);
                break;
            case 'approval':
                $d = $this->buildApproval($i, $person);
                break;
            case 'alarm':
                $d = $this->buildAlarm($i, $person);
                break;
            case 'cert':
                $d = $this->buildCert($i, $person);
                break;
            case 'payroll':
                $d = $this->buildPayroll($i, $person);
                break;
            default:
                $d = $this->buildSignin($i, $person);
        }

        return [
            'i' => $i,
            'epoch' => $epoch,
            'datetime' => FrozenClock::ymd($epoch) . ' ' . FrozenClock::clock($epoch),
            'ago' => $this->ago(self::DEPLOY_EPOCH - $epoch),
            'type' => $type,
            'typeLabel' => $this->typeLabel($type),
            'severity' => $d['severity'],
            'actorId' => $person['id'],
            'actor' => $person['name'],
            'summary' => $d['summary'],
            'entityKind' => $d['entityKind'],
            'entityId' => $d['entityId'],
            'link' => $d['link'],
        ];
    }

    // --- per-type builders (each returns severity/summary/entityKind/entityId/link) ---

    /** Sign-in / failed sign-in — the commonest row; links to the actor's HR profile. */
    private function buildSignin(int $i, array $person): array
    {
        $failed = ($this->h('sfail|' . $i) % 100) < 12;
        if ($failed) {
            $ip = $this->externalIp('sip|' . $i);
            $summary = 'Failed sign-in for ' . $person['name'] . ' from ' . $ip . ' — invalid credentials';
            $severity = 'warn';
        } else {
            $ip = $person['ip'];
            $summary = $person['name'] . ' signed in to OneControl from ' . $ip;
            $severity = 'ok';
        }
        return [
            'severity' => $severity,
            'summary' => $summary,
            'entityKind' => 'user',
            'entityId' => $person['id'],
            'link' => '/hr/employees/' . $this->slug($person['id']),
        ];
    }

    /** Badge / door event — links to the real Access door it names. */
    private function buildDoor(int $i, array $person): array
    {
        $door = $this->doorAt($this->h('door|' . $i) % $this->doorCount());
        $roll = $this->h('dres|' . $i) % 100;
        if ($roll < 14) {
            $result = 'DENIED';
            $reason = $this->pick(['schedule', 'access-level', 'anti-passback', 'expired badge'], 'dwhy|' . $i);
            $summary = 'Badge DENIED (' . $reason . ') for ' . $person['name'] . ' at ' . $door['name'];
            $severity = 'warn';
        } else {
            $result = 'GRANTED';
            $summary = 'Badge GRANTED for ' . $person['name'] . ' at ' . $door['name'];
            $severity = 'ok';
        }
        return [
            'severity' => $severity,
            'summary' => $summary,
            'entityKind' => 'door',
            'entityId' => $door['id'],
            'link' => '/access/' . $this->slug($door['id']),
        ];
    }

    /** Config change on a building module — links to that module, names a real room/zone. */
    private function buildConfig(int $i, array $person): array
    {
        $room = $this->roomAt($this->h('croom|' . $i) % $this->roomCount());
        $module = $this->pick(['hvac', 'lighting', 'shades', 'appliances', 'energy'], 'cmod|' . $i);
        switch ($module) {
            case 'hvac':
                $val = number_format($this->intIn(180, 250, 'cset|' . $i) / 10, 1);
                $summary = $person['name'] . ' set HVAC zone ' . $room['name'] . ' to ' . $val . ' °C';
                break;
            case 'lighting':
                $scene = $this->pick(['After hours', 'Cleaning', 'Presentation', 'Daylight', 'Full on'], 'cscene|' . $i);
                $summary = $person['name'] . " applied lighting scene '" . $scene . "' to " . $room['name'];
                break;
            case 'shades':
                $summary = $person['name'] . ' set blinds to ' . $this->intIn(0, 100, 'cpos|' . $i) . '% in ' . $room['name'];
                break;
            case 'appliances':
                $summary = $person['name'] . ' pushed signage content to the ' . $room['name'] . ' display';
                break;
            default: // energy
                $summary = $person['name'] . ' updated the demand-response schedule for ' . $room['name'];
        }
        return [
            'severity' => 'info',
            'summary' => $summary,
            'entityKind' => 'module',
            'entityId' => $module,
            'link' => '/' . $module,
        ];
    }

    /** Facilities work order raised/updated — links to the work order it names. */
    private function buildWorkorder(int $i, array $person): array
    {
        $room = $this->roomAt($this->h('wroom|' . $i) % $this->roomCount());
        $fault = $this->pick(
            ['dirty filter', 'comms fault', 'lamp failure', 'water leak detected', 'over-temperature',
             'blocked drain', 'door closer worn', 'condensate overflow'],
            'wfault|' . $i
        );
        $wo = 'WO-2026-' . sprintf('%06d', 1000 + ($this->h('wo|' . $i) % 8000));
        $stage = $this->pick(['raised', 'assigned', 'awaiting parts', 'awaiting contractor'], 'wstage|' . $i);
        $summary = 'Work order ' . $wo . ' ' . $stage . ': ' . $fault . ' in ' . $room['name']
            . ' (raised by ' . $person['name'] . ')';
        return [
            'severity' => 'warn',
            'summary' => $summary,
            'entityKind' => 'workorder',
            'entityId' => $wo,
            'link' => '/facilities/work-orders/' . $this->slug($wo),
        ];
    }

    /** Finance invoice awaiting approval — links to the AP invoice. */
    private function buildApproval(int $i, array $person): array
    {
        $vendor = $this->pick(
            ['Northwind Facilities', 'Apex Mechanical', 'Lumen Electrical', 'Harbour Catering',
             'Sentinel Security', 'Cedar Cleaning Co.', 'Orion AV', 'Granary Supplies'],
            'avend|' . $i
        );
        $inv = 'INV-2026-' . sprintf('%06d', 1000 + ($this->h('inv|' . $i) % 9000));
        $amount = number_format($this->intIn(240, 84000, 'amt|' . $i));
        $summary = 'Invoice ' . $inv . ' from ' . $vendor . ' (' . $amount
            . ') awaiting approval by ' . $person['name'];
        return [
            'severity' => 'info',
            'summary' => $summary,
            'entityKind' => 'invoice',
            'entityId' => $inv,
            'link' => '/finance/ap/' . $this->slug($inv),
        ];
    }

    /** Fire-panel or environmental sensor alarm — links to the owning module, names a real room. */
    private function buildAlarm(int $i, array $person): array
    {
        $room = $this->roomAt($this->h('aroom|' . $i) % $this->roomCount());
        $fire = ($this->h('afire|' . $i) % 2) === 0;
        if ($fire) {
            $kind = $this->pick(['detector fault', 'smoke pre-alarm', 'sounder circuit trouble', 'loop device missing'], 'afk|' . $i);
            $summary = 'Fire panel: ' . $kind . ' in ' . $room['name'] . ' (on-call ' . $person['name'] . ')';
            return [
                'severity' => 'crit',
                'summary' => $summary,
                'entityKind' => 'module',
                'entityId' => 'fire',
                'link' => '/fire',
            ];
        }
        $sensorId = 'sensor-' . $this->slug($room['id']) . '-' . $this->pick(['co2', 'temp', 'leak', 'humidity'], 'ask|' . $i);
        $kind = $this->pick(['CO2 above threshold', 'temperature high', 'water leak detected', 'humidity out of range'], 'ask2|' . $i);
        $summary = $kind . ' — ' . $room['name'] . ' (acknowledged by ' . $person['name'] . ')';
        return [
            'severity' => 'warn',
            'summary' => $summary,
            'entityKind' => 'sensor',
            'entityId' => $sensorId,
            'link' => '/sensors/' . $this->slug($sensorId),
        ];
    }

    /** TLS certificate expiry flagged by the IT services module — links to the certificate. */
    private function buildCert(int $i, array $person): array
    {
        $host = $this->pick(
            ['mail', 'vpn', 'portal', 'intranet', 'sso', 'files', 'remote', 'api'],
            'chost|' . $i
        );
        $cn = $host . '.' . $this->certDomain();
        $days = $this->intIn(-3, 30, 'cdays|' . $i);
        if ($days < 0) {
            $summary = 'TLS certificate for ' . $cn . ' EXPIRED ' . abs($days) . ' d ago (owner ' . $person['name'] . ')';
            $severity = 'crit';
        } else {
            $summary = 'TLS certificate for ' . $cn . ' expires in ' . $days . ' d (owner ' . $person['name'] . ')';
            $severity = 'warn';
        }
        $certId = 'cert-' . substr(hash('sha256', $this->seed . '|actcert|' . $i), 0, 8);
        return [
            'severity' => $severity,
            'summary' => $summary,
            'entityKind' => 'cert',
            'entityId' => $certId,
            'link' => '/helpdesk/certs/' . $this->slug($certId),
        ];
    }

    /** Monthly payroll run submitted for approval — links to the HR payroll run. */
    private function buildPayroll(int $i, array $person): array
    {
        $month = sprintf('%02d', $this->intIn(1, 8, 'pmon|' . $i));
        $run = 'run-2026-' . $month;
        $summary = 'Payroll ' . $run . ' submitted for second approval by ' . $person['name'];
        return [
            'severity' => 'info',
            'summary' => $summary,
            'entityKind' => 'run',
            'entityId' => $run,
            'link' => '/hr/payroll/' . $this->slug($run),
        ];
    }

    // --- coherence spine helpers (Org roster + Building rooms + Access doors) ---

    private function headcount(): int
    {
        return $this->org->headcount();
    }

    private function personAt(int $i): array
    {
        if ($this->rosterCache === null) {
            $this->rosterCache = $this->org->people($this->org->headcount());
        }
        return $this->rosterCache[$i];
    }

    /** The flat building room list (all floors), cached. @return list<array> */
    private function rooms(): array
    {
        if ($this->roomsCache !== null) {
            return $this->roomsCache;
        }
        $out = [];
        foreach ($this->building->floors() as $f) {
            foreach ($this->building->roomsFor($f['code']) as $r) {
                $out[] = $r;
            }
        }
        if ($out === []) {
            $out[] = ['id' => 'room-g-01', 'name' => 'Ground Floor', 'floor' => 'G', 'zone' => 'Core', 'type' => 'Open-plan'];
        }
        $this->roomsCache = $out;
        return $out;
    }

    private function roomCount(): int
    {
        return count($this->rooms());
    }

    private function roomAt(int $i): array
    {
        $rooms = $this->rooms();
        return $rooms[$i % count($rooms)];
    }

    /** The Access door estate, cached. @return list<array> */
    private function doors(): array
    {
        if ($this->doorsCache === null) {
            $this->doorsCache = $this->access->doors();
        }
        return $this->doorsCache;
    }

    private function doorCount(): int
    {
        return count($this->doors());
    }

    private function doorAt(int $i): array
    {
        $doors = $this->doors();
        return $doors[$i % count($doors)];
    }

    /** A documentation TEST-NET source address (RFC 5737) for an external/failed sign-in. */
    private function externalIp(string $salt): string
    {
        $block = $this->pick(['198.51.100.', '203.0.113.'], $salt . '|blk');
        return $block . $this->intIn(1, 254, $salt . '|host');
    }

    /** Certificate common-name domain: the persona domain when known, else a seeded fallback. */
    private function certDomain(): string
    {
        return $this->domain !== '' ? $this->domain : $this->org->domain();
    }

    /** Seeded "N ago" string from a second delta — deterministic, never time()/date(). */
    private function ago(int $sec): string
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
}
