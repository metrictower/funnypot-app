<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT global-search aggregator for the deep office panel (spec §D.6) — the cross-module
 * "one company" lure. It owns no corpus of its own; it is a VIEW over the existing seeded generators
 * (Org / Cmdb / Finance / Vendors / Facilities / Helpdesk / Bank), so a search hit is a REAL record that
 * deep-links to that module's own detail page and reads identically there. This is what makes the whole
 * estate feel like one system: the person, invoice, ticket or room a query surfaces resolves everywhere
 * else to the same entity.
 *
 * Design rules (deep-admin dashboard spec §D.6 + §E):
 *  - DETERMINISTIC per (seed, query): every result group, its size and which records it selects are
 *    hash(seed + query-slug + slot). No time()/date()/rand()/shuffle(), so the same URL is byte-identical
 *    on reload (a diffable search page is a tell).
 *  - ALWAYS PLAUSIBLE: every group returns at least one hit for any query, so "password" / "admin" /
 *    "wire" / a name all return confident-looking rows (deep engagement) that all dead-end inertly.
 *  - COHERENT + SAFE: hits are the same fabricated, RFC1918/invalid-format records the modules already
 *    serve — no new secret is minted here and the query itself is only ever a hash salt, never reflected
 *    into a link or persisted. The section escapes the echoed query.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf, no enums/promotion/str_contains/arrow fns) so a fact can
 *    promote into a core template unchanged when one needs it.
 *
 * Returns plain data only (each item is title + sub + a navBase-relative deep-link path); the section
 * renders, prefixes navBase and escapes it.
 */
final class Search
{
    /** @var int */
    private $seed;

    /** @var string */
    private $domain;

    /** @var Org */
    private $org;

    /** @var Cmdb */
    private $cmdb;

    /** @var Finance */
    private $finance;

    /** @var Vendors */
    private $vendors;

    /** @var Facilities */
    private $facilities;

    /** @var Helpdesk */
    private $helpdesk;

    /** @var Bank */
    private $bank;

    private function __construct(int $seed, string $domain)
    {
        $this->seed = $seed;
        $this->domain = $domain;
        $this->org = Org::fromSeed($seed, $domain);
        $this->cmdb = Cmdb::fromSeed($seed, $domain);
        $this->finance = Finance::fromSeed($seed, $domain);
        $this->vendors = Vendors::fromSeed($seed, $domain);
        $this->facilities = Facilities::fromSeed($seed, $domain);
        $this->helpdesk = Helpdesk::fromSeed($seed, $domain);
        $this->bank = Bank::fromSeed($seed, $domain);
    }

    public static function fromSeed(int $seed, string $domain = ''): self
    {
        return new self($seed, $domain);
    }

    // --- deterministic seeded primitives (frozen per seed + query) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|search|' . $salt), 0, 15));
    }

    /** How many hits a group shows: 2..4, clamped to what the pool holds, never above; >=1 while non-empty. */
    private function countFor(string $group, string $query, int $poolSize): int
    {
        if ($poolSize <= 0) {
            return 0;
        }
        $k = 2 + ($this->h('cnt|' . $group . '|' . $query) % 3);   // 2..4
        return $k > $poolSize ? $poolSize : $k;
    }

    /**
     * $k distinct pool indices chosen by hash(seed + query + group + i), so a query picks a stable,
     * spread-out slice of the pool with no repeats.
     *
     * @return list<int>
     */
    private function pickIndices(string $group, string $query, int $poolSize, int $k): array
    {
        $picks = [];
        $i = 0;
        $guard = $k * 6;
        while (count($picks) < $k && $i < $guard) {
            $idx = $this->h('pick|' . $group . '|' . $query . '|' . $i) % $poolSize;
            if (!in_array($idx, $picks, true)) {
                $picks[] = $idx;
            }
            $i++;
        }
        return $picks;
    }

    // --- result groups ---

    /**
     * The ordered result groups for a query. Each group is
     * ['key'=>string, 'label'=>string, 'items'=>list<array{title:string,sub:string,path:string}>];
     * `path` is a navBase-relative deep link into that module's own detail page.
     *
     * @return list<array{key:string,label:string,items:list<array{title:string,sub:string,path:string}>}>
     */
    public function groups(string $query): array
    {
        return [
            $this->peopleGroup($query),
            $this->employeesGroup($query),
            $this->assetsGroup($query),
            $this->invoicesGroup($query),
            $this->vendorsGroup($query),
            $this->roomsGroup($query),
            $this->ticketsGroup($query),
            $this->bankGroup($query),
        ];
    }

    /** Leadership slice of the roster (low roster index = senior), framed as the "People" hits. */
    private function peopleGroup(string $query): array
    {
        $hc = $this->org->headcount();
        $pool = $this->org->people($hc < 24 ? $hc : 24);
        $items = [];
        foreach ($this->pickIndices('people', $query, count($pool), $this->countFor('people', $query, count($pool))) as $idx) {
            $p = $pool[$idx];
            $items[] = [
                'title' => $p['name'],
                'sub' => $p['title'] . ' · ' . $p['dept'],
                'path' => '/hr/employees/' . $p['id'],
            ];
        }
        return ['key' => 'people', 'label' => 'People', 'items' => $items];
    }

    /** The wider directory, framed as the "Employees" hits (distinct sub-line from People). */
    private function employeesGroup(string $query): array
    {
        $pool = $this->org->people($this->org->headcount());
        $items = [];
        foreach ($this->pickIndices('employees', $query, count($pool), $this->countFor('employees', $query, count($pool))) as $idx) {
            $p = $pool[$idx];
            $items[] = [
                'title' => $p['name'],
                'sub' => $p['dept'] . ' · ' . $p['email'],
                'path' => '/hr/employees/' . $p['id'],
            ];
        }
        return ['key' => 'employees', 'label' => 'Employees', 'items' => $items];
    }

    private function assetsGroup(string $query): array
    {
        $pool = $this->cmdb->assets();
        $items = [];
        foreach ($this->pickIndices('assets', $query, count($pool), $this->countFor('assets', $query, count($pool))) as $idx) {
            $a = $pool[$idx];
            $name = ($a['hostname'] !== '' && $a['hostname'] !== '—') ? $a['hostname'] : $a['tag'];
            $sub = $a['typeLabel'] . ' · ' . $a['model'];
            if ($a['assigneeName'] !== '' && $a['assigneeName'] !== '—') {
                $sub .= ' · ' . $a['assigneeName'];
            }
            $items[] = [
                'title' => $name,
                'sub' => $sub,
                'path' => '/it/assets/' . $a['id'],
            ];
        }
        return ['key' => 'assets', 'label' => 'Assets & CMDB', 'items' => $items];
    }

    private function invoicesGroup(string $query): array
    {
        $total = $this->finance->invoiceCount();
        $items = [];
        foreach ($this->pickIndices('invoices', $query, $total, $this->countFor('invoices', $query, $total)) as $idx) {
            $inv = $this->finance->invoiceAt($idx);
            $items[] = [
                'title' => $inv['number'],
                'sub' => $inv['vendorName'] . ' · ' . $this->finance->money($inv['totalCents']) . ' · ' . $inv['status'],
                'path' => '/finance/ap/' . $inv['id'],
            ];
        }
        return ['key' => 'invoices', 'label' => 'Invoices', 'items' => $items];
    }

    private function vendorsGroup(string $query): array
    {
        $vc = $this->vendors->vendorCount();
        $pool = $this->vendors->vendorsPage(0, $vc < 24 ? $vc : 24);
        $items = [];
        foreach ($this->pickIndices('vendors', $query, count($pool), $this->countFor('vendors', $query, count($pool))) as $idx) {
            $v = $pool[$idx];
            $items[] = [
                'title' => $v['name'],
                'sub' => $v['category'] . ' · ' . $v['status'],
                'path' => '/vendors/' . $v['id'],
            ];
        }
        return ['key' => 'vendors', 'label' => 'Vendors', 'items' => $items];
    }

    private function roomsGroup(string $query): array
    {
        $rc = $this->facilities->roomCount();
        $pool = $this->facilities->roomsPage(0, $rc < 60 ? $rc : 60);
        $items = [];
        foreach ($this->pickIndices('rooms', $query, count($pool), $this->countFor('rooms', $query, count($pool))) as $idx) {
            $r = $pool[$idx];
            $items[] = [
                'title' => $r['name'],
                'sub' => 'Floor ' . strtoupper((string) $r['floor']) . ' · ' . $r['type'],
                'path' => '/facilities/rooms/' . $r['id'],
            ];
        }
        return ['key' => 'rooms', 'label' => 'Rooms', 'items' => $items];
    }

    private function ticketsGroup(string $query): array
    {
        $total = $this->helpdesk->ticketCount();
        $items = [];
        foreach ($this->pickIndices('tickets', $query, $total, $this->countFor('tickets', $query, $total)) as $idx) {
            $t = $this->helpdesk->ticketAt($idx);
            $items[] = [
                'title' => $t['number'],
                'sub' => $t['subject'] . ' · ' . $t['status'],
                'path' => '/helpdesk/' . $t['id'],
            ];
        }
        return ['key' => 'tickets', 'label' => 'Tickets', 'items' => $items];
    }

    private function bankGroup(string $query): array
    {
        $pool = $this->bank->accounts();
        $items = [];
        foreach ($this->pickIndices('bank', $query, count($pool), $this->countFor('bank', $query, count($pool))) as $idx) {
            $a = $pool[$idx];
            $items[] = [
                'title' => $a['name'],
                'sub' => $a['bank'] . ' · ' . $a['accountMasked'],
                'path' => '/bank/' . $a['id'],
            ];
        }
        return ['key' => 'bank', 'label' => 'Bank accounts', 'items' => $items];
    }

    // --- landing (empty query) ---

    /**
     * Suggested searches for the empty-query landing: a fixed, teasing vocab (each a plausible thing an
     * operator would look up). Stable across seeds so the landing reads the same everywhere.
     *
     * @return list<string>
     */
    public function suggestions(): array
    {
        return [
            'Payroll', 'Password reset', 'VPN access', 'Overdue invoices', 'Vendor bank change',
            'Offboarding', 'Admin accounts', 'Wire transfer', 'Server inventory', 'Meeting rooms',
        ];
    }

    /**
     * "Recent searches" for the landing: a seeded, deterministic slice of a wider vocab, so the panel
     * reads as if the operator had a search history (per-deploy, but stable per seed).
     *
     * @return list<string>
     */
    public function recentSearches(): array
    {
        $vocab = [
            'q3 board pack', 'domain admin', 'reset mfa', 'ssh keys', 'aws root', 'net 30 vendors',
            'contractor offboarding', 'transfer approval', 'ceo calendar', 'backup restore',
            'privileged access', 'vendor remittance', 'expense report', 'shared mailbox',
        ];
        $out = [];
        $i = 0;
        while (count($out) < 5 && $i < 30) {
            $t = $vocab[$this->h('recent|' . $i) % count($vocab)];
            if (!in_array($t, $out, true)) {
                $out[] = $t;
            }
            $i++;
        }
        return $out;
    }
}
