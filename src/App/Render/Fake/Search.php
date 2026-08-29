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
 *  - PLAUSIBILITY-SCALED: a real-looking term ("password" / "admin" / "wire" / a name) returns confident
 *    multi-group rows (deep engagement) that all dead-end inertly; a gibberish/random-token query scores
 *    low on the character-level plausibility check and returns few or zero hits across fewer areas, so a
 *    blind fuzz probe does not get the same confident results page as a real search term.
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
    use SeededInstanceCache;

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
        return self::seededInstance(
            $seed . '|' . $domain,
            static function () use ($seed, $domain): self {
                return new self($seed, $domain);
            }
        );
    }

    // --- deterministic seeded primitives (frozen per seed + query) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|search|' . $salt), 0, 15));
    }

    /**
     * How many hits a group shows, clamped to what the pool holds. Scaled by plausibility(): a real-looking
     * term gets the original 2..4 confident hits; a marginal query gets a sparse, per-group-varying 0..2;
     * outright gibberish gets 0 in every group (so "N areas" drops with it — see groups()/plausibility()).
     */
    private function countFor(string $group, string $query, int $poolSize): int
    {
        if ($poolSize <= 0) {
            return 0;
        }
        $tier = $this->plausibility($query);
        if ($tier <= 0) {
            return 0;
        }
        $h = $this->h('cnt|' . $group . '|' . $query);
        if ($tier === 1) {
            $k = ($h % 100) < 45 ? 0 : 1;               // marginal: patchy, mostly-empty
        } elseif ($tier === 2) {
            $k = 1 + ($h % 2);                          // 1..2
        } else {
            $k = 2 + ($h % 3);                          // 2..4 — unchanged confident behaviour
        }
        return $k > $poolSize ? $poolSize : $k;
    }

    /**
     * A cheap 0..N "does this look like a real search term" score, derived purely from the query's own
     * characters (never a dictionary, so it stays deterministic and PHP 7.3-clean). Short real words and
     * abbreviations without vowels ("ssn", "vpn") still score as plausible via the length exemption; a
     * keyboard-mash consonant run, a repeated-character string, or a digit-heavy random token scores low.
     * >=3 = confident (the original always-hits behaviour); 1-2 = marginal/sparse; <=0 = no hits anywhere.
     */
    private function plausibility(string $query): int
    {
        $len = strlen($query);
        if ($len === 0) {
            return 0;
        }
        $letters = 0;
        $digits = 0;
        $vowels = 0;
        $maxSameRun = 1;
        $sameRun = 1;
        $maxConsonantRun = 0;
        $consonantRun = 0;
        $prev = '';
        for ($i = 0; $i < $len; $i++) {
            $c = strtolower($query[$i]);
            $isAlpha = ($c >= 'a' && $c <= 'z');
            $isVowel = $isAlpha && strpos('aeiou', $c) !== false;
            if ($isAlpha) {
                $letters++;
                if ($isVowel) {
                    $vowels++;
                }
            } elseif ($c >= '0' && $c <= '9') {
                $digits++;
            }
            if ($isAlpha && !$isVowel) {
                $consonantRun++;
                $maxConsonantRun = $consonantRun > $maxConsonantRun ? $consonantRun : $maxConsonantRun;
            } else {
                $consonantRun = 0;
            }
            $sameRun = ($c === $prev) ? $sameRun + 1 : 1;
            $maxSameRun = $sameRun > $maxSameRun ? $sameRun : $maxSameRun;
            $prev = $c;
        }

        $score = 0;
        $alphaRatio = $letters / $len;
        if ($alphaRatio >= 0.6) {
            $score += 2;
        } elseif ($alphaRatio >= 0.3) {
            $score += 1;
        }
        if ($vowels > 0 || $len <= 4) {
            $score += 1;                                // real short abbreviations lack vowels (ssn, vpn)
        }
        if ($len >= 2 && $len <= 28) {
            $score += 1;
        } else {
            $score -= 1;
        }
        if ($maxConsonantRun >= 5) {
            $score -= 3;                                // keyboard-mash consonant cluster
        }
        if ($maxSameRun >= 6) {
            $score -= 4;                                // "aaaaaaaa" style repeat
        } elseif ($maxSameRun >= 4) {
            $score -= 2;
        }
        if ($digits > 0 && $len >= 8 && ($digits / $len) > 0.35) {
            $score -= 2;                                // digit-heavy — reads like a hash/random token
        }
        return $score;
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

    /**
     * The "top match" documents teaser: a shared-drive hit + an export file that fold the query back in.
     * Item count (0-2) follows the same plausibility scale as groups() — a gibberish query gets no teaser
     * at all — and the attributed department is picked by a query-derived hash rather than always Finance,
     * so two different queries don't surface the identical confident 2-item card.
     *
     * @return list<array{title:string,sub:string,path:string}>
     */
    public function documentsFor(string $query): array
    {
        $tier = $this->plausibility($query);
        if ($tier <= 0) {
            return [];
        }
        $depts = ['Finance', 'Legal', 'HR', 'IT', 'Operations', 'Facilities', 'Security', 'Executive Office'];
        $dept = $depts[$this->h('docdept|' . $query) % count($depts)];
        $items = [
            [
                'title' => '"' . $query . '" — matches in shared drive',
                'sub' => 'Documents / reports · restricted',
                'path' => '/hr/documents',
            ],
            [
                'title' => $query . ' (export).xlsx',
                'sub' => 'Files · last opened by ' . $dept,
                'path' => '/files',
            ],
        ];
        $count = $tier >= 3 ? 2 : 1;
        return array_slice($items, 0, $count);
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
