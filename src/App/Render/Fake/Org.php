<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT company roster for the deep office panel — the ONE headcount all people-facing
 * modules read from so the same person is directory row, org-chart node, payslip line, badge holder,
 * desk owner, VoIP extension and audit actor, and their ids/badge/desk/ext/email/ip always agree.
 *
 * Design rules (deep-admin dashboard spec §A.2 / §C.5 + adversarial critique):
 *  - ONE headcount N = hash(seed)%180 + 90 (~90-270). Every other module's magnitudes derive from N
 *    via a fixed ratio table (magnitudes()) so a 214-person company never shows 50,000 badges (E3/T3).
 *  - COHERENT roster: one person -> id -> badge -> desk -> ext -> email -> RFC1918 ip, all unique and
 *    reproducible standalone. person($id) returns byte-identical data to that person's people() row.
 *  - Manager tree is a pure arithmetic tree (parent index < own index) -> acyclic by construction; the
 *    directory "manager" column, the profile "reports to" and org-chart edges can never disagree.
 *  - SAFE: all PII is fabricated and invalid-format (masked bank/tax id, employee-VLAN 10.0.20.x ip).
 *    No real person, no real trademark.
 *  - ONE DOMAIN: emails render at the host's persona domain (passed in by the caller), never a second
 *    invented domain — one host = one domain. A no-domain fallback is only for standalone/test use.
 *  - DETERMINISTIC: hash(seed+slot) only; no time()/date()/rand()/shuffle(); tenure is pure hash(seed).
 *  - PHP 7.3-clean so a fact can promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the skins render, mask and escape it.
 */
final class Org
{
    /**
     * Org-chart level fan-out: LEVEL_BRANCH[d] is how many children each depth-d node has at depth
     * d+1. Front-loaded small (CEO -> a few VPs -> a few Directors each -> a few Managers each) so the
     * exec/VP/Director/Manager layers stay a thin cap regardless of headcount, then wide at the
     * manager->IC step so the IC bands (depth>=4) are the layer that actually absorbs the 90-269
     * headcount range — a real company's shape, not a flat "Manager" layer swallowing the roster.
     */
    private const LEVEL_BRANCH = [4, 2, 2, 24];

    /** Bijection modulus for badge/ext/desk permutations: prime, comfortably above the max headcount
     *  (269) so every seeded permutation stays injective across the whole roster. */
    private const ID_MODULUS = 997;

    /** @var int */
    private $seed;

    /** @var string the host persona domain emails render at ('' -> the standalone fallback). */
    private $personaDomain;

    private function __construct(int $seed, string $personaDomain)
    {
        $this->seed = $seed;
        $this->personaDomain = $personaDomain;
    }

    /**
     * Build a roster for a seed. Callers that render emails MUST pass the host's persona domain so the
     * roster never contradicts the one domain shown elsewhere on the host. The default '' is only for
     * standalone/test use, where a seeded fallback domain keeps addresses well-formed.
     */
    public static function fromSeed(int $seed, string $personaDomain = ''): self
    {
        return new self($seed, $personaDomain);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|org|' . $salt), 0, 15));
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

    // --- headcount + derived magnitudes ---

    /** The single source of company size (~90-270). Everything else scales off this. */
    public function headcount(): int
    {
        return ($this->h('headcount') % 180) + 90;
    }

    /**
     * The email/AD domain the roster renders at. When the host persona domain was supplied it is used
     * verbatim (one host = one domain); otherwise a seeded, invented, never-real-brand domain keeps
     * standalone/test emails well-formed. It never invents a second domain over the persona's.
     */
    public function domain(): string
    {
        if ($this->personaDomain !== '') {
            return $this->personaDomain;
        }
        $stem = $this->pick(
            ['nordav', 'brightpk', 'apexfit', 'maplegrv', 'lumensta', 'harbourco',
             'meridianfm', 'northgatehq', 'silverbrook', 'oakmontgrp'],
            'domain'
        );
        $tld = $this->pick(['com', 'io', 'co', 'net'], 'domaintld');
        return $stem . '.' . $tld;
    }

    /**
     * The count-ratio table (spec E3/T3): every module's magnitudes derive from N so nothing contradicts.
     *
     * @return array{headcount:int,contractors:int,mailboxes:int,assets:int,extensions:int,cardholders:int,mdmEnrolled:int,auditRowsPerDay:int,auditRetentionDays:int,auditRows:int}
     */
    public function magnitudes(): array
    {
        $n = $this->headcount();
        $contractors = (int) round($n * 0.15);
        $assets = (int) round($n * 1.3);
        $retention = 365;
        return [
            'headcount' => $n,
            'contractors' => $contractors,
            'mailboxes' => $n,
            'assets' => $assets,
            'extensions' => $n,
            'cardholders' => $n + $contractors,
            'mdmEnrolled' => $assets,
            'auditRowsPerDay' => $n * 4,
            'auditRetentionDays' => $retention,
            'auditRows' => $n * 4 * $retention,
        ];
    }

    // --- roster ---

    /**
     * The first $count roster rows (clamped to N), for paginated directory views. Each row is the full
     * cross-reference mapping other modules key off. Row order is stable: index i is always emp-(1001+i).
     *
     * @return list<array{id:string,first:string,last:string,name:string,email:string,title:string,dept:string,location:string,managerId:string,badgeId:string,deskId:string,ext:string,ip:string,status:string,band:string,tenureMonths:int}>
     */
    public function people(int $count): array
    {
        $n = $this->headcount();
        if ($count < 0) {
            $count = 0;
        }
        if ($count > $n) {
            $count = $n;
        }
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $out[] = $this->personAt($i);
        }
        return $out;
    }

    /** One person by id (emp-####). Returns null for an id outside the roster. */
    public function person(string $id): ?array
    {
        $i = $this->indexOfId($id);
        if ($i === null) {
            return null;
        }
        return $this->personAt($i);
    }

    /** emp-#### -> 0-based roster index, or null if the id is not in this roster. */
    private function indexOfId(string $id): ?int
    {
        if (strpos($id, 'emp-') !== 0) {
            return null;
        }
        $num = substr($id, 4);
        if ($num === '' || !ctype_digit($num)) {
            return null;
        }
        $i = ((int) $num) - 1001;
        if ($i < 0 || $i >= $this->headcount()) {
            return null;
        }
        return $i;
    }

    /**
     * The manager tree as id => managerId ('' for the single root). Pure arithmetic parent (index-based)
     * so it is acyclic and always agrees with each person's managerId field.
     *
     * @return array<string,string>
     */
    public function managerTree(): array
    {
        $n = $this->headcount();
        $out = [];
        for ($i = 0; $i < $n; $i++) {
            $out[$this->idFor($i)] = $this->managerIdFor($i);
        }
        return $out;
    }

    /** Direct reports of a person (empty for a leaf or an unknown id). @return list<string> */
    public function directReports(string $id): array
    {
        $i = $this->indexOfId($id);
        if ($i === null) {
            return [];
        }
        $n = $this->headcount();
        $out = [];
        for ($j = 0; $j < $n; $j++) {
            if ($this->parentIndex($j) === $i) {
                $out[] = $this->idFor($j);
            }
        }
        return $out;
    }

    // --- per-person derivation (standalone-consistent) ---

    private function idFor(int $i): string
    {
        return 'emp-' . (1001 + $i);
    }

    /**
     * Level boundaries [start,count) derived once from LEVEL_BRANCH, wide enough to cover the maximum
     * possible headcount (269) without ever exhausting the table.
     *
     * @return list<array{start:int,count:int}>
     */
    private static function levels(): array
    {
        static $cache = null;
        if ($cache !== null) {
            return $cache;
        }
        $levels = [];
        $start = 0;
        $count = 1;
        while ($start < 400) {
            $levels[] = ['start' => $start, 'count' => $count];
            $d = count($levels) - 1;
            $branch = isset(self::LEVEL_BRANCH[$d]) ? self::LEVEL_BRANCH[$d] : self::LEVEL_BRANCH[count(self::LEVEL_BRANCH) - 1];
            $start += $count;
            $count *= $branch;
        }
        $cache = $levels;
        return $cache;
    }

    /** Arithmetic tree parent: root(0) has none; every other node's parent sits one level up, grouped
     *  by that level's branch factor, so parent index < own index always (acyclic by construction). */
    private function parentIndex(int $i): ?int
    {
        if ($i <= 0) {
            return null;
        }
        $levels = self::levels();
        $depth = $this->depthOf($i);
        $branch = isset(self::LEVEL_BRANCH[$depth - 1]) ? self::LEVEL_BRANCH[$depth - 1] : self::LEVEL_BRANCH[count(self::LEVEL_BRANCH) - 1];
        $posInLevel = $i - $levels[$depth]['start'];
        return $levels[$depth - 1]['start'] + intdiv($posInLevel, $branch);
    }

    private function managerIdFor(int $i): string
    {
        $p = $this->parentIndex($i);
        return $p === null ? '' : $this->idFor($p);
    }

    /** Depth from the root (0 = root) — drives the title ladder. */
    private function depthOf(int $i): int
    {
        $levels = self::levels();
        foreach ($levels as $depth => $lvl) {
            if ($i < $lvl['start'] + $lvl['count']) {
                return $depth;
            }
        }
        return count($levels) - 1;
    }

    /**
     * A seeded bijection over 0..ID_MODULUS-1 (affine map mod a prime), independent per $salt. Badge,
     * ext and desk each permute the roster index through THEIR OWN multiplier/offset, so no two of
     * them move in lockstep the way `ext = badge - 2000` did when both were the same loop counter —
     * yet each stays a bijection, so ids drawn from it are still unique across the roster.
     */
    private function permute(int $i, string $salt): int
    {
        $mult = 1 + ($this->h($salt . '|mult') % (self::ID_MODULUS - 1));   // 1..M-1, coprime (M is prime)
        $off = $this->h($salt . '|off') % self::ID_MODULUS;
        return ($i * $mult + $off) % self::ID_MODULUS;
    }

    /** @return array{0:string,1:string} [first, last] — pure function of index. */
    private function nameAt(int $i): array
    {
        $fore = [
            'Aoife', 'Liam', 'Priya', 'Chen', 'Sofia', 'Marcus', 'Nadia', 'Tomas', 'Grace', 'Omar',
            'Elena', 'Kenji', 'Fatima', 'Sean', 'Ingrid', 'Diego', 'Hana', 'Noah', 'Amara', 'Viktor',
            'Leila', 'Mateo', 'Yara', 'Finn', 'Zoya', 'Aditya', 'Clara', 'Ravi', 'Mila', 'Jonas',
            'Sana', 'Eoin', 'Petra', 'Kofi', 'Aya', 'Bruno', 'Iris', 'Tariq', 'Maeve', 'Lucas',
        ];
        $sur = [
            'Nair', 'Okafor', 'Rossi', 'Wei', 'Mitchell', 'Alsayed', 'Meyer', 'Obrien', 'Kaur', 'Novak',
            'Haddad', 'Lindqvist', 'Costa', 'Petrov', 'Fischer', 'Moreno', 'Yamamoto', 'Byrne', 'Adeyemi', 'Kovac',
            'Dubois', 'Santos', 'Ivanov', 'Murphy', 'Kelly', 'Reyes', 'Andersen', 'Bianchi', 'Farrell', 'Schmidt',
            'Doyle', 'Weber', 'Silva', 'Larsen', 'Mensah', 'Horvat', 'Walsh', 'Romano', 'Keane', 'Bauer',
        ];
        $first = $fore[$this->h('fore|' . $i) % count($fore)];
        $last = $sur[$this->h('sur|' . $i) % count($sur)];
        return [$first, $last];
    }

    /**
     * Email local part, unique across the roster: base is first.last, and a numeric suffix is added when
     * an earlier index already claimed it. The scan over j<i is deterministic, so people() and person()
     * always agree on the same address.
     */
    private function emailLocal(int $i, string $first, string $last): string
    {
        $base = strtolower($first) . '.' . strtolower($last);
        $dupes = 0;
        for ($j = 0; $j < $i; $j++) {
            $nm = $this->nameAt($j);
            if (strtolower($nm[0]) . '.' . strtolower($nm[1]) === $base) {
                $dupes++;
            }
        }
        return $dupes === 0 ? $base : $base . ($dupes + 1);
    }

    /** @return array{...} one fully cross-referenced person record. */
    private function personAt(int $i): array
    {
        $nm = $this->nameAt($i);
        $first = $nm[0];
        $last = $nm[1];
        $depth = $this->depthOf($i);

        $dept = $this->pick(
            ['Engineering', 'Sales', 'Finance', 'People', 'Operations', 'Marketing',
             'IT', 'Legal', 'Facilities', 'Support', 'Security', 'Product'],
            'dept|' . $i
        );

        // Third octet spreads onto 10.0.20.0/23 so >254 people still land on the employee VLAN.
        $third = 20 + (int) ($i / 200);
        $host = 2 + ($i % 200);

        // Badge/ext/desk each permute the roster index through an independent seeded bijection, so
        // none of them reveal a shared loop counter — yet all stay unique across the roster.
        $badgeSlot = $this->permute($i, 'badge');
        $extSlot = $this->permute($i, 'ext');
        $deskSlot = $this->permute($i, 'desk');

        return [
            'id' => $this->idFor($i),
            'first' => $first,
            'last' => $last,
            'name' => $first . ' ' . $last,
            'email' => $this->emailLocal($i, $first, $last) . '@' . $this->domain(),
            'title' => $this->titleFor($depth, $dept, $i),
            'dept' => $dept,
            'location' => 'HQ — Floor ' . $this->intIn(1, 8, 'floor|' . $i),
            'managerId' => $this->managerIdFor($i),
            'badgeId' => sprintf('%06d', 4000 + $badgeSlot),   // unique, fabricated
            'deskId' => 'DESK-' . sprintf('%02d', $this->intIn(1, 8, 'floor|' . $i)) . '-' . sprintf('%03d', 1 + $deskSlot),
            'ext' => sprintf('%04d', 2000 + $extSlot),          // unique 4-digit extension
            'ip' => '10.0.' . $third . '.' . $host,            // employee VLAN, RFC1918
            'status' => $this->statusFor($i),
            'band' => $this->bandFor($depth, $i),
            'tenureMonths' => $this->intIn(1, 168, 'tenure|' . $i),
        ];
    }

    private function titleFor(int $depth, string $dept, int $i): string
    {
        if ($depth === 0) {
            return 'Chief Executive Officer';
        }
        if ($depth === 1) {
            return $this->pick(['VP ' . $dept, 'Chief ' . $dept . ' Officer', 'Head of ' . $dept], 'title|' . $i);
        }
        if ($depth === 2) {
            return 'Director, ' . $dept;
        }
        if ($depth === 3) {
            return $dept . ' Manager';
        }
        return $this->pick(
            [$dept . ' Specialist', 'Senior ' . $dept . ' Associate', $dept . ' Associate',
             $dept . ' Analyst', $dept . ' Coordinator'],
            'title|' . $i
        );
    }

    /**
     * IC seniority is seeded independently of org-chart depth: real ICs reporting to the same manager
     * span junior to senior, so tying the band to tree depth would have every IC land on one flat band
     * (IC3) now that the whole IC layer sits at a single depth. Weighted toward junior/mid, like a real
     * ladder (fewer senior ICs than junior/mid ones).
     */
    private function bandFor(int $depth, int $i): string
    {
        if ($depth === 0) {
            return 'EX';
        }
        if ($depth === 1) {
            return 'M5';
        }
        if ($depth === 2) {
            return 'M4';
        }
        if ($depth === 3) {
            return 'M3';
        }
        $r = $this->h('icband|' . $i) % 100;
        if ($r < 25) {
            return 'IC1';
        }
        if ($r < 60) {
            return 'IC2';
        }
        if ($r < 85) {
            return 'IC3';
        }
        return 'IC4';
    }

    /** Mostly Active; a small budgeted minority On leave / Notice (never a buffet of departures). */
    private function statusFor(int $i): string
    {
        $r = $this->h('status|' . $i) % 100;
        if ($r < 92) {
            return 'Active';
        }
        if ($r < 97) {
            return 'On leave';
        }
        return 'Notice';
    }
}
