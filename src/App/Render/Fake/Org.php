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
 *  - DETERMINISTIC: hash(seed+slot) only; no time()/date()/rand()/shuffle(); ages off DEPLOY_EPOCH.
 *  - PHP 7.3-clean so a fact can promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the skins render, mask and escape it.
 */
final class Org
{
    /** Frozen "now" for tenure/ages so a static reload is not a tell (spec E11). Matches Building. */
    public const DEPLOY_EPOCH = 1756000000;

    /** Org-chart branching factor: each manager carries up to this many direct reports. */
    private const BRANCH = 6;

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

    /** Invented email/AD domain — never a real registrable brand (spec E7). */
    public function domain(): string
    {
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

    /** Arithmetic tree parent: root(0) has none; others hang off floor((i-1)/BRANCH) < i. */
    private function parentIndex(int $i): ?int
    {
        if ($i <= 0) {
            return null;
        }
        return (int) (($i - 1) / self::BRANCH);
    }

    private function managerIdFor(int $i): string
    {
        $p = $this->parentIndex($i);
        return $p === null ? '' : $this->idFor($p);
    }

    /** Depth from the root (0 = root) — drives the title ladder. */
    private function depthOf(int $i): int
    {
        $depth = 0;
        while ($i > 0) {
            $i = (int) (($i - 1) / self::BRANCH);
            $depth++;
        }
        return $depth;
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
            'badgeId' => sprintf('%06d', 4000 + $i),          // unique, monotonic, fabricated
            'deskId' => 'DESK-' . sprintf('%02d', $this->intIn(1, 8, 'floor|' . $i)) . '-' . sprintf('%03d', $i + 1),
            'ext' => sprintf('%04d', 2000 + $i),               // unique 4-digit extension
            'ip' => '10.0.' . $third . '.' . $host,            // employee VLAN, RFC1918
            'status' => $this->statusFor($i),
            'band' => $this->bandFor($depth),
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

    private function bandFor(int $depth): string
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
        return 'IC' . ($depth - 1);
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
