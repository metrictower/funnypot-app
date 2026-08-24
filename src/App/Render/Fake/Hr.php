<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT HR view for the deep office panel — the employee directory, per-profile PII, the
 * manager tree for the org chart, PTO balances and per-employee documents. It is a VIEW over the one
 * `Org` roster (never a second headcount) and reads salary through `Payroll`'s single source of truth,
 * so the same person's directory row, org-chart node, compensation and payslips always agree.
 *
 * Design rules (deep-admin dashboard spec §C.5 + adversarial critique):
 *  - PII IS THE LURE, AND IT IS ALL FAKE + INVALID-FORMAT: every SSN/tax id, date of birth, address,
 *    bank account and phone renders MASKED and structurally non-validating (`***-**-4821`, `••/••/1986`,
 *    `••••6614`) — nothing here validates as a real identifier, so a screenshot is worthless.
 *  - COHERENT: manager chain and org-chart edges come from Org's arithmetic tree (they cannot disagree);
 *    PTO reconciles (entitlement + carried = available; available - taken = remaining); start date is
 *    derived from Org tenure off the one frozen anchor.
 *  - DETERMINISTIC per seed: every value is hash(seed+slot); no time()/date()/rand()/shuffle().
 *  - ONE DOMAIN: the only email shown is the roster work email, which renders at the host persona domain
 *    (passed to Org) — never a second invented domain.
 *  - SAFE: no real person, no real bank name/BIN, no scanner-signature string.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf, no enums/promotion/str_contains).
 *
 * Returns plain data only — the section renders, masks-in-place and escapes it.
 */
final class Hr
{
    /** @var int */
    private $seed;

    /** @var Org */
    private $org;

    /** @var Payroll */
    private $payroll;

    /** @var array<int,array>|null cached roster so deep directory/org pages stay cheap */
    private $rosterCache = null;

    private function __construct(int $seed, string $personaDomain)
    {
        $this->seed = $seed;
        $this->org = Org::fromSeed($seed, $personaDomain);
        $this->payroll = Payroll::fromSeed($seed, $personaDomain);
    }

    /**
     * Build the HR view for a seed. Callers MUST pass the host persona domain so the one work email the
     * profile shows never contradicts the domain shown elsewhere on the host (one host = one domain).
     */
    public static function fromSeed(int $seed, string $personaDomain = ''): self
    {
        return new self($seed, $personaDomain);
    }

    /**
     * The current [year, month] for start-date/tenure math. A class const can't call FrozenClock::epoch(),
     * and FrozenClock::YEAR/MONTH describe only the fallback instant — so this reads the deploy epoch's
     * own calendar date at call time, keeping hire dates in step with every other epoch-aware module
     * (Payroll included) under a set FUNNYPOT_EPOCH instead of pinning to the fallback.
     *
     * @return array{0:int,1:int}
     */
    private static function anchorYearMonth(): array
    {
        $c = FrozenClock::civilFromDays(FrozenClock::nowDays());
        return [$c[0], $c[1]];
    }

    // --- deterministic seeded primitives ---

    private function h(string $salt): int
    {
        return (int) hexdec(substr(hash('sha256', $this->seed . '|hr|' . $salt), 0, 15));
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

    // --- roster + directory ---

    public function headcount(): int
    {
        return $this->org->headcount();
    }

    /** The full roster, cached (index i = emp-(1001+i)). */
    private function roster(): array
    {
        if ($this->rosterCache === null) {
            $this->rosterCache = $this->org->people($this->org->headcount());
        }
        return $this->rosterCache;
    }

    /**
     * Distinct departments with their head counts (for landing tiles and the directory filter chips).
     *
     * @return list<array{dept:string,slug:string,count:int}>
     */
    public function departments(): array
    {
        $counts = array();
        foreach ($this->roster() as $p) {
            $d = $p['dept'];
            $counts[$d] = isset($counts[$d]) ? $counts[$d] + 1 : 1;
        }
        ksort($counts);
        $out = array();
        foreach ($counts as $dept => $n) {
            $out[] = array(
                'dept' => $dept,
                'slug' => 'dept-' . strtolower(str_replace(' ', '-', $dept)),
                'count' => $n,
            );
        }
        return $out;
    }

    /**
     * One page of the directory, optionally filtered to a `dept-<name>` slug, by absolute offset so a deep
     * page renders identically. Rows are the Org roster rows (id/name/title/dept/location/manager/status).
     *
     * @return array{rows:list<array>,total:int}
     */
    public function directoryPage(string $deptSlug, int $offset, int $limit): array
    {
        $rows = array();
        foreach ($this->roster() as $p) {
            if ($deptSlug !== '' && $this->deptSlugOf($p['dept']) !== $deptSlug) {
                continue;
            }
            $rows[] = $p;
        }
        $total = count($rows);
        if ($offset < 0) {
            $offset = 0;
        }
        $page = array_slice($rows, $offset, $limit);
        return array('rows' => $page, 'total' => $total);
    }

    private function deptSlugOf(string $dept): string
    {
        return 'dept-' . strtolower(str_replace(' ', '-', $dept));
    }

    /** The manager's display name for a directory row ('—' for the single root). */
    public function managerName(string $managerId): string
    {
        if ($managerId === '') {
            return '—';
        }
        $m = $this->org->person($managerId);
        return $m !== null ? $m['name'] : $managerId;
    }

    // --- one profile ---

    /** A known employee, or a plausible synthetic record for a fuzzed slug (never a 404: spec D.4). */
    public function person(string $empId): array
    {
        $p = $this->org->person($empId);
        if ($p !== null) {
            return $p;
        }
        $first = $this->pick(array('Sam', 'Alex', 'Jo', 'Robin', 'Casey', 'Drew', 'Lee', 'Morgan'), 'synf|' . $empId);
        $last = $this->pick(array('Doyle', 'Hart', 'Ford', 'Beck', 'Cole', 'Frost', 'Nash', 'Reed'), 'synl|' . $empId);
        return array(
            'id' => $this->slug($empId),
            'first' => $first,
            'last' => $last,
            'name' => $first . ' ' . $last,
            'email' => strtolower($first) . '.' . strtolower($last) . '@' . $this->org->domain(),
            'title' => 'Operations Associate',
            'dept' => 'Operations',
            'location' => 'HQ — Floor ' . $this->intIn(1, 8, 'synfloor|' . $empId),
            'managerId' => '',
            'badgeId' => sprintf('%06d', 9000 + ($this->h('synbadge|' . $empId) % 900)),
            'deskId' => 'DESK-01-000',
            'ext' => sprintf('%04d', 2000 + ($this->h('synext|' . $empId) % 900)),
            'ip' => '10.0.20.' . (2 + ($this->h('synip|' . $empId) % 200)),
            'status' => 'Active',
            'band' => 'IC2',
            'tenureMonths' => $this->intIn(1, 60, 'syntenure|' . $empId),
        );
    }

    /**
     * The masked, invalid-format personal PII for a profile's Personal tab. Every identifier is masked in
     * place and structurally non-validating — nothing here is a real SSN/DOB/address/phone/bank number.
     *
     * @return list<array{0:string,1:string}>
     */
    public function personal(string $empId): array
    {
        $p = $this->person($empId);
        $id = $p['id'];
        $ssn4 = sprintf('%04d', $this->intIn(1000, 9999, 'ssn|' . $id));
        // DOB stays coherent with the hire date: nobody was hired as a minor. hireYear caps how young
        // dobYear can be (hireYear - 18); the floor keeps the spread realistic for long-tenured staff.
        $hireYear = (int) substr($this->startDate($p['tenureMonths'], $id), 0, 4);
        $maxDobYear = $hireYear - 18;
        $minDobYear = 1965;
        if ($maxDobYear < $minDobYear) {
            $maxDobYear = $minDobYear;
        }
        $dobYear = $this->intIn($minDobYear, $maxDobYear, 'dob|' . $id);
        $street = $this->pick(
            array('Birch Lane', 'Maple Avenue', 'Cedar Close', 'Willow Court', 'Elm Rise',
                  'Rowan Way', 'Hazel Grove', 'Aspen Drive', 'Alder Street', 'Linden Walk'),
            'street|' . $id
        );
        $city = $this->pick(
            array('Ashford', 'Brookmere', 'Fairhaven', 'Kingsport', 'Northwood',
                  'Oakvale', 'Riverton', 'Stonebridge', 'Westfield', 'Millbrook'),
            'city|' . $id
        );
        $phone2 = sprintf('%02d', $this->intIn(10, 99, 'phone|' . $id));
        $ec = $this->pick(array('Jordan', 'Riley', 'Avery', 'Quinn', 'Sky', 'Reese', 'Blake', 'Sage'), 'ecf|' . $id)
            . ' ' . $p['last'];
        $ecRel = $this->pick(array('Spouse', 'Parent', 'Sibling', 'Partner'), 'ecrel|' . $id);
        $ecPhone2 = sprintf('%02d', $this->intIn(10, 99, 'ecphone|' . $id));

        return array(
            array('Full name', $p['name']),
            array('Employee ID', $id),
            array('Work email', $p['email']),
            array('Date of birth', '••/••/' . $dobYear),
            array('Tax ID (SSN)', '***-**-' . $ssn4),
            array('Home address', '••• ' . $street . ', ' . $city),
            array('Personal mobile', '+•• ••• ••• ••' . $phone2),
            array('Emergency contact', $ec . ' (' . $ecRel . ') · +•• ••• ••• ••' . $ecPhone2),
            array('Medical notes', 'Restricted — request access'),
        );
    }

    /**
     * The Employment tab: start date, tenure, manager chain and salary band — all coherent with Org.
     *
     * @return list<array{0:string,1:string}>
     */
    public function employment(string $empId): array
    {
        $p = $this->person($empId);
        $chain = $this->managerChain($empId);
        $chainNames = array();
        foreach ($chain as $c) {
            $chainNames[] = $c['name'];
        }
        $manager = $p['managerId'] === '' ? '—' : $this->managerName($p['managerId']);
        return array(
            array('Employee ID', $p['id']),
            array('Status', $p['status']),
            array('Start date', $this->startDate($p['tenureMonths'], $p['id'])),
            array('Tenure', $this->tenureText($p['tenureMonths'])),
            array('Department', $p['dept']),
            array('Title', $p['title']),
            array('Manager', $manager),
            array('Reporting line', $chainNames === array() ? '—' : implode(' › ', array_reverse($chainNames))),
            array('Salary band', $p['band']),
            array('Location', $p['location']),
            array('Desk', $p['deskId']),
            array('Extension', 'x' . $p['ext']),
            array('Work IP', $p['ip']),
        );
    }

    /**
     * The Compensation numbers: annual/monthly base (from Payroll's single source of truth) plus masked,
     * invalid-format bank and tax identifiers. Amounts are raw ints; the section formats them.
     *
     * @return array{band:string,annual:int,monthly:int,bankMasked:string,taxMasked:string}
     */
    public function compensation(string $empId): array
    {
        $p = $this->person($empId);
        $monthly = Payroll::monthlyGrossFor($this->seed, $p);
        $bank4 = sprintf('%04d', $this->intIn(1000, 9999, 'bank|' . $p['id']));
        $ssn4 = sprintf('%04d', $this->intIn(1000, 9999, 'ssn|' . $p['id'])); // matches personal() masking
        return array(
            'band' => $p['band'],
            'annual' => $monthly * 12,
            'monthly' => $monthly,
            'bankMasked' => '••••' . $bank4,
            'taxMasked' => '***-**-' . $ssn4,
        );
    }

    /**
     * PTO balance that reconciles: available = entitlement + carried; remaining = available - taken.
     *
     * @return array{entitlement:int,carried:int,available:int,taken:int,remaining:int,sick:int}
     */
    public function ptoBalance(string $empId): array
    {
        $p = $this->person($empId);
        $id = $p['id'];
        $entitlement = $this->intIn(18, 28, 'ptoent|' . $id);
        $carried = $this->intIn(0, 5, 'ptocar|' . $id);
        $available = $entitlement + $carried;
        $taken = $this->intIn(0, $available, 'ptotk|' . $id);
        return array(
            'entitlement' => $entitlement,
            'carried' => $carried,
            'available' => $available,
            'taken' => $taken,
            'remaining' => $available - $taken,
            'sick' => $this->intIn(0, 6, 'ptosick|' . $id),
        );
    }

    /**
     * Per-employee documents — contract, ID scan, screening, offer — as `.zip`-suffixed archive names
     * (the only extension the decoy handler serves: spec E8). All route to the decoy archive.
     *
     * @return list<array{file:string,cells:list<string>}>
     */
    public function documents(string $empId): array
    {
        $id = $this->slug($this->person($empId)['id']);
        return array(
            array('file' => 'employment_contract_' . $id . '.pdf.zip', 'cells' => array('Contract', 'Signed', $this->docSize($id, 'contract', 1500, 3000))),
            array('file' => 'passport_scan_' . $id . '.zip', 'cells' => array('ID document', 'On file', $this->docSize($id, 'idscan', 900, 2000))),
            array('file' => 'background_check_' . $id . '.pdf.zip', 'cells' => array('Screening', 'Cleared', $this->docSize($id, 'screening', 250, 500))),
            array('file' => 'offer_letter_' . $id . '.pdf.zip', 'cells' => array('Offer', 'Accepted', $this->docSize($id, 'offer', 150, 280))),
        );
    }

    /** A per-employee, per-doc-type file size ('2.4 MB' / '340 KB') — every employee's documents get
     *  their own seeded size instead of the whole roster sharing one hardcoded figure per doc type. */
    private function docSize(string $id, string $docType, int $minKB, int $maxKB): string
    {
        $kb = $this->intIn($minKB, $maxKB, 'docsize|' . $docType . '|' . $id);
        if ($kb >= 1024) {
            return number_format($kb / 1024, 1) . ' MB';
        }
        return $kb . ' KB';
    }

    // --- manager tree (org chart) ---

    /** The single root (CEO): the roster row whose manager is ''. */
    public function rootId(): string
    {
        foreach ($this->roster() as $p) {
            if ($p['managerId'] === '') {
                return $p['id'];
            }
        }
        return $this->roster()[0]['id'];
    }

    /** Direct-report person rows of a manager (empty for a leaf/unknown id). @return list<array> */
    public function directReports(string $empId): array
    {
        $out = array();
        foreach ($this->org->directReports($empId) as $childId) {
            $child = $this->org->person($childId);
            if ($child !== null) {
                $out[] = $child;
            }
        }
        return $out;
    }

    /**
     * The chain of managers above a person, immediate manager first up to the CEO. Bounded by the roster
     * size so a malformed tree can never loop.
     *
     * @return list<array>
     */
    public function managerChain(string $empId): array
    {
        $out = array();
        $cur = $this->org->person($empId);
        $guard = 0;
        $n = $this->org->headcount();
        while ($cur !== null && $cur['managerId'] !== '' && $guard < $n) {
            $mgr = $this->org->person($cur['managerId']);
            if ($mgr === null) {
                break;
            }
            $out[] = $mgr;
            $cur = $mgr;
            $guard++;
        }
        return $out;
    }

    // --- start-date / tenure math (off the frozen anchor) ---

    /** The hire date for a roster row (for the directory Start column), off the one frozen anchor. */
    public function hireDate(array $person): string
    {
        return $this->startDate($person['tenureMonths'], $person['id']);
    }

    private function startDate(int $tenureMonths, string $id): string
    {
        [$ay, $am] = self::anchorYearMonth();
        $total = $ay * 12 + ($am - 1) - $tenureMonths;
        if ($total < 0) {
            $total = 0;
        }
        $y = intdiv($total, 12);
        $mo = ($total % 12) + 1;
        $day = $this->intIn(1, 28, 'startday|' . $id);
        return sprintf('%04d-%02d-%02d', $y, $mo, $day);
    }

    private function tenureText(int $months): string
    {
        $y = intdiv($months, 12);
        $m = $months % 12;
        if ($y === 0) {
            return $m . ' mo';
        }
        if ($m === 0) {
            return $y . ' yr';
        }
        return $y . ' yr ' . $m . ' mo';
    }

    private function slug(string $s): string
    {
        $out = trim((string) preg_replace('/[^a-z0-9]+/', '-', strtolower($s)), '-');
        return $out === '' ? 'emp-0000' : $out;
    }
}
