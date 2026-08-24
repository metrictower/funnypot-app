<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT payroll for the deep office panel — the monthly run register and per-employee
 * payslips. It is a VIEW over the one `Org` roster (never a second headcount), so every payslip name,
 * department and band agrees with the directory, the org chart and the finance payroll runs.
 *
 * Design rules (deep-admin dashboard spec §C.5 + adversarial critique):
 *  - COHERENT ARITHMETIC (the whole point): one canonical MONTHLY gross per person is the single source
 *    of truth (monthlyGrossFor()) — the CURRENT figure every run converges toward. Older runs perturb it
 *    a little (a seeded pre-raise discount + a seeded hire cutoff dropping the newest hires) so the
 *    20-month register isn't one figure copy-pasted down the page, the way a real payroll history isn't
 *    flat; every period still closes on its own terms: gross - Σdeductions = net by construction (net is
 *    the remainder); YTD = line * monthNumber (salary is constant across the fiscal year) so YTD closes
 *    column by column; a run's totals = Σ that run's payslips. An attacker who adds it up finds it
 *    consistent, period by period.
 *  - DETERMINISTIC per seed: every value is hash(seed+slot) -> vocab index or [min,max]. No
 *    time()/date()/rand()/shuffle(); "now" is one frozen anchor period (ANCHOR_YEAR/ANCHOR_MONTH), so a
 *    static reload is byte-identical and never a tell.
 *  - SAFE: no real bank/tax numbers live here (the HR profile masks those); this layer is money amounts
 *    only. No real employer, no scanner-signature string.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/intdiv, no enums/promotion/str_contains) so a fact can
 *    promote into a core template unchanged when one needs it.
 *
 * Returns plain data only — the section renders, formats and escapes it.
 */
final class Payroll
{
    /** Frozen "now": the latest (current) pay period, read from the one shared clock (no date()/time()). */
    public const ANCHOR_YEAR = FrozenClock::YEAR;
    public const ANCHOR_MONTH = FrozenClock::MONTH;

    /** How many monthly runs the register goes back (frozen, deterministic). */
    public const RUN_HISTORY = 20;

    /** @var int */
    private $seed;

    /** @var Org */
    private $org;

    /** @var array<int,array>|null cached roster so deep run/payslip pages stay cheap */
    private $rosterCache = null;

    private function __construct(int $seed, string $personaDomain)
    {
        $this->seed = $seed;
        $this->org = Org::fromSeed($seed, $personaDomain);
    }

    /**
     * Build payroll for a seed. Callers pass the host persona domain so any address the roster renders
     * stays on the one host domain; payroll itself shows amounts and names, not emails.
     */
    public static function fromSeed(int $seed, string $personaDomain = ''): self
    {
        return new self($seed, $personaDomain);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|pay|' . $salt), 0, 15));
    }

    private function intIn(int $min, int $max, string $salt): int
    {
        return $min + ($this->h($salt) % (($max - $min) + 1));
    }

    // --- canonical salary (single source of truth, shared with Fake\Hr) ---

    /**
     * The canonical MONTHLY gross for a person, in whole currency units. Everything reconciles off this:
     * annual = monthly*12, every run's payslip repeats it, YTD = monthly * monthNumber. Pure hash(seed+id),
     * so Fake\Hr's compensation tab and every payslip agree without either instance touching the other.
     *
     * @param array{band?:string,id?:string} $person
     */
    public static function monthlyGrossFor(int $seed, array $person): int
    {
        $ranges = array(
            'EX' => array(260000, 420000),
            'M5' => array(185000, 260000),
            'M4' => array(145000, 195000),
            'M3' => array(115000, 150000),
            'IC4' => array(105000, 140000),
            'IC3' => array(88000, 118000),
            'IC2' => array(72000, 96000),
            'IC1' => array(58000, 78000),
        );
        $band = isset($person['band']) ? $person['band'] : 'IC2';
        $r = isset($ranges[$band]) ? $ranges[$band] : array(72000, 96000); // deeper IC levels -> IC2 band
        $id = isset($person['id']) ? $person['id'] : 'emp-0000';
        $span = $r[1] - $r[0];
        $raw = $r[0] + ((int) hexdec(substr(hash('sha256', $seed . '|salary|' . $id), 0, 15)) % ($span + 1));
        // Snap the annual to a multiple of 1200 so annual/12 is an exact whole monthly (arithmetic closes).
        $annual = ((int) round($raw / 1200)) * 1200;
        return intdiv($annual, 12);
    }

    /** Annual gross = monthly*12 (the value the HR compensation tab shows). */
    public function annualGrossFor(array $person): int
    {
        return self::monthlyGrossFor($this->seed, $person) * 12;
    }

    /** Progressive-ish deduction rate by band — higher band, higher marginal rate. */
    private function taxRatePct(string $band): int
    {
        if ($band === 'EX' || $band === 'M5') {
            return 32;
        }
        if ($band === 'M4' || $band === 'M3') {
            return 27;
        }
        return 22;
    }

    /**
     * How many months back a run id is from the anchor (0 = the current period). Clamped to >= 0 so a
     * malformed/future id can never read as "before now".
     */
    private function monthsBackFor(int $y, int $mo): int
    {
        $anchorTotal = self::ANCHOR_YEAR * 12 + (self::ANCHOR_MONTH - 1);
        $total = $y * 12 + ($mo - 1);
        $k = $anchorTotal - $total;
        return $k < 0 ? 0 : $k;
    }

    /**
     * The gross for a specific run, $k months back from the anchor. Most employees show the same
     * current gross in every run (their last raise predates the whole RUN_HISTORY window); a seeded
     * minority had their last raise WITHIN the window, so runs older than that raise show a slightly
     * smaller pre-raise figure — real payroll history steps up over time rather than repeating one
     * flat number, while every figure here stays pure hash(seed+id+k).
     */
    private function monthlyGrossForPeriod(array $person, int $k): int
    {
        $current = self::monthlyGrossFor($this->seed, $person);
        if ($k <= 0) {
            return $current;
        }
        $id = isset($person['id']) ? $person['id'] : 'emp-0000';
        $raiseAt = $this->h('raiseat|' . $id) % 40;   // months-back of the last raise; >= RUN_HISTORY -> predates the register
        if ($k <= $raiseAt) {
            return $current;
        }
        $cutPct = 100 - (3 + ($this->h('raisecut|' . $id) % 6));   // pre-raise gross is 3-8% lower
        return intdiv($current * $cutPct, 100);
    }

    /**
     * One person's month numbers for a specific run ($k months back). Gross is that period's own
     * figure (monthlyGrossForPeriod), so a payslip and its run total can never disagree; net is the
     * remainder (gross - Σdeductions), so gross - deductions = net is true by construction for every
     * period, not just the current one.
     *
     * @return array{gross:int,tax:int,pension:int,fica:int,health:int,ded:int,net:int}
     */
    private function personNumbersForPeriod(array $person, int $k): array
    {
        $gross = $this->monthlyGrossForPeriod($person, $k);
        $band = isset($person['band']) ? $person['band'] : 'IC2';
        $id = isset($person['id']) ? $person['id'] : 'emp-0000';
        $tax = intdiv($gross * $this->taxRatePct($band), 100);
        $pension = intdiv($gross * 5, 100);
        $fica = intdiv($gross * 6, 100);
        $health = $this->intIn(180, 420, 'health|' . $id);
        $ded = $tax + $pension + $fica + $health;
        return array(
            'gross' => $gross,
            'tax' => $tax,
            'pension' => $pension,
            'fica' => $fica,
            'health' => $health,
            'ded' => $ded,
            'net' => $gross - $ded,
        );
    }

    /**
     * The roster as it stood $k months back: a seeded minority of employees (whoever has less tenure
     * than $k months, per Org's own tenure figure) hadn't been hired yet, so older runs show a smaller
     * headcount that grows toward today's — reusing Org's existing per-employee tenure rather than a
     * second independent hire model, so the two can never disagree.
     *
     * @return list<array>
     */
    private function rosterForPeriod(int $k): array
    {
        if ($k <= 0) {
            return $this->roster();
        }
        $out = array();
        foreach ($this->roster() as $p) {
            $tenure = isset($p['tenureMonths']) ? $p['tenureMonths'] : 999;
            if ($tenure >= $k) {
                $out[] = $p;
            }
        }
        return $out;
    }

    // --- runs ---

    /**
     * The run register, newest first (ANCHOR back RUN_HISTORY months). Every run reconciles its own
     * totals from the roster, so the register footer and each run detail always agree.
     *
     * @return list<array{id:string,period:string,payDate:string,year:int,monthNumber:int,status:string,headcount:int,gross:int,deductions:int,net:int}>
     */
    public function runs(): array
    {
        $out = array();
        for ($k = 0; $k < self::RUN_HISTORY; $k++) {
            $out[] = $this->run($this->runIdBack($k));
        }
        return $out;
    }

    /** The run id k whole months before the anchor, e.g. k=0 -> current period. */
    private function runIdBack(int $k): string
    {
        $total = self::ANCHOR_YEAR * 12 + (self::ANCHOR_MONTH - 1) - $k;
        $y = intdiv($total, 12);
        $mo = ($total % 12) + 1;
        return sprintf('run-%04d-%02d', $y, $mo);
    }

    /**
     * One run by id. A malformed/unknown id falls back to the anchor period (a 404 inside the panel is a
     * tell). The latest period reads "Awaiting approval"; every prior period is "Completed".
     *
     * @return array{id:string,period:string,payDate:string,year:int,monthNumber:int,status:string,headcount:int,gross:int,deductions:int,net:int}
     */
    public function run(string $runId): array
    {
        $ym = $this->parseRunId($runId);
        $y = $ym[0];
        $mo = $ym[1];
        $day = $this->intIn(24, 27, 'payday|' . $y . '-' . $mo);
        $anchor = $y === self::ANCHOR_YEAR && $mo === self::ANCHOR_MONTH;
        $totals = $this->runTotals($this->monthsBackFor($y, $mo));
        return array(
            'id' => sprintf('run-%04d-%02d', $y, $mo),
            'period' => $this->monthName($mo) . ' ' . $y,
            'payDate' => sprintf('%04d-%02d-%02d', $y, $mo, $day),
            'year' => $y,
            'monthNumber' => $mo,
            'status' => $anchor ? 'Awaiting approval' : 'Completed',
            'headcount' => $totals['headcount'],
            'gross' => $totals['gross'],
            'deductions' => $totals['deductions'],
            'net' => $totals['net'],
        );
    }

    /** Run totals = Σ over that period's roster of each person's month numbers, so total = Σ payslips
     *  exactly for that run — never a different, independently-seeded figure. */
    private function runTotals(int $k): array
    {
        $gross = 0;
        $ded = 0;
        $net = 0;
        $roster = $this->rosterForPeriod($k);
        foreach ($roster as $p) {
            $num = $this->personNumbersForPeriod($p, $k);
            $gross += $num['gross'];
            $ded += $num['ded'];
            $net += $num['net'];
        }
        return array(
            'headcount' => count($roster),
            'gross' => $gross,
            'deductions' => $ded,
            'net' => $net,
        );
    }

    /** The current period's total net payroll (whole dollars) — the one figure Bank sizes the Payroll
     *  funding account off, so that account can always cover at least this seed's real monthly run. */
    public function currentNet(): int
    {
        return $this->runTotals(0)['net'];
    }

    /** run-YYYY-MM -> [year, month]; anything malformed becomes the anchor period. @return array{0:int,1:int} */
    private function parseRunId(string $runId): array
    {
        if (preg_match('/^run-([0-9]{4})-([0-9]{2})$/', $runId, $m) === 1) {
            $mo = (int) $m[2];
            if ($mo >= 1 && $mo <= 12) {
                return array((int) $m[1], $mo);
            }
        }
        return array(self::ANCHOR_YEAR, self::ANCHOR_MONTH);
    }

    // --- payslips ---

    /**
     * One page of a run's payslip register by absolute offset, so a deep page renders identically and
     * instantly. Each row carries the amounts the payslip page recomputes.
     *
     * @return list<array{empId:string,name:string,dept:string,gross:int,deductions:int,net:int}>
     */
    public function payslipsPage(string $runId, int $offset, int $limit): array
    {
        $ym = $this->parseRunId($runId);
        $periodK = $this->monthsBackFor($ym[0], $ym[1]);
        $roster = $this->rosterForPeriod($periodK);
        if ($offset < 0) {
            $offset = 0;
        }
        $out = array();
        for ($j = 0; $j < $limit; $j++) {
            $i = $offset + $j;
            if ($i >= count($roster)) {
                break;
            }
            $p = $roster[$i];
            $num = $this->personNumbersForPeriod($p, $periodK);
            $out[] = array(
                'empId' => $p['id'],
                'name' => $p['name'],
                'dept' => $p['dept'],
                'gross' => $num['gross'],
                'deductions' => $num['ded'],
                'net' => $num['net'],
            );
        }
        return $out;
    }

    /**
     * One payslip: earnings/deductions lines that reconcile (gross - Σdeductions = net) and a YTD column
     * (= line * monthNumber). An unknown employee slug still yields a plausible payslip (D.4).
     *
     * @return array{empId:string,name:string,title:string,dept:string,runId:string,period:string,payDate:string,monthNumber:int,earnings:list<array{0:string,1:int}>,deductions:list<array{0:string,1:int}>,gross:int,deductionsTotal:int,net:int,ytdGross:int,ytdDeductions:int,ytdNet:int}
     */
    public function payslip(string $runId, string $empId): array
    {
        $run = $this->run($runId);
        $person = $this->personOrSynthetic($empId);
        $periodK = $this->monthsBackFor($run['year'], $run['monthNumber']);
        $num = $this->personNumbersForPeriod($person, $periodK);
        $m = $run['monthNumber'];

        $earnings = array(
            array('Base salary', $num['gross']),
        );
        $deductions = array(
            array('Federal income tax', $num['tax']),
            array('Retirement 401(k)', $num['pension']),
            array('Payroll tax (FICA)', $num['fica']),
            array('Health insurance', $num['health']),
        );

        return array(
            'empId' => $person['id'],
            'name' => $person['name'],
            'title' => isset($person['title']) ? $person['title'] : 'Employee',
            'dept' => isset($person['dept']) ? $person['dept'] : 'Operations',
            'runId' => $run['id'],
            'period' => $run['period'],
            'payDate' => $run['payDate'],
            'monthNumber' => $m,
            'earnings' => $earnings,
            'deductions' => $deductions,
            'gross' => $num['gross'],
            'deductionsTotal' => $num['ded'],
            'net' => $num['net'],
            'ytdGross' => $num['gross'] * $m,
            'ytdDeductions' => $num['ded'] * $m,
            'ytdNet' => $num['net'] * $m,
        );
    }

    /** Deterministic, inert approval ref = hash(seed+slot): stable per path, varies per deploy (D.5). */
    public function approvalRef(string $slot): string
    {
        return 'PR-APR-' . strtoupper(substr(hash('sha256', $this->seed . '|prapr|' . $slot), 0, 6));
    }

    /** The second approver the two-person rule waits on — a real roster name that never actually signs. */
    public function secondApprover(): array
    {
        $roster = $this->roster();
        // A senior signer: scan for the first executive/M5 band, else fall back to the CEO row.
        foreach ($roster as $p) {
            if ($p['band'] === 'M5') {
                return $p;
            }
        }
        return $roster[0];
    }

    public function headcount(): int
    {
        return $this->org->headcount();
    }

    // --- roster + synthesis ---

    /** The full roster, cached (index i is emp-(1001+i), matching the directory order). */
    private function roster(): array
    {
        if ($this->rosterCache === null) {
            $this->rosterCache = $this->org->people($this->org->headcount());
        }
        return $this->rosterCache;
    }

    /** A known employee, or a plausible synthetic IC record for a fuzzed slug (never a 404). */
    private function personOrSynthetic(string $empId): array
    {
        $p = $this->org->person($empId);
        if ($p !== null) {
            return $p;
        }
        return array(
            'id' => $this->slug($empId),
            'name' => $this->prettyName($empId),
            'band' => 'IC2',
            'title' => 'Operations Associate',
            'dept' => 'Operations',
        );
    }

    private function slug(string $s): string
    {
        $out = trim((string) preg_replace('/[^a-z0-9]+/', '-', strtolower($s)), '-');
        return $out === '' ? 'emp-0000' : $out;
    }

    private function prettyName(string $id): string
    {
        $base = strpos($id, 'emp-') === 0 ? substr($id, strlen('emp-')) : $id;
        $words = explode('-', $this->slug($base));
        $out = array();
        foreach ($words as $w) {
            if ($w !== '') {
                $out[] = ucfirst($w);
            }
        }
        return $out === array() ? 'Employee' : 'Employee ' . implode(' ', $out);
    }

    private function monthName(int $mo): string
    {
        $names = array('January', 'February', 'March', 'April', 'May', 'June',
                       'July', 'August', 'September', 'October', 'November', 'December');
        return isset($names[$mo - 1]) ? $names[$mo - 1] : 'Month ' . $mo;
    }
}
