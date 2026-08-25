<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Hr;
use Funnypot\App\Render\Fake\Payroll;
use Funnypot\App\Render\Panel\HrSection;
use Funnypot\App\Render\PanelRoute;
use Funnypot\Core\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class HrSectionTest extends TestCase
{
    /** Any address outside RFC1918 10.x is a leak of real routable space (SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    /** Render a panel path through the section exactly as the skin would (parse -> render). */
    private function render(string $path, int $seed = 7): string
    {
        $route = PanelRoute::parse($path);
        return (new HrSection())->render($route, VisualPersona::fromSeed($seed), '/admin');
    }

    // --- routing / depth ---

    public function test_landing_shows_tiles_and_module_links(): void
    {
        $html = $this->render('/admin/hr');
        self::assertStringContainsString('People · HR', $html);
        self::assertStringContainsString('Headcount', $html);
        self::assertStringContainsString('href="/admin/hr/employees"', $html);
        self::assertStringContainsString('href="/admin/hr/org"', $html);
        self::assertStringContainsString('href="/admin/hr/payroll"', $html);
    }

    public function test_directory_lists_employees_and_links_to_profiles(): void
    {
        $html = $this->render('/admin/hr/employees');
        self::assertStringContainsString('Employee directory', $html);
        self::assertStringContainsString('href="/admin/hr/employees/emp-', $html);
        // Export link is a .zip (the only extension the decoy archive handler serves — spec E8).
        self::assertStringContainsString('employees_2026-08.csv.zip', $html);
    }

    public function test_directory_paginates(): void
    {
        // Seed with a large enough roster to guarantee two pages.
        $seed = $this->seedWithHeadcountOver(50);
        $p1 = $this->render('/admin/hr/employees', $seed);
        $p2 = $this->render('/admin/hr/employees/p2', $seed);
        self::assertStringContainsString('page 1/', $p1);
        self::assertStringContainsString('page 2/', $p2);
        self::assertNotSame($p1, $p2, 'different pages render different rows');
    }

    public function test_department_filter_narrows_the_list(): void
    {
        $hr = Hr::fromSeed(7, VisualPersona::fromSeed(7)->domain());
        $depts = $hr->departments();
        self::assertNotEmpty($depts);
        $slug = $depts[0]['slug'];
        $html = $this->render('/admin/hr/employees/' . $slug, 7);
        self::assertStringContainsString($depts[0]['dept'], $html);
        self::assertStringContainsString('of ' . number_format($depts[0]['count']) . ' ', $html);
    }

    public function test_profile_subtabs_all_render(): void
    {
        foreach (['', '/employment', '/documents', '/leave'] as $sub) {
            $html = $this->render('/admin/hr/employees/emp-1001' . $sub);
            self::assertStringContainsString('alte-tabs', $html, "subtab $sub strip");
            self::assertNotSame('', trim($html), "subtab $sub non-empty");
        }
        // Personal tab masks PII; documents are .zip decoys; leave states the reconciliation.
        self::assertStringContainsString('Tax ID (SSN)', $this->render('/admin/hr/employees/emp-1001'));
        self::assertStringContainsString('.pdf.zip', $this->render('/admin/hr/employees/emp-1001/documents'));
        self::assertStringContainsString('Remaining', $this->render('/admin/hr/employees/emp-1001/leave'));
    }

    public function test_unknown_employee_still_renders_a_profile_not_a_404(): void
    {
        $html = $this->render('/admin/hr/employees/emp-999999');
        self::assertStringContainsString('fp-card', $html);
        self::assertStringContainsString('Edit profile', $html);
    }

    public function test_org_chart_renders_a_nested_tree(): void
    {
        $html = $this->render('/admin/hr/org');
        self::assertStringContainsString('Organisation chart', $html);
        self::assertStringContainsString('fp-orgtree', $html);
        self::assertStringContainsString('<ul', $html);
        self::assertStringContainsString('href="/admin/hr/employees/emp-', $html);
    }

    public function test_payroll_runs_list_and_detail_tabs(): void
    {
        $list = $this->render('/admin/hr/payroll');
        self::assertStringContainsString('Payroll runs', $list);
        self::assertStringContainsString('href="/admin/hr/payroll/run-2026-08"', $list);

        foreach (['', '/payslips', '/exceptions', '/gl', '/audit'] as $sub) {
            $html = $this->render('/admin/hr/payroll/run-2026-08' . $sub);
            self::assertStringContainsString('alte-tabs', $html, "run tab $sub");
        }
        self::assertStringContainsString('debits = credits', $this->render('/admin/hr/payroll/run-2026-08/gl'));
    }

    /** Realism: payroll audit-trail timestamps must not be one hardcoded literal repeated on every
     *  run's page — each run seeds its own times (still monotonic within the run). */
    public function test_payroll_audit_times_vary_per_run(): void
    {
        $a = $this->render('/admin/hr/payroll/run-2026-08/audit');
        $b = $this->render('/admin/hr/payroll/run-2026-06/audit');
        preg_match('/(\d{2}:\d{2}:\d{2})\s+run\.created/', $a, $timeA);
        preg_match('/(\d{2}:\d{2}:\d{2})\s+run\.created/', $b, $timeB);
        self::assertNotSame([], $timeA, 'run.created carries a HH:MM:SS timestamp');
        self::assertNotSame([], $timeB, 'run.created carries a HH:MM:SS timestamp');
        self::assertNotSame($timeA[1], $timeB[1], 'different runs must not share one hardcoded audit time');
    }

    public function test_payslip_detail_renders_with_ytd(): void
    {
        $html = $this->render('/admin/hr/payroll/run-2026-08/payslip/emp-1001');
        self::assertStringContainsString('Statement of earnings', $html);
        self::assertStringContainsString('YTD', $html);
        self::assertStringContainsString('Net pay', $html);
    }

    // --- arithmetic closes (the whole point of the greed lure) ---

    public function test_payslip_arithmetic_closes(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $pay = Payroll::fromSeed($seed);
            $ps = $pay->payslip('run-2026-08', 'emp-1001');

            $dedSum = 0;
            foreach ($ps['deductions'] as $d) {
                $dedSum += $d[1];
            }
            self::assertSame($ps['deductionsTotal'], $dedSum, "seed $seed: deduction lines sum to total");
            self::assertSame($ps['gross'] - $ps['deductionsTotal'], $ps['net'], "seed $seed: gross − deductions = net");

            // YTD = current * monthNumber, and YTD net reconciles the same way.
            $m = $ps['monthNumber'];
            self::assertSame($ps['gross'] * $m, $ps['ytdGross'], "seed $seed: YTD gross = Σ");
            self::assertSame($ps['deductionsTotal'] * $m, $ps['ytdDeductions'], "seed $seed: YTD deductions = Σ");
            self::assertSame($ps['ytdGross'] - $ps['ytdDeductions'], $ps['ytdNet'], "seed $seed: YTD net closes");
        }
    }

    public function test_run_totals_equal_sum_of_payslips(): void
    {
        for ($seed = 0; $seed < 5; $seed++) {
            $pay = Payroll::fromSeed($seed);
            $run = $pay->run('run-2026-08');
            $gross = 0;
            $ded = 0;
            $net = 0;
            $offset = 0;
            do {
                $page = $pay->payslipsPage('run-2026-08', $offset, 50);
                foreach ($page as $row) {
                    $gross += $row['gross'];
                    $ded += $row['deductions'];
                    $net += $row['net'];
                }
                $offset += 50;
            } while ($page !== []);
            self::assertSame($run['gross'], $gross, "seed $seed: run gross = Σ payslips");
            self::assertSame($run['deductions'], $ded, "seed $seed: run deductions = Σ payslips");
            self::assertSame($run['net'], $net, "seed $seed: run net = Σ payslips");
            self::assertSame($run['gross'], $run['net'] + $run['deductions'], "seed $seed: gross = net + deductions");
        }
    }

    /** Realism: the 20-month register must not be one figure copy-pasted down the page — historical
     *  runs vary (hires + a raise cadence) while every run still reconciles internally. */
    public function test_payroll_runs_vary_across_months(): void
    {
        for ($seed = 0; $seed < 5; $seed++) {
            $pay = Payroll::fromSeed($seed);
            $signatures = [];
            foreach ($pay->runs() as $r) {
                self::assertSame($r['gross'], $r['net'] + $r['deductions'], "seed $seed run {$r['id']}: gross = net + deductions");
                self::assertGreaterThan(0, $r['net'], "seed $seed run {$r['id']}: net stays positive");
                $signatures[] = $r['headcount'] . ':' . $r['gross'] . ':' . $r['net'];
            }
            self::assertGreaterThan(1, count(array_unique($signatures)), "seed $seed: the register must not be byte-identical every month");
        }
    }

    public function test_annual_is_twelve_times_monthly(): void
    {
        $person = ['id' => 'emp-1001', 'band' => 'M4'];
        $monthly = Payroll::monthlyGrossFor(3, $person);
        self::assertSame($monthly * 12, Payroll::fromSeed(3)->annualGrossFor($person));
    }

    public function test_pto_balance_reconciles(): void
    {
        $hr = Hr::fromSeed(4, VisualPersona::fromSeed(4)->domain());
        for ($i = 1001; $i < 1012; $i++) {
            $b = $hr->ptoBalance('emp-' . $i);
            self::assertSame($b['entitlement'] + $b['carried'], $b['available'], "emp-$i available");
            self::assertSame($b['available'] - $b['taken'], $b['remaining'], "emp-$i remaining");
            self::assertGreaterThanOrEqual(0, $b['remaining'], "emp-$i remaining non-negative");
        }
    }

    /** Realism: DOB must stay coherent with the hire date — nobody was hired under 18. */
    public function test_no_employee_hired_under_18(): void
    {
        for ($seed = 0; $seed < 8; $seed++) {
            $hr = Hr::fromSeed($seed, 'x.example');
            $n = $hr->headcount();
            for ($i = 1001; $i < 1001 + $n; $i++) {
                $id = 'emp-' . $i;
                $personal = $hr->personal($id);
                $dobYear = null;
                foreach ($personal as $row) {
                    if ($row[0] === 'Date of birth') {
                        preg_match('/(\d{4})$/', $row[1], $m);
                        $dobYear = (int) $m[1];
                    }
                }
                $hireYear = (int) substr($hr->hireDate($hr->person($id)), 0, 4);
                self::assertGreaterThanOrEqual(18, $hireYear - $dobYear, "seed $seed $id: hired under 18 (dob=$dobYear hire=$hireYear)");
            }
        }
    }

    /** Realism: per-employee HR document sizes must not all share the whole roster's one hardcoded
     *  figure per doc type. */
    public function test_employee_document_sizes_vary_per_employee(): void
    {
        $hr = Hr::fromSeed(3, 'x.example');
        $sizes = [];
        for ($i = 1001; $i < 1011; $i++) {
            $docs = $hr->documents('emp-' . $i);
            $sizes[] = $docs[0]['cells'][2];   // the Contract row's size column
        }
        self::assertGreaterThan(1, count(array_unique($sizes)), 'contract sizes must vary across employees');
    }

    // --- guarded money verbs (never "done"/"paid") ---

    public function test_run_payroll_is_a_guarded_soft_deny(): void
    {
        $html = $this->render('/admin/hr/payroll/run-2026-08/run');
        self::assertStringContainsString('Denied', $html);
        self::assertStringContainsStringIgnoringCase('dual authorization', $html);
        self::assertStringContainsString('NOT executed', $html);
        self::assertStringNotContainsString('Queued', $html);       // never a success receipt
    }

    public function test_approve_run_is_the_two_person_rule_and_never_pays(): void
    {
        // First step is a confirmation gate; nothing recorded yet.
        $gate = $this->render('/admin/hr/payroll/run-2026-08/approve');
        self::assertStringContainsString('Type', $gate);
        self::assertStringContainsString('APPROVE', $gate);

        // Confirming records 1 of 2 and waits on a second approver who never signs — nothing is paid.
        $confirm = $this->render('/admin/hr/payroll/run-2026-08/approve/confirm');
        self::assertStringContainsString('1 of 2', $confirm);
        self::assertStringContainsStringIgnoringCase('awaiting', $confirm);
        self::assertStringContainsString('Nothing has been paid', $confirm);
    }

    public function test_edit_profile_saves_over_the_unchanged_profile(): void
    {
        $form = $this->render('/admin/hr/employees/emp-1001/edit');
        self::assertStringContainsString('<form', $form);
        $saved = $this->render('/admin/hr/employees/emp-1001/edit/saved');
        self::assertStringContainsString('Profile changes saved', $saved);
        self::assertStringContainsString('HRC-', $saved);
        // The masked PII is still shown after "saving" (nothing persisted).
        self::assertStringContainsString('Tax ID (SSN)', $saved);
    }

    // --- safety invariants ---

    public function test_one_host_one_domain_for_every_email(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $domain = VisualPersona::fromSeed($seed)->domain();
            $html = $this->render('/admin/hr/employees/emp-1001', $seed);
            self::assertSame(1, preg_match_all('/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/', $html, $m), "seed $seed: exactly one email");
            foreach ($m[0] as $email) {
                self::assertStringEndsWith('@' . $domain, $email, "seed $seed: email on the one persona domain");
            }
        }
    }

    public function test_pii_is_masked_and_no_valid_ssn_leaks(): void
    {
        $html = $this->render('/admin/hr/employees/emp-1001');
        self::assertStringContainsString('***-**-', $html, 'SSN masked');
        self::assertStringContainsString('••', $html, 'values masked at rest');
        // No full ###-##-#### SSN pattern is ever emitted.
        self::assertDoesNotMatchRegularExpression('/\b\d{3}-\d{2}-\d{4}\b/', $html, 'no full SSN');
    }

    public function test_no_public_ip_in_any_view(): void
    {
        $paths = [
            '/admin/hr', '/admin/hr/employees', '/admin/hr/employees/emp-1001',
            '/admin/hr/employees/emp-1001/employment', '/admin/hr/org',
            '/admin/hr/payroll', '/admin/hr/payroll/run-2026-08/payslips',
            '/admin/hr/payroll/run-2026-08/payslip/emp-1001', '/admin/hr/payroll/run-2026-08/run',
        ];
        for ($seed = 0; $seed < 6; $seed++) {
            foreach ($paths as $p) {
                self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $this->render($p, $seed), "seed $seed path $p");
            }
        }
    }

    public function test_reflected_slug_is_escaped_no_script_breakout(): void
    {
        // Slugging strips angle brackets before routing; nothing reflected can break out of HTML.
        $html = $this->render('/admin/hr/employees/emp-%3Cscript%3Ealert(1)%3C-script%3E');
        self::assertStringNotContainsString('<script>alert(1)', $html);
    }

    // --- determinism ---

    public function test_same_url_is_byte_identical(): void
    {
        foreach ([
            '/admin/hr', '/admin/hr/employees', '/admin/hr/employees/emp-1001',
            '/admin/hr/org', '/admin/hr/payroll/run-2026-08/payslip/emp-1001',
        ] as $p) {
            self::assertSame($this->render($p, 11), $this->render($p, 11), "stable: $p");
        }
    }

    public function test_generators_are_deterministic(): void
    {
        self::assertEquals(Payroll::fromSeed(5)->runs(), Payroll::fromSeed(5)->runs());
        self::assertEquals(
            Hr::fromSeed(5, 'x.example')->personal('emp-1001'),
            Hr::fromSeed(5, 'x.example')->personal('emp-1001')
        );
        self::assertNotEquals(Payroll::fromSeed(1)->run('run-2026-08'), Payroll::fromSeed(2)->run('run-2026-08'));
    }

    // --- helpers ---

    /** Find a seed whose roster exceeds $min people, so pagination tests always have >1 page. */
    private function seedWithHeadcountOver(int $min): int
    {
        for ($seed = 0; $seed < 200; $seed++) {
            if (Hr::fromSeed($seed, 'x.example')->headcount() > $min) {
                return $seed;
            }
        }
        self::fail('no seed produced a roster over ' . $min);
    }
}
