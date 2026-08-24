<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Bank;
use Funnypot\App\Render\Fake\Finance;
use Funnypot\App\Render\Fake\FrozenClock;
use Funnypot\App\Render\Fake\Org;
use Funnypot\App\Render\Fake\Payroll;
use Funnypot\App\Render\Fake\Vendors;
use Funnypot\App\Render\Panel\FinanceSection;
use Funnypot\App\Render\PanelRoute;
use Funnypot\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class FinanceSectionTest extends TestCase
{
    /** Any address outside RFC1918 10.x is a leak of real routable space (spec SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    /** Render a panel path through the section exactly as the skin would (parse -> render). */
    private function render(string $path, int $seed = 7): string
    {
        $route = PanelRoute::parse($path);
        return (new FinanceSection())->render($route, VisualPersona::fromSeed($seed), '/admin');
    }

    // --- routing / depth ---

    public function test_dashboard_shows_ap_tiles_and_aging(): void
    {
        $html = $this->render('/admin/finance');
        self::assertStringContainsString('Finance', $html);
        self::assertStringContainsString('AP outstanding', $html);
        self::assertStringContainsString('AP aging', $html);
        // Jump-off links route back under the finance module.
        self::assertStringContainsString('href="/admin/finance/ap"', $html);
    }

    public function test_unknown_section_falls_back_to_dashboard(): void
    {
        // A 404 inside a deep panel is a tell; an unknown section renders the dashboard.
        $html = $this->render('/admin/finance/not-a-real-section');
        self::assertStringContainsString('AP aging', $html);
    }

    public function test_invoice_list_paginates(): void
    {
        $p1 = $this->render('/admin/finance/ap');
        $p2 = $this->render('/admin/finance/ap/p2');
        self::assertStringContainsString('page 1/', $p1);
        self::assertStringContainsString('page 2/', $p2);
        self::assertNotSame($p1, $p2, 'different pages render different rows');
        self::assertStringContainsString('href="/admin/finance/ap/inv-', $p1);
    }

    public function test_invoice_detail_and_subtabs_render(): void
    {
        foreach (['', '/lines', '/approval', '/attachments'] as $sub) {
            $html = $this->render('/admin/finance/ap/inv-2026-004001' . $sub);
            self::assertStringContainsString('INV-2026-004001', $html, "subtab $sub");
            self::assertNotSame('', trim($html), "subtab $sub non-empty");
        }
    }

    public function test_unknown_invoice_slug_still_renders_a_plausible_detail(): void
    {
        // A fuzzed slug must not dead-end.
        $html = $this->render('/admin/finance/ap/inv-does-not-exist-9999999');
        self::assertStringContainsString('fp-card', $html);
        self::assertStringContainsString('Line items', $html);
    }

    public function test_expense_list_and_detail_render(): void
    {
        $list = $this->render('/admin/finance/expenses');
        self::assertStringContainsString('Expense reports', $list);
        self::assertStringContainsString('href="/admin/finance/expenses/exp-', $list);

        $detail = $this->render('/admin/finance/expenses/exp-2026-002001');
        self::assertStringContainsString('EXP-2026-002001', $detail);
        // Receipts are decoy .zip archives (the only extension the decoy handler serves — spec E8).
        self::assertStringContainsString('.pdf.zip', $detail);
    }

    public function test_audit_log_scroll_renders(): void
    {
        $html = $this->render('/admin/finance/audit');
        self::assertStringContainsString('<pre', $html);
        self::assertStringContainsString('Finance audit log', $html);
    }

    public function test_all_downloads_end_in_zip(): void
    {
        // Every download under the panel mount must end .zip/.tar.gz (spec E8).
        $paths = ['/admin/finance/ap/inv-2026-004001/attachments', '/admin/finance/expenses/exp-2026-002001'];
        foreach ($paths as $p) {
            $html = $this->render($p);
            self::assertMatchesRegularExpression('/finance\/download\/[A-Za-z0-9._-]+\.(zip|tar\.gz)"/', $html, $p);
        }
    }

    // --- inert-control behaviour: guarded money verbs deny, never "paid" ---

    public function test_invoice_approve_is_a_canned_queue(): void
    {
        $html = $this->render('/admin/finance/ap/inv-2026-004001/approve');
        self::assertStringContainsString('Queued', $html);
        self::assertStringNotContainsString('Denied', $html);
    }

    public function test_pay_now_is_a_guarded_four_eyes_soft_deny(): void
    {
        $html = $this->render('/admin/finance/ap/inv-2026-004001/pay');
        self::assertStringContainsString('Denied', $html);
        self::assertStringContainsStringIgnoringCase('second', $html);
        self::assertStringContainsString('FIN-CMD-', $html);
        // A guarded money verb must never claim the money moved.
        self::assertStringNotContainsString('Queued', $html);
        self::assertStringNotContainsStringIgnoringCase('payment sent', $html);
        self::assertStringNotContainsStringIgnoringCase('paid in full', $html);
    }

    public function test_edit_remit_is_a_dual_approval_soft_deny(): void
    {
        $html = $this->render('/admin/finance/ap/inv-2026-004001/edit-remit');
        self::assertStringContainsString('Denied', $html);
        self::assertStringContainsStringIgnoringCase('dual approval', $html);
        self::assertStringNotContainsString('Queued', $html);
    }

    public function test_expense_reimburse_is_a_guarded_soft_deny(): void
    {
        $html = $this->render('/admin/finance/expenses/exp-2026-002001/reimburse');
        self::assertStringContainsString('Denied', $html);
        self::assertStringContainsStringIgnoringCase('second approver', $html);
        self::assertStringNotContainsString('Queued', $html);
    }

    public function test_no_control_path_emits_a_raw_script_injection(): void
    {
        // Slugging strips angle brackets before routing; nothing reflected can break out of HTML.
        $html = $this->render('/admin/finance/ap/%3Cscript%3Ealert(1)%3C-script%3E');
        self::assertStringNotContainsString('<script>alert', $html);
    }

    // --- determinism ---

    public function test_same_url_is_byte_identical(): void
    {
        foreach ([
            '/admin/finance',
            '/admin/finance/ap',
            '/admin/finance/ap/inv-2026-004010',
            '/admin/finance/ap/inv-2026-004010/lines',
            '/admin/finance/expenses/exp-2026-002005',
            '/admin/finance/audit',
        ] as $p) {
            self::assertSame($this->render($p, 11), $this->render($p, 11), "stable: $p");
        }
    }

    // --- safety invariants ---

    public function test_no_public_ip_in_any_view(): void
    {
        $paths = ['/admin/finance', '/admin/finance/ap', '/admin/finance/ap/inv-2026-004001/approval',
                  '/admin/finance/expenses/exp-2026-002001', '/admin/finance/audit'];
        for ($seed = 0; $seed < 8; $seed++) {
            foreach ($paths as $p) {
                self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $this->render($p, $seed), "seed $seed path $p");
            }
        }
    }

    public function test_bank_detail_is_masked_and_non_validating(): void
    {
        $html = $this->render('/admin/finance/ap/inv-2026-004001');
        self::assertStringContainsString('••••', $html, 'account masked');
        // Remit-to is the shared Fake\Vendors record: the IBAN carries the always-invalid "00" check
        // digits (ISO 13616 forbids 00/01), so a copied value validates against nothing.
        self::assertMatchesRegularExpression('/[A-Z]{2}00 •••• •••• •••• ••\d{2}/', $html, 'IBAN masked + invalid check digits');
    }

    public function test_every_email_is_at_the_one_persona_domain(): void
    {
        // One host = one domain: any email shown must be at the persona domain, never a second one.
        for ($seed = 0; $seed < 6; $seed++) {
            $persona = VisualPersona::fromSeed($seed);
            $domain = $persona->domain();
            foreach (['/admin/finance/ap/inv-2026-004001/approval', '/admin/finance/expenses/exp-2026-002001'] as $p) {
                $html = $this->render($p, $seed);
                if (preg_match_all('/[a-z0-9._-]+@([a-z0-9.-]+)/i', $html, $m) > 0) {
                    foreach ($m[1] as $d) {
                        self::assertSame($domain, $d, "seed $seed path $p email domain");
                    }
                }
            }
        }
    }

    // --- generator-level checks: arithmetic closes ---

    public function test_generator_deterministic(): void
    {
        $a = Finance::fromSeed(5, 'example.test');
        $b = Finance::fromSeed(5, 'example.test');
        self::assertSame($a->dashboard(), $b->dashboard());
        self::assertSame($a->invoiceAt(0), $b->invoiceAt(0));
        self::assertSame($a->expenseAt(0), $b->expenseAt(0));
        self::assertSame($a->auditLog(20), $b->auditLog(20));
    }

    public function test_invoice_arithmetic_closes(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $fin = Finance::fromSeed($seed, 'example.test');
            for ($i = 0; $i < 40; $i++) {
                $inv = $fin->invoiceAt($i);
                // line items sum to subtotal
                $lineSum = 0;
                foreach ($inv['lines'] as $line) {
                    self::assertSame($line['qty'] * $line['unitCents'], $line['lineCents'], "seed $seed inv $i line");
                    $lineSum += $line['lineCents'];
                }
                self::assertSame($inv['subtotalCents'], $lineSum, "seed $seed inv $i subtotal");
                // subtotal + tax − discount = total
                self::assertSame(
                    $inv['subtotalCents'] + $inv['taxCents'] - $inv['discountCents'],
                    $inv['totalCents'],
                    "seed $seed inv $i total"
                );
                // paid <= total, balance = total − paid
                self::assertLessThanOrEqual($inv['totalCents'], $inv['paidCents'], "seed $seed inv $i paid<=total");
                self::assertSame($inv['totalCents'] - $inv['paidCents'], $inv['balanceCents'], "seed $seed inv $i balance");
            }
        }
    }

    public function test_dashboard_aging_buckets_sum_to_ap_outstanding(): void
    {
        for ($seed = 0; $seed < 8; $seed++) {
            $d = Finance::fromSeed($seed, 'example.test')->dashboard();
            $sum = 0;
            foreach ($d['aging'] as $bucket) {
                $sum += $bucket[1];
            }
            self::assertSame($d['apOutstanding'], $sum, "seed $seed aging closes");
            // overdue is the three past-due buckets (31+ days).
            self::assertSame($d['aging'][2][1] + $d['aging'][3][1] + $d['aging'][4][1], $d['overdue'], "seed $seed overdue");
        }
    }

    public function test_expense_lines_sum_to_total(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $fin = Finance::fromSeed($seed, 'example.test');
            for ($i = 0; $i < 30; $i++) {
                $r = $fin->expenseAt($i);
                $sum = 0;
                foreach ($r['lines'] as $line) {
                    $sum += $line['amountCents'];
                }
                self::assertSame($r['totalCents'], $sum, "seed $seed exp $i total closes");
            }
        }
    }

    public function test_invoice_id_round_trips_to_the_same_record(): void
    {
        $fin = Finance::fromSeed(3, 'example.test');
        $inv = $fin->invoiceAt(9);
        self::assertSame($inv, $fin->invoiceByNumberSlug($inv['id']), 'slug id resolves to its corpus row');
    }

    public function test_second_approver_is_a_real_roster_member(): void
    {
        for ($seed = 0; $seed < 5; $seed++) {
            $second = Finance::fromSeed($seed, 'example.test')->secondApprover();
            $names = [];
            foreach (Org::fromSeed($seed, 'example.test')->people(Org::fromSeed($seed)->headcount()) as $p) {
                $names[] = $p['name'];
            }
            self::assertContains($second['name'], $names, "seed $seed CFO is in the roster");
        }
    }

    // --- P2: the finance cash tile equals the treasury total (one cash figure on one host) ---

    public function test_finance_cash_on_hand_equals_bank_treasury_total(): void
    {
        for ($seed = 0; $seed < 8; $seed++) {
            $fin = Finance::fromSeed($seed, 'example.test')->dashboard();
            $bank = Bank::fromSeed($seed, 'example.test')->summary();
            self::assertSame($bank['cashOnHand'], $fin['cashOnHand'], "seed $seed finance cash == bank total");
        }
    }

    // --- P3: one vendor book, and invoice-number ranges that never collide ---

    public function test_finance_vendor_resolves_on_the_vendors_module(): void
    {
        for ($seed = 0; $seed < 4; $seed++) {
            $fin = Finance::fromSeed($seed, 'example.test');
            $vendors = Vendors::fromSeed($seed, 'example.test');
            // A vendor named on an AP invoice must resolve to the same record under /panel/vendors.
            for ($i = 0; $i < 15; $i++) {
                $inv = $fin->invoiceAt($i);
                $v = $vendors->vendor($inv['vendorId']);
                self::assertSame($inv['vendorId'], $v['id'], "seed $seed inv $i vendor id resolves");
                self::assertSame($inv['vendorName'], $v['name'], "seed $seed inv $i vendor name agrees");
            }
        }
    }

    public function test_finance_and_vendor_invoice_numbers_never_collide(): void
    {
        for ($seed = 0; $seed < 3; $seed++) {
            $fin = Finance::fromSeed($seed, 'example.test');
            $vendors = Vendors::fromSeed($seed, 'example.test');
            // Finance AP numbers live below 100000; vendor-side numbers at/above it — disjoint ranges.
            for ($i = 0; $i < 20; $i++) {
                $num = (int) substr($fin->invoiceAt($i)['number'], -6);
                self::assertLessThan(100000, $num, "seed $seed finance invoice $i below the vendor band");
            }
            for ($k = 0; $k < 12; $k++) {
                foreach ($vendors->invoicesFor('vendor-' . sprintf('%04d', 1001 + $k)) as $inv) {
                    $num = (int) substr($inv['display'], -6);
                    self::assertGreaterThanOrEqual(100000, $num, "seed $seed vendor invoice in the vendor band");
                }
            }
        }
    }

    // --- P4: the audit scroll is strictly newest-first ---

    public function test_audit_log_timestamps_are_monotonic(): void
    {
        for ($seed = 0; $seed < 5; $seed++) {
            $lines = Finance::fromSeed($seed, 'example.test')->auditLog(220);
            $prev = null;
            foreach ($lines as $line) {
                $stamp = substr($line, 0, 19);               // "YYYY-MM-DD HH:MM:SS" — ISO, lexicographic
                if ($prev !== null) {
                    self::assertLessThanOrEqual($prev, $stamp, "seed $seed audit rows descend");
                }
                $prev = $stamp;
            }
        }
    }

    // --- P7: the four-eyes approver carries their real HR title ---

    public function test_second_approver_title_matches_hr_directory(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $second = Finance::fromSeed($seed, 'example.test')->secondApprover();
            $org = Org::fromSeed($seed, 'example.test');
            $title = null;
            foreach ($org->people($org->headcount()) as $p) {
                if ($p['name'] === $second['name']) {
                    $title = $p['title'];
                    break;
                }
            }
            self::assertNotNull($title, "seed $seed approver is in the directory");
            self::assertSame($title, $second['title'], "seed $seed approver title == HR title");
            self::assertNotSame('Chief Financial Officer', $second['title'], "seed $seed no hard-coded CFO title unless HR says so");
            // Same senior signer the payroll four-eyes wall waits on (cross-module coherence).
            self::assertSame(Payroll::fromSeed($seed, 'example.test')->secondApprover()['name'], $second['name'], "seed $seed same signer as payroll");
        }
    }

    // --- M6: every finance-family module reads one frozen "today" ---

    public function test_modules_agree_on_one_frozen_today(): void
    {
        $today = FrozenClock::todayYmd();
        for ($seed = 0; $seed < 4; $seed++) {
            // Finance "as of" and the newest bank ledger row must both read the one frozen day.
            self::assertSame($today, Finance::fromSeed($seed, 'example.test')->asOf(), "seed $seed finance asOf");
            $newest = Bank::fromSeed($seed, 'example.test')->ledgerPage('acct-reserve', 0, 1);
            self::assertSame($today, $newest[0]['date'], "seed $seed bank newest ledger date");
            // Payroll's current period anchors to the same year/month.
            $run = Payroll::fromSeed($seed, 'example.test')->runs()[0];
            self::assertSame(FrozenClock::YEAR, $run['year'], "seed $seed payroll year");
            self::assertSame(FrozenClock::MONTH, $run['monthNumber'], "seed $seed payroll month");
        }
    }
}
