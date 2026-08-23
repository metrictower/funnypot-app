<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Vendors;
use Funnypot\App\Render\Panel\VendorsSection;
use Funnypot\App\Render\PanelRoute;
use Funnypot\App\Render\VisualPersona;
use PHPUnit\Framework\TestCase;

final class VendorsSectionTest extends TestCase
{
    /** Any address outside RFC1918 10.x is a leak of real routable space (spec SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    /** Render a panel path through the section exactly as the skin would (parse -> render). */
    private function render(string $path, int $seed = 7): string
    {
        $route = PanelRoute::parse($path);
        return (new VendorsSection())->render($route, VisualPersona::fromSeed($seed), '/admin');
    }

    // --- routing / depth ---

    public function test_landing_lists_vendors_tiles_and_search(): void
    {
        $html = $this->render('/admin/vendors');
        self::assertStringContainsString('Vendors', $html);
        self::assertStringContainsString('Spend YTD', $html);
        self::assertStringContainsString('Open payables', $html);
        self::assertStringContainsString('Filter vendors', $html);
        // A vendor link must route back under the same module mount.
        self::assertStringContainsString('href="/admin/vendors/vendor-', $html);
    }

    public function test_vendor_detail_subtabs_render(): void
    {
        foreach (['', '/spend', '/invoices', '/documents', '/banking'] as $sub) {
            $html = $this->render('/admin/vendors/vendor-1001' . $sub);
            self::assertNotSame('', trim($html), "subtab $sub non-empty");
            self::assertStringContainsString('alte-card', $html, "subtab $sub");
        }
    }

    public function test_unknown_vendor_slug_still_renders_a_plausible_detail(): void
    {
        // A fuzzed slug must not dead-end (a 404 inside a deep panel is a tell).
        $html = $this->render('/admin/vendors/vendor-does-not-exist-9999');
        self::assertStringContainsString('alte-card', $html);
        self::assertStringContainsString('Edit banking details', $html);
    }

    public function test_landing_paginates(): void
    {
        $p1 = $this->render('/admin/vendors');
        $p2 = $this->render('/admin/vendors/p2');
        self::assertStringContainsString('page 1/', $p1);
        self::assertStringContainsString('page 2/', $p2);
        self::assertNotSame($p1, $p2, 'different pages render different rows');
    }

    public function test_invoice_detail_leaf_renders_and_lines_reconcile(): void
    {
        // Pull a real invoice id from the generator and open its detail leaf.
        $vendors = Vendors::fromSeed(7, VisualPersona::fromSeed(7)->domain());
        $inv = $vendors->invoicesFor('vendor-1001')[0];
        $html = $this->render('/admin/vendors/vendor-1001/invoice/' . $inv['routeId']);
        self::assertStringContainsString($inv['display'], $html);
        self::assertStringContainsString('Subtotal', $html);
        self::assertStringContainsString('Total', $html);
        // The masked remit-to panel appears on the invoice (the AP jackpot the attacker screenshots).
        self::assertStringContainsString('IBAN', $html);
    }

    public function test_documents_are_zip_downloads(): void
    {
        // Every download ends .zip — the only extension the decoy archive handler serves (spec E8).
        $html = $this->render('/admin/vendors/vendor-1001/documents');
        self::assertStringContainsString('vendor_onboarding_pack.pdf.zip', $html);
        self::assertStringNotContainsString('.pdf"', $html, 'no bare .pdf link under the panel mount');
    }

    // --- the BEC control (the key trick): edit-banking is a guarded, never-saved wall ---

    public function test_edit_banking_form_is_inert(): void
    {
        $html = $this->render('/admin/vendors/vendor-1001/edit-banking');
        self::assertStringContainsString('<form', $html);
        self::assertStringContainsString('Submit change for approval', $html);
        // The form must not claim anything was saved just by being shown.
        self::assertStringNotContainsString('saved', $html);
    }

    public function test_edit_banking_submit_is_a_guarded_soft_deny_never_saved(): void
    {
        $html = $this->render('/admin/vendors/vendor-1001/edit-banking/submit');
        self::assertStringContainsString('Denied', $html);
        self::assertStringContainsStringIgnoringCase('dual approval', $html);
        self::assertStringContainsStringIgnoringCase('verification callback', $html);
        self::assertStringContainsString('VND-CHG-', $html);
        // A guarded money verb must never claim success.
        self::assertStringNotContainsString('Queued', $html);
        self::assertStringNotContainsStringIgnoringCase('saved', $html);
        self::assertStringNotContainsStringIgnoringCase('updated', $html);
        self::assertStringNotContainsStringIgnoringCase('payment sent', $html);
    }

    public function test_submitted_bank_values_are_never_reflected(): void
    {
        // Attacker-supplied slot values reach the arg positions; nothing may echo raw into output.
        $html = $this->render('/admin/vendors/vendor-1001/edit-banking/%3Cscript%3Ealert(1)%3C%2Fscript%3E');
        self::assertStringNotContainsString('<script>alert', $html);
    }

    // --- arithmetic closes (integer cents, exact) ---

    public function test_invoice_arithmetic_closes(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $vendors = Vendors::fromSeed($seed, '');
            for ($i = 1001; $i < 1006; $i++) {
                foreach ($vendors->invoicesFor('vendor-' . $i) as $inv) {
                    $lineSum = 0;
                    foreach ($inv['lines'] as $l) {
                        self::assertSame($l['qty'] * $l['unitCents'], $l['amountCents'], 'line amount = qty*unit');
                        $lineSum += $l['amountCents'];
                    }
                    self::assertSame($inv['subtotalCents'], $lineSum, 'subtotal = sum(lines)');
                    self::assertSame($inv['subtotalCents'] + $inv['taxCents'], $inv['totalCents'], 'subtotal+tax=total');
                    self::assertSame($inv['totalCents'], $inv['paidCents'] + $inv['balanceCents'], 'paid+balance=total');
                    self::assertGreaterThanOrEqual(0, $inv['balanceCents']);
                    self::assertLessThanOrEqual($inv['totalCents'], $inv['paidCents']);
                }
            }
        }
    }

    public function test_vendor_aggregates_reconcile_to_invoices(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $vendors = Vendors::fromSeed($seed, '');
            for ($i = 1001; $i < 1010; $i++) {
                $id = 'vendor-' . $i;
                $spend = 0;
                $open = 0;
                foreach ($vendors->invoicesFor($id) as $inv) {
                    $spend += $inv['paidCents'];
                    $open += $inv['balanceCents'];
                }
                $agg = $vendors->aggregatesFor($id);
                self::assertSame($spend, $agg['spendYtd'], "spend YTD = sum(paid) for $id");
                self::assertSame($open, $agg['openBalance'], "open balance = sum(balance) for $id");
                // Aging buckets sum back to the open balance.
                $bucketSum = 0;
                foreach ($agg['aging'] as $cents) {
                    $bucketSum += $cents;
                }
                self::assertSame($agg['openBalance'], $bucketSum, "aging buckets sum to open balance for $id");
            }
        }
    }

    public function test_summary_reconciles_to_the_vendor_list(): void
    {
        $vendors = Vendors::fromSeed(3, '');
        $total = $vendors->vendorCount();
        $spend = 0;
        $open = 0;
        // Walk the whole list in pages and add it up — must equal the landing tiles.
        for ($offset = 0; $offset < $total; $offset += 50) {
            foreach ($vendors->vendorsPage($offset, 50) as $v) {
                $spend += $v['spendYtd'];
                $open += $v['openBalance'];
            }
        }
        $s = $vendors->summary();
        self::assertSame($total, $s['total']);
        self::assertSame($spend, $s['spendYtdCents'], 'tile spend = sum of list rows');
        self::assertSame($open, $s['openPayablesCents'], 'tile open payables = sum of list rows');
    }

    // --- determinism + safety invariants ---

    public function test_same_url_is_byte_identical(): void
    {
        foreach (['/admin/vendors', '/admin/vendors/vendor-1002', '/admin/vendors/vendor-1002/invoices',
                  '/admin/vendors/vendor-1002/banking', '/admin/vendors/p3'] as $p) {
            self::assertSame($this->render($p, 11), $this->render($p, 11), "stable: $p");
        }
    }

    public function test_no_public_ip_in_any_view(): void
    {
        $paths = ['/admin/vendors', '/admin/vendors/vendor-1001', '/admin/vendors/vendor-1001/invoices',
                  '/admin/vendors/vendor-1001/banking', '/admin/vendors/vendor-1001/edit-banking/submit'];
        for ($seed = 0; $seed < 8; $seed++) {
            foreach ($paths as $p) {
                self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $this->render($p, $seed), "seed $seed path $p");
            }
        }
    }

    public function test_all_emails_use_the_one_persona_domain(): void
    {
        for ($seed = 0; $seed < 8; $seed++) {
            $domain = VisualPersona::fromSeed($seed)->domain();
            $paths = ['/admin/vendors', '/admin/vendors/vendor-1001', '/admin/vendors/vendor-1003'];
            foreach ($paths as $p) {
                $html = $this->render($p, $seed);
                if (preg_match_all('/@([A-Za-z0-9.-]+)/', $html, $m) > 0) {
                    foreach ($m[1] as $host) {
                        self::assertSame($domain, rtrim($host, '.'), "email domain matches persona ($p seed $seed)");
                    }
                }
            }
        }
    }

    public function test_remit_to_details_are_masked_and_invalid(): void
    {
        $html = $this->render('/admin/vendors/vendor-1001/banking');
        self::assertStringContainsString('••', $html, 'account/IBAN masked');
        // The IBAN carries "00" check digits, which are always invalid — nothing validates.
        self::assertMatchesRegularExpression('/[A-Z]{2}00 /', $html, 'IBAN has invalid check digits');
        // No 16+ digit run (a full card/account number) leaks anywhere.
        self::assertDoesNotMatchRegularExpression('/\d{16,}/', $html, 'no full account number leaks');
    }

    public function test_escaping_of_fuzzed_slug(): void
    {
        // Slugging strips angle brackets before routing; nothing reflected can break out of HTML.
        $html = $this->render('/admin/vendors/%3Cscript%3Ealert(1)%3C%2Fscript%3E');
        self::assertStringNotContainsString('<script>alert', $html);
    }

    // --- generator-level checks ---

    public function test_generator_deterministic_and_coherent(): void
    {
        $a = Vendors::fromSeed(5, 'example.test');
        $b = Vendors::fromSeed(5, 'example.test');
        self::assertSame($a->summary(), $b->summary());
        self::assertSame($a->vendorsPage(0, 20), $b->vendorsPage(0, 20));
        self::assertSame($a->invoicesFor('vendor-1001'), $b->invoicesFor('vendor-1001'));

        foreach ($a->vendorsPage(0, 10) as $v) {
            self::assertMatchesRegularExpression('/^vendor-\d{4}$/', $v['id'], 'vendor id is a slug');
            self::assertStringEndsWith('@example.test', $v['ownerEmail'], 'owner email at persona domain');
            self::assertGreaterThanOrEqual(0, $v['spendYtd']);
            self::assertGreaterThanOrEqual(0, $v['openBalance']);
        }
    }

    public function test_vendor_count_scales_off_org_headcount(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $n = \Funnypot\App\Render\Fake\Org::fromSeed($seed)->headcount();
            $expected = (int) round($n * 0.6) + 20;
            self::assertSame($expected, Vendors::fromSeed($seed)->vendorCount(), "seed $seed count scales off N");
        }
    }
}
