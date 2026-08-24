<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Bank;
use Funnypot\App\Render\Fake\Org;
use Funnypot\App\Render\Panel\BankSection;
use Funnypot\App\Render\PanelRoute;
use Funnypot\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class BankSectionTest extends TestCase
{
    /** Any address outside RFC1918 10.x is a leak of real routable space (spec SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    /** Render a panel path through the section exactly as the skin would (parse -> render). */
    private function render(string $path, int $seed = 7): string
    {
        $route = PanelRoute::parse($path);
        return (new BankSection())->render($route, VisualPersona::fromSeed($seed), '/admin');
    }

    // --- routing / depth ---

    public function test_landing_lists_accounts_and_cash_tile(): void
    {
        $html = $this->render('/admin/bank');
        self::assertStringContainsString('Bank &amp; Treasury', $html);
        self::assertStringContainsString('Cash on hand', $html);
        self::assertStringContainsString('Corporate cards', $html);
        // An account link routes back under the same module mount.
        self::assertStringContainsString('href="/admin/bank/acct-', $html);
    }

    public function test_account_detail_and_subtabs_render(): void
    {
        foreach (['', '/ledger', '/details', '/statements'] as $sub) {
            $html = $this->render('/admin/bank/acct-reserve' . $sub);
            self::assertNotSame('', trim($html), "subtab $sub non-empty");
            self::assertStringContainsString('Reserve', $html, "subtab $sub");
        }
    }

    public function test_unknown_account_slug_still_renders_a_plausible_detail(): void
    {
        // A fuzzed slug must not dead-end (a 404 inside a deep panel is a tell).
        $html = $this->render('/admin/bank/acct-does-not-exist-9999');
        self::assertStringContainsString('fp-card', $html);
        self::assertStringContainsString('Send wire', $html);
    }

    public function test_ledger_paginates(): void
    {
        $p1 = $this->render('/admin/bank/acct-reserve/ledger');
        $p2 = $this->render('/admin/bank/acct-reserve/ledger/p2');
        self::assertStringContainsString('page 1/', $p1);
        self::assertStringContainsString('page 2/', $p2);
        self::assertNotSame($p1, $p2, 'different pages render different rows');
        // Statement export is a .zip (the only extension the decoy archive handler serves — spec E8).
        self::assertStringContainsString('.csv.zip', $p1);
    }

    public function test_cards_list_detail_and_reveal(): void
    {
        $list = $this->render('/admin/bank/cards');
        self::assertStringContainsString('Corporate cards', $list);
        self::assertStringContainsString('href="/admin/bank/cards/card-', $list);
        // Masked at rest: no revealed digits in the list, only the masked form.
        self::assertStringContainsString('•••• •••• ••••', $list);

        $bank = Bank::fromSeed(7, VisualPersona::fromSeed(7)->domain());
        $cardId = $bank->cards()[0]['id'];
        $detail = $this->render('/admin/bank/cards/' . $cardId);
        self::assertStringContainsString('Reveal card number', $detail);

        $reveal = $this->render('/admin/bank/cards/' . $cardId . '/reveal');
        self::assertStringContainsString('Revealed', $reveal);
    }

    // --- guarded money verbs (the key trick) ---

    public function test_wire_form_is_inert_and_routes_to_2fa(): void
    {
        $form = $this->render('/admin/bank/acct-reserve/wire');
        self::assertStringContainsString('<form', $form);
        self::assertStringContainsString('Submit for authorization', $form);
        self::assertStringContainsString('action="/admin/bank/acct-reserve/wire/2fa"', $form);
        // The bare form is not itself a success or denial.
        self::assertStringNotContainsString('Denied', $form);
        self::assertStringNotContainsString('Submitted', $form);
    }

    public function test_transfer_pay_freeze_stop_payment_all_denied(): void
    {
        foreach (['transfer', 'pay', 'freeze', 'stop-payment'] as $verb) {
            $html = $this->render('/admin/bank/acct-reserve/' . $verb);
            self::assertStringContainsString('Denied', $html, $verb);
            self::assertStringNotContainsString('Queued', $html, $verb);
        }
    }

    // --- wire gauntlet: complete-then-reversal (spec §1) ---

    public function test_wire_2fa_step_accepts_any_code_and_never_authenticates(): void
    {
        $step = $this->render('/admin/bank/acct-reserve/wire/2fa');
        self::assertStringContainsStringIgnoringCase('one-time code was sent by sms', $step);
        // Masked as five dots + last three digits of a fake 555-01xx phone — never a real number shown.
        self::assertMatchesRegularExpression('/•{5}\d{3}/u', $step);
        self::assertStringContainsString('<form', $step);
        self::assertStringContainsString('action="/admin/bank/acct-reserve/wire/confirm"', $step);
        // The code field has no name attribute — it is a dead form; nothing is ever validated server-side.
        self::assertStringNotContainsString('name=', $step);
    }

    public function test_wire_confirm_shows_success_but_ledger_shows_it_reversed(): void
    {
        $confirm = $this->render('/admin/bank/acct-reserve/wire/confirm');
        self::assertStringContainsString('Submitted', $confirm);
        self::assertStringContainsStringIgnoringCase('settlement', $confirm);
        self::assertStringNotContainsString('Denied', $confirm);
        self::assertStringContainsString('WIRE-2026-', $confirm);
        // Never a final/settled claim — "in progress", never "cleared"/"complete"/"settled".
        self::assertStringNotContainsStringIgnoringCase('settled', $confirm);
        self::assertStringNotContainsStringIgnoringCase('complete', $confirm);
        self::assertStringContainsString('href="/admin/bank/acct-reserve/ledger"', $confirm);

        // The account's ledger/pending view deterministically shows recent outbound wires reversed.
        $ledger = $this->render('/admin/bank/acct-reserve/ledger');
        self::assertStringContainsStringIgnoringCase('reversed', $ledger);
        self::assertStringContainsStringIgnoringCase('compliance hold', $ledger);
        self::assertStringContainsString('Recent wire activity', $ledger);
    }

    public function test_wire_never_reaches_a_persistent_settled_state(): void
    {
        // Every reachable wire step for this account, across every seed: never claims cleared/settled/
        // complete, and every wire attempt shown anywhere always reads as reversed, not settled.
        foreach (['', '/2fa', '/confirm', '/confirm/acme-holdings', '/bogus-step'] as $step) {
            $html = $this->render('/admin/bank/acct-reserve/wire' . $step);
            self::assertStringNotContainsStringIgnoringCase('settled', $html, "step $step");
            self::assertStringNotContainsStringIgnoringCase('funds have been transferred', $html, "step $step");
        }
    }

    public function test_wire_confirm_beneficiary_arg_is_reflected_escaped(): void
    {
        // The arg is the one place a typed-in value reaches output; slugging + esc() keep it inert.
        $html = $this->render('/admin/bank/acct-reserve/wire/confirm/acme-holdings');
        self::assertStringContainsString('acme-holdings', $html);

        $inject = $this->render('/admin/bank/acct-reserve/wire/confirm/%3Cscript%3E');
        self::assertStringNotContainsString('<script>alert', $inject);
        self::assertStringNotContainsString('<script>', $inject);
    }

    public function test_unknown_wire_step_is_a_safe_fallback_not_a_crash(): void
    {
        $html = $this->render('/admin/bank/acct-reserve/wire/some-garbage-step');
        self::assertStringContainsString('<form', $html);
        self::assertStringContainsString('Submit for authorization', $html);
    }

    // --- arithmetic closes ---

    public function test_cash_on_hand_equals_sum_of_balances(): void
    {
        for ($seed = 0; $seed < 8; $seed++) {
            $bank = Bank::fromSeed($seed);
            $sum = 0;
            foreach ($bank->accounts() as $a) {
                $sum += $a['balance'];
            }
            self::assertSame($sum, $bank->summary()['cashOnHand'], "seed $seed cash = Σ balances");
        }
    }

    public function test_ledger_running_balance_reconciles_down_the_page(): void
    {
        // Each row's balance must equal the older (next) row's balance plus this row's signed amount,
        // and the reconciliation must hold across a page boundary (page 2 continues page 1 exactly).
        for ($seed = 0; $seed < 5; $seed++) {
            $bank = Bank::fromSeed($seed);
            foreach ($bank->accounts() as $a) {
                $rows = $bank->ledgerPage($a['id'], 0, 60);
                self::assertGreaterThan(1, count($rows));
                for ($i = 0; $i < count($rows) - 1; $i++) {
                    self::assertSame(
                        $rows[$i]['balance'],
                        $rows[$i + 1]['balance'] + $rows[$i]['amountSigned'],
                        "seed $seed acct {$a['id']} row $i reconciles"
                    );
                    // Newest first: dates are monotonically non-increasing.
                    self::assertGreaterThanOrEqual($rows[$i + 1]['date'], $rows[$i]['date'], "date order row $i");
                }
                // Newest row shows the account's current balance.
                self::assertSame($a['balance'], $rows[0]['balance'], "seed $seed newest balance = account balance");
                // All displayed balances are positive (a negative treasury balance is a tell).
                foreach ($rows as $r) {
                    self::assertGreaterThan(0, $r['balance']);
                }
            }
        }
    }

    public function test_page_boundary_continues_running_balance(): void
    {
        $bank = Bank::fromSeed(3);
        $id = 'acct-reserve';
        $p1 = $bank->ledgerPage($id, 0, 50);
        $p2 = $bank->ledgerPage($id, 50, 50);
        // Last row of page 1 reconciles against the first row of page 2.
        self::assertSame(
            $p1[49]['balance'],
            $p2[0]['balance'] + $p1[49]['amountSigned'],
            'running balance is continuous across the page boundary'
        );
    }

    // --- SAFE: invalid-format banking coordinates ---

    public function test_banking_coordinates_are_structurally_invalid(): void
    {
        for ($seed = 0; $seed < 8; $seed++) {
            foreach (Bank::fromSeed($seed)->accounts() as $a) {
                // IBAN check digits (chars 3-4) are "00" — never valid under ISO 13616.
                self::assertSame('00', substr($a['iban'], 2, 2), "seed $seed IBAN check digits invalid");
                // Routing number uses Federal Reserve prefix "00" — never assigned.
                self::assertStringStartsWith('00', $a['routing'], "seed $seed routing prefix invalid");
                // Account number is masked to its last four.
                self::assertStringStartsWith('••', $a['accountMasked']);
            }
        }
    }

    public function test_revealed_card_pan_is_luhn_valid_on_a_test_bin(): void
    {
        // Deliberate design: the PAN passes Luhn (so a scanner treats it as a live number to try) but is
        // built on a published test-card BIN — network sandbox space, never issued to a real cardholder —
        // so it can never be a real card. Length is 15 (Amex) or 16 (others).
        $testBins = ['424242', '400000', '555555', '222300', '378282'];
        for ($seed = 0; $seed < 6; $seed++) {
            $bank = Bank::fromSeed($seed);
            foreach ($bank->cards() as $c) {
                $pan = str_replace(' ', '', $bank->cardReveal($c['id']));
                self::assertMatchesRegularExpression('/^\d{15,16}$/', $pan, "seed $seed card {$c['id']} PAN is 15-16 digits");
                self::assertTrue($this->luhn($pan), "seed $seed card {$c['id']} PAN passes Luhn");
                $bin6 = substr($pan, 0, 6);
                self::assertContains($bin6, $testBins, "seed $seed card {$c['id']} PAN on a test BIN ($bin6)");
            }
        }
    }

    private function luhn(string $num): bool
    {
        $sum = 0;
        $alt = false;
        for ($i = strlen($num) - 1; $i >= 0; $i--) {
            $d = (int) $num[$i];
            if ($alt) {
                $d *= 2;
                if ($d > 9) {
                    $d -= 9;
                }
            }
            $sum += $d;
            $alt = !$alt;
        }
        return $sum % 10 === 0;
    }

    // --- one host = one domain ---

    public function test_card_holder_email_uses_persona_domain(): void
    {
        $persona = VisualPersona::fromSeed(7);
        $domain = $persona->domain();
        $bank = Bank::fromSeed(7, $domain);
        foreach ($bank->cards() as $c) {
            self::assertStringEndsWith('@' . $domain, $c['email'], 'card email at the one persona domain');
        }
        // The rendered card detail carries that same domain.
        $html = $this->render('/admin/bank/cards/' . $bank->cards()[0]['id']);
        self::assertStringContainsString('@' . $domain, $html);
    }

    // --- determinism + safety invariants ---

    public function test_same_url_is_byte_identical(): void
    {
        $paths = ['/admin/bank', '/admin/bank/acct-reserve', '/admin/bank/acct-reserve/ledger/p3',
                  '/admin/bank/cards', '/admin/bank/acct-reserve/wire/submit'];
        foreach ($paths as $p) {
            self::assertSame($this->render($p, 11), $this->render($p, 11), "stable: $p");
        }
    }

    public function test_no_public_ip_in_any_view(): void
    {
        $paths = ['/admin/bank', '/admin/bank/acct-reserve', '/admin/bank/acct-reserve/ledger',
                  '/admin/bank/acct-reserve/details', '/admin/bank/cards',
                  '/admin/bank/acct-reserve/wire', '/admin/bank/acct-reserve/wire/submit'];
        for ($seed = 0; $seed < 8; $seed++) {
            foreach ($paths as $p) {
                self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $this->render($p, $seed), "seed $seed path $p");
            }
        }
    }

    public function test_generator_deterministic(): void
    {
        $a = Bank::fromSeed(5, 'example.test');
        $b = Bank::fromSeed(5, 'example.test');
        self::assertSame($a->accounts(), $b->accounts());
        self::assertSame($a->summary(), $b->summary());
        self::assertSame($a->cards(), $b->cards());
        self::assertSame($a->ledgerPage('acct-reserve', 0, 40), $b->ledgerPage('acct-reserve', 0, 40));
    }

    public function test_card_count_matches_fleet(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $bank = Bank::fromSeed($seed);
            self::assertSame($bank->cardCount(), count($bank->cards()), "seed $seed fleet size");
        }
    }

    // --- P1: the ledger never predates the account's open date ---

    public function test_oldest_ledger_row_is_not_older_than_the_account_open_date(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $bank = Bank::fromSeed($seed);
            foreach ($bank->accounts() as $a) {
                $total = $bank->ledgerCount($a['id']);
                self::assertGreaterThan(0, $total, "seed $seed {$a['id']} has ledger rows");
                // The oldest row (highest global index) must not fall before the account opened.
                $oldest = $bank->ledgerPage($a['id'], $total - 1, 1);
                self::assertCount(1, $oldest);
                self::assertGreaterThanOrEqual(
                    $a['opened'],
                    $oldest[0]['date'],
                    "seed $seed {$a['id']} oldest ledger row {$oldest[0]['date']} >= opened {$a['opened']}"
                );
            }
        }
    }

    // --- M5: no $0 ledger rows; several transactions may share a day ---

    public function test_no_zero_amount_ledger_rows(): void
    {
        for ($seed = 0; $seed < 5; $seed++) {
            $bank = Bank::fromSeed($seed);
            foreach ($bank->accounts() as $a) {
                foreach ($bank->ledgerPage($a['id'], 0, 200) as $r) {
                    self::assertNotSame(0, $r['amountSigned'], "seed $seed {$a['id']} no \$0 row");
                }
            }
        }
    }

    // --- P5: the card reveal ends in the same last four the mask showed ---

    public function test_card_reveal_ends_with_masked_last4(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $bank = Bank::fromSeed($seed);
            foreach ($bank->cards() as $c) {
                $pan = str_replace(' ', '', $bank->cardReveal($c['id']));
                self::assertStringEndsWith($c['last4'], $pan, "seed $seed card {$c['id']} reveal ends in last4");
            }
        }
    }

    // ================= Landing links to the new sections =================

    public function test_landing_links_to_crypto_approvers_and_approvals(): void
    {
        $html = $this->render('/admin/bank');
        self::assertStringContainsString('href="/admin/bank/crypto"', $html);
        self::assertStringContainsString('href="/admin/bank/approvers"', $html);
        self::assertStringContainsString('href="/admin/bank/approvals"', $html);
    }

    // ================= Approvers & the 2FA-bypass illusion (spec §2) =================

    public function test_all_approver_phones_are_in_the_reserved_fictional_range(): void
    {
        for ($seed = 0; $seed < 8; $seed++) {
            $bank = Bank::fromSeed($seed);
            foreach ($bank->approvers() as $a) {
                self::assertMatchesRegularExpression('/^555-01\d\d$/', $a['phoneFull'], "seed $seed approver {$a['id']} phone");
                self::assertMatchesRegularExpression('/•{5}\d{3}/u', $a['phoneMasked'], "seed $seed approver {$a['id']} masked");
            }
            // The reset-2fa "new phone" is also in-range.
            foreach ($bank->approvers() as $a) {
                self::assertMatchesRegularExpression('/^555-01\d\d$/', $bank->approverNewPhone($a['id'])['full']);
            }
            // The wire/crypto 2FA initiator phone is also in-range.
            self::assertMatchesRegularExpression('/^555-01\d\d$/', $bank->wireInitiatorPhone('acct-reserve')['full']);
        }
    }

    public function test_approvers_list_and_detail_render(): void
    {
        $list = $this->render('/admin/bank/approvers');
        self::assertStringContainsString('Wire approvers', $list);
        self::assertStringContainsString('href="/admin/bank/approvers/appr-', $list);
        // Masked at rest — no full 555-01xx phone visible on the list page.
        self::assertDoesNotMatchRegularExpression('/555-01\d\d/', $list);

        $bank = Bank::fromSeed(7, VisualPersona::fromSeed(7)->domain());
        $apprId = $bank->approvers()[0]['id'];
        $detail = $this->render('/admin/bank/approvers/' . $apprId);
        self::assertStringContainsString('Edit phone / reset 2FA device', $detail);
    }

    public function test_approver_reset_2fa_accepts_any_code_and_never_authenticates(): void
    {
        $bank = Bank::fromSeed(7, VisualPersona::fromSeed(7)->domain());
        $appr = $bank->approvers()[0];
        $base = '/admin/bank/approvers/' . $appr['id'] . '/reset-2fa';

        $form = $this->render($base);
        self::assertStringContainsString('<form', $form);
        self::assertStringContainsString('action="' . $base . '/verify"', $form);
        self::assertStringNotContainsString('name=', $form);

        $verify = $this->render($base . '/verify');
        self::assertStringContainsStringIgnoringCase('verification sms sent', $verify);
        self::assertStringContainsString('action="' . $base . '/confirm"', $verify);

        $confirm = $this->render($base . '/confirm');
        self::assertStringContainsString('Phone updated', $confirm);
        // The "bypass" is an illusion: the confirm page cites a DIFFERENT approver still required —
        // dual authorization is never actually reduced to one signer.
        self::assertStringContainsStringIgnoringCase('second, independent approver', $confirm);
        $other = $bank->otherApprover($appr['id']);
        self::assertNotSame($appr['id'], $other['id']);
        self::assertStringContainsString($other['name'], $confirm, 'confirm cites the OTHER (still-required) approver by name');
    }

    public function test_other_approver_is_always_different_from_the_excluded_one(): void
    {
        for ($seed = 0; $seed < 8; $seed++) {
            $bank = Bank::fromSeed($seed);
            foreach ($bank->approvers() as $a) {
                $other = $bank->otherApprover($a['id']);
                self::assertNotSame($a['id'], $other['id'], "seed $seed approver {$a['id']} otherApprover differs");
            }
        }
    }

    // ================= Pending wires awaiting approval (spec §4) =================

    public function test_pending_approvals_list_and_every_approve_is_a_soft_deny(): void
    {
        $list = $this->render('/admin/bank/approvals');
        self::assertStringContainsString('awaiting your approval', $list);
        self::assertStringContainsString('href="/admin/bank/approvals/', $list);

        $bank = Bank::fromSeed(7, VisualPersona::fromSeed(7)->domain());
        foreach ($bank->pendingApprovals() as $p) {
            $decision = $this->render('/admin/bank/approvals/' . $p['id'] . '/approve');
            self::assertStringContainsString('Denied', $decision, $p['id']);
            self::assertStringContainsStringIgnoringCase('second, independent', $decision, $p['id']);
            self::assertStringNotContainsStringIgnoringCase('released', $decision, $p['id']);
        }
    }

    // ================= ETH digital asset reserve (spec §3) =================

    private const REAL_ETH_ADDRESSES = [
        '0x638A2f4c652DcdD671Adc9b712e0DaBF01E256C5',
        '0x68C936f2A0EdEd3c28293af9BEdD2E01D4A4c95C',
        '0xFc8bD5408d04Cd82465F929d37d8279f464e8D8F',
        '0x27684c1938239e09bC74c607ceCa0C718dedcaC6',
    ];

    public function test_crypto_returns_the_4_real_eth_addresses_with_deterministic_balances(): void
    {
        for ($seed = 0; $seed < 5; $seed++) {
            $bank = Bank::fromSeed($seed);
            $rows = $bank->crypto();
            self::assertCount(4, $rows, "seed $seed 4 tranches");
            $addrs = array_column($rows, 'address');
            sort($addrs);
            $expected = self::REAL_ETH_ADDRESSES;
            sort($expected);
            self::assertSame($expected, $addrs, "seed $seed same 4 real addresses regardless of seed");
            foreach ($rows as $r) {
                self::assertGreaterThan(0, $r['ethBalance'], $r['address']);
                self::assertGreaterThan(0, $r['usdCents'], $r['address']);
            }
            // Deterministic: a second call returns byte-identical data.
            self::assertSame($rows, $bank->crypto(), "seed $seed crypto() stable");
        }
    }

    public function test_crypto_list_and_detail_render_real_addresses_and_balances(): void
    {
        $html = $this->render('/admin/bank/crypto');
        self::assertStringContainsString('Digital Asset Reserve', $html);
        foreach (self::REAL_ETH_ADDRESSES as $addr) {
            self::assertStringContainsString($addr, $html);
        }

        $bank = Bank::fromSeed(7, VisualPersona::fromSeed(7)->domain());
        $id = $bank->crypto()[0]['id'];
        $detail = $this->render('/admin/bank/crypto/' . $id);
        self::assertStringContainsString($bank->crypto()[0]['address'], $detail);
        self::assertStringContainsString('ETH', $detail);
        // The keystore download link is the specific decoy path, not a generic download.
        self::assertStringContainsString('href="/admin/bank/crypto/' . $id . '/wallet.json"', $detail);
    }

    public function test_crypto_send_gauntlet_accepts_any_code_and_never_reaches_broadcast_complete(): void
    {
        $bank = Bank::fromSeed(7, VisualPersona::fromSeed(7)->domain());
        $id = $bank->crypto()[0]['id'];
        $base = '/admin/bank/crypto/' . $id . '/send';

        $form = $this->render($base);
        self::assertStringContainsString('<form', $form);
        self::assertStringContainsString('action="' . $base . '/2fa"', $form);

        $twoFa = $this->render($base . '/2fa');
        self::assertStringContainsStringIgnoringCase('one-time code was sent by sms', $twoFa);
        self::assertStringContainsString('action="' . $base . '/broadcast"', $twoFa);
        self::assertStringNotContainsString('name=', $twoFa);

        foreach (['/broadcast', '/broadcast/anything/deeper'] as $suffix) {
            $broadcast = $this->render($base . $suffix);
            self::assertStringContainsStringIgnoringCase('0 / 12', $broadcast, $suffix);
            self::assertStringContainsStringIgnoringCase('broadcasting', $broadcast, $suffix);
            // Never a completed/confirmed broadcast state.
            self::assertStringNotContainsStringIgnoringCase('broadcast complete', $broadcast, $suffix);
            self::assertStringNotContainsStringIgnoringCase('12 / 12', $broadcast, $suffix);
            self::assertStringNotContainsStringIgnoringCase('confirmed', $broadcast, $suffix);
        }
    }

    public function test_crypto_unknown_id_falls_back_to_one_of_the_4_real_tranches(): void
    {
        // A fuzzed tranche id must never dead-end, and must never invent a 5th (unverifiable) address.
        $bank = Bank::fromSeed(7);
        $addr = $bank->cryptoAddress('does-not-exist-9999');
        self::assertContains($addr['address'], self::REAL_ETH_ADDRESSES);

        $html = $this->render('/admin/bank/crypto/does-not-exist-9999');
        self::assertStringContainsString('fp-card', $html);
    }

    // ================= Fuzzing / escape-by-construction across all new sections =================

    public function test_fuzzed_ids_and_args_never_break_out_or_500(): void
    {
        $fuzz = ['%3Cscript%3E', '../../etc/passwd', '"; DROP TABLE x;--', str_repeat('a', 500), '0', ''];
        $bases = [
            '/admin/bank/crypto/', '/admin/bank/crypto/eth-a/send/',
            '/admin/bank/approvers/', '/admin/bank/approvers/appr-1/reset-2fa/',
            '/admin/bank/approvals/',
        ];
        foreach ($bases as $base) {
            foreach ($fuzz as $f) {
                $html = $this->render($base . $f);
                self::assertIsString($html, "$base$f did not throw");
                self::assertStringNotContainsString('<script>alert', $html, "$base$f");
                self::assertStringNotContainsString('Fatal error', $html, "$base$f");
            }
        }
    }

    // ================= Determinism for the new sections =================

    public function test_new_sections_are_byte_identical_per_seed(): void
    {
        $paths = [
            '/admin/bank/crypto', '/admin/bank/crypto/eth-a', '/admin/bank/crypto/eth-a/send',
            '/admin/bank/crypto/eth-a/send/2fa', '/admin/bank/crypto/eth-a/send/broadcast',
            '/admin/bank/approvers', '/admin/bank/approvers/appr-1',
            '/admin/bank/approvers/appr-1/reset-2fa', '/admin/bank/approvers/appr-1/reset-2fa/verify',
            '/admin/bank/approvers/appr-1/reset-2fa/confirm',
            '/admin/bank/approvals', '/admin/bank/approvals/pnd-0100/approve',
            '/admin/bank/acct-reserve/wire', '/admin/bank/acct-reserve/wire/2fa',
            '/admin/bank/acct-reserve/wire/confirm', '/admin/bank/acct-reserve/ledger',
        ];
        foreach ($paths as $p) {
            self::assertSame($this->render($p, 11), $this->render($p, 11), "stable: $p");
        }
    }

    public function test_no_public_ip_in_any_new_section_view(): void
    {
        $paths = [
            '/admin/bank/crypto', '/admin/bank/crypto/eth-a', '/admin/bank/approvers',
            '/admin/bank/approvers/appr-1', '/admin/bank/approvals',
            '/admin/bank/acct-reserve/wire/2fa', '/admin/bank/acct-reserve/wire/confirm',
        ];
        for ($seed = 0; $seed < 5; $seed++) {
            foreach ($paths as $p) {
                self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $this->render($p, $seed), "seed $seed path $p");
            }
        }
    }
}
