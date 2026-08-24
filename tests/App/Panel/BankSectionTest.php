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

    public function test_wire_form_is_inert_and_submit_is_guarded(): void
    {
        $form = $this->render('/admin/bank/acct-reserve/wire');
        self::assertStringContainsString('<form', $form);
        self::assertStringContainsString('Submit for authorization', $form);
        // The bare form is not itself a success or denial.
        self::assertStringNotContainsString('Denied', $form);

        $submit = $this->render('/admin/bank/acct-reserve/wire/submit');
        self::assertStringContainsString('Denied', $submit);
        self::assertStringContainsStringIgnoringCase('dual authorization', $submit);
        self::assertStringContainsStringIgnoringCase('OFAC', $submit);
        self::assertStringContainsString('WIRE-2026-', $submit);
        // A guarded money verb must NEVER claim the funds moved.
        self::assertStringNotContainsStringIgnoringCase('sent', $submit);
        self::assertStringNotContainsStringIgnoringCase('paid', $submit);
        self::assertStringNotContainsString('Queued', $submit);
    }

    public function test_transfer_pay_freeze_stop_payment_all_denied(): void
    {
        foreach (['transfer', 'pay', 'freeze', 'stop-payment'] as $verb) {
            $html = $this->render('/admin/bank/acct-reserve/' . $verb);
            self::assertStringContainsString('Denied', $html, $verb);
            self::assertStringNotContainsString('Queued', $html, $verb);
        }
    }

    public function test_wire_beneficiary_arg_is_reflected_escaped(): void
    {
        // The arg is the one place a submitted value reaches output; slugging + esc() keep it inert.
        $html = $this->render('/admin/bank/acct-reserve/wire/submit/acme-holdings');
        self::assertStringContainsString('acme-holdings', $html);

        $inject = $this->render('/admin/bank/acct-reserve/wire/submit/%3Cscript%3E');
        self::assertStringNotContainsString('<script>alert', $inject);
        self::assertStringNotContainsString('<script>', $inject);
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

    public function test_revealed_card_pan_is_invalid(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $bank = Bank::fromSeed($seed);
            foreach ($bank->cards() as $c) {
                $pan = str_replace(' ', '', $bank->cardReveal($c['id']));
                self::assertSame('0000', substr($pan, 0, 4), "seed $seed card {$c['id']} BIN 0000");
                self::assertFalse($this->luhn($pan), "seed $seed card {$c['id']} PAN fails Luhn");
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
}
