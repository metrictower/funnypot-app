<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Bank;
use Funnypot\Support\VisualPersona;

/**
 * Bank / Treasury (spec §C.6, expanded per the greed-lure deep-treasury spec) — the top-tier greed
 * lure. Renders over the `Fake\Bank` view: accounts landing (+ cash-on-hand tiles) -> account detail
 * with sub-tabs (overview / ledger / details / statements); the corporate-card fleet (masked) with a
 * per-card reveal of a full Luhn-VALID PAN (+ expiry + CVV) on published test-card BIN space; a wire
 * gauntlet that appears to COMPLETE then reads as reversed; a wire-approvers roster with a 2FA-bypass
 * illusion that never actually removes dual authorization; an ETH "Digital Asset Reserve" of 4 real,
 * verifiable cold-storage addresses (garbage keys — funds unspendable via this honeypot); an ETH
 * staking decoy layered on the reserve (fake masked validators, a stuck-forever unstake gauntlet, a
 * live-aging rewards feed); and a pending-wires-awaiting-approval queue. See `Fake\Bank` for the
 * SAFE/DETERMINISTIC data rules.
 *
 * Cold wallets vs everything else (crypto-mask-staking spec §1): the 4 real ETH_RESERVE addresses are
 * the ONLY crypto addresses ever shown in full anywhere in this section — an attacker who verifies one
 * on-chain finds real money (unspendable via this honeypot, but genuine), which is the hook. Every
 * OTHER crypto address (staking validators, tx-history counterparties, the crypto-send broadcast tx
 * hash) is fabricated and MUST go through maskEvmAddress()/maskTxHash() before it reaches output — a
 * fabricated address shown in full would be a verifiable, disprovable mismatch and break the illusion
 * for every fake address around it.
 *
 * The whole surface is INERT. Every money-movement path (wire, transfer, pay, freeze, stop-payment,
 * crypto send, wire approval) either lands on a GUARDED soft-deny (dual authorization + OFAC /
 * sanctions screening hold) or — for the wire gauntlet specifically — appears to submit, then the
 * ledger deterministically shows it reversed/clawed back for compliance. Every 2FA/verification step
 * (wire, approver phone reset, crypto send) accepts ANY code; nothing is ever validated, nothing is
 * ever persisted, no external call happens at request time, and no path yields a persistent "settled"
 * or "broadcast complete" state. IBAN/routing coordinates stay structurally invalid (IBAN check digits
 * 00, routing prefix 00); card PANs are the one deliberate exception — Luhn-valid on test-card BIN
 * space so a scanner treats them as live, yet can never be a real card. The 4 ETH addresses are the
 * other deliberate exception — real, funded, block-explorer-verifiable — but this project never holds
 * their private keys (see the wallet.json keystore decoy: nonsense ciphertext/mac, no functional key).
 *
 * Route slots (PanelRoute): module=bank; section = ''|cards|crypto|approvers|approvals|<account-id>.
 *  - cards: entity = '' (fleet) | <card-id>; subtab = '' (detail) | reveal.
 *  - crypto: entity = '' (reserve list) | staking | <tranche-id>; subtab = '' (detail) | send
 *    (2FA-gauntlet leaf: action = '' form | 2fa | broadcast — broadcast is a dead end, stuck at 0/12
 *    forever). entity=staking is checked BEFORE the tranche lookup so it never falls into
 *    cryptoAddress()'s any-id-resolves fallback:
 *      - staking: subtab = '' (overview: fake masked validators) | rewards (LIVE ages — see
 *        stakingRewardAge()) | unstake (gauntlet: action = '' form | 2fa | pending — pending is the
 *        stuck-forever failed end state, never a withdrawn/settled success).
 *  - approvers: entity = '' (roster) | <approver-id>; subtab = '' (detail) | reset-2fa (dead-form
 *    gauntlet: action = '' form | verify | confirm).
 *  - approvals: entity = '' (queue) | <wire-id>; subtab = approve (soft-deny; needs the OTHER approver).
 *  - account: entity = '' (overview) | ledger|details|statements (sub-tab) | wire|transfer|freeze|
 *    stop-payment|pay (control verb). transfer/pay/freeze/stop-payment stay an instant guarded
 *    soft-deny. wire is the complete-then-reversal gauntlet: subtab = '' (form) | 2fa | confirm.
 */
final class BankSection extends AbstractPanelSection
{
    /** Money-movement verbs in the account's entity slot — each lands on a guarded soft-deny. */
    private const CONTROL_VERBS = ['wire', 'transfer', 'freeze', 'stop-payment', 'pay'];

    /** Detail sub-tabs in the account's entity slot — everything else there is a control verb. */
    private const SUBTABS = ['overview', 'ledger', 'details', 'statements'];

    /** The staking-rewards feed's rolling display window, in seconds — see stakingRewardAge(). */
    private const STAKING_REWARD_CYCLE_SECONDS = 86400;

    private const PAGE_SIZE = 50;

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $bank = Bank::fromSeed($persona->seed(), $persona->domain());
        $section = $route['section'];

        if ($section === '') {
            return $this->landing($bank, $navBase);
        }
        if ($section === 'cards') {
            return $this->cardsRouter($bank, $navBase, $route);
        }
        if ($section === 'crypto') {
            return $this->cryptoRouter($bank, $navBase, $route);
        }
        if ($section === 'approvers') {
            return $this->approversRouter($bank, $navBase, $route);
        }
        if ($section === 'approvals') {
            return $this->approvalsRouter($bank, $navBase, $route);
        }

        // Otherwise the section slot is an account id (plausible fallback for an unknown slug).
        $acct = $bank->account($section);
        $verb = $route['entity'];
        if ($verb !== '' && in_array($verb, self::CONTROL_VERBS, true)) {
            return $this->accountControl($bank, $navBase, $acct, $verb, $route['subtab'], $route['action'], $persona->seed());
        }
        return $this->accountDetail($bank, $navBase, $acct, $verb === '' ? 'overview' : $verb, $route['page']);
    }

    // --- landing: cash tiles + accounts table + cards link ---

    private function landing(Bank $bank, string $navBase): string
    {
        $s = $bank->summary();
        $crypto = $bank->cryptoSummary();
        $tiles = $this->statCardsHtml([
            ['label' => 'Cash on hand', 'value' => $this->money($s['cashOnHand']), 'sub' => $s['currency'] . ' · all accounts'],
            ['label' => 'Bank accounts', 'value' => (string) $s['accounts']],
            ['label' => 'Largest balance', 'value' => $this->money($s['largest']), 'sub' => $s['largestName']],
            ['label' => 'Corporate cards', 'value' => (string) $s['cards']],
            ['label' => 'Digital assets', 'value' => $this->ethAmount($crypto['totalEth']), 'sub' => $this->money($crypto['totalUsdCents']) . ' · ' . $crypto['tranches'] . ' cold tranches'],
            ['label' => 'Pending wires', 'value' => (string) $s['pendingWires'], 'sub' => 'awaiting authorization'],
        ], 'fp-tiles', 'fp-tile');

        $links = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin:12px 0">'
            . $this->actionLink($navBase . '/bank/cards', 'Corporate cards', false)
            . $this->actionLink($navBase . '/bank/crypto', 'Digital asset reserve', false)
            . $this->actionLink($navBase . '/bank/approvers', 'Approvers & security', false)
            . $this->actionLink($navBase . '/bank/approvals', 'Pending approvals', false)
            . '</div>';

        $rows = '';
        foreach ($bank->accounts() as $a) {
            $href = $this->esc($navBase . '/bank/' . $a['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($a['name']) . '</a></td>'
                . '<td>' . $this->esc($a['type']) . '</td>'
                . '<td>' . $this->esc($a['bank']) . '</td>'
                . '<td>' . $this->esc($a['accountMasked']) . '</td>'
                . '<td>' . $this->esc($this->money($a['balance']) . ' ' . $a['currency']) . '</td>'
                . '<td>' . $this->pillHtml($a['status'], 'ok') . '</td>'
                . '</tr>';
        }
        $table = '<div style="overflow-x:auto"><table class="alte-table">'
            . '<thead><tr><th>Account</th><th>Type</th><th>Bank</th><th>Number</th><th>Balance</th><th>Status</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';

        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Bank & Treasury'))
            . $tiles
            . $links
            . $this->card('Company bank accounts', $table, 'Cash on hand ' . $this->money($s['cashOnHand']) . ' ' . $s['currency']);
    }

    // --- account detail + sub-tabs ---

    private function accountDetail(Bank $bank, string $navBase, array $acct, string $subtab, int $page): string
    {
        if (!in_array($subtab, self::SUBTABS, true)) {
            $subtab = 'overview';
        }
        $acctBase = $navBase . '/bank/' . $acct['id'];
        $crumbs = [
            ['Corevance', $navBase],
            ['Bank & Treasury', $navBase . '/bank'],
            [$acct['name'], ''],
        ];
        $tabs = $this->tabStrip($acctBase, $subtab, [
            'overview' => 'Overview',
            'ledger' => 'Transactions',
            'details' => 'Banking details',
            'statements' => 'Statements',
        ]);

        switch ($subtab) {
            case 'ledger':
                $body = $this->ledgerCard($bank, $navBase, $acct, $page);
                break;
            case 'details':
                $body = $this->detailsCard($acct);
                break;
            case 'statements':
                $body = $this->statementsCard($bank, $navBase, $acct);
                break;
            default:
                $body = $this->overviewCard($bank, $navBase, $acct);
        }
        return $this->breadcrumbHtml($crumbs) . $tabs . $body;
    }

    private function overviewCard(Bank $bank, string $navBase, array $acct): string
    {
        $acctBase = $navBase . '/bank/' . $acct['id'];
        $kv = $this->kvTableHtml([
            ['Account', $acct['name'] . ' (' . $acct['id'] . ')'],
            ['Type', $acct['type']],
            ['Bank', $acct['bank']],
            ['Number', $acct['accountMasked']],
            ['Balance', $this->money($acct['balance']) . ' ' . $acct['currency']],
            ['Status', $acct['status']],
            ['Opened', $acct['opened']],
        ], ' class="alte-kv"');

        $controls = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">'
            . $this->actionLink($acctBase . '/wire', 'Send wire', true)
            . $this->actionLink($acctBase . '/transfer', 'New transfer', true)
            . $this->actionLink($acctBase . '/stop-payment', 'Stop payment', true)
            . $this->actionLink($acctBase . '/freeze', 'Freeze account', true)
            . $this->actionLink($acctBase . '/ledger', 'View transactions', false)
            . '</div>';

        $preview = $this->ledgerTable($bank->ledgerPage($acct['id'], 0, 6), false);
        $previewCard = $this->card('Recent transactions', $preview
            . '<div style="margin-top:8px"><a class="fp-dl" href="' . $this->esc($acctBase . '/ledger') . '">View full ledger ›</a></div>',
            'newest first');

        return $this->card($acct['name'], $kv . $controls, $acct['type'] . ' · ' . $acct['bank']) . $previewCard;
    }

    private function ledgerCard(Bank $bank, string $navBase, array $acct, int $page): string
    {
        $acctBase = $navBase . '/bank/' . $acct['id'];
        $total = $bank->ledgerCount($acct['id']);
        $page = $page < 1 ? 1 : $page;
        $pages = (int) ceil($total / self::PAGE_SIZE);
        if ($pages < 1) {
            $pages = 1;
        }
        if ($page > $pages) {
            $page = $pages;
        }
        $offset = ($page - 1) * self::PAGE_SIZE;
        $rowsData = $bank->ledgerPage($acct['id'], $offset, self::PAGE_SIZE);

        $table = $this->ledgerTable($rowsData, true);
        $from = $total === 0 ? 0 : $offset + 1;
        $to = $offset + count($rowsData);
        $pager = $this->pager($acctBase . '/ledger', $page, $pages, $from, $to, $total);

        $export = '<div style="margin:10px 0">'
            . $this->downloadTableHtml(
                ['Export', 'Period', 'Format', 'Rows'],
                [['file' => 'statement_' . $acct['slug'] . '_2026-08.csv.zip', 'cells' => ['2026-08', 'CSV (zip)', number_format(count($rowsData))]]],
                $navBase,
                '/bank/download',
                ' class="alte-table"',
                'fp-dl'
            )
            . '</div>';

        return $this->recentWireActivityCard($bank, $acct)
            . $this->card('Transaction ledger', $table . $pager . $export,
                $acct['name'] . ' · running balance in ' . $acct['currency']);
    }

    /**
     * The "pending/ledger view" reversal illusion: every recently-attempted outbound wire on this
     * account reads as reversed/clawed back for compliance — the complete-then-reversal gauntlet never
     * yields a persistent settled state. DISPLAY-ONLY: these rows are not part of the reconciling
     * ledger, so they never move a balance.
     */
    private function recentWireActivityCard(Bank $bank, array $acct): string
    {
        $attempts = $bank->recentWireAttempts($acct['id']);
        if ($attempts === []) {
            return '';
        }
        $rows = '';
        foreach ($attempts as $w) {
            $rows .= '<tr>'
                . '<td>' . $this->esc($w['date']) . '</td>'
                . '<td>' . $this->esc($w['ref']) . '</td>'
                . '<td>' . $this->esc($w['beneficiary']) . '</td>'
                . '<td>' . $this->esc($this->money($w['amount']) . ' ' . $acct['currency']) . '</td>'
                . '<td>' . $this->pillHtml($w['status'], 'warn') . '</td>'
                . '<td>' . $this->esc($w['reason']) . '</td>'
                . '</tr>';
        }
        $table = '<div style="overflow-x:auto"><table class="alte-table">'
            . '<thead><tr><th>Date</th><th>Reference</th><th>Beneficiary</th><th>Amount</th><th>Status</th><th>Reason</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        return $this->card('Recent wire activity', $table, 'Attempted outbound wires — none settled');
    }

    /** The ledger table. Running balance reconciles: each row's balance = the row below + this amount. */
    private function ledgerTable(array $rows, bool $withBalance): string
    {
        $cols = $withBalance
            ? ['Date', 'Reference', 'Description', 'Debit', 'Credit', 'Balance']
            : ['Date', 'Reference', 'Description', 'Debit', 'Credit'];
        $out = [];
        foreach ($rows as $r) {
            $debit = $r['amountSigned'] < 0 ? $this->money(-$r['amountSigned']) : '';
            $credit = $r['amountSigned'] >= 0 ? $this->money($r['amountSigned']) : '';
            $cells = [$r['date'], $r['ref'], $r['description'], $debit, $credit];
            if ($withBalance) {
                $cells[] = $this->money($r['balance']);
            }
            $out[] = $cells;
        }
        return '<div style="overflow-x:auto">' . $this->tableHtml($cols, $out, ' class="alte-table"') . '</div>';
    }

    private function detailsCard(array $acct): string
    {
        $kv = $this->kvTableHtml([
            ['Account name', $acct['name']],
            ['Bank', $acct['bank']],
            ['Branch', $acct['branch']],
            ['Account number', $acct['accountMasked']],
            ['Routing / ABA', $acct['routing']],
            ['IBAN', $acct['iban']],
            ['SWIFT / BIC', $acct['bic']],
            ['Currency', $acct['currency']],
        ], ' class="alte-kv"');
        $note = '<p class="fp-muted" style="margin-top:8px">Coordinates shown for reconciliation only. '
            . 'Changes to remit-to or wire instructions require dual approval and a verification callback.</p>';
        return $this->card('Banking details', $kv . $note, $acct['name']);
    }

    private function statementsCard(Bank $bank, string $navBase, array $acct): string
    {
        $table = $this->downloadTableHtml(
            ['Statement', 'Period', 'Format', 'Rows'],
            $bank->statements($acct['id']),
            $navBase,
            '/bank/download',
            ' class="alte-table"',
            'fp-dl'
        );
        return $this->card('Statements', $table, $acct['name']);
    }

    // --- corporate cards ---

    private function cardsRouter(Bank $bank, string $navBase, array $route): string
    {
        $cardId = $route['entity'];
        if ($cardId === '') {
            return $this->cardsList($bank, $navBase);
        }
        $card = $bank->card($cardId);
        if ($route['subtab'] === 'reveal') {
            return $this->cardReveal($bank, $navBase, $card);
        }
        return $this->cardDetail($navBase, $card);
    }

    private function cardsList(Bank $bank, string $navBase): string
    {
        $rows = '';
        foreach ($bank->cards() as $c) {
            $href = $this->esc($navBase . '/bank/cards/' . $c['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($c['id']) . '</a></td>'
                . '<td>' . $this->esc($c['holder']) . '</td>'
                . '<td>' . $this->esc($c['program']) . '</td>'
                . '<td>' . $this->esc($c['masked']) . '</td>'
                . '<td>' . $this->esc($this->money($c['limit'])) . '</td>'
                . '<td>' . $this->esc($this->money($c['spentMtd'])) . '</td>'
                . '<td>' . $this->pillHtml($c['status'], $c['status'] === 'Active' ? 'ok' : 'warn') . '</td>'
                . '</tr>';
        }
        $search = '<input id="bnk-card-q" type="search" placeholder="Filter cards…" '
            . 'style="margin-bottom:10px;padding:6px 10px;width:100%;max-width:280px;box-sizing:border-box" autocomplete="off">';
        $table = '<div style="overflow-x:auto"><table id="bnk-card-tbl" class="alte-table">'
            . '<thead><tr><th>Card</th><th>Holder</th><th>Program</th><th>Number</th><th>Limit</th><th>Spent MTD</th><th>Status</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'], ['Corporate cards', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Corporate cards', $search . $table . $this->filterScript('bnk-card-q', 'bnk-card-tbl'),
                number_format($bank->cardCount()) . ' cards issued');
    }

    private function cardDetail(string $navBase, array $card): string
    {
        $cardBase = $navBase . '/bank/cards/' . $card['id'];
        $kv = $this->kvTableHtml([
            ['Card id', $card['id']],
            ['Holder', $card['holder'] . ' (' . $card['holderId'] . ')'],
            ['Email', $card['email']],
            ['Program', $card['program']],
            ['Network', $card['network']],
            ['Number', $card['masked']],
            ['Expiry', $card['expiry']],
            ['Limit', $this->money($card['limit'])],
            ['Spent MTD', $this->money($card['spentMtd'])],
            ['Status', $card['status']],
        ], ' class="alte-kv"');
        $reveal = '<div class="alte-actions" style="margin-top:12px">'
            . $this->actionLink($cardBase . '/reveal', 'Reveal card number', false) . '</div>';
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   ['Corporate cards', $navBase . '/bank/cards'], [$card['id'], '']];
        return $this->breadcrumbHtml($crumbs) . $this->card($card['holder'] . ' · ' . $card['id'], $kv . $reveal, $card['program']);
    }

    /** The reveal leaf: the card's full Luhn-valid PAN (+ network/expiry/CVV) on test-card BIN space —
     *  bait an attacker will try, never a real card (see Fake\Bank). */
    private function cardReveal(Bank $bank, string $navBase, array $card): string
    {
        $pan = $bank->cardReveal($card['id']);
        $body = $this->kvTableHtml([
            ['Holder', $card['holder']],
            ['Network', $card['network']],
            ['Card number', $pan],
            ['Expiry', $card['expiry']],
            ['CVV', $card['cvv']],
        ], ' class="fp-result-kv" style="border-collapse:collapse;width:100%"');
        $note = 'Full card details — treasury reconciliation use only. Access to this view is logged for '
            . 'audit. Do not distribute.';
        $card2 = '<div class="fp-result-card" style="background:#fff;border:1px solid #d7dbdf;'
            . 'border-left:4px solid #c07a1a;border-radius:4px;margin:16px 0">'
            . '<div class="fp-result-head" style="padding:10px 14px;border-bottom:1px solid #eef1f3;'
            . 'display:flex;align-items:center;gap:8px">'
            . $this->pillHtml('Revealed', 'warn')
            . '<span class="fp-result-title" style="font-weight:600;color:#2c3136">' . $this->esc('Card ' . $card['id']) . '</span></div>'
            . '<div class="fp-result-body" style="padding:12px 14px">' . $body
            . '<p class="fp-muted" style="margin:10px 0 0">' . $this->esc($note) . '</p></div></div>';
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   ['Corporate cards', $navBase . '/bank/cards'],
                   [$card['id'], $navBase . '/bank/cards/' . $card['id']], ['Reveal', '']];
        return $this->breadcrumbHtml($crumbs) . $card2;
    }

    // --- control leaves (inert; money verbs are always guarded) ---

    /**
     * A money-movement control. `wire` runs the complete-then-reversal gauntlet (see wireGauntlet());
     * every other money verb returns an instant guarded soft-deny (dual authorization + OFAC /
     * sanctions hold). Nothing is ever "sent"/"paid" and no state changes.
     */
    private function accountControl(Bank $bank, string $navBase, array $acct, string $verb, string $subtab, string $arg, int $seed): string
    {
        $acctBase = $navBase . '/bank/' . $acct['id'];

        if ($verb === 'wire') {
            return $this->wireGauntlet($bank, $navBase, $acct, $subtab, $arg);
        }

        $crumbs = [
            ['Corevance', $navBase],
            ['Bank & Treasury', $navBase . '/bank'],
            [$acct['name'], $acctBase],
            [$this->verbTitle($verb), ''],
        ];

        if ($verb === 'transfer' || $verb === 'pay') {
            $ref = $bank->wireRef($acct['id'], $verb . '|' . $subtab . '|' . $arg);
            $detail = [
                ['From account', $acct['name'] . ' (' . $acct['accountMasked'] . ')'],
                ['Reason', 'Outbound funds movement requires dual authorization and OFAC / sanctions screening.'],
                ['Screening', 'OFAC / sanctions hold — verification callback scheduled'],
                ['Second approver', 'awaiting — CFO / Treasury (segregation of duties)'],
                ['Reference', $ref],
            ];
            // The one place a submitted value reaches output: the (slugified) beneficiary, escaped.
            if ($arg !== '') {
                $detail[] = ['Beneficiary (as entered)', $arg];
            }
            $note = 'The instruction was recorded and routed for authorization. No funds have moved; the '
                . 'transfer will not execute until a second authorized approver signs off and OFAC / '
                . 'sanctions screening clears.';
            return $this->breadcrumbHtml($crumbs) . $this->softDenyCard($this->verbTitle($verb) . ' — ' . $acct['name'], $detail, $note);
        }

        // freeze / stop-payment: still guarded (a treasury lever), never a plain success.
        $ref = $bank->wireRef($acct['id'], $verb);
        $detail = [
            ['Account', $acct['name'] . ' (' . $acct['id'] . ')'],
            ['Reason', 'This action changes account status and requires a second Treasury approver.'],
            ['Second approver', 'awaiting — request pending'],
            ['Reference', $ref],
        ];
        return $this->breadcrumbHtml($crumbs) . $this->softDenyCard($this->verbTitle($verb) . ' — ' . $acct['name'], $detail,
            'The request was recorded and routed; account status is unchanged until a second Treasury approver confirms.');
    }

    /**
     * The wire complete-then-reversal gauntlet (spec §1): form -> 2fa (any code advances) -> confirm
     * (a green "submitted" success — never a persistent settled state; the account ledger separately
     * shows recent wires reversed/clawed back — see recentWireActivityCard()). An unrecognised step
     * under `wire` is a safe no-op back to the form (never a dead end).
     */
    private function wireGauntlet(Bank $bank, string $navBase, array $acct, string $step, string $arg): string
    {
        switch ($step) {
            case '2fa':
                return $this->wireTwoFa($bank, $navBase, $acct);
            case 'confirm':
                return $this->wireConfirm($bank, $navBase, $acct, $arg);
            default:
                return $this->wireForm($navBase, $acct);
        }
    }

    /** The inert wire-out form. Submitting it (any method) only routes to the 2FA step. */
    private function wireForm(string $navBase, array $acct): string
    {
        $acctBase = $navBase . '/bank/' . $acct['id'];
        $action = $this->esc($acctBase . '/wire/2fa');
        $form = '<form class="fp-wire-form" method="get" action="' . $action . '" style="max-width:440px">'
            . $this->field('Beneficiary name', 'text')
            . $this->field('Beneficiary bank', 'text')
            . $this->field('IBAN / account number', 'text')
            . $this->field('SWIFT / BIC', 'text')
            . $this->field('Amount (' . $acct['currency'] . ')', 'text')
            . '<button class="alte-btn" type="submit" style="display:inline-block;padding:8px 16px;border:0;'
            . 'border-radius:4px;background:#b23b3b;color:#fff;font-size:.9em;font-weight:600;cursor:pointer">'
            . 'Submit for authorization</button></form>';
        $note = '<p class="fp-muted" style="margin-top:10px">Wires are released only after dual '
            . 'authorization and OFAC / sanctions screening. A verification callback is placed to the '
            . 'beneficiary bank before release.</p>';
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   [$acct['name'], $acctBase], ['Send wire', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Send wire — ' . $acct['name'], $form . $note,
                'From ' . $acct['accountMasked'] . ' · balance ' . $this->money($acct['balance']) . ' ' . $acct['currency']);
    }

    /** The wire 2FA step: "code sent" to a masked fake phone. A dead form — ANY code advances; nothing
     *  is ever validated, no SMS is ever sent. */
    private function wireTwoFa(Bank $bank, string $navBase, array $acct): string
    {
        $acctBase = $navBase . '/bank/' . $acct['id'];
        $phone = $bank->wireInitiatorPhone($acct['id']);
        $action = $this->esc($acctBase . '/wire/confirm');
        $form = '<form method="get" action="' . $action . '" style="max-width:320px">'
            . $this->field('One-time verification code', 'text')
            . '<button class="alte-btn" type="submit" style="display:inline-block;padding:8px 16px;border:0;'
            . 'border-radius:4px;background:#3b7ea1;color:#fff;font-size:.9em;font-weight:600;cursor:pointer">'
            . 'Verify &amp; continue</button></form>';
        $note = '<p class="fp-muted">For security, a one-time code was sent by SMS to '
            . $this->esc($phone['masked']) . '.</p>';
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   [$acct['name'], $acctBase], ['Send wire', $acctBase . '/wire'], ['Verify', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Verify identity — ' . $acct['name'], $note . $form, 'Step 2 of 2');
    }

    /**
     * The wire "confirm" step — reads as a completed submission (green, "Submitted"), but this is the
     * ONLY state a wire ever reaches: never a later "settled"/"cleared" state, and the account's own
     * ledger view separately shows it reversed (recentWireActivityCard()). $arg is the one place a
     * typed-in beneficiary reaches output (escaped) — matching the account's other control verbs.
     */
    private function wireConfirm(Bank $bank, string $navBase, array $acct, string $arg): string
    {
        $acctBase = $navBase . '/bank/' . $acct['id'];
        $ref = $bank->wireRef($acct['id'], 'confirm|' . $arg);
        $amount = $bank->wireAttemptAmount($acct['id']);
        $beneficiary = $arg !== '' ? $arg : 'the beneficiary on file';
        $detail = [
            ['From account', $acct['name'] . ' (' . $acct['accountMasked'] . ')'],
            ['Beneficiary', $beneficiary],
            ['Amount', $this->money($amount) . ' ' . $acct['currency']],
            ['Reference', $ref],
            ['Status', 'Settlement in progress'],
        ];
        $note = 'The transfer was submitted and is now in settlement. Track its status in the account '
            . 'ledger — settlement can still be reversed or held for compliance review at any point '
            . 'before it clears.';
        $card = $this->successCard('Transfer submitted — ' . $acct['name'], $detail, $note);
        $link = '<p style="margin:10px 0 0"><a class="fp-dl" href="'
            . $this->esc($acctBase . '/ledger') . '">View in ledger / pending ›</a></p>';
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   [$acct['name'], $acctBase], ['Send wire', $acctBase . '/wire'], ['Submitted', '']];
        return $this->breadcrumbHtml($crumbs) . $card . $link;
    }

    /** A labelled inert form field (no name attribute is echoed back; the form is a dead end). */
    private function field(string $label, string $type): string
    {
        return '<label style="display:block;margin-bottom:10px;font-size:.86em;color:#40474e">'
            . $this->esc($label)
            . '<input type="' . $this->esc($type) . '" autocomplete="off" '
            . 'style="display:block;width:100%;box-sizing:border-box;padding:7px 10px;margin-top:4px;'
            . 'border:1px solid #c9ccd1;border-radius:4px"></label>';
    }

    // --- small shared UI helpers (all escape-by-construction) ---

    /** A guarded-denial card: crit accent, no "queued" — the money verbs never claim success. */
    private function softDenyCard(string $title, array $detailPairs, string $note): string
    {
        return '<div class="fp-result-card" style="background:#fff;border:1px solid #d7dbdf;'
            . 'border-left:4px solid #b23b3b;border-radius:4px;margin:16px 0">'
            . '<div class="fp-result-head" style="padding:10px 14px;border-bottom:1px solid #eef1f3;'
            . 'display:flex;align-items:center;gap:8px">'
            . $this->pillHtml('Denied', 'crit')
            . '<span class="fp-result-title" style="font-weight:600;color:#2c3136">' . $this->esc($title) . '</span></div>'
            . '<div class="fp-result-body" style="padding:12px 14px">'
            . $this->kvTableHtml($detailPairs, ' class="fp-result-kv" style="border-collapse:collapse;width:100%"')
            . '<p class="fp-muted" style="margin:10px 0 0">' . $this->esc($note) . '</p>'
            . '</div></div>';
    }

    /** A guarded-SUCCESS card: green accent, "Submitted" pill — the complete-then-reversal gauntlet's
     *  apparent win. Never claims a final settled state (see the class docblock). */
    private function successCard(string $title, array $detailPairs, string $note): string
    {
        return '<div class="fp-result-card" style="background:#fff;border:1px solid #d7dbdf;'
            . 'border-left:4px solid #2e8b57;border-radius:4px;margin:16px 0">'
            . '<div class="fp-result-head" style="padding:10px 14px;border-bottom:1px solid #eef1f3;'
            . 'display:flex;align-items:center;gap:8px">'
            . $this->pillHtml('Submitted', 'ok')
            . '<span class="fp-result-title" style="font-weight:600;color:#2c3136">' . $this->esc($title) . '</span></div>'
            . '<div class="fp-result-body" style="padding:12px 14px">'
            . $this->kvTableHtml($detailPairs, ' class="fp-result-kv" style="border-collapse:collapse;width:100%"')
            . '<p class="fp-muted" style="margin:10px 0 0">' . $this->esc($note) . '</p>'
            . '</div></div>';
    }

    /** A sub-tab strip: each tab an <a> to a sibling path; the active one is plain text. */
    private function tabStrip(string $base, string $active, array $tabs): string
    {
        $html = '<nav class="alte-tabs" style="display:flex;flex-wrap:wrap;gap:4px;margin:0 0 12px;'
            . 'border-bottom:1px solid #e3e6e8">';
        foreach ($tabs as $slug => $label) {
            $href = $slug === 'overview' ? $base : $base . '/' . $slug;
            $isActive = ($active === $slug);
            if ($isActive) {
                $html .= '<span class="alte-tab is-active" style="padding:7px 12px;border-bottom:2px solid #3b7ea1;'
                    . 'font-weight:600;color:#2c3136">' . $this->esc($label) . '</span>';
            } else {
                $html .= '<a class="alte-tab" style="padding:7px 12px;color:#3b7ea1;text-decoration:none" href="'
                    . $this->esc($href) . '">' . $this->esc($label) . '</a>';
            }
        }
        return $html . '</nav>';
    }

    /** A button-styled action link. $danger tints it as a scary verb (still just a link to a leaf). */
    private function actionLink(string $href, string $label, bool $danger): string
    {
        $bg = $danger ? '#b23b3b' : '#3b7ea1';
        return '<a class="alte-btn" style="display:inline-block;padding:7px 14px;border-radius:4px;'
            . 'background:' . $bg . ';color:#fff;text-decoration:none;font-size:.86em;font-weight:600" href="'
            . $this->esc($href) . '">' . $this->esc($label) . '</a>';
    }

    /** Prev/next + page count pager, all links pointing at `<base>/pN`. */
    private function pager(string $base, int $page, int $pages, int $from, int $to, int $total): string
    {
        $prev = $page > 1
            ? '<a class="fp-dl" href="' . $this->esc($base . '/p' . ($page - 1)) . '">‹ Prev</a>'
            : '<span class="fp-muted">‹ Prev</span>';
        $next = $page < $pages
            ? '<a class="fp-dl" href="' . $this->esc($base . '/p' . ($page + 1)) . '">Next ›</a>'
            : '<span class="fp-muted">Next ›</span>';
        return '<div class="fp-pager" style="display:flex;gap:14px;align-items:center;margin-top:10px">'
            . $prev . $next
            . '<span class="fp-muted">Showing ' . $this->esc(number_format($from)) . '–' . $this->esc(number_format($to))
            . ' of ' . $this->esc(number_format($total)) . ' · page ' . $page . '/' . $pages . '</span></div>';
    }

    /** A scoped client-side row filter. Degrades cleanly (no-JS shows every row); changes no state. */
    private function filterScript(string $inputId, string $tableId): string
    {
        return '<script>(function(){var i=document.getElementById(' . json_encode($inputId)
            . '),t=document.getElementById(' . json_encode($tableId) . ');if(!i||!t||!t.tBodies[0])return;'
            . 'i.addEventListener("input",function(){var q=i.value.toLowerCase(),r=t.tBodies[0].rows,k;'
            . 'for(k=0;k<r.length;k++){r[k].style.display=r[k].textContent.toLowerCase().indexOf(q)>-1?"":"none";}});})();</script>';
    }

    private function verbTitle(string $verb): string
    {
        $map = [
            'wire' => 'Wire transfer',
            'transfer' => 'Account transfer',
            'pay' => 'Payment',
            'freeze' => 'Freeze account',
            'stop-payment' => 'Stop payment',
        ];
        return isset($map[$verb]) ? $map[$verb] : ucfirst($verb);
    }

    /** Integer-cents currency formatter — exact (no float drift), $1,234.56, matching the finance family. */
    private function money(int $cents): string
    {
        $sign = $cents < 0 ? '-' : '';
        $c = $cents < 0 ? -$cents : $cents;
        return $sign . '$' . number_format(intdiv($c, 100)) . '.' . sprintf('%02d', $c % 100);
    }

    /** ETH amount formatter — 4dp, e.g. "500.1919 ETH" (display only; Fake\Bank owns the real figure). */
    private function ethAmount(float $eth): string
    {
        return number_format($eth, 4) . ' ETH';
    }

    /**
     * MetaMask/Etherscan-style truncation: "0x" + first 6 hex digits, an ellipsis, then the last 4 hex
     * digits. Shared by maskEvmAddress()/maskTxHash() (crypto-mask-staking spec §1) — every crypto
     * value that reaches this that is NOT one of the 4 real cold-wallet addresses is fabricated, so
     * showing it in full would be a verifiable, disprovable on-chain mismatch. Short/malformed input
     * (a fuzzed value) is returned as-is rather than truncated into something misleadingly short.
     */
    private function truncateHex(string $hex): string
    {
        if (strlen($hex) <= 12) {
            return $hex;
        }
        return substr($hex, 0, 8) . '…' . substr($hex, -4);
    }

    /** Masks a fake EVM address (0x + 40 hex). Never call this on a real cold-wallet address — those
     *  are shown in full, on purpose (see the class docblock). */
    private function maskEvmAddress(string $addr): string
    {
        return $this->truncateHex($addr);
    }

    /** Masks a fake tx hash (0x + 64 hex). Every tx hash in this section is fabricated, so this is
     *  called unconditionally — there is no "real" tx hash to leave unmasked. */
    private function maskTxHash(string $hash): string
    {
        return $this->truncateHex($hash);
    }

    // ================= Digital asset reserve (ETH; spec §3) =================

    private function cryptoRouter(Bank $bank, string $navBase, array $route): string
    {
        $id = $route['entity'];
        if ($id === '') {
            return $this->cryptoList($bank, $navBase);
        }
        // Checked BEFORE the tranche lookup: 'staking' is not a tranche id, and cryptoAddress()
        // resolves ANY unknown id to one of the 4 real tranches (never a dead end) — so without this
        // check, /crypto/staking would render as if it were a cold-wallet detail page.
        if ($id === 'staking') {
            return $this->stakingRouter($bank, $navBase, $route);
        }
        $addr = $bank->cryptoAddress($id);
        if ($route['subtab'] === 'send') {
            return $this->cryptoSendFlow($bank, $navBase, $addr, $route['action']);
        }
        return $this->cryptoDetail($bank, $navBase, $addr);
    }

    private function cryptoList(Bank $bank, string $navBase): string
    {
        $summary = $bank->cryptoSummary();
        $tiles = $this->statCardsHtml([
            ['label' => 'Total reserve', 'value' => $this->ethAmount($summary['totalEth']), 'sub' => $this->money($summary['totalUsdCents'])],
            ['label' => 'Cold-storage tranches', 'value' => (string) $summary['tranches']],
            ['label' => 'Chain', 'value' => 'Ethereum'],
        ], 'fp-tiles', 'fp-tile');

        $rows = '';
        foreach ($bank->crypto() as $t) {
            $href = $this->esc($navBase . '/bank/crypto/' . $t['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($t['label']) . '</a></td>'
                . '<td>' . $this->esc($t['chain']) . '</td>'
                . '<td><code>' . $this->esc($t['address']) . '</code></td>'
                . '<td>' . $this->esc($this->ethAmount($t['ethBalance'])) . '</td>'
                . '<td>' . $this->esc($this->money($t['usdCents'])) . '</td>'
                . '</tr>';
        }
        $table = '<div style="overflow-x:auto"><table class="alte-table">'
            . '<thead><tr><th>Tranche</th><th>Chain</th><th>Address</th><th>Balance</th><th>Value</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        $note = '<p class="fp-muted" style="margin-top:8px">Cold-storage reserve, split across tranches '
            . 'for custody policy. Addresses are read-only from this console; signing keys are held in '
            . 'offline cold storage.</p>';
        $links = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">'
            . $this->actionLink($navBase . '/bank/crypto/staking', 'ETH staking', false)
            . '</div>';

        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'], ['Digital Asset Reserve', '']];
        return $this->breadcrumbHtml($crumbs)
            . $tiles
            . $this->card('Digital Asset Reserve', $table . $note . $links, $this->ethAmount($summary['totalEth']) . ' total');
    }

    private function cryptoDetail(Bank $bank, string $navBase, array $addr): string
    {
        $addrBase = $navBase . '/bank/crypto/' . $addr['id'];
        $kv = $this->kvTableHtml([
            ['Tranche', $addr['label']],
            ['Chain', $addr['chain']],
            ['Address', $addr['address']],
            ['Balance', $this->ethAmount($addr['ethBalance'])],
            ['Value', $this->money($addr['usdCents'])],
        ], ' class="alte-kv"');

        $walletHref = $this->esc($addrBase . '/wallet.json');
        $controls = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">'
            . $this->actionLink($addrBase . '/send', 'Send', true)
            . '<a class="fp-dl" href="' . $walletHref . '" style="align-self:center">Download keystore (wallet.json)</a>'
            . '</div>';

        $txRows = '';
        foreach ($bank->cryptoTxHistory($addr['id'], 0, 25) as $tx) {
            $sign = $tx['direction'] === 'in' ? '+' : '-';
            // Fabricated tx history (spec §2): hash + counterparty are fake, so both are masked —
            // never shown in full, unlike the tranche's own (real, cold-wallet) address above.
            $txRows .= '<tr>'
                . '<td>' . $this->esc($tx['date']) . '</td>'
                . '<td><code>' . $this->esc($this->maskTxHash($tx['hash'])) . '</code></td>'
                . '<td>' . $this->esc(strtoupper($tx['direction'])) . '</td>'
                . '<td><code>' . $this->esc($this->maskEvmAddress($tx['counterparty'])) . '</code></td>'
                . '<td>' . $this->esc($sign . number_format($tx['amountEth'], 4) . ' ETH') . '</td>'
                . '<td>' . $this->pillHtml($tx['status'], 'ok') . '</td>'
                . '</tr>';
        }
        $txTable = '<div style="overflow-x:auto"><table class="alte-table">'
            . '<thead><tr><th>Date</th><th>Tx hash</th><th>Dir</th><th>Counterparty</th><th>Amount</th><th>Status</th></tr></thead>'
            . '<tbody>' . $txRows . '</tbody></table></div>';

        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   ['Digital Asset Reserve', $navBase . '/bank/crypto'], [$addr['label'], '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card($addr['label'], $kv . $controls, $addr['chain'])
            . $this->card('Recent on-chain activity', $txTable, 'newest first');
    }

    /** The crypto "Send" gauntlet: form -> 2fa (any code advances) -> broadcast. Broadcast is a dead
     *  end that always reads "0/12 confirmations" — no state beyond it, nothing is ever relayed. */
    private function cryptoSendFlow(Bank $bank, string $navBase, array $addr, string $step): string
    {
        $addrBase = $navBase . '/bank/crypto/' . $addr['id'];
        switch ($step) {
            case '2fa':
                return $this->cryptoSendTwoFa($bank, $navBase, $addr);
            case 'broadcast':
                return $this->cryptoSendBroadcast($bank, $navBase, $addr);
            default:
                return $this->cryptoSendForm($navBase, $addr);
        }
    }

    private function cryptoSendForm(string $navBase, array $addr): string
    {
        $addrBase = $navBase . '/bank/crypto/' . $addr['id'];
        $action = $this->esc($addrBase . '/send/2fa');
        $form = '<form method="get" action="' . $action . '" style="max-width:440px">'
            . $this->field('Recipient address (0x…)', 'text')
            . $this->field('Amount (ETH)', 'text')
            . '<button class="alte-btn" type="submit" style="display:inline-block;padding:8px 16px;border:0;'
            . 'border-radius:4px;background:#b23b3b;color:#fff;font-size:.9em;font-weight:600;cursor:pointer">'
            . 'Continue</button></form>';
        $note = '<p class="fp-muted" style="margin-top:10px">Outbound transfers from cold storage require '
            . 'two-factor verification before broadcast.</p>';
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   ['Digital Asset Reserve', $navBase . '/bank/crypto'],
                   [$addr['label'], $addrBase], ['Send', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Send — ' . $addr['label'], $form . $note,
                'Balance ' . $this->ethAmount($addr['ethBalance']));
    }

    private function cryptoSendTwoFa(Bank $bank, string $navBase, array $addr): string
    {
        $addrBase = $navBase . '/bank/crypto/' . $addr['id'];
        $phone = $bank->wireInitiatorPhone('crypto|' . $addr['id']);
        $action = $this->esc($addrBase . '/send/broadcast');
        $form = '<form method="get" action="' . $action . '" style="max-width:320px">'
            . $this->field('One-time verification code', 'text')
            . '<button class="alte-btn" type="submit" style="display:inline-block;padding:8px 16px;border:0;'
            . 'border-radius:4px;background:#3b7ea1;color:#fff;font-size:.9em;font-weight:600;cursor:pointer">'
            . 'Verify &amp; broadcast</button></form>';
        $note = '<p class="fp-muted">For security, a one-time code was sent by SMS to '
            . $this->esc($phone['masked']) . '.</p>';
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   ['Digital Asset Reserve', $navBase . '/bank/crypto'],
                   [$addr['label'], $addrBase], ['Send', $addrBase . '/send'], ['Verify', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Verify identity — ' . $addr['label'], $note . $form, 'Step 2 of 2');
    }

    /** The stuck-forever broadcast leaf: always "0/12 confirmations", never further. */
    private function cryptoSendBroadcast(Bank $bank, string $navBase, array $addr): string
    {
        $addrBase = $navBase . '/bank/crypto/' . $addr['id'];
        $hash = $bank->cryptoSendTxHash($addr['id'], 'broadcast');
        $detail = [
            ['Tranche', $addr['label']],
            ['Tx hash', $this->maskTxHash($hash)],
            ['Confirmations', '0 / 12'],
            ['Status', 'Broadcasting — pending network relay'],
        ];
        $card = $this->successCard('Broadcasting — ' . $addr['label'], $detail,
            'The transaction is queued for network relay. This page will show confirmation progress '
            . 'once the transaction is picked up by the network.');
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   ['Digital Asset Reserve', $navBase . '/bank/crypto'],
                   [$addr['label'], $addrBase], ['Send', $addrBase . '/send'], ['Broadcasting', '']];
        return $this->breadcrumbHtml($crumbs) . $card;
    }

    // ================= ETH staking decoy (crypto-mask-staking spec §3) =================

    private function stakingRouter(Bank $bank, string $navBase, array $route): string
    {
        $subtab = $route['subtab'];
        if ($subtab === 'rewards') {
            return $this->stakingRewardsCard($bank, $navBase);
        }
        if ($subtab === 'unstake') {
            return $this->stakingUnstakeGauntlet($bank, $navBase, $route['action']);
        }
        return $this->stakingOverview($bank, $navBase);
    }

    private function stakingOverview(Bank $bank, string $navBase): string
    {
        $stakingBase = $navBase . '/bank/crypto/staking';
        $summary = $bank->stakingSummary();
        $tiles = $this->statCardsHtml([
            ['label' => 'Total staked', 'value' => $this->ethAmount($summary['totalStakedEth']), 'sub' => $this->money($summary['usdCents'])],
            ['label' => 'Validators', 'value' => (string) $summary['validatorCount']],
            ['label' => 'APR', 'value' => number_format($summary['apr'], 2) . '%'],
            ['label' => 'Status', 'value' => $summary['status']],
        ], 'fp-tiles', 'fp-tile');

        $rows = '';
        foreach ($bank->stakingValidators() as $v) {
            // Fake validator — never one of the 4 real cold wallets — so the withdrawal address is masked.
            $rows .= '<tr>'
                . '<td><code>' . $this->esc($v['id']) . '</code></td>'
                . '<td><code>' . $this->esc($this->maskEvmAddress($v['address'])) . '</code></td>'
                . '<td>' . $this->esc($this->ethAmount($v['stakedEth'])) . '</td>'
                . '<td>' . $this->pillHtml($v['status'], 'ok') . '</td>'
                . '</tr>';
        }
        $table = '<div style="overflow-x:auto"><table class="alte-table">'
            . '<thead><tr><th>Validator</th><th>Withdrawal address</th><th>Staked</th><th>Status</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';

        $links = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">'
            . $this->actionLink($stakingBase . '/rewards', 'View rewards', false)
            . $this->actionLink($stakingBase . '/unstake', 'Unstake', true)
            . '</div>';
        $note = '<p class="fp-muted" style="margin-top:8px">Validators are custodied under the Digital '
            . 'Asset Reserve; withdrawal credentials point back to cold storage. Exiting a validator '
            . 'requires the unstake request below and is subject to network exit-queue and '
            . 'slashing-risk review.</p>';

        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   ['Digital Asset Reserve', $navBase . '/bank/crypto'], ['Staking', '']];
        return $this->breadcrumbHtml($crumbs)
            . $tiles
            . $this->card('ETH staking', $table . $links . $note,
                $this->ethAmount($summary['totalStakedEth']) . ' staked · ' . $summary['validatorCount'] . ' validators');
    }

    /**
     * The rewards feed — the ONE deliberate, documented exception to this class's frozen-clock rule
     * (mirrors the 4 real ETH addresses being the one deliberate exception to "every address is fake":
     * see Fake\Bank's ETH_RESERVE docblock). Every other view in this section is 100% deterministic per
     * seed; this one calls time() so a reward's displayed age actually advances between visits instead
     * of freezing at whatever it read on first render — a "2h ago" that never moves is itself a tell.
     *
     * The underlying data (validator, type, amount, order) still comes entirely from
     * Bank::stakingRewards(), which is fully seeded and time()-free; only the age TEXT is live —
     * see stakingRewardAge().
     *
     * RUNTIME CAVEAT (cannot be fixed inside this file — flagged for the owner of
     * `src/App/Llm/LlmFakeResponder.php`): panel pages are rendered once and cached byte-identical
     * forever (`LlmFakeResponder::attempt()`, step 2, `$this->cache->put(...)`). Unless this view's
     * cache key is exempted from that cache (or given a short TTL) before this ships, the very first
     * render's age freezes in the cache exactly like a non-live view would, defeating the point of
     * this exception.
     */
    private function stakingRewardsCard(Bank $bank, string $navBase): string
    {
        $stakingBase = $navBase . '/bank/crypto/staking';
        $rows = '';
        foreach ($bank->stakingRewards() as $r) {
            $rows .= '<tr>'
                . '<td>' . $this->esc($this->stakingRewardAge($r['ageOffsetSeconds'])) . '</td>'
                . '<td>' . $this->esc($r['type']) . '</td>'
                . '<td><code>' . $this->esc($r['validatorId']) . '</code></td>'
                . '<td><code>' . $this->esc($this->maskEvmAddress($r['validatorAddress'])) . '</code></td>'
                . '<td>' . $this->esc(number_format($r['amountEth'], 5) . ' ETH') . '</td>'
                . '</tr>';
        }
        $table = '<div style="overflow-x:auto"><table class="alte-table">'
            . '<thead><tr><th>Received</th><th>Type</th><th>Validator</th><th>Address</th><th>Amount</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        $note = '<p class="fp-muted" style="margin-top:8px">Rewards accrue automatically and compound '
            . 'into the staked balance; nothing here is withdrawable without completing a validator '
            . 'exit (see Unstake).</p>';

        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   ['Digital Asset Reserve', $navBase . '/bank/crypto'],
                   ['Staking', $stakingBase], ['Rewards', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Staking rewards', $table . $note, count($bank->stakingRewards()) . ' recent rewards');
    }

    /**
     * Turns a reward's seeded, time()-free offset into a live "Nh ago"-style string. Anchored to a
     * rolling 1-day window (elapsed seconds since the most recent UTC midnight, plus the seeded
     * offset) rather than a fixed historical instant, so the feed keeps reading as recently-earned no
     * matter how long the honeypot has been deployed — a validator that has been "staking" for months
     * would otherwise accumulate reward ages in the tens of days, which reads as stale, not enticing.
     */
    private function stakingRewardAge(int $offsetSeconds): string
    {
        $cyclePos = time() % self::STAKING_REWARD_CYCLE_SECONDS;
        return $this->formatAge($cyclePos + $offsetSeconds);
    }

    /** Coarse "N unit ago" bucketing — matches the spec's own examples ('2h ago', '1d ago', '3d ago'). */
    private function formatAge(int $seconds): string
    {
        if ($seconds < 60) {
            return 'just now';
        }
        if ($seconds < 3600) {
            return intdiv($seconds, 60) . 'm ago';
        }
        if ($seconds < 86400) {
            return intdiv($seconds, 3600) . 'h ago';
        }
        return intdiv($seconds, 86400) . 'd ago';
    }

    private function stakingUnstakeGauntlet(Bank $bank, string $navBase, string $step): string
    {
        switch ($step) {
            case '2fa':
                return $this->stakingUnstakeTwoFa($bank, $navBase);
            case 'pending':
                return $this->stakingUnstakePending($bank, $navBase);
            default:
                return $this->stakingUnstakeForm($navBase);
        }
    }

    /** The inert unstake-request form. Submitting it (any method) only routes to the 2FA step. */
    private function stakingUnstakeForm(string $navBase): string
    {
        $stakingBase = $navBase . '/bank/crypto/staking';
        $action = $this->esc($stakingBase . '/unstake/2fa');
        $form = '<form method="get" action="' . $action . '" style="max-width:440px">'
            . $this->field('Validator ID', 'text')
            . $this->field('Amount to unstake (ETH)', 'text')
            . '<button class="alte-btn" type="submit" style="display:inline-block;padding:8px 16px;border:0;'
            . 'border-radius:4px;background:#b23b3b;color:#fff;font-size:.9em;font-weight:600;cursor:pointer">'
            . 'Request exit</button></form>';
        $note = '<p class="fp-muted" style="margin-top:10px">Exiting a validator requires two-factor '
            . 'verification and is subject to the network exit queue.</p>';
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   ['Digital Asset Reserve', $navBase . '/bank/crypto'],
                   ['Staking', $stakingBase], ['Unstake', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Unstake', $form . $note, 'Validator exit request');
    }

    /** The unstake 2FA step: a dead form — ANY code advances; nothing is ever validated, no SMS is
     *  ever sent (same idiom as wireTwoFa()/cryptoSendTwoFa()). */
    private function stakingUnstakeTwoFa(Bank $bank, string $navBase): string
    {
        $stakingBase = $navBase . '/bank/crypto/staking';
        $phone = $bank->wireInitiatorPhone('staking|unstake');
        $action = $this->esc($stakingBase . '/unstake/pending');
        $form = '<form method="get" action="' . $action . '" style="max-width:320px">'
            . $this->field('One-time verification code', 'text')
            . '<button class="alte-btn" type="submit" style="display:inline-block;padding:8px 16px;border:0;'
            . 'border-radius:4px;background:#3b7ea1;color:#fff;font-size:.9em;font-weight:600;cursor:pointer">'
            . 'Verify &amp; submit</button></form>';
        $note = '<p class="fp-muted">For security, a one-time code was sent by SMS to '
            . $this->esc($phone['masked']) . '.</p>';
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   ['Digital Asset Reserve', $navBase . '/bank/crypto'],
                   ['Staking', $stakingBase], ['Unstake', $stakingBase . '/unstake'], ['Verify', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Verify identity — unstake', $note . $form, 'Step 2 of 2');
    }

    /**
     * The unstake gauntlet's terminal state: reads as initiated (queued, with a queue position and an
     * estimated wait — the momentary illusion of progress) then FAILED — never a withdrawn/settled
     * success, and no ETH ever moves. This is the only step reachable after 2FA; there is no further
     * "retry succeeded" state (mirrors the wire/crypto-send gauntlets always dead-ending short of a
     * persistent success).
     */
    private function stakingUnstakePending(Bank $bank, string $navBase): string
    {
        $stakingBase = $navBase . '/bank/crypto/staking';
        $ref = $bank->stakingUnstakeRef('pending');
        $queuePos = $bank->stakingUnstakeQueuePosition();
        $waitDays = $bank->stakingUnstakeWaitDays();
        $reason = $bank->stakingUnstakeFailureReason();
        $detail = [
            ['Reference', $ref],
            ['Exit queue position', '~' . number_format($queuePos)],
            ['Estimated wait', $waitDays . ' days'],
            ['Status', 'Failed — ' . $reason],
        ];
        $note = 'Unstaking initiated — queued at exit position ~' . number_format($queuePos) . ', '
            . 'estimated wait ' . $waitDays . ' days. The request then failed: ' . $reason . '. No ETH '
            . 'has moved; the validator remains active and staked.';
        $card = $this->failedCard('Unstake — request failed', $detail, $note);
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   ['Digital Asset Reserve', $navBase . '/bank/crypto'],
                   ['Staking', $stakingBase], ['Unstake', $stakingBase . '/unstake'], ['Failed', '']];
        return $this->breadcrumbHtml($crumbs) . $card;
    }

    /** A guarded-FAILURE card: same shape as softDenyCard() but with a "Failed" pill — this is a
     *  request that was rejected/held, not one that needs a second approver's sign-off. */
    private function failedCard(string $title, array $detailPairs, string $note): string
    {
        return '<div class="fp-result-card" style="background:#fff;border:1px solid #d7dbdf;'
            . 'border-left:4px solid #b23b3b;border-radius:4px;margin:16px 0">'
            . '<div class="fp-result-head" style="padding:10px 14px;border-bottom:1px solid #eef1f3;'
            . 'display:flex;align-items:center;gap:8px">'
            . $this->pillHtml('Failed', 'crit')
            . '<span class="fp-result-title" style="font-weight:600;color:#2c3136">' . $this->esc($title) . '</span></div>'
            . '<div class="fp-result-body" style="padding:12px 14px">'
            . $this->kvTableHtml($detailPairs, ' class="fp-result-kv" style="border-collapse:collapse;width:100%"')
            . '<p class="fp-muted" style="margin:10px 0 0">' . $this->esc($note) . '</p>'
            . '</div></div>';
    }

    // ================= Approvers & 2FA (spec §2) =================

    private function approversRouter(Bank $bank, string $navBase, array $route): string
    {
        $id = $route['entity'];
        if ($id === '') {
            return $this->approversList($bank, $navBase);
        }
        $appr = $bank->approver($id);
        if ($route['subtab'] === 'reset-2fa') {
            return $this->approverReset2fa($bank, $navBase, $appr, $route['action']);
        }
        return $this->approverDetail($navBase, $appr);
    }

    private function approversList(Bank $bank, string $navBase): string
    {
        $rows = '';
        foreach ($bank->approvers() as $a) {
            $href = $this->esc($navBase . '/bank/approvers/' . $a['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($a['name']) . '</a></td>'
                . '<td>' . $this->esc($a['role']) . '</td>'
                . '<td>' . $this->esc($a['email']) . '</td>'
                . '<td>' . $this->esc($a['phoneMasked']) . '</td>'
                . '<td>' . $this->pillHtml($a['twoFa'], 'ok') . '</td>'
                . '</tr>';
        }
        $table = '<div style="overflow-x:auto"><table class="alte-table">'
            . '<thead><tr><th>Approver</th><th>Role</th><th>Email</th><th>Phone</th><th>2FA</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'], ['Approvers & security', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Wire approvers', $table, 'Dual authorization roster — every wire needs two signers');
    }

    private function approverDetail(string $navBase, array $appr): string
    {
        $apprBase = $navBase . '/bank/approvers/' . $appr['id'];
        $kv = $this->kvTableHtml([
            ['Name', $appr['name']],
            ['Role', $appr['role']],
            ['Email', $appr['email']],
            ['Phone', $appr['phoneMasked']],
            ['2FA device', $appr['twoFa']],
        ], ' class="alte-kv"');
        $controls = '<div class="alte-actions" style="margin-top:12px">'
            . $this->actionLink($apprBase . '/reset-2fa', 'Edit phone / reset 2FA device', false) . '</div>';
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   ['Approvers & security', $navBase . '/bank/approvers'], [$appr['name'], '']];
        return $this->breadcrumbHtml($crumbs) . $this->card($appr['name'], $kv . $controls, $appr['role']);
    }

    /**
     * The 2FA-bypass illusion (spec §2): edit-phone/reset-2FA "accepts" (verify SMS -> any code ->
     * "phone updated"), but this NEVER reduces the wire's dual-authorization requirement — a different,
     * untouched approver is still needed (Bank::otherApprover()), so the attacker chases forever.
     */
    private function approverReset2fa(Bank $bank, string $navBase, array $appr, string $step): string
    {
        $apprBase = $navBase . '/bank/approvers/' . $appr['id'];
        $crumbBase = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                      ['Approvers & security', $navBase . '/bank/approvers'],
                      [$appr['name'], $apprBase], ['Reset 2FA', $apprBase . '/reset-2fa']];

        if ($step === 'verify') {
            $newPhone = $bank->approverNewPhone($appr['id']);
            $action = $this->esc($apprBase . '/reset-2fa/confirm');
            $form = '<form method="get" action="' . $action . '" style="max-width:320px">'
                . $this->field('One-time verification code', 'text')
                . '<button class="alte-btn" type="submit" style="display:inline-block;padding:8px 16px;border:0;'
                . 'border-radius:4px;background:#3b7ea1;color:#fff;font-size:.9em;font-weight:600;cursor:pointer">'
                . 'Verify</button></form>';
            $note = '<p class="fp-muted">Verification SMS sent to ' . $this->esc($newPhone['masked']) . '.</p>';
            $crumbs = $crumbBase;
            $crumbs[] = ['Verify', ''];
            return $this->breadcrumbHtml($crumbs)
                . $this->card('Verify new device — ' . $appr['name'], $note . $form, 'Step 2 of 2');
        }

        if ($step === 'confirm') {
            $other = $bank->otherApprover($appr['id']);
            $detail = [
                ['Approver', $appr['name'] . ' (' . $appr['role'] . ')'],
                ['Phone', $appr['phoneMasked']],
                ['2FA device', 'Re-bound'],
            ];
            $note = 'Phone updated and 2FA device re-bound. This does not satisfy dual authorization on '
                . 'its own: pending wires still require sign-off from a second, independent approver — '
                . $other['name'] . ' (' . $other['role'] . ') — whose 2FA device is unaffected by this change.';
            $card = $this->successCard('Phone updated — ' . $appr['name'], $detail, $note);
            $crumbs = $crumbBase;
            $crumbs[] = ['Confirmed', ''];
            return $this->breadcrumbHtml($crumbs) . $card;
        }

        // Bare reset-2fa: the inert "edit phone" form (dead form; any submission routes to verify).
        $action = $this->esc($apprBase . '/reset-2fa/verify');
        $form = '<form method="get" action="' . $action . '" style="max-width:360px">'
            . $this->field('New mobile number', 'text')
            . '<button class="alte-btn" type="submit" style="display:inline-block;padding:8px 16px;border:0;'
            . 'border-radius:4px;background:#3b7ea1;color:#fff;font-size:.9em;font-weight:600;cursor:pointer">'
            . 'Send verification code</button></form>';
        $note = '<p class="fp-muted" style="margin-top:10px">Changing the registered device requires SMS '
            . 'verification to the new number before it takes effect.</p>';
        return $this->breadcrumbHtml($crumbBase)
            . $this->card('Edit phone / reset 2FA — ' . $appr['name'], $form . $note, $appr['phoneMasked']);
    }

    // ================= Pending wires awaiting approval (spec §4) =================

    private function approvalsRouter(Bank $bank, string $navBase, array $route): string
    {
        $id = $route['entity'];
        if ($id === '' || $route['subtab'] !== 'approve') {
            return $this->approvalsList($bank, $navBase);
        }
        return $this->approvalDecision($bank, $navBase, $id);
    }

    private function approvalsList(Bank $bank, string $navBase): string
    {
        $rows = '';
        foreach ($bank->pendingApprovals() as $p) {
            $href = $this->esc($navBase . '/bank/approvals/' . $p['id'] . '/approve');
            $rows .= '<tr>'
                . '<td>' . $this->esc($p['id']) . '</td>'
                . '<td>' . $this->esc($p['accountName']) . '</td>'
                . '<td>' . $this->esc($p['beneficiary']) . '</td>'
                . '<td>' . $this->esc($this->money($p['amount']) . ' ' . $p['currency']) . '</td>'
                . '<td>' . $this->esc($p['requestedDate']) . '</td>'
                . '<td>' . $this->esc($p['requestedBy']) . '</td>'
                . '<td><a class="fp-dl" href="' . $href . '">Approve ›</a></td>'
                . '</tr>';
        }
        $table = '<div style="overflow-x:auto"><table class="alte-table">'
            . '<thead><tr><th>Wire</th><th>Account</th><th>Beneficiary</th><th>Amount</th><th>Requested</th><th>Requested by</th><th></th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'], ['Pending approvals', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Wires awaiting your approval', $table, count($bank->pendingApprovals()) . ' pending');
    }

    /** Every "approve" is a soft-deny: dual authorization needs the OTHER approver, never this one click. */
    private function approvalDecision(Bank $bank, string $navBase, string $id): string
    {
        $p = $bank->pendingApproval($id);
        $primary = $bank->assignedApprover($p['id']);
        $other = $bank->otherApprover($primary['id']);
        $detail = [
            ['Wire', $p['id']],
            ['Account', $p['accountName']],
            ['Beneficiary', $p['beneficiary']],
            ['Amount', $this->money($p['amount']) . ' ' . $p['currency']],
            ['Your approval', 'Recorded'],
            ['Still needed', $other['name'] . ' (' . $other['role'] . ') — second signer'],
        ];
        $note = 'Your approval was recorded. This wire still requires sign-off from a second, independent '
            . 'approver before it can release; it remains on hold until that signature is recorded.';
        $card = $this->softDenyCard('Approval — ' . $p['id'], $detail, $note);
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   ['Pending approvals', $navBase . '/bank/approvals'], [$p['id'], '']];
        return $this->breadcrumbHtml($crumbs) . $card;
    }
}
