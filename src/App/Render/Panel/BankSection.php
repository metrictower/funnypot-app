<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Bank;
use Funnypot\App\Render\VisualPersona;

/**
 * Bank / Treasury (spec §C.6) — the top-tier greed lure. Renders the five-rung ladder over the
 * `Fake\Bank` view: accounts landing (+ cash-on-hand tiles) -> account detail with sub-tabs
 * (overview / ledger / details / statements) -> the send-wire control leaf; plus the corporate-card
 * fleet (masked) with a per-card reveal that is a non-validating dummy, never a PAN.
 *
 * The whole surface is INERT. The scary money verbs — send wire, transfer, pay, freeze, stop-payment —
 * never return "sent"/"paid"/"done": they land on a GUARDED soft-deny (dual authorization + OFAC /
 * sanctions screening hold) carrying a deterministic wire ref that never resolves. The wire form is a
 * dead form: submitting it only routes to that guarded card. Nothing is persisted; the account detail
 * always shows its seeded balance, so the non-change reads as a pending hold, not a fake. Every
 * banking coordinate is structurally invalid (IBAN check digits 00, routing prefix 00, card PAN with
 * BIN 0000 failing Luhn) so nothing an attacker copies out will ever validate.
 *
 * Route slots (PanelRoute): module=bank; section = ''|cards|<account-id>.
 *  - cards: entity = '' (fleet) | <card-id>; subtab = '' (detail) | reveal.
 *  - account: entity = '' (overview) | ledger|details|statements (sub-tab) | wire|transfer|freeze|
 *    stop-payment|pay (control verb); for wire, subtab = '' (form) | anything (routed -> guarded).
 */
final class BankSection extends AbstractPanelSection
{
    /** Money-movement verbs in the account's entity slot — each lands on a guarded soft-deny. */
    private const CONTROL_VERBS = ['wire', 'transfer', 'freeze', 'stop-payment', 'pay'];

    /** Detail sub-tabs in the account's entity slot — everything else there is a control verb. */
    private const SUBTABS = ['overview', 'ledger', 'details', 'statements'];

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
        $tiles = $this->statCardsHtml([
            ['label' => 'Cash on hand', 'value' => $this->money($s['cashOnHand']), 'sub' => $s['currency'] . ' · all accounts'],
            ['label' => 'Bank accounts', 'value' => (string) $s['accounts']],
            ['label' => 'Largest balance', 'value' => $this->money($s['largest']), 'sub' => $s['largestName']],
            ['label' => 'Corporate cards', 'value' => (string) $s['cards']],
            ['label' => 'Pending wires', 'value' => (string) $s['pendingWires'], 'sub' => 'awaiting authorization'],
        ], 'fp-tiles', 'fp-tile');

        $links = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin:12px 0">'
            . $this->actionLink($navBase . '/bank/cards', 'Corporate cards', false)
            . '</div>';

        $rows = '';
        foreach ($bank->accounts() as $a) {
            $href = $this->esc($navBase . '/bank/' . $a['id']);
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($a['name']) . '</a></td>'
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
            . '<div style="margin-top:8px"><a class="alte-dl" href="' . $this->esc($acctBase . '/ledger') . '">View full ledger ›</a></div>',
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
                'alte-dl'
            )
            . '</div>';

        return $this->card('Transaction ledger', $table . $pager . $export,
            $acct['name'] . ' · running balance in ' . $acct['currency']);
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
        $note = '<p class="alte-muted" style="margin-top:8px">Coordinates shown for reconciliation only. '
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
            'alte-dl'
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
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($c['id']) . '</a></td>'
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

    /** The reveal leaf: a per-card, structurally INVALID PAN (BIN 0000, fails Luhn) — never a real PAN. */
    private function cardReveal(Bank $bank, string $navBase, array $card): string
    {
        $pan = $bank->cardReveal($card['id']);
        $body = $this->kvTableHtml([
            ['Holder', $card['holder']],
            ['Card number', $pan],
            ['Expiry', $card['expiry']],
        ], ' class="fp-result-kv" style="border-collapse:collapse;width:100%"');
        $note = 'This number is issued for reference within the treasury console only and cannot be used '
            . 'for card-present or card-not-present transactions.';
        $card2 = '<div class="fp-result-card" style="background:#fff;border:1px solid #d7dbdf;'
            . 'border-left:4px solid #c07a1a;border-radius:4px;margin:16px 0">'
            . '<div class="fp-result-head" style="padding:10px 14px;border-bottom:1px solid #eef1f3;'
            . 'display:flex;align-items:center;gap:8px">'
            . $this->pillHtml('Revealed', 'warn')
            . '<span class="fp-result-title" style="font-weight:600;color:#2c3136">' . $this->esc('Card ' . $card['id']) . '</span></div>'
            . '<div class="fp-result-body" style="padding:12px 14px">' . $body
            . '<p class="alte-muted" style="margin:10px 0 0">' . $this->esc($note) . '</p></div></div>';
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   ['Corporate cards', $navBase . '/bank/cards'],
                   [$card['id'], $navBase . '/bank/cards/' . $card['id']], ['Reveal', '']];
        return $this->breadcrumbHtml($crumbs) . $card2;
    }

    // --- control leaves (inert; money verbs are always guarded) ---

    /**
     * A money-movement control. `wire` with no submit slot renders the (dead) wire form; every submit
     * and every other money verb returns a guarded soft-deny (dual authorization + OFAC / sanctions
     * hold). Nothing is ever "sent"/"paid" and no state changes.
     */
    private function accountControl(Bank $bank, string $navBase, array $acct, string $verb, string $subtab, string $arg, int $seed): string
    {
        $acctBase = $navBase . '/bank/' . $acct['id'];

        // The bare wire path shows the inert form; submitting it routes back here with a filled subtab.
        if ($verb === 'wire' && $subtab === '') {
            return $this->wireForm($navBase, $acct);
        }

        $crumbs = [
            ['Corevance', $navBase],
            ['Bank & Treasury', $navBase . '/bank'],
            [$acct['name'], $acctBase],
            [$this->verbTitle($verb), ''],
        ];

        if ($verb === 'wire' || $verb === 'transfer' || $verb === 'pay') {
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

    /** The inert wire-out form. Submitting it (any method) only routes to the guarded soft-deny. */
    private function wireForm(string $navBase, array $acct): string
    {
        $acctBase = $navBase . '/bank/' . $acct['id'];
        $action = $this->esc($acctBase . '/wire/submit');
        $form = '<form class="fp-wire-form" method="get" action="' . $action . '" style="max-width:440px">'
            . $this->field('Beneficiary name', 'text')
            . $this->field('Beneficiary bank', 'text')
            . $this->field('IBAN / account number', 'text')
            . $this->field('SWIFT / BIC', 'text')
            . $this->field('Amount (' . $acct['currency'] . ')', 'text')
            . '<button class="alte-btn" type="submit" style="display:inline-block;padding:8px 16px;border:0;'
            . 'border-radius:4px;background:#b23b3b;color:#fff;font-size:.9em;font-weight:600;cursor:pointer">'
            . 'Submit for authorization</button></form>';
        $note = '<p class="alte-muted" style="margin-top:10px">Wires are released only after dual '
            . 'authorization and OFAC / sanctions screening. A verification callback is placed to the '
            . 'beneficiary bank before release.</p>';
        $crumbs = [['Corevance', $navBase], ['Bank & Treasury', $navBase . '/bank'],
                   [$acct['name'], $acctBase], ['Send wire', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Send wire — ' . $acct['name'], $form . $note,
                'From ' . $acct['accountMasked'] . ' · balance ' . $this->money($acct['balance']) . ' ' . $acct['currency']);
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
            . '<p class="alte-muted" style="margin:10px 0 0">' . $this->esc($note) . '</p>'
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
            ? '<a class="alte-dl" href="' . $this->esc($base . '/p' . ($page - 1)) . '">‹ Prev</a>'
            : '<span class="alte-muted">‹ Prev</span>';
        $next = $page < $pages
            ? '<a class="alte-dl" href="' . $this->esc($base . '/p' . ($page + 1)) . '">Next ›</a>'
            : '<span class="alte-muted">Next ›</span>';
        return '<div class="alte-pager" style="display:flex;gap:14px;align-items:center;margin-top:10px">'
            . $prev . $next
            . '<span class="alte-muted">Showing ' . $this->esc(number_format($from)) . '–' . $this->esc(number_format($to))
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

    /** Whole-dollar money formatting; a negative reads as -$N. */
    private function money(int $cents): string
    {
        if ($cents < 0) {
            return '-$' . number_format(-$cents);
        }
        return '$' . number_format($cents);
    }
}
