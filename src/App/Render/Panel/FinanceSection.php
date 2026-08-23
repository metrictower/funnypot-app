<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Finance;
use Funnypot\App\Render\VisualPersona;

/**
 * Finance / Accounts Payable (spec §C.6) — the greed lure. Renders the five-rung ladder over the
 * `Fake\Finance` view of the Org roster + fabricated vendor/invoice/expense corpora: finance dashboard
 * (AP/AR/cash tiles + aging) -> paginated invoices list -> invoice detail with sub-tabs (lines /
 * approval / attachments) -> money control leaves; plus paginated expense reports with detail, and a
 * finance audit-log scroll.
 *
 * The whole surface is INERT, and the SCARY money verbs are GUARDED soft-denials, never a success:
 * `Pay now` hits a four-eyes / segregation-of-duties wall routed to a CFO who exists in the directory but
 * whom the attacker can never act as; `Edit remit-to` (the BEC bait) needs dual approval and never
 * completes. The milder `Approve`/`Reject` land on the canned "queued" receipt. Nothing is persisted; a
 * detail page always shows its seeded state, so a non-change reads as workflow latency, not a fake. All
 * arithmetic closes (line items -> subtotal + tax − discount = total; aging buckets -> AP outstanding;
 * expense lines -> total) so an attacker who adds it up finds it consistent.
 *
 * Route slots (PanelRoute): module=finance;
 *   section = ''(dashboard) | ap | expenses | audit (any other section falls back to the dashboard).
 *   For ap:       entity = ''(list) | <invoice-id>; subtab = detail sub-tab OR a money verb.
 *   For expenses: entity = ''(list) | <report-id>;  subtab = a money verb (else the report detail).
 */
final class FinanceSection extends AbstractPanelSection
{
    /** Money verbs in an invoice's sub-tab slot; anything else there is a detail sub-tab. */
    private const INVOICE_VERBS = ['approve', 'reject', 'pay', 'edit-remit'];

    /** Money verbs in an expense report's sub-tab slot. */
    private const EXPENSE_VERBS = ['approve', 'reject', 'reimburse'];

    private const PAGE_SIZE = 50;

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $fin = Finance::fromSeed($persona->seed(), $persona->domain());
        $section = $route['section'];

        if ($section === 'ap') {
            return $this->ap($fin, $navBase, $route, $persona->seed());
        }
        if ($section === 'expenses') {
            return $this->expenses($fin, $navBase, $route, $persona->seed());
        }
        if ($section === 'audit') {
            return $this->auditLog($fin, $navBase);
        }
        // '' and any unknown section -> the dashboard (a 404 inside a deep panel is a tell).
        return $this->dashboard($fin, $navBase);
    }

    // --- dashboard: stat tiles + aging + jump-off links ---

    private function dashboard(Finance $fin, string $navBase): string
    {
        $d = $fin->dashboard();
        $tiles = $this->statCardsHtml([
            ['label' => 'Cash on hand', 'value' => $fin->money($d['cashOnHand']), 'sub' => 'across all accounts'],
            ['label' => 'AP outstanding', 'value' => $fin->money($d['apOutstanding']), 'sub' => $d['invoicesOpen'] . ' open invoices'],
            ['label' => 'AR outstanding', 'value' => $fin->money($d['arOutstanding'])],
            ['label' => 'Overdue', 'value' => $fin->money($d['overdue']), 'sub' => '31+ days'],
        ], 'fp-tiles', 'fp-tile');

        // Aging table — the buckets sum to AP outstanding by construction.
        $agingRows = [];
        foreach ($d['aging'] as $bucket) {
            $agingRows[] = [$bucket[0], $fin->money($bucket[1])];
        }
        $agingRows[] = ['Total AP outstanding', $fin->money($d['apOutstanding'])];
        $aging = $this->tableHtml(['Bucket', 'Amount'], $agingRows, ' class="alte-table"');

        $links = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin:12px 0">'
            . $this->actionLink($navBase . '/finance/ap', 'Accounts Payable', false)
            . $this->actionLink($navBase . '/finance/expenses', 'Expenses', false)
            . $this->actionLink($navBase . '/finance/audit', 'Audit log', false)
            . '</div>';

        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Finance'))
            . $tiles
            . $links
            . $this->card('AP aging', $aging, 'as of ' . $fin->asOf() . ' · ' . $fin->currency());
    }

    // --- Accounts Payable: invoice list / detail / money leaves ---

    private function ap(Finance $fin, string $navBase, array $route, int $seed): string
    {
        $entity = $route['entity'];
        if ($entity === '') {
            return $this->invoiceList($fin, $navBase, $route['page']);
        }

        $invoice = $fin->invoiceByNumberSlug($entity);
        $verb = $route['subtab'];
        if ($verb !== '' && in_array($verb, self::INVOICE_VERBS, true)) {
            return $this->invoiceControl($fin, $navBase, $invoice, $verb, $seed);
        }
        return $this->invoiceDetail($fin, $navBase, $invoice, $verb === '' ? 'overview' : $verb);
    }

    private function invoiceList(Finance $fin, string $navBase, int $page): string
    {
        $total = $fin->invoiceCount();
        $page = $page < 1 ? 1 : $page;
        $pages = (int) ceil($total / self::PAGE_SIZE);
        if ($pages < 1) {
            $pages = 1;
        }
        if ($page > $pages) {
            $page = $pages;
        }
        $offset = ($page - 1) * self::PAGE_SIZE;
        $invoices = $fin->invoicePage($offset, self::PAGE_SIZE);

        $rows = '';
        foreach ($invoices as $inv) {
            $href = $this->esc($navBase . '/finance/ap/' . $inv['id']);
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($inv['number']) . '</a></td>'
                . '<td>' . $this->esc($inv['vendorName']) . '</td>'
                . '<td>' . $this->esc($inv['po']) . '</td>'
                . '<td>' . $this->esc($inv['dueDate']) . '</td>'
                . '<td>' . $this->esc($fin->money($inv['totalCents'])) . '</td>'
                . '<td>' . $this->esc($fin->money($inv['balanceCents'])) . '</td>'
                . '<td>' . $this->pillHtml($inv['status'], $this->invoiceStatus($inv['status'])) . '</td>'
                . '<td>' . $this->esc($inv['approver'] !== '' ? $inv['approver'] : '—') . '</td>'
                . '</tr>';
        }
        $search = '<input id="fin-inv-q" type="search" placeholder="Filter by vendor, number, amount, status…" '
            . 'style="margin-bottom:10px;padding:6px 10px;width:100%;max-width:340px;box-sizing:border-box" autocomplete="off">';
        $table = '<div style="overflow-x:auto"><table id="fin-inv-tbl" class="alte-table">'
            . '<thead><tr><th>Invoice</th><th>Vendor</th><th>PO</th><th>Due</th><th>Total</th><th>Balance</th><th>Status</th><th>Approver</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';

        $from = $total === 0 ? 0 : $offset + 1;
        $to = $offset + count($invoices);
        $pager = $this->pager($navBase . '/finance/ap', $page, $pages, $from, $to, $total);

        $crumbs = [['Corevance', $navBase], ['Finance', $navBase . '/finance'], ['Accounts Payable', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Invoices', $search . $table . $pager . $this->filterScript('fin-inv-q', 'fin-inv-tbl'),
                number_format($total) . ' invoices · FY ' . $fin->fiscalYear());
    }

    private function invoiceDetail(Finance $fin, string $navBase, array $inv, string $subtab): string
    {
        $invBase = $navBase . '/finance/ap/' . $inv['id'];
        $crumbs = [
            ['Corevance', $navBase],
            ['Finance', $navBase . '/finance'],
            ['Accounts Payable', $navBase . '/finance/ap'],
            [$inv['number'], ''],
        ];
        $tabs = $this->tabStrip($invBase, $subtab, [
            'overview' => 'Overview',
            'lines' => 'Line items',
            'approval' => 'Approval trail',
            'attachments' => 'Attachments',
        ]);

        switch ($subtab) {
            case 'lines':
                $body = $this->invoiceLinesCard($fin, $inv);
                break;
            case 'approval':
                $body = $this->invoiceApprovalCard($fin, $inv);
                break;
            case 'attachments':
                $body = $this->invoiceAttachmentsCard($navBase, $inv);
                break;
            default:
                $body = $this->invoiceOverviewCard($fin, $navBase, $inv);
        }
        return $this->breadcrumbHtml($crumbs) . $tabs . $body;
    }

    private function invoiceOverviewCard(Finance $fin, string $navBase, array $inv): string
    {
        $kv = $this->kvTableHtml([
            ['Invoice', $inv['number']],
            ['Vendor', $inv['vendorName']],
            ['Purchase order', $inv['po']],
            ['Invoice date', $inv['invoiceDate']],
            ['Due date', $inv['dueDate']],
            ['Total', $fin->money($inv['totalCents'])],
            ['Paid', $fin->money($inv['paidCents'])],
            ['Balance', $fin->money($inv['balanceCents'])],
            ['Status', $inv['status']],
            ['Approver', $inv['approver'] !== '' ? $inv['approver'] : 'unassigned'],
        ], ' class="alte-kv"');

        // Remit-to — masked at rest, structurally invalid on reveal (the AP jackpot the attacker screenshots).
        $vendor = $this->vendorForInvoice($fin, $inv);
        $remit = $this->kvTableHtml([
            ['Beneficiary', $vendor['name']],
            ['Bank', $vendor['bankName']],
            ['Account', $vendor['acctMasked']],
            ['Sort code', $vendor['sortMasked']],
            ['IBAN', $vendor['ibanMasked']],
        ], ' class="alte-kv"');

        $invBase = $navBase . '/finance/ap/' . $inv['id'];
        $controls = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">'
            . $this->actionLink($invBase . '/approve', 'Approve', false)
            . $this->actionLink($invBase . '/reject', 'Reject', false)
            . $this->actionLink($invBase . '/pay', 'Pay now', true)
            . $this->actionLink($invBase . '/edit-remit', 'Edit remit-to', true)
            . '</div>';

        return $this->card($inv['number'], $kv . $controls, $inv['vendorName'] . ' · ' . $inv['status'])
            . $this->card('Remit-to (banking)', $remit, 'masked — verification required to release');
    }

    private function invoiceLinesCard(Finance $fin, array $inv): string
    {
        $rows = [];
        foreach ($inv['lines'] as $line) {
            $rows[] = [
                $line['desc'],
                (string) $line['qty'],
                $fin->money($line['unitCents']),
                $fin->money($line['lineCents']),
            ];
        }
        $table = $this->tableHtml(['Description', 'Qty', 'Unit price', 'Line total'], $rows, ' class="alte-table"');

        // Totals block — subtotal + tax − discount = total, verifiable against the line sum above.
        $totalsPairs = [
            ['Subtotal', $fin->money($inv['subtotalCents'])],
            ['Tax (' . number_format($inv['taxRateBp'] / 100, 2) . '%)', $fin->money($inv['taxCents'])],
        ];
        if ($inv['discountCents'] > 0) {
            $totalsPairs[] = ['Discount', '-' . $fin->money($inv['discountCents'])];
        }
        $totalsPairs[] = ['Total', $fin->money($inv['totalCents'])];
        $totals = $this->kvTableHtml($totalsPairs, ' class="alte-kv"');

        return $this->card('Line items', $table . $totals, $inv['number']);
    }

    private function invoiceApprovalCard(Finance $fin, array $inv): string
    {
        $pairs = [
            ['Created', $inv['invoiceDate'] . ' · AP automation'],
            ['Three-way match', 'PO ' . $inv['po'] . ' · goods receipt · invoice'],
        ];
        if ($inv['approver'] !== '') {
            $pairs[] = ['Approved by', $inv['approver'] . ' <' . $inv['approverEmail'] . '>'];
        } else {
            $pairs[] = ['First approval', 'pending'];
        }
        $second = $fin->secondApprover();
        $pairs[] = ['Second approver', $second['name'] . ' (' . $second['title'] . ') — required for payment'];
        $pairs[] = ['Status', $inv['status']];
        return $this->card('Approval trail', $this->kvTableHtml($pairs, ' class="alte-kv"'), $inv['number']);
    }

    private function invoiceAttachmentsCard(string $navBase, array $inv): string
    {
        $files = [
            ['file' => 'invoice_' . $inv['id'] . '.pdf.zip', 'cells' => ['Vendor invoice', 'PDF (zip)']],
            ['file' => 'po_' . strtolower($inv['po']) . '.pdf.zip', 'cells' => ['Purchase order', 'PDF (zip)']],
            ['file' => 'grn_' . $inv['id'] . '.pdf.zip', 'cells' => ['Goods-receipt note', 'PDF (zip)']],
        ];
        $table = $this->downloadTableHtml(
            ['File', 'Type', 'Format'],
            $files,
            $navBase,
            '/finance/download',
            ' class="alte-table"',
            'alte-dl'
        );
        return $this->card('Attachments', $table, $inv['number']);
    }

    /**
     * A per-invoice money control. `approve`/`reject` are the canned queue; `pay` and `edit-remit` are
     * GUARDED soft-denials (four-eyes / dual approval) that never claim the money moved.
     */
    private function invoiceControl(Finance $fin, string $navBase, array $inv, string $verb, int $seed): string
    {
        $invBase = $navBase . '/finance/ap/' . $inv['id'];
        $crumbs = [
            ['Corevance', $navBase],
            ['Finance', $navBase . '/finance'],
            ['Accounts Payable', $navBase . '/finance/ap'],
            [$inv['number'], $invBase],
            [ucfirst(str_replace('-', ' ', $verb)), ''],
        ];
        $second = $fin->secondApprover();

        if ($verb === 'pay') {
            $ref = $this->cmdRef($seed, $inv['id'] . '|pay');
            $body = $this->softDenyCard(
                'Pay now — ' . $inv['number'],
                [
                    ['Invoice', $inv['number'] . ' · ' . $inv['vendorName']],
                    ['Amount', $fin->money($inv['balanceCents'])],
                    ['Reason', 'Payment requires secondary authorization (four-eyes). You cannot approve a payment you initiated (segregation of duties).'],
                    ['Routed to', $second['name'] . ' (' . $second['title'] . ')'],
                    ['Request', $ref . ' · awaiting second approver'],
                ],
                'The payment request was recorded and routed to the CFO for secondary authorization. No funds have moved and no bank system was contacted; the invoice balance is unchanged until a second authorized approver releases it.'
            );
            return $this->breadcrumbHtml($crumbs) . $body;
        }

        if ($verb === 'edit-remit') {
            $ref = $this->cmdRef($seed, $inv['id'] . '|remit');
            $body = $this->softDenyCard(
                'Edit remit-to — ' . $inv['vendorName'],
                [
                    ['Vendor', $inv['vendorName']],
                    ['Reason', 'A change to vendor bank details requires dual approval (Finance controller + CFO) and an out-of-band verification callback.'],
                    ['Routed to', $second['name'] . ' (' . $second['title'] . ')'],
                    ['Request', $ref . ' · verification callback scheduled'],
                    ['Second approver', 'awaiting — request pending'],
                ],
                'The banking change was submitted for dual approval and a verification callback was scheduled with the vendor on file. No remit-to detail has changed; the request will not apply until both approvals are registered.'
            );
            return $this->breadcrumbHtml($crumbs) . $body;
        }

        // approve / reject — canned queue (no money moves either way).
        $detail = [
            ['Invoice', $inv['number'] . ' · ' . $inv['vendorName']],
            ['Amount', $fin->money($inv['totalCents'])],
            ['Job', $this->cmdRef($seed, $inv['id'] . '|' . $verb)],
            ['Status', $verb === 'approve'
                ? 'queued for approval workflow; posts at next AP sync (~2 min)'
                : 'rejection queued; vendor notified at next AP sync (~2 min)'],
        ];
        return $this->breadcrumbHtml($crumbs)
            . $this->controlResultCard(ucfirst($verb) . ' — ' . $inv['number'], $detail);
    }

    /** Resolve the vendor record behind an invoice (for the remit-to panel), by matching vendor id. */
    private function vendorForInvoice(Finance $fin, array $inv): array
    {
        for ($j = 0; $j < $fin->vendorCount(); $j++) {
            $v = $fin->vendorAt($j);
            if ($v['id'] === $inv['vendorId']) {
                return $v;
            }
        }
        return $fin->vendorAt(0);
    }

    // --- Expenses: report list / detail / money leaves ---

    private function expenses(Finance $fin, string $navBase, array $route, int $seed): string
    {
        $entity = $route['entity'];
        if ($entity === '') {
            return $this->expenseList($fin, $navBase, $route['page']);
        }
        $report = $fin->expenseByNumberSlug($entity);
        $verb = $route['subtab'];
        if ($verb !== '' && in_array($verb, self::EXPENSE_VERBS, true)) {
            return $this->expenseControl($fin, $navBase, $report, $verb, $seed);
        }
        return $this->expenseDetail($fin, $navBase, $report);
    }

    private function expenseList(Finance $fin, string $navBase, int $page): string
    {
        $total = $fin->expenseCount();
        $page = $page < 1 ? 1 : $page;
        $pages = (int) ceil($total / self::PAGE_SIZE);
        if ($pages < 1) {
            $pages = 1;
        }
        if ($page > $pages) {
            $page = $pages;
        }
        $offset = ($page - 1) * self::PAGE_SIZE;
        $reports = $fin->expensePage($offset, self::PAGE_SIZE);

        $rows = '';
        foreach ($reports as $r) {
            $href = $this->esc($navBase . '/finance/expenses/' . $r['id']);
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($r['number']) . '</a></td>'
                . '<td>' . $this->esc($r['employee']) . '</td>'
                . '<td>' . $this->esc($r['submitted']) . '</td>'
                . '<td>' . $this->esc($fin->money($r['totalCents'])) . '</td>'
                . '<td>' . $this->pillHtml($r['status'], $this->expenseStatus($r['status'])) . '</td>'
                . '</tr>';
        }
        $search = '<input id="fin-exp-q" type="search" placeholder="Filter by employee, number, amount, status…" '
            . 'style="margin-bottom:10px;padding:6px 10px;width:100%;max-width:340px;box-sizing:border-box" autocomplete="off">';
        $table = '<div style="overflow-x:auto"><table id="fin-exp-tbl" class="alte-table">'
            . '<thead><tr><th>Report</th><th>Employee</th><th>Submitted</th><th>Total</th><th>Status</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';

        $from = $total === 0 ? 0 : $offset + 1;
        $to = $offset + count($reports);
        $pager = $this->pager($navBase . '/finance/expenses', $page, $pages, $from, $to, $total);

        $crumbs = [['Corevance', $navBase], ['Finance', $navBase . '/finance'], ['Expenses', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Expense reports', $search . $table . $pager . $this->filterScript('fin-exp-q', 'fin-exp-tbl'),
                number_format($total) . ' reports · FY ' . $fin->fiscalYear());
    }

    private function expenseDetail(Finance $fin, string $navBase, array $r): string
    {
        $rows = [];
        foreach ($r['lines'] as $line) {
            $rows[] = [$line['date'], $line['category'], $line['merchant'], $fin->money($line['amountCents'])];
        }
        $table = $this->tableHtml(['Date', 'Category', 'Merchant', 'Amount'], $rows, ' class="alte-table"');
        $totals = $this->kvTableHtml([['Report total', $fin->money($r['totalCents'])]], ' class="alte-kv"');

        // Receipts as decoy archive downloads.
        $files = [];
        foreach ($r['receipts'] as $n => $name) {
            $files[] = ['file' => $name, 'cells' => ['Receipt ' . ($n + 1), 'PDF (zip)']];
        }
        $receipts = $this->downloadTableHtml(['File', 'Item', 'Format'], $files, $navBase, '/finance/download', ' class="alte-table"', 'alte-dl');

        $meta = $this->kvTableHtml([
            ['Report', $r['number']],
            ['Employee', $r['employee'] . ' <' . $r['employeeEmail'] . '>'],
            ['Submitted', $r['submitted']],
            ['Status', $r['status']],
        ], ' class="alte-kv"');

        $rptBase = $navBase . '/finance/expenses/' . $r['id'];
        $controls = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">'
            . $this->actionLink($rptBase . '/approve', 'Approve', false)
            . $this->actionLink($rptBase . '/reject', 'Reject', false)
            . $this->actionLink($rptBase . '/reimburse', 'Reimburse', true)
            . '</div>';

        $crumbs = [['Corevance', $navBase], ['Finance', $navBase . '/finance'], ['Expenses', $navBase . '/finance/expenses'], [$r['number'], '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card($r['number'], $meta . $controls, $r['employee'] . ' · ' . $r['status'])
            . $this->card('Line items', $table . $totals, $r['number'])
            . $this->card('Receipts', $receipts, 'attachments');
    }

    /** `approve`/`reject` are the canned queue; `reimburse` (money out) is a four-eyes soft-deny. */
    private function expenseControl(Finance $fin, string $navBase, array $r, string $verb, int $seed): string
    {
        $rptBase = $navBase . '/finance/expenses/' . $r['id'];
        $crumbs = [
            ['Corevance', $navBase],
            ['Finance', $navBase . '/finance'],
            ['Expenses', $navBase . '/finance/expenses'],
            [$r['number'], $rptBase],
            [ucfirst($verb), ''],
        ];

        if ($verb === 'reimburse') {
            $second = $fin->secondApprover();
            $ref = $this->cmdRef($seed, $r['id'] . '|reimburse');
            $body = $this->softDenyCard(
                'Reimburse — ' . $r['number'],
                [
                    ['Report', $r['number'] . ' · ' . $r['employee']],
                    ['Amount', $fin->money($r['totalCents'])],
                    ['Reason', 'Reimbursement requires a second approver (four-eyes) before disbursement.'],
                    ['Routed to', $second['name'] . ' (' . $second['title'] . ')'],
                    ['Request', $ref . ' · awaiting second approver'],
                ],
                'The reimbursement was recorded and routed for secondary authorization. No funds have moved; the report stays payable-pending until a second approver releases it.'
            );
            return $this->breadcrumbHtml($crumbs) . $body;
        }

        $detail = [
            ['Report', $r['number'] . ' · ' . $r['employee']],
            ['Amount', $fin->money($r['totalCents'])],
            ['Job', $this->cmdRef($seed, $r['id'] . '|' . $verb)],
            ['Status', $verb === 'approve'
                ? 'queued for approval; posts at next expense sync (~2 min)'
                : 'rejection queued; employee notified at next expense sync (~2 min)'],
        ];
        return $this->breadcrumbHtml($crumbs)
            . $this->controlResultCard(ucfirst($verb) . ' — ' . $r['number'], $detail);
    }

    // --- finance audit-log scroll ---

    private function auditLog(Finance $fin, string $navBase): string
    {
        $lines = $fin->auditLog(220);
        $scroll = $this->preScrollHtml($lines, 'alte-log');
        $crumbs = [['Corevance', $navBase], ['Finance', $navBase . '/finance'], ['Audit log', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Finance audit log', $scroll,
                number_format($fin->auditRowCount()) . ' entries · live tail (cached ~30 s)');
    }

    // --- small shared UI helpers (all escape-by-construction) ---

    /** A guarded-denial card: same construction as controlResultCard but a crit pill + no "queued". */
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
            $isActive = ($active === $slug) || ($active === 'overview' && $slug === 'overview');
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

    /** Deterministic, inert command ref = hash(seed + slot): stable per path, varies per deploy (D.5). */
    private function cmdRef(int $seed, string $slot): string
    {
        return 'FIN-CMD-' . strtoupper(substr(hash('sha256', $seed . '|fincmd|' . $slot), 0, 6));
    }

    private function invoiceStatus(string $status): string
    {
        if ($status === 'Paid') {
            return 'ok';
        }
        if ($status === 'Overdue') {
            return 'crit';
        }
        if ($status === 'Rejected') {
            return 'idle';
        }
        if ($status === 'Approved') {
            return 'info';
        }
        return 'warn';       // Pending
    }

    private function expenseStatus(string $status): string
    {
        if ($status === 'Reimbursed') {
            return 'ok';
        }
        if ($status === 'Approved') {
            return 'info';
        }
        if ($status === 'Rejected') {
            return 'idle';
        }
        return 'warn';       // Submitted
    }
}
