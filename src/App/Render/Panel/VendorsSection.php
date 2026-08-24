<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Vendors;
use Funnypot\Support\VisualPersona;

/**
 * Vendors / Suppliers (spec §C.6) — the business-email-compromise (BEC) lure. Renders the five-rung
 * ladder over the `Fake\Vendors` view of the Org roster: vendor landing (+ stat tiles) -> paginated,
 * searchable vendor list -> vendor detail with sub-tabs (overview / spend / invoices / documents /
 * banking) -> invoice detail leaf and the edit-banking control leaf; plus onboarding docs as downloads.
 *
 * The whole surface is INERT and the arithmetic closes: a vendor's spend history, linked invoices, open
 * balance and aging buckets all reconcile to one invoice corpus. The masked remit-to bank details are
 * the AP jackpot the attacker screenshots — and the classic BEC target. Editing them is a GUARDED
 * two-approver + verification-callback wall that never saves: the change is "recorded and routed" for a
 * dual approval and a callback to the vendor's on-file number, so the attacker hunts a second approver
 * and a callback that never resolve. Nothing is persisted; a re-POST renders the same wall.
 *
 * Route slots (PanelRoute): module=vendors; section = ''|<vendor-id>. For a vendor:
 *   entity = a sub-tab (spend/invoices/documents/banking) OR a control verb (edit-banking/invoice);
 *   subtab carries the leaf arg (invoice route id, or edit-banking `submit`).
 */
final class VendorsSection extends AbstractPanelSection
{
    /** Detail sub-tabs (anything else in the entity slot is a control verb or an unknown -> overview). */
    private const SUBTABS = ['overview', 'spend', 'invoices', 'documents', 'banking'];

    private const PAGE_SIZE = 50;

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $vendors = Vendors::fromSeed($persona->seed(), $persona->domain());
        $section = $route['section'];

        if ($section === '') {
            return $this->landing($vendors, $navBase, $route['page']);
        }

        // Otherwise the section slot is a vendor id.
        $vendor = $vendors->vendor($section);
        $verb = $route['entity'];

        if ($verb === 'edit-banking') {
            return $this->editBanking($vendors, $navBase, $vendor, $route['subtab'], $persona->seed());
        }
        if ($verb === 'invoice') {
            return $this->invoiceDetail($vendors, $navBase, $vendor, $route['subtab']);
        }

        $subtab = ($verb !== '' && in_array($verb, self::SUBTABS, true)) ? $verb : 'overview';
        return $this->vendorDetail($vendors, $navBase, $vendor, $subtab);
    }

    // --- landing: stat tiles + paginated, searchable vendor list ---

    private function landing(Vendors $vendors, string $navBase, int $page): string
    {
        $s = $vendors->summary();
        $tiles = $this->statCardsHtml([
            ['label' => 'Vendors', 'value' => number_format($s['total']), 'sub' => 'active suppliers'],
            ['label' => 'Active', 'value' => number_format($s['active'])],
            ['label' => 'On hold', 'value' => number_format($s['onHold'])],
            ['label' => 'Pending review', 'value' => number_format($s['pendingReview'])],
            ['label' => 'Spend YTD', 'value' => $this->money($s['spendYtdCents'])],
            ['label' => 'Open payables', 'value' => $this->money($s['openPayablesCents'])],
            ['label' => 'Bank changes (90d)', 'value' => (string) $s['bankChanges'], 'sub' => 'flagged for review'],
        ], 'fp-tiles', 'fp-tile');

        $total = $s['total'];
        $page = $page < 1 ? 1 : $page;
        $pages = (int) ceil($total / self::PAGE_SIZE);
        if ($pages < 1) {
            $pages = 1;
        }
        if ($page > $pages) {
            $page = $pages;
        }
        $offset = ($page - 1) * self::PAGE_SIZE;
        $rowsData = $vendors->vendorsPage($offset, self::PAGE_SIZE);

        $rows = '';
        foreach ($rowsData as $v) {
            $href = $this->esc($navBase . '/vendors/' . $v['id']);
            $flag = $v['bankChanged'] ? ' ' . $this->pillHtml('bank changed', 'warn') : '';
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($v['name']) . '</a>' . $flag . '</td>'
                . '<td>' . $this->esc($v['category']) . '</td>'
                . '<td>' . $this->esc($v['owner']) . '</td>'
                . '<td>' . $this->esc($v['terms']) . '</td>'
                . '<td>' . $this->esc($this->money($v['spendYtd'])) . '</td>'
                . '<td>' . $this->esc($this->money($v['openBalance'])) . '</td>'
                . '<td>' . $this->pillHtml($v['status'], $this->statusPill($v['status'])) . '</td>'
                . '</tr>';
        }
        $search = '<input id="vnd-q" type="search" placeholder="Filter vendors…" '
            . 'style="margin-bottom:10px;padding:6px 10px;width:100%;max-width:280px;box-sizing:border-box" autocomplete="off">';
        $table = '<div style="overflow-x:auto"><table id="vnd-tbl" class="alte-table">'
            . '<thead><tr><th>Vendor</th><th>Category</th><th>Owner</th><th>Terms</th>'
            . '<th>Spend YTD</th><th>Open balance</th><th>Status</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';

        $from = $total === 0 ? 0 : $offset + 1;
        $to = $offset + count($rowsData);
        $pager = $this->pager($navBase . '/vendors', $page, $pages, $from, $to, $total);

        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Vendors'))
            . $tiles
            . $this->card('Suppliers & vendors',
                $search . $table . $pager . $this->filterScript('vnd-q', 'vnd-tbl'),
                number_format($total) . ' vendors · ' . $this->money($s['openPayablesCents']) . ' open payables');
    }

    // --- vendor detail + sub-tabs ---

    private function vendorDetail(Vendors $vendors, string $navBase, array $vendor, string $subtab): string
    {
        $base = $navBase . '/vendors/' . $vendor['id'];
        $crumbs = [
            ['Corevance', $navBase],
            ['Vendors', $navBase . '/vendors'],
            [$vendor['name'], ''],
        ];

        $tabs = $this->tabStrip($base, $subtab, [
            'overview' => 'Overview',
            'spend' => 'Spend history',
            'invoices' => 'Invoices',
            'documents' => 'Documents',
            'banking' => 'Remit-to / banking',
        ]);

        switch ($subtab) {
            case 'spend':
                $body = $this->spendCard($vendors, $vendor);
                break;
            case 'invoices':
                $body = $this->invoicesCard($vendors, $navBase, $vendor);
                break;
            case 'documents':
                $body = $this->documentsCard($navBase, $vendor);
                break;
            case 'banking':
                $body = $this->bankingCard($vendors, $navBase, $vendor);
                break;
            default:
                $body = $this->overviewCard($vendors, $navBase, $vendor);
        }

        return $this->breadcrumbHtml($crumbs) . $tabs . $body;
    }

    private function overviewCard(Vendors $vendors, string $navBase, array $vendor): string
    {
        $base = $navBase . '/vendors/' . $vendor['id'];
        $contact = $vendors->contactFor($vendor['id']);
        $remit = $vendors->remitToFor($vendor['id']);

        $kv = $this->kvTableHtml([
            ['Vendor id', $vendor['id']],
            ['Status', $vendor['status']],
            ['Category', $vendor['category']],
            ['Payment terms', $vendor['terms']],
            ['Relationship owner', $vendor['owner'] . ' · ' . $vendor['ownerEmail']],
            ['Vendor contact', $contact[0] . ' · ' . $contact[1]],
            ['Tax id', $remit['taxIdMasked']],
            ['Spend YTD', $this->money($vendor['spendYtd'])],
            ['Open balance', $this->money($vendor['openBalance'])],
            ['Invoices on file', (string) $vendor['invoiceCount']],
            ['Last invoice', $vendor['lastInvoice']],
        ], ' class="alte-kv"');

        $flag = $vendor['bankChanged']
            ? '<p class="fp-muted" style="margin-top:8px">' . $this->pillHtml('bank details changed', 'warn')
                . ' Remit-to banking was amended recently — pending AP review.</p>'
            : '';

        $links = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">'
            . $this->actionLink($base . '/invoices', 'View invoices', false)
            . $this->actionLink($base . '/banking', 'Remit-to / banking', false)
            . $this->actionLink($base . '/edit-banking', 'Edit banking details', true)
            . $this->actionLink($base . '/documents', 'Onboarding documents', false)
            . '</div>';

        return $this->card($vendor['name'], $kv . $flag . $links,
            $vendor['category'] . ' · ' . $vendor['terms']);
    }

    private function spendCard(Vendors $vendors, array $vendor): string
    {
        $invoices = $vendors->invoicesFor($vendor['id']);
        $rows = [];
        $sum = 0;
        foreach ($invoices as $inv) {
            if ($inv['paidCents'] <= 0) {
                continue;
            }
            $sum += $inv['paidCents'];
            $rows[] = [$inv['display'], $inv['date'], $inv['po'], $this->money($inv['paidCents']), $inv['status']];
        }
        $table = $this->tableHtml(['Invoice', 'Date', 'PO', 'Paid', 'Status'], $rows, ' class="alte-table"');
        // The footer total equals the row sum, which equals the vendor's spend YTD (arithmetic closes).
        $foot = '<p class="fp-muted" style="margin-top:8px">YTD paid: <strong>'
            . $this->esc($this->money($sum)) . '</strong> (sum of ' . count($rows) . ' settled invoices)</p>';
        return $this->card('Spend history', $table . $foot, $vendor['name']);
    }

    private function invoicesCard(Vendors $vendors, string $navBase, array $vendor): string
    {
        $base = $navBase . '/vendors/' . $vendor['id'];
        $invoices = $vendors->invoicesFor($vendor['id']);
        $rows = '';
        foreach ($invoices as $inv) {
            $href = $this->esc($base . '/invoice/' . $inv['routeId']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($inv['display']) . '</a></td>'
                . '<td>' . $this->esc($inv['date']) . '</td>'
                . '<td>' . $this->esc($inv['due']) . '</td>'
                . '<td>' . $this->esc($this->money($inv['totalCents'])) . '</td>'
                . '<td>' . $this->esc($this->money($inv['paidCents'])) . '</td>'
                . '<td>' . $this->esc($this->money($inv['balanceCents'])) . '</td>'
                . '<td>' . $this->pillHtml($inv['status'], $this->invStatusPill($inv['status'])) . '</td>'
                . '</tr>';
        }
        $table = '<div style="overflow-x:auto"><table class="alte-table">'
            . '<thead><tr><th>Invoice</th><th>Date</th><th>Due</th><th>Total</th><th>Paid</th><th>Balance</th><th>Status</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';

        // Aging table — the buckets sum back to the open balance.
        $agg = $vendors->aggregatesFor($vendor['id']);
        $ageRows = [];
        foreach ($agg['aging'] as $bucket => $cents) {
            $ageRows[] = [$bucket, $this->money($cents)];
        }
        $ageRows[] = ['Open balance (total)', $this->money($agg['openBalance'])];
        $aging = $this->tableHtml(['Aging bucket', 'Amount'], $ageRows, ' class="alte-table"');

        return $this->card('Invoices', $table, $vendor['name'])
            . $this->card('Aging', $aging, 'buckets reconcile to open balance');
    }

    private function documentsCard(string $navBase, array $vendor): string
    {
        $sub = '/vendors/' . $vendor['id'] . '/doc';
        $rows = [
            ['file' => 'vendor_onboarding_pack.pdf.zip', 'cells' => ['Onboarding pack', 'PDF (zip)']],
            ['file' => 'msa_signed.pdf.zip', 'cells' => ['Master services agreement', 'PDF (zip)']],
            ['file' => 'w9_tax_form.pdf.zip', 'cells' => ['Tax form (W-9)', 'PDF (zip)']],
            ['file' => 'insurance_certificate.pdf.zip', 'cells' => ['Certificate of insurance', 'PDF (zip)']],
            ['file' => 'bank_verification_letter.pdf.zip', 'cells' => ['Bank verification letter', 'PDF (zip)']],
        ];
        $dl = $this->downloadTableHtml(
            ['Document', 'Description', 'Format'],
            $rows,
            $navBase,
            $sub,
            ' class="alte-table"',
            'fp-dl'
        );
        return $this->card('Onboarding documents', $dl, $vendor['name']);
    }

    private function bankingCard(Vendors $vendors, string $navBase, array $vendor): string
    {
        $base = $navBase . '/vendors/' . $vendor['id'];
        $remit = $vendors->remitToFor($vendor['id']);
        $kv = $this->kvTableHtml([
            ['Beneficiary', $vendor['name']],
            ['Bank', $remit['bank']],
            ['Account', $remit['accountMasked']],
            ['IBAN', $remit['ibanMasked']],
            ['Sort / routing', $remit['sortMasked']],
            ['SWIFT / BIC', $remit['swiftMasked']],
            ['Tax id', $remit['taxIdMasked']],
        ], ' class="alte-kv"');
        $note = '<p class="fp-muted" style="margin-top:8px">Remit-to details are masked at rest. '
            . 'Changes require dual approval and a verification callback to the vendor\'s on-file number.</p>';
        $edit = '<div class="alte-actions" style="display:flex;gap:8px;margin-top:12px">'
            . $this->actionLink($base . '/edit-banking', 'Edit banking details', true)
            . '</div>';
        return $this->card('Remit-to / banking', $kv . $note . $edit, $vendor['name']);
    }

    // --- invoice detail leaf (lines reconcile to the header) ---

    private function invoiceDetail(Vendors $vendors, string $navBase, array $vendor, string $invoiceRouteId): string
    {
        $base = $navBase . '/vendors/' . $vendor['id'];
        $inv = $vendors->invoice($vendor['id'], $invoiceRouteId);
        $remit = $vendors->remitToFor($vendor['id']);

        $crumbs = [
            ['Corevance', $navBase],
            ['Vendors', $navBase . '/vendors'],
            [$vendor['name'], $base],
            [$inv['display'], ''],
        ];

        $lineRows = [];
        foreach ($inv['lines'] as $l) {
            $lineRows[] = [
                $l['desc'],
                (string) $l['qty'],
                $this->money($l['unitCents']),
                $this->money($l['amountCents']),
            ];
        }
        // Totals appended as body rows so subtotal + tax = total is visible and closes on the page.
        $lineRows[] = ['', '', 'Subtotal', $this->money($inv['subtotalCents'])];
        $lineRows[] = ['', '', 'Tax (' . $inv['taxRate'] . '%)', $this->money($inv['taxCents'])];
        $lineRows[] = ['', '', 'Total', $this->money($inv['totalCents'])];
        $lineRows[] = ['', '', 'Paid', $this->money($inv['paidCents'])];
        $lineRows[] = ['', '', 'Balance', $this->money($inv['balanceCents'])];
        $lines = $this->tableHtml(['Description', 'Qty', 'Unit', 'Amount'], $lineRows, ' class="alte-table"');

        $header = $this->kvTableHtml([
            ['Invoice', $inv['display']],
            ['Vendor', $vendor['name'] . ' (' . $vendor['id'] . ')'],
            ['Invoice date', $inv['date']],
            ['Due date', $inv['due']],
            ['Purchase order', $inv['po']],
            ['Status', $inv['status']],
        ], ' class="alte-kv"');

        $remitPanel = $this->kvTableHtml([
            ['Beneficiary', $vendor['name']],
            ['Bank', $remit['bank']],
            ['Account', $remit['accountMasked']],
            ['IBAN', $remit['ibanMasked']],
            ['SWIFT / BIC', $remit['swiftMasked']],
        ], ' class="alte-kv"');

        $sub = '/vendors/' . $vendor['id'] . '/doc';
        $attach = $this->downloadTableHtml(
            ['Attachment', 'Type'],
            [['file' => $inv['routeId'] . '.pdf.zip', 'cells' => ['Invoice PDF (zip)']]],
            $navBase,
            $sub,
            ' class="alte-table"',
            'fp-dl'
        );

        return $this->breadcrumbHtml($crumbs)
            . $this->card('Invoice ' . $inv['display'], $header, $vendor['name'])
            . $this->card('Line items', $lines, 'subtotal + tax = total')
            . $this->card('Remit-to (masked)', $remitPanel, 'verify by callback before payment')
            . $this->card('Attachments', $attach, '');
    }

    // --- control leaf: edit banking (the BEC target) — inert form -> guarded two-approver wall ---

    private function editBanking(Vendors $vendors, string $navBase, array $vendor, string $step, int $seed): string
    {
        $base = $navBase . '/vendors/' . $vendor['id'];
        $crumbs = [
            ['Corevance', $navBase],
            ['Vendors', $navBase . '/vendors'],
            [$vendor['name'], $base],
            ['Edit banking', ''],
        ];

        // Submit step: the guarded wall. Nothing is saved; a re-POST renders the same wall.
        if ($step === 'submit') {
            $ref = $this->cmdRef($seed, $vendor['id'] . '|bankchg');
            $body = $this->softDenyCard(
                'Vendor banking change — ' . $vendor['name'],
                [
                    ['Vendor', $vendor['name'] . ' (' . $vendor['id'] . ')'],
                    ['Change type', 'Remit-to bank details'],
                    ['Control', 'Dual approval required (AP Manager + Controller)'],
                    ['Verification', 'Callback to vendor on-file number scheduled'],
                    ['Request', $ref . ' recorded — awaiting review'],
                    ['Second approver', 'awaiting — request pending'],
                ],
                'Vendor bank-detail changes cannot take effect from this screen. The request was recorded '
                . 'and routed for a second approval, and a verification callback to the vendor\'s on-file '
                . 'number has been scheduled. No banking details were modified.'
            );
            return $this->breadcrumbHtml($crumbs) . $body;
        }

        // Form step: an inert form. Submitted values are never reflected (no attacker PII echo) or saved.
        $remit = $vendors->remitToFor($vendor['id']);
        $current = $this->kvTableHtml([
            ['Current bank', $remit['bank']],
            ['Current account', $remit['accountMasked']],
            ['Current IBAN', $remit['ibanMasked']],
        ], ' class="alte-kv"');

        $inputStyle = 'display:block;width:100%;max-width:360px;box-sizing:border-box;padding:6px 10px;margin:4px 0 12px';
        $form = '<form method="post" action="' . $this->esc($base . '/edit-banking/submit') . '" autocomplete="off">'
            . '<label style="font-size:.86em;color:#5b636a">New bank name'
            . '<input type="text" name="bank" style="' . $inputStyle . '"></label>'
            . '<label style="font-size:.86em;color:#5b636a">New IBAN / account number'
            . '<input type="text" name="iban" style="' . $inputStyle . '"></label>'
            . '<label style="font-size:.86em;color:#5b636a">New SWIFT / BIC'
            . '<input type="text" name="swift" style="' . $inputStyle . '"></label>'
            . '<button type="submit" class="alte-btn" style="display:inline-block;padding:7px 14px;border:0;'
            . 'border-radius:4px;background:#b23b3b;color:#fff;font-size:.86em;font-weight:600;cursor:pointer">'
            . 'Submit change for approval</button>'
            . '</form>';
        $warn = '<p class="fp-muted" style="margin-top:12px">Changing a vendor\'s remit-to details is a '
            . 'high-risk action. Submissions require a second approver and a verification callback before '
            . 'any change is applied.</p>';

        return $this->breadcrumbHtml($crumbs)
            . $this->card('Edit banking details — ' . $vendor['name'], $current . $form . $warn,
                'dual approval + verification callback required');
    }

    // --- small shared UI helpers (all escape-by-construction) ---

    /** Integer-cents currency formatter — exact (no float drift), so displayed sums keep closing. */
    private function money(int $cents): string
    {
        $sign = $cents < 0 ? '-' : '';
        $c = $cents < 0 ? -$cents : $cents;
        $dollars = intdiv($c, 100);
        $rem = $c % 100;
        return $sign . '$' . number_format($dollars) . '.' . sprintf('%02d', $rem);
    }

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

    /** Deterministic, inert command ref = hash(seed + slot): stable per path, varies per deploy (D.5). */
    private function cmdRef(int $seed, string $slot): string
    {
        return 'VND-CHG-' . strtoupper(substr(hash('sha256', $seed . '|vndcmd|' . $slot), 0, 8));
    }

    private function statusPill(string $status): string
    {
        if ($status === 'Active') {
            return 'ok';
        }
        if ($status === 'On hold') {
            return 'crit';
        }
        return 'warn';
    }

    private function invStatusPill(string $status): string
    {
        if ($status === 'Paid') {
            return 'ok';
        }
        if ($status === 'Overdue') {
            return 'crit';
        }
        if ($status === 'Partial') {
            return 'warn';
        }
        return 'info';
    }
}
