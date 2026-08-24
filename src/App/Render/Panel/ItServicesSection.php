<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Helpdesk;
use Funnypot\App\Render\Fake\ItServices;
use Funnypot\App\Render\VisualPersona;

/**
 * IT & Platform services (spec §C.7) — the lateral-movement intel lure. One section renders six sub-areas
 * over the shared spines (`Fake\Helpdesk` + `Fake\ItServices`, both VIEWS of the `Org` roster and
 * `Fake\Building`): helpdesk TICKETS (list -> threaded detail with a comment thread), PRINTERS/MFPs (per
 * printer: model, Building-room location, queue, toner, scan-to-email -> release/cancel a job), software
 * LICENCES (seats used/total, key masked + per-key non-validating reveal), the MDM endpoint fleet
 * (device/os/compliance/last-sync -> guarded fleet + per-device controls), MAIL admin (mailboxes, quotas,
 * forwarding rules) and CERTIFICATES (subject/issuer/expiry off the frozen clock, fingerprint).
 *
 * The whole surface is INERT. The mild verbs (release a print job, add a forwarding rule) land on the
 * canned "queued" receipt; the DESTRUCTIVE verbs (MDM remote wipe, mailbox search-and-purge) return a
 * GUARDED soft-deny that never claims anything was deleted — the second approver the attacker hunts does
 * not exist, so failure burns more time than success. Nothing is persisted; a detail page always shows
 * its seeded state, so a non-change reads as sync latency, not a fake.
 *
 * Routing. The canonical module slug is `helpdesk`; a sub-area is the SECTION slot
 * (`/{mount}/helpdesk/{area}/...`). Each area also has a root alias (printers/licenses/mdm/mail/
 * certificates/tickets), so `/{mount}/printers/...` reaches the same area with the slots shifted up one —
 * both entry styles are normalised here into (area, entity, subtab, action) and one $root path prefix so
 * every link the page emits stays under whichever entry the crawler is on.
 */
final class ItServicesSection extends AbstractPanelSection
{
    private const PAGE_SIZE = 50;

    /** Module slugs that root the tickets-first landing; anything else entering here is an area alias. */
    private const HELPDESK_FAMILY = ['helpdesk', 'it', 'itsm', ''];

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $seed = $persona->seed();
        $domain = $persona->domain();
        $hd = Helpdesk::fromSeed($seed, $domain);
        $it = ItServices::fromSeed($seed, $domain);

        $module = $route['module'];
        if (in_array($module, self::HELPDESK_FAMILY, true)) {
            // /mount/helpdesk[/<area>/...] — but tickets is the default area with no path token of its own,
            // so a non-area section slot is a ticket id sitting one level up (module=helpdesk/section=<id>).
            $areaKw = $this->areaKeyword($route['section']);
            if ($areaKw === null) {
                $area = 'tickets';
                $entity = $route['section'];
                $subtab = $route['entity'];
                $action = $route['subtab'];
                $root = $navBase . '/helpdesk';
            } else {
                $area = $areaKw;
                $entity = $route['entity'];
                $subtab = $route['subtab'];
                $action = $route['action'];
                $root = $area === 'tickets' ? $navBase . '/helpdesk' : $navBase . '/helpdesk/' . $area;
            }
        } else {
            // Entered via an area root alias (/admin/printers/...): the module IS the area; slots shift up.
            $areaKw = $this->areaKeyword($module);
            $area = $areaKw === null ? 'tickets' : $areaKw;
            $entity = $route['section'];
            $subtab = $route['entity'];
            $action = $route['subtab'];
            $root = $navBase . '/' . $module;
        }
        $page = $route['page'];

        switch ($area) {
            case 'printers':
                return $this->printersArea($it, $navBase, $root, $entity, $subtab, $action, $page, $seed);
            case 'licenses':
                return $this->licensesArea($it, $navBase, $root, $entity, $subtab, $page);
            case 'mdm':
                return $this->mdmArea($it, $navBase, $root, $entity, $subtab, $page, $seed);
            case 'mail':
                return $this->mailArea($it, $navBase, $root, $entity, $subtab, $page, $seed);
            case 'certs':
                return $this->certsArea($it, $navBase, $root, $entity, $page);
            default:
                return $this->ticketsArea($hd, $navBase, $root, $entity, $subtab, $page);
        }
    }

    /**
     * Map an area token (a section slot or an alias module) to its canonical area name, or null when the
     * token is NOT an area keyword — in which case it is a ticket id in the default tickets area, not a
     * sub-area. Keeping tickets out of the keyword set is what lets `/helpdesk/<ticket-id>` resolve.
     */
    private function areaKeyword(string $slug): ?string
    {
        $map = [
            'tickets' => 'tickets', 'ticket' => 'tickets', 'helpdesk' => 'tickets',
            'printers' => 'printers', 'printer' => 'printers', 'mfp' => 'printers',
            'licenses' => 'licenses', 'license' => 'licenses', 'licensing' => 'licenses', 'licences' => 'licenses',
            'mdm' => 'mdm', 'endpoints' => 'mdm', 'endpoint' => 'mdm', 'devices' => 'mdm',
            'mail' => 'mail', 'email' => 'mail', 'mailboxes' => 'mail',
            'certs' => 'certs', 'certificates' => 'certs', 'certificate' => 'certs', 'cert' => 'certs',
        ];
        return isset($map[$slug]) ? $map[$slug] : null;
    }

    // =====================================================================
    // Helpdesk tickets
    // =====================================================================

    private function ticketsArea(Helpdesk $hd, string $navBase, string $root, string $entity, string $subtab, int $page): string
    {
        if ($entity === '') {
            return $this->ticketList($hd, $navBase, $root, $page);
        }
        return $this->ticketDetail($hd, $navBase, $root, $hd->ticketByIdSlug($entity), $subtab === '' ? 'overview' : $subtab);
    }

    private function ticketList(Helpdesk $hd, string $navBase, string $root, int $page): string
    {
        $total = $hd->ticketCount();
        [$page, $pages, $offset] = $this->paginate($total, $page);
        $tickets = $hd->ticketPage($offset, self::PAGE_SIZE);

        $rows = '';
        foreach ($tickets as $t) {
            $href = $this->esc($root . '/' . $t['id']);
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($t['number']) . '</a></td>'
                . '<td>' . $this->esc($t['subject']) . '</td>'
                . '<td>' . $this->esc($t['requester']) . '</td>'
                . '<td>' . $this->esc($t['assignee']) . '</td>'
                . '<td>' . $this->pillHtml($t['priority'], $this->priorityStatus($t['priority'])) . '</td>'
                . '<td>' . $this->pillHtml($t['status'], $this->ticketStatus($t['status'])) . '</td>'
                . '<td>' . $this->esc($t['updated']) . '</td>'
                . '</tr>';
        }
        $search = $this->searchBox('its-tkt-q', 'Filter by number, subject, requester, assignee…');
        $table = '<div style="overflow-x:auto"><table id="its-tkt-tbl" class="alte-table">'
            . '<thead><tr><th>Ticket</th><th>Subject</th><th>Requester</th><th>Assignee</th><th>Priority</th><th>Status</th><th>Updated</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        $pager = $this->pagerHtml($root, $page, $pages, $this->pageSummary($offset, count($tickets), $total, 'tickets'));

        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Helpdesk', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->areaNav($navBase, 'tickets')
            . $this->card('Helpdesk tickets', $search . $table . $pager . $this->filterScript('its-tkt-q', 'its-tkt-tbl'),
                number_format($total) . ' tickets · ITSM queue');
    }

    private function ticketDetail(Helpdesk $hd, string $navBase, string $root, array $t, string $subtab): string
    {
        $tBase = $root . '/' . $t['id'];
        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Helpdesk', $root], [$t['number'], '']];
        $tabs = $this->tabStrip($tBase, $subtab, [
            'overview' => 'Overview',
            'comments' => 'Comments',
            'attachments' => 'Attachments',
        ]);

        if ($subtab === 'comments') {
            $body = $this->ticketCommentsCard($t);
        } elseif ($subtab === 'attachments') {
            $body = $this->ticketAttachmentsCard($navBase, $t);
        } else {
            $body = $this->ticketOverviewCard($t);
        }
        return $this->breadcrumbHtml($crumbs) . $tabs . $body;
    }

    private function ticketOverviewCard(array $t): string
    {
        $kv = $this->kvTableHtml([
            ['Ticket', $t['number']],
            ['Subject', $t['subject']],
            ['Category', $t['category']],
            ['Priority', $t['priority']],
            ['Status', $t['status']],
            ['Requester', $t['requester'] . ' <' . $t['requesterEmail'] . '> · ' . $t['requesterDept']],
            ['Assignee', $t['assignee'] . ' <' . $t['assigneeEmail'] . '>'],
            ['Created', $t['created']],
            ['Last updated', $t['updated']],
        ], ' class="alte-kv"');
        $desc = '<p style="margin:10px 0 0">' . $this->esc($t['description']) . '</p>';
        return $this->card($t['number'], $kv . $desc, $t['requester'] . ' · ' . $t['status']);
    }

    private function ticketCommentsCard(array $t): string
    {
        $thread = '';
        foreach ($t['comments'] as $c) {
            $tag = $c['internal']
                ? '<span class="alte-muted" style="color:#b23b3b;font-weight:600"> · internal note</span>'
                : '';
            $border = $c['internal'] ? '#b23b3b' : '#3b7ea1';
            $thread .= '<div style="border-left:3px solid ' . $border . ';padding:6px 12px;margin:8px 0;background:#fafbfc">'
                . '<div style="font-size:.84em;color:#5b636a"><strong>' . $this->esc($c['author']) . '</strong> · '
                . $this->esc($c['when']) . $tag . '</div>'
                . '<div style="margin-top:3px">' . $this->esc($c['body']) . '</div></div>';
        }
        return $this->card('Comment thread', $thread, $t['number']);
    }

    private function ticketAttachmentsCard(string $navBase, array $t): string
    {
        $files = [];
        foreach ($t['attachments'] as $n => $name) {
            $files[] = ['file' => $name, 'cells' => ['Attachment ' . ($n + 1), 'archive (zip)']];
        }
        $table = $this->downloadTableHtml(['File', 'Item', 'Format'], $files, $navBase, '/helpdesk/download', ' class="alte-table"', 'alte-dl');
        return $this->card('Attachments', $table, $t['number']);
    }

    // =====================================================================
    // Printers / MFPs
    // =====================================================================

    private function printersArea(ItServices $it, string $navBase, string $root, string $entity, string $subtab, string $action, int $page, int $seed): string
    {
        if ($entity === '') {
            return $this->printerList($it, $navBase, $root, $page);
        }
        $printer = $it->printerById($entity);
        if ($subtab === 'release' || $subtab === 'cancel') {
            return $this->printerControl($navBase, $root, $printer, $subtab, $action, $seed);
        }
        return $this->printerDetail($it, $navBase, $root, $printer, $subtab === '' ? 'overview' : $subtab);
    }

    private function printerList(ItServices $it, string $navBase, string $root, int $page): string
    {
        $total = $it->printerCount();
        [$page, $pages, $offset] = $this->paginate($total, $page);
        $printers = $it->printerPage($offset, self::PAGE_SIZE);

        $rows = '';
        foreach ($printers as $p) {
            $href = $this->esc($root . '/' . $p['id']);
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($p['id']) . '</a></td>'
                . '<td>' . $this->esc($p['model']) . '</td>'
                . '<td>' . $this->esc($p['location']) . '</td>'
                . '<td>' . $this->esc($p['ip']) . '</td>'
                . '<td>' . $this->pillHtml($p['status'], $this->printerStatus($p['status'])) . '</td>'
                . '<td>' . (string) $p['queueJobs'] . '</td>'
                . '<td>' . (string) $p['tonerBlack'] . '%</td>'
                . '</tr>';
        }
        $search = $this->searchBox('its-prn-q', 'Filter printers…');
        $table = '<div style="overflow-x:auto"><table id="its-prn-tbl" class="alte-table">'
            . '<thead><tr><th>Printer</th><th>Model</th><th>Location</th><th>IP</th><th>Status</th><th>Queue</th><th>Toner (K)</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        $pager = $this->pagerHtml($root, $page, $pages, $this->pageSummary($offset, count($printers), $total, 'printers'));

        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Printers & MFPs', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->areaNav($navBase, 'printers')
            . $this->card('Printer status', $search . $table . $pager . $this->filterScript('its-prn-q', 'its-prn-tbl'),
                number_format($total) . ' devices');
    }

    private function printerDetail(ItServices $it, string $navBase, string $root, array $p, string $subtab): string
    {
        $pBase = $root . '/' . $p['id'];
        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Printers & MFPs', $root], [$p['id'], '']];
        $tabs = $this->tabStrip($pBase, $subtab, [
            'overview' => 'Overview',
            'queue' => 'Print queue',
            'toner' => 'Consumables',
            'scan' => 'Scan-to-email',
        ]);

        if ($subtab === 'queue') {
            $body = $this->printerQueueCard($it, $pBase, $p);
        } elseif ($subtab === 'toner') {
            $body = $this->printerTonerCard($p);
        } elseif ($subtab === 'scan') {
            $body = $this->printerScanCard($p);
        } else {
            $body = $this->printerOverviewCard($pBase, $p);
        }
        return $this->breadcrumbHtml($crumbs) . $tabs . $body;
    }

    private function printerOverviewCard(string $pBase, array $p): string
    {
        $kv = $this->kvTableHtml([
            ['Device id', $p['id']],
            ['Model', $p['model']],
            ['Location', $p['location']],
            ['IP address', $p['ip']],
            ['Serial', $p['serial']],
            ['Firmware', $p['firmware']],
            ['Status', $p['status']],
            ['Queued jobs', (string) $p['queueJobs']],
            ['Last seen', $p['lastSeen']],
        ], ' class="alte-kv"');
        $links = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">'
            . $this->actionLink($pBase . '/queue', 'View print queue', false)
            . $this->actionLink($pBase . '/scan', 'Scan-to-email config', false)
            . '</div>';
        return $this->card($p['id'], $kv . $links, $p['model'] . ' · ' . $p['status']);
    }

    private function printerQueueCard(ItServices $it, string $pBase, array $p): string
    {
        $jobs = $it->printerQueue($p);
        if ($jobs === []) {
            return $this->card('Print queue', '<p class="alte-muted">Queue is empty.</p>', $p['id']);
        }
        $rows = '';
        foreach ($jobs as $j) {
            $rows .= '<tr>'
                . '<td>' . $this->esc($j['jobId']) . '</td>'
                . '<td>' . $this->esc($j['owner']) . '</td>'
                . '<td>' . $this->esc($j['document']) . '</td>'
                . '<td>' . (string) $j['pages'] . '</td>'
                . '<td>' . $this->esc($j['submitted']) . '</td>'
                . '<td>' . $this->pillHtml($j['status'], 'info') . '</td>'
                . '<td>'
                . $this->actionLink($pBase . '/release/' . $j['jobId'], 'Release', false) . ' '
                . $this->actionLink($pBase . '/cancel/' . $j['jobId'], 'Cancel', true)
                . '</td>'
                . '</tr>';
        }
        $table = '<div style="overflow-x:auto"><table class="alte-table">'
            . '<thead><tr><th>Job</th><th>Owner</th><th>Document</th><th>Pages</th><th>Submitted</th><th>Status</th><th>Actions</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        return $this->card('Print queue', $table, $p['id'] . ' · ' . $p['queueJobs'] . ' jobs');
    }

    private function printerTonerCard(array $p): string
    {
        $rows = [
            ['Black', $p['tonerBlack'] . '%'],
            ['Cyan', $p['tonerCyan'] . '%'],
            ['Magenta', $p['tonerMagenta'] . '%'],
            ['Yellow', $p['tonerYellow'] . '%'],
        ];
        return $this->card('Consumables', $this->tableHtml(['Cartridge', 'Level'], $rows, ' class="alte-table"'), $p['id']);
    }

    private function printerScanCard(array $p): string
    {
        $kv = $this->kvTableHtml([
            ['Scan-to-email address', $p['scanToEmail']],
            ['SMTP relay', 'smtp-relay (10.0.5.25:587, STARTTLS)'],
            ['SMTP account', $p['smtpUserMasked']],
            ['Authentication', 'stored on device — masked'],
        ], ' class="alte-kv"');
        return $this->card('Scan-to-email', $kv, $p['id']);
    }

    private function printerControl(string $navBase, string $root, array $p, string $verb, string $job, int $seed): string
    {
        $pBase = $root . '/' . $p['id'];
        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Printers & MFPs', $root],
                   [$p['id'], $pBase], [ucfirst($verb) . ' job', '']];
        $detail = [
            ['Printer', $p['id'] . ' · ' . $p['model']],
            ['Location', $p['location']],
        ];
        if ($job !== '') {
            $detail[] = ['Job', $job];   // echoed escaped by kvTableHtml
        }
        $detail[] = ['Command', $this->cmdRef($seed, $p['id'] . '|' . $verb . '|' . $job)];
        $detail[] = ['Status', $verb === 'release'
            ? 'release queued to the spooler; applies at next poll (~15 s)'
            : 'cancellation queued to the spooler; applies at next poll (~15 s)'];
        return $this->breadcrumbHtml($crumbs)
            . $this->controlResultCard(ucfirst($verb) . ' print job — ' . $p['id'], $detail);
    }

    // =====================================================================
    // Software licences
    // =====================================================================

    private function licensesArea(ItServices $it, string $navBase, string $root, string $entity, string $subtab, int $page): string
    {
        if ($entity === '') {
            return $this->licenseList($it, $navBase, $root, $page);
        }
        $license = $it->licenseById($entity);
        if ($subtab === 'reveal') {
            return $this->licenseReveal($it, $navBase, $root, $license);
        }
        return $this->licenseDetail($navBase, $root, $license);
    }

    private function licenseList(ItServices $it, string $navBase, string $root, int $page): string
    {
        $total = $it->licenseCount();
        [$page, $pages, $offset] = $this->paginate($total, $page);
        $licenses = $it->licensePage($offset, self::PAGE_SIZE);

        $rows = '';
        foreach ($licenses as $l) {
            $href = $this->esc($root . '/' . $l['id']);
            $seatState = $l['seatsUsed'] >= $l['seatsTotal'] ? 'crit' : ($l['seatsUsed'] >= (int) round($l['seatsTotal'] * 0.9) ? 'warn' : 'ok');
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($l['product']) . '</a></td>'
                . '<td>' . $this->esc($l['edition']) . '</td>'
                . '<td>' . $this->pillHtml($l['seatsUsed'] . '/' . $l['seatsTotal'], $seatState) . '</td>'
                . '<td>' . $this->esc($l['keyMasked']) . '</td>'
                . '<td>' . $this->esc($l['expiry']) . '</td>'
                . '</tr>';
        }
        $search = $this->searchBox('its-lic-q', 'Filter licences…');
        $table = '<div style="overflow-x:auto"><table id="its-lic-tbl" class="alte-table">'
            . '<thead><tr><th>Product</th><th>Edition</th><th>Seats</th><th>Key</th><th>Expiry</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        $pager = $this->pagerHtml($root, $page, $pages, $this->pageSummary($offset, count($licenses), $total, 'licences'));

        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Licences', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->areaNav($navBase, 'licenses')
            . $this->card('Software licences', $search . $table . $pager . $this->filterScript('its-lic-q', 'its-lic-tbl'),
                number_format($total) . ' licence records');
    }

    private function licenseDetail(string $navBase, string $root, array $l): string
    {
        $lBase = $root . '/' . $l['id'];
        $kv = $this->kvTableHtml([
            ['Product', $l['product']],
            ['Vendor', $l['vendor']],
            ['Edition', $l['edition']],
            ['Seats used', $l['seatsUsed'] . ' of ' . $l['seatsTotal']],
            ['Product key', $l['keyMasked']],
            ['Expiry', $l['expiry']],
            ['Support tier', $l['supportTier']],
        ], ' class="alte-kv"');
        $controls = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">'
            . $this->actionLink($lBase . '/reveal', 'Reveal product key', false)
            . '</div>';
        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Licences', $root], [$l['product'], '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card($l['product'], $kv . $controls, $l['edition'] . ' · ' . $l['seatsUsed'] . '/' . $l['seatsTotal'] . ' seats');
    }

    private function licenseReveal(ItServices $it, string $navBase, string $root, array $l): string
    {
        $lBase = $root . '/' . $l['id'];
        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Licences', $root],
                   [$l['product'], $lBase], ['Reveal key', '']];
        $detail = [
            ['Product', $l['product'] . ' · ' . $l['edition']],
            ['Product key', $it->keyReveal($l)],
            ['Note', 'Activation key is bound to this tenant and audited on use.'],
        ];
        return $this->breadcrumbHtml($crumbs)
            . $this->controlResultCard('Product key — ' . $l['product'], $detail);
    }

    // =====================================================================
    // MDM endpoint fleet
    // =====================================================================

    private function mdmArea(ItServices $it, string $navBase, string $root, string $entity, string $subtab, int $page, int $seed): string
    {
        if ($entity === '') {
            return $this->mdmLanding($it, $navBase, $root, $page);
        }
        if ($entity === 'run-script' || $entity === 'push-app') {
            return $this->mdmFleetControl($navBase, $root, $entity, $seed);
        }
        $device = $it->mdmDeviceById($entity);
        if ($subtab === 'lock' || $subtab === 'wipe') {
            return $this->mdmDeviceControl($navBase, $root, $device, $subtab, $seed);
        }
        return $this->mdmDeviceDetail($navBase, $root, $device);
    }

    private function mdmLanding(ItServices $it, string $navBase, string $root, int $page): string
    {
        $s = $it->mdmSummary();
        $tiles = $this->statCardsHtml([
            ['label' => 'Enrolled', 'value' => number_format($s['enrolled'])],
            ['label' => 'Compliant', 'value' => number_format($s['compliant'])],
            ['label' => 'At risk', 'value' => number_format($s['atRisk'])],
            ['label' => 'Non-compliant', 'value' => number_format($s['nonCompliant'])],
        ], 'fp-tiles', 'fp-tile');

        $fleet = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin:12px 0">'
            . $this->actionLink($root . '/run-script', 'Run script (all devices)', true)
            . $this->actionLink($root . '/push-app', 'Push app (all devices)', true)
            . '</div>';

        [$page, $pages, $offset] = $this->paginate($s['enrolled'], $page);
        $devices = $it->mdmPage($offset, self::PAGE_SIZE);
        $rows = '';
        foreach ($devices as $d) {
            $href = $this->esc($root . '/' . $d['id']);
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($d['hostname']) . '</a></td>'
                . '<td>' . $this->esc($d['owner']) . '</td>'
                . '<td>' . $this->esc($d['os'] . ' ' . $d['osVersion']) . '</td>'
                . '<td>' . $this->esc($d['ip']) . '</td>'
                . '<td>' . $this->pillHtml($d['compliance'], $this->complianceStatus($d['compliance'])) . '</td>'
                . '<td>' . $this->esc($d['lastSync']) . '</td>'
                . '</tr>';
        }
        $search = $this->searchBox('its-mdm-q', 'Filter endpoints…');
        $table = '<div style="overflow-x:auto"><table id="its-mdm-tbl" class="alte-table">'
            . '<thead><tr><th>Hostname</th><th>Owner</th><th>OS</th><th>Last IP</th><th>Compliance</th><th>Last sync</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        $pager = $this->pagerHtml($root, $page, $pages, $this->pageSummary($offset, count($devices), $s['enrolled'], 'endpoints'));

        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Endpoints (MDM)', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->areaNav($navBase, 'mdm')
            . $tiles
            . $fleet
            . $this->card('Enrolled endpoints', $search . $table . $pager . $this->filterScript('its-mdm-q', 'its-mdm-tbl'),
                number_format($s['enrolled']) . ' devices');
    }

    private function mdmDeviceDetail(string $navBase, string $root, array $d): string
    {
        $dBase = $root . '/' . $d['id'];
        $kv = $this->kvTableHtml([
            ['Device id', $d['id']],
            ['Hostname', $d['hostname']],
            ['Owner', $d['owner'] . ' <' . $d['ownerEmail'] . '>'],
            ['OS', $d['os'] . ' ' . $d['osVersion']],
            ['Model', $d['model']],
            ['Serial', $d['serial']],
            ['Last IP', $d['ip']],
            ['Disk encryption', $d['encrypted']],
            ['Compliance', $d['compliance']],
            ['Enrolled', $d['enrolled']],
            ['Last sync', $d['lastSync']],
        ], ' class="alte-kv"');
        $controls = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">'
            . $this->actionLink($dBase . '/lock', 'Remote lock', false)
            . $this->actionLink($dBase . '/wipe', 'Remote wipe', true)
            . '</div>';
        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Endpoints (MDM)', $root], [$d['hostname'], '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card($d['hostname'], $kv . $controls, $d['owner'] . ' · ' . $d['compliance']);
    }

    /** Remote lock is the canned queue; remote wipe (destructive) is a guarded soft-deny (never "done"). */
    private function mdmDeviceControl(string $navBase, string $root, array $d, string $verb, int $seed): string
    {
        $dBase = $root . '/' . $d['id'];
        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Endpoints (MDM)', $root],
                   [$d['hostname'], $dBase], [ucfirst($verb), '']];
        if ($verb === 'wipe') {
            $body = $this->softDenyCard(
                'Remote wipe — ' . $d['hostname'],
                [
                    ['Device', $d['hostname'] . ' (' . $d['id'] . ')'],
                    ['Owner', $d['owner']],
                    ['Reason', 'A destructive remote wipe requires a second authorized administrator (four-eyes) and a manager sign-off.'],
                    ['Request', $this->cmdRef($seed, $d['id'] . '|wipe') . ' · awaiting second approver'],
                    ['Second approver', 'awaiting — request pending'],
                ],
                'The wipe request was recorded and routed for secondary authorization. No command was sent to the device and no data has been erased; the device stays enrolled until a second administrator approves.'
            );
            return $this->breadcrumbHtml($crumbs) . $body;
        }
        $detail = [
            ['Device', $d['hostname'] . ' (' . $d['id'] . ')'],
            ['Owner', $d['owner']],
            ['Command', $this->cmdRef($seed, $d['id'] . '|lock')],
            ['Status', 'lock queued to MDM; applies at next device check-in (~5 min)'],
        ];
        return $this->breadcrumbHtml($crumbs)
            . $this->controlResultCard('Remote lock — ' . $d['hostname'], $detail);
    }

    /** Fleet-wide run-script / push-app: the highest perceived RCE payoff — always a guarded soft-deny. */
    private function mdmFleetControl(string $navBase, string $root, string $verb, int $seed): string
    {
        $title = $verb === 'run-script' ? 'Run script on all devices' : 'Push app to all devices';
        $reason = $verb === 'run-script'
            ? 'Fleet-wide script execution requires a signed script package and dual administrator approval before it is dispatched.'
            : 'A fleet-wide app deployment requires a signed package and dual administrator approval before it is dispatched.';
        $body = $this->softDenyCard($title, [
            ['Scope', 'All enrolled endpoints'],
            ['Reason', $reason],
            ['Request', $this->cmdRef($seed, 'fleet|' . $verb) . ' · awaiting second approver'],
            ['Second approver', 'awaiting — request pending'],
        ], 'The request was recorded and routed for approval. Nothing was dispatched to any device; no code has run and no app has installed until a second administrator signs off.');
        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Endpoints (MDM)', $root], [$title, '']];
        return $this->breadcrumbHtml($crumbs) . $body;
    }

    // =====================================================================
    // Mail admin
    // =====================================================================

    private function mailArea(ItServices $it, string $navBase, string $root, string $entity, string $subtab, int $page, int $seed): string
    {
        if ($entity === '') {
            return $this->mailboxList($it, $navBase, $root, $page);
        }
        if ($entity === 'search-purge') {
            return $this->mailPurgeControl($navBase, $root, $seed);
        }
        $mbx = $it->mailboxById($entity);
        if ($subtab === 'add-forwarding' || $subtab === 'grant-access') {
            return $this->mailControl($navBase, $root, $mbx, $subtab, $seed);
        }
        return $this->mailboxDetail($navBase, $root, $mbx);
    }

    private function mailboxList(ItServices $it, string $navBase, string $root, int $page): string
    {
        $total = $it->mailboxCount();
        [$page, $pages, $offset] = $this->paginate($total, $page);
        $boxes = $it->mailboxPage($offset, self::PAGE_SIZE);

        $rows = '';
        foreach ($boxes as $b) {
            $href = $this->esc($root . '/' . $b['id']);
            $fwd = '';
            foreach ($b['forwarding'] as $f) {
                if ($f['suspicious']) {
                    $fwd = $this->pillHtml('external fwd', 'crit');
                } elseif ($fwd === '') {
                    $fwd = $this->pillHtml('fwd', 'info');
                }
            }
            $pct = $b['quotaTotalMb'] > 0 ? (int) round($b['quotaUsedMb'] / $b['quotaTotalMb'] * 100) : 0;
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($b['address']) . '</a></td>'
                . '<td>' . $this->esc($b['displayName']) . '</td>'
                . '<td>' . $this->esc($b['dept']) . '</td>'
                . '<td>' . $pct . '%</td>'
                . '<td>' . $this->esc($b['lastSignIn']) . '</td>'
                . '<td>' . $fwd . '</td>'
                . '</tr>';
        }
        $search = $this->searchBox('its-mail-q', 'Filter mailboxes…');
        $table = '<div style="overflow-x:auto"><table id="its-mail-tbl" class="alte-table">'
            . '<thead><tr><th>Mailbox</th><th>Name</th><th>Dept</th><th>Quota</th><th>Last sign-in</th><th>Forwarding</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        $pager = $this->pagerHtml($root, $page, $pages, $this->pageSummary($offset, count($boxes), $total, 'mailboxes'));

        $purge = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin:12px 0">'
            . $this->actionLink($root . '/search-purge', 'Search & purge', true)
            . '</div>';

        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Mail admin', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->areaNav($navBase, 'mail')
            . $purge
            . $this->card('Mailboxes', $search . $table . $pager . $this->filterScript('its-mail-q', 'its-mail-tbl'),
                number_format($total) . ' mailboxes');
    }

    private function mailboxDetail(string $navBase, string $root, array $b): string
    {
        $bBase = $root . '/' . $b['id'];
        $kv = $this->kvTableHtml([
            ['Mailbox', $b['address']],
            ['Display name', $b['displayName']],
            ['Department', $b['dept']],
            ['Quota', number_format($b['quotaUsedMb']) . ' / ' . number_format($b['quotaTotalMb']) . ' MB'],
            ['Last sign-in', $b['lastSignIn']],
        ], ' class="alte-kv"');

        $fwdRows = [];
        foreach ($b['forwarding'] as $f) {
            $fwdRows[] = [$f['to'], $f['scope'], $f['suspicious'] ? 'review' : 'ok'];
        }
        $fwdCard = $fwdRows === []
            ? $this->card('Forwarding rules', '<p class="alte-muted">No forwarding rules configured.</p>', $b['address'])
            : $this->card('Forwarding rules', $this->tableHtml(['Forward to', 'Scope', 'Flag'], $fwdRows, ' class="alte-table"'), $b['address']);

        $controls = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">'
            . $this->actionLink($bBase . '/add-forwarding', 'Add forwarding rule', false)
            . $this->actionLink($bBase . '/grant-access', 'Grant full access', true)
            . '</div>';

        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Mail admin', $root], [$b['address'], '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card($b['address'], $kv . $controls, $b['displayName'] . ' · ' . $b['dept'])
            . $fwdCard;
    }

    /** Add-forwarding / grant-access are the canned queue (persistence toolkit, inert — nothing applied). */
    private function mailControl(string $navBase, string $root, array $b, string $verb, int $seed): string
    {
        $bBase = $root . '/' . $b['id'];
        $label = $verb === 'add-forwarding' ? 'Add forwarding rule' : 'Grant full access';
        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Mail admin', $root],
                   [$b['address'], $bBase], [$label, '']];
        $detail = [
            ['Mailbox', $b['address']],
            ['Command', $this->cmdRef($seed, $b['id'] . '|' . $verb)],
            ['Status', $verb === 'add-forwarding'
                ? 'rule queued; applies at next directory sync (~2 min)'
                : 'delegation queued; applies at next directory sync (~2 min)'],
        ];
        return $this->breadcrumbHtml($crumbs)
            . $this->controlResultCard($label . ' — ' . $b['address'], $detail);
    }

    /** Search & purge is destructive, so it is a guarded soft-deny that never claims anything was deleted. */
    private function mailPurgeControl(string $navBase, string $root, int $seed): string
    {
        $body = $this->softDenyCard('Search & purge', [
            ['Scope', 'Tenant-wide message search'],
            ['Reason', 'A purge that deletes mail requires a legal-hold check and a second administrator approval before any message is removed.'],
            ['Request', $this->cmdRef($seed, 'mail|purge') . ' · awaiting second approver'],
            ['Second approver', 'awaiting — request pending'],
        ], 'The search was recorded and routed for approval. No messages were removed from any mailbox; a purge cannot run until legal-hold clears and a second administrator approves.');
        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Mail admin', $root], ['Search & purge', '']];
        return $this->breadcrumbHtml($crumbs) . $body;
    }

    // =====================================================================
    // Certificates
    // =====================================================================

    private function certsArea(ItServices $it, string $navBase, string $root, string $entity, int $page): string
    {
        if ($entity === '') {
            return $this->certList($it, $navBase, $root, $page);
        }
        return $this->certDetail($navBase, $root, $it->certById($entity));
    }

    private function certList(ItServices $it, string $navBase, string $root, int $page): string
    {
        $total = $it->certCount();
        [$page, $pages, $offset] = $this->paginate($total, $page);
        $certs = $it->certPage($offset, self::PAGE_SIZE);

        $rows = '';
        foreach ($certs as $c) {
            $href = $this->esc($root . '/' . $c['id']);
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($c['subject']) . '</a></td>'
                . '<td>' . $this->esc($c['issuer']) . '</td>'
                . '<td>' . $this->esc($c['keyType']) . '</td>'
                . '<td>' . $this->esc($c['notAfter']) . '</td>'
                . '<td>' . $this->pillHtml($c['status'], $this->certStatus($c['status'])) . '</td>'
                . '</tr>';
        }
        $search = $this->searchBox('its-cert-q', 'Filter certificates…');
        $table = '<div style="overflow-x:auto"><table id="its-cert-tbl" class="alte-table">'
            . '<thead><tr><th>Subject</th><th>Issuer</th><th>Key</th><th>Expires</th><th>Status</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        $pager = $this->pagerHtml($root, $page, $pages, $this->pageSummary($offset, count($certs), $total, 'certificates'));

        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Certificates', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->areaNav($navBase, 'certs')
            . $this->card('Certificates', $search . $table . $pager . $this->filterScript('its-cert-q', 'its-cert-tbl'),
                number_format($total) . ' certificates');
    }

    private function certDetail(string $navBase, string $root, array $c): string
    {
        $kv = $this->kvTableHtml([
            ['Subject', $c['subject']],
            ['Issuer', $c['issuer']],
            ['Serial', $c['serial']],
            ['Key type', $c['keyType']],
            ['Valid from', $c['notBefore']],
            ['Valid to', $c['notAfter']],
            ['SHA-256 fingerprint', $c['fingerprint']],
            ['SANs', implode(', ', $c['sans'])],
            ['Status', $c['status']],
        ], ' class="alte-kv"');

        // Private material is never generated — the "downloads" are inert decoy archives (spec E10).
        $files = [
            ['file' => 'cert_' . $c['id'] . '.pem.zip', 'cells' => ['Certificate (PEM)', 'archive (zip)']],
            ['file' => 'key_' . $c['id'] . '.pem.zip', 'cells' => ['Private key (PEM)', 'archive (zip)']],
            ['file' => 'bundle_' . $c['id'] . '.pfx.zip', 'cells' => ['PKCS#12 bundle', 'archive (zip)']],
        ];
        $downloads = $this->downloadTableHtml(['File', 'Item', 'Format'], $files, $navBase, '/helpdesk/download', ' class="alte-table"', 'alte-dl');

        $crumbs = [['Corevance', $navBase], ['IT Services', $navBase . '/helpdesk'], ['Certificates', $root], [$c['subject'], '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card($c['subject'], $kv, $c['issuer'] . ' · ' . $c['status'])
            . $this->card('Export', $downloads, 'private material is protected — export requires HSM authorization');
    }

    // =====================================================================
    // small shared UI helpers (all escape-by-construction)
    // =====================================================================

    /** Cross-area jump links so every sub-area is reachable from any list (the site-graph has no leaves). */
    private function areaNav(string $navBase, string $current): string
    {
        $areas = [
            'tickets' => ['Helpdesk', $navBase . '/helpdesk'],
            'printers' => ['Printers', $navBase . '/helpdesk/printers'],
            'licenses' => ['Licences', $navBase . '/helpdesk/licenses'],
            'mdm' => ['Endpoints', $navBase . '/helpdesk/mdm'],
            'mail' => ['Mail', $navBase . '/helpdesk/mail'],
            'certs' => ['Certificates', $navBase . '/helpdesk/certs'],
        ];
        $html = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin:12px 0">';
        foreach ($areas as $slug => $a) {
            if ($slug === $current) {
                $html .= '<span class="alte-btn" style="display:inline-block;padding:7px 14px;border-radius:4px;'
                    . 'background:#2c3136;color:#fff;font-size:.86em;font-weight:600">' . $this->esc($a[0]) . '</span>';
            } else {
                $html .= $this->actionLink($a[1], $a[0], false);
            }
        }
        return $html . '</div>';
    }

    /** Clamp a page into [1, pages] and return [page, pages, offset] for a total-row count. */
    private function paginate(int $total, int $page): array
    {
        $pages = (int) ceil($total / self::PAGE_SIZE);
        if ($pages < 1) {
            $pages = 1;
        }
        if ($page < 1) {
            $page = 1;
        }
        if ($page > $pages) {
            $page = $pages;
        }
        return [$page, $pages, ($page - 1) * self::PAGE_SIZE];
    }

    /** Pre-assembled pager summary (digits/commas only, safe as trusted markup for pagerHtml). */
    private function pageSummary(int $offset, int $shown, int $total, string $noun): string
    {
        $from = $total === 0 ? 0 : $offset + 1;
        $to = $offset + $shown;
        return 'Showing ' . number_format($from) . '&ndash;' . number_format($to) . ' of ' . number_format($total) . ' ' . $noun;
    }

    private function searchBox(string $id, string $placeholder): string
    {
        return '<input id="' . $id . '" type="search" placeholder="' . $this->esc($placeholder) . '" '
            . 'style="margin-bottom:10px;padding:6px 10px;width:100%;max-width:340px;box-sizing:border-box" autocomplete="off">';
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
        return 'ITS-CMD-' . strtoupper(substr(hash('sha256', $seed . '|itcmd|' . $slot), 0, 6));
    }

    private function priorityStatus(string $p): string
    {
        if ($p === 'P1') {
            return 'crit';
        }
        if ($p === 'P2') {
            return 'warn';
        }
        if ($p === 'P3') {
            return 'info';
        }
        return 'idle';
    }

    private function ticketStatus(string $s): string
    {
        if ($s === 'Resolved' || $s === 'Closed') {
            return 'ok';
        }
        if ($s === 'Open') {
            return 'warn';
        }
        if ($s === 'Pending') {
            return 'idle';
        }
        return 'info';   // In Progress
    }

    private function printerStatus(string $s): string
    {
        if ($s === 'Ready') {
            return 'ok';
        }
        if ($s === 'Offline' || $s === 'Paper jam') {
            return 'crit';
        }
        if ($s === 'Toner low') {
            return 'warn';
        }
        return 'info';   // Printing
    }

    private function complianceStatus(string $c): string
    {
        if ($c === 'Compliant') {
            return 'ok';
        }
        if ($c === 'At risk') {
            return 'warn';
        }
        return 'crit';   // Non-compliant
    }

    private function certStatus(string $s): string
    {
        if ($s === 'Valid') {
            return 'ok';
        }
        if ($s === 'Expiring soon') {
            return 'warn';
        }
        return 'crit';   // Expired
    }
}
