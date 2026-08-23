<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Access;
use Funnypot\App\Render\VisualPersona;

/**
 * Access Control (spec §C.3) — flagship physical-access lure. Renders the five-rung ladder over the
 * `Fake\Access` view of the Building/Org spines: doors landing (+ stat tiles) -> door detail with
 * sub-tabs (events / schedule / who-has-access / anti-passback) -> unlock control leaf; plus the
 * cardholder/badge roster (paginated, masked) and the building-wide access-event scroll.
 *
 * The whole surface is INERT. An ordinary door's unlock lands on the canned "queued" receipt; the
 * crown-jewel doors (server room, MDF, records vault) and the building-wide LOCKDOWN / fire-egress
 * levers return a GUARDED soft-deny (dual authorization / hardware interlock) with a routed request
 * ref that never resolves — the second approver the attacker hunts for does not exist, so failure
 * burns more time than success would. Nothing is persisted; the door detail always shows its seeded
 * state, so the non-change reads as controller latency, not a fake.
 *
 * Route slots (PanelRoute): module=access; section = ''|cardholders|events|lockdown-all|unlock-all|<door-id>.
 * For a door: entity = sub-tab (events/schedule/access/anti-passback) OR a control verb
 * (unlock/lock/pulse/hold/lockdown/mode); subtab carries the mode arg for `.../mode/<value>`.
 */
final class AccessSection extends AbstractPanelSection
{
    /** Control verbs in the door's entity slot — everything else there is a detail sub-tab. */
    private const CONTROL_VERBS = ['unlock', 'lock', 'pulse', 'hold', 'lockdown', 'mode'];

    private const PAGE_SIZE = 50;

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $access = Access::fromSeed($persona->seed());
        $section = $route['section'];

        if ($section === '') {
            return $this->landing($access, $navBase);
        }
        if ($section === 'cardholders') {
            return $this->cardholders($access, $navBase, $route['page']);
        }
        if ($section === 'events') {
            return $this->eventLog($access, $navBase);
        }
        if ($section === 'lockdown-all') {
            return $this->buildingControl($navBase, 'lockdown', $persona->seed());
        }
        if ($section === 'unlock-all') {
            return $this->buildingControl($navBase, 'egress', $persona->seed());
        }

        // Otherwise the section slot is a door id.
        $door = $access->door($section);
        $verb = $route['entity'];
        if ($verb !== '' && in_array($verb, self::CONTROL_VERBS, true)) {
            return $this->doorControl($navBase, $door, $verb, $route['subtab'], $persona->seed());
        }
        return $this->doorDetail($access, $navBase, $door, $verb === '' ? 'overview' : $verb);
    }

    // --- landing: stat tiles + building-wide levers + doors list ---

    private function landing(Access $access, string $navBase): string
    {
        $s = $access->summary();
        $tiles = $this->statCardsHtml([
            ['label' => 'Doors', 'value' => (string) $s['total'], 'sub' => 'across all floors'],
            ['label' => 'Secured', 'value' => (string) $s['secured']],
            ['label' => 'Unsecured', 'value' => (string) $s['unsecured'], 'sub' => 'held / forced'],
            ['label' => 'High-security', 'value' => (string) $s['highSecurity']],
            ['label' => 'Readers online', 'value' => $s['readersOnline'] . '/' . $s['readersTotal']],
            ['label' => 'Active alarms', 'value' => (string) $s['alarms']],
            ['label' => 'Cardholders', 'value' => number_format($access->cardholderCount())],
        ], 'fp-tiles', 'fp-tile');

        $levers = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin:12px 0">'
            . $this->actionLink($navBase . '/access/lockdown-all', 'LOCKDOWN ALL', true)
            . $this->actionLink($navBase . '/access/unlock-all', 'Unlock all (fire egress)', true)
            . $this->actionLink($navBase . '/access/cardholders', 'Cardholders & badges', false)
            . $this->actionLink($navBase . '/access/events', 'Access-event log', false)
            . '</div>';

        $doorsTable = $this->doorsTable($access->doors(), $navBase);

        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Access & Doors'))
            . $tiles
            . $levers
            . $this->card('Doors & readers', $doorsTable, $s['total'] . ' doors · ' . $s['highSecurity'] . ' high-security');
    }

    /** Doors list with a client-side filter box (progressive enhancement; no-JS shows all rows). */
    private function doorsTable(array $doors, string $navBase): string
    {
        $rows = '';
        foreach ($doors as $d) {
            $href = $this->esc($navBase . '/access/' . $d['id']);
            $state = $this->pillHtml($d['state'], $this->stateStatus($d['state']));
            $hs = $d['highSecurity'] ? $this->pillHtml('high-sec', 'warn') : '';
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($d['name']) . '</a> ' . $hs . '</td>'
                . '<td>' . $this->esc($d['area']) . '</td>'
                . '<td>' . $this->esc($d['type']) . '</td>'
                . '<td>' . $this->esc($d['controller']) . ' · ' . $this->esc($d['controllerIp']) . '</td>'
                . '<td>' . $this->esc($d['mode']) . '</td>'
                . '<td>' . $state . '</td>'
                . '<td>' . $this->esc($d['lastSeen']) . '</td>'
                . '</tr>';
        }
        $search = '<input id="acc-door-q" type="search" placeholder="Filter doors…" '
            . 'style="margin-bottom:10px;padding:6px 10px;width:100%;max-width:280px;box-sizing:border-box" autocomplete="off">';
        $table = '<div style="overflow-x:auto"><table id="acc-door-tbl" class="alte-table">'
            . '<thead><tr><th>Door</th><th>Area</th><th>Type</th><th>Controller</th><th>Mode</th><th>State</th><th>Last event</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        return $search . $table . $this->filterScript('acc-door-q', 'acc-door-tbl');
    }

    // --- door detail + sub-tabs ---

    private function doorDetail(Access $access, string $navBase, array $door, string $subtab): string
    {
        $doorBase = $navBase . '/access/' . $door['id'];
        $crumbs = [
            ['OneControl', $navBase],
            ['Access & Doors', $navBase . '/access'],
            [$door['name'], ''],
        ];

        $tabs = $this->tabStrip($doorBase, $subtab, [
            'overview' => 'Overview',
            'events' => 'Recent events',
            'schedule' => 'Schedule',
            'access' => 'Who has access',
            'anti-passback' => 'Anti-passback',
        ]);

        switch ($subtab) {
            case 'events':
                $body = $this->doorEventsCard($access, $door);
                break;
            case 'schedule':
                $body = $this->doorScheduleCard($access, $door);
                break;
            case 'access':
                $body = $this->doorAccessCard($access, $door);
                break;
            case 'anti-passback':
                $body = $this->card('Anti-passback', $this->kvTableHtml($access->antiPassbackFor($door['id']), ' class="alte-kv"'));
                break;
            default:
                $body = $this->doorOverviewCard($access, $navBase, $door);
        }

        return $this->breadcrumbHtml($crumbs) . $tabs . $body;
    }

    private function doorOverviewCard(Access $access, string $navBase, array $door): string
    {
        $doorBase = $navBase . '/access/' . $door['id'];
        $camId = 'cam-' . $door['id'] . '-01';
        $kv = $this->kvTableHtml([
            ['Door id', $door['id']],
            ['State', $door['state']],
            ['Mode', $door['mode']],
            ['Type', $door['type']],
            ['Area', $door['area']],
            ['Controller', $door['controller'] . ' (' . $door['controllerIp'] . ')'],
            ['Loop / reader', $door['highSecurity'] ? 'OSDP secure channel · REX + DPS' : 'Wiegand · REX + DPS'],
            ['Last event', $door['lastEvent'] . ' · ' . $door['lastSeen']],
            ['Camera', 'View on ' . strtoupper($camId)],
        ], ' class="alte-kv"');

        $controls = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">'
            . $this->actionLink($doorBase . '/unlock', 'Unlock', $door['highSecurity'])
            . $this->actionLink($doorBase . '/pulse', 'Momentary pulse', false)
            . $this->actionLink($doorBase . '/hold', 'Hold unlocked', $door['highSecurity'])
            . $this->actionLink($doorBase . '/lock', 'Lock', false)
            . $this->actionLink($doorBase . '/mode/card-pin', 'Set mode: Card+PIN', false)
            . $this->actionLink($doorBase . '/lockdown', 'Lockdown door', true)
            . '</div>';

        $cam = '<div style="margin-top:8px"><a class="alte-dl" href="'
            . $this->esc($navBase . '/cctv/' . $camId) . '">Open ' . $this->esc(strtoupper($camId)) . ' feed</a></div>';

        return $this->card($door['name'], $kv . $controls . $cam,
            $door['highSecurity'] ? 'high-security door' : 'standard door');
    }

    private function doorEventsCard(Access $access, array $door): string
    {
        $events = $access->badgeEventsFor($door['id'], 40);
        $rows = [];
        foreach ($events as $e) {
            $rows[] = [$e['time'], $e['result'], $e['badge'], $e['holder'], $e['reason']];
        }
        $table = $this->tableHtml(['Time', 'Result', 'Badge', 'Holder', 'Reason'], $rows, ' class="alte-table"');
        return $this->card('Recent transactions', $table, $door['name']);
    }

    private function doorScheduleCard(Access $access, array $door): string
    {
        $rows = [];
        foreach ($access->scheduleFor($door['id']) as $s) {
            $rows[] = [$s['days'], $s['window'], $s['mode']];
        }
        $table = $this->tableHtml(['Days', 'Window', 'Mode'], $rows, ' class="alte-table"');
        return $this->card('Auto-unlock schedule', $table, $door['name']);
    }

    private function doorAccessCard(Access $access, array $door): string
    {
        $rows = [];
        foreach ($access->whoHasAccess($door['id'], 25) as $a) {
            $rows[] = [$a['holder'], $a['dept'], $a['level'], $a['lastSeen']];
        }
        $table = $this->tableHtml(['Holder', 'Dept', 'Access level', 'Last seen'], $rows, ' class="alte-table"');
        $note = $door['highSecurity']
            ? '<p class="alte-muted" style="margin-top:8px">Access limited to elevated authorization levels. To request access, raise a ticket to the Security desk.</p>'
            : '';
        return $this->card('Who has access', $table . $note, $door['name']);
    }

    // --- cardholder / badge roster (paginated, masked) ---

    private function cardholders(Access $access, string $navBase, int $page): string
    {
        $total = $access->cardholderCount();
        $page = $page < 1 ? 1 : $page;
        $pages = (int) ceil($total / self::PAGE_SIZE);
        if ($pages < 1) {
            $pages = 1;
        }
        if ($page > $pages) {
            $page = $pages;
        }
        $offset = ($page - 1) * self::PAGE_SIZE;
        $rowsData = $access->cardholderPage($offset, self::PAGE_SIZE);

        $rows = '';
        foreach ($rowsData as $c) {
            $rows .= '<tr>'
                . '<td>' . $this->esc($c['badge']) . '</td>'
                . '<td>' . $this->esc($c['holder']) . '</td>'
                . '<td>' . $this->esc($c['dept']) . '</td>'
                . '<td>' . $this->pillHtml($c['level'], $this->levelStatus($c['level'])) . '</td>'
                . '<td>' . $this->pillHtml($c['status'], $this->cardStatus($c['status'])) . '</td>'
                . '<td>' . $this->esc($c['lastDoor']) . '</td>'
                . '<td>' . $this->esc($c['lastSeen']) . '</td>'
                . '<td>' . $this->esc($c['pin']) . '</td>'
                . '</tr>';
        }
        $search = '<input id="acc-ch-q" type="search" placeholder="Filter cardholders…" '
            . 'style="margin-bottom:10px;padding:6px 10px;width:100%;max-width:280px;box-sizing:border-box" autocomplete="off">';
        $table = '<div style="overflow-x:auto"><table id="acc-ch-tbl" class="alte-table">'
            . '<thead><tr><th>Badge</th><th>Holder</th><th>Dept</th><th>Access level</th><th>Status</th><th>Last door</th><th>Last seen</th><th>PIN</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';

        $from = $total === 0 ? 0 : $offset + 1;
        $to = $offset + count($rowsData);
        $pager = $this->pager($navBase . '/access/cardholders', $page, $pages, $from, $to, $total);

        $export = '<div style="margin:10px 0">'
            . $this->downloadTableHtml(
                ['Export', 'Rows', 'Format'],
                [['file' => 'cardholders_2026-08.csv.zip', 'cells' => [number_format($total), 'CSV (zip)']]],
                $navBase,
                '/access/download',
                ' class="alte-table"',
                'alte-dl'
            )
            . '</div>';

        $crumbs = [['OneControl', $navBase], ['Access & Doors', $navBase . '/access'], ['Cardholders', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Cardholders & badges', $search . $table . $pager . $export . $this->filterScript('acc-ch-q', 'acc-ch-tbl'),
                number_format($total) . ' active credentials');
    }

    // --- global access-event log scroll ---

    private function eventLog(Access $access, string $navBase): string
    {
        $lines = $access->accessEventLog(220);
        $scroll = $this->preScrollHtml($lines, 'alte-log');
        $crumbs = [['OneControl', $navBase], ['Access & Doors', $navBase . '/access'], ['Access events', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Access-event log', $scroll, 'ACS controllers · live tail (cached ~30 s)');
    }

    // --- control leaves (inert) ---

    /**
     * A per-door control. The crown-jewel doors' unlock/hold/lockdown return a guarded soft-deny (dual
     * authorization / hardware interlock) with a routed request ref; everything else is the canned queue.
     */
    private function doorControl(string $navBase, array $door, string $verb, string $arg, int $seed): string
    {
        $doorBase = $navBase . '/access/' . $door['id'];
        $crumbs = [
            ['OneControl', $navBase],
            ['Access & Doors', $navBase . '/access'],
            [$door['name'], $doorBase],
            [ucfirst($verb), ''],
        ];

        $guarded = $door['highSecurity'] && in_array($verb, ['unlock', 'hold', 'lockdown'], true);
        if ($guarded) {
            $ref = $this->cmdRef($seed, $door['id'] . '|' . $verb);
            $body = $this->softDenyCard(
                $this->verbTitle($verb) . ' — ' . $door['name'],
                [
                    ['Door', $door['name'] . ' (' . $door['id'] . ')'],
                    ['Controller', $door['controller'] . ' · ' . $door['controllerIp']],
                    ['Reason', 'Dual authorization required (Security + Facilities). Hardware interlock engaged.'],
                    ['Request', $ref . ' routed to Security desk'],
                    ['Second approver', 'awaiting — request pending'],
                ],
                'This door requires a second authorized operator. The command was recorded and routed; it will not actuate until a second approval is registered at the Security desk.'
            );
            return $this->breadcrumbHtml($crumbs) . $body;
        }

        // Mode change echoes the (escaped) requested value; everything else is a plain queue.
        $detail = [
            ['Door', $door['name'] . ' (' . $door['id'] . ')'],
            ['Controller', $door['controller'] . ' · ' . $door['controllerIp']],
        ];
        if ($verb === 'mode' && $arg !== '') {
            $detail[] = ['Requested mode', $arg];
        }
        $detail[] = ['Job', $this->cmdRef($seed, $door['id'] . '|' . $verb . '|' . $arg)];
        $detail[] = ['Status', 'queued to controller; applies at next poll (~30 s), write-priority 8'];

        return $this->breadcrumbHtml($crumbs)
            . $this->controlResultCard($this->verbTitle($verb) . ' — ' . $door['name'], $detail);
    }

    /** Building-wide LOCKDOWN / fire-egress — always a guarded soft-deny (never "done"). */
    private function buildingControl(string $navBase, string $which, int $seed): string
    {
        if ($which === 'lockdown') {
            $title = 'Building-wide LOCKDOWN';
            $reason = 'Site-wide lockdown requires dual authorization (Security Manager + Facilities Manager) and a confirmed panel ACK.';
            $extra = 'The lockdown command was recorded and routed to every ACS controller queue. Doors will not actuate until a second authorized operator confirms; no state has changed.';
        } else {
            $title = 'Unlock all doors (fire egress)';
            $reason = 'Global free-egress release is governed by the fire-panel interlock and cannot be issued from the access console.';
            $extra = 'Free-egress is asserted by the fire-alarm system on alarm. This console cannot override the hardware interlock; the request was logged only.';
        }
        $ref = $this->cmdRef($seed, 'site|' . $which);
        $body = $this->softDenyCard($title, [
            ['Scope', 'All ACS controllers · all doors'],
            ['Reason', $reason],
            ['Request', $ref . ' routed to Security desk'],
            ['Second approver', 'awaiting — request pending'],
        ], $extra);
        $crumbs = [['OneControl', $navBase], ['Access & Doors', $navBase . '/access'], [$title, '']];
        return $this->breadcrumbHtml($crumbs) . $body;
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

    private function verbTitle(string $verb): string
    {
        $map = [
            'unlock' => 'Unlock command',
            'lock' => 'Lock command',
            'pulse' => 'Momentary pulse',
            'hold' => 'Hold-unlocked command',
            'lockdown' => 'Door lockdown',
            'mode' => 'Mode change',
        ];
        return isset($map[$verb]) ? $map[$verb] : ucfirst($verb) . ' command';
    }

    /** Deterministic, inert command ref = hash(seed + slot): stable per path, varies per deploy (D.5). */
    private function cmdRef(int $seed, string $slot): string
    {
        return 'FAC-CMD-' . strtoupper(substr(hash('sha256', $seed . '|accmd|' . $slot), 0, 6));
    }

    private function stateStatus(string $state): string
    {
        if ($state === 'Secured') {
            return 'ok';
        }
        if ($state === 'Forced') {
            return 'crit';
        }
        return 'warn';
    }

    private function levelStatus(string $level): string
    {
        if ($level === 'MASTER' || $level === 'SERVER-ROOM') {
            return 'crit';
        }
        if ($level === 'Executive' || $level === 'Facilities') {
            return 'warn';
        }
        if ($level === 'Contractor') {
            return 'info';
        }
        return 'idle';
    }

    private function cardStatus(string $status): string
    {
        if ($status === 'Active') {
            return 'ok';
        }
        if (strpos($status, 'Lost') !== false || $status === 'Expired') {
            return 'crit';
        }
        return 'warn';
    }
}
