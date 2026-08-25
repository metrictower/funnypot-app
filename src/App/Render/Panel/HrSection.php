<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Hr;
use Funnypot\App\Render\Fake\Payroll;
use Funnypot\Core\Support\VisualPersona;

/**
 * HR portal (spec §C.5) — the PII gold-mine illusion. Renders the five-rung ladder over the `Fake\Hr`
 * and `Fake\Payroll` views of the one `Org` roster: an HR landing (stat tiles) -> the employee DIRECTORY
 * (paginated, searchable, dept-filtered) -> a per-employee PROFILE with sub-tabs (Personal / Employment /
 * Documents / Leave) -> control leaves; plus the ORG CHART (Org manager tree) and PAYROLL (runs register
 * -> run detail tabs -> payslip, all arithmetic-closing).
 *
 * The whole surface is INERT. Editing a profile / starting offboarding land on canned "recorded" receipts
 * over the UNCHANGED entity (nothing persisted). The one scary money verb — running / approving payroll —
 * is GUARDED: it never returns "done", only a two-person-rule wall ("Approval recorded 1 of 2, awaiting
 * second approver") or a dual-authorization soft-deny. All PII is masked and invalid-format; the only
 * email shown is the roster work email at the host's one persona domain.
 *
 * Route slots (PanelRoute): module=hr; section = ''|employees|org|payroll|pto|documents.
 *  - employees: entity = emp-<id> (profile) with subtab = personal|employment|documents|leave OR a control
 *    verb (edit/offboard); or entity = dept-<name> (filtered list). page peels from a trailing pN.
 *  - payroll: entity = run-<yyyy>-<mm> (run detail) with subtab = summary|payslips|exceptions|gl|audit,
 *    or subtab = payslip + action = emp-<id> (payslip), or subtab = approve|run (guarded control leaf).
 */
final class HrSection extends AbstractPanelSection
{
    private const PAGE_SIZE = 50;

    /** Profile control verbs in the subtab slot — everything else there is a detail sub-tab. */
    private const PROFILE_CONTROLS = ['edit', 'offboard'];

    /** Payroll control verbs in the subtab slot — everything else there is a run sub-tab. */
    private const PAYROLL_CONTROLS = ['approve', 'run'];

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $hr = Hr::fromSeed($persona->seed(), $persona->domain());
        $payroll = Payroll::fromSeed($persona->seed(), $persona->domain());
        $section = $route['section'];

        if ($section === 'employees') {
            return $this->employees($hr, $navBase, $route, $persona->seed());
        }
        if ($section === 'org') {
            return $this->orgChart($hr, $navBase);
        }
        if ($section === 'payroll') {
            return $this->payroll($hr, $payroll, $navBase, $route, $persona->seed());
        }
        if ($section === 'pto') {
            return $this->ptoOverview($hr, $navBase);
        }
        if ($section === 'documents') {
            return $this->documentsHub($navBase);
        }
        // '' and any unknown section -> the HR landing (a 404 inside the panel is a tell).
        return $this->landing($hr, $navBase);
    }

    // --- landing ---

    private function landing(Hr $hr, string $navBase): string
    {
        $depts = $hr->departments();
        $onLeave = 0;
        $managers = array();
        foreach ($this->rosterStats($hr) as $st) {
            if ($st['status'] !== 'Active') {
                $onLeave++;
            }
            if ($st['managerId'] !== '') {
                $managers[$st['managerId']] = true;
            }
        }
        $tiles = $this->statCardsHtml([
            ['label' => 'Headcount', 'value' => number_format($hr->headcount()), 'sub' => 'active roster'],
            ['label' => 'Departments', 'value' => (string) count($depts)],
            ['label' => 'People managers', 'value' => (string) count($managers)],
            ['label' => 'On leave / notice', 'value' => (string) $onLeave],
            ['label' => 'Latest payroll', 'value' => 'Aug 2026', 'sub' => 'awaiting approval'],
        ], 'fp-tiles', 'fp-tile');

        $levers = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin:12px 0">'
            . $this->actionLink($navBase . '/hr/employees', 'Employee directory', false)
            . $this->actionLink($navBase . '/hr/org', 'Org chart', false)
            . $this->actionLink($navBase . '/hr/payroll', 'Payroll runs', false)
            . $this->actionLink($navBase . '/hr/pto', 'Time & PTO', false)
            . $this->actionLink($navBase . '/hr/documents', 'Documents / reports', false)
            . '</div>';

        $rows = array();
        foreach ($depts as $d) {
            $rows[] = [
                '<a class="fp-dl" href="' . $this->esc($navBase . '/hr/employees/' . $d['slug']) . '">' . $this->esc($d['dept']) . '</a>',
                (string) $d['count'],
            ];
        }
        $deptTable = '<table class="alte-table"><thead><tr><th>Department</th><th>Headcount</th></tr></thead><tbody>';
        foreach ($rows as $r) {
            $deptTable .= '<tr><td>' . $r[0] . '</td><td>' . $this->esc($r[1]) . '</td></tr>';
        }
        $deptTable .= '</tbody></table>';

        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'People · HR'))
            . $tiles
            . $levers
            . $this->card('Departments', $deptTable, count($depts) . ' departments');
    }

    /** @return list<array{status:string,managerId:string}> lightweight roster status slice for the landing. */
    private function rosterStats(Hr $hr): array
    {
        $out = array();
        $page = $hr->directoryPage('', 0, $hr->headcount());
        foreach ($page['rows'] as $p) {
            $out[] = ['status' => $p['status'], 'managerId' => $p['managerId']];
        }
        return $out;
    }

    // --- employee directory + profile ---

    private function employees(Hr $hr, string $navBase, array $route, int $seed): string
    {
        $entity = $route['entity'];

        // A profile (entity is an emp id) — possibly a control leaf on it.
        if (strpos($entity, 'emp-') === 0) {
            $subtab = $route['subtab'];
            if (in_array($subtab, self::PROFILE_CONTROLS, true)) {
                return $this->profileControl($hr, $navBase, $entity, $subtab, $route['action'], $seed);
            }
            return $this->profile($hr, $navBase, $entity, $subtab === '' ? 'personal' : $subtab);
        }

        // Otherwise a directory list, optionally filtered to a dept-<name> slug.
        $deptSlug = strpos($entity, 'dept-') === 0 ? $entity : '';
        return $this->directory($hr, $navBase, $deptSlug, $route['page']);
    }

    private function directory(Hr $hr, string $navBase, string $deptSlug, int $page): string
    {
        $page = $page < 1 ? 1 : $page;
        $probe = $hr->directoryPage($deptSlug, 0, 1);
        $total = $probe['total'];
        $pages = (int) ceil($total / self::PAGE_SIZE);
        if ($pages < 1) {
            $pages = 1;
        }
        if ($page > $pages) {
            $page = $pages;
        }
        $offset = ($page - 1) * self::PAGE_SIZE;
        $data = $hr->directoryPage($deptSlug, $offset, self::PAGE_SIZE);

        $rows = '';
        foreach ($data['rows'] as $p) {
            $href = $this->esc($navBase . '/hr/employees/' . $p['id']);
            $rows .= '<tr>'
                . '<td>' . $this->esc($p['id']) . '</td>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($p['name']) . '</a></td>'
                . '<td>' . $this->esc($p['title']) . '</td>'
                . '<td>' . $this->esc($p['dept']) . '</td>'
                . '<td>' . $this->esc($p['location']) . '</td>'
                . '<td>' . $this->esc($hr->managerName($p['managerId'])) . '</td>'
                . '<td>' . $this->pillHtml($p['status'], $this->statusPill($p['status'])) . '</td>'
                . '<td>' . $this->esc($hr->hireDate($p)) . '</td>'
                . '</tr>';
        }
        $search = '<input id="hr-dir-q" type="search" placeholder="Filter employees…" '
            . 'style="margin-bottom:10px;padding:6px 10px;width:100%;max-width:280px;box-sizing:border-box" autocomplete="off">';
        $table = '<div style="overflow-x:auto"><table id="hr-dir-tbl" class="alte-table">'
            . '<thead><tr><th>ID</th><th>Name</th><th>Title</th><th>Dept</th><th>Location</th><th>Manager</th><th>Status</th><th>Start</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';

        $from = $total === 0 ? 0 : $offset + 1;
        $to = $offset + count($data['rows']);
        $base = $navBase . '/hr/employees' . ($deptSlug !== '' ? '/' . $deptSlug : '');
        $pager = $this->pager($base, $page, $pages, $from, $to, $total);

        $chips = $this->deptChips($hr, $navBase, $deptSlug);

        $export = '<div style="margin:10px 0">'
            . $this->downloadTableHtml(
                ['Export', 'Rows', 'Format'],
                [['file' => 'employees_2026-08.csv.zip', 'cells' => [number_format($total), 'CSV (zip)']]],
                $navBase,
                '/hr/employees/download',
                ' class="alte-table"',
                'fp-dl'
            )
            . '</div>';

        $crumbs = [['Corevance', $navBase], ['People · HR', $navBase . '/hr'], ['Employee directory', '']];
        return $this->breadcrumbHtml($crumbs)
            . $chips
            . $this->card(
                'Employee directory',
                $search . $table . $pager . $export . $this->filterScript('hr-dir-q', 'hr-dir-tbl'),
                number_format($total) . ' people'
            );
    }

    private function deptChips(Hr $hr, string $navBase, string $active): string
    {
        $chips = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:6px;margin:0 0 12px">';
        $chips .= $this->chipLink($navBase . '/hr/employees', 'All', $active === '');
        foreach ($hr->departments() as $d) {
            $chips .= $this->chipLink($navBase . '/hr/employees/' . $d['slug'], $d['dept'] . ' (' . $d['count'] . ')', $active === $d['slug']);
        }
        return $chips . '</div>';
    }

    private function profile(Hr $hr, string $navBase, string $empId, string $subtab): string
    {
        $person = $hr->person($empId);
        $base = $navBase . '/hr/employees/' . $person['id'];
        $tabs = $this->tabStrip($base, $subtab, [
            'personal' => 'Personal',
            'employment' => 'Employment',
            'documents' => 'Documents',
            'leave' => 'Leave',
        ]);

        switch ($subtab) {
            case 'employment':
                $body = $this->employmentTab($hr, $person);
                break;
            case 'documents':
                $body = $this->documentsTab($hr, $navBase, $person);
                break;
            case 'leave':
                $body = $this->leaveTab($hr, $person);
                break;
            default:
                $body = $this->personalTab($hr, $base, $person);
        }

        $crumbs = [
            ['Corevance', $navBase],
            ['People · HR', $navBase . '/hr'],
            ['Employee directory', $navBase . '/hr/employees'],
            [$person['name'], ''],
        ];
        return $this->breadcrumbHtml($crumbs) . $this->profileHeader($person) . $tabs . $body;
    }

    private function profileHeader(array $person): string
    {
        return '<div class="fp-profile-head" style="margin:0 0 10px">'
            . '<span style="font-size:1.15em;font-weight:600;color:#2c3136">' . $this->esc($person['name']) . '</span> '
            . $this->pillHtml($person['status'], $this->statusPill($person['status']))
            . '<div class="fp-muted" style="font-size:.86em">' . $this->esc($person['title'] . ' · ' . $person['dept'] . ' · ' . $person['id']) . '</div></div>';
    }

    private function personalTab(Hr $hr, string $base, array $person): string
    {
        $kv = $this->kvTableHtml($hr->personal($person['id']), ' class="alte-kv"');
        $note = '<p class="fp-muted" style="margin:8px 0 0">Personal data is masked at rest. Unmasking requires an approved access request to People Operations.</p>';
        $controls = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">'
            . $this->actionLink($base . '/edit', 'Edit profile', false)
            . $this->actionLink($base . '/offboard', 'Start offboarding', true)
            . '</div>';
        return $this->card($person['name'] . ' — personal', $kv . $note . $controls, 'masked · restricted');
    }

    private function employmentTab(Hr $hr, array $person): string
    {
        $comp = $hr->compensation($person['id']);
        $kv = $this->kvTableHtml($hr->employment($person['id']), ' class="alte-kv"');
        $compKv = $this->kvTableHtml([
            ['Salary band', $comp['band']],
            ['Annual base', $this->money($comp['annual'])],
            ['Monthly base', $this->money($comp['monthly'])],
            ['Direct-deposit account', $comp['bankMasked']],
            ['Tax ID', $comp['taxMasked']],
        ], ' class="alte-kv"');
        return $this->card($person['name'] . ' — employment', $kv, $person['band'])
            . $this->card('Compensation', $compKv, 'masked · invalid-format');
    }

    private function documentsTab(Hr $hr, string $navBase, array $person): string
    {
        $table = $this->downloadTableHtml(
            ['File', 'Type', 'Status', 'Size'],
            $hr->documents($person['id']),
            $navBase,
            '/hr/employees/' . $person['id'] . '/doc',
            ' class="alte-table"',
            'fp-dl'
        );
        return $this->card($person['name'] . ' — documents', $table, 'contracts · ID scans · screening');
    }

    private function leaveTab(Hr $hr, array $person): string
    {
        $b = $hr->ptoBalance($person['id']);
        $kv = $this->kvTableHtml([
            ['Annual entitlement', $b['entitlement'] . ' days'],
            ['Carried over', $b['carried'] . ' days'],
            ['Total available', $b['available'] . ' days'],
            ['Taken YTD', $b['taken'] . ' days'],
            ['Remaining', $b['remaining'] . ' days'],
            ['Sick days used', $b['sick'] . ' days'],
        ], ' class="alte-kv"');
        return $this->card($person['name'] . ' — leave & PTO', $kv, 'entitlement + carried = available; available − taken = remaining');
    }

    // --- profile control leaves (inert) ---

    private function profileControl(Hr $hr, string $navBase, string $empId, string $verb, string $action, int $seed): string
    {
        $person = $hr->person($empId);
        $base = $navBase . '/hr/employees/' . $person['id'];
        $crumbs = [
            ['Corevance', $navBase],
            ['People · HR', $navBase . '/hr'],
            ['Employee directory', $navBase . '/hr/employees'],
            [$person['name'], $base],
            [ucfirst($verb), ''],
        ];

        if ($verb === 'offboard') {
            $card = $this->controlResultCard('Offboarding — ' . $person['name'], [
                ['Employee', $person['name'] . ' (' . $person['id'] . ')'],
                ['Checklist', $this->cmdRef($seed, $person['id'] . '|offboard', 'HRC')],
                ['Status', 'checklist created — appears within 15 minutes; access unchanged until effective date'],
            ]);
            return $this->breadcrumbHtml($crumbs) . $card;
        }

        // Edit: an inert form that POSTs to /edit/saved; the "saved" landing shows a green flash over the
        // UNCHANGED profile (nothing persisted; the ref is stable per path, i.e. "your last change").
        if ($action === 'saved') {
            $ref = $this->cmdRef($seed, $person['id'] . '|edit', 'HRC');
            $flash = '<div class="fp-flash" style="background:#e8f4ec;border:1px solid #b7dcc4;border-left:4px solid #2e8b57;'
                . 'border-radius:4px;padding:10px 14px;margin:12px 0;color:#256b45">'
                . 'Profile changes saved · ref ' . $this->esc($ref) . '</div>';
            return $this->breadcrumbHtml($crumbs) . $flash . $this->card($person['name'] . ' — personal', $this->kvTableHtml($hr->personal($person['id']), ' class="alte-kv"'), 'unchanged');
        }
        $form = '<form class="fp-edit-form" method="post" action="' . $this->esc($base . '/edit/saved') . '" style="margin:12px 0">'
            . '<label style="display:block;margin:6px 0">Title <input name="title" value="' . $this->esc($person['title']) . '" style="width:100%;max-width:320px;padding:6px 10px;box-sizing:border-box"></label>'
            . '<label style="display:block;margin:6px 0">Location <input name="location" value="' . $this->esc($person['location']) . '" style="width:100%;max-width:320px;padding:6px 10px;box-sizing:border-box"></label>'
            . '<button class="alte-btn" type="submit" style="margin-top:8px;padding:7px 14px;border:0;border-radius:4px;background:#3b7ea1;color:#fff;font-weight:600;cursor:pointer">Save changes</button>'
            . '</form>';
        return $this->breadcrumbHtml($crumbs) . $this->card('Edit ' . $person['name'], $form, 'changes are recorded on submit');
    }

    // --- org chart ---

    private function orgChart(Hr $hr, string $navBase): string
    {
        $root = $hr->rootId();
        $tree = '<div class="fp-orgtree" style="overflow-x:auto"><ul style="list-style:none;padding-left:0;margin:0">'
            . $this->orgNode($hr, $navBase, $root, 0)
            . '</ul></div>';
        $crumbs = [['Corevance', $navBase], ['People · HR', $navBase . '/hr'], ['Org chart', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Organisation chart', $tree, number_format($hr->headcount()) . ' people · reporting tree');
    }

    /** One org-tree node + its reports as a nested <ul>. Bounded by the roster, so it cannot recurse away. */
    private function orgNode(Hr $hr, string $navBase, string $empId, int $depth): string
    {
        if ($depth > 12) {
            return '';
        }
        $p = $hr->person($empId);
        $href = $this->esc($navBase . '/hr/employees/' . $p['id']);
        $line = '<a class="fp-dl" href="' . $href . '">' . $this->esc($p['name']) . '</a>'
            . ' <span class="fp-muted" style="font-size:.85em">' . $this->esc($p['title']) . '</span>';
        $reports = $hr->directReports($empId);
        $children = '';
        if ($reports !== array()) {
            $children = '<ul style="list-style:none;margin:2px 0 2px 18px;padding-left:12px;border-left:1px solid #d7dbdf">';
            foreach ($reports as $child) {
                $children .= $this->orgNode($hr, $navBase, $child['id'], $depth + 1);
            }
            $children .= '</ul>';
        }
        return '<li style="margin:3px 0">' . $line . $children . '</li>';
    }

    // --- payroll ---

    private function payroll(Hr $hr, Payroll $payroll, string $navBase, array $route, int $seed): string
    {
        $entity = $route['entity'];
        if (strpos($entity, 'run-') === 0) {
            $subtab = $route['subtab'];
            if (in_array($subtab, self::PAYROLL_CONTROLS, true)) {
                return $this->payrollControl($payroll, $navBase, $entity, $subtab, $route['action'], $seed);
            }
            if ($subtab === 'payslip') {
                return $this->payslip($payroll, $navBase, $entity, $route['action']);
            }
            return $this->runDetail($payroll, $navBase, $entity, $subtab === '' ? 'summary' : $subtab, $route['page'], $seed);
        }
        return $this->runsList($payroll, $navBase);
    }

    private function runsList(Payroll $payroll, string $navBase): string
    {
        $rows = '';
        foreach ($payroll->runs() as $r) {
            $href = $this->esc($navBase . '/hr/payroll/' . $r['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($r['id']) . '</a></td>'
                . '<td>' . $this->esc($r['period']) . '</td>'
                . '<td>' . $this->esc($r['payDate']) . '</td>'
                . '<td>' . $this->esc(number_format($r['headcount'])) . '</td>'
                . '<td>' . $this->esc($this->money($r['gross'])) . '</td>'
                . '<td>' . $this->esc($this->money($r['net'])) . '</td>'
                . '<td>' . $this->pillHtml($r['status'], $r['status'] === 'Completed' ? 'ok' : 'warn') . '</td>'
                . '</tr>';
        }
        $table = '<div style="overflow-x:auto"><table class="alte-table">'
            . '<thead><tr><th>Run</th><th>Period</th><th>Pay date</th><th>Headcount</th><th>Gross</th><th>Net</th><th>Status</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        $crumbs = [['Corevance', $navBase], ['People · HR', $navBase . '/hr'], ['Payroll runs', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Payroll runs', $table, Payroll::RUN_HISTORY . ' monthly runs');
    }

    private function runDetail(Payroll $payroll, string $navBase, string $runId, string $subtab, int $page, int $seed): string
    {
        $run = $payroll->run($runId);
        $base = $navBase . '/hr/payroll/' . $run['id'];
        $tabs = $this->tabStrip($base, $subtab, [
            'summary' => 'Summary',
            'payslips' => 'Payslips',
            'exceptions' => 'Exceptions',
            'gl' => 'GL export',
            'audit' => 'Audit',
        ]);

        switch ($subtab) {
            case 'payslips':
                $body = $this->runPayslips($payroll, $base, $run, $page);
                break;
            case 'exceptions':
                $body = $this->runExceptions($payroll, $navBase, $run);
                break;
            case 'gl':
                $body = $this->runGl($run);
                break;
            case 'audit':
                $body = $this->runAudit($payroll, $run, $seed);
                break;
            default:
                $body = $this->runSummary($payroll, $base, $run, $seed);
        }

        $crumbs = [
            ['Corevance', $navBase],
            ['People · HR', $navBase . '/hr'],
            ['Payroll runs', $navBase . '/hr/payroll'],
            [$run['period'], ''],
        ];
        return $this->breadcrumbHtml($crumbs) . $tabs . $body;
    }

    private function runSummary(Payroll $payroll, string $base, array $run, int $seed): string
    {
        $tiles = $this->statCardsHtml([
            ['label' => 'Headcount', 'value' => number_format($run['headcount'])],
            ['label' => 'Gross', 'value' => $this->money($run['gross'])],
            ['label' => 'Deductions', 'value' => $this->money($run['deductions'])],
            ['label' => 'Net pay', 'value' => $this->money($run['net'])],
        ], 'fp-tiles', 'fp-tile');
        $kv = $this->kvTableHtml([
            ['Run', $run['id']],
            ['Period', $run['period']],
            ['Pay date', $run['payDate']],
            ['Status', $run['status']],
            ['Gross − deductions', $this->money($run['gross']) . ' − ' . $this->money($run['deductions']) . ' = ' . $this->money($run['net'])],
        ], ' class="alte-kv"');
        $actions = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">'
            . $this->actionLink($base . '/payslips', 'View payslips', false)
            . $this->actionLink($base . '/approve', 'Approve run', true)
            . $this->actionLink($base . '/run', 'Run payroll', true)
            . '</div>';
        return $tiles . $this->card('Run summary', $kv . $actions, $run['status']);
    }

    private function runPayslips(Payroll $payroll, string $base, array $run, int $page): string
    {
        $total = $run['headcount'];
        $page = $page < 1 ? 1 : $page;
        $pages = (int) ceil($total / self::PAGE_SIZE);
        if ($pages < 1) {
            $pages = 1;
        }
        if ($page > $pages) {
            $page = $pages;
        }
        $offset = ($page - 1) * self::PAGE_SIZE;
        $data = $payroll->payslipsPage($run['id'], $offset, self::PAGE_SIZE);

        $rows = '';
        foreach ($data as $ps) {
            $href = $this->esc($base . '/payslip/' . $ps['empId']);
            $rows .= '<tr>'
                . '<td>' . $this->esc($ps['empId']) . '</td>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($ps['name']) . '</a></td>'
                . '<td>' . $this->esc($ps['dept']) . '</td>'
                . '<td>' . $this->esc($this->money($ps['gross'])) . '</td>'
                . '<td>' . $this->esc($this->money($ps['deductions'])) . '</td>'
                . '<td>' . $this->esc($this->money($ps['net'])) . '</td>'
                . '</tr>';
        }
        $search = '<input id="hr-ps-q" type="search" placeholder="Filter payslips…" '
            . 'style="margin-bottom:10px;padding:6px 10px;width:100%;max-width:280px;box-sizing:border-box" autocomplete="off">';
        $table = '<div style="overflow-x:auto"><table id="hr-ps-tbl" class="alte-table">'
            . '<thead><tr><th>ID</th><th>Name</th><th>Dept</th><th>Gross</th><th>Deductions</th><th>Net</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        $from = $total === 0 ? 0 : $offset + 1;
        $to = $offset + count($data);
        $pager = $this->pager($base . '/payslips', $page, $pages, $from, $to, $total);
        return $this->card('Payslips — ' . $run['period'], $search . $table . $pager . $this->filterScript('hr-ps-q', 'hr-ps-tbl'), number_format($total) . ' payslips');
    }

    private function runExceptions(Payroll $payroll, string $navBase, array $run): string
    {
        // A tiny, budgeted exceptions list that links back into profiles (a small goose-chase).
        $roster = $payroll->payslipsPage($run['id'], 0, 3);
        $rows = array();
        $notes = ['Missing timesheet approval', 'New starter — prorated', 'Bank detail change pending review'];
        foreach ($roster as $i => $ps) {
            $rows[] = [
                '<a class="fp-dl" href="' . $this->esc($navBase . '/hr/employees/' . $ps['empId']) . '">' . $this->esc($ps['name']) . '</a>',
                $this->esc($ps['empId']),
                $this->esc(isset($notes[$i]) ? $notes[$i] : 'Review'),
            ];
        }
        $table = '<table class="alte-table"><thead><tr><th>Employee</th><th>ID</th><th>Exception</th></tr></thead><tbody>';
        foreach ($rows as $r) {
            $table .= '<tr><td>' . $r[0] . '</td><td>' . $r[1] . '</td><td>' . $r[2] . '</td></tr>';
        }
        $table .= '</tbody></table>';
        return $this->card('Exceptions — ' . $run['period'], $table, count($rows) . ' to review');
    }

    private function runGl(array $run): string
    {
        // The GL export balances: total debits = total credits = gross. Net pay + deductions = gross.
        $rows = [
            ['6000 · Salaries & wages (Dr)', $this->money($run['gross']), ''],
            ['2100 · Net pay clearing (Cr)', '', $this->money($run['net'])],
            ['2200 · Payroll liabilities (Cr)', '', $this->money($run['deductions'])],
        ];
        $table = '<table class="alte-table"><thead><tr><th>Account</th><th>Debit</th><th>Credit</th></tr></thead><tbody>';
        foreach ($rows as $r) {
            $table .= '<tr><td>' . $this->esc($r[0]) . '</td><td>' . $this->esc($r[1]) . '</td><td>' . $this->esc($r[2]) . '</td></tr>';
        }
        $table .= '<tr><th>Total</th><th>' . $this->esc($this->money($run['gross'])) . '</th><th>' . $this->esc($this->money($run['net'] + $run['deductions'])) . '</th></tr>';
        $table .= '</tbody></table>';
        return $this->card('GL export — ' . $run['period'], $table, 'debits = credits');
    }

    private function runAudit(Payroll $payroll, array $run, int $seed): string
    {
        $approver = $payroll->secondApprover();
        $times = $this->auditTimes($seed, $run['id']);
        $lines = [
            $run['payDate'] . ' ' . $times[0] . '  run.created        actor=payroll-service   period=' . $run['id'],
            $run['payDate'] . ' ' . $times[1] . '  run.calculated     headcount=' . $run['headcount'] . '   gross=' . $this->money($run['gross']),
            $run['payDate'] . ' ' . $times[2] . '  approval.requested  approver=' . $approver['name'] . '   ref=' . $payroll->approvalRef($run['id']),
            $run['payDate'] . ' --:--:--  approval.pending    awaiting second approver',
        ];
        return $this->card('Audit — ' . $run['period'], $this->preScrollHtml($lines, 'alte-log'), 'append-only');
    }

    /**
     * Seeded HH:MM:SS for a run's audit-trail lines: created, calculated, approval-requested — each
     * offset per run id (so every run's timestamps differ, not one literal repeated on every page) but
     * kept monotonic within the run (create -> calculate -> approval request), inside a plausible
     * business-morning window.
     *
     * @return array{0:string,1:string,2:string}
     */
    private function auditTimes(int $seed, string $runId): array
    {
        $h = (int) hexdec(substr(hash('sha256', $seed . '|hraudit|' . $runId), 0, 8));
        $created = 32100 + ($h % 900);                    // ~08:55:00-09:10:00
        $calc = $created + 20 + (($h >> 9) % 90);          // +20-109s after created
        $req = $created + 300 + (($h >> 18) % 900);        // +5-20min after created
        return [$this->hms($created), $this->hms($calc), $this->hms($req)];
    }

    private function hms(int $secondsOfDay): string
    {
        $secondsOfDay %= 86400;
        return sprintf(
            '%02d:%02d:%02d',
            intdiv($secondsOfDay, 3600),
            intdiv($secondsOfDay % 3600, 60),
            $secondsOfDay % 60
        );
    }

    private function payslip(Payroll $payroll, string $navBase, string $runId, string $empId): string
    {
        $ps = $payroll->payslip($runId, $empId);
        $base = $navBase . '/hr/payroll/' . $ps['runId'];

        $table = '<table class="alte-table"><thead><tr><th>Item</th><th>Current</th><th>YTD</th></tr></thead><tbody>'
            . '<tr><th colspan="3" style="text-align:left">Earnings</th></tr>'
            . '<tr><td>Base salary</td><td>' . $this->esc($this->money($ps['gross'])) . '</td><td>' . $this->esc($this->money($ps['ytdGross'])) . '</td></tr>'
            . '<tr><th colspan="3" style="text-align:left">Deductions</th></tr>';
        foreach ($ps['deductions'] as $d) {
            $table .= '<tr><td>' . $this->esc($d[0]) . '</td><td>' . $this->esc($this->money($d[1])) . '</td><td>—</td></tr>';
        }
        $table .= '<tr><th>Gross</th><th>' . $this->esc($this->money($ps['gross'])) . '</th><th>' . $this->esc($this->money($ps['ytdGross'])) . '</th></tr>'
            . '<tr><th>Total deductions</th><th>' . $this->esc($this->money($ps['deductionsTotal'])) . '</th><th>' . $this->esc($this->money($ps['ytdDeductions'])) . '</th></tr>'
            . '<tr><th>Net pay</th><th>' . $this->esc($this->money($ps['net'])) . '</th><th>' . $this->esc($this->money($ps['ytdNet'])) . '</th></tr>'
            . '</tbody></table>';

        $meta = $this->kvTableHtml([
            ['Employee', $ps['name'] . ' (' . $ps['empId'] . ')'],
            ['Title', $ps['title']],
            ['Department', $ps['dept']],
            ['Period', $ps['period']],
            ['Pay date', $ps['payDate']],
            ['Gross − deductions = net', $this->money($ps['gross']) . ' − ' . $this->money($ps['deductionsTotal']) . ' = ' . $this->money($ps['net'])],
        ], ' class="alte-kv"');

        $crumbs = [
            ['Corevance', $navBase],
            ['People · HR', $navBase . '/hr'],
            ['Payroll runs', $navBase . '/hr/payroll'],
            [$ps['period'], $base],
            ['Payslip', ''],
        ];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Payslip — ' . $ps['name'], $meta, $ps['period'])
            . $this->card('Statement of earnings', $table, 'gross − deductions = net · YTD = Σ prior periods');
    }

    // --- payroll control leaf (guarded — the scary money verb) ---

    private function payrollControl(Payroll $payroll, string $navBase, string $runId, string $verb, string $action, int $seed): string
    {
        $run = $payroll->run($runId);
        $base = $navBase . '/hr/payroll/' . $run['id'];
        $ref = $payroll->approvalRef($run['id'] . '|' . $verb);
        $approver = $payroll->secondApprover();
        $crumbs = [
            ['Corevance', $navBase],
            ['People · HR', $navBase . '/hr'],
            ['Payroll runs', $navBase . '/hr/payroll'],
            [$run['period'], $base],
            [ucfirst($verb), ''],
        ];

        if ($verb === 'run') {
            // Running payroll is a full soft-deny: dual authorization + no funds movement, never "done".
            $body = $this->softDenyCard('Run payroll — ' . $run['period'], [
                ['Run', $run['id']],
                ['Amount', $this->money($run['net']) . ' net across ' . number_format($run['headcount']) . ' payslips'],
                ['Reason', 'Executing a pay run requires dual authorization (Payroll + Finance) and a released bank file. No disbursement can be initiated from this console.'],
                ['Request', $ref . ' routed to Finance'],
                ['Second approver', $approver['name'] . ' — awaiting'],
            ], 'The pay run was NOT executed. No funds have moved and no bank file was released; the request was recorded for dual authorization only.');
            return $this->breadcrumbHtml($crumbs) . $body;
        }

        // Approve: the two-person rule. It records "1 of 2" and waits on a second approver who never signs.
        if ($action === 'confirm') {
            $body = $this->pendingCard('Approve payroll run — ' . $run['period'], [
                ['Run', $run['id']],
                ['Approval', 'recorded — 1 of 2'],
                ['Second approver', $approver['name'] . ' — awaiting'],
                ['Request', $ref],
                ['Status', 'not released — the run stays "' . $run['status'] . '" until the second approval is registered'],
            ], 'Approval recorded (1 of 2). This run will not be released for payment until a second authorized approver confirms. Nothing has been paid.');
            return $this->breadcrumbHtml($crumbs) . $body;
        }
        // First step: a "type APPROVE to confirm" gate, no state change.
        $form = '<form class="fp-approve-form" method="post" action="' . $this->esc($base . '/approve/confirm') . '" style="margin:12px 0">'
            . '<p>Type <strong>APPROVE</strong> to record your approval of ' . $this->esc($run['period']) . ' (' . $this->esc($this->money($run['net'])) . ' net).</p>'
            . '<input name="confirm" placeholder="APPROVE" style="padding:6px 10px;width:100%;max-width:220px;box-sizing:border-box" autocomplete="off"> '
            . '<button class="alte-btn" type="submit" style="padding:7px 14px;border:0;border-radius:4px;background:#b23b3b;color:#fff;font-weight:600;cursor:pointer">Confirm approval</button>'
            . '</form>';
        return $this->breadcrumbHtml($crumbs) . $this->card('Approve payroll run — ' . $run['period'], $form, 'two-person rule');
    }

    // --- time & PTO overview (company-level) ---

    private function ptoOverview(Hr $hr, string $navBase): string
    {
        $rows = '';
        $page = $hr->directoryPage('', 0, 25);
        foreach ($page['rows'] as $p) {
            $b = $hr->ptoBalance($p['id']);
            $href = $this->esc($navBase . '/hr/employees/' . $p['id'] . '/leave');
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($p['name']) . '</a></td>'
                . '<td>' . $this->esc($p['dept']) . '</td>'
                . '<td>' . $this->esc($b['available'] . ' d') . '</td>'
                . '<td>' . $this->esc($b['taken'] . ' d') . '</td>'
                . '<td>' . $this->esc($b['remaining'] . ' d') . '</td>'
                . '</tr>';
        }
        $table = '<div style="overflow-x:auto"><table class="alte-table">'
            . '<thead><tr><th>Employee</th><th>Dept</th><th>Available</th><th>Taken</th><th>Remaining</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        $crumbs = [['Corevance', $navBase], ['People · HR', $navBase . '/hr'], ['Time & PTO', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Time & PTO balances', $table, 'available − taken = remaining');
    }

    // --- documents / reports hub (decoy downloads) ---

    private function documentsHub(string $navBase): string
    {
        $table = $this->downloadTableHtml(
            ['Report', 'Category', 'Period', 'Size'],
            [
                ['file' => 'headcount_report_2026-08.csv.zip', 'cells' => ['Headcount', 'Aug 2026', '84 KB']],
                ['file' => 'compensation_review_2026.pdf.zip', 'cells' => ['Compensation', 'FY2026', '3.2 MB']],
                ['file' => 'org_directory_export.csv.zip', 'cells' => ['Directory', 'Current', '112 KB']],
                ['file' => 'diversity_report_2026-q2.pdf.zip', 'cells' => ['DEI', 'Q2 2026', '1.1 MB']],
            ],
            $navBase,
            '/hr/documents/download',
            ' class="alte-table"',
            'fp-dl'
        );
        $crumbs = [['Corevance', $navBase], ['People · HR', $navBase . '/hr'], ['Documents / reports', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('HR documents & reports', $table, 'exports · archived reports');
    }

    // --- small shared UI helpers (all escape-by-construction) ---

    /** A guarded-denial card: crit pill + explicit "not done" note; never a "queued"/"paid" success. */
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

    /** A two-person-rule pending card: warn pill, records "1 of 2", explicitly not released for payment. */
    private function pendingCard(string $title, array $detailPairs, string $note): string
    {
        return '<div class="fp-result-card" style="background:#fff;border:1px solid #d7dbdf;'
            . 'border-left:4px solid #c07a1a;border-radius:4px;margin:16px 0">'
            . '<div class="fp-result-head" style="padding:10px 14px;border-bottom:1px solid #eef1f3;'
            . 'display:flex;align-items:center;gap:8px">'
            . $this->pillHtml('Awaiting approval', 'warn')
            . '<span class="fp-result-title" style="font-weight:600;color:#2c3136">' . $this->esc($title) . '</span></div>'
            . '<div class="fp-result-body" style="padding:12px 14px">'
            . $this->kvTableHtml($detailPairs, ' class="fp-result-kv" style="border-collapse:collapse;width:100%"')
            . '<p class="fp-muted" style="margin:10px 0 0">' . $this->esc($note) . '</p>'
            . '</div></div>';
    }

    /** A sub-tab strip: each tab an <a> to a sibling path; the active one is plain text. */
    private function tabStrip(string $base, string $active, array $tabs): string
    {
        $first = array_key_first($tabs);
        $html = '<nav class="alte-tabs" style="display:flex;flex-wrap:wrap;gap:4px;margin:0 0 12px;'
            . 'border-bottom:1px solid #e3e6e8">';
        foreach ($tabs as $slug => $label) {
            $href = $slug === $first ? $base : $base . '/' . $slug;
            $isActive = ($active === $slug) || ($active === '' && $slug === $first);
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

    /** A filter chip (dept selector). The active chip is filled; others are outlined links. */
    private function chipLink(string $href, string $label, bool $active): string
    {
        $style = $active
            ? 'background:#3b7ea1;color:#fff;border:1px solid #3b7ea1'
            : 'background:#fff;color:#3b7ea1;border:1px solid #cdd6db';
        return '<a class="alte-chip" style="display:inline-block;padding:4px 10px;border-radius:12px;'
            . 'text-decoration:none;font-size:.8em;' . $style . '" href="' . $this->esc($href) . '">' . $this->esc($label) . '</a>';
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

    /** Deterministic, inert reference = hash(seed + slot): stable per path, varies per deploy (D.5). */
    private function cmdRef(int $seed, string $slot, string $prefix): string
    {
        return $prefix . '-' . strtoupper(substr(hash('sha256', $seed . '|hrcmd|' . $slot), 0, 6));
    }

    /**
     * Currency display, $1,234.56 — the one convention across the finance-family modules. Payroll amounts
     * are whole dollars, so the cents read .00; the fixed two-decimal form keeps the format consistent
     * with Finance/Bank/Vendors (no module shows a bare $1,234 next to another's $1,234.56).
     */
    private function money(int $dollars): string
    {
        return '$' . number_format($dollars, 2);
    }

    private function statusPill(string $status): string
    {
        if ($status === 'Active') {
            return 'ok';
        }
        if ($status === 'Notice') {
            return 'crit';
        }
        return 'warn';
    }
}
