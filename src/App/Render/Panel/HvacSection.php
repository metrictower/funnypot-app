<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Hvac;
use Funnypot\App\Render\VisualPersona;

/**
 * HVAC / Climate (spec §C.2): the building's climate plane rendered off Fake\Hvac (which itself sits on
 * Fake\Building, so zones, controllers and server rooms reconcile with every other building module).
 *
 * The five-rung ladder for this module:
 *   /<mount>/hvac                         landing — summary tiles + zone list (paginated pN, JS search)
 *   /<mount>/hvac/<zoneId>                zone detail — gauges, 24h trend, sub-tab strip, setpoint control
 *   /<mount>/hvac/<zoneId>/points         BACnet point list (recon bait: object ids + host:port)
 *   /<mount>/hvac/<zoneId>/set/<n>        setpoint control leaf -> controlResultCard ("queued, next poll")
 *   /<mount>/hvac/<cracId>                CRAC detail — cross-links the server room; anomaly -> a work
 *                                         order one step short; scary verbs get a guarded soft-deny
 *
 * Positional route slots inside this module: section = zone/CRAC id, entity = sub-tab OR control action,
 * subtab = control arg. Everything stays INERT and DETERMINISTIC per seed; a control never changes state.
 */
final class HvacSection extends AbstractPanelSection
{
    /** Zone rows per landing page. */
    private const PER_PAGE = 25;

    /** Detail sub-tabs (entity slot values that render a view, not a control). */
    private const SUBTABS = ['overview', 'trends', 'schedule', 'alarms', 'points', 'maintenance'];

    /** Control actions (entity slot values whose subtab slot is the arg — resolve to a receipt/deny). */
    private const ACTIONS = ['set', 'mode', 'fan', 'preset'];

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $hvac = Hvac::fromSeed($persona->seed());
        $section = $route['section'];

        if ($section === '') {
            return $this->landing($hvac, (int) $route['page'], $navBase);
        }

        $isCrac = strpos($section, 'crac-') === 0;
        $entity = $route['entity'];

        // Control leaf: entity is an action verb, subtab is its arg.
        if (in_array($entity, self::ACTIONS, true)) {
            return $this->controlLeaf($hvac, $section, $isCrac, $entity, $route['subtab'], $persona, $navBase);
        }

        $subtab = in_array($entity, self::SUBTABS, true) ? $entity : 'overview';
        return $isCrac
            ? $this->cracDetail($hvac, $section, $subtab, $navBase)
            : $this->zoneDetail($hvac, $section, $subtab, (int) $route['page'], $navBase);
    }

    // --- landing: summary + zone list + CRAC card ---

    private function landing(Hvac $hvac, int $page, string $navBase): string
    {
        $s = $hvac->summary();
        $tiles = $this->statCardsHtml([
            ['label' => 'Zones in comfort', 'value' => $s['inComfort'] . ' / ' . $s['zones']],
            ['label' => 'Avg setpoint', 'value' => number_format($s['avgSetpoint'], 1) . ' °C'],
            ['label' => 'Filters due', 'value' => (string) $s['filtersDue'], 'sub' => $s['filtersDue'] === 0 ? 'all clean' : 'PPM required'],
            ['label' => 'CRAC units', 'value' => (string) $s['cracUnits'], 'sub' => 'server-room cooling'],
            ['label' => 'BMS controllers', 'value' => (string) $s['controllers'], 'sub' => 'BACnet/IP'],
            ['label' => 'Active alarms', 'value' => (string) $s['activeAlarms'], 'sub' => $s['activeAlarms'] === 0 ? 'all clear' : 'requires review'],
        ], 'alte-stats', 'alte-st');

        $zones = $hvac->zones();
        $total = count($zones);
        if ($page < 1) {
            $page = 1;
        }
        $pages = $total > 0 ? (int) ceil($total / self::PER_PAGE) : 1;
        if ($page > $pages) {
            $page = $pages;
        }
        $slice = array_slice($zones, ($page - 1) * self::PER_PAGE, self::PER_PAGE);

        $rows = '';
        foreach ($slice as $z) {
            $href = $this->esc($navBase . '/hvac/' . $z['id']);
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($z['name']) . '</a></td>'
                . '<td>' . $this->esc($z['floorLabel']) . '</td>'
                . '<td>' . $this->pillHtml($z['hvacMode'], $this->modePill($z['hvacMode'])) . '</td>'
                . '<td>' . $this->esc(number_format((float) $z['currentTemp'], 1) . ' °C') . '</td>'
                . '<td>' . $this->esc(number_format((float) $z['setpoint'], 1) . ' °C') . '</td>'
                . '<td>' . $this->esc($z['fanMode']) . '</td>'
                . '<td>' . $this->esc($z['humidity'] . '%') . '</td>'
                . '<td>' . $this->esc($z['co2'] . ' ppm') . '</td>'
                . '<td>' . $this->pillHtml($z['filterStatus'], $z['filterStatus'] === 'OK' ? 'ok' : 'warn') . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Zone</th><th>Floor</th><th>Mode</th><th>Current</th><th>Setpoint</th>'
            . '<th>Fan</th><th>RH</th><th>CO₂</th><th>Filter</th></tr></thead>';
        $table = $this->zoneSearchBox()
            . '<table class="alte-table" id="hvac-zones">' . $head . '<tbody>' . $rows . '</tbody></table>'
            . $this->pager($navBase . '/hvac', $total, $page, $pages);

        $body = $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Climate / HVAC'))
            . $tiles
            . $this->card('Climate zones', $table, $total . ' zones · last BMS poll ' . $hvac->lastPollAge())
            . $this->cracCard($hvac, $navBase);

        return $body . $this->searchScript();
    }

    /** The CRAC / server-room cooling card on the landing — the flagship cross-link into the server room. */
    private function cracCard(Hvac $hvac, string $navBase): string
    {
        $cracs = $hvac->cracUnits();
        if ($cracs === []) {
            return '';
        }
        $rows = '';
        foreach ($cracs as $c) {
            $href = $this->esc($navBase . '/hvac/' . $c['id']);
            $state = $c['anomaly'] === '' ? 'ok' : 'crit';
            $stateLabel = $c['anomaly'] === '' ? 'Normal' : ($c['anomaly'] === 'dirty-filter' ? 'Filter alarm' : 'Comms fault');
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($c['name']) . '</a></td>'
                . '<td>' . $this->esc($c['servesRoomName']) . '</td>'
                . '<td>' . $this->esc(number_format((float) $c['currentTemp'], 1) . ' °C') . '</td>'
                . '<td>' . $this->esc(number_format((float) $c['setpoint'], 1) . ' °C') . '</td>'
                . '<td>' . $this->pillHtml($stateLabel, $state) . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Unit</th><th>Serves</th><th>Supply</th><th>Setpoint</th><th>Status</th></tr></thead>';
        $table = '<table class="alte-table">' . $head . '<tbody>' . $rows . '</tbody></table>';
        return $this->card('Precision cooling (CRAC)', $table, 'server / comms rooms');
    }

    // --- zone detail ---

    private function zoneDetail(Hvac $hvac, string $zoneId, string $subtab, int $page, string $navBase): string
    {
        $z = $hvac->zone($zoneId);
        $crumbs = [['Corevance', $navBase], ['Climate / HVAC', $navBase . '/hvac'], [$z['name'], '']];
        $body = $this->breadcrumbHtml($crumbs)
            . $this->tabStrip($navBase . '/hvac/' . $zoneId, $subtab, self::SUBTABS);

        switch ($subtab) {
            case 'points':
                return $body . $this->pointsCard($hvac, $z, $navBase);
            case 'trends':
                return $body . $this->trendsCard($hvac, $z);
            case 'schedule':
                return $body . $this->scheduleCard($hvac, $z);
            case 'alarms':
                return $body . $this->alarmsCard($z);
            case 'maintenance':
                return $body . $this->zoneMaintenanceCard($z);
            default:
                return $body . $this->zoneOverview($hvac, $z, $navBase);
        }
    }

    private function zoneOverview(Hvac $hvac, array $z, string $navBase): string
    {
        $kv = $this->kvTableHtml([
            ['Zone id', $z['id']],
            ['Location', $z['floorLabel'] . ' — ' . $z['zone']],
            ['Mode', $z['hvacMode']],
            ['Action', $z['hvacAction']],
            ['Current temperature', number_format((float) $z['currentTemp'], 1) . ' °C'],
            ['Setpoint', number_format((float) $z['setpoint'], 1) . ' °C'],
            ['Fan', $z['fanMode']],
            ['Preset', $z['presetMode']],
            ['Humidity', $z['humidity'] . ' %'],
            ['CO₂', $z['co2'] . ' ppm'],
            ['Damper', $z['damperPct'] . ' %'],
            ['Reheat valve', $z['valvePct'] . ' %'],
            ['Filter', $z['filterStatus']],
            ['Runtime', number_format($z['runtimeHours']) . ' h'],
            ['Controller', $z['controller'] . ' · bacnet://' . $z['controllerIp'] . ':' . Hvac::BACNET_PORT],
        ], ' class="alte-kv"');

        $gauges = '<div class="alte-grid">'
            . '<div class="alte-card"><div class="alte-card-body">' . $this->gaugeHtml('Humidity', (int) $z['humidity'], $z['humidity'] . ' %') . '</div></div>'
            . '<div class="alte-card"><div class="alte-card-body">' . $this->gaugeHtml('CO₂', $this->co2Pct((int) $z['co2']), $z['co2'] . ' ppm') . '</div></div>'
            . '<div class="alte-card"><div class="alte-card-body">' . $this->gaugeHtml('Damper', (int) $z['damperPct'], $z['damperPct'] . ' %') . '</div></div>'
            . '</div>';

        return $gauges
            . $this->card('Zone state', $kv, $z['name'])
            . $this->card('24 h temperature', $this->sparklineHtml($hvac->tempTrend($z)), 'cached 30 s')
            . $this->setpointControl($z, false, $navBase);
    }

    /** The setpoint / mode control block — every control is an <a> to a leaf, never a state change. */
    private function setpointControl(array $z, bool $isCrac, string $navBase): string
    {
        $base = $navBase . '/hvac/' . $z['id'];
        $sp = (int) round((float) $z['setpoint']);
        $down = $this->esc($base . '/set/' . ($sp - 1));
        $up = $this->esc($base . '/set/' . ($sp + 1));
        $slider = '<div class="fp-slider" style="display:flex;align-items:center;gap:12px;margin:6px 0">'
            . '<a class="alte-btn" href="' . $down . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">−</a>'
            . '<span style="font-weight:600;font-size:1.1em;color:#2c3136">' . $this->esc(number_format((float) $z['setpoint'], 1) . ' °C') . '</span>'
            . '<a class="alte-btn" href="' . $up . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">+</a>'
            . '</div>';

        $modes = '';
        foreach (['cool', 'heat_cool', 'auto', 'fan_only', 'off'] as $m) {
            $href = $this->esc($base . '/mode/' . $m);
            $modes .= '<a class="alte-btn" href="' . $href . '" style="text-decoration:none;padding:3px 10px;margin-right:6px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136;font-size:.85em">' . $this->esc($m) . '</a>';
        }

        $fans = '';
        foreach (['auto', 'low', 'medium', 'high'] as $f) {
            $href = $this->esc($base . '/fan/' . $f);
            $fans .= '<a class="alte-btn" href="' . $href . '" style="text-decoration:none;padding:3px 10px;margin-right:6px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136;font-size:.85em">' . $this->esc($f) . '</a>';
        }

        $note = $isCrac
            ? '<p class="alte-muted" style="font-size:.85em;color:#6c757d">Precision-cooling changes are interlocked — see the confirmation.</p>'
            : '<p class="alte-muted" style="font-size:.85em;color:#6c757d">Changes queue to the BMS controller and apply at the next BACnet poll.</p>';

        $inner = '<div style="margin-bottom:10px"><strong>Setpoint</strong>' . $slider . '</div>'
            . '<div style="margin-bottom:10px"><strong>Mode</strong><div style="margin-top:6px">' . $modes . '</div></div>'
            . '<div style="margin-bottom:6px"><strong>Fan</strong><div style="margin-top:6px">' . $fans . '</div></div>'
            . $note;
        return $this->card('Controls', $inner, $isCrac ? 'interlocked' : 'write-priority 8');
    }

    private function pointsCard(Hvac $hvac, array $z, string $navBase): string
    {
        $rows = [];
        foreach ($hvac->points($z) as $p) {
            $val = $p['unit'] !== '' ? $p['value'] . ' ' . $p['unit'] : $p['value'];
            $rows[] = [$p['object'], $p['name'], $val, $p['host']];
        }
        $table = $this->tableHtml(['Object', 'Name', 'Present value', 'Host'], $rows, ' class="alte-table"');
        return $this->card('BACnet points', $table, $z['controller'] . ' · read-only mirror');
    }

    private function trendsCard(Hvac $hvac, array $z): string
    {
        $spark = $this->sparklineHtml($hvac->tempTrend($z));
        $body = $spark . '<p class="alte-muted" style="font-size:.85em;color:#6c757d">'
            . $this->esc('24 h zone temperature, hourly · setpoint ' . number_format((float) $z['setpoint'], 1) . ' °C · cached 30 s') . '</p>';
        return $this->card('Trends', $body, 'temperature');
    }

    private function scheduleCard(Hvac $hvac, array $z): string
    {
        $days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
        $rows = [];
        foreach ($days as $d) {
            $weekend = ($d === 'Sat' || $d === 'Sun');
            $occ = $weekend ? 'Unoccupied' : '07:00–19:00';
            $day = $weekend ? number_format((float) $z['setpoint'] + 2.0, 1) : number_format((float) $z['setpoint'], 1);
            $night = number_format((float) $z['setpoint'] + 3.0, 1);
            $rows[] = [$d, $occ, $day . ' °C', $night . ' °C'];
        }
        $table = $this->tableHtml(['Day', 'Occupied', 'Occupied setpoint', 'Setback'], $rows, ' class="alte-table"');
        return $this->card('Schedule', $table, 'weekly · applied by BMS');
    }

    private function alarmsCard(array $z): string
    {
        $lines = [];
        if ($z['co2'] >= 1000) {
            $lines[] = 'CO₂ high — ' . $z['co2'] . ' ppm (ventilation demand)';
        }
        if ($z['filterStatus'] !== 'OK') {
            $lines[] = 'Filter ' . strtolower($z['filterStatus']) . ' — inspection due';
        }
        if ($lines === []) {
            $lines[] = 'No active alarms for this zone.';
        }
        return $this->card('Alarms', $this->preScrollHtml($lines, 'alte-log'), 'zone buffer');
    }

    private function zoneMaintenanceCard(array $z): string
    {
        $kv = $this->kvTableHtml([
            ['Filter status', $z['filterStatus']],
            ['Runtime', number_format($z['runtimeHours']) . ' h'],
            ['Next PPM', 'Quarterly filter check'],
            ['Controller', $z['controller']],
        ], ' class="alte-kv"');
        return $this->card('Maintenance', $kv, 'PPM');
    }

    // --- CRAC detail (server-room cooling; the flagship cross-link + one-step-short work order) ---

    private function cracDetail(Hvac $hvac, string $cracId, string $subtab, string $navBase): string
    {
        $c = $hvac->crac($cracId);
        $crumbs = [['Corevance', $navBase], ['Climate / HVAC', $navBase . '/hvac'], [$c['name'], '']];
        $body = $this->breadcrumbHtml($crumbs)
            . $this->tabStrip($navBase . '/hvac/' . $cracId, $subtab, ['overview', 'points', 'maintenance']);

        if ($subtab === 'points') {
            return $body . $this->pointsCard($hvac, $c, $navBase);
        }
        if ($subtab === 'maintenance') {
            return $body . $this->cracMaintenanceCard($c, $navBase);
        }
        return $body . $this->cracOverview($hvac, $c, $navBase);
    }

    private function cracOverview(Hvac $hvac, array $c, string $navBase): string
    {
        $kv = $this->kvTableHtml([
            ['Unit id', $c['id']],
            ['Serves', $c['servesRoomName']],
            ['Supply temperature', number_format((float) $c['supplyTemp'], 1) . ' °C'],
            ['Return temperature', number_format((float) $c['returnTemp'], 1) . ' °C'],
            ['Setpoint', number_format((float) $c['setpoint'], 1) . ' °C'],
            ['Mode / action', $c['hvacMode'] . ' · ' . $c['hvacAction']],
            ['Fan', $c['fanMode']],
            ['Humidity', $c['humidity'] . ' %'],
            ['Compressor', $c['compressor']],
            ['Filter', $c['filterStatus']],
            ['Runtime', number_format($c['runtimeHours']) . ' h'],
            ['Controller', $c['controller'] . ' · bacnet://' . $c['controllerIp'] . ':' . Hvac::BACNET_PORT],
        ], ' class="alte-kv"');

        // The flagship cross-link: this unit cools the server/comms room shared with Access & System.
        $accessHref = $this->esc($navBase . '/access');
        $sysHref = $this->esc($navBase . '/system');
        $links = '<p style="margin:8px 0">Cooling load: <strong>' . $this->esc($c['servesRoomName']) . '</strong> · '
            . '<a class="alte-dl" href="' . $accessHref . '">Physical access &amp; doors</a> · '
            . '<a class="alte-dl" href="' . $sysHref . '">Server hosts</a></p>';

        $anomaly = '';
        if ($c['anomaly'] !== '') {
            $anomaly = $this->cracAnomalyNotice($c, $navBase);
        }

        $gauge = '<div class="alte-card"><div class="alte-card-body">'
            . $this->gaugeHtml('Return temp load', $this->tempPct((float) $c['returnTemp']), number_format((float) $c['returnTemp'], 1) . ' °C')
            . '</div></div>';

        return $anomaly
            . $this->card('CRAC state', $links . $kv, $c['name'])
            . '<div class="alte-grid">' . $gauge . '</div>'
            . $this->setpointControl($c, true, $navBase);
    }

    /** The budgeted anomaly banner + the work order that ends one step short (spec F5.6). */
    private function cracAnomalyNotice(array $c, string $navBase): string
    {
        if ($c['anomaly'] === 'dirty-filter') {
            $title = 'Filter differential-pressure alarm';
            $detail = 'Return-air filter loaded — airflow reduced. Precision cooling still within tolerance.';
        } else {
            $title = 'Controller communications fault';
            $detail = 'Lost BACnet trend polling to this unit; last values shown are the cached mirror.';
        }
        $wo = (string) $c['workOrder'];
        $woHref = $this->esc($navBase . '/facilities/work-orders/' . $wo);
        $status = $c['anomaly'] === 'dirty-filter' ? 'Awaiting parts — filter cartridge on order' : 'Awaiting contractor — comms module RMA';
        $body = '<p style="margin:0 0 8px">' . $this->esc($detail) . '</p>'
            . '<p style="margin:0">Work order <a class="alte-dl" href="' . $woHref . '">' . $this->esc($wo) . '</a> — '
            . $this->pillHtml($status, 'warn') . '</p>';
        return '<div class="fp-result-card" style="background:#fff;border:1px solid #d7dbdf;border-left:4px solid #b23b3b;border-radius:4px;margin:16px 0">'
            . '<div class="fp-result-head" style="padding:10px 14px;border-bottom:1px solid #eef1f3;display:flex;align-items:center;gap:8px">'
            . $this->pillHtml('Alarm', 'crit')
            . '<span style="font-weight:600;color:#2c3136">' . $this->esc($title) . '</span></div>'
            . '<div class="fp-result-body" style="padding:12px 14px">' . $body . '</div></div>';
    }

    private function cracMaintenanceCard(array $c, string $navBase): string
    {
        $notice = $c['anomaly'] !== '' ? $this->cracAnomalyNotice($c, $navBase) : '';
        $kv = $this->kvTableHtml([
            ['Filter status', $c['filterStatus']],
            ['Compressor', $c['compressor']],
            ['Runtime', number_format($c['runtimeHours']) . ' h'],
            ['Serves', $c['servesRoomName']],
            ['Next PPM', 'Semi-annual chiller service'],
        ], ' class="alte-kv"');
        return $notice . $this->card('Maintenance', $kv, 'PPM · precision cooling');
    }

    // --- control leaf (INERT): receipt for zones, guarded soft-deny for CRAC ---

    private function controlLeaf(Hvac $hvac, string $entityId, bool $isCrac, string $action, string $arg, VisualPersona $persona, string $navBase): string
    {
        if ($isCrac) {
            $c = $hvac->crac($entityId);
            $crumbs = [['Corevance', $navBase], ['Climate / HVAC', $navBase . '/hvac'],
                       [$c['name'], $navBase . '/hvac/' . $entityId], ['Command', '']];
            return $this->breadcrumbHtml($crumbs) . $this->cracSoftDeny($c, $action, $arg, $persona);
        }

        $z = $hvac->zone($entityId);
        $crumbs = [['Corevance', $navBase], ['Climate / HVAC', $navBase . '/hvac'],
                   [$z['name'], $navBase . '/hvac/' . $entityId], ['Command', '']];
        return $this->breadcrumbHtml($crumbs) . $this->zoneReceipt($z, $action, $arg, $persona);
    }

    /** A normal zone command: queued to the BMS controller, applies at next poll (never state-changing). */
    private function zoneReceipt(array $z, string $action, string $arg, VisualPersona $persona): string
    {
        $job = 'cmd-' . substr(hash('sha256', $persona->seed() . '|hvaccmd|' . $z['id'] . '|' . $action . '|' . $arg), 0, 8);
        $what = $this->commandLabel($action, $arg);
        return $this->controlResultCard($this->receiptTitle($action) . ' — ' . $z['name'], [
            ['Command', $what],
            ['Target', $z['name'] . ' (' . $z['id'] . ')'],
            ['Controller', 'bacnet://' . $z['controllerIp'] . ':' . Hvac::BACNET_PORT . ' (' . $z['controller'] . ')'],
            ['Status', 'Queued — applies at next BACnet poll (~30 s), write-priority 8'],
            ['Job', $job],
        ]);
    }

    /**
     * CRAC scary verbs (cooling the servers) get a guarded soft-denial, never "done" — a dual-auth +
     * thermal-protection interlock the attacker chases a second approver for that does not exist (spec
     * §C.2 flagship: the "set 30 °C / off" lever is inert; §F5.2 guarded soft-denials).
     */
    private function cracSoftDeny(array $c, string $action, string $arg, VisualPersona $persona): string
    {
        $req = 'FAC-CMD-' . strtoupper(substr(hash('sha256', $persona->seed() . '|craccmd|' . $c['id'] . '|' . $action . '|' . $arg), 0, 6));
        $what = $this->commandLabel($action, $arg);
        return '<div class="fp-result-card" style="background:#fff;border:1px solid #d7dbdf;border-left:4px solid #b23b3b;border-radius:4px;margin:16px 0">'
            . '<div class="fp-result-head" style="padding:10px 14px;border-bottom:1px solid #eef1f3;display:flex;align-items:center;gap:8px">'
            . $this->pillHtml('Denied', 'crit')
            . '<span style="font-weight:600;color:#2c3136">' . $this->esc('Command blocked — ' . $c['name']) . '</span></div>'
            . '<div class="fp-result-body" style="padding:12px 14px">'
            . '<p style="margin:0 0 10px">Changes to precision cooling on a server / comms room require dual authorization '
            . '(Facilities + IT) and are held by a thermal-protection interlock. The unit will not act until a second '
            . 'approver releases the interlock.</p>'
            . $this->kvTableHtml([
                ['Requested', $what],
                ['Target', $c['name'] . ' (' . $c['id'] . ')'],
                ['Serves', $c['servesRoomName']],
                ['Result', 'DENIED — dual-authorization required (Facilities + IT)'],
                ['Interlock', 'Thermal-protection — awaiting second approver'],
                ['Request', $req . ' routed to Facilities desk'],
            ], ' class="fp-result-kv" style="border-collapse:collapse;width:100%"')
            . '</div></div>';
    }

    /** Receipt heading matching the command verb — a mode/fan/preset change is not a "setpoint" change. */
    private function receiptTitle(string $action): string
    {
        switch ($action) {
            case 'mode':
                return 'Mode change queued';
            case 'fan':
                return 'Fan change queued';
            case 'preset':
                return 'Preset change queued';
            default:
                return 'Setpoint change queued';
        }
    }

    /** Human label for a control action + its (escaped-by-construction slug) arg. */
    private function commandLabel(string $action, string $arg): string
    {
        switch ($action) {
            case 'set':
                return 'Setpoint → ' . $arg . ' °C';
            case 'mode':
                return 'Mode → ' . $arg;
            case 'fan':
                return 'Fan → ' . $arg;
            case 'preset':
                return 'Preset → ' . $arg;
            default:
                return $action . ' → ' . $arg;
        }
    }

    // --- shared bits ---

    /** A sub-tab strip; the active tab is plain, the rest link to their sibling sub-path. */
    private function tabStrip(string $base, string $active, array $tabs): string
    {
        $html = '<div class="alte-tabs" style="display:flex;flex-wrap:wrap;gap:4px;margin:8px 0 14px;border-bottom:1px solid #e3e6e8">';
        foreach ($tabs as $t) {
            $label = ucfirst($t);
            if ($t === $active) {
                $html .= '<span class="alte-tab is-active" style="padding:6px 12px;border-bottom:2px solid #3b7ea1;font-weight:600;color:#2c3136">' . $this->esc($label) . '</span>';
            } else {
                $href = $this->esc($t === 'overview' ? $base : $base . '/' . $t);
                $html .= '<a class="alte-tab" href="' . $href . '" style="padding:6px 12px;color:#3b7ea1;text-decoration:none">' . $this->esc($label) . '</a>';
            }
        }
        return $html . '</div>';
    }

    private function pager(string $base, int $total, int $page, int $pages): string
    {
        $from = $total === 0 ? 0 : (($page - 1) * self::PER_PAGE) + 1;
        $to = min($page * self::PER_PAGE, $total);
        $summary = 'Showing ' . $from . '&ndash;' . $to . ' of ' . number_format($total) . ' zones';
        return $this->pagerHtml($base, $page, $pages, $summary);
    }

    /** Progressive-enhancement search box (client-side row filter); degrades to showing all rows. */
    private function zoneSearchBox(): string
    {
        return '<input type="text" id="hvac-zone-search" placeholder="Filter zones…" '
            . 'style="margin:0 0 10px;padding:6px 10px;border:1px solid #c9ccd1;border-radius:4px;width:100%;max-width:320px" '
            . 'aria-label="Filter zones">';
    }

    /** Vanilla, self-contained row filter — no external code, no state change (spec R1 / D.5). */
    private function searchScript(): string
    {
        return '<script>(function(){var i=document.getElementById("hvac-zone-search"),'
            . 't=document.getElementById("hvac-zones");if(!i||!t)return;'
            . 'i.addEventListener("input",function(){var q=i.value.toLowerCase(),'
            . 'r=t.tBodies[0]?t.tBodies[0].rows:[];for(var k=0;k<r.length;k++){'
            . 'r[k].style.display=r[k].textContent.toLowerCase().indexOf(q)>-1?"":"none";}});})();</script>';
    }

    /** Fixed pill state per HVAC mode (never rendered itself — only selects a colour). */
    private function modePill(string $mode): string
    {
        if ($mode === 'off') {
            return 'idle';
        }
        if ($mode === 'cool' || $mode === 'auto' || $mode === 'heat_cool') {
            return 'info';
        }
        return 'ok';
    }

    private function co2Pct(int $co2): int
    {
        $pct = (int) round($co2 / 2000 * 100);
        return $pct < 0 ? 0 : ($pct > 100 ? 100 : $pct);
    }

    private function tempPct(float $temp): int
    {
        // Map 15–35 °C onto 0–100 so a hot return reads as the more severe gauge band.
        $pct = (int) round(($temp - 15.0) / 20.0 * 100);
        return $pct < 0 ? 0 : ($pct > 100 ? 100 : $pct);
    }
}
