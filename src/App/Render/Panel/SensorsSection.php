<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\FrozenClock;
use Funnypot\App\Render\Fake\Sensors;
use Funnypot\App\Render\VisualPersona;

/**
 * Sensors / Environment (spec §C.2): the HA device-class long tail rendered off Fake\Sensors (which sits
 * on Fake\Building, so every sensor's room, floor, zone and BMS controller reconcile with every other
 * building module). This is the cheapest breadth in the panel — hundreds of read-only rows across a
 * dozen device classes, each with a gauge or a state pill, a history sparkline, and a BMS point mirror.
 *
 * The ladder for this module (READ-ONLY — no controls; smoke/leak response is the Fire module):
 *   /<mount>/sensors                       landing — summary tiles + gauges + filter chips + sensor list
 *   /<mount>/sensors/class/<dc>            list filtered to one device class (paginated pN, JS search)
 *   /<mount>/sensors/floor/<code>         list filtered to one floor (paginated pN, JS search)
 *   /<mount>/sensors/<sensorId>            sensor detail — gauge/state, statistics, sub-tab strip
 *   /<mount>/sensors/<sensorId>/history   history sub-tab — seeded 24 h sparkline + reading table
 *   /<mount>/sensors/<sensorId>/points    BMS point mirror (recon bait: object id + host:port)
 *
 * Positional route slots: section = 'class'/'floor'/<sensorId>; entity = filter value OR detail sub-tab.
 * Everything stays INERT and DETERMINISTIC per seed.
 */
final class SensorsSection extends AbstractPanelSection
{
    /** Sensor rows per list page (long tail — a big page keeps the scroll dense). */
    private const PER_PAGE = 50;

    /** Detail sub-tabs (entity slot values that render a view). */
    private const SUBTABS = ['overview', 'history', 'statistics', 'points'];

    /** Reserved section slugs that select a filtered list rather than a sensor id. */
    private const FILTERS = ['class', 'floor'];

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $sensors = Sensors::fromSeed($persona->seed());
        $section = $route['section'];

        if ($section === '') {
            return $this->landing($sensors, (int) $route['page'], $navBase);
        }
        if (in_array($section, self::FILTERS, true)) {
            return $this->filteredList($sensors, $section, $route['entity'], (int) $route['page'], $navBase);
        }
        return $this->detail($sensors, $section, $route['entity'], $navBase);
    }

    // --- landing: summary + gauges + filter chips + full sensor list ---

    private function landing(Sensors $sensors, int $page, string $navBase): string
    {
        $s = $sensors->summary();
        $tiles = $this->statCardsHtml([
            ['label' => 'Sensors', 'value' => number_format($s['total']), 'sub' => $s['classes'] . ' device classes'],
            ['label' => 'Online', 'value' => number_format($s['online']) . ' / ' . number_format($s['total']), 'sub' => $s['offline'] . ' offline · ' . $s['faults'] . ' fault'],
            ['label' => 'Active alerts', 'value' => (string) $s['alarms'], 'sub' => $s['alarms'] === 0 ? 'all nominal' : 'out-of-band readings'],
            ['label' => 'Low battery', 'value' => (string) $s['lowBattery'], 'sub' => $s['lowBattery'] === 0 ? 'all healthy' : 'replace soon'],
            ['label' => 'Leak detectors', 'value' => $s['leaks'] === 0 ? 'Dry' : (string) $s['leaks'], 'sub' => $s['leaks'] === 0 ? 'no water detected' : 'water detected'],
            ['label' => 'Last BMS poll', 'value' => $sensors->lastPollAge(), 'sub' => 'cached 30 s'],
        ], 'alte-stats', 'alte-st');

        $gauges = '<div class="alte-grid" style="display:flex;flex-wrap:wrap;gap:16px">'
            . '<div class="alte-card" style="flex:1;min-width:200px"><div class="alte-card-body">'
            . $this->gaugeHtml('Avg temperature', $this->clamp((int) round(($s['avgTemp'] - 15.0) / 15.0 * 100)), number_format($s['avgTemp'], 1) . ' °C')
            . '</div></div>'
            . '<div class="alte-card" style="flex:1;min-width:200px"><div class="alte-card-body">'
            . $this->gaugeHtml('Avg CO₂', $this->clamp((int) round($s['avgCo2'] / 2000 * 100)), $s['avgCo2'] . ' ppm')
            . '</div></div>'
            . '<div class="alte-card" style="flex:1;min-width:200px"><div class="alte-card-body">'
            . $this->gaugeHtml('Avg PM2.5', $this->clamp((int) round($s['avgPm25'] / 60 * 100)), $s['avgPm25'] . ' µg/m³')
            . '</div></div></div>';

        $leakBanner = $s['leaks'] > 0 ? $this->leakBanner($sensors, $navBase) : '';

        $all = $sensors->sensors();
        $list = $this->listCard($sensors, $all, 'All sensors', $navBase . '/sensors', $page, $navBase, true);

        $body = $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Sensors / Environment'))
            . $tiles
            . $gauges
            . $leakBanner
            . $this->filterChips($sensors, $navBase)
            . $list;

        return $body . $this->searchScript();
    }

    /** The planted-leak alarm banner: one Server-Comms leak reading Wet -> a work order one step short. */
    private function leakBanner(Sensors $sensors, string $navBase): string
    {
        $leak = null;
        foreach ($sensors->sensors() as $s) {
            if ($s['class'] === 'moisture' && $s['value'] === 'Wet') {
                $leak = $s;
                break;
            }
        }
        if ($leak === null) {
            return '';
        }
        $href = $this->esc($navBase . '/sensors/' . $leak['id']);
        $woHref = $this->esc($navBase . '/facilities/work-orders/' . $leak['workOrder']);
        $body = '<p style="margin:0 0 8px">Water detected at <a class="alte-dl" href="' . $href . '">'
            . $this->esc($leak['name']) . '</a> (' . $this->esc($leak['roomName']) . '). '
            . 'Under-floor leak detector tripped — facilities dispatched.</p>'
            . '<p style="margin:0">Work order <a class="alte-dl" href="' . $woHref . '">' . $this->esc($leak['workOrder']) . '</a> — '
            . $this->pillHtml('Awaiting attendance — plumber en route', 'warn') . '</p>';
        return '<div class="fp-result-card" style="background:#fff;border:1px solid #d7dbdf;border-left:4px solid #b23b3b;border-radius:4px;margin:16px 0">'
            . '<div class="fp-result-head" style="padding:10px 14px;border-bottom:1px solid #eef1f3;display:flex;align-items:center;gap:8px">'
            . $this->pillHtml('Leak', 'crit')
            . '<span style="font-weight:600;color:#2c3136">' . $this->esc('Water leak — ' . $leak['roomName']) . '</span></div>'
            . '<div class="fp-result-body" style="padding:12px 14px">' . $body . '</div></div>';
    }

    /** Filter chips: one row of device-class links, one row of floor links — deep, server-side filters. */
    private function filterChips(Sensors $sensors, string $navBase): string
    {
        $classChips = '';
        foreach ($sensors->classes() as $dc) {
            $href = $this->esc($navBase . '/sensors/class/' . $dc);
            $classChips .= '<a class="alte-btn" href="' . $href . '" style="text-decoration:none;padding:3px 10px;margin:0 6px 6px 0;border:1px solid #c9ccd1;border-radius:12px;color:#3b7ea1;font-size:.82em;display:inline-block">'
                . $this->esc($sensors->classLabel($dc)) . '</a>';
        }
        $floorChips = '';
        foreach ($this->buildingFloors($sensors) as $f) {
            $href = $this->esc($navBase . '/sensors/floor/' . strtolower($f['code']));
            $floorChips .= '<a class="alte-btn" href="' . $href . '" style="text-decoration:none;padding:3px 10px;margin:0 6px 6px 0;border:1px solid #c9ccd1;border-radius:12px;color:#3b7ea1;font-size:.82em;display:inline-block">'
                . $this->esc($f['label']) . '</a>';
        }
        $inner = '<div style="margin-bottom:8px"><strong style="font-size:.85em;color:#6c757d">By class</strong><div style="margin-top:6px">' . $classChips . '</div></div>'
            . '<div><strong style="font-size:.85em;color:#6c757d">By floor</strong><div style="margin-top:6px">' . $floorChips . '</div></div>';
        return $this->card('Filter', $inner, 'read-only');
    }

    /** Distinct floors present in the estate, in building order. @return list<array{code:string,label:string}> */
    private function buildingFloors(Sensors $sensors): array
    {
        $seen = [];
        $out = [];
        foreach ($sensors->sensors() as $s) {
            $code = (string) $s['floor'];
            if (!isset($seen[$code])) {
                $seen[$code] = true;
                $out[] = ['code' => $code, 'label' => (string) $s['floorLabel']];
            }
        }
        return $out;
    }

    // --- filtered list (by device class or by floor) ---

    private function filteredList(Sensors $sensors, string $kind, string $value, int $page, string $navBase): string
    {
        $all = $sensors->sensors();
        $rows = [];
        $title = '';
        $base = '';
        if ($kind === 'class') {
            foreach ($all as $s) {
                if ($s['class'] === $value) {
                    $rows[] = $s;
                }
            }
            $title = $sensors->classLabel($value) . ' sensors';
            $base = $navBase . '/sensors/class/' . $value;
            $crumbLabel = $sensors->classLabel($value);
        } else {
            foreach ($all as $s) {
                if (strtolower((string) $s['floor']) === $value) {
                    $rows[] = $s;
                }
            }
            $label = $rows !== [] ? (string) $rows[0]['floorLabel'] : strtoupper($value);
            $title = $label . ' sensors';
            $base = $navBase . '/sensors/floor/' . $value;
            $crumbLabel = $label;
        }

        $crumbs = [['Corevance', $navBase], ['Sensors / Environment', $navBase . '/sensors'], [$crumbLabel, '']];
        $body = $this->breadcrumbHtml($crumbs)
            . $this->listCard($sensors, $rows, $title, $base, $page, $navBase, true);
        return $body . $this->searchScript();
    }

    // --- the shared list card (paginated + JS search) ---

    /**
     * @param list<array<string,mixed>> $rowsData
     */
    private function listCard(Sensors $sensors, array $rowsData, string $title, string $base, int $page, string $navBase, bool $withSearch): string
    {
        $total = count($rowsData);
        if ($page < 1) {
            $page = 1;
        }
        $pages = $total > 0 ? (int) ceil($total / self::PER_PAGE) : 1;
        if ($page > $pages) {
            $page = $pages;
        }
        $slice = array_slice($rowsData, ($page - 1) * self::PER_PAGE, self::PER_PAGE);

        $rows = '';
        foreach ($slice as $s) {
            $href = $this->esc($navBase . '/sensors/' . $s['id']);
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($s['name']) . '</a></td>'
                . '<td>' . $this->esc($s['classLabel']) . '</td>'
                . '<td>' . $this->readingCell($s) . '</td>'
                . '<td>' . $this->esc($s['roomName']) . '</td>'
                . '<td>' . $this->esc($s['floorLabel']) . '</td>'
                . '<td>' . $this->statusPill($s['status']) . '</td>'
                . '<td>' . $this->esc($s['lastSeen']) . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Sensor</th><th>Class</th><th>Reading</th><th>Room</th><th>Floor</th>'
            . '<th>Status</th><th>Last seen</th></tr></thead>';
        $search = $withSearch ? $this->searchBox() : '';
        $table = $search
            . '<table class="alte-table" id="sensors-list">' . $head . '<tbody>' . $rows . '</tbody></table>'
            . $this->pager($total, $page, $pages, $base);

        return $this->card($title, $table, number_format($total) . ' sensors · last BMS poll ' . $sensors->lastPollAge());
    }

    /** Reading cell: numeric shows the value with a severity dot; binary shows a state pill. */
    private function readingCell(array $s): string
    {
        if ($s['kind'] === 'binary') {
            return $this->pillHtml((string) $s['value'], $this->sevPill((string) $s['severity']));
        }
        $dot = '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;'
            . 'background:' . $this->sevColor((string) $s['severity']) . '"></span>';
        return $dot . $this->esc((string) $s['value']);
    }

    // --- sensor detail ---

    private function detail(Sensors $sensors, string $sensorId, string $entity, string $navBase): string
    {
        $s = $sensors->sensor($sensorId);
        $subtab = in_array($entity, self::SUBTABS, true) ? $entity : 'overview';
        $crumbs = [['Corevance', $navBase], ['Sensors / Environment', $navBase . '/sensors'], [$s['name'], '']];
        $body = $this->breadcrumbHtml($crumbs)
            . $this->tabStrip($navBase . '/sensors/' . $sensorId, $subtab, self::SUBTABS);

        switch ($subtab) {
            case 'history':
                return $body . $this->historyCard($sensors, $s);
            case 'statistics':
                return $body . $this->statisticsCard($sensors, $s);
            case 'points':
                return $body . $this->pointsCard($sensors, $s);
            default:
                return $body . $this->overview($sensors, $s, $navBase);
        }
    }

    private function overview(Sensors $sensors, array $s, string $navBase): string
    {
        $leakNotice = ($s['class'] === 'moisture' && $s['value'] === 'Wet') ? $this->leakDetailNotice($s, $navBase) : '';

        $kv = $this->kvTableHtml([
            ['Entity id', $s['entityId']],
            ['Device class', $s['classLabel']],
            ['Present value', $s['value']],
            ['Status', ucfirst((string) $s['status'])],
            ['Location', $s['floorLabel'] . ' — ' . $s['roomName'] . ' (' . $s['zone'] . ')'],
            ['Room type', $s['roomType']],
            ['Controller', $s['controller'] . ' · bacnet://' . $s['controllerIp'] . ':' . Sensors::BACNET_PORT],
            ['Firmware', $s['firmware']],
            ['Power', $s['battery'] < 0 ? 'Mains' : 'Battery ' . $s['battery'] . ' %'],
            ['Signal', $s['signal'] . ' dBm'],
            ['Last seen', FrozenClock::ymd((int) $s['lastSeenEpoch']) . ' ' . FrozenClock::clock((int) $s['lastSeenEpoch']) . ' (' . $s['lastSeen'] . ')'],
        ], ' class="alte-kv"');

        // The reading widget: a gauge for a numeric class, a state pill for a binary class.
        if ($s['kind'] === 'numeric') {
            $widget = '<div class="alte-card"><div class="alte-card-body" style="text-align:center">'
                . $this->gaugeHtml((string) $s['classLabel'], (int) $s['gaugePct'], (string) $s['value'])
                . '</div></div>';
        } else {
            $widget = '<div class="alte-card"><div class="alte-card-body" style="text-align:center">'
                . '<div style="font-size:.72em;color:#9aa1a8;text-transform:uppercase;letter-spacing:.04em;margin-bottom:8px">' . $this->esc((string) $s['classLabel']) . '</div>'
                . $this->pillHtml((string) $s['value'], $this->sevPill((string) $s['severity']))
                . '</div></div>';
        }

        // Cross-coherence: link the sensor's real room aggregate and the floor filter.
        $roomHref = $this->esc($navBase . '/rooms/' . $s['roomId']);
        $floorHref = $this->esc($navBase . '/sensors/floor/' . strtolower((string) $s['floor']));
        $classHref = $this->esc($navBase . '/sensors/class/' . $s['class']);
        $links = '<p style="margin:8px 0">Bound to <a class="alte-dl" href="' . $roomHref . '">' . $this->esc($s['roomName']) . '</a> · '
            . '<a class="alte-dl" href="' . $floorHref . '">All sensors on ' . $this->esc((string) $s['floorLabel']) . '</a> · '
            . '<a class="alte-dl" href="' . $classHref . '">All ' . $this->esc((string) $s['classLabel']) . '</a></p>';

        $trend = $s['kind'] === 'numeric'
            ? $this->card('24 h trend', $this->sparklineHtml($sensors->history($s)), 'cached 30 s')
            : '';

        return $leakNotice
            . '<div class="alte-grid">' . $widget . '</div>'
            . $this->card('Sensor state', $links . $kv, (string) $s['name'])
            . $trend;
    }

    /** Leak detail notice mirroring the landing banner, so a crawler reaches the WO from the sensor too. */
    private function leakDetailNotice(array $s, string $navBase): string
    {
        $woHref = $this->esc($navBase . '/facilities/work-orders/' . $s['workOrder']);
        $body = '<p style="margin:0 0 8px">Under-floor water detected in ' . $this->esc((string) $s['roomName'])
            . '. Detector latched Wet; the reading holds until reset by facilities.</p>'
            . '<p style="margin:0">Work order <a class="alte-dl" href="' . $woHref . '">' . $this->esc((string) $s['workOrder']) . '</a> — '
            . $this->pillHtml('Awaiting attendance', 'warn') . '</p>';
        return '<div class="fp-result-card" style="background:#fff;border:1px solid #d7dbdf;border-left:4px solid #b23b3b;border-radius:4px;margin:16px 0">'
            . '<div class="fp-result-head" style="padding:10px 14px;border-bottom:1px solid #eef1f3;display:flex;align-items:center;gap:8px">'
            . $this->pillHtml('Leak', 'crit')
            . '<span style="font-weight:600;color:#2c3136">' . $this->esc('Water detected — ' . $s['roomName']) . '</span></div>'
            . '<div class="fp-result-body" style="padding:12px 14px">' . $body . '</div></div>';
    }

    private function historyCard(Sensors $sensors, array $s): string
    {
        $hist = $sensors->history($s);
        $spark = $this->sparklineHtml($hist);
        $rows = [];
        $n = count($hist);
        for ($i = 0; $i < $n; $i++) {
            $hoursAgo = ($n - 1) - $i;
            $when = $hoursAgo === 0 ? 'now' : $hoursAgo . ' h ago';
            $val = $s['kind'] === 'numeric'
                ? number_format($hist[$i], 1) . ($s['unit'] !== '' ? ' ' . $s['unit'] : '')
                : ($hist[$i] > 0 ? 'Active' : 'Inactive');
            $rows[] = [$when, $val];
        }
        $table = $this->tableHtml(['Time', 'Reading'], $rows, ' class="alte-table"');
        $note = '<p class="alte-muted" style="font-size:.85em;color:#6c757d">'
            . $this->esc('24 h history, hourly · ' . $s['classLabel'] . ' · cached 30 s') . '</p>';
        return $this->card('History', $spark . $note, (string) $s['name'])
            . $this->card('Hourly readings', $table, 'read-only mirror');
    }

    private function statisticsCard(Sensors $sensors, array $s): string
    {
        $stats = $sensors->statistics($s);
        if ($stats === null) {
            $kv = $this->kvTableHtml([
                ['Present state', $s['value']],
                ['Class', $s['classLabel']],
                ['Note', 'Binary sensor — no numeric distribution'],
            ], ' class="alte-kv"');
            return $this->card('Statistics', $kv, (string) $s['name']);
        }
        $u = $stats['unit'] !== '' ? ' ' . $stats['unit'] : '';
        $cards = $this->statCardsHtml([
            ['label' => 'Current', 'value' => number_format($stats['current'], 1) . $u],
            ['label' => 'Min (24 h)', 'value' => number_format($stats['min'], 1) . $u],
            ['label' => 'Max (24 h)', 'value' => number_format($stats['max'], 1) . $u],
            ['label' => 'Mean (24 h)', 'value' => number_format($stats['avg'], 1) . $u],
        ], 'alte-stats', 'alte-st');
        return $this->card('Statistics', $cards, (string) $s['name']);
    }

    private function pointsCard(Sensors $sensors, array $s): string
    {
        $rows = [];
        foreach ($sensors->points($s) as $p) {
            $rows[] = [$p['object'], $p['name'], $p['value'], $p['host']];
        }
        $table = $this->tableHtml(['Object', 'Name', 'Present value', 'Host'], $rows, ' class="alte-table"');
        return $this->card('BMS points', $table, $s['controller'] . ' · read-only mirror');
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

    /** Pager line with prev/next sibling links (kept under the same list base, so depth stays crawlable). */
    private function pager(int $total, int $page, int $pages, string $base): string
    {
        $from = $total === 0 ? 0 : (($page - 1) * self::PER_PAGE) + 1;
        $to = min($page * self::PER_PAGE, $total);
        $summary = 'Showing ' . $from . '&ndash;' . $to . ' of ' . number_format($total);
        return $this->pagerHtml($base, $page, $pages, $summary);
    }

    /** Progressive-enhancement search box (client-side row filter); degrades to showing all rows. */
    private function searchBox(): string
    {
        return '<input type="text" id="sensors-search" placeholder="Filter sensors…" '
            . 'style="margin:0 0 10px;padding:6px 10px;border:1px solid #c9ccd1;border-radius:4px;width:100%;max-width:320px" '
            . 'aria-label="Filter sensors">';
    }

    /** Vanilla, self-contained row filter — no external code, no state change (spec R1 / D.5). */
    private function searchScript(): string
    {
        return '<script>(function(){var i=document.getElementById("sensors-search"),'
            . 't=document.getElementById("sensors-list");if(!i||!t)return;'
            . 'i.addEventListener("input",function(){var q=i.value.toLowerCase(),'
            . 'r=t.tBodies[0]?t.tBodies[0].rows:[];for(var k=0;k<r.length;k++){'
            . 'r[k].style.display=r[k].textContent.toLowerCase().indexOf(q)>-1?"":"none";}});})();</script>';
    }

    /** Status -> pill state: online reads healthy, fault warns, offline is neutral idle. */
    private function statusPill(string $status): string
    {
        if ($status === 'online') {
            return $this->pillHtml('Online', 'ok');
        }
        if ($status === 'fault') {
            return $this->pillHtml('Fault', 'warn');
        }
        return $this->pillHtml('Offline', 'idle');
    }

    /** Severity band -> pill state (idle falls to the neutral pill; others map straight through). */
    private function sevPill(string $sev): string
    {
        return in_array($sev, ['ok', 'warn', 'crit', 'info'], true) ? $sev : 'idle';
    }

    /** Fixed dot colour per severity band (matches the D.2 status custom properties). */
    private function sevColor(string $sev): string
    {
        switch ($sev) {
            case 'crit':
                return '#b23b3b';
            case 'warn':
                return '#c07a1a';
            case 'info':
                return '#3b7ea1';
            case 'ok':
                return '#2e8b57';
            default:
                return '#9aa1a8';
        }
    }

    private function clamp(int $pct): int
    {
        return $pct < 0 ? 0 : ($pct > 100 ? 100 : $pct);
    }
}
