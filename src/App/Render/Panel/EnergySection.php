<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Energy;
use Funnypot\Support\VisualPersona;

/**
 * Energy & Power / BMS (module slug `energy`, spec §C.8) — the SCADA-flavoured electrical plane rendered
 * off Fake\Energy (which sits on Fake\Building, so sub-meters, breaker boards, UPS, gensets and HVAC plant
 * reconcile with every other building module and land in real Plant / Server-Comms rooms).
 *
 * The category ladder for this module (positional route: section = category, entity = item id / action,
 * subtab = sub-view or control verb, action = control arg):
 *   /<mount>/energy                                overview — tiles, gauges, single-line diagram, load trend
 *   /<mount>/energy/meters[/pN]                    sub-meter list (paginated, JS search) — the dead-meter chase
 *   /<mount>/energy/meters/<id>[/trend|config|comms]   meter detail + BACnet-style point/config sub-tabs
 *   /<mount>/energy/breakers/<board>               breaker schedule; toggle -> "queued, awaiting second operator"
 *   /<mount>/energy/ups/<id>[/strings|snmp]        UPS detail; the SNMP tab carries the lone trap-receiver IP
 *   /<mount>/energy/generator/<id>[/self-test|start]   genset; self-test canned, start = PIN-at-HMI soft-deny
 *   /<mount>/energy/solar[/<string>]               PV strings; the one planted fault -> electrician WO chain
 *   /<mount>/energy/bess                           battery storage detail
 *   /<mount>/energy/utilities[/<id>[/shutoff]]     water/gas/waste; gas shut-off = break-glass soft-deny
 *   /<mount>/energy/plant[/<id>]                    chillers/boilers/AHUs from Building
 *   /<mount>/energy/demand-response[/simulate|shed]    DR: simulate = canned report, shed = guarded deny
 *   /<mount>/energy/bills · /trends · /alarms       archives + plant alarm console
 *
 * Everything stays INERT and DETERMINISTIC per seed; a control is always an <a>/receipt, never a state
 * change. Every reflected value reaches HTML through the escape-by-construction helpers on
 * AbstractPanelSection; the only attacker value echoed is a control arg, and it is esc()'d.
 */
final class EnergySection extends AbstractPanelSection
{
    /** Sub-meter rows per landing page. */
    private const METERS_PER_PAGE = 30;

    private const MODULE_TITLE = 'Energy & Power';

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $energy = Energy::fromSeed($persona->seed());
        $section = $route['section'];

        switch ($section) {
            case '':
                return $this->landing($energy, $navBase);
            case 'meters':
                return $route['entity'] === ''
                    ? $this->metersList($energy, (int) $route['page'], $navBase)
                    : $this->meterDetail($energy, $route['entity'], $route['subtab'], $navBase);
            case 'breakers':
                return $this->breakers($energy, $route, $persona, $navBase);
            case 'ups':
                return $route['entity'] === ''
                    ? $this->upsList($energy, $navBase)
                    : $this->upsDetail($energy, $route['entity'], $route['subtab'], $navBase);
            case 'generator':
                return $this->generator($energy, $route, $persona, $navBase);
            case 'solar':
                return $route['entity'] === ''
                    ? $this->solarList($energy, $navBase)
                    : $this->solarDetail($energy, $route['entity'], $navBase);
            case 'bess':
                return $this->bess($energy, $navBase);
            case 'utilities':
                return $this->utilities($energy, $route, $persona, $navBase);
            case 'plant':
                return $route['entity'] === ''
                    ? $this->plantList($energy, $navBase)
                    : $this->plantDetail($energy, $route['entity'], $navBase);
            case 'demand-response':
                return $this->demandResponse($energy, $route, $persona, $navBase);
            case 'bills':
                return $this->bills($energy, $navBase);
            case 'trends':
                return $this->trends($energy, $navBase);
            case 'alarms':
                return $this->alarms($energy, $navBase);
            default:
                return $this->landing($energy, $navBase);
        }
    }

    // --- landing: power dashboard + single-line diagram ---

    private function landing(Energy $energy, string $navBase): string
    {
        $s = $energy->summary();
        $tiles = $this->statCardsHtml([
            ['label' => 'Building load', 'value' => number_format($s['loadKw'], 1) . ' kW', 'sub' => 'peak ' . number_format($s['peakKw'], 1) . ' kW'],
            ['label' => 'Energy today', 'value' => number_format($s['kwhToday']) . ' kWh', 'sub' => 'from midnight'],
            ['label' => 'Cost today', 'value' => $s['currencySym'] . number_format($s['costToday'], 2), 'sub' => $s['currencyCode'] . ' @ ' . $s['currencySym'] . number_format($s['tariffRate'], 2) . '/kWh'],
            ['label' => 'Carbon today', 'value' => number_format($s['carbonToday']) . ' kg', 'sub' => 'CO₂e @ ' . number_format($s['carbonFactor'], 2) . ' kg/kWh'],
            ['label' => 'Solar output', 'value' => number_format($s['pvKw'], 1) . ' kW', 'sub' => number_format($s['pvYieldToday']) . ' kWh today'],
            ['label' => 'BESS charge', 'value' => $s['bessSoc'] . ' %', 'sub' => 'state of charge'],
            ['label' => 'Power factor', 'value' => number_format($s['powerFactor'], 2), 'sub' => 'site aggregate'],
            ['label' => 'Active alarms', 'value' => (string) $s['activeAlarms'], 'sub' => $s['activeAlarms'] === 0 ? 'all clear' : 'requires review'],
        ], 'fp-tiles', 'fp-tile');

        $gauges = '<div class="alte-grid">'
            . $this->gaugeCard('Load vs peak', $this->pctOf($s['loadKw'], $s['peakKw']), number_format($s['loadKw'], 1) . ' kW')
            . $this->gaugeCard('BESS SoC', $s['bessSoc'], $s['bessSoc'] . ' %')
            . $this->gaugeCard('Power factor', (int) round($s['powerFactor'] * 100), number_format($s['powerFactor'], 2))
            . '</div>';

        $diagram = $this->card('Electrical single-line', $this->singleLineSvg($energy, $navBase), 'utility → MSB → distribution');
        $trend = $this->card('24 h building load', $this->sparklineHtml($energy->loadTrend()), 'cached 30 s · ' . $energy->lastPollAge());

        $body = $this->breadcrumbHtml($this->baseCrumbs($navBase, self::MODULE_TITLE))
            . $tiles
            . $gauges
            . $diagram
            . $trend
            . $this->categoryCards($energy, $navBase)
            . $this->commsFailTeaser($energy, $navBase);

        return $body;
    }

    /** The category deep-link grid — every energy sub-domain one click away. */
    private function categoryCards(Energy $energy, string $navBase): string
    {
        $s = $energy->summary();
        $solar = $energy->solarSummary();
        $items = [
            ['meters', 'Sub-metering', $s['meterCount'] . ' meters · ' . $s['commsFails'] . ' comms fault(s)'],
            ['breakers', 'Breaker schedule', count($energy->boards()) . ' distribution boards'],
            ['ups', 'UPS fleet', count($energy->upsFleet()) . ' units'],
            ['generator', 'Standby generators', count($energy->generators()) . ' genset(s)'],
            ['solar', 'Solar PV', $solar['strings'] . ' strings · ' . ($solar['faultString'] === '' ? 'all producing' : $solar['faultString'] . ' fault')],
            ['bess', 'Battery storage', $energy->bess()['soc'] . '% SoC · ' . $energy->bess()['mode']],
            ['utilities', 'Water · gas · waste', 'utility meters'],
            ['plant', 'HVAC plant', count($energy->plant()) . ' chillers/boilers/AHUs'],
            ['demand-response', 'Demand response', 'shed / DR event'],
            ['bills', 'Bills archive', 'monthly statements'],
            ['trends', 'Trends catalog', 'CSV exports'],
            ['alarms', 'Alarm console', number_format($energy->alarmTotal()) . ' historical'],
        ];
        $cards = '<div class="alte-grid">';
        foreach ($items as $it) {
            $href = $this->esc($navBase . '/energy/' . $it[0]);
            $cards .= '<a class="fp-card" href="' . $href . '" style="text-decoration:none;color:inherit;display:block">'
                . '<div class="fp-card-body">'
                . '<div style="font-weight:600;color:#2c3136">' . $this->esc($it[1]) . '</div>'
                . '<div class="fp-muted" style="font-size:.85em;color:#6c757d;margin-top:4px">' . $this->esc($it[2]) . '</div>'
                . '</div></a>';
        }
        return $cards . '</div>';
    }

    /** The dead-sub-meter teaser on the landing — the budgeted comms fails, each a link into the list. */
    private function commsFailTeaser(Energy $energy, string $navBase): string
    {
        $rows = [];
        foreach ($energy->meters() as $m) {
            if ($m['comms'] === 'FAIL') {
                $rows[] = [$m['id'], $m['label'], $m['controller'] . ' (' . $m['controllerIp'] . ')', $m['lastSeen']];
            }
        }
        if ($rows === []) {
            return '';
        }
        $table = $this->tableHtml(['Meter', 'Circuit', 'Field controller', 'Last seen'], $rows, ' class="alte-table"');
        $link = '<p style="margin:8px 0 0"><a class="fp-dl" href="' . $this->esc($navBase . '/energy/meters') . '">Open sub-metering →</a></p>';
        return $this->card('Sub-meters not reporting', $table . $link, 'comms fault');
    }

    /** The inline single-line diagram: utility → MSB → distribution, with PV/BESS/genset/UPS infeeds. */
    private function singleLineSvg(Energy $energy, string $navBase): string
    {
        $s = $energy->summary();
        $node = function (int $x, int $y, int $w, string $label, string $sub, string $slug, string $fill) use ($navBase): string {
            $href = $this->esc($navBase . '/energy/' . $slug);
            $tx = $x + (int) ($w / 2);
            return '<a href="' . $href . '">'
                . '<rect x="' . $x . '" y="' . $y . '" width="' . $w . '" height="40" rx="4" fill="' . $fill . '" stroke="#7d868f"/>'
                . '<text x="' . $tx . '" y="' . ($y + 17) . '" text-anchor="middle" font-size="12" font-family="sans-serif" font-weight="bold" fill="#1b1e21">' . $this->esc($label) . '</text>'
                . '<text x="' . $tx . '" y="' . ($y + 32) . '" text-anchor="middle" font-size="9" font-family="sans-serif" fill="#4a525a">' . $this->esc($sub) . '</text>'
                . '</a>';
        };
        $line = function (int $x1, int $y1, int $x2, int $y2): string {
            return '<line x1="' . $x1 . '" y1="' . $y1 . '" x2="' . $x2 . '" y2="' . $y2 . '" stroke="#7d868f" stroke-width="1.5"/>';
        };

        $svg = '<div style="overflow-x:auto"><svg viewBox="0 0 640 280" preserveAspectRatio="xMidYMid meet" '
            . 'style="width:100%;max-width:640px;height:auto;display:block" role="img" aria-label="Electrical single-line diagram">'
            // Utility -> MSB
            . $line(300, 50, 300, 78)
            // MSB -> distribution bus
            . $line(300, 118, 300, 150)
            . $line(120, 150, 520, 150)
            . $line(120, 150, 120, 190) . $line(300, 150, 300, 190) . $line(520, 150, 520, 190)
            // infeeds into MSB bus
            . $line(90, 98, 240, 98) . $line(360, 98, 560, 98)
            . $line(90, 98, 90, 200) . $line(560, 98, 560, 200)
            . $node(230, 10, 140, 'Utility supply', number_format($s['loadKw'], 0) . ' kW import', 'meters', '#e7edf2')
            . $node(230, 78, 140, 'Main switchboard', 'MSB · PF ' . number_format($s['powerFactor'], 2), 'breakers', '#dfe7ee')
            . $node(60, 200, 120, 'Solar PV', number_format($s['pvKw'], 1) . ' kW', 'solar', '#e6f0e6')
            . $node(500, 200, 120, 'BESS', $s['bessSoc'] . '% SoC', 'bess', '#e6f0e6')
            . $node(60, 40, 60, 'Genset', 'standby', 'generator', '#f0ece0')
            . $node(520, 40, 60, 'UPS', 'online', 'ups', '#f0ece0')
            . $node(60, 190, 120, 'DB — low level', 'lighting/power', 'breakers', '#eef1f3')
            . $node(240, 190, 120, 'DB — mid', 'mechanical', 'breakers', '#eef1f3')
            . $node(460, 190, 120, 'DB — plant', 'HVAC plant', 'plant', '#eef1f3')
            . '</svg></div>';
        return $svg;
    }

    // --- sub-meters ---

    private function metersList(Energy $energy, int $page, string $navBase): string
    {
        $meters = $energy->meters();
        $total = count($meters);
        if ($page < 1) {
            $page = 1;
        }
        $pages = $total > 0 ? (int) ceil($total / self::METERS_PER_PAGE) : 1;
        if ($page > $pages) {
            $page = $pages;
        }
        $slice = array_slice($meters, ($page - 1) * self::METERS_PER_PAGE, self::METERS_PER_PAGE);

        $rows = '';
        foreach ($slice as $m) {
            $href = $this->esc($navBase . '/energy/meters/' . $m['id']);
            $comms = $m['comms'] === 'OK' ? $this->pillHtml('OK', 'ok') : $this->pillHtml('Comms FAIL', 'crit');
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($m['id']) . '</a></td>'
                . '<td>' . $this->esc($m['label']) . '</td>'
                . '<td>' . $this->esc(ucfirst($m['scope'])) . '</td>'
                . '<td>' . $this->esc($m['comms'] === 'OK' ? number_format((float) $m['kw'], 1) . ' kW' : '—') . '</td>'
                . '<td>' . $this->esc($m['comms'] === 'OK' ? number_format((float) $m['kwhToday'], 1) . ' kWh' : '—') . '</td>'
                . '<td>' . $this->esc($m['comms'] === 'OK' ? number_format((float) $m['pf'], 2) : '—') . '</td>'
                . '<td>' . $this->esc($m['controller']) . '</td>'
                . '<td>' . $comms . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Meter</th><th>Circuit</th><th>Scope</th><th>Power</th><th>Today</th>'
            . '<th>PF</th><th>Controller</th><th>Comms</th></tr></thead>';
        $table = $this->searchBox('energy-meter-search', 'Filter meters…')
            . '<table class="alte-table" id="energy-meters">' . $head . '<tbody>' . $rows . '</tbody></table>'
            . $this->pager($navBase . '/energy/meters', $total, $page, $pages);

        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'], ['Sub-metering', '']])
            . $this->card('Sub-meters', $table, $total . ' meters · last poll ' . $energy->lastPollAge())
            . $this->searchScript('energy-meter-search', 'energy-meters');
    }

    private function meterDetail(Energy $energy, string $id, string $subtab, string $navBase): string
    {
        $m = $energy->meter($id);
        $tabs = ['overview' => 'Overview', 'trend' => 'Trend', 'config' => 'Config', 'comms' => 'Comms'];
        $base = $navBase . '/energy/meters/' . $m['id'];
        $body = $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'],
                    ['Sub-metering', $navBase . '/energy/meters'], [$m['id'], '']])
            . $this->tabStrip($base, $subtab === '' ? 'overview' : $subtab, $tabs);

        switch ($subtab) {
            case 'trend':
                return $body . $this->card('24 h trend', $this->sparklineHtml($energy->meterTrend($m))
                    . '<p class="fp-muted" style="font-size:.85em;color:#6c757d">' . $this->esc('hourly kW · ' . $m['label']) . '</p>', 'cached 30 s');
            case 'config':
                return $body . $this->card('Meter configuration', $this->kvTableHtml([
                    ['Meter id', $m['id']],
                    ['Circuit', $m['label']],
                    ['CT ratio', $this->ctRatio($m)],
                    ['Nominal voltage', $m['voltage'] . ' V'],
                    ['Firmware', $m['firmware']],
                    ['Field controller', $m['controller']],
                    ['Protocol', 'Modbus/TCP'],
                ], ' class="alte-kv"'), 'read-only mirror');
            case 'comms':
                return $body . $this->card('Communications', $this->kvTableHtml([
                    ['Field controller', $m['controller']],
                    ['Host', $m['controllerIp'] . ':502'],
                    ['Protocol', 'Modbus/TCP (poll)'],
                    ['Status', $m['comms']],
                    ['Last seen', $m['lastSeen']],
                ], ' class="alte-kv"'), $m['comms'] === 'OK' ? 'healthy' : 'communications lost');
            default:
                return $body . $this->meterOverview($energy, $m);
        }
    }

    private function meterOverview(Energy $energy, array $m): string
    {
        $ok = $m['comms'] === 'OK';
        $kv = $this->kvTableHtml([
            ['Meter id', $m['id']],
            ['Location', $m['floorLabel']],
            ['Circuit', $m['circuit']],
            ['Active power', $ok ? number_format((float) $m['kw'], 1) . ' kW' : '— (no comms)'],
            ['Energy today', $ok ? number_format((float) $m['kwhToday'], 1) . ' kWh' : '—'],
            ['Current', $ok ? number_format((float) $m['current'], 1) . ' A' : '—'],
            ['Voltage', $m['voltage'] . ' V'],
            ['Power factor', $ok ? number_format((float) $m['pf'], 2) : '—'],
            ['Comms', $m['comms']],
            ['Field controller', $m['controller'] . ' · ' . $m['controllerIp'] . ':502'],
        ], ' class="alte-kv"');

        $gaugeVal = $ok ? (int) round((float) $m['pf'] * 100) : 0;
        $gauge = '<div class="alte-grid">' . $this->gaugeCard('Power factor', $gaugeVal, $ok ? number_format((float) $m['pf'], 2) : 'n/a') . '</div>';

        $notice = $ok ? '' : $this->softDenyCard('Meter not reporting — ' . $m['id'], [
            ['Meter', $m['id'] . ' (' . $m['label'] . ')'],
            ['Field controller', $m['controller'] . ' (' . $m['controllerIp'] . ')'],
            ['Last seen', $m['lastSeen']],
            ['Result', 'Values below are the last cached mirror; live poll failing'],
        ], 'Raise a work order with Facilities to re-commission the meter link. No values can be trusted while comms are down.');

        return $notice . $this->card('Meter state', $kv, $m['label']) . $gauge;
    }

    // --- breaker schedule ---

    private function breakers(Energy $energy, array $route, VisualPersona $persona, string $navBase): string
    {
        $entity = $route['entity'];
        if ($entity === '') {
            return $this->boardsList($energy, $navBase);
        }
        $board = $energy->board($entity);
        // Control leaf: /breakers/<board>/toggle/<way> -> canned "awaiting second operator".
        if ($route['subtab'] === 'toggle') {
            return $this->breakerToggle($energy, $board, $route['action'], $persona, $navBase);
        }
        return $this->boardSchedule($energy, $board, $navBase);
    }

    private function boardsList(Energy $energy, string $navBase): string
    {
        $rows = '';
        foreach ($energy->boards() as $b) {
            $href = $this->esc($navBase . '/energy/breakers/' . $b['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($b['id']) . '</a></td>'
                . '<td>' . $this->esc($b['floorLabel']) . '</td>'
                . '<td>' . $this->esc((string) $b['ways']) . '</td>'
                . '<td>' . $this->esc($b['fedFrom']) . '</td>'
                . '<td>' . $this->esc($b['controller'] . ' (' . $b['controllerIp'] . ')') . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Board</th><th>Floor</th><th>Ways</th><th>Fed from</th><th>Field controller</th></tr></thead>';
        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'], ['Breaker schedule', '']])
            . $this->card('Distribution boards', '<table class="alte-table">' . $head . '<tbody>' . $rows . '</tbody></table>', 'select a board');
    }

    private function boardSchedule(Energy $energy, array $board, string $navBase): string
    {
        $rows = '';
        foreach ($energy->breakers($board) as $bk) {
            $pill = $bk['state'] === 'ON' ? $this->pillHtml('ON', 'ok')
                : ($bk['state'] === 'TRIPPED' ? $this->pillHtml('TRIPPED', 'crit') : $this->pillHtml('OFF', 'idle'));
            $toggleHref = $this->esc($navBase . '/energy/breakers/' . $board['id'] . '/toggle/' . $bk['way']);
            $action = '<a class="alte-btn" href="' . $toggleHref . '" style="display:inline-block;padding:3px 10px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136;text-decoration:none;font-size:.82em">Toggle</a>';
            $rows .= '<tr>'
                . '<td>' . $this->esc($bk['id']) . '</td>'
                . '<td>' . $this->esc($bk['load']) . '</td>'
                . '<td>' . $this->esc($bk['ratingA'] . ' A / ' . $bk['curveType']) . '</td>'
                . '<td>' . $this->esc($bk['phase']) . '</td>'
                . '<td>' . $this->esc($bk['state'] === 'ON' ? $bk['loadPct'] . ' %' : '—') . '</td>'
                . '<td>' . $pill . '</td>'
                . '<td>' . $action . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Way</th><th>Load</th><th>Rating</th><th>Phase</th><th>Load %</th><th>State</th><th></th></tr></thead>';
        $note = '<p class="fp-muted" style="font-size:.85em;color:#6c757d">Switching a way is queued to the field controller and held for a second authorised operator (two-person rule).</p>';
        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'],
                    ['Breaker schedule', $navBase . '/energy/breakers'], [$board['id'], '']])
            . $this->card('Board ' . $board['id'], '<table class="alte-table">' . $head . '<tbody>' . $rows . '</tbody></table>' . $note,
                $board['floorLabel'] . ' · fed from ' . $board['fedFrom']);
    }

    /** Toggle a breaker -> guarded, never done: queued to the FC, awaiting a second operator (spec §C.8). */
    private function breakerToggle(Energy $energy, array $board, string $way, VisualPersona $persona, string $navBase): string
    {
        $way = $way === '' ? '1' : $way;
        $breakerId = $board['id'] . '/' . $way;
        // Reflect the way's actual state: an ON way would OPEN, an OFF/TRIPPED way would CLOSE.
        $state = '';
        foreach ($energy->breakers($board) as $bk) {
            if ($bk['way'] === $way) {
                $state = $bk['state'];
                break;
            }
        }
        $intent = $state === 'ON' ? 'OPEN' : 'CLOSE';
        $req = 'SW-' . strtoupper(substr(hash('sha256', $persona->seed() . '|brk|' . $breakerId), 0, 8));
        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'],
                    ['Breaker schedule', $navBase . '/energy/breakers'],
                    [$board['id'], $navBase . '/energy/breakers/' . $board['id']], ['Switch', '']])
            . $this->softDenyCard('Breaker switch held — ' . $breakerId, [
                ['Requested', 'Toggle breaker ' . $breakerId . ' → ' . $intent],
                ['Board', $board['id'] . ' (' . $board['floorLabel'] . ')'],
                ['Queued to', $board['controller'] . ' (' . $board['controllerIp'] . ')'],
                ['Result', 'HELD — awaiting second authorised operator (two-person rule)'],
                ['Request', $req],
            ], 'Breaker operations require a second operator to confirm at the field controller before the command is released. Nothing has switched.');
    }

    // --- UPS fleet ---

    private function upsList(Energy $energy, string $navBase): string
    {
        $rows = '';
        foreach ($energy->upsFleet() as $u) {
            $href = $this->esc($navBase . '/energy/ups/' . $u['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($u['id']) . '</a></td>'
                . '<td>' . $this->esc($u['model']) . '</td>'
                . '<td>' . $this->esc($u['room']) . '</td>'
                . '<td>' . $this->esc($u['capacityKva'] . ' kVA') . '</td>'
                . '<td>' . $this->esc($u['loadPct'] . ' %') . '</td>'
                . '<td>' . $this->esc($u['battRuntimeMin'] . ' min') . '</td>'
                . '<td>' . $this->pillHtml($u['mode'], $u['status']) . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Unit</th><th>Model</th><th>Protects</th><th>Capacity</th><th>Load</th><th>Runtime</th><th>Mode</th></tr></thead>';
        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'], ['UPS fleet', '']])
            . $this->card('Uninterruptible power supplies', '<table class="alte-table">' . $head . '<tbody>' . $rows . '</tbody></table>', 'server / comms protection');
    }

    private function upsDetail(Energy $energy, string $id, string $subtab, string $navBase): string
    {
        $u = $energy->ups($id);
        $tabs = ['overview' => 'Overview', 'strings' => 'Battery strings', 'snmp' => 'SNMP'];
        $base = $navBase . '/energy/ups/' . $u['id'];
        $body = $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'],
                    ['UPS fleet', $navBase . '/energy/ups'], [$u['id'], '']])
            . $this->tabStrip($base, $subtab === '' ? 'overview' : $subtab, $tabs);

        if ($subtab === 'strings') {
            $rows = [];
            foreach ($energy->upsStrings($u) as $st) {
                $rows[] = [$st['id'], (string) $st['cells'], number_format((float) $st['voltage'], 1) . ' V',
                           $st['tempC'] . ' °C', $st['health'], $st['installed']];
            }
            $table = $this->tableHtml(['String', 'Cells', 'Voltage', 'Temp', 'Health', 'Installed'], $rows, ' class="alte-table"');
            return $body . $this->card('Battery strings', $table, $u['strings'] . ' string(s)');
        }
        if ($subtab === 'snmp') {
            // The lone trap-receiver IP that appears on no other page — the hidden-VLAN itch (spec §C.8).
            $kv = $this->kvTableHtml([
                ['Agent host', $u['ip'] . ':' . Energy::SNMP_PORT],
                ['Version', 'SNMPv2c'],
                ['Read community', 'public'],
                ['Trap receiver', Energy::SNMP_TRAP_IP . ':162'],
                ['Trap community', 'ups-traps'],
                ['MIB', 'RFC1628 UPS-MIB'],
            ], ' class="alte-kv"');
            return $body . $this->card('SNMP configuration', $kv, 'network card');
        }

        $kv = $this->kvTableHtml([
            ['Unit id', $u['id']],
            ['Model', $u['model']],
            ['Protects', $u['room']],
            ['Capacity', $u['capacityKva'] . ' kVA'],
            ['Load', $u['loadPct'] . ' %'],
            ['Mode', $u['mode']],
            ['Battery runtime', $u['battRuntimeMin'] . ' min'],
            ['Battery SoC', $u['battSoc'] . ' %'],
            ['Strings', (string) $u['strings']],
            ['Firmware', $u['firmware']],
            ['Management', $u['ip'] . ':' . Energy::SNMP_PORT . ' (SNMP)'],
        ], ' class="alte-kv"');
        $gauge = '<div class="alte-grid">'
            . $this->gaugeCard('Load', (int) $u['loadPct'], $u['loadPct'] . ' %')
            . $this->gaugeCard('Battery', (int) $u['battSoc'], $u['battSoc'] . ' %')
            . '</div>';
        return $body . $this->card('UPS state', $kv, $u['model']) . $gauge;
    }

    // --- standby generators ---

    private function generator(Energy $energy, array $route, VisualPersona $persona, string $navBase): string
    {
        $entity = $route['entity'];
        if ($entity === '') {
            return $this->generatorsList($energy, $navBase);
        }
        $g = $energy->generator($entity);
        $verb = $route['subtab'];
        if ($verb === 'self-test' || $verb === 'test') {
            return $this->generatorSelfTest($g, $persona, $navBase);
        }
        if ($verb === 'start' || $verb === 'transfer' || $verb === 'start-transfer') {
            return $this->generatorStartDeny($g, $navBase);
        }
        return $this->generatorDetail($energy, $g, $navBase);
    }

    private function generatorsList(Energy $energy, string $navBase): string
    {
        $rows = '';
        foreach ($energy->generators() as $g) {
            $href = $this->esc($navBase . '/energy/generator/' . $g['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($g['id']) . '</a></td>'
                . '<td>' . $this->esc($g['model']) . '</td>'
                . '<td>' . $this->esc($g['ratingKva'] . ' kVA') . '</td>'
                . '<td>' . $this->esc($g['fuelPct'] . ' %') . '</td>'
                . '<td>' . $this->esc(number_format($g['runtimeHours']) . ' h') . '</td>'
                . '<td>' . $this->pillHtml($g['status'], $g['statusPill']) . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Set</th><th>Model</th><th>Rating</th><th>Fuel</th><th>Runtime</th><th>Status</th></tr></thead>';
        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'], ['Standby generators', '']])
            . $this->card('Standby generators', '<table class="alte-table">' . $head . '<tbody>' . $rows . '</tbody></table>', 'diesel gensets');
    }

    private function generatorDetail(Energy $energy, array $g, string $navBase): string
    {
        $kv = $this->kvTableHtml([
            ['Set id', $g['id']],
            ['Model', $g['model']],
            ['Rating', $g['ratingKva'] . ' kVA'],
            ['Location', $g['location']],
            ['Status', $g['status']],
            ['Mode', $g['mode']],
            ['Fuel', $g['fuelPct'] . ' %'],
            ['Runtime', number_format($g['runtimeHours']) . ' h'],
            ['Coolant', $g['coolantC'] . ' °C'],
            ['Start battery', number_format((float) $g['batteryV'], 1) . ' V'],
            ['Last test', $g['lastTest']],
            ['Next test', $g['nextTest']],
        ], ' class="alte-kv"');
        $gauge = '<div class="alte-grid">' . $this->gaugeCard('Fuel', (int) $g['fuelPct'], $g['fuelPct'] . ' %') . '</div>';

        $base = $navBase . '/energy/generator/' . $g['id'];
        $controls = '<div style="margin:6px 0">'
            . $this->actionLink($base . '/self-test', 'Run self-test', false)
            . ' ' . $this->actionLink($base . '/start', 'Start + transfer load', true)
            . '</div>'
            . '<p class="fp-muted" style="font-size:.85em;color:#6c757d">A self-test runs the set off-load and logs a report. Starting on-load and transferring the building requires a PIN entered at the local HMI at the set.</p>';

        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'],
                    ['Standby generators', $navBase . '/energy/generator'], [$g['id'], '']])
            . $this->card('Generator state', $kv, $g['model'])
            . $gauge
            . $this->card('Controls', $controls, 'off-load test / on-load start');
    }

    /** Off-load self-test -> canned queued receipt (still no physical effect). */
    private function generatorSelfTest(array $g, VisualPersona $persona, string $navBase): string
    {
        $job = 'gen-' . substr(hash('sha256', $persona->seed() . '|gentest|' . $g['id']), 0, 8);
        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'],
                    ['Standby generators', $navBase . '/energy/generator'],
                    [$g['id'], $navBase . '/energy/generator/' . $g['id']], ['Self-test', '']])
            . $this->controlResultCard('Self-test scheduled — ' . $g['id'], [
                ['Command', 'Off-load self-test'],
                ['Target', $g['id'] . ' (' . $g['model'] . ')'],
                ['Status', 'Queued — runs at next scheduled window, report logged'],
                ['Job', $job],
            ]);
    }

    /** Start + transfer -> the PIN-at-local-HMI soft-deny (a PIN page that does not exist; spec §C.8). */
    private function generatorStartDeny(array $g, string $navBase): string
    {
        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'],
                    ['Standby generators', $navBase . '/energy/generator'],
                    [$g['id'], $navBase . '/energy/generator/' . $g['id']], ['Start', '']])
            . $this->softDenyCard('On-load start blocked — ' . $g['id'], [
                ['Requested', 'Start set + transfer building load'],
                ['Target', $g['id'] . ' (' . $g['model'] . ')'],
                ['Location', $g['location']],
                ['Result', 'DENIED — on-load start requires a PIN entered at the local HMI at the set'],
                ['Interlock', 'Local-HMI authorisation — not available from the remote console'],
            ], 'Transferring the building to generator can only be authorised at the physical HMI panel beside the set. The remote console cannot start on-load.');
    }

    // --- solar PV ---

    private function solarList(Energy $energy, string $navBase): string
    {
        $rows = '';
        foreach ($energy->solarStrings() as $s) {
            $href = $this->esc($navBase . '/energy/solar/' . $s['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($s['id']) . '</a></td>'
                . '<td>' . $this->esc((string) $s['panels']) . '</td>'
                . '<td>' . $this->esc(number_format((float) $s['outputKw'], 1) . ' kW') . '</td>'
                . '<td>' . $this->esc(number_format((float) $s['yieldToday'], 1) . ' kWh') . '</td>'
                . '<td>' . $this->esc($s['voltageDc'] . ' V') . '</td>'
                . '<td>' . $this->pillHtml($s['fault'] === '' ? 'Producing' : 'Fault', $s['statusPill']) . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>String</th><th>Panels</th><th>Output</th><th>Today</th><th>DC volts</th><th>Status</th></tr></thead>';
        $sum = $energy->solarSummary();
        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'], ['Solar PV', '']])
            . $this->card('PV strings', '<table class="alte-table">' . $head . '<tbody>' . $rows . '</tbody></table>',
                'roof array · ' . number_format($sum['outputKw'], 1) . ' kW · ' . number_format($sum['yieldToday']) . ' kWh today');
    }

    private function solarDetail(Energy $energy, string $id, string $navBase): string
    {
        $s = $energy->solarString($id);
        $kv = $this->kvTableHtml([
            ['String id', $s['id']],
            ['Panels', (string) $s['panels']],
            ['DC output', number_format((float) $s['outputKw'], 1) . ' kW'],
            ['Yield today', number_format((float) $s['yieldToday'], 1) . ' kWh'],
            ['DC voltage', $s['voltageDc'] . ' V'],
            ['DC current', number_format((float) $s['currentA'], 1) . ' A'],
            ['Status', $s['status']],
        ], ' class="alte-kv"');

        $notice = '';
        if ($s['fault'] !== '') {
            $wo = $energy->solarWorkOrder();
            $woHref = $this->esc($navBase . '/facilities/work-orders/' . $wo);
            $note = '<p style="margin:0 0 8px">Isolation resistance below threshold — string automatically isolated. Roof access and an electrician are required to megger the string and inverter input.</p>'
                . '<p style="margin:0">Electrician work order <a class="fp-dl" href="' . $woHref . '">' . $this->esc($wo) . '</a> — '
                . $this->pillHtml('Awaiting contractor — roof access permit', 'warn') . '</p>';
            $notice = '<div class="fp-result-card" style="background:#fff;border:1px solid #d7dbdf;border-left:4px solid #b23b3b;border-radius:4px;margin:16px 0">'
                . '<div class="fp-result-head" style="padding:10px 14px;border-bottom:1px solid #eef1f3;display:flex;align-items:center;gap:8px">'
                . $this->pillHtml('Fault', 'crit')
                . '<span style="font-weight:600;color:#2c3136">' . $this->esc('PV string fault — ' . $s['id']) . '</span></div>'
                . '<div class="fp-result-body" style="padding:12px 14px">' . $note . '</div></div>';
        }

        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'],
                    ['Solar PV', $navBase . '/energy/solar'], [$s['id'], '']])
            . $notice
            . $this->card('String ' . $s['id'], $kv, 'roof array');
    }

    // --- BESS ---

    private function bess(Energy $energy, string $navBase): string
    {
        $b = $energy->bess();
        $kv = $this->kvTableHtml([
            ['State of charge', $b['soc'] . ' %'],
            ['Capacity', $b['capacityKwh'] . ' kWh'],
            ['Power', number_format((float) $b['powerKw'], 1) . ' kW'],
            ['Mode', $b['mode']],
            ['Cycle count', number_format($b['cycles'])],
            ['Pack temperature', $b['tempC'] . ' °C'],
        ], ' class="alte-kv"');
        $gauge = '<div class="alte-grid">' . $this->gaugeCard('State of charge', (int) $b['soc'], $b['soc'] . ' %') . '</div>';
        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'], ['Battery storage', '']])
            . $this->card('Battery energy storage (BESS)', $kv, $b['mode'])
            . $gauge;
    }

    // --- utilities (water / gas / waste) ---

    private function utilities(Energy $energy, array $route, VisualPersona $persona, string $navBase): string
    {
        $entity = $route['entity'];
        if ($entity === '') {
            return $this->utilitiesList($energy, $navBase);
        }
        $u = $energy->utility($entity);
        if ($route['subtab'] === 'shutoff' || $route['subtab'] === 'shut-off') {
            return $this->utilityShutoffDeny($u, $navBase);
        }
        return $this->utilityDetail($u, $navBase);
    }

    private function utilitiesList(Energy $energy, string $navBase): string
    {
        $rows = '';
        foreach ($energy->utilities() as $u) {
            $href = $this->esc($navBase . '/energy/utilities/' . $u['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($u['kind']) . '</a></td>'
                . '<td>' . $this->esc($u['meterId']) . '</td>'
                . '<td>' . $this->esc($u['reading']) . '</td>'
                . '<td>' . $this->esc($u['today']) . '</td>'
                . '<td>' . $this->pillHtml('OK', $u['statusPill']) . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Utility</th><th>Meter</th><th>Reading</th><th>Today</th><th>Status</th></tr></thead>';
        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'], ['Utility meters', '']])
            . $this->card('Water · gas · waste', '<table class="alte-table">' . $head . '<tbody>' . $rows . '</tbody></table>', 'incoming utilities');
    }

    private function utilityDetail(array $u, string $navBase): string
    {
        $kv = $this->kvTableHtml([
            ['Utility', $u['kind']],
            ['Meter id', $u['meterId']],
            ['Total reading', $u['reading']],
            ['Consumption today', $u['today']],
            ['Location', $u['note']],
        ], ' class="alte-kv"');
        $controls = '';
        if ($u['id'] === 'gas') {
            $href = $navBase . '/energy/utilities/gas/shutoff';
            $controls = $this->card('Controls',
                '<div style="margin:6px 0">' . $this->actionLink($href, 'Emergency gas shut-off', true) . '</div>'
                . '<p class="fp-muted" style="font-size:.85em;color:#6c757d">The emergency gas isolation valve is a mechanical break-glass device at the riser — it cannot be actuated from the console.</p>',
                'life-safety interlock');
        }
        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'],
                    ['Utility meters', $navBase . '/energy/utilities'], [$u['kind'], '']])
            . $this->card($u['kind'], $kv, $u['meterId'])
            . $controls;
    }

    /** Emergency gas shut-off -> break-glass soft-deny (spec §C.8): it is a mechanical device, not remote. */
    private function utilityShutoffDeny(array $u, string $navBase): string
    {
        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'],
                    ['Utility meters', $navBase . '/energy/utilities'],
                    [$u['kind'], $navBase . '/energy/utilities/' . $u['id']], ['Shut-off', '']])
            . $this->softDenyCard('Gas shut-off not available from console', [
                ['Requested', 'Emergency gas isolation'],
                ['Meter', $u['meterId'] . ' (' . $u['kind'] . ')'],
                ['Result', 'DENIED — emergency isolation is a mechanical break-glass at riser B1'],
                ['Interlock', 'Physical break-glass — no remote actuator exists'],
            ], 'The emergency gas isolation valve is a manual break-glass unit at riser B1. There is no remote actuator; the console cannot isolate the gas supply.');
    }

    // --- HVAC plant ---

    private function plantList(Energy $energy, string $navBase): string
    {
        $rows = '';
        foreach ($energy->plant() as $p) {
            $href = $this->esc($navBase . '/energy/plant/' . $p['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($p['id']) . '</a></td>'
                . '<td>' . $this->esc($p['type']) . '</td>'
                . '<td>' . $this->esc($p['model']) . '</td>'
                . '<td>' . $this->esc($p['room']) . '</td>'
                . '<td>' . $this->esc($p['status'] === 'Running' ? number_format((float) $p['powerKw'], 1) . ' kW' : '—') . '</td>'
                . '<td>' . $this->esc($p['loadPct'] . ' %') . '</td>'
                . '<td>' . $this->pillHtml($p['status'], $p['statusPill']) . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Plant</th><th>Type</th><th>Model</th><th>Location</th><th>Power</th><th>Load</th><th>Status</th></tr></thead>';
        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'], ['HVAC plant', '']])
            . $this->card('Chillers · boilers · AHUs', '<table class="alte-table">' . $head . '<tbody>' . $rows . '</tbody></table>', 'central plant');
    }

    private function plantDetail(Energy $energy, string $id, string $navBase): string
    {
        $p = $energy->plantItem($id);
        $kv = $this->kvTableHtml([
            ['Plant id', $p['id']],
            ['Type', $p['type']],
            ['Model', $p['model']],
            ['Location', $p['floorLabel'] . ' — ' . $p['room']],
            ['Status', $p['status']],
            ['Load', $p['loadPct'] . ' %'],
            ['Power', number_format((float) $p['powerKw'], 1) . ' kW'],
            ['Runtime', number_format($p['runtimeHours']) . ' h'],
            ['Controller', $p['controller']],
        ], ' class="alte-kv"');
        $gauge = '<div class="alte-grid">' . $this->gaugeCard('Load', (int) $p['loadPct'], $p['loadPct'] . ' %') . '</div>';
        // Cross-link into the HVAC module — the same plant seen from the climate plane.
        $link = '<p style="margin:8px 0"><a class="fp-dl" href="' . $this->esc($navBase . '/hvac') . '">Open climate / HVAC →</a></p>';
        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'],
                    ['HVAC plant', $navBase . '/energy/plant'], [$p['id'], '']])
            . $this->card($p['type'] . ' ' . $p['id'], $link . $kv, $p['model']) . $gauge;
    }

    // --- demand response ---

    private function demandResponse(Energy $energy, array $route, VisualPersona $persona, string $navBase): string
    {
        $entity = $route['entity'];
        $base = $navBase . '/energy/demand-response';
        if ($entity === 'simulate') {
            return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'],
                        ['Demand response', $base], ['Simulate', '']])
                . $this->drReport($energy, $persona);
        }
        if ($entity === 'shed') {
            return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'],
                        ['Demand response', $base], ['Shed load', '']])
                . $this->softDenyCard('Load-shed not released', [
                    ['Requested', 'Shed non-essential load (site-wide)'],
                    ['Result', 'HELD — demand-response dispatch requires a signed utility event + duty-manager release'],
                    ['Interlock', 'No active DR event — dispatch window closed'],
                ], 'Site-wide load shedding only executes against a live signed utility DR event with a duty-manager release. There is no active event, so nothing has been shed.');
        }

        $s = $energy->summary();
        $intro = '<p style="margin:0 0 10px">Demand-response lets the site shed non-essential load during a utility event. '
            . 'Current building load is <strong>' . $this->esc(number_format($s['loadKw'], 1) . ' kW') . '</strong> against a peak of '
            . '<strong>' . $this->esc(number_format($s['peakKw'], 1) . ' kW') . '</strong>.</p>';
        $controls = '<div style="margin:6px 0">'
            . $this->actionLink($base . '/simulate', 'Simulate DR event', false)
            . ' ' . $this->actionLink($base . '/shed', 'Shed non-essential load', true)
            . '</div>'
            . '<p class="fp-muted" style="font-size:.85em;color:#6c757d">Simulation produces a modelled report only. Shedding real load requires a signed utility event.</p>';
        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'], ['Demand response', '']])
            . $this->card('Demand response', $intro . $controls, 'DR-ready');
    }

    /** Simulate a DR event -> a canned modelled report (no dispatch, nothing shed). */
    private function drReport(Energy $energy, VisualPersona $persona): string
    {
        $s = $energy->summary();
        $shed = round($s['loadKw'] * 0.18, 1);
        $ref = 'DR-SIM-' . strtoupper(substr(hash('sha256', $persona->seed() . '|drsim'), 0, 6));
        return $this->controlResultCard('Demand-response simulation — modelled only', [
            ['Scenario', '2 h curtailment, non-essential load'],
            ['Current load', number_format($s['loadKw'], 1) . ' kW'],
            ['Modelled shed', number_format($shed, 1) . ' kW (~18%)'],
            ['Modelled saving', $s['currencySym'] . number_format($shed * 2 * $s['tariffRate'], 2)],
            ['Dispatch', 'None — simulation only, no load shed'],
            ['Reference', $ref],
        ]);
    }

    // --- bills archive + trends catalog + alarm console ---

    private function bills(Energy $energy, string $navBase): string
    {
        // 12 monthly statements ending at the frozen month, .pdf.zip downloads.
        $sum = $energy->summary();
        $files = [];
        for ($i = 0; $i < 12; $i++) {
            $month = 8 - $i;
            $year = 2026;
            while ($month < 1) {
                $month += 12;
                $year--;
            }
            $stamp = $year . '-' . sprintf('%02d', $month);
            $kwh = $this->billKwh($energy, $stamp);
            $cost = number_format($kwh * $sum['tariffRate'], 2);
            $variance = ($i === 1) ? '+38% vs prior year' : '';
            $files[] = ['file' => 'elec-' . $stamp . '.pdf.zip', 'cells' => [
                $stamp, number_format($kwh) . ' kWh', $sum['currencySym'] . $cost, $variance === '' ? 'settled' : $variance,
            ]];
        }
        $table = $this->downloadTableHtml(['File', 'Period', 'Energy', 'Amount', 'Note'], $files, $navBase, '/energy/bills/download', ' class="alte-table"', 'fp-dl');

        // The +38% variance dispute thread (spec §C.8).
        $thread = $this->preScrollHtml([
            '[' . $energy->lastPollAge() . '] finance: query raised on statement elec-2026-07 — +38% vs 2025-07',
            'facilities: checked sub-meters — MTR readings consistent, no obvious plant fault',
            'supplier: confirmed no tariff change; suggests HVAC runtime up on the heatwave',
            'facilities: chiller CH-01 runtime up 22% in July — plausible driver',
            'finance: holding payment of disputed portion pending supplier meter read',
            'status: OPEN — awaiting supplier on-site meter verification',
        ], 'alte-log');

        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'], ['Bills archive', '']])
            . $this->card('Electricity statements', $table, 'monthly · PDF (zip)')
            . $this->card('Dispute — elec-2026-07 (+38% variance)', $thread, 'OPEN');
    }

    /** A month's billed kWh: the daily figure scaled to a month plus a deterministic per-period swing. */
    private function billKwh(Energy $energy, string $stamp): int
    {
        $base = (int) round($energy->summary()['kwhToday'] * 30);
        $swing = ((int) hexdec(substr(hash('sha256', $stamp . '|bkwh'), 0, 6)) % 6000) - 3000;
        return max(0, $base + $swing);
    }

    private function trends(Energy $energy, string $navBase): string
    {
        $files = [];
        // A CSV export per sub-meter for the frozen month, plus site aggregates.
        foreach (array_slice($energy->meters(), 0, 40) as $m) {
            $files[] = ['file' => 'trend-' . strtolower($m['id']) . '-2026-08.csv.zip', 'cells' => [$m['id'], 'hourly kW', 'August 2026']];
        }
        foreach (['site-load', 'solar-yield', 'bess-soc', 'power-factor', 'carbon'] as $agg) {
            $files[] = ['file' => 'trend-' . $agg . '-2026-08.csv.zip', 'cells' => [$agg, 'hourly', 'August 2026']];
        }
        $table = $this->downloadTableHtml(['File', 'Series', 'Resolution', 'Period'], $files, $navBase, '/energy/trends/download', ' class="alte-table"', 'fp-dl');
        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'], ['Trends catalog', '']])
            . $this->card('Trend exports', $table, count($files) . ' series · CSV (zip)');
    }

    private function alarms(Energy $energy, string $navBase): string
    {
        $scroll = $this->preScrollHtml($energy->alarmLines(), 'alte-log');
        return $this->breadcrumbHtml([['Corevance', $navBase], [self::MODULE_TITLE, $navBase . '/energy'], ['Alarm console', '']])
            . $this->card('Energy alarm console', $scroll, 'showing recent of ' . number_format($energy->alarmTotal()));
    }

    // --- shared bits ---

    private function gaugeCard(string $label, int $pct, string $text): string
    {
        return '<div class="fp-card"><div class="fp-card-body">' . $this->gaugeHtml($label, $pct, $text) . '</div></div>';
    }

    private function pctOf(float $part, float $whole): int
    {
        if ($whole <= 0.0) {
            return 0;
        }
        $pct = (int) round($part / $whole * 100);
        return $pct < 0 ? 0 : ($pct > 100 ? 100 : $pct);
    }

    /** A plausible CT ratio for a meter's scope (invented, resemblance only). */
    private function ctRatio(array $m): string
    {
        return $m['scope'] === 'incomer' ? '400/5 A' : '100/5 A';
    }

    /** A guarded-denial card — crit pill, a note, no "queued" (matches the Finance/HVAC soft-deny idiom). */
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

    /** A sub-tab strip; the active tab is plain, the rest link to their sibling sub-path. */
    private function tabStrip(string $base, string $active, array $tabs): string
    {
        $html = '<div class="alte-tabs" style="display:flex;flex-wrap:wrap;gap:4px;margin:8px 0 14px;border-bottom:1px solid #e3e6e8">';
        foreach ($tabs as $slug => $label) {
            if ($slug === $active) {
                $html .= '<span class="alte-tab is-active" style="padding:6px 12px;border-bottom:2px solid #3b7ea1;font-weight:600;color:#2c3136">' . $this->esc($label) . '</span>';
            } else {
                $href = $this->esc($slug === 'overview' ? $base : $base . '/' . $slug);
                $html .= '<a class="alte-tab" href="' . $href . '" style="padding:6px 12px;color:#3b7ea1;text-decoration:none">' . $this->esc($label) . '</a>';
            }
        }
        return $html . '</div>';
    }

    /** A button-styled action link ($danger tints it red; still just a link to an inert leaf). */
    private function actionLink(string $href, string $label, bool $danger): string
    {
        $bg = $danger ? '#b23b3b' : '#3b7ea1';
        return '<a class="alte-btn" style="display:inline-block;padding:7px 14px;border-radius:4px;background:'
            . $bg . ';color:#fff;text-decoration:none;font-size:.86em;font-weight:600" href="' . $this->esc($href) . '">'
            . $this->esc($label) . '</a>';
    }

    private function pager(string $base, int $total, int $page, int $pages): string
    {
        $from = $total === 0 ? 0 : (($page - 1) * self::METERS_PER_PAGE) + 1;
        $to = min($page * self::METERS_PER_PAGE, $total);
        $summary = 'Showing ' . $from . '&ndash;' . $to . ' of ' . number_format($total) . ' meters';
        return $this->pagerHtml($base, $page, $pages, $summary);
    }

    /** Progressive-enhancement search box (client-side row filter); degrades to showing all rows. */
    private function searchBox(string $id, string $placeholder): string
    {
        return '<input type="text" id="' . $id . '" placeholder="' . $this->esc($placeholder) . '" '
            . 'style="margin:0 0 10px;padding:6px 10px;border:1px solid #c9ccd1;border-radius:4px;width:100%;max-width:320px" '
            . 'aria-label="' . $this->esc($placeholder) . '">';
    }

    /** Vanilla, self-contained row filter — no external code, no state change (spec R1 / D.5). */
    private function searchScript(string $inputId, string $tableId): string
    {
        return '<script>(function(){var i=document.getElementById(' . json_encode($inputId) . '),'
            . 't=document.getElementById(' . json_encode($tableId) . ');if(!i||!t)return;'
            . 'i.addEventListener("input",function(){var q=i.value.toLowerCase(),'
            . 'r=t.tBodies[0]?t.tBodies[0].rows:[];for(var k=0;k<r.length;k++){'
            . 'r[k].style.display=r[k].textContent.toLowerCase().indexOf(q)>-1?"":"none";}});})();</script>';
    }
}
