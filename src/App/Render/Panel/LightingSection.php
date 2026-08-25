<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Lighting;
use Funnypot\Core\Support\VisualPersona;

/**
 * Lighting & Covers (spec §C.2 light/scene/cover): the building's lighting plane rendered off
 * Fake\Lighting (which itself sits on Fake\Building, so every luminaire group and roller blind lives in
 * a real room on a real floor+zone and is driven by a real BMS controller). This is the "turn the
 * lights on/off in the building" surface — every control is an <a>/leaf that only ever queues.
 *
 * The route ladder for this module (positional slots: section / entity / subtab / action):
 *   /<mount>/lighting                          landing — summary tiles + group list + scenes + covers card
 *   /<mount>/lighting/<groupId>                group detail — gauges, 24h trend, sub-tabs, controls
 *   /<mount>/lighting/<groupId>/<subtab>       schedule / history / energy / wiring sub-tab
 *   /<mount>/lighting/<groupId>/<verb>/<arg>   control leaf -> receipt ("N fixtures queued")
 *   /<mount>/lighting/scenes                   scene catalogue (all-on / all-off / evening / presentation…)
 *   /<mount>/lighting/scenes/apply/<sceneId>   scene apply leaf -> receipt
 *   /<mount>/lighting/covers                   blinds/shades list (paginated pN, JS search)
 *   /<mount>/lighting/covers/<coverId>         cover detail — position bar + open/close/stop/position
 *   /<mount>/lighting/covers/<coverId>/<v>/<n> cover control leaf -> receipt
 *   /<mount>/lighting/master/<on|off>          master "all building lights" -> canned queued confirmation
 *
 * Everything stays INERT and DETERMINISTIC per seed; a control never changes state.
 */
final class LightingSection extends AbstractPanelSection
{
    /** Rows per landing / list page. */
    private const PER_PAGE = 25;

    /** Group-detail sub-tabs (entity slot values that render a view, not a control). */
    private const SUBTABS = ['overview', 'schedule', 'history', 'energy', 'wiring'];

    /** Group control verbs (entity slot; the subtab slot carries the arg — resolve to a receipt). */
    private const ACTIONS = ['bright', 'cct', 'scene', 'power', 'floor'];

    /** Cover control verbs (subtab slot; the action slot carries the arg). */
    private const COVER_ACTIONS = ['open', 'close', 'stop', 'pos', 'tilt'];

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $lx = Lighting::fromSeed($persona->seed());
        $section = $route['section'];

        if ($section === '') {
            return $this->landing($lx, (int) $route['page'], $navBase);
        }
        if ($section === 'scenes') {
            return $this->scenesArea($lx, $route, $persona, $navBase);
        }
        if ($section === 'covers') {
            return $this->coversArea($lx, $route, $persona, $navBase);
        }
        if ($section === 'master') {
            return $this->masterControl($lx, $route['entity'], $persona, $navBase);
        }

        // A luminaire group: section is its id.
        $entity = $route['entity'];
        if (in_array($entity, self::ACTIONS, true)) {
            return $this->groupControlLeaf($lx, $section, $entity, $route['subtab'], $persona, $navBase);
        }
        $subtab = in_array($entity, self::SUBTABS, true) ? $entity : 'overview';
        return $this->groupDetail($lx, $section, $subtab, $navBase);
    }

    // --- landing: summary + group list + scenes card + covers card ---

    private function landing(Lighting $lx, int $page, string $navBase): string
    {
        $s = $lx->summary();
        $tiles = $this->statCardsHtml([
            ['label' => 'Luminaire groups', 'value' => (string) $s['groups'], 'sub' => 'across the site'],
            ['label' => 'On', 'value' => (string) $s['on'], 'sub' => 'illuminated now'],
            ['label' => 'Off', 'value' => (string) $s['off']],
            ['label' => 'Fault', 'value' => (string) $s['fault'], 'sub' => $s['fault'] === 0 ? 'all healthy' : 'lamp / driver'],
            ['label' => 'Lighting load', 'value' => number_format($s['kw'], 1) . ' kW', 'sub' => 'live estimate'],
            ['label' => 'Blinds & shades', 'value' => (string) $s['covers'], 'sub' => $s['coversOpen'] . ' open'],
            ['label' => 'Scenes', 'value' => (string) $s['scenes'], 'sub' => 'building-wide'],
            ['label' => 'BMS controllers', 'value' => (string) $s['controllers'], 'sub' => 'DALI/KNX gateway'],
        ], 'fp-tiles', 'fp-tile');

        $groups = $lx->groups();
        $total = count($groups);
        [$page, $pages, $slice] = $this->paginate($groups, $page);

        $rows = '';
        foreach ($slice as $g) {
            $href = $this->esc($navBase . '/lighting/' . $g['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($g['name']) . '</a>'
                . '<div style="font-size:.82em;color:#9aa1a8">' . $this->esc($g['haEntity']) . '</div></td>'
                . '<td>' . $this->esc($g['floorLabel'] . ' · ' . $g['zone']) . '</td>'
                . '<td>' . $this->statePill($g['state']) . '</td>'
                . '<td>' . $this->esc($g['state'] === 'off' ? '—' : $g['brightnessPct'] . '%') . '</td>'
                . '<td>' . $this->esc($g['colorTempK'] . ' K') . '</td>'
                . '<td>' . $this->esc(ucfirst((string) $g['scene'])) . '</td>'
                . '<td>' . $this->esc($g['wattage'] . ' W') . '</td>'
                . '<td>' . $this->esc($g['occupancyLinked'] ? 'linked' : 'manual') . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Group</th><th>Location</th><th>State</th><th>Bright</th><th>CCT</th>'
            . '<th>Scene</th><th>Power</th><th>Occupancy</th></tr></thead>';
        $table = $this->searchBox()
            . '<table class="alte-table" id="lgt-groups">' . $head . '<tbody>' . $rows . '</tbody></table>'
            . $this->pager($navBase . '/lighting', $total, $page, $pages, 'groups');

        $body = $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Lighting & Covers'))
            . $tiles
            . $this->masterCard($navBase)
            . $this->card('Luminaire groups', $table, $total . ' groups · last DALI poll ' . $lx->lastPollAge())
            . $this->scenesCard($lx, $navBase)
            . $this->coversCard($lx, $navBase);

        return $body . $this->searchScript();
    }

    /** The master "all building lights" lever — a link to a canned, inert confirmation leaf. */
    private function masterCard(string $navBase): string
    {
        $on = $this->esc($navBase . '/lighting/master/on');
        $off = $this->esc($navBase . '/lighting/master/off');
        $inner = '<p style="margin:0 0 10px">Apply to <strong>every controllable luminaire in the building</strong> '
            . 'in one action. Changes queue to each BMS controller and apply at the next DALI poll.</p>'
            . '<div style="display:flex;gap:10px;flex-wrap:wrap">'
            . '<a class="alte-btn" href="' . $on . '" style="text-decoration:none;padding:6px 16px;border:1px solid #2e8b57;border-radius:4px;color:#2e8b57;font-weight:600">All lights ON</a>'
            . '<a class="alte-btn" href="' . $off . '" style="text-decoration:none;padding:6px 16px;border:1px solid #b23b3b;border-radius:4px;color:#b23b3b;font-weight:600">All lights OFF</a>'
            . '</div>';
        return $this->card('Master control — whole building', $inner, 'broadcast');
    }

    private function scenesCard(Lighting $lx, string $navBase): string
    {
        $rows = '';
        foreach ($lx->scenes() as $sc) {
            $href = $this->esc($navBase . '/lighting/scenes/apply/' . $sc['id']);
            $rows .= '<tr>'
                . '<td>' . $this->esc($sc['name']) . '</td>'
                . '<td>' . $this->esc($sc['desc']) . '</td>'
                . '<td>' . $this->esc($sc['members'] . ' groups') . '</td>'
                . '<td><a class="fp-dl" href="' . $href . '">Apply</a></td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Scene</th><th>Effect</th><th>Members</th><th></th></tr></thead>';
        $all = $this->esc($navBase . '/lighting/scenes');
        $table = '<table class="alte-table">' . $head . '<tbody>' . $rows . '</tbody></table>'
            . '<p style="margin:10px 0 0"><a class="fp-dl" href="' . $all . '">All scenes &amp; details &rarr;</a></p>';
        return $this->card('Scenes', $table, 'building-wide · inert until poll');
    }

    private function coversCard(Lighting $lx, string $navBase): string
    {
        $covers = $lx->covers();
        $access = [];
        foreach ($covers as $c) {
            if ($c['access']) {
                $access[] = $c;
            }
        }
        $rows = '';
        foreach ($access as $c) {
            $href = $this->esc($navBase . '/lighting/covers/' . $c['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($c['name']) . '</a></td>'
                . '<td>' . $this->esc(ucfirst((string) $c['type'])) . '</td>'
                . '<td>' . $this->esc($c['position'] . '% open') . '</td>'
                . '<td>' . $this->coverStatePill($c['state']) . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Cover</th><th>Type</th><th>Position</th><th>State</th></tr></thead>';
        $all = $this->esc($navBase . '/lighting/covers');
        $table = '<table class="alte-table">' . $head . '<tbody>' . $rows . '</tbody></table>'
            . '<p style="margin:10px 0 0"><a class="fp-dl" href="' . $all . '">All blinds &amp; shades ('
            . count($covers) . ') &rarr;</a></p>';
        return $this->card('Perimeter & access covers', $table, 'loading dock · barriers · skylights');
    }

    // --- group detail ---

    private function groupDetail(Lighting $lx, string $groupId, string $subtab, string $navBase): string
    {
        $g = $lx->group($groupId);
        $crumbs = [['Corevance', $navBase], ['Lighting & Covers', $navBase . '/lighting'], [$g['name'], '']];
        $body = $this->breadcrumbHtml($crumbs)
            . $this->tabStrip($navBase . '/lighting/' . $groupId, $subtab, self::SUBTABS);

        switch ($subtab) {
            case 'schedule':
                return $body . $this->scheduleCard($g);
            case 'history':
                return $body . $this->historyCard($lx, $g);
            case 'energy':
                return $body . $this->energyCard($g);
            case 'wiring':
                return $body . $this->wiringCard($g, $navBase);
            default:
                return $body . $this->groupOverview($g, $navBase);
        }
    }

    private function groupOverview(array $g, string $navBase): string
    {
        $notice = $g['special'] !== '' ? $this->specialNotice($g) : '';

        $kv = $this->kvTableHtml([
            ['Entity', $g['haEntity']],
            ['Location', $g['floorLabel'] . ' — ' . $g['roomName'] . ' (' . $g['zone'] . ')'],
            ['Room type', $g['roomType']],
            ['State', ucfirst((string) $g['state'])],
            ['Brightness', $g['state'] === 'off' ? 'off' : $g['brightnessPct'] . ' % (' . $g['brightnessRaw'] . '/255)'],
            ['Colour temperature', $g['colorTempK'] . ' K'],
            ['Effect', $g['effect']],
            ['Scene', ucfirst((string) $g['scene'])],
            ['Fixtures', (string) $g['fixtures']],
            ['Load', $g['wattage'] . ' W'],
            ['Occupancy-linked', $g['occupancyLinked'] ? 'yes' : 'no'],
            ['Daylight harvest', $g['daylightHarvest'] ? 'yes' : 'no'],
            ['Lamp hours', number_format((int) $g['lampUsed']) . ' / ' . number_format((int) $g['lampRated'])],
            ['Bus', $g['busType'] . ' · ' . $g['busAddress']],
            ['Controller', $g['controller'] . ' · bacnet://' . $g['controllerIp'] . ':' . Lighting::BACNET_PORT],
            ['Last changed', $g['lastChanged']],
        ], ' class="alte-kv"');

        $lampPct = (int) round((int) $g['lampUsed'] / max(1, (int) $g['lampRated']) * 100);
        $gauges = '<div class="alte-grid">'
            . '<div class="fp-card"><div class="fp-card-body">' . $this->gaugeHtml('Brightness', (int) $g['brightnessPct'], $g['brightnessPct'] . ' %') . '</div></div>'
            . '<div class="fp-card"><div class="fp-card-body">' . $this->gaugeHtml('Lamp life used', $lampPct, number_format((int) $g['lampUsed']) . ' h') . '</div></div>'
            . '</div>';

        return $notice
            . $gauges
            . $this->card('Group state', $kv, $g['name'])
            . $this->controls($g, $navBase);
    }

    /** The control block — every control is an <a> to a leaf, never a state change. */
    private function controls(array $g, string $navBase): string
    {
        $base = $navBase . '/lighting/' . $g['id'];

        // Brightness slider: a visual fill bar + stepped preset links.
        $bright = (int) $g['brightnessPct'];
        $down = $this->esc($base . '/bright/' . max(0, $bright - 10));
        $up = $this->esc($base . '/bright/' . min(100, $bright + 10));
        $slider = '<div style="display:flex;align-items:center;gap:12px;margin:6px 0">'
            . '<a class="alte-btn" href="' . $down . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">−</a>'
            . $this->fillBar($bright, '#c07a1a')
            . '<a class="alte-btn" href="' . $up . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">+</a>'
            . '</div>';
        $presets = '';
        foreach ([0, 25, 50, 75, 100] as $p) {
            $href = $this->esc($base . '/bright/' . $p);
            $presets .= '<a class="alte-btn" href="' . $href . '" style="text-decoration:none;padding:3px 10px;margin-right:6px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136;font-size:.85em">' . $p . '%</a>';
        }

        // CCT presets.
        $cct = '';
        foreach ([2700, 3000, 4000, 5000, 6500] as $k) {
            $href = $this->esc($base . '/cct/' . $k);
            $cct .= '<a class="alte-btn" href="' . $href . '" style="text-decoration:none;padding:3px 10px;margin-right:6px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136;font-size:.85em">' . $k . ' K</a>';
        }

        // Power + scene + apply-to-floor.
        $powerOn = $this->esc($base . '/power/on');
        $powerOff = $this->esc($base . '/power/off');
        $power = '<a class="alte-btn" href="' . $powerOn . '" style="text-decoration:none;padding:4px 14px;margin-right:6px;border:1px solid #2e8b57;border-radius:4px;color:#2e8b57;font-weight:600">On</a>'
            . '<a class="alte-btn" href="' . $powerOff . '" style="text-decoration:none;padding:4px 14px;border:1px solid #b23b3b;border-radius:4px;color:#b23b3b;font-weight:600">Off</a>';

        $scenes = '';
        foreach (['work', 'evening', 'presentation', 'cleaning', 'away'] as $sc) {
            $href = $this->esc($base . '/scene/' . $sc);
            $scenes .= '<a class="alte-btn" href="' . $href . '" style="text-decoration:none;padding:3px 10px;margin-right:6px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136;font-size:.85em">' . $this->esc(ucfirst($sc)) . '</a>';
        }

        $floorHref = $this->esc($base . '/floor/apply');
        $floorLink = '<a class="alte-btn" href="' . $floorHref . '" style="text-decoration:none;padding:4px 14px;border:1px solid #3b7ea1;border-radius:4px">Apply to whole floor ('
            . $this->esc((string) $g['floorLabel']) . ')</a>';

        $swatches = '';
        if ($g['rgbCapable']) {
            $swatches = '<div style="margin-bottom:10px"><strong>Colour</strong><div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap">'
                . $this->rgbSwatches($g, $base) . '</div></div>';
        }

        $note = '<p class="fp-muted" style="font-size:.85em;color:#6c757d">Changes queue to the BMS gateway and apply at the next DALI/KNX poll (~10 s). Nothing is written until then.</p>';

        $inner = '<div style="margin-bottom:10px"><strong>Brightness</strong>' . $slider
            . '<div style="margin-top:6px">' . $presets . '</div></div>'
            . '<div style="margin-bottom:10px"><strong>Colour temperature</strong><div style="margin-top:6px">' . $cct . '</div></div>'
            . $swatches
            . '<div style="margin-bottom:10px"><strong>Power</strong><div style="margin-top:6px">' . $power . '</div></div>'
            . '<div style="margin-bottom:10px"><strong>Scene</strong><div style="margin-top:6px">' . $scenes . '</div></div>'
            . '<div style="margin-bottom:6px"><strong>Group</strong><div style="margin-top:6px">' . $floorLink . '</div></div>'
            . $note;
        return $this->card('Controls', $inner, $g['fixtures'] . ' fixtures');
    }

    /** RGB preset swatches for a tunable group — each an <a> to an inert scene leaf. */
    private function rgbSwatches(array $g, string $base): string
    {
        $out = '';
        // The group's current colour, then a fixed palette of tasteful literals.
        $palette = [(string) $g['rgbHex'], '#f2d9a6', '#ffffff', '#a9c9e8', '#e8b6b6', '#bfe3c2'];
        foreach ($palette as $i => $hex) {
            // Only [0-9a-f#] reaches the style; the href arg is a fixed slug, never the raw hex.
            $safe = preg_match('/^#[0-9a-f]{6}$/i', $hex) === 1 ? $hex : '#cccccc';
            $href = $this->esc($base . '/scene/color-' . $i);
            $out .= '<a href="' . $href . '" title="Apply colour" style="display:inline-block;width:26px;height:26px;border-radius:4px;border:1px solid #c9ccd1;background:' . $safe . '"></a>';
        }
        return $out;
    }

    private function specialNotice(array $g): string
    {
        if ($g['special'] === 'uv') {
            $title = 'UV-C germicidal circuit';
            $detail = 'Interlocked to room-vacancy + door-closed. Energises only under a maintenance work order; the '
                . 'panel keeps it disabled while the space is occupied.';
        } else {
            $title = 'Datacenter row lighting';
            $detail = 'This circuit serves a server/comms room. It is on the critical panel; changes are logged and '
                . 'queue behind the BMS interlock like every other group.';
        }
        return '<div class="fp-result-card" style="background:#fff;border:1px solid #d7dbdf;border-left:4px solid #c07a1a;border-radius:4px;margin:16px 0">'
            . '<div class="fp-result-head" style="padding:10px 14px;border-bottom:1px solid #eef1f3;display:flex;align-items:center;gap:8px">'
            . $this->pillHtml('Restricted', 'warn')
            . '<span style="font-weight:600;color:#2c3136">' . $this->esc($title) . '</span></div>'
            . '<div class="fp-result-body" style="padding:12px 14px"><p style="margin:0">' . $this->esc($detail) . '</p></div></div>';
    }

    private function scheduleCard(array $g): string
    {
        $days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
        $rows = [];
        foreach ($days as $d) {
            $weekend = ($d === 'Sat' || $d === 'Sun');
            $on = $weekend ? '— (occupancy only)' : '07:30';
            $off = $weekend ? '—' : '19:30';
            $level = $weekend ? 'Occupancy' : $g['brightnessPct'] . '%';
            $rows[] = [$d, $on, $off, $level];
        }
        $table = $this->tableHtml(['Day', 'On', 'Off', 'Level'], $rows, ' class="alte-table"');
        return $this->card('Schedule', $table, 'weekly · applied by BMS');
    }

    private function historyCard(Lighting $lx, array $g): string
    {
        $spark = $this->sparklineHtml($lx->brightnessTrend($g));
        $lines = [
            $g['lastChanged'] . '  scene "' . $g['scene'] . '" recalled (' . $g['brightnessPct'] . '%)',
            'earlier      occupancy ' . ($g['occupancyLinked'] ? 'hold released' : 'manual set'),
            'earlier      daylight harvest ' . ($g['daylightHarvest'] ? 'trimmed to ' . $g['brightnessPct'] . '%' : 'disabled'),
            'earlier      power-on soft-start ramp 0→' . $g['brightnessPct'] . '% over 2 s',
        ];
        return $this->card('History', $spark . $this->preScrollHtml($lines, 'alte-log'), '24 h · cached 30 s');
    }

    private function energyCard(array $g): string
    {
        $watt = (int) $g['wattage'];
        $daily = round($watt * 11 / 1000, 2);       // ~11 illuminated hours
        $monthly = round($daily * 30, 1);
        $kv = $this->kvTableHtml([
            ['Instant load', $watt . ' W'],
            ['Fixtures', (string) $g['fixtures']],
            ['Est. daily energy', number_format($daily, 2) . ' kWh'],
            ['Est. monthly energy', number_format($monthly, 1) . ' kWh'],
            ['Daylight harvest', $g['daylightHarvest'] ? 'active' : 'off'],
        ], ' class="alte-kv"');
        return $this->card('Energy', $kv, 'estimate · not billed');
    }

    private function wiringCard(array $g, string $navBase): string
    {
        $kv = $this->kvTableHtml([
            ['Bus', $g['busType']],
            ['Address', $g['busAddress']],
            ['Controller', $g['controller']],
            ['Gateway', 'bacnet://' . $g['controllerIp'] . ':' . Lighting::BACNET_PORT],
            ['Fixtures', (string) $g['fixtures']],
            ['Lamp hours', number_format((int) $g['lampUsed']) . ' / ' . number_format((int) $g['lampRated'])],
            ['Commissioned', \Funnypot\App\Render\Fake\FrozenClock::ymdFromDays(
                \Funnypot\App\Render\Fake\FrozenClock::nowDays()
                - (500 + ((int) hexdec(substr(hash('sha256', 'lgt-comm|' . $g['id']), 0, 8))) % 2400)
            )],
        ], ' class="alte-kv"');
        $ctrlHref = $this->esc($navBase . '/hvac');
        $link = '<p style="margin:8px 0">Shares the BMS gateway with '
            . '<a class="fp-dl" href="' . $ctrlHref . '">Climate / HVAC</a> on the same 10.0.50.x fabric.</p>';
        return $this->card('Wiring', $link . $kv, $g['busType'] . ' · read-only mirror');
    }

    // --- group control leaf (INERT receipt) ---

    private function groupControlLeaf(Lighting $lx, string $groupId, string $action, string $arg, VisualPersona $persona, string $navBase): string
    {
        $g = $lx->group($groupId);
        $crumbs = [['Corevance', $navBase], ['Lighting & Covers', $navBase . '/lighting'],
                   [$g['name'], $navBase . '/lighting/' . $groupId], ['Command', '']];

        // "Apply to whole floor" fans out across every group on this floor.
        $scope = $action === 'floor'
            ? $this->floorFixtures($lx, (string) $g['floor'])
            : (int) $g['fixtures'];
        $target = $action === 'floor'
            ? 'All groups on ' . $g['floorLabel']
            : $g['name'] . ' (' . $g['id'] . ')';

        $job = 'cmd-' . substr(hash('sha256', $persona->seed() . '|lgtcmd|' . $groupId . '|' . $action . '|' . $arg), 0, 8);
        return $this->breadcrumbHtml($crumbs) . $this->controlResultCard(
            $this->actionTitle($action) . ' — ' . ($action === 'floor' ? $g['floorLabel'] : $g['roomName']),
            [
                ['Command', $this->actionLabel($action, $arg)],
                ['Target', $target],
                ['Fixtures', number_format($scope) . ' queued'],
                ['Controller', 'bacnet://' . $g['controllerIp'] . ':' . Lighting::BACNET_PORT . ' (' . $g['controller'] . ')'],
                ['Status', 'Queued — applies at next DALI poll (~10 s)'],
                ['Job', $job],
            ]
        );
    }

    private function floorFixtures(Lighting $lx, string $floorCode): int
    {
        $n = 0;
        foreach ($lx->groups() as $g) {
            if ((string) $g['floor'] === $floorCode) {
                $n += (int) $g['fixtures'];
            }
        }
        return $n;
    }

    private function actionTitle(string $action): string
    {
        switch ($action) {
            case 'cct':
                return 'Colour-temperature change queued';
            case 'scene':
                return 'Scene recall queued';
            case 'power':
                return 'Power change queued';
            case 'floor':
                return 'Floor apply queued';
            default:
                return 'Brightness change queued';
        }
    }

    private function actionLabel(string $action, string $arg): string
    {
        switch ($action) {
            case 'bright':
                return 'Brightness → ' . $arg . ' %';
            case 'cct':
                return 'Colour temperature → ' . $arg . ' K';
            case 'scene':
                return 'Scene → ' . $arg;
            case 'power':
                return 'Power → ' . $arg;
            case 'floor':
                return 'Apply current settings to whole floor';
            default:
                return $action . ' → ' . $arg;
        }
    }

    // --- scenes area ---

    private function scenesArea(Lighting $lx, array $route, VisualPersona $persona, string $navBase): string
    {
        // /lighting/scenes/apply/<sceneId>
        if ($route['entity'] === 'apply') {
            $sc = $lx->scene($route['subtab']);
            $crumbs = [['Corevance', $navBase], ['Lighting & Covers', $navBase . '/lighting'],
                       ['Scenes', $navBase . '/lighting/scenes'], ['Apply', '']];
            $job = 'scn-' . substr(hash('sha256', $persona->seed() . '|scnapply|' . $sc['id']), 0, 8);
            return $this->breadcrumbHtml($crumbs) . $this->controlResultCard('Scene applied — ' . $sc['name'], [
                ['Scene', $sc['name']],
                ['Effect', $sc['desc']],
                ['Groups', number_format((int) $sc['members']) . ' queued'],
                ['Status', 'Queued — applies at next DALI poll (~10 s)'],
                ['Job', $job],
            ]);
        }

        $rows = '';
        foreach ($lx->scenes() as $sc) {
            $href = $this->esc($navBase . '/lighting/scenes/apply/' . $sc['id']);
            $rows .= '<tr>'
                . '<td>' . $this->esc($sc['name']) . '</td>'
                . '<td>' . $this->esc($sc['desc']) . '</td>'
                . '<td>' . $this->esc(number_format((int) $sc['members']) . ' groups') . '</td>'
                . '<td><a class="fp-dl" href="' . $href . '">Apply</a></td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Scene</th><th>Effect</th><th>Members</th><th></th></tr></thead>';
        $crumbs = [['Corevance', $navBase], ['Lighting & Covers', $navBase . '/lighting'], ['Scenes', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Scenes', '<table class="alte-table">' . $head . '<tbody>' . $rows . '</tbody></table>',
                'building-wide · inert until poll');
    }

    // --- covers area ---

    private function coversArea(Lighting $lx, array $route, VisualPersona $persona, string $navBase): string
    {
        $entity = $route['entity'];
        if ($entity === '') {
            return $this->coversList($lx, (int) $route['page'], $navBase);
        }
        $subtab = $route['subtab'];
        if (in_array($subtab, self::COVER_ACTIONS, true)) {
            return $this->coverControlLeaf($lx, $entity, $subtab, $route['action'], $persona, $navBase);
        }
        return $this->coverDetail($lx, $entity, $navBase);
    }

    private function coversList(Lighting $lx, int $page, string $navBase): string
    {
        $covers = $lx->covers();
        $total = count($covers);
        [$page, $pages, $slice] = $this->paginate($covers, $page);

        $rows = '';
        foreach ($slice as $c) {
            $href = $this->esc($navBase . '/lighting/covers/' . $c['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($c['name']) . '</a></td>'
                . '<td>' . $this->esc(ucfirst((string) $c['type'])) . '</td>'
                . '<td>' . $this->esc($c['floorLabel'] . ' · ' . $c['zone']) . '</td>'
                . '<td>' . $this->esc($c['position'] . '%') . '</td>'
                . '<td>' . $this->coverStatePill($c['state']) . '</td>'
                . '<td>' . $this->esc($c['battery'] . '%') . '</td>'
                . '<td>' . ($c['windLockout'] ? $this->pillHtml('wind lockout', 'warn') : $this->esc('—')) . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Cover</th><th>Type</th><th>Location</th><th>Position</th><th>State</th>'
            . '<th>Battery</th><th>Interlock</th></tr></thead>';
        $table = $this->searchBox()
            . '<table class="alte-table" id="lgt-groups">' . $head . '<tbody>' . $rows . '</tbody></table>'
            . $this->pager($navBase . '/lighting/covers', $total, $page, $pages, 'covers');
        $crumbs = [['Corevance', $navBase], ['Lighting & Covers', $navBase . '/lighting'], ['Blinds & shades', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Blinds & shades', $table, $total . ' covers')
            . $this->searchScript();
    }

    private function coverDetail(Lighting $lx, string $coverId, string $navBase): string
    {
        $c = $lx->cover($coverId);
        $crumbs = [['Corevance', $navBase], ['Lighting & Covers', $navBase . '/lighting'],
                   ['Blinds & shades', $navBase . '/lighting/covers'], [$c['name'], '']];

        $kvPairs = [
            ['Entity', $c['haEntity']],
            ['Type', ucfirst((string) $c['type'])],
            ['Location', $c['floorLabel'] . ($c['roomName'] !== '' ? ' — ' . $c['roomName'] : '') . ' (' . $c['zone'] . ')'],
            ['Position', $c['position'] . ' % open'],
            ['State', ucfirst((string) $c['state'])],
        ];
        if ((int) $c['tilt'] >= 0) {
            $kvPairs[] = ['Tilt', $c['tilt'] . ' %'];
        }
        $kvPairs[] = ['Wind lockout', $c['windLockout'] ? 'ACTIVE — movement inhibited' : 'clear'];
        $kvPairs[] = ['Battery', $c['battery'] . ' %'];
        $kv = $this->kvTableHtml($kvPairs, ' class="alte-kv"');

        $bar = '<div class="fp-card"><div class="fp-card-body">'
            . '<div style="font-size:.72em;color:#9aa1a8;text-transform:uppercase;letter-spacing:.04em;margin-bottom:6px">Position</div>'
            . $this->fillBar((int) $c['position'], '#3b7ea1')
            . '</div></div>';

        $body = $this->breadcrumbHtml($crumbs)
            . '<div class="alte-grid">' . $bar . '</div>'
            . $this->card('Cover state', $kv, $c['name'])
            . $this->coverControls($c, $navBase);
        return $body;
    }

    private function coverControls(array $c, string $navBase): string
    {
        $base = $navBase . '/lighting/covers/' . $c['id'];
        $open = $this->esc($base . '/open/100');
        $close = $this->esc($base . '/close/0');
        $stop = $this->esc($base . '/stop/x');
        $buttons = '<a class="alte-btn" href="' . $open . '" style="text-decoration:none;padding:4px 16px;margin-right:6px;border:1px solid #2e8b57;border-radius:4px;color:#2e8b57;font-weight:600">Open</a>'
            . '<a class="alte-btn" href="' . $close . '" style="text-decoration:none;padding:4px 16px;margin-right:6px;border:1px solid #b23b3b;border-radius:4px;color:#b23b3b;font-weight:600">Close</a>'
            . '<a class="alte-btn" href="' . $stop . '" style="text-decoration:none;padding:4px 16px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">Stop</a>';

        $pos = (int) $c['position'];
        $down = $this->esc($base . '/pos/' . max(0, $pos - 10));
        $up = $this->esc($base . '/pos/' . min(100, $pos + 10));
        $slider = '<div style="display:flex;align-items:center;gap:12px;margin:6px 0">'
            . '<a class="alte-btn" href="' . $down . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">−</a>'
            . $this->fillBar($pos, '#3b7ea1')
            . '<a class="alte-btn" href="' . $up . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">+</a>'
            . '</div>';

        $tilt = '';
        if ((int) $c['tilt'] >= 0) {
            $t = (int) $c['tilt'];
            $tdown = $this->esc($base . '/tilt/' . max(0, $t - 15));
            $tup = $this->esc($base . '/tilt/' . min(100, $t + 15));
            $tilt = '<div style="margin-bottom:10px"><strong>Tilt</strong>'
                . '<div style="display:flex;align-items:center;gap:12px;margin:6px 0">'
                . '<a class="alte-btn" href="' . $tdown . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">−</a>'
                . $this->fillBar($t, '#c07a1a')
                . '<a class="alte-btn" href="' . $tup . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">+</a>'
                . '</div></div>';
        }

        $note = $c['windLockout']
            ? '<p class="fp-muted" style="font-size:.85em;color:#c07a1a">Wind lockout active — commands queue but movement is inhibited until the anemometer clears.</p>'
            : '<p class="fp-muted" style="font-size:.85em;color:#6c757d">Commands queue to the BMS controller and apply at the next poll.</p>';

        $inner = '<div style="margin-bottom:10px"><strong>Movement</strong><div style="margin-top:6px">' . $buttons . '</div></div>'
            . '<div style="margin-bottom:10px"><strong>Position</strong>' . $slider . '</div>'
            . $tilt
            . $note;
        return $this->card('Controls', $inner, $c['access'] ? 'physical-access cover' : 'shading');
    }

    private function coverControlLeaf(Lighting $lx, string $coverId, string $action, string $arg, VisualPersona $persona, string $navBase): string
    {
        $c = $lx->cover($coverId);
        $crumbs = [['Corevance', $navBase], ['Lighting & Covers', $navBase . '/lighting'],
                   ['Blinds & shades', $navBase . '/lighting/covers'],
                   [$c['name'], $navBase . '/lighting/covers/' . $coverId], ['Command', '']];
        $job = 'cmd-' . substr(hash('sha256', $persona->seed() . '|covcmd|' . $coverId . '|' . $action . '|' . $arg), 0, 8);
        $status = $c['windLockout']
            ? 'Queued — HELD by wind lockout until anemometer clears'
            : 'Queued — applies at next BMS poll';
        return $this->breadcrumbHtml($crumbs) . $this->controlResultCard(
            $this->coverActionTitle($action) . ' — ' . $c['name'],
            [
                ['Command', $this->coverActionLabel($action, $arg)],
                ['Target', $c['name'] . ' (' . $c['id'] . ')'],
                ['Interlock', $c['windLockout'] ? 'Wind lockout ACTIVE' : 'clear'],
                ['Status', $status],
                ['Job', $job],
            ]
        );
    }

    private function coverActionTitle(string $action): string
    {
        switch ($action) {
            case 'open':
                return 'Open queued';
            case 'close':
                return 'Close queued';
            case 'stop':
                return 'Stop queued';
            case 'tilt':
                return 'Tilt change queued';
            default:
                return 'Position change queued';
        }
    }

    private function coverActionLabel(string $action, string $arg): string
    {
        switch ($action) {
            case 'open':
                return 'Open → 100 %';
            case 'close':
                return 'Close → 0 %';
            case 'stop':
                return 'Stop at current position';
            case 'tilt':
                return 'Tilt → ' . $arg . ' %';
            default:
                return 'Position → ' . $arg . ' %';
        }
    }

    // --- master control (INERT canned confirmation) ---

    private function masterControl(Lighting $lx, string $entity, VisualPersona $persona, string $navBase): string
    {
        $onOff = $entity === 'off' ? 'off' : 'on';
        $s = $lx->summary();
        $crumbs = [['Corevance', $navBase], ['Lighting & Covers', $navBase . '/lighting'], ['Master command', '']];
        $job = 'cmd-' . substr(hash('sha256', $persona->seed() . '|lgtmaster|' . $onOff), 0, 8);
        return $this->breadcrumbHtml($crumbs) . $this->controlResultCard(
            'Building-wide lighting — all ' . strtoupper($onOff),
            [
                ['Command', 'All controllable luminaires → ' . strtoupper($onOff)],
                ['Scope', 'Whole building (all floors, all zones)'],
                ['Groups', number_format((int) $s['groups']) . ' queued across ' . $s['controllers'] . ' controllers'],
                ['Status', 'Queued — broadcast applies at the next DALI poll (~10 s)'],
                ['Note', 'Life-safety and emergency lighting circuits are excluded by the panel.'],
                ['Job', $job],
            ]
        );
    }

    // --- shared bits ---

    /**
     * A horizontal fill bar (0-100 %) — an inline styled div; the width is a clamped integer and the
     * colour a fixed literal, so nothing model-derived reaches the markup.
     */
    private function fillBar(int $pct, string $color): string
    {
        $pct = $pct < 0 ? 0 : ($pct > 100 ? 100 : $pct);
        $safe = preg_match('/^#[0-9a-f]{6}$/i', $color) === 1 ? $color : '#3b7ea1';
        return '<div style="flex:1;min-width:120px;max-width:280px;height:14px;background:#e3e6e8;border-radius:7px;overflow:hidden">'
            . '<div style="width:' . $pct . '%;height:100%;background:' . $safe . '"></div></div>'
            . '<span style="font-weight:600;color:#2c3136;min-width:40px;text-align:right">' . $pct . '%</span>';
    }

    /** @param list<array<string,mixed>> $items @return array{0:int,1:int,2:list<array<string,mixed>>} */
    private function paginate(array $items, int $page): array
    {
        $total = count($items);
        if ($page < 1) {
            $page = 1;
        }
        $pages = $total > 0 ? (int) ceil($total / self::PER_PAGE) : 1;
        if ($page > $pages) {
            $page = $pages;
        }
        return [$page, $pages, array_slice($items, ($page - 1) * self::PER_PAGE, self::PER_PAGE)];
    }

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

    private function pager(string $base, int $total, int $page, int $pages, string $noun): string
    {
        $from = $total === 0 ? 0 : (($page - 1) * self::PER_PAGE) + 1;
        $to = min($page * self::PER_PAGE, $total);
        $summary = 'Showing ' . $from . '&ndash;' . $to . ' of ' . number_format($total) . ' ' . $this->esc($noun);
        return $this->pagerHtml($base, $page, $pages, $summary);
    }

    private function searchBox(): string
    {
        return '<input type="text" id="lgt-search" placeholder="Filter…" '
            . 'style="margin:0 0 10px;padding:6px 10px;border:1px solid #c9ccd1;border-radius:4px;width:100%;max-width:320px" '
            . 'aria-label="Filter rows">';
    }

    /** Vanilla, self-contained row filter — no external code, no state change (spec R1 / D.5). */
    private function searchScript(): string
    {
        return '<script>(function(){var i=document.getElementById("lgt-search"),'
            . 't=document.getElementById("lgt-groups");if(!i||!t)return;'
            . 'i.addEventListener("input",function(){var q=i.value.toLowerCase(),'
            . 'r=t.tBodies[0]?t.tBodies[0].rows:[];for(var k=0;k<r.length;k++){'
            . 'r[k].style.display=r[k].textContent.toLowerCase().indexOf(q)>-1?"":"none";}});})();</script>';
    }

    private function statePill(string $state): string
    {
        if ($state === 'on') {
            return $this->pillHtml('On', 'ok');
        }
        if ($state === 'fault') {
            return $this->pillHtml('Fault', 'crit');
        }
        return $this->pillHtml('Off', 'idle');
    }

    private function coverStatePill(string $state): string
    {
        if ($state === 'open') {
            return $this->pillHtml('Open', 'info');
        }
        if ($state === 'closed') {
            return $this->pillHtml('Closed', 'idle');
        }
        return $this->pillHtml('Partial', 'warn');
    }
}
