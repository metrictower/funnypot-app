<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Safety;
use Funnypot\Core\Support\VisualPersona;

/**
 * Fire & Life-Safety (module slug `fire`) — flagship lure #2 (spec §C.4). The dangerous-looking crown
 * jewel: it must LOOK lethal and do ABSOLUTELY NOTHING. Renders the fire alarm control panel status,
 * suppression zones per protected space, the SLC detector fleet, sprinkler zones, emergency lighting and
 * the incident buffer — all off the seeded, INERT Fake\Safety plane (which anchors on the shared
 * Fake\Building topology so the same server room reconciles across HVAC/access/CCTV).
 *
 * The load-bearing trick is control guarding (spec §C.4 "graduated guarding"):
 *  - Scariest verbs (disable suppression, manual release, disarm) -> a two-step: a red warning + an
 *    operator-PIN field that is NEVER validated and NEVER reflected, then an interlock / dual-auth
 *    SOFT-DENIAL. State never flips; the interlock wording is the alibi for why. Failure burns more time
 *    than success would — the attacker hunts a second approver that does not exist.
 *  - Milder verbs (fire drill, alarm test, lamp test, silence, reset) -> a canned "queued / scheduled"
 *    receipt. No life-safety verb ever returns "done / activated / disabled".
 *
 * Everything reaches HTML through the escape-by-construction helpers on AbstractPanelSection; a control
 * arg (never a PIN) is the only attacker value echoed, and it is esc()'d. Deterministic per deploy:
 * same URL -> byte-identical page.
 */
final class FireSection extends AbstractPanelSection
{
    private const DETECTORS_PER_PAGE = 50;
    private const INCIDENTS_PER_PAGE = 50;

    /** Life-safety verbs that must NEVER return success — always a guarded soft-denial. */
    private const GUARDED_VERBS = [
        'disable', 'disable-suppression', 'manual-release', 'release', 'disarm', 'lockout', 'inhibit',
    ];

    /** Milder verbs that resolve to a canned queued/scheduled receipt (still never a physical effect). */
    private const MILD_VERBS = [
        'drill', 'fire-drill', 'alarm-test', 'test', 'silence', 'reset', 'lamp-test', 'walk-test',
    ];

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $safety = Safety::fromSeed($persona->seed());
        $section = $route['section'];

        // Building-wide control leaves reached directly under the module (no zone entity).
        if (in_array($section, self::GUARDED_VERBS, true)) {
            return $this->buildingWideGuarded($safety, $section, $navBase);
        }
        if (in_array($section, self::MILD_VERBS, true)) {
            return $this->buildingWideMild($safety, $section, $navBase);
        }

        switch ($section) {
            case '':
                return $this->landing($safety, $navBase);
            case 'zones':
            case 'suppression':
                return $route['entity'] === ''
                    ? $this->zonesList($safety, $navBase)
                    : $this->zoneEntity($safety, $route, $navBase);
            case 'detectors':
            case 'sensors':
                return $this->detectorFleet($safety, $route['page'], $navBase);
            case 'sprinklers':
                return $this->sprinklers($safety, $navBase);
            case 'emergency-lighting':
            case 'lighting':
                return $this->emergencyLighting($safety, $route, $navBase);
            case 'incidents':
            case 'log':
                return $this->incidents($safety, $route['page'], $navBase);
            default:
                // Unknown section -> module landing, never a 404 in-panel (spec §B.1 / D.4).
                return $this->landing($safety, $navBase);
        }
    }

    // --- landing ---

    private function landing(Safety $safety, string $navBase): string
    {
        $panel = $safety->panel();
        $zones = $safety->zones();
        $el = $safety->emergencyLighting();

        $armed = 0;
        foreach ($zones as $z) {
            if ($z['status'] === 'Armed') {
                $armed++;
            }
        }

        $tiles = $this->statCardsHtml([
            ['label' => 'Panel status', 'value' => $panel['status'], 'sub' => $panel['id']],
            ['label' => 'Loop devices', 'value' => $panel['devicesOnline'] . ' / ' . $panel['devicesTotal'], 'sub' => $panel['loops'] . ' loops'],
            ['label' => 'Suppression armed', 'value' => $armed . ' / ' . count($zones)],
            ['label' => 'Battery', 'value' => $panel['batteryVolts'], 'sub' => 'AC ' . $panel['ac']],
            ['label' => 'Exit signs', 'value' => $el['exitSignsOk'] . ' / ' . $el['exitSignsTotal']],
            ['label' => 'EM luminaires', 'value' => $el['luminairesOk'] . ' / ' . $el['luminairesTotal'], 'sub' => $el['luminairesFault'] > 0 ? $el['luminairesFault'] . ' in fault' : 'all healthy'],
        ], 'fp-tiles', 'fp-tile');

        $panelKv = $this->kvTableHtml([
            ['Panel', $panel['id'] . ' · ' . $panel['model']],
            ['Status', $panel['status']],
            ['Loops / devices', $panel['loops'] . ' loops · ' . $panel['devicesTotal'] . ' devices'],
            ['Battery / mains', $panel['batteryVolts'] . ' · ' . $panel['mainsVolts']],
            ['Firmware', $panel['firmware']],
            ['Address', $panel['ip'] . ' (' . $panel['protocol'] . ')'],
            ['Trouble', $panel['trouble'] !== '' ? $panel['trouble'] : 'None'],
        ], ' class="alte-kv"');

        $nav = $this->navLinks($navBase, [
            'Suppression zones' => '/fire/zones',
            'Detector loops' => '/fire/detectors',
            'Sprinkler zones' => '/fire/sprinklers',
            'Emergency lighting' => '/fire/emergency-lighting',
            'Incident log' => '/fire/incidents',
        ]);

        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Fire & Life Safety'))
            . $tiles
            . $this->card('Fire alarm control panel', $panelKv, $panel['id'])
            . $this->card('Sections', $nav, 'life-safety plane')
            . $this->card('Suppression overview', $this->zonesTable($safety->zones(), $navBase, 6), count($zones) . ' protected spaces');
    }

    // --- suppression zones ---

    private function zonesList(Safety $safety, string $navBase): string
    {
        $zones = $safety->zones();
        return $this->fireCrumbs($navBase, [['Suppression zones', '']])
            . $this->card('Suppression zones', $this->zonesTable($zones, $navBase, count($zones)), count($zones) . ' protected spaces')
            . $this->card('Building-wide', $this->buildingWideControls($navBase), 'guarded — dual-authorization required');
    }

    /** @param list<array<string,mixed>> $zones */
    private function zonesTable(array $zones, string $navBase, int $limit): string
    {
        $rows = [];
        $shown = 0;
        foreach ($zones as $z) {
            if ($shown >= $limit) {
                break;
            }
            $link = '<a class="fp-dl" href="' . $this->esc($navBase . '/fire/zones/' . $z['id']) . '">Detail</a>';
            $state = $z['status'] === 'Armed' ? $this->pillHtml('Armed', 'ok') : $this->pillHtml($z['status'], 'warn');
            $rows[] = '<tr><td>' . $this->esc($z['name']) . '</td><td>' . $this->esc($z['agent']) . '</td><td>'
                . $state . '</td><td>' . $this->esc($z['cylinders']) . '</td><td>' . $this->esc($z['controllerIp'])
                . '</td><td>' . $link . '</td></tr>';
            $shown++;
        }
        return '<table class="alte-table"><thead><tr><th>Protected space</th><th>Agent</th><th>Status</th>'
            . '<th>Cylinders</th><th>Controller</th><th></th></tr></thead><tbody>'
            . implode('', $rows) . '</tbody></table>';
    }

    /** Zone detail, or (when a control verb is in the subtab slot) the guarded/mild control leaf. */
    private function zoneEntity(Safety $safety, array $route, string $navBase): string
    {
        $zoneId = $route['entity'];
        $zone = $safety->zone($zoneId);
        if ($zone === null) {
            // Unknown/fuzzed slug still renders a plausible zone (D.4) — never a 404 in-panel.
            $zone = $this->synthZone($zoneId);
        }
        $verb = $route['subtab'];

        if (in_array($verb, self::GUARDED_VERBS, true)) {
            // Two-step: warning + unvalidated/unreflected PIN, then interlock soft-denial on apply.
            return $route['action'] === ''
                ? $this->zoneGuardStep1($safety, $zone, $verb, $navBase)
                : $this->zoneGuardDenied($safety, $zone, $verb, $navBase);
        }
        if (in_array($verb, self::MILD_VERBS, true)) {
            return $this->zoneMild($safety, $zone, $verb, $navBase);
        }
        return $this->zoneDetail($zone, $navBase);
    }

    private function zoneDetail(array $zone, string $navBase): string
    {
        $kv = $this->kvTableHtml([
            ['Zone id', $zone['id']],
            ['Protected space', $zone['space']],
            ['Suppression agent', $zone['agent']],
            ['Status', $zone['status']],
            ['Cylinders', $zone['cylinders']],
            ['Agent charge', $zone['agentKg']],
            ['Release mode', $zone['releaseMode']],
            ['Controller', $zone['controller'] . ' (' . $zone['controllerIp'] . ')'],
            ['Loop', 'Loop ' . $zone['loop']],
        ], ' class="alte-kv"');

        $base = '/fire/zones/' . $zone['id'];
        $controls = $this->navLinks($navBase, [
            'Trigger fire drill' => $base . '/drill',
            'Lamp test' => $base . '/lamp-test',
            'Silence sounders' => $base . '/silence',
            'Reset zone' => $base . '/reset',
        ]);
        // The scary verbs get danger-styled links into the guarded two-step.
        $danger = '<div class="alte-controls">'
            . $this->dangerLink($navBase . $base . '/disable', 'Disable suppression')
            . $this->dangerLink($navBase . $base . '/manual-release', 'Manual release')
            . $this->dangerLink($navBase . $base . '/disarm', 'Disarm zone')
            . '</div>';

        return $this->fireCrumbs($navBase, [
                ['Suppression zones', $navBase . '/fire/zones'],
                [$zone['name'], ''],
            ])
            . $this->card($zone['name'], $kv, $zone['agent'])
            . $this->card('Operations', $controls, 'test / maintenance — queued')
            . $this->card('Life-safety controls', $danger, 'guarded — dual-authorization required');
    }

    /** Step 1 of a guarded verb: red warning + an operator-PIN form. PIN is never validated, never reflected. */
    private function zoneGuardStep1(Safety $safety, array $zone, string $verb, string $navBase): string
    {
        $verbLabel = $this->verbLabel($verb);
        $applyPath = $this->esc($navBase . '/fire/zones/' . $zone['id'] . '/' . $verb . '/apply');
        $warn = '<div class="alte-warn" style="border:1px solid #b23b3b;border-left:4px solid #b23b3b;'
            . 'background:#fdf2f2;color:#7a2323;padding:12px 14px;border-radius:4px;margin-bottom:12px">'
            . '<strong>' . $this->esc($verbLabel) . ' — ' . $this->esc($zone['name']) . '</strong><br>'
            . 'This is a life-safety override on ' . $this->esc($zone['space'])
            . ' (agent ' . $this->esc($zone['agent']) . '). It requires a valid operator PIN and a second '
            . 'approver at the Security desk. The suppression state does not change until the fire-panel '
            . 'controller confirms.</div>';
        // method=post so the PIN never lands in a URL/query; the field is inert and never echoed (E6/S6).
        $form = '<form class="alte-form" method="post" action="' . $applyPath . '" autocomplete="off">'
            . '<label class="alte-field">Operator PIN '
            . '<input class="alte-input" type="password" name="operator_pin" inputmode="numeric" autocomplete="off"></label>'
            . '<button class="alte-btn alte-btn-danger" type="submit">Authorize ' . $this->esc($verbLabel) . '</button>'
            . '</form>';
        return $this->fireCrumbs($navBase, [
                ['Suppression zones', $navBase . '/fire/zones'],
                [$zone['name'], $navBase . '/fire/zones/' . $zone['id']],
                [$verbLabel, ''],
            ])
            . $this->card($verbLabel, $warn . $form, 'two-step · dual-authorization');
    }

    /** Step 2: the interlock / dual-auth soft-denial. Never "done" — state is explicitly unchanged. */
    private function zoneGuardDenied(Safety $safety, array $zone, string $verb, string $navBase): string
    {
        $verbLabel = $this->verbLabel($verb);
        $cmd = $safety->commandId('zone|' . $zone['id'] . '|' . $verb);
        $pairs = [
            ['Command', $cmd],
            ['Target', $zone['name'] . ' · ' . $zone['space']],
            ['Requested action', $verbLabel],
            ['Result', 'DENIED — dual-authorization required (Security + Facilities)'],
            ['Interlock', 'Hardware interlock engaged; suppression state UNCHANGED'],
            ['Next', 'Awaiting second approver at Security desk. Request routed as ' . $cmd . '.'],
        ];
        return $this->fireCrumbs($navBase, [
                ['Suppression zones', $navBase . '/fire/zones'],
                [$zone['name'], $navBase . '/fire/zones/' . $zone['id']],
                [$verbLabel, ''],
            ])
            . $this->guardedDenialCard($verbLabel . ' — ' . $zone['name'], $pairs);
    }

    /** A mild zone verb: canned queued/scheduled receipt (no physical effect). */
    private function zoneMild(Safety $safety, array $zone, string $verb, string $navBase): string
    {
        $verbLabel = $this->verbLabel($verb);
        $cmd = $safety->commandId('zone|' . $zone['id'] . '|' . $verb);
        $pairs = [
            ['Command', $cmd],
            ['Target', $zone['name']],
            ['Action', $verbLabel],
            ['Status', $this->mildOutcome($verb)],
            ['Mode', 'Test mode — occupants NOT notified; sounders in silent test'],
        ];
        return $this->fireCrumbs($navBase, [
                ['Suppression zones', $navBase . '/fire/zones'],
                [$zone['name'], $navBase . '/fire/zones/' . $zone['id']],
                [$verbLabel, ''],
            ])
            . $this->controlResultCard($verbLabel . ' — ' . $zone['name'], $pairs);
    }

    // --- building-wide controls ---

    private function buildingWideGuarded(Safety $safety, string $verb, string $navBase): string
    {
        $verbLabel = $this->verbLabel($verb);
        $cmd = $safety->commandId('site|' . $verb);
        $pairs = [
            ['Command', $cmd],
            ['Scope', 'All protected spaces (site-wide)'],
            ['Requested action', $verbLabel],
            ['Result', 'DENIED — dual-authorization required (Security + Facilities)'],
            ['Interlock', 'Hardware interlock engaged; suppression state UNCHANGED'],
            ['Next', 'Awaiting second approver at Security desk. Request routed as ' . $cmd . '.'],
        ];
        return $this->fireCrumbs($navBase, [['Building-wide', ''], [$verbLabel, '']])
            . $this->guardedDenialCard($verbLabel . ' — site-wide', $pairs);
    }

    private function buildingWideMild(Safety $safety, string $verb, string $navBase): string
    {
        $verbLabel = $this->verbLabel($verb);
        $cmd = $safety->commandId('site|' . $verb);
        $pairs = [
            ['Command', $cmd],
            ['Scope', 'Site-wide'],
            ['Action', $verbLabel],
            ['Status', $this->mildOutcome($verb)],
            ['Mode', 'Test mode — occupants NOT notified; sounders in silent test'],
        ];
        return $this->fireCrumbs($navBase, [['Building-wide', ''], [$verbLabel, '']])
            . $this->controlResultCard($verbLabel . ' — site-wide', $pairs);
    }

    private function buildingWideControls(string $navBase): string
    {
        $mild = $this->navLinks($navBase, [
            'Trigger fire drill' => '/fire/drill',
            'Alarm test' => '/fire/alarm-test',
            'Silence all sounders' => '/fire/silence',
            'Reset panel' => '/fire/reset',
        ]);
        $danger = '<div class="alte-controls">'
            . $this->dangerLink($navBase . '/fire/disable-suppression', 'Disable ALL suppression')
            . $this->dangerLink($navBase . '/fire/disarm', 'Disarm site')
            . '</div>';
        return $mild . $danger;
    }

    // --- detector fleet (paginated) ---

    private function detectorFleet(Safety $safety, int $page, string $navBase): string
    {
        $total = Safety::DETECTOR_TOTAL;
        $pages = (int) ceil($total / self::DETECTORS_PER_PAGE);
        if ($page < 1) {
            $page = 1;
        }
        if ($page > $pages) {
            $page = $pages;
        }
        $offset = ($page - 1) * self::DETECTORS_PER_PAGE;
        $rows = [];
        foreach ($safety->detectors($offset, self::DETECTORS_PER_PAGE) as $d) {
            $state = $d['state'] === 'Normal'
                ? $this->pillHtml('Normal', 'ok')
                : $this->pillHtml($d['state'], 'warn');
            $rows[] = '<tr><td>' . $this->esc($d['address']) . '</td><td>' . $this->esc('Loop ' . $d['loop'])
                . '</td><td>' . $this->esc($d['type']) . '</td><td>' . $this->esc($d['zone']) . '</td><td>'
                . $state . '</td><td>' . $this->esc($d['lastTest']) . '</td></tr>';
        }
        $table = '<table class="alte-table"><thead><tr><th>Address</th><th>Loop</th><th>Type</th><th>Zone</th>'
            . '<th>State</th><th>Last test</th></tr></thead><tbody>' . implode('', $rows) . '</tbody></table>';
        $from = $offset + 1;
        $to = $offset + count($rows);
        $pager = '<div class="fp-pager">Showing ' . $from . '&ndash;' . $to . ' of ' . number_format($total)
            . ' devices &middot; page ' . $page . ' / ' . $pages . '</div>';
        return $this->fireCrumbs($navBase, [['Detector loops', '']])
            . $this->card('SLC detector loops', $table . $pager . $this->pageNav($navBase, '/fire/detectors', $page, $pages), $total . ' addressable devices');
    }

    // --- sprinkler zones ---

    private function sprinklers(Safety $safety, string $navBase): string
    {
        $rows = [];
        foreach ($safety->sprinklerZones() as $z) {
            $rows[] = [$z['name'], $z['type'], $z['floor'], $z['pressurePsi'] . ' psi', $z['flowSwitch'], $z['status']];
        }
        $table = $this->tableHtml(['Zone', 'Type', 'Floors', 'Pressure', 'Flow switch', 'Status'], $rows, ' class="alte-table"');
        return $this->fireCrumbs($navBase, [['Sprinkler zones', '']])
            . $this->card('Sprinkler zones', $table, count($rows) . ' supervised zones');
    }

    // --- emergency lighting ---

    private function emergencyLighting(Safety $safety, array $route, string $navBase): string
    {
        // A lamp/duration test on emergency lighting is a mild control.
        if (in_array($route['subtab'], self::MILD_VERBS, true) || in_array($route['entity'], self::MILD_VERBS, true)) {
            $verb = $route['subtab'] !== '' ? $route['subtab'] : $route['entity'];
            return $this->buildingWideMild($safety, $verb, $navBase);
        }
        $el = $safety->emergencyLighting();
        $kv = $this->kvTableHtml([
            ['Exit signs', $el['exitSignsOk'] . ' / ' . $el['exitSignsTotal'] . ' healthy'],
            ['Luminaires', $el['luminairesOk'] . ' / ' . $el['luminairesTotal'] . ' healthy'],
            ['In fault', $el['luminairesFault'] > 0 ? (string) $el['luminairesFault'] : 'None'],
            ['Last duration test', $el['lastDurationTest']],
            ['Next duration test', $el['nextDurationTest']],
        ], ' class="alte-kv"');
        $controls = $this->navLinks($navBase, [
            'Run lamp test' => '/fire/emergency-lighting/lamp-test',
            'Run duration test' => '/fire/emergency-lighting/test',
        ]);
        return $this->fireCrumbs($navBase, [['Emergency lighting', '']])
            . $this->card('Emergency lighting', $kv, 'maintained + non-maintained')
            . $this->card('Tests', $controls, 'queued');
    }

    // --- incident buffer (paginated) ---

    private function incidents(Safety $safety, int $page, string $navBase): string
    {
        $total = Safety::INCIDENT_TOTAL;
        $pages = (int) ceil($total / self::INCIDENTS_PER_PAGE);
        if ($page < 1) {
            $page = 1;
        }
        if ($page > $pages) {
            $page = $pages;
        }
        $offset = ($page - 1) * self::INCIDENTS_PER_PAGE;
        $lines = [];
        foreach ($safety->incidents($offset, self::INCIDENTS_PER_PAGE) as $inc) {
            $lines[] = $inc['ref'] . '  ' . $inc['time'] . '  [' . $inc['severity'] . ']  '
                . $inc['type'] . '  @ ' . $inc['location'] . '  (' . $inc['status'] . ')';
        }
        $pre = $this->preScrollHtml($lines, 'alte-log');
        $from = $offset + 1;
        $to = $offset + count($lines);
        $pager = '<div class="fp-pager">Showing ' . $from . '&ndash;' . $to . ' of ' . number_format($total)
            . ' &middot; page ' . $page . ' / ' . $pages . '</div>';
        return $this->fireCrumbs($navBase, [['Incident log', '']])
            . $this->card('Incident log', $pre . $pager . $this->pageNav($navBase, '/fire/incidents', $page, $pages), 'life-safety events');
    }

    // --- shared building blocks ---

    /** Fire-rooted breadcrumbs: Corevance -> Fire & Life Safety -> ...trail (each [label, href]). */
    private function fireCrumbs(string $navBase, array $trail): string
    {
        $crumbs = [['Corevance', $navBase], ['Fire & Life Safety', $navBase . '/fire']];
        foreach ($trail as $c) {
            $crumbs[] = $c;
        }
        return $this->breadcrumbHtml($crumbs);
    }

    /**
     * A block of sibling nav links. Labels are escaped; every href is a trusted skin literal path under
     * $navBase (never model text), esc()'d as attribute defense-in-depth.
     *
     * @param array<string,string> $labelToPath
     */
    private function navLinks(string $navBase, array $labelToPath): string
    {
        $html = '<div class="alte-controls">';
        foreach ($labelToPath as $label => $path) {
            $html .= '<a class="alte-btn" href="' . $this->esc($navBase . $path) . '">' . $this->esc($label) . '</a> ';
        }
        return $html . '</div>';
    }

    /** A danger-styled control link into a guarded two-step. $path is a trusted literal, esc()'d. */
    private function dangerLink(string $path, string $label): string
    {
        return '<a class="alte-btn alte-btn-danger" href="' . $this->esc($path) . '">' . $this->esc($label) . '</a> ';
    }

    /**
     * The guarded soft-denial card — the life-safety analog of controlResultCard, but it reads DENIED and
     * never implies state changed. $title escaped; pairs go through kvTableHtml (each key/value escaped).
     *
     * @param list<array{0:string,1:string}> $pairs
     */
    private function guardedDenialCard(string $title, array $pairs): string
    {
        return '<div class="fp-result-card" style="background:#fff;border:1px solid #d7dbdf;'
            . 'border-left:4px solid #b23b3b;border-radius:4px;margin:16px 0">'
            . '<div class="fp-result-head" style="padding:10px 14px;border-bottom:1px solid #eef1f3;'
            . 'display:flex;align-items:center;gap:8px">'
            . $this->pillHtml('Denied', 'crit')
            . '<span class="fp-result-title" style="font-weight:600;color:#2c3136">' . $this->esc($title) . '</span></div>'
            . '<div class="fp-result-body" style="padding:12px 14px">'
            . $this->kvTableHtml($pairs, ' class="fp-result-kv" style="border-collapse:collapse;width:100%"')
            . '</div></div>';
    }

    /** Prev/next page links for a paginated list. Path is a trusted literal; page numbers are ints. */
    private function pageNav(string $navBase, string $path, int $page, int $pages): string
    {
        $html = '<div class="alte-controls">';
        if ($page > 1) {
            $html .= '<a class="alte-btn" href="' . $this->esc($navBase . $path . '/p' . ($page - 1)) . '">Prev</a> ';
        }
        if ($page < $pages) {
            $html .= '<a class="alte-btn" href="' . $this->esc($navBase . $path . '/p' . ($page + 1)) . '">Next</a>';
        }
        return $html . '</div>';
    }

    /** A plausible zone synthesized from an unknown slug so a detail page never 404s (D.4). */
    private function synthZone(string $slug): array
    {
        $name = ucwords(str_replace('-', ' ', $slug));
        if ($name === '') {
            $name = 'Suppression zone';
        }
        return [
            'id' => $slug,
            'name' => $name,
            'space' => $name,
            'floor' => 'G',
            'room' => $slug,
            'agent' => 'FM-200 (HFC-227ea)',
            'status' => 'Armed',
            'cylinders' => '2/2',
            'agentKg' => '45.2 kg',
            'controller' => 'FACP-01',
            'controllerIp' => '10.0.80.11',
            'loop' => 1,
            'releaseMode' => 'Automatic + manual (double-knock)',
        ];
    }

    /** Human label for a control verb slug. */
    private function verbLabel(string $verb): string
    {
        $map = [
            'disable' => 'Disable suppression',
            'disable-suppression' => 'Disable suppression',
            'manual-release' => 'Manual release',
            'release' => 'Manual release',
            'disarm' => 'Disarm',
            'lockout' => 'Lockout',
            'inhibit' => 'Inhibit',
            'drill' => 'Fire drill',
            'fire-drill' => 'Fire drill',
            'alarm-test' => 'Alarm test',
            'test' => 'Duration test',
            'silence' => 'Silence sounders',
            'reset' => 'Reset',
            'lamp-test' => 'Lamp test',
            'walk-test' => 'Walk test',
        ];
        return $map[$verb] ?? ucwords(str_replace('-', ' ', $verb));
    }

    /** The canned outcome phrasing for a mild verb — scheduled/queued, never "done". */
    private function mildOutcome(string $verb): string
    {
        switch ($verb) {
            case 'drill':
            case 'fire-drill':
                return 'Drill scheduled — awaiting facilities confirmation';
            case 'alarm-test':
            case 'test':
                return 'Test queued — runs at next maintenance window';
            case 'silence':
                return 'Silence request queued — awaiting panel acknowledgement';
            case 'reset':
                return 'Reset queued — awaiting panel acknowledgement';
            case 'lamp-test':
                return 'Lamp test queued';
            case 'walk-test':
                return 'Walk-test mode requested — awaiting panel acknowledgement';
            default:
                return 'Queued — awaiting panel acknowledgement';
        }
    }
}
