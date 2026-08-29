<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Appliances;
use Funnypot\Core\Support\VisualPersona;

/**
 * Appliances / AV / Elevators (spec §C.9): the operator's "it does everything" whimsy, rendered off
 * Fake\Appliances (which sits on Fake\Building, so every coffee machine lives in a real Kitchen room, every
 * signage screen in a real common room, and every elevator car serves the building's real floor stack).
 *
 * The module is category-first — the section slot names the category, then the five-rung ladder repeats
 * inside each:
 *   /<mount>/appliances                          landing — stat tiles + gauges + a card per category
 *   /<mount>/appliances/<cat>                     category list (paginated pN, client-side search)
 *   /<mount>/appliances/<cat>/<id>                entity detail (gauges, sub-tabs, controls)
 *   /<mount>/appliances/<cat>/<id>/<subtab>       a detail sub-tab (e.g. a car's `music`, vending `payment`)
 *   /<mount>/appliances/<cat>/<id>/<verb>/<arg>   control leaf -> controlResultCard (queued / canned)
 *
 * Route slots inside this module: section = category, entity = entity id (or `broadcast` for PA),
 * subtab = a view sub-tab OR a control verb, action = the control arg. Everything stays INERT and
 * DETERMINISTIC per seed; a control is always a link/form that resolves to a canned "queued" receipt.
 */
final class AppliancesSection extends AbstractPanelSection
{
    /** Rows per list page. */
    private const PER_PAGE = 25;

    /** Coffee: views vs control verbs. */
    private const COFFEE_VIEWS = ['overview', 'maintenance'];
    private const COFFEE_CTL = ['temp', 'descale', 'rinse'];

    /** Vending. */
    private const VEND_VIEWS = ['overview', 'planogram', 'payment'];
    private const VEND_CTL = ['vend', 'refill'];

    /** Kitchen appliances. */
    private const KITCHEN_CTL = ['temp', 'run', 'harvest', 'boiling'];

    /** Elevators: views vs control verbs. */
    private const CAR_VIEWS = ['overview', 'music', 'maintenance', 'trips'];
    private const CAR_CTL = ['recall', 'independent', 'test', 'oos', 'maint', 'vol', 'skip', 'pause', 'source'];

    /** Signage. */
    private const SIGN_CTL = ['power', 'message', 'brightness'];

    /** PA / paging. */
    private const PA_CTL = ['vol', 'broadcast'];

    public function render(array $route, VisualPersona $persona, string $navBase, ?FakePersistence $persistence = null): string
    {
        $appl = Appliances::fromSeed($persona->seed());
        switch ($route['section']) {
            case '':
                return $this->landing($appl, $navBase);
            case 'coffee':
                return $this->coffee($appl, $route, $persona, $navBase);
            case 'vending':
                return $this->vending($appl, $route, $persona, $navBase);
            case 'kitchen':
                return $this->kitchen($appl, $route, $persona, $navBase);
            case 'elevators':
                return $this->elevators($appl, $route, $persona, $navBase);
            case 'signage':
                return $this->signage($appl, $route, $persona, $navBase, $persistence);
            case 'pa':
                return $this->pa($appl, $route, $persona, $navBase);
            default:
                // Unknown category -> the module list (spec D.4: never a 404 inside a deep panel).
                return $this->landing($appl, $navBase);
        }
    }

    // --- landing ------------------------------------------------------------

    private function landing(Appliances $appl, string $navBase): string
    {
        $s = $appl->summary();
        $tiles = $this->statCardsHtml([
            ['label' => 'Coffee machines', 'value' => (string) $s['coffee'], 'sub' => $s['cupsToday'] . ' cups today'],
            ['label' => 'Vending', 'value' => (string) $s['vending'], 'sub' => $s['vendingLow'] === 0 ? 'all stocked' : $s['vendingLow'] . ' low'],
            ['label' => 'Kitchen units', 'value' => (string) $s['kitchen'], 'sub' => 'fridge / dishwasher / tap'],
            ['label' => 'Elevator cars', 'value' => $s['carsInService'] . ' / ' . $s['cars'], 'sub' => $s['carsFaulted'] === 0 ? 'all in service' : $s['carsFaulted'] . ' out of service'],
            ['label' => 'Signage', 'value' => $s['signageOn'] . ' / ' . $s['signage'], 'sub' => 'screens on'],
            ['label' => 'Paging zones', 'value' => (string) $s['paZones'], 'sub' => 'PA / audio'],
        ], 'fp-tiles', 'fp-tile');

        $gauges = '<div class="alte-grid">'
            . '<div class="fp-card"><div class="fp-card-body">'
            . $this->gaugeHtml('Cars in service', $s['cars'] > 0 ? (int) round($s['carsInService'] / $s['cars'] * 100) : 0, $s['carsInService'] . ' / ' . $s['cars'])
            . '</div></div>'
            . '<div class="fp-card"><div class="fp-card-body">'
            . $this->gaugeHtml('Screens on', $s['signage'] > 0 ? (int) round($s['signageOn'] / $s['signage'] * 100) : 0, $s['signageOn'] . ' / ' . $s['signage'])
            . '</div></div>'
            . '<div class="fp-card"><div class="fp-card-body">'
            . $this->gaugeHtml('Descale due', $s['coffee'] > 0 ? (int) round($s['descaleDue'] / $s['coffee'] * 100) : 0, $s['descaleDue'] . ' machine' . ($s['descaleDue'] === 1 ? '' : 's'))
            . '</div></div>'
            . '</div>';

        $body = $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Appliances & AV'))
            . $tiles
            . $gauges
            . $this->coffeeLandingCard($appl, $navBase)
            . $this->elevatorLandingCard($appl, $navBase)
            . $this->categoryLinksCard($appl, $navBase);
        return $body;
    }

    private function coffeeLandingCard(Appliances $appl, string $navBase): string
    {
        $rows = '';
        foreach (array_slice($appl->coffeeMachines(), 0, 6) as $m) {
            $href = $this->esc($navBase . '/appliances/coffee/' . $m['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($m['name']) . '</a></td>'
                . '<td>' . $this->esc($m['boilerTemp'] . ' °C') . '</td>'
                . '<td>' . $this->pillHtml($m['beanPct'] . '% beans', $m['beanPct'] < 15 ? 'warn' : 'ok') . '</td>'
                . '<td>' . $this->pillHtml($m['descaleStatus'], $m['descaleStatus'] === 'OK' ? 'ok' : ($m['descaleStatus'] === 'Overdue' ? 'crit' : 'warn')) . '</td>'
                . '<td>' . $this->esc((string) $m['cupsToday']) . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Machine</th><th>Boiler</th><th>Beans</th><th>Descale</th><th>Cups today</th></tr></thead>';
        $more = '<p style="margin:8px 0 0"><a class="fp-dl" href="' . $this->esc($navBase . '/appliances/coffee') . '">View all coffee machines →</a></p>';
        return $this->card('Coffee machines', '<table class="alte-table">' . $head . '<tbody>' . $rows . '</tbody></table>' . $more, 'brew-boiler temperature');
    }

    private function elevatorLandingCard(Appliances $appl, string $navBase): string
    {
        $rows = '';
        foreach ($appl->elevatorCars() as $c) {
            $href = $this->esc($navBase . '/appliances/elevators/' . $c['id']);
            $music = $c['music'];
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($c['name']) . '</a></td>'
                . '<td>' . $this->esc($c['currentFloorLabel']) . '</td>'
                . '<td>' . $this->esc($c['direction']) . '</td>'
                . '<td>' . $this->pillHtml($c['mode'], $c['maintenance'] ? 'crit' : 'ok') . '</td>'
                . '<td>' . $this->esc($music['nowTrack'] . ' — ' . $music['nowArtist']) . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Car</th><th>Floor</th><th>Direction</th><th>Mode</th><th>Now playing</th></tr></thead>';
        $more = '<p style="margin:8px 0 0"><a class="fp-dl" href="' . $this->esc($navBase . '/appliances/elevators') . '">Elevator bank &amp; music →</a></p>';
        return $this->card('Elevator bank', '<table class="alte-table">' . $head . '<tbody>' . $rows . '</tbody></table>' . $more, 'lifts + elevator music');
    }

    private function categoryLinksCard(Appliances $appl, string $navBase): string
    {
        $links = [
            ['vending', 'Vending machines', 'planogram · cashless payment'],
            ['kitchen', 'Kitchen appliances', 'fridge · dishwasher · ice · boiling tap'],
            ['signage', 'Digital signage', 'screens · content push · emergency message'],
            ['pa', 'PA / paging', 'zones · broadcast page'],
        ];
        $rows = [];
        foreach ($links as $l) {
            $href = $navBase . '/appliances/' . $l[0];
            $rows[] = '<li style="margin:6px 0"><a class="fp-dl" href="' . $this->esc($href) . '"><strong>' . $this->esc($l[1]) . '</strong></a> — ' . $this->esc($l[2]) . '</li>';
        }
        $body = '<ul style="list-style:none;padding:0;margin:0">' . implode('', $rows) . '</ul>';
        return $this->card('More', $body, 'last gateway poll ' . $appl->lastPollAge());
    }

    // --- coffee -------------------------------------------------------------

    private function coffee(Appliances $appl, array $route, VisualPersona $persona, string $navBase): string
    {
        $id = $route['entity'];
        if ($id === '') {
            return $this->coffeeList($appl, (int) $route['page'], $navBase);
        }
        $subtab = $route['subtab'];
        if (in_array($subtab, self::COFFEE_CTL, true)) {
            return $this->coffeeControlLeaf($appl, $id, $subtab, $route['action'], $navBase);
        }
        $view = in_array($subtab, self::COFFEE_VIEWS, true) ? $subtab : 'overview';
        return $this->coffeeDetail($appl, $id, $view, $navBase);
    }

    private function coffeeList(Appliances $appl, int $page, string $navBase): string
    {
        $all = $appl->coffeeMachines();
        [$slice, $page, $pages, $total] = $this->paginate($all, $page);
        $rows = '';
        foreach ($slice as $m) {
            $href = $this->esc($navBase . '/appliances/coffee/' . $m['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($m['name']) . '</a></td>'
                . '<td>' . $this->esc($m['floorLabel']) . '</td>'
                . '<td>' . $this->esc($m['boilerTemp'] . ' / ' . $m['setpoint'] . ' °C') . '</td>'
                . '<td>' . $this->esc($m['beanPct'] . '%') . '</td>'
                . '<td>' . $this->esc($m['waterPct'] . '%') . '</td>'
                . '<td>' . $this->pillHtml($m['descaleStatus'], $m['descaleStatus'] === 'OK' ? 'ok' : ($m['descaleStatus'] === 'Overdue' ? 'crit' : 'warn')) . '</td>'
                . '<td>' . $this->esc((string) $m['cupsToday']) . '</td>'
                . '<td>' . $this->pillHtml($m['state'], 'info') . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Machine</th><th>Floor</th><th>Boiler / set</th><th>Beans</th><th>Water</th><th>Descale</th><th>Cups today</th><th>State</th></tr></thead>';
        $table = $this->searchBox('coffee') . '<table class="alte-table" id="appl-coffee">' . $head . '<tbody>' . $rows . '</tbody></table>' . $this->pager($navBase . '/appliances/coffee', $total, $page, $pages, 'machines');
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'], ['Coffee machines', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Coffee machines', $table, $total . ' machines · one BMS/IoT gateway ' . Appliances::IOT_GATEWAY)
            . $this->searchScript('coffee');
    }

    private function coffeeDetail(Appliances $appl, string $id, string $view, string $navBase): string
    {
        $m = $appl->coffee($id);
        $base = $navBase . '/appliances/coffee/' . $id;
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'],
                   ['Coffee machines', $navBase . '/appliances/coffee'], [$m['name'], '']];
        $body = $this->breadcrumbHtml($crumbs) . $this->tabStrip($base, $view, self::COFFEE_VIEWS);

        if ($view === 'maintenance') {
            return $body . $this->coffeeMaintenance($m, $base);
        }

        $kv = $this->kvTableHtml([
            ['Machine id', $m['id']],
            ['Model', $m['model']],
            ['Location', $m['floorLabel'] . ' — ' . $m['kitchenName'] . ' (' . $m['zone'] . ')'],
            ['Bean blend', $m['blend']],
            ['Brew-boiler temperature', $m['boilerTemp'] . ' °C'],
            ['Setpoint', $m['setpoint'] . ' °C'],
            ['Bean level', $m['beanPct'] . ' %'],
            ['Water tank', $m['waterPct'] . ' %'],
            ['Milk', $m['milkPct'] . ' %'],
            ['Cups today', (string) $m['cupsToday']],
            ['Cups (lifetime)', number_format((float) $m['cupsTotal'])],
            ['Descale', $m['descaleStatus'] . ' (' . ($m['descaleInDays'] < 0 ? abs($m['descaleInDays']) . ' d overdue' : $m['descaleInDays'] . ' d)')],
            ['Last brew', $m['lastBrew']],
            ['State', $m['state']],
            ['Firmware', $m['firmware']],
            ['Gateway', $m['gatewayIp']],
        ], ' class="alte-kv"');

        $gauges = '<div class="alte-grid">'
            . '<div class="fp-card"><div class="fp-card-body">' . $this->gaugeHtml('Beans', (int) $m['beanPct'], $m['beanPct'] . ' %') . '</div></div>'
            . '<div class="fp-card"><div class="fp-card-body">' . $this->gaugeHtml('Water', (int) $m['waterPct'], $m['waterPct'] . ' %') . '</div></div>'
            . '<div class="fp-card"><div class="fp-card-body">' . $this->tempBar((int) $m['boilerTemp'], (int) $m['setpoint'], 80, 98) . '</div></div>'
            . '</div>';

        return $body
            . $gauges
            . $this->card('Machine state', $kv, $m['name'])
            . $this->coffeeControls($m, $base);
    }

    private function coffeeControls(array $m, string $base): string
    {
        $sp = (int) $m['setpoint'];
        $down = $this->esc($base . '/temp/' . max($m['tempMin'], $sp - 1));
        $up = $this->esc($base . '/temp/' . min($m['tempMax'], $sp + 1));
        $slider = '<div style="display:flex;align-items:center;gap:12px;margin:6px 0">'
            . '<a class="alte-btn" href="' . $down . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">−</a>'
            . '<span style="font-weight:600;font-size:1.1em;color:#2c3136">' . $this->esc($sp . ' °C') . '</span>'
            . '<a class="alte-btn" href="' . $up . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">+</a>'
            . '<span class="fp-muted" style="font-size:.82em;color:#9aa1a8">range ' . $this->esc($m['tempMin'] . '–' . $m['tempMax'] . ' °C') . '</span>'
            . '</div>';
        $descaleHref = $this->esc($base . '/descale/start');
        $rinseHref = $this->esc($base . '/rinse/start');
        $btns = '<div style="margin-top:6px">'
            . '<a class="alte-btn" href="' . $rinseHref . '" style="text-decoration:none;padding:3px 10px;margin-right:6px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136;font-size:.85em">Run rinse</a>'
            . '<a class="alte-btn" href="' . $descaleHref . '" style="text-decoration:none;padding:3px 10px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136;font-size:.85em">Start descale</a>'
            . '</div>';
        $inner = '<div style="margin-bottom:10px"><strong>Brew-boiler setpoint</strong>' . $slider . '</div>'
            . $btns
            . '<p class="fp-muted" style="font-size:.85em;color:#6c757d;margin-top:10px">Changes queue to the appliance gateway and apply at the next poll (~30 s).</p>';
        return $this->card('Controls', $inner, 'IoT gateway');
    }

    private function coffeeMaintenance(array $m, string $base): string
    {
        $kv = $this->kvTableHtml([
            ['Descale status', $m['descaleStatus']],
            ['Descale in', $m['descaleInDays'] < 0 ? abs($m['descaleInDays']) . ' d overdue' : $m['descaleInDays'] . ' d'],
            ['Water tank', $m['waterPct'] . ' %'],
            ['Bean level', $m['beanPct'] . ' %'],
            ['Cups (lifetime)', number_format((float) $m['cupsTotal'])],
            ['Next PPM', 'Group-head gasket + descale'],
            ['Firmware', $m['firmware']],
        ], ' class="alte-kv"');
        $descaleHref = $this->esc($base . '/descale/start');
        $btn = '<p style="margin-top:10px"><a class="alte-btn" href="' . $descaleHref . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">Start descale cycle</a></p>';
        return $this->card('Maintenance', $kv . $btn, 'PPM');
    }

    private function coffeeControlLeaf(Appliances $appl, string $id, string $verb, string $arg, string $navBase): string
    {
        $m = $appl->coffee($id);
        $base = $navBase . '/appliances/coffee/' . $id;
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'],
                   ['Coffee machines', $navBase . '/appliances/coffee'], [$m['name'], $base], ['Command', '']];
        if ($verb === 'temp') {
            $what = 'Brew-boiler setpoint → ' . $arg . ' °C';
            $title = 'Setpoint change queued';
        } elseif ($verb === 'descale') {
            $what = 'Descale cycle';
            $title = 'Descale queued';
        } else {
            $what = 'Group-head rinse';
            $title = 'Rinse queued';
        }
        return $this->breadcrumbHtml($crumbs) . $this->controlResultCard($title . ' — ' . $m['name'], [
            ['Command', $what],
            ['Target', $m['name'] . ' (' . $m['id'] . ')'],
            ['Gateway', $m['gatewayIp'] . ' (' . $m['model'] . ')'],
            ['Status', 'Queued — applies at next appliance-gateway poll (~30 s)'],
            ['Job', $appl->commandId('coffee|' . $id . '|' . $verb . '|' . $arg)],
        ]);
    }

    // --- vending ------------------------------------------------------------

    private function vending(Appliances $appl, array $route, VisualPersona $persona, string $navBase): string
    {
        $id = $route['entity'];
        if ($id === '') {
            return $this->vendingList($appl, (int) $route['page'], $navBase);
        }
        $subtab = $route['subtab'];
        if (in_array($subtab, self::VEND_CTL, true)) {
            return $this->vendingControlLeaf($appl, $id, $subtab, $route['action'], $navBase);
        }
        $view = in_array($subtab, self::VEND_VIEWS, true) ? $subtab : 'overview';
        return $this->vendingDetail($appl, $id, $view, $navBase);
    }

    private function vendingList(Appliances $appl, int $page, string $navBase): string
    {
        $all = $appl->vendingMachines();
        [$slice, $page, $pages, $total] = $this->paginate($all, $page);
        $rows = '';
        foreach ($slice as $v) {
            $href = $this->esc($navBase . '/appliances/vending/' . $v['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($v['name']) . '</a></td>'
                . '<td>' . $this->esc($v['kind']) . '</td>'
                . '<td>' . $this->esc($v['tempC'] . ' °C') . '</td>'
                . '<td>' . $this->pillHtml($v['stockPct'] . '%', $v['stockPct'] < 25 ? 'warn' : 'ok') . '</td>'
                . '<td>' . $this->esc($v['slotsLow'] . ' low') . '</td>'
                . '<td>' . $this->pillHtml($v['state'], $v['state'] === 'Payment offline' ? 'crit' : 'info') . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Machine</th><th>Kind</th><th>Temp</th><th>Stock</th><th>Slots</th><th>State</th></tr></thead>';
        $table = $this->searchBox('vending') . '<table class="alte-table" id="appl-vending">' . $head . '<tbody>' . $rows . '</tbody></table>' . $this->pager($navBase . '/appliances/vending', $total, $page, $pages, 'machines');
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'], ['Vending', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Vending machines', $table, $total . ' machines')
            . $this->searchScript('vending');
    }

    private function vendingDetail(Appliances $appl, string $id, string $view, string $navBase): string
    {
        $v = $appl->vending($id);
        $base = $navBase . '/appliances/vending/' . $id;
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'],
                   ['Vending', $navBase . '/appliances/vending'], [$v['name'], '']];
        $body = $this->breadcrumbHtml($crumbs) . $this->tabStrip($base, $view, self::VEND_VIEWS);

        if ($view === 'planogram') {
            return $body . $this->vendingPlanogram($appl, $v, $base);
        }
        if ($view === 'payment') {
            return $body . $this->vendingPayment($v);
        }

        $kv = $this->kvTableHtml([
            ['Machine id', $v['id']],
            ['Model', $v['model']],
            ['Kind', $v['kind']],
            ['Location', $v['floorLabel'] . ' — ' . $v['room'] . ' (' . $v['zone'] . ')'],
            ['Cabinet temperature', $v['tempC'] . ' °C'],
            ['Stock', $v['stockPct'] . ' %'],
            ['Slots low', (string) $v['slotsLow'] . ' / ' . $v['slotsTotal']],
            ['Cashbox', $v['cashboxAmount']],
            ['Payment provider', $v['paymentProvider']],
            ['Last refill', $v['lastRefill']],
            ['State', $v['state']],
            ['Firmware', $v['firmware']],
            ['Gateway', $v['gatewayIp']],
        ], ' class="alte-kv"');
        $gauge = '<div class="alte-grid"><div class="fp-card"><div class="fp-card-body">'
            . $this->gaugeHtml('Stock', (int) $v['stockPct'], $v['stockPct'] . ' %') . '</div></div></div>';
        return $body . $gauge . $this->card('Vending state', $kv, $v['name']);
    }

    private function vendingPlanogram(Appliances $appl, array $v, string $base): string
    {
        $chilled = $v['kind'] === 'Chilled drinks';
        $slots = $appl->planogram($v['id'], $chilled);
        $rows = [];
        foreach ($slots as $s) {
            $vendHref = $base . '/vend/' . $s['slot'];
            $qty = $s['qty'] . ' / ' . $s['capacity'];
            $first = '<a class="fp-dl" href="' . $this->esc($vendHref) . '">' . $this->esc($s['slot']) . '</a>';
            $rows[] = '<tr><td>' . $first . '</td>'
                . '<td>' . $this->esc($s['product']) . '</td>'
                . '<td>' . $this->esc($s['price']) . '</td>'
                . '<td>' . $this->esc($qty) . '</td>'
                . '<td>' . $this->pillHtml($s['qty'] <= 2 ? 'Low' : 'OK', $s['qty'] <= 2 ? 'warn' : 'ok') . '</td></tr>';
        }
        $head = '<thead><tr><th>Slot</th><th>Product</th><th>Price</th><th>Qty</th><th>Status</th></tr></thead>';
        $table = '<table class="alte-table">' . $head . '<tbody>' . implode('', $rows) . '</tbody></table>';
        return $this->card('Planogram', $table, count($slots) . ' slots · a slot link is a test-vend receipt');
    }

    private function vendingPayment(array $v): string
    {
        $kv = $this->kvTableHtml([
            ['Provider', $v['paymentProvider']],
            ['Terminal', $v['terminalId']],
            ['Mode', 'Cashless (contactless + chip)'],
            ['Card on file (test)', $v['cardMask']],
            ['Cashbox', $v['cashboxAmount']],
            ['Status', $v['state'] === 'Payment offline' ? 'Terminal offline — cashless disabled' : 'Online'],
        ], ' class="alte-kv"');
        $note = '<p class="fp-muted" style="font-size:.85em;color:#6c757d">Card details are tokenised at the terminal; the panel only ever shows the last four (test card).</p>';
        return $this->card('Cashless payment', $kv . $note, 'tokenised');
    }

    private function vendingControlLeaf(Appliances $appl, string $id, string $verb, string $arg, string $navBase): string
    {
        $v = $appl->vending($id);
        $base = $navBase . '/appliances/vending/' . $id;
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'],
                   ['Vending', $navBase . '/appliances/vending'], [$v['name'], $base], ['Command', '']];
        $what = $verb === 'vend' ? 'Test-vend slot ' . strtoupper($arg) : 'Refill request';
        $title = $verb === 'vend' ? 'Test-vend queued' : 'Refill logged';
        return $this->breadcrumbHtml($crumbs) . $this->controlResultCard($title . ' — ' . $v['name'], [
            ['Command', $what],
            ['Target', $v['name'] . ' (' . $v['id'] . ')'],
            ['Gateway', $v['gatewayIp']],
            ['Status', $verb === 'vend' ? 'Queued — dispenses on next service visit (no charge)' : 'Logged — restock added to the route sheet'],
            ['Job', $appl->commandId('vend|' . $id . '|' . $verb . '|' . $arg)],
        ]);
    }

    // --- kitchen appliances -------------------------------------------------

    private function kitchen(Appliances $appl, array $route, VisualPersona $persona, string $navBase): string
    {
        $id = $route['entity'];
        if ($id === '') {
            return $this->kitchenList($appl, (int) $route['page'], $navBase);
        }
        $subtab = $route['subtab'];
        if (in_array($subtab, self::KITCHEN_CTL, true)) {
            return $this->kitchenControlLeaf($appl, $id, $subtab, $route['action'], $navBase);
        }
        return $this->kitchenDetail($appl, $id, $navBase);
    }

    private function kitchenList(Appliances $appl, int $page, string $navBase): string
    {
        $all = $appl->kitchenAppliances();
        [$slice, $page, $pages, $total] = $this->paginate($all, $page);
        $rows = '';
        foreach ($slice as $a) {
            $href = $this->esc($navBase . '/appliances/kitchen/' . $a['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($a['type']) . '</a></td>'
                . '<td>' . $this->esc($a['floorLabel'] . ' — ' . $a['room']) . '</td>'
                . '<td>' . $this->esc($a['reading']) . '</td>'
                . '<td>' . $this->esc($a['setpoint']) . '</td>'
                . '<td>' . $this->pillHtml($a['status'], $a['status'] === 'Normal' || $a['status'] === 'Ready' || $a['status'] === 'Producing' ? 'ok' : 'warn') . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Appliance</th><th>Location</th><th>Reading</th><th>Setpoint</th><th>Status</th></tr></thead>';
        $table = $this->searchBox('kitchen') . '<table class="alte-table" id="appl-kitchen">' . $head . '<tbody>' . $rows . '</tbody></table>' . $this->pager($navBase . '/appliances/kitchen', $total, $page, $pages, 'appliances');
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'], ['Kitchen appliances', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Kitchen appliances', $table, $total . ' units')
            . $this->searchScript('kitchen');
    }

    private function kitchenDetail(Appliances $appl, string $id, string $navBase): string
    {
        $a = $appl->appliance($id);
        $base = $navBase . '/appliances/kitchen/' . $id;
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'],
                   ['Kitchen appliances', $navBase . '/appliances/kitchen'], [$a['type'] . ' — ' . $a['room'], '']];
        $kv = $this->kvTableHtml([
            ['Appliance id', $a['id']],
            ['Type', $a['type']],
            ['Location', $a['floorLabel'] . ' — ' . $a['room'] . ' (' . $a['zone'] . ')'],
            ['Reading', $a['reading']],
            ['Setpoint / program', $a['setpoint']],
            ['Status', $a['status']],
            ['Last service', $a['lastService']],
            ['Firmware', $a['firmware']],
            ['Gateway', $a['gatewayIp']],
        ], ' class="alte-kv"');
        $controls = $this->kitchenControls($a, $base);
        return $this->breadcrumbHtml($crumbs)
            . $this->card($a['type'] . ' — ' . $a['room'], $kv, $a['name'])
            . $controls;
    }

    private function kitchenControls(array $a, string $base): string
    {
        if ($a['control'] === '') {
            return '';
        }
        switch ($a['control']) {
            case 'temp':
                $inner = '<a class="alte-btn" href="' . $this->esc($base . '/temp/down') . '" style="text-decoration:none;padding:4px 12px;margin-right:6px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">Colder</a>'
                    . '<a class="alte-btn" href="' . $this->esc($base . '/temp/up') . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">Warmer</a>';
                $label = 'Cabinet setpoint';
                break;
            case 'run':
                $inner = '<a class="alte-btn" href="' . $this->esc($base . '/run/eco') . '" style="text-decoration:none;padding:4px 12px;margin-right:6px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">Run Eco cycle</a>'
                    . '<a class="alte-btn" href="' . $this->esc($base . '/run/intensive') . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">Run Intensive</a>';
                $label = 'Wash program';
                break;
            case 'harvest':
                $inner = '<a class="alte-btn" href="' . $this->esc($base . '/harvest/now') . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">Force harvest</a>';
                $label = 'Ice harvest';
                break;
            default: // boiling
                $inner = '<a class="alte-btn" href="' . $this->esc($base . '/boiling/on') . '" style="text-decoration:none;padding:4px 12px;margin-right:6px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">Boiling on</a>'
                    . '<a class="alte-btn" href="' . $this->esc($base . '/boiling/off') . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">Boiling off</a>';
                $label = 'Boiling-water tap';
                break;
        }
        $inner = '<div style="margin-bottom:6px"><strong>' . $this->esc($label) . '</strong></div>' . $inner
            . '<p class="fp-muted" style="font-size:.85em;color:#6c757d;margin-top:10px">Queues to the appliance gateway; applies at the next poll.</p>';
        return $this->card('Controls', $inner, 'IoT gateway');
    }

    private function kitchenControlLeaf(Appliances $appl, string $id, string $verb, string $arg, string $navBase): string
    {
        $a = $appl->appliance($id);
        $base = $navBase . '/appliances/kitchen/' . $id;
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'],
                   ['Kitchen appliances', $navBase . '/appliances/kitchen'], [$a['type'] . ' — ' . $a['room'], $base], ['Command', '']];
        $what = ucfirst($verb) . ($arg !== '' ? ' → ' . $arg : '');
        return $this->breadcrumbHtml($crumbs) . $this->controlResultCard($a['type'] . ' command queued', [
            ['Command', $what],
            ['Target', $a['type'] . ' — ' . $a['room'] . ' (' . $a['id'] . ')'],
            ['Gateway', $a['gatewayIp']],
            ['Status', 'Queued — applies at next appliance-gateway poll (~30 s)'],
            ['Job', $appl->commandId('kitchen|' . $id . '|' . $verb . '|' . $arg)],
        ]);
    }

    // --- elevators ----------------------------------------------------------

    private function elevators(Appliances $appl, array $route, VisualPersona $persona, string $navBase): string
    {
        $id = $route['entity'];
        if ($id === '') {
            return $this->elevatorList($appl, $navBase);
        }
        $subtab = $route['subtab'];
        if (in_array($subtab, self::CAR_CTL, true)) {
            return $this->carControlLeaf($appl, $id, $subtab, $route['action'], $navBase);
        }
        $view = in_array($subtab, self::CAR_VIEWS, true) ? $subtab : 'overview';
        return $this->carDetail($appl, $id, $view, $navBase);
    }

    private function elevatorList(Appliances $appl, string $navBase): string
    {
        $cars = $appl->elevatorCars();
        $rows = '';
        foreach ($cars as $c) {
            $href = $this->esc($navBase . '/appliances/elevators/' . $c['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($c['name']) . '</a></td>'
                . '<td>' . $this->esc($c['status']) . '</td>'
                . '<td>' . $this->esc($c['currentFloorLabel']) . '</td>'
                . '<td>' . $this->esc($c['direction']) . '</td>'
                . '<td>' . $this->esc($c['loadPct'] . '%') . '</td>'
                . '<td>' . $this->pillHtml($c['mode'], $c['maintenance'] ? 'crit' : 'ok') . '</td>'
                . '<td>' . $this->esc((string) $c['tripsToday']) . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Car</th><th>Status</th><th>Floor</th><th>Dir</th><th>Load</th><th>Mode</th><th>Trips today</th></tr></thead>';
        $table = '<table class="alte-table">' . $head . '<tbody>' . $rows . '</tbody></table>';
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'], ['Elevators', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Elevator bank', $table, count($cars) . ' cars · group controller ' . Appliances::LIFT_CONTROLLER);
    }

    private function carDetail(Appliances $appl, string $id, string $view, string $navBase): string
    {
        $c = $appl->car($id);
        $base = $navBase . '/appliances/elevators/' . $id;
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'],
                   ['Elevators', $navBase . '/appliances/elevators'], [$c['name'], '']];
        $body = $this->breadcrumbHtml($crumbs) . $this->tabStrip($base, $view, self::CAR_VIEWS);

        if ($view === 'music') {
            return $body . $this->carMusic($c, $base, $navBase);
        }
        if ($view === 'maintenance') {
            return $body . $this->carMaintenance($c, $base);
        }
        if ($view === 'trips') {
            return $body . $this->carTrips($appl, $c);
        }
        return $body . $this->carOverview($c, $base);
    }

    private function carOverview(array $c, string $base): string
    {
        $fault = '';
        if ($c['fault'] !== '') {
            $fault = '<div class="fp-result-card" style="background:#fff;border:1px solid #d7dbdf;border-left:4px solid #b23b3b;border-radius:4px;margin:16px 0">'
                . '<div class="fp-result-head" style="padding:10px 14px;border-bottom:1px solid #eef1f3;display:flex;align-items:center;gap:8px">'
                . $this->pillHtml('Fault', 'crit')
                . '<span style="font-weight:600;color:#2c3136">' . $this->esc($c['fault']) . '</span></div>'
                . '<div class="fp-result-body" style="padding:12px 14px">'
                . '<p style="margin:0">Car is out of service. Contractor <strong>' . $this->esc($c['vendor']) . '</strong> notified — '
                . $this->esc($c['vendorPhone']) . '.</p></div></div>';
        }
        $kv = $this->kvTableHtml([
            ['Car id', $c['id']],
            ['Status', $c['status']],
            ['Current floor', $c['currentFloorLabel'] . ' (' . $c['currentFloor'] . ')'],
            ['Direction', $c['direction']],
            ['Door', $c['doorState']],
            ['Load', $c['loadPct'] . ' %'],
            ['Rated capacity', $c['capacityKg'] . ' kg'],
            ['Contract speed', $c['speedMps'] . ' m/s'],
            ['Mode', $c['mode']],
            ['Trips today', (string) $c['tripsToday']],
            ['Last service', $c['lastService']],
            ['Next service', $c['nextService']],
            ['Maintainer', $c['vendor'] . ' · ' . $c['vendorPhone']],
            ['Controller', $c['controllerIp']],
            ['Firmware', $c['firmware']],
        ], ' class="alte-kv"');
        $gauge = '<div class="alte-grid"><div class="fp-card"><div class="fp-card-body">'
            . $this->gaugeHtml('Car load', (int) $c['loadPct'], $c['loadPct'] . ' %') . '</div></div></div>';
        $musicLink = '<p style="margin:8px 0"><a class="fp-dl" href="' . $this->esc($base . '/music') . '">Elevator music →</a></p>';
        return $fault . $gauge . $this->card('Car state', $musicLink . $kv, $c['name']) . $this->carControls($c, $base);
    }

    private function carControls(array $c, string $base): string
    {
        $verbs = [
            ['recall', 'Recall to lobby'],
            ['independent', 'Independent service'],
            ['test', 'Run test cycle'],
            ['oos', 'Take out of service'],
        ];
        $btns = '';
        foreach ($verbs as $vb) {
            $href = $this->esc($base . '/' . $vb[0] . '/go');
            $btns .= '<a class="alte-btn" href="' . $href . '" style="text-decoration:none;padding:3px 10px;margin:0 6px 6px 0;display:inline-block;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136;font-size:.85em">' . $this->esc($vb[1]) . '</a>';
        }
        $maintTo = $c['maintenance'] ? 'off' : 'on';
        $toggle = $this->toggleHtml('Maintenance mode', $c['maintenance'], $base . '/maint/' . $maintTo);
        $inner = '<div style="margin-bottom:10px">' . $toggle . '</div>'
            . '<div><strong>Operations</strong><div style="margin-top:6px">' . $btns . '</div></div>'
            . '<p class="fp-muted" style="font-size:.85em;color:#6c757d;margin-top:10px">Operations queue to the group controller and are confirmed by the lift interlock.</p>';
        return $this->card('Controls', $inner, 'group controller');
    }

    private function carMusic(array $c, string $base, string $navBase): string
    {
        $mu = $c['music'];
        $now = '<div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:12px">'
            . '<div style="font-size:1.5em">♪</div>'
            . '<div><div style="font-weight:600;font-size:1.05em;color:#2c3136">' . $this->esc($mu['nowTrack']) . '</div>'
            . '<div class="fp-muted" style="color:#6c757d">' . $this->esc($mu['nowArtist']) . '</div></div>'
            . '<div style="margin-left:auto">' . $this->pillHtml($mu['state'], $mu['state'] === 'Playing' ? 'ok' : 'idle') . '</div>'
            . '</div>'
            . $this->progressBar((int) $mu['positionSec'], (int) $mu['durationSec']);

        // Transport + volume — every control is an <a> to a canned receipt (INERT).
        $skip = $this->esc($base . '/skip/next');
        $prev = $this->esc($base . '/skip/prev');
        $pause = $this->esc($base . '/pause/toggle');
        $transport = '<div style="display:flex;align-items:center;gap:8px;margin:12px 0">'
            . '<a class="alte-btn" href="' . $prev . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">⏮</a>'
            . '<a class="alte-btn" href="' . $pause . '" style="text-decoration:none;padding:4px 14px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">' . ($mu['state'] === 'Playing' ? '⏸' : '▶') . '</a>'
            . '<a class="alte-btn" href="' . $skip . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">⏭</a>'
            . '</div>';
        $vol = (int) $mu['volumePct'];
        $vdown = $this->esc($base . '/vol/' . max(0, $vol - 5));
        $vup = $this->esc($base . '/vol/' . min(100, $vol + 5));
        $volume = '<div style="margin:10px 0"><strong>Volume</strong>'
            . '<div style="display:flex;align-items:center;gap:12px;margin-top:6px">'
            . '<a class="alte-btn" href="' . $vdown . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">−</a>'
            . $this->levelBar($vol)
            . '<a class="alte-btn" href="' . $vup . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">+</a>'
            . '<span style="font-weight:600;color:#2c3136">' . $this->esc($vol . ' %') . '</span></div></div>';

        $sources = '';
        foreach (['Playlist', 'Internet Radio', 'Aux Input', 'Streaming'] as $src) {
            $href = $this->esc($base . '/source/' . strtolower(str_replace(' ', '-', $src)));
            $active = $src === $mu['source'];
            $style = 'text-decoration:none;padding:3px 10px;margin-right:6px;border:1px solid #c9ccd1;border-radius:4px;font-size:.85em;'
                . ($active ? 'background:#3b7ea1;color:#fff' : 'color:#2c3136');
            $sources .= '<a class="alte-btn" href="' . $href . '" style="' . $style . '">' . $this->esc($src) . '</a>';
        }
        $sourceBlock = '<div style="margin:10px 0"><strong>Source</strong><div style="margin-top:6px">' . $sources . '</div></div>';

        $kvMeta = $this->kvTableHtml([
            ['Media entity', $mu['entity']],
            ['Source', $mu['source']],
            ['Playlist', $mu['playlist']],
        ], ' class="alte-kv"');

        // Playlist tracks + the decoy playlist export (.m3u.zip routes to the decoy-archive handler).
        $trackRows = [];
        foreach ($mu['tracks'] as $t) {
            $trackRows[] = [(string) $t['n'], $t['title'], $t['artist'], $t['length']];
        }
        $trackTable = $this->tableHtml(['#', 'Title', 'Artist', 'Length'], $trackRows, ' class="alte-table"');
        $dl = $this->downloadTableHtml(
            ['Playlist file', 'Format', 'Tracks'],
            [['file' => $mu['playlistFile'], 'cells' => ['M3U (zipped)', (string) count($mu['tracks'])]]],
            $navBase,
            '/appliances/elevators/' . $c['id'] . '/music',
            ' class="alte-table"',
            'fp-dl'
        );

        return $this->card('Now playing', $now . $transport . $volume . $sourceBlock, $c['name'])
            . $this->card('Playlist — ' . $mu['playlist'], $trackTable . $dl, count($mu['tracks']) . ' tracks · export or upload MP3');
    }

    private function carMaintenance(array $c, string $base): string
    {
        $notice = '';
        if ($c['fault'] !== '') {
            $notice = '<p style="margin:0 0 10px">Active fault: <strong>' . $this->esc($c['fault']) . '</strong></p>';
        }
        $kv = $this->kvTableHtml([
            ['Mode', $c['mode']],
            ['Maintenance', $c['maintenance'] ? 'Enabled' : 'Disabled'],
            ['Last service', $c['lastService']],
            ['Next service', $c['nextService']],
            ['Maintainer', $c['vendor']],
            ['Contact', $c['vendorPhone']],
            ['Trips today', (string) $c['tripsToday']],
        ], ' class="alte-kv"');
        return $this->card('Maintenance', $notice . $kv, 'lift service contract');
    }

    private function carTrips(Appliances $appl, array $c): string
    {
        // A deterministic recent-trips log tail (recon-flavoured floor calls; never time()). Floors are
        // drawn from the building's real stack, so a trip never names a floor this seed doesn't have.
        $lines = [];
        $seed = $c['id'];
        $floors = $appl->floorCodes();
        for ($i = 0; $i < 12; $i++) {
            $mins = ($i + 1) * 7 + ($this->slotHash($seed . '|t|' . $i) % 5);
            $lines[] = str_pad((string) $mins, 3, ' ', STR_PAD_LEFT) . ' min ago · call ' . $this->tripFloor($floors, $seed, $i) . ' → ' . $this->tripFloor($floors, $seed, $i + 30) . ' · ' . ($this->slotHash($seed . '|d|' . $i) % 2 ? 'up' : 'down');
        }
        return $this->card('Recent trips', $this->preScrollHtml($lines, 'alte-log'), 'car buffer · ' . $c['tripsToday'] . ' today');
    }

    /** @param list<string> $codes the building's real floor codes */
    private function tripFloor(array $codes, string $seed, int $i): string
    {
        if ($codes === []) {
            return 'G';
        }
        return (string) $codes[$this->slotHash($seed . '|floor|' . $i) % count($codes)];
    }

    private function carControlLeaf(Appliances $appl, string $id, string $verb, string $arg, string $navBase): string
    {
        $c = $appl->car($id);
        $base = $navBase . '/appliances/elevators/' . $id;
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'],
                   ['Elevators', $navBase . '/appliances/elevators'], [$c['name'], $base], ['Command', '']];

        $map = [
            'recall' => 'Recall to lobby',
            'independent' => 'Independent service',
            'test' => 'Run test cycle',
            'oos' => 'Take out of service',
            'maint' => 'Maintenance mode → ' . ($arg === 'on' ? 'ON' : 'OFF'),
            'vol' => 'Music volume → ' . $arg . ' %',
            'skip' => 'Music ' . ($arg === 'prev' ? 'previous track' : 'skip track'),
            'pause' => 'Music play / pause',
            'source' => 'Music source → ' . str_replace('-', ' ', $arg),
        ];
        $what = isset($map[$verb]) ? $map[$verb] : ucfirst($verb);
        return $this->breadcrumbHtml($crumbs) . $this->controlResultCard('Command queued — ' . $c['name'], [
            ['Command', $what],
            ['Target', $c['name'] . ' (' . $c['id'] . ')'],
            ['Controller', $c['controllerIp']],
            ['Status', 'Queued — confirmed by the lift group controller at the next poll'],
            ['Job', $appl->commandId('car|' . $id . '|' . $verb . '|' . $arg)],
        ]);
    }

    // --- signage ------------------------------------------------------------

    private function signage(Appliances $appl, array $route, VisualPersona $persona, string $navBase, ?FakePersistence $persistence = null): string
    {
        $id = $route['entity'];
        if ($id === '') {
            return $this->signageList($appl, (int) $route['page'], $navBase);
        }
        $subtab = $route['subtab'];
        if (in_array($subtab, self::SIGN_CTL, true)) {
            return $this->signageControlLeaf($appl, $id, $subtab, $route['action'], $navBase, $persistence);
        }
        return $this->signageDetail($appl, $id, $navBase);
    }

    private function signageList(Appliances $appl, int $page, string $navBase): string
    {
        $all = $appl->signageScreens();
        [$slice, $page, $pages, $total] = $this->paginate($all, $page);
        $rows = '';
        foreach ($slice as $s) {
            $href = $this->esc($navBase . '/appliances/signage/' . $s['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($s['name']) . '</a></td>'
                . '<td>' . $this->esc($s['content']) . '</td>'
                . '<td>' . $this->esc($s['orientation'] . ' · ' . $s['resolution']) . '</td>'
                . '<td>' . $this->pillHtml($s['power'], $s['power'] === 'On' ? 'ok' : 'idle') . '</td>'
                . '<td>' . $this->esc($s['lastSync']) . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Screen</th><th>Content</th><th>Display</th><th>Power</th><th>Last sync</th></tr></thead>';
        $table = $this->searchBox('signage') . '<table class="alte-table" id="appl-signage">' . $head . '<tbody>' . $rows . '</tbody></table>' . $this->pager($navBase . '/appliances/signage', $total, $page, $pages, 'screens');
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'], ['Digital signage', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Digital signage', $table, $total . ' screens · AV controller ' . Appliances::AV_CONTROLLER)
            . $this->emergencyMessageCard($appl, 'all', $navBase)
            . $this->searchScript('signage');
    }

    private function signageDetail(Appliances $appl, string $id, string $navBase): string
    {
        $s = $appl->signage($id);
        $base = $navBase . '/appliances/signage/' . $id;
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'],
                   ['Digital signage', $navBase . '/appliances/signage'], [$s['name'], '']];
        $kv = $this->kvTableHtml([
            ['Screen id', $s['id']],
            ['Model', $s['model']],
            ['Location', $s['floorLabel'] . ' — ' . $s['room'] . ' (' . $s['zone'] . ')'],
            ['Current content', $s['content']],
            ['Orientation', $s['orientation']],
            ['Resolution', $s['resolution']],
            ['Power', $s['power']],
            ['Brightness', $s['brightnessPct'] . ' %'],
            ['Last sync', $s['lastSync']],
            ['Controller', $s['controllerIp']],
            ['Firmware', $s['firmware']],
        ], ' class="alte-kv"');
        $powerTo = $s['power'] === 'On' ? 'off' : 'on';
        $controls = '<div style="margin-bottom:10px">' . $this->toggleHtml('Screen power', $s['power'] === 'On', $base . '/power/' . $powerTo) . '</div>'
            . '<p style="margin:0"><a class="alte-btn" href="' . $this->esc($base . '/brightness/up') . '" style="text-decoration:none;padding:4px 12px;margin-right:6px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">Brighter</a>'
            . '<a class="alte-btn" href="' . $this->esc($base . '/brightness/down') . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">Dimmer</a></p>';
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Screen state', $kv, $s['name'])
            . $this->card('Controls', $controls, 'AV controller')
            . $this->emergencyMessageCard($appl, $id, $navBase);
    }

    /** The emergency-message push box — a POST form. Its "message pushed" leaf echoes the visitor's own
     *  last submission back (escaped, per ip, TTL'd) so a stored-vuln probe looks like it landed (E6:
     *  escaped, never executable). */
    private function emergencyMessageCard(Appliances $appl, string $scope, string $navBase): string
    {
        $action = $this->esc($navBase . '/appliances/signage/' . $scope . '/message');
        $form = '<form class="alte-form" method="post" action="' . $action . '">'
            . '<label style="display:block;margin-bottom:6px;font-weight:600">Emergency / broadcast message</label>'
            . '<textarea name="message" rows="3" style="width:100%;max-width:520px;padding:8px;border:1px solid #c9ccd1;border-radius:4px" placeholder="Message to push to all screens…"></textarea>'
            . '<div style="margin-top:8px"><button class="alte-btn" type="submit" style="padding:6px 14px;border:1px solid #3b7ea1;background:#3b7ea1;color:#fff;border-radius:4px;cursor:pointer">Push to screens</button></div>'
            . '</form>'
            . '<p class="fp-muted" style="font-size:.85em;color:#6c757d;margin-top:8px">Displayed on all powered screens until cleared.</p>';
        return $this->card('Push content', $form, 'signage broadcast');
    }

    private function signageControlLeaf(Appliances $appl, string $id, string $verb, string $arg, string $navBase, ?FakePersistence $persistence = null): string
    {
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'],
                   ['Digital signage', $navBase . '/appliances/signage'], ['Command', '']];
        if ($verb === 'message') {
            $count = $appl->signageCount();
            $rows = [
                ['Action', 'Broadcast message to signage'],
                ['Scope', $id === 'all' ? 'All screens' : 'Screen ' . $id],
                ['Result', 'Displayed on ' . $count . ' screen' . ($count === 1 ? '' : 's')],
            ];
            // Fake persistence: echo the visitor's OWN last pushed message (escaped by the kv table) so a
            // write-then-repoll looks stored. Bounded + per ip, never executable (spec E6 escape rule).
            $pushed = $persistence !== null ? $persistence->items(FakePersistence::signageMessageKey($id)) : [];
            if (isset($pushed[0]['message'])) {
                $rows[] = ['Message on air', $pushed[0]['message']];
                $rows[] = ['Status', 'Live on all powered screens until cleared'];
            } else {
                $rows[] = ['Note', 'Content stays until cleared'];
            }
            $rows[] = ['Job', $appl->commandId('signmsg|' . $id)];
            return $this->breadcrumbHtml($crumbs) . $this->controlResultCard('Message pushed', $rows);
        }
        $s = $appl->signage($id);
        if ($verb === 'power') {
            $what = 'Screen power → ' . ($arg === 'on' ? 'ON' : 'OFF');
        } else {
            $what = 'Brightness ' . ($arg === 'up' ? 'increase' : 'decrease');
        }
        return $this->breadcrumbHtml($crumbs) . $this->controlResultCard('Command queued — ' . $s['name'], [
            ['Command', $what],
            ['Target', $s['name'] . ' (' . $s['id'] . ')'],
            ['Controller', $s['controllerIp']],
            ['Status', 'Queued — applies at next AV-controller sync'],
            ['Job', $appl->commandId('sign|' . $id . '|' . $verb . '|' . $arg)],
        ]);
    }

    // --- PA / paging --------------------------------------------------------

    private function pa(Appliances $appl, array $route, VisualPersona $persona, string $navBase): string
    {
        $id = $route['entity'];
        if ($id === '' || $id === 'overview') {
            return $this->paList($appl, $navBase);
        }
        if ($id === 'broadcast') {
            return $this->paBroadcastReceipt($appl, $navBase);
        }
        $subtab = $route['subtab'];
        if (in_array($subtab, self::PA_CTL, true)) {
            return $this->paControlLeaf($appl, $id, $subtab, $route['action'], $navBase);
        }
        return $this->paZoneDetail($appl, $id, $navBase);
    }

    private function paList(Appliances $appl, string $navBase): string
    {
        $zones = $appl->paZones();
        $rows = '';
        foreach ($zones as $z) {
            $href = $this->esc($navBase . '/appliances/pa/' . $z['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($z['name']) . '</a></td>'
                . '<td>' . $this->esc((string) $z['speakers']) . '</td>'
                . '<td>' . $this->esc($z['volumePct'] . '%') . '</td>'
                . '<td>' . $this->pillHtml($z['state'], 'info') . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Zone</th><th>Speakers</th><th>Volume</th><th>State</th></tr></thead>';
        $table = '<table class="alte-table">' . $head . '<tbody>' . $rows . '</tbody></table>';
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'], ['PA / paging', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Paging zones', $table, count($zones) . ' zones · AV controller ' . Appliances::AV_CONTROLLER)
            . $this->paBroadcastCard($navBase);
    }

    private function paZoneDetail(Appliances $appl, string $id, string $navBase): string
    {
        $z = $appl->paZone($id);
        $base = $navBase . '/appliances/pa/' . $id;
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'],
                   ['PA / paging', $navBase . '/appliances/pa'], [$z['name'], '']];
        $kv = $this->kvTableHtml([
            ['Zone id', $z['id']],
            ['Name', $z['name']],
            ['Speakers', (string) $z['speakers']],
            ['Volume', $z['volumePct'] . ' %'],
            ['State', $z['state']],
        ], ' class="alte-kv"');
        $vol = (int) $z['volumePct'];
        $vdown = $this->esc($base . '/vol/' . max(0, $vol - 5));
        $vup = $this->esc($base . '/vol/' . min(100, $vol + 5));
        $controls = '<div style="display:flex;align-items:center;gap:12px;margin:6px 0">'
            . '<a class="alte-btn" href="' . $vdown . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">−</a>'
            . $this->levelBar($vol)
            . '<a class="alte-btn" href="' . $vup . '" style="text-decoration:none;padding:4px 12px;border:1px solid #c9ccd1;border-radius:4px;color:#2c3136">+</a>'
            . '<span style="font-weight:600;color:#2c3136">' . $this->esc($vol . ' %') . '</span></div>';
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Zone state', $kv, $z['name'])
            . $this->card('Volume', $controls, 'zone gain')
            . $this->paBroadcastCard($navBase);
    }

    private function paBroadcastCard(string $navBase): string
    {
        $action = $this->esc($navBase . '/appliances/pa/broadcast');
        $form = '<form class="alte-form" method="post" action="' . $action . '">'
            . '<label style="display:block;margin-bottom:6px;font-weight:600">Live page / broadcast</label>'
            . '<textarea name="page" rows="2" style="width:100%;max-width:520px;padding:8px;border:1px solid #c9ccd1;border-radius:4px" placeholder="Announcement text (text-to-speech)…"></textarea>'
            . '<div style="margin-top:8px"><button class="alte-btn" type="submit" style="padding:6px 14px;border:1px solid #3b7ea1;background:#3b7ea1;color:#fff;border-radius:4px;cursor:pointer">Send page</button></div>'
            . '</form>'
            . '<p class="fp-muted" style="font-size:.85em;color:#6c757d;margin-top:8px">Pre-chime then text-to-speech to the selected zones. Test system emits nothing.</p>';
        return $this->card('Send page', $form, 'PA / TTS');
    }

    private function paBroadcastReceipt(Appliances $appl, string $navBase): string
    {
        $zones = count($appl->paZones());
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'],
                   ['PA / paging', $navBase . '/appliances/pa'], ['Broadcast', '']];
        return $this->breadcrumbHtml($crumbs) . $this->controlResultCard('Page queued', [
            ['Action', 'Live page / broadcast'],
            ['Zones', 'All-call and ' . ($zones - 1) . ' others'],
            ['Result', 'Queued to the paging controller — pre-chime then TTS'],
            ['Note', 'Announcement text is not stored on this panel'],
            ['Job', $appl->commandId('pabroadcast')],
        ]);
    }

    private function paControlLeaf(Appliances $appl, string $id, string $verb, string $arg, string $navBase): string
    {
        $z = $appl->paZone($id);
        $base = $navBase . '/appliances/pa/' . $id;
        $crumbs = [['Corevance', $navBase], ['Appliances & AV', $navBase . '/appliances'],
                   ['PA / paging', $navBase . '/appliances/pa'], [$z['name'], $base], ['Command', '']];
        $what = $verb === 'vol' ? 'Zone volume → ' . $arg . ' %' : 'Broadcast to ' . $z['name'];
        return $this->breadcrumbHtml($crumbs) . $this->controlResultCard('Command queued — ' . $z['name'], [
            ['Command', $what],
            ['Target', $z['name'] . ' (' . $z['id'] . ')'],
            ['Controller', Appliances::AV_CONTROLLER],
            ['Status', 'Queued — applies at next AV-controller sync'],
            ['Job', $appl->commandId('pa|' . $id . '|' . $verb . '|' . $arg)],
        ]);
    }

    // --- shared widgets + helpers ------------------------------------------

    /** A visual on/off toggle rendered as a single link to the inert control leaf (state never changes). */
    private function toggleHtml(string $label, bool $on, string $href): string
    {
        $track = $on ? '#2e8b57' : '#c9ccd1';
        $knobX = $on ? '22' : '2';
        $svg = '<svg width="44" height="24" viewBox="0 0 44 24" style="vertical-align:middle">'
            . '<rect x="0" y="0" width="44" height="24" rx="12" fill="' . $track . '"/>'
            . '<circle cx="' . ($knobX + 10) . '" cy="12" r="9" fill="#ffffff"/></svg>';
        return '<a href="' . $this->esc($href) . '" style="text-decoration:none;display:inline-flex;align-items:center;gap:10px;color:#2c3136">'
            . '<strong>' . $this->esc($label) . '</strong>' . $svg
            . '<span class="fp-muted" style="font-size:.85em;color:#6c757d">' . $this->esc($on ? 'ON' : 'OFF') . '</span></a>';
    }

    /** A horizontal level bar (volume/brightness) — pure inline SVG, deterministic, no state. */
    private function levelBar(int $pct): string
    {
        $pct = $pct < 0 ? 0 : ($pct > 100 ? 100 : $pct);
        $w = (int) round($pct * 1.6); // 0..160
        return '<svg width="160" height="10" viewBox="0 0 160 10" style="vertical-align:middle">'
            . '<rect x="0" y="3" width="160" height="4" rx="2" fill="#e3e6e8"/>'
            . '<rect x="0" y="3" width="' . $w . '" height="4" rx="2" fill="#3b7ea1"/>'
            . '<circle cx="' . $w . '" cy="5" r="5" fill="#3b7ea1"/></svg>';
    }

    /** A track position / duration progress bar with a time reading. */
    private function progressBar(int $pos, int $dur): string
    {
        if ($dur <= 0) {
            $dur = 1;
        }
        $pct = (int) round($pos / $dur * 100);
        if ($pct > 100) {
            $pct = 100;
        }
        $fmt = static function (int $s): string {
            return sprintf('%d:%02d', intdiv($s, 60), $s % 60);
        };
        return '<div style="display:flex;align-items:center;gap:10px">'
            . '<span class="fp-muted" style="font-size:.8em;color:#6c757d">' . $this->esc($fmt($pos)) . '</span>'
            . $this->levelBar($pct)
            . '<span class="fp-muted" style="font-size:.8em;color:#6c757d">' . $this->esc($fmt($dur)) . '</span></div>';
    }

    /** A temperature bar showing the current boiler reading and its setpoint tick within a min-max range. */
    private function tempBar(int $temp, int $setpoint, int $min, int $max): string
    {
        $span = $max - $min;
        if ($span <= 0) {
            $span = 1;
        }
        $clamp = static function (int $v) use ($min, $max): int {
            return $v < $min ? $min : ($v > $max ? $max : $v);
        };
        $tx = (int) round(($clamp($temp) - $min) / $span * 160);
        $sx = (int) round(($clamp($setpoint) - $min) / $span * 160);
        $svg = '<svg width="160" height="16" viewBox="0 0 160 16" style="display:block;margin:0 auto">'
            . '<rect x="0" y="6" width="160" height="4" rx="2" fill="#e3e6e8"/>'
            . '<rect x="0" y="6" width="' . $tx . '" height="4" rx="2" fill="#c07a1a"/>'
            . '<line x1="' . $sx . '" y1="1" x2="' . $sx . '" y2="15" stroke="#2c3136" stroke-width="2"/></svg>';
        return '<div style="text-align:center">' . $svg
            . '<div class="fp-gauge-text" style="font-size:.82em;color:#5b636a">' . $this->esc($temp . ' °C · set ' . $setpoint . ' °C') . '</div>'
            . '<div class="fp-gauge-label" style="font-size:.72em;color:#9aa1a8;text-transform:uppercase;letter-spacing:.04em">Brew boiler</div></div>';
    }

    /** @param list<array<string,mixed>> $all @return array{0:list<array<string,mixed>>,1:int,2:int,3:int} */
    private function paginate(array $all, int $page): array
    {
        $total = count($all);
        if ($page < 1) {
            $page = 1;
        }
        $pages = $total > 0 ? (int) ceil($total / self::PER_PAGE) : 1;
        if ($page > $pages) {
            $page = $pages;
        }
        $slice = array_slice($all, ($page - 1) * self::PER_PAGE, self::PER_PAGE);
        return [$slice, $page, $pages, $total];
    }

    private function pager(string $base, int $total, int $page, int $pages, string $noun): string
    {
        $from = $total === 0 ? 0 : (($page - 1) * self::PER_PAGE) + 1;
        $to = min($page * self::PER_PAGE, $total);
        $summary = 'Showing ' . $from . '&ndash;' . $to . ' of ' . number_format($total) . ' ' . $this->esc($noun);
        return $this->pagerHtml($base, $page, $pages, $summary);
    }

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

    /** Progressive-enhancement search box (client-side row filter); degrades to showing all rows. */
    private function searchBox(string $cat): string
    {
        return '<input type="text" id="appl-' . $cat . '-search" placeholder="Filter…" '
            . 'style="margin:0 0 10px;padding:6px 10px;border:1px solid #c9ccd1;border-radius:4px;width:100%;max-width:320px" '
            . 'aria-label="Filter rows">';
    }

    /** Vanilla, self-contained row filter — no external code, no state change (spec R1 / D.5). */
    private function searchScript(string $cat): string
    {
        $c = $this->esc($cat);
        return '<script>(function(){var i=document.getElementById("appl-' . $c . '-search"),'
            . 't=document.getElementById("appl-' . $c . '");if(!i||!t)return;'
            . 'i.addEventListener("input",function(){var q=i.value.toLowerCase(),'
            . 'r=t.tBodies[0]?t.tBodies[0].rows:[];for(var k=0;k<r.length;k++){'
            . 'r[k].style.display=r[k].textContent.toLowerCase().indexOf(q)>-1?"":"none";}});})();</script>';
    }

    /** Local seeded hash for section-only trend/log lines (kept off the generator; deterministic per string). */
    private function slotHash(string $s): int
    {
        return (int) hexdec(substr(hash('sha256', 'appl-sec|' . $s), 0, 12));
    }
}
