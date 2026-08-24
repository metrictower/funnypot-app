<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Facilities;
use Funnypot\App\Render\VisualPersona;

/**
 * Facilities (spec §C.1 / §C.9) — the building FLOORPLAN hub and the maintenance fault-chain hub. It is
 * the spatial index into every building-side module and the target of the "one step short" anomaly links
 * that HVAC / sensors / energy plant elsewhere. Renders the five-rung ladder over the `Fake\Facilities`
 * view of the Building/Org spines:
 *
 *   - a FLOORPLAN hub: an inline-SVG floor map (a rect per room, each an <a> into that room) with a floor
 *     selector, tinted by seeded room status — a spatial index onto the whole building estate;
 *   - ROOMS: a paginated list -> per-room DETAIL (occupancy, the devices in the room cross-linked into
 *     HVAC/lighting/access/CCTV/sensors, and its bookings). This detail serves both `/facilities/rooms/<id>`
 *     and the bare `/rooms/<id>` link other modules already emit;
 *   - MEETING-ROOM BOOKINGS: an inline week calendar whose entries reference the Org roster (the title/
 *     organiser leak is a real cross-reference into the directory);
 *   - WORK ORDERS: a paginated list -> per-order DETAIL. This serves `/facilities/work-orders/<WO>`, the
 *     target of the sensor/energy/HVAC fault links. A work order is derived purely from its id number, so
 *     the SAME `WO-YYYY-NNNNNN` renders identically whether reached from a sensor leak or the list, and
 *     most read one step short ("awaiting parts / awaiting contractor") with a "see also FM-####" cross-ref.
 *
 * The whole surface is INERT: room/work-order controls land on the canned "queued" receipt and nothing is
 * persisted, so a detail page always shows its seeded state. Every list uses pagerHtml so deep pages stay
 * reachable. A fuzzed room/work-order slug still renders a plausible detail — a 404 inside a deep panel is
 * a tell.
 *
 * Route slots (PanelRoute): this section is registered for module `facilities` and the aliases
 * `floorplan` / `rooms` / `work-orders` / `meeting-rooms` / `bookings`; render() normalises whichever
 * mount it was reached through into an internal (view, id, sub) tuple.
 */
final class FacilitiesSection extends AbstractPanelSection
{
    private const PAGE_SIZE = 50;

    /** Control verbs in a room's action slot; anything else there is a detail sub-tab. */
    private const ROOM_VERBS = ['raise-wo', 'book'];

    /** Control verbs in a work order's action slot. */
    private const WO_VERBS = ['close', 'add-note', 'reassign'];

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $fac = Facilities::fromSeed($persona->seed(), $persona->domain());
        [$view, $id, $sub] = $this->normalize($route);
        $page = $route['page'];
        $seed = $persona->seed();

        switch ($view) {
            case 'floorplan':
                return $this->floorplanView($fac, $navBase, $id);
            case 'rooms':
                return $id === ''
                    ? $this->roomsList($fac, $navBase, $page)
                    : $this->roomDispatch($fac, $navBase, $id, $sub, $seed);
            case 'work-orders':
                return $id === ''
                    ? $this->workOrdersList($fac, $navBase, $page)
                    : $this->workOrderDispatch($fac, $navBase, $id, $sub, $seed);
            case 'bookings':
                return $id === ''
                    ? $this->bookingsLanding($fac, $navBase)
                    : $this->bookingDetail($fac, $navBase, $id, $sub, $seed);
            default:
                return $this->hub($fac, $navBase);
        }
    }

    /**
     * Fold whichever mount/alias this was reached through into (view, id, sub). `facilities` is the hub
     * with named sections; the aliases root a single view directly (so the bare `/rooms/<id>` and
     * `/facilities/work-orders/<WO>` links other modules emit both land here).
     *
     * @return array{0:string,1:string,2:string}
     */
    private function normalize(array $route): array
    {
        $module = $route['module'];
        if ($module === 'rooms') {
            return ['rooms', $route['section'], $route['entity']];
        }
        if ($module === 'meeting-rooms' || $module === 'bookings') {
            return ['bookings', $route['section'], $route['entity']];
        }
        if ($module === 'work-orders' || $module === 'workorders') {
            return ['work-orders', $route['section'], $route['entity']];
        }
        if ($module === 'floorplan') {
            return ['floorplan', $route['section'], $route['entity']];
        }
        // module === 'facilities' (or any unknown module the registry routed here) -> hub with sections.
        switch ($route['section']) {
            case 'floorplan':
                return ['floorplan', $route['entity'], $route['subtab']];
            case 'rooms':
                return ['rooms', $route['entity'], $route['subtab']];
            case 'work-orders':
            case 'workorders':
                return ['work-orders', $route['entity'], $route['subtab']];
            case 'meeting-rooms':
            case 'bookings':
                return ['bookings', $route['entity'], $route['subtab']];
            default:
                return ['hub', '', ''];
        }
    }

    // --- hub: tiles + floorplan of a default floor + jump-off links ---

    private function hub(Facilities $fac, string $navBase): string
    {
        $s = $fac->summary();
        $tiles = $this->statCardsHtml([
            ['label' => 'Occupancy', 'value' => $s['occupied'] . '/' . $s['occupancyDesign'], 'sub' => 'people on site'],
            ['label' => 'Zones in comfort', 'value' => $s['zonesInComfort'] . '/' . $s['zonesTotal']],
            ['label' => 'Open work orders', 'value' => (string) $s['openWorkOrders']],
            ['label' => 'Active alarms', 'value' => (string) $s['activeAlarms']],
            ['label' => 'Energy now', 'value' => $s['energyKw'] . ' kW'],
            ['label' => 'Doors unsecured', 'value' => (string) $s['doorsUnsecured']],
            ['label' => 'Cameras online', 'value' => $s['camerasOnline'] . '/' . $s['camerasTotal']],
            ['label' => 'Rooms free', 'value' => $s['roomsFree'] . '/' . $s['meetingTotal']],
        ], 'fp-tiles', 'fp-tile');

        $links = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin:12px 0">'
            . $this->actionLink($navBase . '/facilities/floorplan', 'Building map', false)
            . $this->actionLink($navBase . '/facilities/rooms', 'Rooms', false)
            . $this->actionLink($navBase . '/facilities/bookings', 'Meeting rooms', false)
            . $this->actionLink($navBase . '/facilities/work-orders', 'Work orders', false)
            . '</div>';

        $default = $this->defaultFloorCode($fac);
        $map = $this->floorplanCard($fac, $navBase, $default);

        $site = $fac->site();
        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Facilities'))
            . $tiles
            . $links
            . $map
            . $this->card('Site', $this->kvTableHtml([
                ['Building', $site['name']],
                ['Site code', $site['code']],
                ['Address', $site['street'] . ', ' . $site['city']],
                ['Timezone', $site['timezone']],
                ['Gross area', number_format($site['grossAreaSqm']) . ' m²'],
                ['Floors', (string) $site['floors']],
                ['Rooms', (string) $site['rooms']],
            ], ' class="alte-kv"'), 'as surveyed');
    }

    private function defaultFloorCode(Facilities $fac): string
    {
        $floors = $fac->floors();
        foreach ($floors as $f) {
            if ($f['code'] === 'G') {
                return 'G';
            }
        }
        return $floors[0]['code'];
    }

    // --- floorplan view ---

    private function floorplanView(Facilities $fac, string $navBase, string $floorSlug): string
    {
        $floorCode = $this->resolveFloor($fac, $floorSlug);
        $crumbs = [
            ['Corevance', $navBase],
            ['Facilities', $navBase . '/facilities'],
            ['Building map', ''],
        ];
        return $this->breadcrumbHtml($crumbs) . $this->floorplanCard($fac, $navBase, $floorCode);
    }

    /** Match a floor slug (lowercased code) to a real floor code; default to the ground/first floor. */
    private function resolveFloor(Facilities $fac, string $floorSlug): string
    {
        foreach ($fac->floors() as $f) {
            if (strtolower($f['code']) === $floorSlug) {
                return $f['code'];
            }
        }
        return $this->defaultFloorCode($fac);
    }

    /** The floor selector + the inline-SVG floor map, wrapped in a card. */
    private function floorplanCard(Facilities $fac, string $navBase, string $floorCode): string
    {
        $selector = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px">';
        foreach ($fac->floors() as $f) {
            $href = $this->esc($navBase . '/facilities/floorplan/' . strtolower($f['code']));
            if ($f['code'] === $floorCode) {
                $selector .= '<span class="alte-tab is-active" style="padding:5px 11px;border-radius:4px;'
                    . 'background:#3b7ea1;color:#fff;font-size:.82em;font-weight:600">' . $this->esc($f['label']) . '</span>';
            } else {
                $selector .= '<a class="alte-tab" style="padding:5px 11px;border-radius:4px;border:1px solid #cfd6dc;'
                    . 'color:#3b7ea1;text-decoration:none;font-size:.82em" href="' . $href . '">' . $this->esc($f['label']) . '</a>';
            }
        }
        $selector .= '</div>';

        $rooms = $fac->roomsOnFloor($floorCode);
        $svg = $this->floorplanSvg($rooms, $navBase);
        $legend = '<div style="margin-top:8px;font-size:.78em;color:#6c757d">'
            . '<span style="color:#2e8b57">●</span> occupied &nbsp; '
            . '<span style="color:#9aa1a8">●</span> vacant &nbsp; '
            . '<span style="color:#c07a1a">●</span> fault</div>';

        $label = '';
        foreach ($fac->floors() as $f) {
            if ($f['code'] === $floorCode) {
                $label = $f['label'];
                break;
            }
        }
        return $this->card('Floor map — ' . $label, $selector . $svg . $legend, count($rooms) . ' rooms');
    }

    /** An inline-SVG floor map: one <a>-wrapped rect per room, tinted by status, linking into the room. */
    private function floorplanSvg(array $rooms, string $navBase): string
    {
        $cols = 5;
        $cellW = 120;
        $cellH = 66;
        $gap = 8;
        $pad = 6;
        $n = count($rooms);
        $rows = $n === 0 ? 1 : (int) ceil($n / $cols);
        $w = $cols * ($cellW + $gap) - $gap + 2 * $pad;
        $hgt = $rows * ($cellH + $gap) - $gap + 2 * $pad;

        $body = '';
        foreach ($rooms as $i => $r) {
            $c = $i % $cols;
            $row = (int) ($i / $cols);
            $x = $pad + $c * ($cellW + $gap);
            $y = $pad + $row * ($cellH + $gap);
            [$fill, $dot] = $this->statusColors($r['status']);
            $href = $this->esc($navBase . '/facilities/rooms/' . $r['id']);
            $cx = $x + 12;
            $cy = $y + 14;
            $tx = $x + 22;
            $body .= '<a href="' . $href . '">'
                . '<rect x="' . $x . '" y="' . $y . '" width="' . $cellW . '" height="' . $cellH
                . '" rx="4" fill="' . $fill . '" stroke="#a7b0b8"/>'
                . '<circle cx="' . $cx . '" cy="' . $cy . '" r="4" fill="' . $dot . '"/>'
                . '<text x="' . $tx . '" y="' . ($cy + 4) . '" font-size="11" font-family="sans-serif" '
                . 'font-weight="bold" fill="#1b1e21">' . $this->esc($this->clip($r['name'], 14)) . '</text>'
                . '<text x="' . ($x + 8) . '" y="' . ($y + 34) . '" font-size="9" font-family="sans-serif" '
                . 'fill="#4a525a">' . $this->esc($this->clip($r['type'], 16)) . '</text>'
                . '<text x="' . ($x + 8) . '" y="' . ($y + 50) . '" font-size="8.5" font-family="sans-serif" '
                . 'fill="#6c757d">' . $this->esc($r['zone'] . ' · cap ' . $r['capacity']) . '</text>'
                . '</a>';
        }

        return '<div style="overflow-x:auto"><svg viewBox="0 0 ' . $w . ' ' . $hgt . '" '
            . 'preserveAspectRatio="xMidYMid meet" style="width:100%;max-width:' . $w . 'px;height:auto;display:block" '
            . 'role="img" aria-label="Floor plan">' . $body . '</svg></div>';
    }

    private function statusColors(string $status): array
    {
        if ($status === 'occupied') {
            return ['#e6f0e6', '#2e8b57'];
        }
        if ($status === 'fault') {
            return ['#f7ecd9', '#c07a1a'];
        }
        return ['#eef1f3', '#9aa1a8'];
    }

    // --- rooms list + detail ---

    private function roomsList(Facilities $fac, string $navBase, int $page): string
    {
        $total = $fac->roomCount();
        $pages = (int) ceil($total / self::PAGE_SIZE);
        if ($pages < 1) {
            $pages = 1;
        }
        $page = $page < 1 ? 1 : ($page > $pages ? $pages : $page);
        $offset = ($page - 1) * self::PAGE_SIZE;
        $rooms = $fac->roomsPage($offset, self::PAGE_SIZE);

        $rows = '';
        foreach ($rooms as $r) {
            $href = $this->esc($navBase . '/facilities/rooms/' . $r['id']);
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($r['name']) . '</a></td>'
                . '<td>' . $this->esc(strtoupper($r['floor'])) . '</td>'
                . '<td>' . $this->esc($r['zone']) . '</td>'
                . '<td>' . $this->esc($r['type']) . '</td>'
                . '<td>' . $this->esc((string) $r['capacity']) . '</td>'
                . '<td>' . $this->pillHtml($this->statusLabel($r['status']), $this->statusPill($r['status'])) . '</td>'
                . '<td>' . $this->esc($r['status'] === 'occupied' ? $r['occupants'] . ' in room' : '—') . '</td>'
                . '</tr>';
        }
        $search = '<input id="fac-room-q" type="search" placeholder="Filter rooms…" '
            . 'style="margin-bottom:10px;padding:6px 10px;width:100%;max-width:300px;box-sizing:border-box" autocomplete="off">';
        $table = '<div style="overflow-x:auto"><table id="fac-room-tbl" class="alte-table">'
            . '<thead><tr><th>Room</th><th>Floor</th><th>Zone</th><th>Type</th><th>Cap</th><th>Status</th><th>Occupancy</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';

        $from = $total === 0 ? 0 : $offset + 1;
        $to = $offset + count($rooms);
        $summary = 'Showing ' . number_format($from) . '&ndash;' . number_format($to) . ' of ' . number_format($total) . ' rooms';
        $pager = $this->pagerHtml($navBase . '/facilities/rooms', $page, $pages, $summary);

        $crumbs = [['Corevance', $navBase], ['Facilities', $navBase . '/facilities'], ['Rooms', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Rooms', $search . $table . $pager . $this->filterScript('fac-room-q', 'fac-room-tbl'),
                number_format($total) . ' rooms');
    }

    /** A room path is either a detail sub-tab or a control verb. */
    private function roomDispatch(Facilities $fac, string $navBase, string $id, string $sub, int $seed): string
    {
        $room = $fac->room($id);
        if ($sub !== '' && in_array($sub, self::ROOM_VERBS, true)) {
            return $this->roomControl($navBase, $room, $sub, $seed);
        }
        return $this->roomDetail($fac, $navBase, $room, $sub === '' ? 'overview' : $sub);
    }

    private function roomDetail(Facilities $fac, string $navBase, array $room, string $subtab): string
    {
        $roomBase = $navBase . '/facilities/rooms/' . $room['id'];
        $crumbs = [
            ['Corevance', $navBase],
            ['Facilities', $navBase . '/facilities'],
            ['Rooms', $navBase . '/facilities/rooms'],
            [$room['name'], ''],
        ];
        $tabDefs = ['overview' => 'Overview', 'devices' => 'Devices'];
        if ($room['bookable']) {
            $tabDefs['bookings'] = 'Bookings';
        }
        $tabs = $this->tabStrip($roomBase, $subtab, $tabDefs);

        switch ($subtab) {
            case 'devices':
                $body = $this->roomDevicesCard($fac, $navBase, $room);
                break;
            case 'bookings':
                $body = $room['bookable']
                    ? $this->calendarCard($fac, $navBase, $room)
                    : $this->roomOverviewCard($fac, $navBase, $room);
                break;
            default:
                $body = $this->roomOverviewCard($fac, $navBase, $room);
        }
        return $this->breadcrumbHtml($crumbs) . $tabs . $body;
    }

    private function roomOverviewCard(Facilities $fac, string $navBase, array $room): string
    {
        $roomBase = $navBase . '/facilities/rooms/' . $room['id'];
        $devices = $fac->devicesInRoom($room['id']);
        $kv = $this->kvTableHtml([
            ['Room id', $room['id']],
            ['Name', $room['name']],
            ['Floor', strtoupper((string) $room['floor'])],
            ['Zone', $room['zone']],
            ['Type', $room['type']],
            ['Capacity', (string) $room['capacity']],
            ['Area', $room['areaSqm'] . ' m²'],
            ['Status', $this->statusLabel($room['status'])],
            ['Occupancy', $room['status'] === 'occupied' ? $room['occupants'] . ' of ' . $room['capacity'] : 'vacant'],
            ['Devices', (string) count($devices)],
        ], ' class="alte-kv"');

        $controls = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">'
            . $this->actionLink($roomBase . '/raise-wo', 'Raise work order', false);
        if ($room['bookable']) {
            $controls .= $this->actionLink($roomBase . '/book', 'Book room', false);
        }
        $controls .= '</div>';

        $body = $this->card($room['name'], $kv . $controls, $room['type'] . ' · ' . $this->statusLabel($room['status']));

        // A faulty room points at its work order (the map's amber dot leads here) — the fault-chain start.
        if ($room['status'] === 'fault') {
            $wo = $fac->workOrder('WO-2026-' . sprintf('%06d', $this->faultWoNumber($room['id'])));
            $woHref = $this->esc($navBase . '/facilities/work-orders/' . strtolower($wo['id']));
            $note = '<p style="margin:0">Open fault on this room — work order '
                . '<a class="alte-dl" href="' . $woHref . '">' . $this->esc($wo['id']) . '</a> ('
                . $this->esc($wo['status']) . ').</p>';
            $body .= $this->card('Maintenance', $note, 'fault');
        }
        return $body;
    }

    private function roomDevicesCard(Facilities $fac, string $navBase, array $room): string
    {
        $devices = $fac->devicesInRoom($room['id']);
        if ($devices === []) {
            return $this->card('Devices in room', '<p class="alte-muted" style="margin:0">No addressable devices in this room.</p>', $room['name']);
        }
        $rows = '';
        foreach ($devices as $d) {
            $href = $this->esc($navBase . '/' . $d['module'] . '/' . $d['id']);
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($d['id']) . '</a></td>'
                . '<td>' . $this->esc($d['type']) . '</td>'
                . '<td>' . $this->esc($d['controller']) . '</td>'
                . '<td>' . $this->pillHtml($d['state'], $this->deviceStatePill($d['state'])) . '</td>'
                . '<td>' . $this->esc($d['lastSeen']) . '</td>'
                . '</tr>';
        }
        $table = '<div style="overflow-x:auto"><table class="alte-table">'
            . '<thead><tr><th>Device</th><th>Type</th><th>Controller</th><th>State</th><th>Last seen</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        return $this->card('Devices in room', $table, count($devices) . ' devices · cross-linked to their controllers');
    }

    /** A deterministic work-order number for a faulty room, so the map dot and detail agree. */
    private function faultWoNumber(string $roomId): int
    {
        return 4000 + (int) hexdec(substr(hash('sha256', $roomId . '|faultwo'), 0, 8)) % 6000;
    }

    private function roomControl(string $navBase, array $room, string $verb, int $seed): string
    {
        $roomBase = $navBase . '/facilities/rooms/' . $room['id'];
        $crumbs = [
            ['Corevance', $navBase],
            ['Facilities', $navBase . '/facilities'],
            ['Rooms', $navBase . '/facilities/rooms'],
            [$room['name'], $roomBase],
            [ucfirst(str_replace('-', ' ', $verb)), ''],
        ];
        if ($verb === 'book') {
            $detail = [
                ['Room', $room['name'] . ' (' . $room['id'] . ')'],
                ['Job', $this->cmdRef($seed, $room['id'] . '|book')],
                ['Status', 'provisional hold placed; confirms after organiser accepts (~2 min)'],
            ];
            return $this->breadcrumbHtml($crumbs)
                . $this->controlResultCard('Book room — ' . $room['name'], $detail);
        }
        // raise-wo
        $detail = [
            ['Location', $room['name'] . ' (' . $room['id'] . ')'],
            ['Ticket', $this->cmdRef($seed, $room['id'] . '|wo')],
            ['Status', 'work order created; a facilities coordinator picks it up within 15 minutes'],
        ];
        return $this->breadcrumbHtml($crumbs)
            . $this->controlResultCard('Raise work order — ' . $room['name'], $detail);
    }

    // --- meeting-room bookings ---

    private function bookingsLanding(Facilities $fac, string $navBase): string
    {
        $rooms = $fac->meetingRooms();
        $rows = '';
        foreach ($rooms as $r) {
            $href = $this->esc($navBase . '/facilities/bookings/' . $r['id']);
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($r['name']) . '</a></td>'
                . '<td>' . $this->esc(strtoupper((string) $r['floor'])) . '</td>'
                . '<td>' . $this->esc($r['type']) . '</td>'
                . '<td>' . $this->esc((string) $r['capacity']) . '</td>'
                . '<td>' . $this->pillHtml($this->statusLabel($r['status']), $this->statusPill($r['status'])) . '</td>'
                . '</tr>';
        }
        $search = '<input id="fac-mr-q" type="search" placeholder="Filter meeting rooms…" '
            . 'style="margin-bottom:10px;padding:6px 10px;width:100%;max-width:300px;box-sizing:border-box" autocomplete="off">';
        $table = '<div style="overflow-x:auto"><table id="fac-mr-tbl" class="alte-table">'
            . '<thead><tr><th>Room</th><th>Floor</th><th>Type</th><th>Cap</th><th>Now</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';

        $crumbs = [['Corevance', $navBase], ['Facilities', $navBase . '/facilities'], ['Meeting rooms', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Meeting rooms', $search . $table . $this->filterScript('fac-mr-q', 'fac-mr-tbl'),
                count($rooms) . ' bookable rooms · week of ' . $fac->weekMondayYmd());
    }

    private function bookingDetail(Facilities $fac, string $navBase, string $id, string $sub, int $seed): string
    {
        $room = $fac->room($id);
        if ($sub === 'book') {
            $roomBase = $navBase . '/facilities/bookings/' . $room['id'];
            $crumbs = [
                ['Corevance', $navBase],
                ['Facilities', $navBase . '/facilities'],
                ['Meeting rooms', $navBase . '/facilities/bookings'],
                [$room['name'], $roomBase],
                ['Book', ''],
            ];
            $detail = [
                ['Room', $room['name'] . ' (' . $room['id'] . ')'],
                ['Job', $this->cmdRef($seed, $room['id'] . '|book')],
                ['Status', 'provisional hold placed; confirms after organiser accepts (~2 min)'],
            ];
            return $this->breadcrumbHtml($crumbs)
                . $this->controlResultCard('Book room — ' . $room['name'], $detail);
        }
        return $this->calendarView($fac, $navBase, $room);
    }

    private function calendarView(Facilities $fac, string $navBase, array $room): string
    {
        $crumbs = [
            ['Corevance', $navBase],
            ['Facilities', $navBase . '/facilities'],
            ['Meeting rooms', $navBase . '/facilities/bookings'],
            [$room['name'], ''],
        ];
        return $this->breadcrumbHtml($crumbs) . $this->calendarCard($fac, $navBase, $room);
    }

    /** The inline week-calendar grid + a booking list + an inert book control. */
    private function calendarCard(Facilities $fac, string $navBase, array $room): string
    {
        $events = $fac->bookings($room['id']);
        // Index events by [day][hour] so the grid can mark start + continuation cells.
        $byCell = [];
        foreach ($events as $e) {
            for ($hr = $e['start']; $hr < $e['end']; $hr++) {
                $byCell[$e['day'] . ':' . $hr] = ['event' => $e, 'start' => $hr === $e['start']];
            }
        }
        $dayNames = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'];
        $head = '<tr><th style="width:52px">Time</th>';
        foreach ($dayNames as $i => $dn) {
            $head .= '<th>' . $this->esc($dn . ' ' . $fac->weekdayYmd($i)) . '</th>';
        }
        $head .= '</tr>';

        $body = '';
        for ($hr = 8; $hr <= 18; $hr++) {
            $body .= '<tr><td style="font-size:.8em;color:#6c757d;white-space:nowrap">' . sprintf('%02d:00', $hr) . '</td>';
            for ($d = 0; $d < 5; $d++) {
                $cell = $byCell[$d . ':' . $hr] ?? null;
                if ($cell === null) {
                    $body .= '<td style="border:1px solid #eef1f3"></td>';
                } elseif ($cell['start']) {
                    $e = $cell['event'];
                    $body .= '<td style="border:1px solid #cfe0d6;background:#e6f0e6;vertical-align:top">'
                        . '<div style="font-size:.8em;font-weight:600;color:#1b1e21">' . $this->esc($this->clip($e['title'], 28)) . '</div>'
                        . '<div style="font-size:.72em;color:#4a525a">' . $this->esc($e['organizer']) . '</div></td>';
                } else {
                    $body .= '<td style="border:1px solid #cfe0d6;background:#eef6ef"></td>';
                }
            }
            $body .= '</tr>';
        }
        $grid = '<div style="overflow-x:auto"><table class="alte-table" style="min-width:640px">'
            . '<thead>' . $head . '</thead><tbody>' . $body . '</tbody></table></div>';

        // The booking list (organiser cross-links leak into the directory).
        $listRows = [];
        foreach ($events as $e) {
            $listRows[] = [
                $dayNames[$e['day']] . ' ' . sprintf('%02d:00', $e['start']) . '–' . sprintf('%02d:00', $e['end']),
                $e['title'],
                $e['organizer'] . ' <' . $e['organizerEmail'] . '>',
            ];
        }
        $list = $this->tableHtml(['When', 'Title', 'Organiser'], $listRows, ' class="alte-table"');

        $roomBase = $navBase . '/facilities/bookings/' . $room['id'];
        $book = '<div class="alte-actions" style="margin-top:12px">'
            . $this->actionLink($roomBase . '/book', 'Book room', false) . '</div>';

        return $this->card('Bookings — ' . $room['name'], $grid . $book, 'week of ' . $fac->weekMondayYmd())
            . $this->card('This week', $list, count($events) . ' bookings');
    }

    // --- work orders list + detail ---

    private function workOrdersList(Facilities $fac, string $navBase, int $page): string
    {
        $total = $fac->workOrderCount();
        $pages = (int) ceil($total / self::PAGE_SIZE);
        if ($pages < 1) {
            $pages = 1;
        }
        $page = $page < 1 ? 1 : ($page > $pages ? $pages : $page);
        $offset = ($page - 1) * self::PAGE_SIZE;
        $wos = $fac->workOrderPage($offset, self::PAGE_SIZE);

        $rows = '';
        foreach ($wos as $w) {
            $href = $this->esc($navBase . '/facilities/work-orders/' . strtolower($w['id']));
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($w['id']) . '</a></td>'
                . '<td>' . $this->esc($w['title']) . '</td>'
                . '<td>' . $this->esc($w['category']) . '</td>'
                . '<td>' . $this->pillHtml($w['priority'], $this->priorityPill($w['priority'])) . '</td>'
                . '<td>' . $this->pillHtml($w['status'], $this->woStatusPill($w['status'])) . '</td>'
                . '<td>' . $this->esc($w['assignee']) . '</td>'
                . '<td>' . $this->esc($w['opened']) . '</td>'
                . '</tr>';
        }
        $search = '<input id="fac-wo-q" type="search" placeholder="Filter by title, category, assignee, status…" '
            . 'style="margin-bottom:10px;padding:6px 10px;width:100%;max-width:360px;box-sizing:border-box" autocomplete="off">';
        $table = '<div style="overflow-x:auto"><table id="fac-wo-tbl" class="alte-table">'
            . '<thead><tr><th>Work order</th><th>Title</th><th>Category</th><th>Priority</th><th>Status</th><th>Assignee</th><th>Opened</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';

        $from = $total === 0 ? 0 : $offset + 1;
        $to = $offset + count($wos);
        $summary = 'Showing ' . number_format($from) . '&ndash;' . number_format($to) . ' of ' . number_format($total) . ' work orders';
        $pager = $this->pagerHtml($navBase . '/facilities/work-orders', $page, $pages, $summary);

        $crumbs = [['Corevance', $navBase], ['Facilities', $navBase . '/facilities'], ['Work orders', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Work orders', $search . $table . $pager . $this->filterScript('fac-wo-q', 'fac-wo-tbl'),
                number_format($total) . ' orders · ' . $fac->openWorkOrderCount() . ' open');
    }

    private function workOrderDispatch(Facilities $fac, string $navBase, string $id, string $sub, int $seed): string
    {
        $wo = $fac->workOrder($id);
        if ($sub !== '' && in_array($sub, self::WO_VERBS, true)) {
            return $this->workOrderControl($navBase, $wo, $sub, $seed);
        }
        return $this->workOrderDetail($fac, $navBase, $wo, $id);
    }

    private function workOrderDetail(Facilities $fac, string $navBase, array $wo, string $slug): string
    {
        $woBase = $navBase . '/facilities/work-orders/' . strtolower($wo['id']);
        $crumbs = [
            ['Corevance', $navBase],
            ['Facilities', $navBase . '/facilities'],
            ['Work orders', $navBase . '/facilities/work-orders'],
            [$wo['id'], ''],
        ];

        $assignee = $wo['assigneeKind'] === 'in-house'
            ? $wo['assignee'] . ' <' . $wo['assigneeEmail'] . '>'
            : $wo['assignee'] . ' (external contractor)';
        $roomHref = $this->esc($navBase . '/facilities/rooms/' . $wo['assetRoomId']);
        $seeAlsoHref = $this->esc($navBase . '/facilities/work-orders/' . strtolower($wo['seeAlso']));

        $kv = $this->kvTableHtml([
            ['Work order', $wo['id']],
            ['Title', $wo['title']],
            ['Category', $wo['category']],
            ['Priority', $wo['priority']],
            ['Status', $wo['status']],
            ['Assignee', $assignee],
            ['Opened', $wo['opened']],
            ['SLA due', $wo['sla']],
        ], ' class="alte-kv"');

        $asset = '<p style="margin:8px 0 0">Linked asset: <a class="alte-dl" href="' . $roomHref . '">'
            . $this->esc($wo['assetLabel']) . '</a></p>'
            . '<p style="margin:6px 0 0">See also: <a class="alte-dl" href="' . $seeAlsoHref . '">'
            . $this->esc($wo['seeAlso']) . '</a></p>';

        $woBaseC = $woBase;
        $controls = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">'
            . $this->actionLink($woBaseC . '/add-note', 'Add note', false)
            . $this->actionLink($woBaseC . '/reassign', 'Reassign', false)
            . $this->actionLink($woBaseC . '/close', 'Close work order', false)
            . '</div>';

        $notes = $this->preScrollHtml($fac->workOrderNotes($slug), 'alte-log');

        $files = [
            ['file' => 'quote_' . strtolower($wo['id']) . '.pdf.zip', 'cells' => ['Contractor quote', 'PDF (zip)']],
            ['file' => 'method_statement_' . strtolower($wo['id']) . '.pdf.zip', 'cells' => ['Method statement', 'PDF (zip)']],
        ];
        $attachments = $this->downloadTableHtml(['File', 'Item', 'Format'], $files, $navBase, '/facilities/download', ' class="alte-table"', 'alte-dl');

        return $this->breadcrumbHtml($crumbs)
            . $this->card($wo['id'], $kv . $asset . $controls, $wo['category'] . ' · ' . $wo['priority'] . ' · ' . $wo['status'])
            . $this->card('Notes', $notes, 'thread')
            . $this->card('Attachments', $attachments, $wo['id']);
    }

    private function workOrderControl(string $navBase, array $wo, string $verb, int $seed): string
    {
        $woBase = $navBase . '/facilities/work-orders/' . strtolower($wo['id']);
        $crumbs = [
            ['Corevance', $navBase],
            ['Facilities', $navBase . '/facilities'],
            ['Work orders', $navBase . '/facilities/work-orders'],
            [$wo['id'], $woBase],
            [ucfirst(str_replace('-', ' ', $verb)), ''],
        ];
        $statusText = [
            'close' => 'closure queued; awaiting supervisor sign-off before the order is archived (~2 min)',
            'add-note' => 'note queued; appears on the thread at next helpdesk sync (~2 min)',
            'reassign' => 'reassignment queued; the new owner is notified at next helpdesk sync (~2 min)',
        ];
        $detail = [
            ['Work order', $wo['id'] . ' · ' . $wo['title']],
            ['Job', $this->cmdRef($seed, $wo['id'] . '|' . $verb)],
            ['Status', $statusText[$verb] ?? 'queued'],
        ];
        return $this->breadcrumbHtml($crumbs)
            . $this->controlResultCard(ucfirst(str_replace('-', ' ', $verb)) . ' — ' . $wo['id'], $detail);
    }

    // --- small shared UI helpers (all escape-by-construction) ---

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

    /** A button-styled action link ($danger tints it as a scary verb; still just a link to a leaf). */
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
        return 'FAC-CMD-' . strtoupper(substr(hash('sha256', $seed . '|faccmd|' . $slot), 0, 6));
    }

    /** Truncate a label for a fixed-width SVG/grid cell, escape happens at the call site. */
    private function clip(string $s, int $max): string
    {
        if (function_exists('mb_strlen') && mb_strlen($s) > $max) {
            return rtrim(mb_substr($s, 0, $max - 1)) . '…';
        }
        if (strlen($s) > $max) {
            return rtrim(substr($s, 0, $max - 1)) . '…';
        }
        return $s;
    }

    private function statusLabel(string $status): string
    {
        if ($status === 'occupied') {
            return 'Occupied';
        }
        if ($status === 'fault') {
            return 'Fault';
        }
        return 'Vacant';
    }

    private function statusPill(string $status): string
    {
        if ($status === 'occupied') {
            return 'ok';
        }
        if ($status === 'fault') {
            return 'warn';
        }
        return 'idle';
    }

    private function deviceStatePill(string $state): string
    {
        if ($state === 'online') {
            return 'ok';
        }
        if ($state === 'fault') {
            return 'warn';
        }
        return 'idle';       // offline
    }

    private function priorityPill(string $priority): string
    {
        if ($priority === 'P1') {
            return 'crit';
        }
        if ($priority === 'P2') {
            return 'warn';
        }
        if ($priority === 'P3') {
            return 'info';
        }
        return 'idle';       // P4
    }

    private function woStatusPill(string $status): string
    {
        if ($status === 'Open') {
            return 'info';
        }
        if ($status === 'In progress' || $status === 'Scheduled') {
            return 'ok';
        }
        // Awaiting parts / Awaiting contractor / On hold — the "one step short" states.
        return 'warn';
    }
}
