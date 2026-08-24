<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Cmdb;
use Funnypot\App\Render\Fake\FrozenClock;
use Funnypot\App\Render\Fake\Integrations;
use Funnypot\App\Render\VisualPersona;

/**
 * IT Assets / CMDB + Integrations registry (spec §C.7; §F.3 #15). Two deep, read-only surfaces off one
 * module:
 *   - the asset INVENTORY / CMDB (Fake\Cmdb over the Org roster + Building rooms) — laptops/desktops/
 *     servers/phones/monitors/tablets, each assigned to a real person and located in a real room;
 *   - the INTEGRATIONS / device registry (Fake\Integrations over the Building controllers + a scaling
 *     network/OT fabric) — protocol endpoints (MQTT/BACnet/SNMP/Modbus/REST) as host:port on RFC1918,
 *     the juiciest lateral-move map in the panel.
 *
 * Everything is INERT (no controls; a registry/inventory is a read surface — the RCE-shaped bait lives in
 * MDM/Network, not here) and DETERMINISTIC per seed. The whole ladder is landing -> paginated+searchable
 * LIST (with a server-side filter) -> DETAIL with sub-tabs, so depth stays crawlable via pagerHtml.
 *
 * Route slots (PanelRoute), module = it:
 *   section = ''(landing) | assets | integrations (unknown falls back to the landing — a 404 is a tell).
 *   For assets:       entity = ''(list) | 'type' (filter; subtab = type value) | <asset-id> (subtab = sub-tab).
 *   For integrations: entity = ''(list) | 'protocol' (filter; subtab = proto slug) | <endpoint-id>.
 * When wired at the top level as module = integrations, the endpoint id / filter sits in the section slot;
 * that shift is normalised in render().
 */
final class ItAssetsSection extends AbstractPanelSection
{
    private const PER_PAGE_ASSETS = 50;
    private const PER_PAGE_ENDPOINTS = 25;

    /** Section slugs (and legacy aliases) that select the CMDB vs the integrations registry. */
    private const ASSET_SECTIONS = ['assets', 'cmdb', 'inventory'];
    private const INTEG_SECTIONS = ['integrations', 'registry', 'devices', 'endpoints'];

    /** Module slugs that mean "the integrations registry is the whole module" (top-level mount). */
    private const INTEG_MODULES = ['integrations', 'registry', 'devices', 'endpoints'];

    private const ASSET_SUBTABS = ['overview', 'hardware', 'network', 'compliance'];
    private const ENDPOINT_SUBTABS = ['overview', 'connection', 'credentials'];

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $module = $route['module'];
        // Top-level integrations mount: shift the slots left by one so the endpoint id / filter that would
        // sit under /it/integrations/<x> reads the same as /integrations/<x>.
        if (in_array($module, self::INTEG_MODULES, true)) {
            $integ = Integrations::fromSeed($persona->seed());
            return $this->integrations($integ, $navBase, $route['section'], $route['entity'], (int) $route['page'], 'integrations');
        }

        $section = $route['section'];
        if (in_array($section, self::ASSET_SECTIONS, true)) {
            $cmdb = Cmdb::fromSeed($persona->seed(), $persona->domain());
            return $this->assets($cmdb, $navBase, $route['entity'], $route['subtab'], (int) $route['page']);
        }
        if (in_array($section, self::INTEG_SECTIONS, true)) {
            $integ = Integrations::fromSeed($persona->seed());
            return $this->integrations($integ, $navBase, $route['entity'], $route['subtab'], (int) $route['page'], 'it/integrations');
        }
        // '' and any unknown section -> the module landing.
        return $this->landing($persona, $navBase);
    }

    // --- module landing: estate + fabric tiles + jump-off links ---

    private function landing(VisualPersona $persona, string $navBase): string
    {
        $cmdb = Cmdb::fromSeed($persona->seed(), $persona->domain());
        $integ = Integrations::fromSeed($persona->seed());
        $cs = $cmdb->summary();
        $is = $integ->summary();

        $tiles = $this->statCardsHtml([
            ['label' => 'Managed assets', 'value' => number_format($cs['total']), 'sub' => $cs['byType']['laptop'] . ' laptops · ' . $cs['byType']['server'] . ' servers'],
            ['label' => 'Integrations', 'value' => number_format($is['total']), 'sub' => count($is['byProtocol']) . ' protocols'],
            ['label' => 'Endpoints up', 'value' => number_format($is['up']) . ' / ' . number_format($is['total']), 'sub' => $is['down'] . ' down · ' . $is['degraded'] . ' degraded'],
            ['label' => 'Unencrypted', 'value' => (string) $cs['unencrypted'], 'sub' => $cs['unencrypted'] === 0 ? 'all encrypted' : 'review at-rest encryption'],
            ['label' => 'Patch-gap > 30d', 'value' => (string) $cs['patchBehind'], 'sub' => 'behind on updates'],
            ['label' => 'Out of warranty', 'value' => (string) $cs['outOfWarranty'], 'sub' => 'renewal candidates'],
        ], 'alte-stats', 'alte-st');

        $links = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin:12px 0">'
            . $this->jumpLink($navBase . '/it/assets', 'Asset inventory / CMDB')
            . $this->jumpLink($navBase . '/it/integrations', 'Integrations registry')
            . '</div>';

        // A taste of the two deep surfaces: asset-type chips + protocol chips, each a server-side filter.
        $typeChips = '';
        foreach ($cmdb->types() as $t) {
            $typeChips .= $this->chip($navBase . '/it/assets/type/' . $t, $cmdb->typeLabel($t) . ' (' . $cs['byType'][$t] . ')');
        }
        $protoChips = '';
        foreach ($integ->protocols() as $p) {
            $protoChips .= $this->chip($navBase . '/it/integrations/protocol/' . $integ->protoSlug($p), $p . ' (' . $is['byProtocol'][$p] . ')');
        }
        $chips = $this->card('Browse assets by type', '<div>' . $typeChips . '</div>', 'read-only')
            . $this->card('Browse integrations by protocol', '<div>' . $protoChips . '</div>', 'read-only');

        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'IT & Platform'))
            . $tiles
            . $links
            . $chips;
    }

    // ============================ CMDB / asset inventory ============================

    private function assets(Cmdb $cmdb, string $navBase, string $entity, string $subtab, int $page): string
    {
        if ($entity === '') {
            return $this->assetList($cmdb, $navBase, $cmdb->assets(), 'All assets', $navBase . '/it/assets', $page, ['IT & Platform', $navBase . '/it'], ['Assets / CMDB', '']);
        }
        if ($entity === 'type') {
            $type = $subtab;
            $rows = [];
            foreach ($cmdb->assets() as $a) {
                if ($a['type'] === $type) {
                    $rows[] = $a;
                }
            }
            $label = $cmdb->typeLabel($type);
            return $this->assetList($cmdb, $navBase, $rows, $label . 's', $navBase . '/it/assets/type/' . $type, $page,
                ['IT & Platform', $navBase . '/it'], ['Assets / CMDB', $navBase . '/it/assets'], [$label, '']);
        }
        return $this->assetDetail($cmdb, $navBase, $cmdb->asset($entity), $subtab);
    }

    /**
     * @param list<array<string,mixed>> $rowsData
     * @param array{0:string,1:string} ...$tailCrumbs
     */
    private function assetList(Cmdb $cmdb, string $navBase, array $rowsData, string $title, string $base, int $page, array ...$tailCrumbs): string
    {
        $total = count($rowsData);
        $pages = $total > 0 ? (int) ceil($total / self::PER_PAGE_ASSETS) : 1;
        $page = $page < 1 ? 1 : ($page > $pages ? $pages : $page);
        $offset = ($page - 1) * self::PER_PAGE_ASSETS;
        $slice = array_slice($rowsData, $offset, self::PER_PAGE_ASSETS);

        $rows = '';
        foreach ($slice as $a) {
            $href = $this->esc($navBase . '/it/assets/' . $a['id']);
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($a['tag']) . '</a></td>'
                . '<td>' . $this->esc($a['typeLabel']) . '</td>'
                . '<td>' . $this->esc($a['model']) . '</td>'
                . '<td>' . $this->esc($a['serial']) . '</td>'
                . '<td>' . $this->esc($a['assigneeName']) . '</td>'
                . '<td>' . $this->esc($a['roomName'] . ' (' . $a['floorLabel'] . ')') . '</td>'
                . '<td>' . $this->warrantyPill($a) . '</td>'
                . '<td>' . $this->esc($a['lastCheckin']) . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Asset tag</th><th>Type</th><th>Model</th><th>Serial</th><th>Assignee</th>'
            . '<th>Location</th><th>Warranty</th><th>Last check-in</th></tr></thead>';
        $table = $this->searchBox('cmdb-search', 'Filter assets…')
            . '<div style="overflow-x:auto"><table class="alte-table" id="cmdb-list">' . $head . '<tbody>' . $rows . '</tbody></table></div>'
            . $this->pager($base, $page, $pages, $offset, count($slice), $total, 'assets');

        // Inventory export (decoy archive — the only extension the decoy handler serves).
        $dl = $this->downloadTableHtml(
            ['File', 'Contents', 'Format'],
            [['file' => 'assets-export.csv.zip', 'cells' => [number_format($total) . ' rows', 'CSV (zip)']]],
            $navBase,
            '/it/download',
            ' class="alte-table"',
            'alte-dl'
        );

        $crumbs = array_merge([['Corevance', $navBase]], $tailCrumbs);
        return $this->breadcrumbHtml($crumbs)
            . $this->card($title, $table, number_format($total) . ' assets · CMDB')
            . $this->card('Export', $dl, 'inventory')
            . $this->searchScript('cmdb-search', 'cmdb-list');
    }

    private function assetDetail(Cmdb $cmdb, string $navBase, array $a, string $subtab): string
    {
        $sub = in_array($subtab, self::ASSET_SUBTABS, true) ? $subtab : 'overview';
        $base = $navBase . '/it/assets/' . $a['id'];
        $crumbs = [
            ['Corevance', $navBase],
            ['IT & Platform', $navBase . '/it'],
            ['Assets / CMDB', $navBase . '/it/assets'],
            [$a['tag'], ''],
        ];
        $body = $this->breadcrumbHtml($crumbs) . $this->tabStrip($base, $sub, self::ASSET_SUBTABS);

        switch ($sub) {
            case 'hardware':
                return $body . $this->assetHardwareCard($a);
            case 'network':
                return $body . $this->assetNetworkCard($navBase, $a);
            case 'compliance':
                return $body . $this->assetComplianceCard($a);
            default:
                return $body . $this->assetOverviewCard($navBase, $a);
        }
    }

    private function assetOverviewCard(string $navBase, array $a): string
    {
        // Cross-coherence: the assignee resolves in HR, the location resolves in the building rooms.
        $assignee = $a['assigneeId'] !== ''
            ? '<a class="alte-dl" href="' . $this->esc($navBase . '/hr/' . $a['assigneeId']) . '">' . $this->esc($a['assigneeName']) . '</a>'
                . ' &lt;' . $this->esc($a['assigneeEmail']) . '&gt;'
            : $this->esc($a['assigneeName']);
        $room = '<a class="alte-dl" href="' . $this->esc($navBase . '/rooms/' . $a['roomId']) . '">' . $this->esc($a['roomName']) . '</a>';

        $kvBody = '<tr><th>Asset tag</th><td>' . $this->esc($a['tag']) . '</td></tr>'
            . '<tr><th>Type</th><td>' . $this->esc($a['typeLabel']) . '</td></tr>'
            . '<tr><th>Model</th><td>' . $this->esc($a['model']) . '</td></tr>'
            . '<tr><th>Serial</th><td>' . $this->esc($a['serial']) . '</td></tr>'
            . '<tr><th>Operating system</th><td>' . $this->esc($a['os']) . '</td></tr>'
            . '<tr><th>Assignee</th><td>' . $assignee . '</td></tr>'
            . '<tr><th>Department</th><td>' . $this->esc($a['assigneeDept']) . '</td></tr>'
            . '<tr><th>Location</th><td>' . $room . $this->esc(' — ' . $a['floorLabel'] . ' (' . $a['zone'] . ')') . '</td></tr>'
            . '<tr><th>State</th><td>' . $this->statePill($a['state']) . '</td></tr>'
            . '<tr><th>Last check-in</th><td>' . $this->esc(FrozenClock::ymd((int) $a['lastCheckinEpoch']) . ' ' . FrozenClock::clock((int) $a['lastCheckinEpoch']) . ' (' . $a['lastCheckin'] . ')') . '</td></tr>';
        $kv = '<table class="alte-kv"><tbody>' . $kvBody . '</tbody></table>';

        return $this->card($a['tag'], $kv, $a['model'] . ' · ' . $a['assigneeName']);
    }

    private function assetHardwareCard(array $a): string
    {
        $kv = $this->kvTableHtml([
            ['Model', $a['model']],
            ['Serial number', $a['serial']],
            ['Operating system', $a['os']],
            ['Firmware / BIOS', $a['firmware']],
            ['Purchase date', $a['purchaseDate']],
            ['Warranty end', $a['warrantyEnd'] . ($a['daysToExpiry'] >= 0 ? ' (' . $a['daysToExpiry'] . ' d left)' : ' (expired)')],
            ['Warranty status', $a['warrantyStatus']],
        ], ' class="alte-kv"');
        return $this->card('Hardware', $kv, $a['tag']);
    }

    private function assetNetworkCard(string $navBase, array $a): string
    {
        $kv = $this->kvTableHtml([
            ['Hostname', $a['hostname']],
            ['MAC address', $a['mac']],
            ['Last known IP', $a['lastIp']],
            ['Switch port', $a['switchPort']],
            ['VLAN', $this->vlanLabel($a['lastIp'])],
        ], ' class="alte-kv"');
        $note = $a['switchPort'] !== '—'
            ? '<p class="alte-muted" style="font-size:.85em;color:#6c757d;margin:8px 0 0">Cabling maps to the access switch in Network Devices.</p>'
            : '';
        return $this->card('Network', $kv . $note, $a['tag']);
    }

    private function assetComplianceCard(array $a): string
    {
        $kvBody = '<tr><th>At-rest encryption</th><td>' . $this->encPill((bool) $a['encrypted']) . '</td></tr>'
            . '<tr><th>MDM enrolment</th><td>' . ($a['mdmEnrolled'] ? $this->pillHtml('Enrolled', 'ok') : $this->pillHtml('Not enrolled', 'warn')) . '</td></tr>'
            . '<tr><th>Patch gap</th><td>' . $this->patchCell((int) $a['patchGapDays']) . '</td></tr>'
            . '<tr><th>Warranty</th><td>' . $this->warrantyPill($a) . '</td></tr>'
            . '<tr><th>Last check-in</th><td>' . $this->esc($a['lastCheckin']) . '</td></tr>';
        $kv = '<table class="alte-kv"><tbody>' . $kvBody . '</tbody></table>';
        return $this->card('Compliance & posture', $kv, $a['tag']);
    }

    // ============================ Integrations / endpoint registry ============================

    /** @param string $modBase the module path prefix ('it/integrations' or 'integrations'). */
    private function integrations(Integrations $integ, string $navBase, string $entity, string $subtab, int $page, string $modBase): string
    {
        $root = $navBase . '/' . $modBase;
        if ($entity === '') {
            return $this->endpointList($integ, $navBase, $root, $integ->endpoints(), 'All integrations', $root, $page, null);
        }
        if ($entity === 'protocol') {
            $slug = $subtab;
            $rows = [];
            $label = strtoupper($slug);
            foreach ($integ->endpoints() as $e) {
                if ($e['protocolSlug'] === $slug) {
                    $rows[] = $e;
                    $label = $e['protocol'];
                }
            }
            return $this->endpointList($integ, $navBase, $root, $rows, $label . ' endpoints', $root . '/protocol/' . $slug, $page, $label);
        }
        return $this->endpointDetail($integ, $navBase, $root, $integ->endpoint($entity), $subtab);
    }

    /**
     * @param list<array<string,mixed>> $rowsData
     * @param string|null $filterLabel a crumb label when this is a filtered view, else null
     */
    private function endpointList(Integrations $integ, string $navBase, string $root, array $rowsData, string $title, string $base, int $page, ?string $filterLabel): string
    {
        $total = count($rowsData);
        $pages = $total > 0 ? (int) ceil($total / self::PER_PAGE_ENDPOINTS) : 1;
        $page = $page < 1 ? 1 : ($page > $pages ? $pages : $page);
        $offset = ($page - 1) * self::PER_PAGE_ENDPOINTS;
        $slice = array_slice($rowsData, $offset, self::PER_PAGE_ENDPOINTS);

        $rows = '';
        foreach ($slice as $e) {
            $href = $this->esc($root . '/' . $e['id']);
            $rows .= '<tr>'
                . '<td><a class="alte-dl" href="' . $href . '">' . $this->esc($e['name']) . '</a></td>'
                . '<td>' . $this->esc($e['protocol']) . '</td>'
                . '<td><code>' . $this->esc($e['endpoint']) . '</code></td>'
                . '<td>' . $this->esc($e['category']) . '</td>'
                . '<td>' . $this->statusPill($e['status']) . '</td>'
                . '<td>' . $this->esc($e['lastSeen']) . '</td>'
                . '</tr>';
        }
        $head = '<thead><tr><th>Integration</th><th>Protocol</th><th>Endpoint (host:port)</th><th>Category</th>'
            . '<th>Status</th><th>Last seen</th></tr></thead>';

        // Protocol filter chips — server-side deep filters into the same registry.
        $chips = '';
        foreach ($integ->protocols() as $p) {
            $chips .= $this->chip($root . '/protocol/' . $integ->protoSlug($p), $p);
        }

        $table = $this->searchBox('intg-search', 'Filter integrations…')
            . '<div style="overflow-x:auto"><table class="alte-table" id="intg-list">' . $head . '<tbody>' . $rows . '</tbody></table></div>'
            . $this->pager($base, $page, $pages, $offset, count($slice), $total, 'endpoints');

        $dl = $this->downloadTableHtml(
            ['File', 'Contents', 'Format'],
            [['file' => 'integrations-registry.csv.zip', 'cells' => [number_format($total) . ' endpoints', 'CSV (zip)']]],
            $navBase,
            '/it/download',
            ' class="alte-table"',
            'alte-dl'
        );

        $crumbs = [['Corevance', $navBase], ['IT & Platform', $navBase . '/it'], ['Integrations', $filterLabel === null ? '' : $root]];
        if ($filterLabel !== null) {
            $crumbs[] = [$filterLabel, ''];
        }
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Filter by protocol', '<div>' . $chips . '</div>', 'read-only')
            . $this->card($title, $table, number_format($total) . ' endpoints · device registry')
            . $this->card('Export', $dl, 'registry')
            . $this->searchScript('intg-search', 'intg-list');
    }

    private function endpointDetail(Integrations $integ, string $navBase, string $root, array $e, string $subtab): string
    {
        $sub = in_array($subtab, self::ENDPOINT_SUBTABS, true) ? $subtab : 'overview';
        $base = $root . '/' . $e['id'];
        $crumbs = [
            ['Corevance', $navBase],
            ['IT & Platform', $navBase . '/it'],
            ['Integrations', $root],
            [$e['name'], ''],
        ];
        $body = $this->breadcrumbHtml($crumbs) . $this->tabStrip($base, $sub, self::ENDPOINT_SUBTABS);

        switch ($sub) {
            case 'connection':
                return $body . $this->endpointConnectionCard($e);
            case 'credentials':
                return $body . $this->endpointCredentialsCard($e);
            default:
                return $body . $this->endpointOverviewCard($root, $e);
        }
    }

    private function endpointOverviewCard(string $root, array $e): string
    {
        $linked = $e['linkedController'] !== ''
            ? $this->esc($e['linkedController']) . ' (building controller)'
            : '—';
        $kvBody = '<tr><th>Integration</th><td>' . $this->esc($e['name']) . '</td></tr>'
            . '<tr><th>Protocol</th><td>' . $this->esc($e['protocol']) . ' / ' . $this->esc($e['transport']) . '</td></tr>'
            . '<tr><th>Endpoint</th><td><code>' . $this->esc($e['endpoint']) . '</code></td></tr>'
            . '<tr><th>Category</th><td>' . $this->esc($e['category']) . '</td></tr>'
            . '<tr><th>Status</th><td>' . $this->statusPill($e['status']) . '</td></tr>'
            . '<tr><th>Last seen</th><td>' . $this->esc($e['lastSeen']) . '</td></tr>'
            . '<tr><th>Latency</th><td>' . $this->esc($e['latencyMs'] < 0 ? 'no response' : $e['latencyMs'] . ' ms') . '</td></tr>'
            . '<tr><th>Bound controller</th><td>' . $linked . '</td></tr>';
        $kv = '<table class="alte-kv"><tbody>' . $kvBody . '</tbody></table>';
        return $this->card($e['name'], $kv, $e['protocol'] . ' · ' . $e['endpoint']);
    }

    private function endpointConnectionCard(array $e): string
    {
        $kv = $this->kvTableHtml([
            ['Host', substr($e['endpoint'], 0, (int) strpos($e['endpoint'], ':'))],
            ['Port', (string) $e['port']],
            ['Transport', strtoupper($e['transport'])],
            ['TLS', $e['tls'] ? 'enabled' : 'not configured'],
            ['Firmware / version', $e['firmware']],
            ['Status', ucfirst((string) $e['status'])],
        ], ' class="alte-kv"');
        return $this->card('Connection', $kv, $e['endpoint']);
    }

    private function endpointCredentialsCard(array $e): string
    {
        $cred = $e['credential'] !== '' ? $e['credential'] : 'none (no stored secret)';
        $kv = $this->kvTableHtml([
            ['Auth mode', $e['authMode']],
            ['Stored credential', $cred],
        ], ' class="alte-kv"');
        $note = '<p class="alte-muted" style="font-size:.85em;color:#6c757d;margin:8px 0 0">'
            . 'Stored secrets are shown masked. Reveal requires a break-glass request through the secrets vault.</p>';
        return $this->card('Credentials', $kv . $note, $e['name']);
    }

    // --- small shared UI helpers (all escape-by-construction) ---

    /** A button-styled jump link (not a control — just a link to a sibling surface). */
    private function jumpLink(string $href, string $label): string
    {
        return '<a class="alte-btn" style="display:inline-block;padding:7px 14px;border-radius:4px;'
            . 'background:#3b7ea1;color:#fff;text-decoration:none;font-size:.86em;font-weight:600" href="'
            . $this->esc($href) . '">' . $this->esc($label) . '</a>';
    }

    /** A pill-styled filter chip linking to a server-side filtered list. */
    private function chip(string $href, string $label): string
    {
        return '<a class="alte-btn" href="' . $this->esc($href) . '" style="text-decoration:none;padding:3px 10px;'
            . 'margin:0 6px 6px 0;border:1px solid #c9ccd1;border-radius:12px;color:#3b7ea1;font-size:.82em;display:inline-block">'
            . $this->esc($label) . '</a>';
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

    /** Pager built on the trait's pagerHtml so every deep page is reachable. */
    private function pager(string $base, int $page, int $pages, int $offset, int $shown, int $total, string $noun): string
    {
        $from = $total === 0 ? 0 : $offset + 1;
        $to = $offset + $shown;
        $summary = 'Showing ' . number_format($from) . '&ndash;' . number_format($to) . ' of ' . number_format($total) . ' ' . $noun;
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
        return '<script>(function(){var i=document.getElementById(' . json_encode($inputId)
            . '),t=document.getElementById(' . json_encode($tableId) . ');if(!i||!t||!t.tBodies[0])return;'
            . 'i.addEventListener("input",function(){var q=i.value.toLowerCase(),r=t.tBodies[0].rows,k;'
            . 'for(k=0;k<r.length;k++){r[k].style.display=r[k].textContent.toLowerCase().indexOf(q)>-1?"":"none";}});})();</script>';
    }

    private function warrantyPill(array $a): string
    {
        if ($a['warrantyStatus'] === 'Expired') {
            return $this->pillHtml('Expired', 'crit');
        }
        if ($a['warrantyStatus'] === 'Expiring') {
            return $this->pillHtml('Expiring', 'warn');
        }
        return $this->pillHtml('In warranty', 'ok');
    }

    private function statePill(string $state): string
    {
        return $state === 'stale' ? $this->pillHtml('Stale check-in', 'warn') : $this->pillHtml('Active', 'ok');
    }

    private function encPill(bool $encrypted): string
    {
        return $encrypted ? $this->pillHtml('Encrypted', 'ok') : $this->pillHtml('Not encrypted', 'crit');
    }

    private function patchCell(int $days): string
    {
        if ($days > 30) {
            return $this->pillHtml($days . ' d behind', 'crit');
        }
        if ($days > 7) {
            return $this->pillHtml($days . ' d behind', 'warn');
        }
        return $this->pillHtml($days === 0 ? 'Current' : $days . ' d behind', 'ok');
    }

    private function statusPill(string $status): string
    {
        if ($status === 'up') {
            return $this->pillHtml('Up', 'ok');
        }
        if ($status === 'degraded') {
            return $this->pillHtml('Degraded', 'warn');
        }
        return $this->pillHtml('Down', 'crit');
    }

    /** Label the RFC1918 VLAN an IP sits on (from the §C.7 fabric); '—' for an unnetworked asset. */
    private function vlanLabel(string $ip): string
    {
        if (strpos($ip, '10.0.10.') === 0) {
            return 'VLAN 10 — Servers';
        }
        if (strpos($ip, '10.0.20.') === 0 || strpos($ip, '10.0.21.') === 0) {
            return 'VLAN 20 — Employees';
        }
        if (strpos($ip, '10.0.30.') === 0) {
            return 'VLAN 30 — Voice';
        }
        return '—';
    }
}
