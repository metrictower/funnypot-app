<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Network;
use Funnypot\Core\Support\VisualPersona;

/**
 * Network / VPN / VoIP (spec §C.7) — the lateral-movement intel lure. Renders the deep ladder over the
 * `Fake\Network` view of the `Org` roster + `Building` topology: a network landing (device/VLAN/VPN/VoIP
 * tiles) -> paginated device LIST -> device DETAIL with sub-tabs (overview / running-config <pre> /
 * interfaces+LLDP / VLANs) -> device control leaves; plus the VPN view (accounts list + active tunnel
 * sessions) and the VoIP view (extension directory + CDR call-log scroll + voicemail box).
 *
 * The whole surface is INERT and reachable: every list pages through `pagerHtml`, configs/inventory are
 * decoy `.tar.gz`/`.csv.zip` downloads, `Ping`/`Traceroute` return canned RFC1918 output that executes
 * nothing, and the one scary verb (`Reboot` a device) is a GUARDED soft-denial routed to a change window
 * — it never claims the device restarted. All addressing is RFC1918 (device mgmt on the Mgmt VLAN, VPN
 * tunnels on 10.20.x.x) or TEST-NET documentation space (a VPN session's "public" source); running-config
 * secrets are masked; external phone numbers are the reserved fictional 555-01xx range.
 *
 * Route slots (PanelRoute): module = network (aliases vpn / voip enter the matching view directly);
 *   section = ''(landing) | devices | vpn | voip | vlans (any other section falls back to the landing).
 *   For devices: entity = ''(list) | <device-id>; subtab = a detail sub-tab OR a device verb.
 */
final class NetworkSection extends AbstractPanelSection
{
    /** Verbs in a device's sub-tab slot; anything else there is a detail sub-tab. */
    private const DEVICE_VERBS = ['reboot', 'ping', 'traceroute'];

    private const PAGE_SIZE = 25;

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $net = Network::fromSeed($persona->seed(), $persona->domain());
        $module = $route['module'];
        $section = $route['section'];

        // Alias entry points (/admin/vpn, /admin/voip) land straight on the matching view.
        if ($module === 'vpn') {
            return $this->vpn($net, $navBase, $route['page']);
        }
        if ($module === 'voip') {
            return $this->voip($net, $navBase, $route['page']);
        }

        if ($section === 'devices') {
            return $this->devicesArm($net, $navBase, $route, $persona->seed());
        }
        if ($section === 'vpn') {
            return $this->vpn($net, $navBase, $route['page']);
        }
        if ($section === 'voip') {
            return $this->voip($net, $navBase, $route['page']);
        }
        if ($section === 'vlans') {
            return $this->vlansView($net, $navBase);
        }
        // '' and any unknown section -> the landing (a 404 inside a deep panel is a tell).
        return $this->landing($net, $navBase);
    }

    // --- landing: tiles + jump-off links + health + downloads ---

    private function landing(Network $net, string $navBase): string
    {
        $devices = $net->devices();
        $up = 0;
        foreach ($devices as $d) {
            if ($d['health'] === 'ok') {
                $up++;
            }
        }
        $tiles = $this->statCardsHtml([
            ['label' => 'Managed devices', 'value' => (string) count($devices), 'sub' => $up . ' healthy'],
            ['label' => 'VLANs', 'value' => (string) count($net->vlans())],
            ['label' => 'Active VPN sessions', 'value' => (string) count($net->vpnSessions())],
            ['label' => 'Extensions', 'value' => number_format($net->extensionCount())],
        ], 'fp-tiles', 'fp-tile');

        $links = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin:12px 0">'
            . $this->actionLink($navBase . '/network/devices', 'Devices', false)
            . $this->actionLink($navBase . '/network/vlans', 'VLANs', false)
            . $this->actionLink($navBase . '/network/vpn', 'VPN', false)
            . $this->actionLink($navBase . '/network/voip', 'VoIP', false)
            . '</div>';

        // Health summary — mostly ok, so any anomaly reads against a clean baseline.
        $healthRows = [];
        foreach ($devices as $d) {
            if ($d['health'] !== 'ok') {
                $healthRows[] = [$d['hostname'], $d['role'], $d['mgmtIp'], $d['health']];
            }
        }
        if ($healthRows === []) {
            $healthCard = $this->card('Device health', '<p class="fp-muted">All managed devices report healthy.</p>');
        } else {
            $healthCard = $this->card('Device health — attention',
                $this->tableHtml(['Device', 'Role', 'Mgmt IP', 'State'], $healthRows, ' class="alte-table"'));
        }

        $files = [
            ['file' => 'configs-backup.tar.gz', 'cells' => ['All running-configs', 'tar.gz']],
            ['file' => 'lldp-topology.csv.zip', 'cells' => ['LLDP neighbour map', 'CSV (zip)']],
        ];
        $downloads = $this->downloadTableHtml(['File', 'Contents', 'Format'], $files, $navBase, '/network/download', ' class="alte-table"', 'fp-dl');

        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Network'))
            . $tiles
            . $links
            . $healthCard
            . $this->card('Backups', $downloads, 'nightly export');
    }

    // --- devices: list / detail / control leaves ---

    private function devicesArm(Network $net, string $navBase, array $route, int $seed): string
    {
        $entity = $route['entity'];
        if ($entity === '') {
            return $this->deviceList($net, $navBase, $route['page']);
        }
        $device = $net->deviceBySlug($entity);
        $verb = $route['subtab'];
        if ($verb !== '' && in_array($verb, self::DEVICE_VERBS, true)) {
            return $this->deviceControl($net, $navBase, $device, $verb, $seed);
        }
        return $this->deviceDetail($net, $navBase, $device, $verb === '' ? 'overview' : $verb);
    }

    private function deviceList(Network $net, string $navBase, int $page): string
    {
        $total = $net->deviceCount();
        [$page, $pages, $offset] = $this->paginate($page, $total);
        $devices = $net->devicePage($offset, self::PAGE_SIZE);

        $rows = '';
        foreach ($devices as $d) {
            $href = $this->esc($navBase . '/network/devices/' . $d['id']);
            $rows .= '<tr>'
                . '<td><a class="fp-dl" href="' . $href . '">' . $this->esc($d['hostname']) . '</a></td>'
                . '<td>' . $this->esc($d['role']) . '</td>'
                . '<td>' . $this->esc($d['model']) . '</td>'
                . '<td>' . $this->esc($d['mgmtIp']) . '</td>'
                . '<td>' . $this->esc($d['floorLabel']) . '</td>'
                . '<td>' . $this->esc((string) $d['portCount']) . '</td>'
                . '<td>' . $this->esc($d['uptime']) . '</td>'
                . '<td>' . $this->pillHtml($d['health'], $this->healthStatus($d['health'])) . '</td>'
                . '</tr>';
        }
        $search = $this->searchBox('net-dev-q', 'Filter by hostname, role, model, IP, floor…');
        $table = '<div style="overflow-x:auto"><table id="net-dev-tbl" class="alte-table">'
            . '<thead><tr><th>Device</th><th>Role</th><th>Model</th><th>Mgmt IP</th><th>Floor</th><th>Ports</th><th>Uptime</th><th>Health</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        $pager = $this->pagerHtml($navBase . '/network/devices', $page, $pages,
            $this->summary($offset, count($devices), $total, 'devices'));

        $crumbs = [['Corevance', $navBase], ['Network', $navBase . '/network'], ['Devices', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Network devices',
                $search . $table . $pager . $this->filterScript('net-dev-q', 'net-dev-tbl'),
                number_format($total) . ' managed devices');
    }

    private function deviceDetail(Network $net, string $navBase, array $d, string $subtab): string
    {
        $devBase = $navBase . '/network/devices/' . $d['id'];
        $crumbs = [
            ['Corevance', $navBase],
            ['Network', $navBase . '/network'],
            ['Devices', $navBase . '/network/devices'],
            [$d['hostname'], ''],
        ];
        $tabs = $this->tabStrip($devBase, $subtab, [
            'overview' => 'Overview',
            'config' => 'Running config',
            'interfaces' => 'Interfaces',
            'vlans' => 'VLANs',
        ]);

        switch ($subtab) {
            case 'config':
                $body = $this->deviceConfigCard($net, $navBase, $d);
                break;
            case 'interfaces':
                $body = $this->deviceInterfacesCard($net, $d);
                break;
            case 'vlans':
                $body = $this->vlanTableCard($net, $d['hostname']);
                break;
            default:
                $body = $this->deviceOverviewCard($net, $navBase, $d);
        }
        return $this->breadcrumbHtml($crumbs) . $tabs . $body;
    }

    private function deviceOverviewCard(Network $net, string $navBase, array $d): string
    {
        $kv = $this->kvTableHtml([
            ['Hostname', $d['hostname']],
            ['Role', $d['role']],
            ['Model', $d['model']],
            ['Serial', $d['serial']],
            ['Management IP', $d['mgmtIp']],
            ['Location', $d['floorLabel'] . ' · ' . $d['room']],
            ['Ports', (string) $d['portCount']],
            ['Uplink', $d['uplink'] !== '' ? $d['uplink'] : '— (edge)'],
            ['Uptime', $d['uptime']],
            ['Firmware', $d['firmware']],
            ['Health', $d['health']],
        ], ' class="alte-kv"');

        $devBase = $navBase . '/network/devices/' . $d['id'];
        $controls = '<div class="alte-actions" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">'
            . $this->actionLink($devBase . '/ping', 'Ping', false)
            . $this->actionLink($devBase . '/traceroute', 'Traceroute', false)
            . $this->actionLink($devBase . '/reboot', 'Reboot', true)
            . '</div>';

        $files = [['file' => $d['id'] . '.cfg.zip', 'cells' => ['Running-config', 'CLI (zip)']]];
        $download = $this->downloadTableHtml(['File', 'Contents', 'Format'], $files, $navBase, '/network/download', ' class="alte-table"', 'fp-dl');

        return $this->card($d['hostname'], $kv . $controls, $d['role'] . ' · ' . $d['mgmtIp'])
            . $this->card('Config backup', $download, $d['hostname']);
    }

    private function deviceConfigCard(Network $net, string $navBase, array $d): string
    {
        $scroll = $this->preScrollHtml($net->runningConfig($d), 'alte-log');
        $files = [['file' => $d['id'] . '.cfg.zip', 'cells' => ['Running-config', 'CLI (zip)']]];
        $download = $this->downloadTableHtml(['File', 'Contents', 'Format'], $files, $navBase, '/network/download', ' class="alte-table"', 'fp-dl');
        return $this->card('Running config — ' . $d['hostname'], $scroll, 'read-only snapshot · secrets masked')
            . $this->card('Download', $download, $d['hostname']);
    }

    private function deviceInterfacesCard(Network $net, array $d): string
    {
        $rows = [];
        foreach ($net->interfaces($d) as $if) {
            $rows[] = [
                $if['port'],
                $if['admin'],
                $if['oper'],
                $if['mode'] === 'trunk' ? 'trunk' : ('vlan ' . $if['vlan']),
                $if['speed'],
                $if['neighbor'] !== '' ? $if['neighbor'] : '—',
                $if['desc'] !== '' ? $if['desc'] : '—',
            ];
        }
        $table = $this->tableHtml(
            ['Port', 'Admin', 'Oper', 'Mode', 'Speed', 'LLDP neighbour', 'Description'],
            $rows,
            ' class="alte-table"'
        );
        return $this->card('Interfaces & neighbours', '<div style="overflow-x:auto">' . $table . '</div>',
            $d['hostname'] . ' · ' . $d['portCount'] . ' ports');
    }

    private function vlanTableCard(Network $net, string $context): string
    {
        $rows = [];
        foreach ($net->vlans() as $v) {
            $rows[] = [$v['id'], $v['name'], $v['subnet'], $v['gateway']];
        }
        $table = $this->tableHtml(['VLAN', 'Name', 'Subnet', 'Gateway'], $rows, ' class="alte-table"');
        return $this->card('VLAN plan', $table, $context);
    }

    /** A device control leaf. `ping`/`traceroute` are canned inert output; `reboot` is a soft-denial. */
    private function deviceControl(Network $net, string $navBase, array $d, string $verb, int $seed): string
    {
        $devBase = $navBase . '/network/devices/' . $d['id'];
        $crumbs = [
            ['Corevance', $navBase],
            ['Network', $navBase . '/network'],
            ['Devices', $navBase . '/network/devices'],
            [$d['hostname'], $devBase],
            [ucfirst($verb), ''],
        ];

        if ($verb === 'reboot') {
            $ref = $this->cmdRef($seed, $d['id'] . '|reboot');
            $body = $this->softDenyCard(
                'Reboot — ' . $d['hostname'],
                [
                    ['Device', $d['hostname'] . ' · ' . $d['role']],
                    ['Management IP', $d['mgmtIp']],
                    ['Reason', 'A device reboot is a service-affecting change and requires an approved maintenance window (change management) plus a second operator.'],
                    ['Request', $ref . ' · awaiting change approval'],
                    ['Status', 'not executed'],
                ],
                'The reboot request was recorded and queued against the next change window. No device was restarted and no command was sent; the device keeps its current uptime until an approved window and a second operator release it.'
            );
            return $this->breadcrumbHtml($crumbs) . $body;
        }

        // ping / traceroute — canned RFC1918 output, executes nothing.
        if ($verb === 'ping') {
            $target = $d['mgmtIp'];
            $lines = [
                'PING ' . $target . ' (' . $target . ') 56(84) bytes of data.',
                '64 bytes from ' . $target . ': icmp_seq=1 ttl=64 time=0.42 ms',
                '64 bytes from ' . $target . ': icmp_seq=2 ttl=64 time=0.39 ms',
                '64 bytes from ' . $target . ': icmp_seq=3 ttl=64 time=0.44 ms',
                '',
                '--- ' . $target . ' ping statistics ---',
                '3 packets transmitted, 3 received, 0% packet loss, time 2003ms',
                'rtt min/avg/max/mdev = 0.39/0.41/0.44/0.02 ms',
            ];
            return $this->breadcrumbHtml($crumbs)
                . $this->card('Ping — ' . $d['hostname'], $this->preScrollHtml($lines, 'alte-log'), 'diagnostic · no state change');
        }

        // traceroute
        $rows = [];
        foreach ($net->tracerouteHops() as $hop) {
            $rows[] = $hop;
        }
        $table = $this->tableHtml(['Hop', 'Node', 'RTT'], $rows, ' class="alte-table"');
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Traceroute — ' . $d['hostname'], $table, 'diagnostic · no state change');
    }

    // --- VPN view: accounts list + active sessions ---

    private function vpn(Network $net, string $navBase, int $page): string
    {
        $total = $net->vpnUserCount();
        [$page, $pages, $offset] = $this->paginate($page, $total);
        $users = $net->vpnUsers($offset, self::PAGE_SIZE);

        $rows = '';
        foreach ($users as $u) {
            $rows .= '<tr>'
                . '<td>' . $this->esc($u['user']) . '</td>'
                . '<td>' . $this->esc($u['name']) . '</td>'
                . '<td>' . $this->esc($u['group']) . '</td>'
                . '<td>' . $this->pillHtml($u['mfa'] === 'on' ? 'MFA on' : 'MFA off', $u['mfa'] === 'on' ? 'ok' : 'crit') . '</td>'
                . '<td>' . $this->esc($u['lastConnect']) . '</td>'
                . '<td>' . $this->pillHtml($u['status'], $u['status'] === 'enabled' ? 'info' : 'idle') . '</td>'
                . '</tr>';
        }
        $search = $this->searchBox('net-vpn-q', 'Filter by user, name, group…');
        $table = '<div style="overflow-x:auto"><table id="net-vpn-tbl" class="alte-table">'
            . '<thead><tr><th>User</th><th>Name</th><th>Group</th><th>MFA</th><th>Last connect</th><th>Status</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        $pager = $this->pagerHtml($navBase . '/network/vpn', $page, $pages,
            $this->summary($offset, count($users), $total, 'accounts'));

        // Active tunnel sessions — the live subset on the 10.20.x.x pool.
        $sessRows = [];
        foreach ($net->vpnSessions() as $s) {
            $sessRows[] = [$s['user'], $s['tunnelIp'], $s['sourceIp'], $s['sourceGeo'], $s['since'], $s['rx'] . ' / ' . $s['tx']];
        }
        $sessions = $this->tableHtml(
            ['User', 'Tunnel IP', 'Source', 'Source ASN', 'Connected since', 'Rx / Tx'],
            $sessRows,
            ' class="alte-table"'
        );

        $crumbs = [['Corevance', $navBase], ['Network', $navBase . '/network'], ['VPN', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Active sessions', '<div style="overflow-x:auto">' . $sessions . '</div>',
                count($sessRows) . ' connected · pool 10.20.0.0/16')
            . $this->card('VPN accounts',
                $search . $table . $pager . $this->filterScript('net-vpn-q', 'net-vpn-tbl'),
                number_format($total) . ' accounts');
    }

    // --- VoIP view: extension directory + CDR scroll + voicemail ---

    private function voip(Network $net, string $navBase, int $page): string
    {
        $total = $net->extensionCount();
        [$page, $pages, $offset] = $this->paginate($page, $total);
        $exts = $net->extensions($offset, self::PAGE_SIZE);

        $rows = '';
        foreach ($exts as $e) {
            $rows .= '<tr>'
                . '<td>' . $this->esc($e['ext']) . '</td>'
                . '<td>' . $this->esc($e['name']) . '</td>'
                . '<td>' . $this->esc($e['dept']) . '</td>'
                . '<td>' . $this->esc($e['device']) . '</td>'
                . '<td>' . $this->esc($e['ip']) . '</td>'
                . '<td>' . $this->pillHtml($e['status'], $e['status'] === 'registered' ? 'ok' : 'warn') . '</td>'
                . '</tr>';
        }
        $search = $this->searchBox('net-voip-q', 'Filter by extension, name, department…');
        $table = '<div style="overflow-x:auto"><table id="net-voip-tbl" class="alte-table">'
            . '<thead><tr><th>Ext</th><th>Name</th><th>Department</th><th>Device</th><th>Voice IP</th><th>Registration</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table></div>';
        $pager = $this->pagerHtml($navBase . '/network/voip', $page, $pages,
            $this->summary($offset, count($exts), $total, 'extensions'));

        // CDR scroll — newest first, walked back from the frozen now.
        $cdr = $this->preScrollHtml($net->callLog(160), 'alte-log');

        // Voicemail box.
        $vmRows = [];
        foreach ($net->voicemail(24) as $vm) {
            $vmRows[] = [
                $vm['new'] ? '● new' : 'read',
                $vm['from'],
                $vm['to'] . ' · ' . $vm['toName'],
                $vm['received'],
                $vm['duration'],
                $vm['transcript'],
            ];
        }
        $voicemail = $this->tableHtml(
            ['State', 'From', 'To', 'Received', 'Duration', 'Transcript'],
            $vmRows,
            ' class="alte-table"'
        );

        $crumbs = [['Corevance', $navBase], ['Network', $navBase . '/network'], ['VoIP', '']];
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Extensions',
                $search . $table . $pager . $this->filterScript('net-voip-q', 'net-voip-tbl'),
                number_format($total) . ' extensions · Voice VLAN 30')
            . $this->card('Call log (CDR)', $cdr,
                number_format($net->callLogCount()) . ' records · live tail (cached ~30 s)')
            . $this->card('Voicemail', '<div style="overflow-x:auto">' . $voicemail . '</div>', 'transcripts only · no audio stored');
    }

    // --- VLAN plan view ---

    private function vlansView(Network $net, string $navBase): string
    {
        $crumbs = [['Corevance', $navBase], ['Network', $navBase . '/network'], ['VLANs', '']];
        return $this->breadcrumbHtml($crumbs) . $this->vlanTableCard($net, 'site-wide');
    }

    // --- small shared UI helpers (all escape-by-construction) ---

    /** Clamp a page request to [1, pages] and return [page, pages, offset]. */
    private function paginate(int $page, int $total): array
    {
        $pages = (int) ceil($total / self::PAGE_SIZE);
        if ($pages < 1) {
            $pages = 1;
        }
        if ($page < 1) {
            $page = 1;
        }
        if ($page > $pages) {
            $page = $pages;
        }
        return [$page, $pages, ($page - 1) * self::PAGE_SIZE];
    }

    /** A pager summary line, e.g. "Showing 1&ndash;25 of 62 devices" — trusted assembled markup. */
    private function summary(int $offset, int $shown, int $total, string $noun): string
    {
        $from = $total === 0 ? 0 : $offset + 1;
        $to = $offset + $shown;
        return 'Showing ' . number_format($from) . '&ndash;' . number_format($to)
            . ' of ' . number_format($total) . ' ' . $noun;
    }

    private function searchBox(string $id, string $placeholder): string
    {
        return '<input id="' . $id . '" type="search" placeholder="' . $this->esc($placeholder) . '" '
            . 'style="margin-bottom:10px;padding:6px 10px;width:100%;max-width:340px;box-sizing:border-box" autocomplete="off">';
    }

    /** A guarded-denial card: a crit pill over the reason detail, never a "queued" success. */
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

    /** A scoped client-side row filter. Degrades cleanly (no-JS shows every row); changes no state. */
    private function filterScript(string $inputId, string $tableId): string
    {
        return '<script>(function(){var i=document.getElementById(' . json_encode($inputId)
            . '),t=document.getElementById(' . json_encode($tableId) . ');if(!i||!t||!t.tBodies[0])return;'
            . 'i.addEventListener("input",function(){var q=i.value.toLowerCase(),r=t.tBodies[0].rows,k;'
            . 'for(k=0;k<r.length;k++){r[k].style.display=r[k].textContent.toLowerCase().indexOf(q)>-1?"":"none";}});})();</script>';
    }

    /** Deterministic, inert command ref = hash(seed + slot): stable per path, varies per deploy. */
    private function cmdRef(int $seed, string $slot): string
    {
        return 'NET-CMD-' . strtoupper(substr(hash('sha256', $seed . '|netcmd|' . $slot), 0, 6));
    }

    private function healthStatus(string $health): string
    {
        if ($health === 'ok') {
            return 'ok';
        }
        if ($health === 'degraded' || $health === 'flapping') {
            return 'warn';
        }
        return 'crit';
    }
}
