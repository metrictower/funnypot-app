<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Fleet;
use Funnypot\Core\Support\VisualPersona;

/**
 * Server control panel — a fleet console over the seeded Fleet generator. The list shows every host with
 * live-ish gauges; a host drills into a detail view (gauges + services + sockets) with a Console button
 * into that host's web terminal and INERT lifecycle actions (reboot/stop/snapshot → "queued", never a
 * real state change). Each host reuses the same generators as the shell, so console, detail, and terminal
 * agree. Rendered entirely through the escape-by-construction helpers.
 */
final class FleetSection extends AbstractPanelSection
{
    private const COUNT = 24;
    private const ACTIONS = ['reboot', 'start', 'stop', 'restart', 'snapshot', 'resize'];

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $fleet = Fleet::fromSeed($persona->seed(), self::COUNT);
        $host = $route['section'];
        if ($host === '') {
            return $this->listView($fleet, $navBase);
        }
        $detail = $fleet->detail($host);
        if ($detail === null) {
            return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Fleet'))
                . $this->card('Host not found', '<p>No such host in this fleet.</p>');
        }
        $action = $route['entity'];
        if ($action === 'console') {
            return $this->consoleView($detail, $navBase);
        }
        if (in_array($action, self::ACTIONS, true)) {
            return $this->actionResult($detail, $action, $navBase);
        }

        return $this->detailView($detail, $navBase);
    }

    /** @param Fleet $fleet */
    private function listView(Fleet $fleet, string $navBase): string
    {
        $agg = $fleet->aggregate();
        $cards = $this->statCardsHtml([
            ['label' => 'Hosts', 'value' => (string) $agg['total'], 'sub' => 'total'],
            ['label' => 'Running', 'value' => (string) $agg['running'], 'sub' => 'healthy'],
            ['label' => 'Degraded', 'value' => (string) ($agg['degraded'] + $agg['stopped']), 'sub' => 'attention'],
            ['label' => 'Offline', 'value' => (string) $agg['offline'], 'sub' => 'unreachable'],
        ], 'alte-stats', 'alte-stat');

        $rows = [];
        foreach ($fleet->servers() as $s) {
            $rows[] = [
                'file' => strtolower($s['host']), // links to /fleet/<host>
                'cells' => [
                    $s['role'],
                    $s['status'],
                    $s['live'] ? $s['cpuPct'] . '%' : '—',
                    $s['live'] ? $s['memGib'] . 'G / ' . $s['memPct'] . '%' : '—',
                    $s['diskPct'] . '%',
                    $s['live'] ? $s['uptimeDays'] . 'd' : '—',
                    $s['ip'],
                    $s['dc'],
                    $s['os'],
                ],
            ];
        }
        $table = $this->downloadTableHtml(
            ['Host', 'Role', 'Status', 'CPU', 'Mem', 'Disk', 'Uptime', 'IP', 'DC', 'OS'],
            $rows,
            $navBase,
            '/fleet',
            ' class="alte-table alte-mono"',
            'alte-link'
        );

        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Fleet'))
            . $cards
            . $this->card('Servers', $table, $agg['total'] . ' hosts');
    }

    /** @param array{summary:array<string,mixed>,facts:\Funnypot\Shell\Host\HostFacts} $detail */
    private function detailView(array $detail, string $navBase): string
    {
        $s = $detail['summary'];
        $facts = $detail['facts'];
        $hostL = strtolower((string) $s['host']);

        $crumbs = $this->baseCrumbs($navBase, 'Fleet');
        $crumbs[] = [(string) $s['host'], $navBase . '/fleet/' . $hostL];

        $gauges = $s['live']
            ? $this->gaugeHtml('CPU', (int) $s['cpuPct'], $s['cpuPct'] . '%')
                . $this->gaugeHtml('Memory', (int) $s['memPct'], $s['memGib'] . ' GiB')
                . $this->gaugeHtml('Disk', (int) $s['diskPct'], $s['diskPct'] . '% of usable')
            : '<p>Host is ' . $this->esc((string) $s['status']) . ' — no live metrics.</p>';

        $kv = $this->kvTableHtml([
            ['Status', (string) $s['status']],
            ['Role', (string) $s['role']],
            ['OS', (string) $s['os']],
            ['IP', (string) $s['ip']],
            ['Datacenter', (string) $s['dc']],
            ['Uptime', $s['live'] ? $s['uptimeDays'] . ' days' : '—'],
        ], ' class="alte-kv"');

        // services / processes (from HostFacts — coherent with the shell's `ps`)
        $psRows = [];
        foreach (array_slice($facts->processTable(), 0, 12) as $p) {
            $psRows[] = [(string) $p['pid'], $p['user'], $p['cpu'] . '%', $p['mem'] . '%', $p['command']];
        }
        $ps = $this->tableHtml(['PID', 'User', 'CPU', 'MEM', 'Command'], $psRows, ' class="alte-table alte-mono"');

        // listening sockets (from HostFacts::netstat)
        $sockRows = [];
        foreach ($facts->netstat() as $c) {
            $sockRows[] = [$c['proto'], $c['local'], $c['foreign'], $c['state']];
        }
        $sock = $this->tableHtml(['Proto', 'Local', 'Foreign', 'State'], $sockRows, ' class="alte-table alte-mono"');

        // Console only opens on a live host — a down box has no shell to attach to.
        $consoleBtn = $s['live']
            ? '<a class="alte-btn alte-btn-primary" href="' . $this->esc($navBase . '/fleet/' . $hostL . '/console') . '">Open console</a>'
            : '<span class="alte-btn alte-btn-disabled" aria-disabled="true">Open console</span>';
        $buttons = '<div class="alte-actions">' . $consoleBtn;
        foreach (['reboot', 'stop', 'restart', 'snapshot'] as $a) {
            $buttons .= ' <a class="alte-btn" href="' . $this->esc($navBase . '/fleet/' . $hostL . '/' . $a) . '">' . ucfirst($a) . '</a>';
        }
        // "Download latest backup" bait: a native download of /backup.zip. A registered service worker
        // fabricates an endless throttled stream client-side; without it the server sends a capped
        // fallback. Either way the fetch is logged as intel. The whole feature is gated at the Router
        // mount layer, so when it is off these paths fall through to the honeypot and the link is inert.
        $dlHref = '/backup.zip?host=' . rawurlencode($hostL);
        $buttons .= ' <a class="alte-btn" id="fp-dl-backup" href="' . $this->esc($dlHref) . '" download="backup.zip">Download latest backup</a>';
        $buttons .= '</div>';
        $buttons .= '<script>' . $this->downloadJs() . '</script>';

        return $this->breadcrumbHtml($crumbs)
            . $this->card((string) $s['host'], $gauges . $kv . $buttons, (string) $s['os'])
            . $this->card('Services', $ps, 'ps')
            . $this->card('Listening sockets', $sock, 'ss -tlnp');
    }

    /** Register the download service worker (scope "/") so it can intercept /backup.zip. Best-effort:
     *  if registration fails or SW is unsupported, the plain download link still hits the server
     *  fallback. No inline handlers, no external script. */
    private function downloadJs(): string
    {
        return "(function(){if('serviceWorker' in navigator){"
            . "navigator.serviceWorker.register('/__dl/sw.js',{scope:'/'}).catch(function(){});}})();";
    }

    /** @param array{summary:array<string,mixed>,facts:\Funnypot\Shell\Host\HostFacts} $detail */
    private function actionResult(array $detail, string $action, string $navBase): string
    {
        $s = $detail['summary'];
        $ticket = 'OPS-' . (crc32($action . '|' . $s['host']) % 90000 + 10000);
        $crumbs = $this->baseCrumbs($navBase, 'Fleet');
        $crumbs[] = [(string) $s['host'], $navBase . '/fleet/' . strtolower((string) $s['host'])];

        return $this->breadcrumbHtml($crumbs)
            . $this->controlResultCard(ucfirst($action) . ' queued', [
                ['Host', (string) $s['host']],
                ['Action', $action],
                ['State', 'queued — awaiting scheduler'],
                ['Request', $ticket],
            ]);
    }

    /** @param array{summary:array<string,mixed>,facts:\Funnypot\Shell\Host\HostFacts} $detail */
    private function consoleView(array $detail, string $navBase): string
    {
        $s = $detail['summary'];
        $facts = $detail['facts'];
        $host = (string) $s['host'];
        $crumbs = $this->baseCrumbs($navBase, 'Fleet');
        $crumbs[] = [$host, $navBase . '/fleet/' . strtolower($host)];
        $crumbs[] = ['console', $navBase . '/fleet/' . strtolower($host) . '/console'];

        // A host the fleet reports as down has no live shell to open — say so, don't render a terminal
        // that would then answer live commands (that mismatch is a tell).
        if (empty($s['live'])) {
            return $this->breadcrumbHtml($crumbs)
                . $this->card('Web console — ' . $host, '<p>Host is ' . $this->esc((string) $s['status']) . ' — console unavailable.</p>', 'offline');
        }

        // Live streaming web terminal: each command POSTs to the ConsoleRouter endpoint (a gate-exempt
        // Router-level route) and the response streams back in. The shell runs SERVER-side (all commands
        // logged as intel); the browser holds no filesystem state. Scoped inline JS only — no framework,
        // no external script (the panel's trusted-chrome exemption covers it).
        //
        // The MOTD is baked, but NOT the prompt: on load the client fetches the real prompt with an empty
        // command, so the shown cwd always matches the server session (a baked "~" would lie after a cd
        // then reload).
        $initial = 'Last login: ' . gmdate('D M j H:i:s Y') . ' from ' . (string) $s['ip'] . "\n"
            . $facts->uname() . "\n\n";
        $term = '<div class="alte-term" style="background:#0c0c0c;color:#d6d6d6;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;line-height:1.45;padding:12px;border-radius:4px">'
            . '<pre id="fp-term-out" style="margin:0;white-space:pre-wrap;overflow-wrap:anywhere;max-height:62vh;overflow:auto">' . $this->esc($initial) . '</pre>'
            . '<div style="display:flex;align-items:baseline"><input id="fp-term-in" autocomplete="off" autocapitalize="off" spellcheck="false" '
            . 'style="flex:1;background:transparent;border:0;color:#d6d6d6;font-family:inherit;font-size:13px;outline:none;padding:0"></div>'
            . '</div><script>' . $this->terminalJs($host) . '</script>';

        return $this->breadcrumbHtml($crumbs)
            . $this->card('Web console — ' . $host, $term, 'interactive terminal');
    }

    /** Scoped terminal client: POST each command to the console endpoint, stream the response back in.
     *  No inline event-handler attributes, no javascript:/data: URLs — only addEventListener + fetch.
     *  When a response ends without a shell prompt (exit/logout, or a down host), the input stays
     *  disabled — the session is over. On load it fetches the real initial prompt with an empty command. */
    private function terminalJs(string $host): string
    {
        // HEX flags keep the literal inert even if a host ever contained < & ' " (defence in depth; the
        // fleet's hosts are [a-z0-9-]).
        $h = (string) json_encode($host, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

        return '(function(){var H=' . $h . ",o=document.getElementById('fp-term-out'),i=document.getElementById('fp-term-in');"
            . 'if(!o||!i)return;'
            . 'function send(cmd){i.disabled=true;'
            . "return fetch('/__console/exec',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host:H,command:cmd})})"
            . '.then(function(r){var rd=r.body.getReader(),d=new TextDecoder();return (function p(){return rd.read().then(function(x){'
            . 'if(x.done){return;}o.textContent+=d.decode(x.value,{stream:true});o.scrollTop=o.scrollHeight;return p();});})();})'
            . ".catch(function(){o.textContent+='\\n[connection reset]\\n';})"
            . '.then(function(){if(/#\\s$/.test(o.textContent)){i.disabled=false;i.focus();}o.scrollTop=o.scrollHeight;});}'
            . "i.addEventListener('keydown',function(e){if(e.key!=='Enter')return;e.preventDefault();"
            . "var c=i.value;i.value='';o.textContent+=c+'\\n';send(c);});send('');})();";
    }
}
