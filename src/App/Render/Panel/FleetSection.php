<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Fleet;
use Funnypot\Support\VisualPersona;

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

        $buttons = '<div class="alte-actions">'
            . '<a class="alte-btn alte-btn-primary" href="' . $this->esc($navBase . '/fleet/' . $hostL . '/console') . '">Open console</a>';
        foreach (['reboot', 'stop', 'restart', 'snapshot'] as $a) {
            $buttons .= ' <a class="alte-btn" href="' . $this->esc($navBase . '/fleet/' . $hostL . '/' . $a) . '">' . ucfirst($a) . '</a>';
        }
        $buttons .= '</div>';

        return $this->breadcrumbHtml($crumbs)
            . $this->card((string) $s['host'], $gauges . $kv . $buttons, (string) $s['os'])
            . $this->card('Services', $ps, 'ps')
            . $this->card('Listening sockets', $sock, 'ss -tlnp');
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
        $crumbs = $this->baseCrumbs($navBase, 'Fleet');
        $crumbs[] = [(string) $s['host'], $navBase . '/fleet/' . strtolower((string) $s['host'])];
        $crumbs[] = ['console', $navBase . '/fleet/' . strtolower((string) $s['host']) . '/console'];

        // Phase-4 placeholder: a static console snapshot. Phase 5 replaces this with the live streaming
        // web terminal (a Router-level POST endpoint reusing StreamEmitter).
        $motd = [
            'Last login: ' . gmdate('D M j H:i:s Y') . ' from ' . (string) $s['ip'],
            $facts->uname(),
            '',
            'root@' . $facts->hostname() . ':~# ',
        ];

        return $this->breadcrumbHtml($crumbs)
            . $this->card('Web console — ' . (string) $s['host'], $this->preScrollHtml($motd, 'alte-console'), 'interactive terminal');
    }
}
