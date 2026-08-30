<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\DeviceConsole;
use Funnypot\Core\Support\VisualPersona;

/**
 * The operational-device console for a device-id path (/{mount}/{device-id}) — a POS terminal, a
 * host/mainframe, a PLC/controller or an embedded gateway. Scanners probe these device paths by name;
 * without this they fell through to the generic Dashboard. AdminLteSkin dispatches here (instead of the
 * Dashboard fallback) only for an UNREGISTERED module slug that looks like a device id, so a real panel
 * module is never captured (see DeviceConsole::looksLikeDevice).
 *
 * The console is READ-ONLY by design: the panel routes on the path only (the query string is stripped
 * before routing), so there is no live command echo to reflect or to poison the path cache — the command
 * box submits back to the same page and the transcript soft-denies a privileged verb from a monitor role.
 * Everything is deterministic per (seed, device-id) via Fake\DeviceConsole and escape-by-construction.
 */
final class DeviceConsoleSection extends AbstractPanelSection
{
    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $id = (string) ($route['module'] ?? '');

        // Any slug that is not itself device-shaped is the fleet landing: the registered `consoles` slug,
        // its aliases (op-consoles/terminals/fleet-consoles — which reach this section without rewriting
        // the module), and the empty root. A device console detail is only ever reached with a
        // device-shaped id (the skin's !has() && looksLikeDevice() gate), so that is the exact split.
        if ($id === '' || !DeviceConsole::looksLikeDevice($id)) {
            return $this->fleetLanding($persona, $navBase);
        }

        $d = DeviceConsole::forId($persona->seed(), $id);

        $crumbs = [['Consoles', $navBase . '/consoles'], [$id, '']];
        $html = $this->breadcrumbHtml($crumbs);

        $html .= '<div class="fp-page-head" style="display:flex;align-items:center;gap:10px;margin-bottom:10px">'
            . '<h2 style="margin:0;font-size:1.15em">' . $this->esc($d['personaLabel']) . ' &mdash; ' . $this->esc($id) . '</h2>'
            . $this->pillHtml($d['statusLabel'], $d['status'])
            . '</div>';

        // Identity / status table.
        $html .= $this->card('Device', $this->kvTableHtml($d['detail'], ' class="fp-kv" style="border-collapse:collapse;width:100%"'));

        // A read-only terminal transcript: banner, a monitor login, a status read-back, and a privileged
        // verb soft-denied. Canned + deterministic; no attacker input is ever echoed.
        $term = array_merge(
            explode("\n", $d['banner']),
            [
                '',
                $id . ' login: monitor',
                'Last login: ' . $d['lastContact'] . ' from ' . $this->loginFrom($d['ip']),
                '',
                'monitor@' . $id . ':~$ show status',
                $d['personaLabel'] . ' ' . $d['statusLabel'] . ' — uptime ' . $d['uptime'],
                'monitor@' . $id . ':~$ config',
                '% access denied: read-only session (role: monitor)',
                'monitor@' . $id . ':~$ ',
            ]
        );

        $consoleBody = $this->preScrollHtml($term, 'fp-console-term')
            . $this->commandForm($navBase, $id)
            . '<p class="fp-muted" style="margin:8px 0 0;font-size:.85em">Monitoring session (role: monitor). '
            . 'Command execution is disabled on this account.</p>';
        $html .= $this->card('Console', $consoleBody);

        // Recent activity log.
        $html .= $this->card('Recent activity', $this->preScrollHtml($d['activity'], 'fp-console-log'));

        return $html;
    }

    /** The fleet landing: a table of device consoles, each id linking to its own console page. */
    private function fleetLanding(VisualPersona $persona, string $navBase): string
    {
        $fleet = DeviceConsole::fleet($persona->seed());

        $rows = '';
        foreach ($fleet as $dev) {
            $href = $this->esc($navBase . '/' . $dev['id']);
            $rows .= '<tr>'
                . '<td><a href="' . $href . '">' . $this->esc($dev['id']) . '</a></td>'
                . '<td>' . $this->esc($dev['personaLabel']) . '</td>'
                . '<td>' . $this->esc($dev['site']) . '</td>'
                . '<td>' . $this->pillHtml($dev['statusLabel'], $dev['status']) . '</td>'
                . '</tr>';
        }
        $table = '<table class="fp-devices" style="border-collapse:collapse;width:100%">'
            . '<thead><tr><th>Device</th><th>Type</th><th>Site</th><th>Status</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table>';

        return $this->breadcrumbHtml([['Consoles', '']])
            . $this->card('Operational consoles', $table);
    }

    /** The command box. Submits GET to the same device path; the panel strips the query, so it simply
     *  reloads the read-only console — no attacker value is ever reflected or cached. */
    private function commandForm(string $navBase, string $id): string
    {
        $action = $this->esc($navBase . '/' . $id);

        return '<form class="fp-console-cmd" method="get" action="' . $action . '" '
            . 'style="display:flex;gap:8px;margin-top:10px">'
            . '<span style="font-family:monospace;align-self:center;color:#6c757d">monitor@' . $this->esc($id) . ':~$</span>'
            . '<input type="text" name="cmd" autocomplete="off" spellcheck="false" '
            . 'placeholder="enter a command" style="flex:1;font-family:monospace;padding:4px 8px" />'
            . '<button type="submit" style="padding:4px 12px">Run</button>'
            . '</form>';
    }

    /** A plausible inert source address for the "last login" line, derived from the device's own subnet. */
    private function loginFrom(string $ip): string
    {
        $dot = strrpos($ip, '.');
        $net = $dot !== false ? substr($ip, 0, $dot) : '10.0.0';

        return $net . '.9';
    }
}
