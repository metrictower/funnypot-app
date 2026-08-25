<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\FakeCron;
use Funnypot\App\Render\Fake\MinerRig;
use Funnypot\Core\Support\VisualPersona;

/** Processes: the ps table plus the "already compromised, actively mining" lure (migrated from
 *  AdminLteSkin::processesCard). */
final class ProcessesSection extends AbstractPanelSection
{
    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $seed = $persona->seed();
        // Miner lure: the box looks already-compromised and actively mining — a rabbit hole in itself.
        // Read the summary first so the process table below can inject a matching process line — the
        // alert must never appear above a ps table with no miner in it (that mismatch is a tell).
        $mr = MinerRig::fromSeed($seed);
        $s = $mr->summary();
        $rows = [];
        foreach (FakeCron::fromSeed($seed)->processes(['algo' => $s['algo'], 'pool' => $s['pool'], 'wallet' => $s['wallet']]) as $p) {
            $rows[] = [$p['pid'], $p['user'], $p['cpu'], $p['mem'], $p['command']];
        }
        $ps = $this->tableHtml(['PID', 'User', '%CPU', '%MEM', 'Command'], $rows, ' class="alte-table alte-mono"');
        $miner = $this->kvTableHtml([
            ['Status', 'ACTIVE — ' . $s['coin'] . ' (' . $s['algo'] . ')'],
            ['Pool', $s['pool']],
            ['Wallet', $s['wallet']],
            ['Hashrate', $s['totalHashrate'] . ' · ' . $s['workersOnline'] . ' workers'],
            ['Unpaid balance', $s['unpaidBalance'] . ' (~' . $s['estDailyUsd'] . '/day)'],
        ], ' class="alte-kv"');
        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Processes'))
            . $this->card('Processes', $ps, 'ps aux')
            . $this->card('Miner detected', $miner, 'lfd: suspicious process');
    }
}
