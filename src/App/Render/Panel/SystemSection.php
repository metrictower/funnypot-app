<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\ServerProfile;
use Funnypot\Core\Support\VisualPersona;

/** Servers / system information: the host hardware, OS and network identity (migrated from the old
 *  AdminLteSkin::systemCard). All facts from the seeded ServerProfile, so the whole host agrees. */
final class SystemSection extends AbstractPanelSection
{
    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $sp = ServerProfile::fromSeed($persona->seed());
        $cpu = $sp->cpu();
        $mem = $sp->memory();
        $stg = $sp->storage();
        $osx = $sp->os();
        $chs = $sp->chassis();
        $kv = $this->kvTableHtml([
            ['CPU', $cpu['sockets'] . '× ' . $cpu['model'] . ' (' . $cpu['cores'] . 'C/' . $cpu['threads'] . 'T)'],
            ['Memory', $mem['totalGib'] . ' GiB — ' . $mem['dimmCount'] . '× ' . $mem['dimmSizeGb'] . ' GB ' . $mem['dimmPart'] . ' @ ' . $mem['speed'] . ' MT/s'],
            ['Storage', '2× ' . $stg['bootModel'] . ' NVMe RAID-1 · ' . $stg['dataDisks'] . '× ' . $stg['dataDiskTb'] . ' TB ' . $stg['dataModel'] . ' on ' . $stg['controller'] . ' (~' . $stg['usableTb'] . ' TB, ' . $stg['usedPct'] . '% full)'],
            ['OS', $osx['distro'] . ' — ' . $osx['kernel']],
            ['Chassis', $chs['vendor'] . ' ' . $chs['product'] . ' · BIOS ' . $chs['biosVendor'] . ' ' . $chs['biosVer']],
            ['Service tag', $chs['serviceTag'] . ' · UUID ' . $chs['uuid']],
            ['Network', 'bond0 (LACP) 20000 Mb/s · ' . $sp->primaryIp() . '/24'],
        ], ' class="alte-kv"');
        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'System Information'))
            . $this->card('System Information', $kv, $chs['vendor'] . ' ' . $chs['product']);
    }
}
