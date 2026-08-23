<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Skins;

use Funnypot\App\Render\AbstractSkin;
use Funnypot\App\Render\Fake\ServerProfile;
use Funnypot\App\Render\PageSlots;
use Funnypot\App\Render\PathSegments;
use Funnypot\App\Render\VisualPersona;

/**
 * A hand-authored lookalike of an AdminLTE/Bootstrap-style admin panel: a fixed left sidebar of menu
 * links, a top navbar naming the company, and card content in the main pane. Structural resemblance
 * only — no upstream AdminLTE/Bootstrap markup or CSS bytes are reproduced. This is the broadest
 * matcher of the four skins (`/admin`, `/dashboard`, `/manage`), so it is registered last in the
 * SkinSet — more specific product analogs (WordPress, phpMyAdmin, Grafana) get first refusal.
 */
final class AdminLteSkin extends AbstractSkin
{
    public function matches(string $path): bool
    {
        // This is the broadest resemblance matcher of the four, so it anchors the tightest: each
        // token must BE a whole path segment — or that segment plus a file extension (admin.php,
        // admin.aspx, dashboard.php, manage.php) — not merely appear inside one (e.g. "admin-notes"
        // and "administer" are not "admin"). "administrator" (Joomla's admin path, a common scanner
        // target) gets its own exact-segment token since the dot-suffix rule doesn't reach it — there
        // is no dot right after "admin" in "administrator". That's what keeps this skin from
        // swallowing paths it has no real business claiming, on top of being registered last in the
        // SkinSet.
        return PathSegments::hasSegmentOrDotSuffix($path, 'admin')
            || PathSegments::hasSegmentOrDotSuffix($path, 'dashboard')
            || PathSegments::hasSegmentOrDotSuffix($path, 'manage')
            || PathSegments::hasSegmentOrDotSuffix($path, 'panel')
            || PathSegments::hasSegmentOrDotSuffix($path, 'console')
            || PathSegments::hasSegmentOrDotSuffix($path, 'cp')
            || PathSegments::has($path, 'administrator');
    }

    public function key(): string
    {
        return 'adminlte';
    }

    public function render(PageSlots $slots, VisualPersona $persona, string $escapedPath, string $path = ''): string
    {
        $navBase = $this->navBase($path);
        $company = $this->esc($persona->company());
        $appName = $this->esc($slots->appName());
        $title = $slots->pageTitle() !== '' ? $slots->pageTitle() : $slots->appName();

        $html = '<div class="alte-wrapper">';

        $html .= '<nav class="alte-navbar">';
        $html .= '<span class="alte-brand">' . $company . '</span>';
        if ($appName !== '') {
            $html .= '<span class="alte-app">' . $appName . '</span>';
        }
        $html .= '</nav>';

        $html .= '<aside class="alte-sidebar">';
        $html .= '<ul class="alte-nav-sidebar">';
        foreach ($slots->navItems() as $item) {
            $html .= '<li class="alte-nav-item">' . $this->navHtml([$item], 'alte-nav-link', $navBase) . '</li>';
        }
        $html .= '</ul>';
        $html .= '</aside>';

        $html .= '<div class="alte-content-wrapper"><section class="alte-content">';
        $html .= '<div class="alte-card">';

        $heading = $slots->heading();
        if ($heading !== '') {
            $html .= '<div class="alte-card-header">' . $this->esc($heading) . '</div>';
        }
        $html .= '<div class="alte-card-body">';
        if ($slots->intro() !== '') {
            $html .= '<p class="alte-intro">' . $this->esc($slots->intro()) . '</p>';
        }

        $html .= $this->tableHtml($slots->tableCols(), $slots->tableRows(), ' class="alte-table"');

        if ($slots->flash() !== '') {
            $html .= '<div class="alte-flash">' . $this->esc($slots->flash()) . '</div>';
        }
        $html .= '</div>'; // alte-card-body
        $html .= '</div>'; // alte-card

        // Deterministic server-panel enrichment: stat cards, hardware, backups (bait) and a bottomless
        // loot table. Always-on for this "server control panel" skin, seeded off the persona so the host
        // identity stays coherent with the rest of the page. Frozen per deploy (bucket 0) so the cached
        // page stays byte-identical. All values inert; backup links route to the decoy-archive handler.
        $sp = ServerProfile::fromSeed($persona->seed());
        $cpu = $sp->cpu();
        $mem = $sp->memory();
        $stg = $sp->storage();
        $osx = $sp->os();
        $chs = $sp->chassis();
        $live = $sp->liveStats(0);
        $upd = $sp->pendingUpdates();

        $html .= $this->statCardsHtml([
            ['label' => 'CPU load', 'value' => $live['cpuPct'] . '%', 'sub' => $cpu['cores'] . ' cores / ' . $cpu['threads'] . ' threads'],
            ['label' => 'Memory', 'value' => $live['memUsedGib'] . ' / ' . $mem['totalGib'] . ' GiB'],
            ['label' => 'Load average', 'value' => $live['load1'] . ', ' . $live['load5'] . ', ' . $live['load15']],
            ['label' => 'Uptime', 'value' => $sp->uptimeDays() . ' days'],
            ['label' => 'Data volume', 'value' => $stg['usedPct'] . '% of ' . $stg['usableTb'] . ' TB', 'sub' => 'RAID-6'],
            ['label' => 'Pending updates', 'value' => (string) $upd['total'], 'sub' => $upd['security'] . ' security'],
        ], 'alte-stats', 'alte-st');

        $html .= '<div class="alte-card"><div class="alte-card-header">System Information</div><div class="alte-card-body">';
        $html .= $this->kvTableHtml([
            ['CPU', $cpu['sockets'] . '× ' . $cpu['model'] . ' (' . $cpu['cores'] . 'C/' . $cpu['threads'] . 'T)'],
            ['Memory', $mem['totalGib'] . ' GiB — ' . $mem['dimmCount'] . '× ' . $mem['dimmSizeGb'] . ' GB ' . $mem['dimmPart'] . ' @ ' . $mem['speed'] . ' MT/s'],
            ['Storage', '2× ' . $stg['bootModel'] . ' NVMe RAID-1 · ' . $stg['dataDisks'] . '× ' . $stg['dataDiskTb'] . ' TB ' . $stg['dataModel'] . ' on ' . $stg['controller'] . ' (~' . $stg['usableTb'] . ' TB, ' . $stg['usedPct'] . '% full)'],
            ['OS', $osx['distro'] . ' — ' . $osx['kernel']],
            ['Chassis', $chs['vendor'] . ' ' . $chs['product'] . ' · BIOS ' . $chs['biosVendor'] . ' ' . $chs['biosVer']],
            ['Service tag', $chs['serviceTag'] . ' · UUID ' . $chs['uuid']],
            ['Network', 'bond0 (LACP) 20000 Mb/s · ' . $sp->primaryIp() . '/24'],
        ], ' class="alte-kv"');
        $html .= '</div></div>';

        $bkRows = [];
        foreach ($sp->backups() as $b) {
            $bkRows[] = ['file' => $b['name'], 'cells' => [$b['size'], $b['age'], 'Download']];
        }
        $html .= '<div class="alte-card"><div class="alte-card-header">Backups</div><div class="alte-card-body">';
        $html .= $this->downloadTableHtml(['File', 'Size', 'Created', ''], $bkRows, $navBase, '/backups', ' class="alte-table"', 'alte-dl');
        $html .= '</div></div>';

        $loot = $sp->lootRowCount('users');
        $lootRows = $sp->lootUsers($persona->domain());
        $html .= '<div class="alte-card"><div class="alte-card-header">users</div><div class="alte-card-body">';
        $html .= $this->tableHtml(['id', 'username', 'email', 'role', 'password_hash'], $lootRows, ' class="alte-table"');
        $html .= '<div class="alte-pager">Showing 1&ndash;' . count($lootRows) . ' of ' . number_format($loot) . ' rows</div>';
        $html .= '</div></div>';

        $html .= '</section></div>'; // alte-content-wrapper

        $html .= '</div>'; // alte-wrapper

        return $this->document(
            $title,
            $this->css(),
            $html,
            ' lang="en"',
            '<meta charset="utf-8"><meta name="viewport" content="width=device-width">',
            ' class="alte-body"'
        );
    }

    private function css(): string
    {
        // Palette reads as a Bootstrap-admin-template scheme (dark sidebar, blue-grey accent) but every
        // hex is nudged off any specific template's exact brand tokens — resemblance, not reuse.
        return 'body.alte-body{margin:0;font-family:sans-serif;background:#eef1f3;color:#2c3136}'
            . '.alte-wrapper{min-height:100vh}'
            . '.alte-navbar{position:fixed;top:0;left:0;right:0;height:52px;background:#fff;'
            . 'border-bottom:1px solid #d7dbdf;display:flex;align-items:center;gap:10px;padding:0 16px;'
            . 'box-sizing:border-box;z-index:2}'
            . '.alte-brand{font-weight:bold;color:#3b7ea1}'
            . '.alte-app{color:#6c757d}'
            . '.alte-sidebar{position:fixed;top:52px;bottom:0;left:0;width:230px;background:#2f3640;'
            . 'padding-top:10px;box-sizing:border-box;overflow-y:auto}'
            . '.alte-nav-sidebar{list-style:none;margin:0;padding:0}'
            . '.alte-nav-item{margin:0}'
            . '.alte-nav-link{display:block;padding:10px 16px;color:#c9ccd1;text-decoration:none}'
            . '.alte-nav-link:hover{background:#3b4148;color:#fff}'
            . '.alte-content-wrapper{margin-left:230px;padding-top:52px;box-sizing:border-box}'
            . '.alte-content{padding:20px}'
            . '.alte-card{background:#fff;border:1px solid #d7dbdf;border-radius:4px}'
            . '.alte-card-header{padding:10px 14px;border-bottom:1px solid #d7dbdf;font-weight:bold;'
            . 'color:#2c3136}'
            . '.alte-card-body{padding:14px}'
            . '.alte-intro{color:#5b636a}'
            . '.alte-table{border-collapse:collapse;width:100%;margin-top:8px}'
            . '.alte-table th,.alte-table td{border:1px solid #d7dbdf;padding:6px 10px;text-align:left}'
            . '.alte-flash{margin-top:12px;padding:8px 12px;background:#eaf2f6;border-left:4px solid #3b7ea1}'
            . '.alte-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:20px}'
            . '.alte-st{background:#fff;border:1px solid #d7dbdf;border-radius:4px;padding:14px 16px}'
            . '.alte-st-v{font-size:1.5em;font-weight:bold;color:#2c3136}'
            . '.alte-st-l{color:#6c757d;font-size:.82em;margin-top:2px}'
            . '.alte-st-sub{color:#9aa1a8;font-size:.74em;margin-top:4px}'
            . '.alte-kv{border-collapse:collapse;width:100%}'
            . '.alte-kv th{width:150px;text-align:left;color:#6c757d;font-weight:600;vertical-align:top;'
            . 'padding:6px 10px;border-bottom:1px solid #eef1f3}'
            . '.alte-kv td{padding:6px 10px;border-bottom:1px solid #eef1f3}'
            . '.alte-dl{color:#3b7ea1;text-decoration:none;font-family:monospace}'
            . '.alte-dl:hover{text-decoration:underline}'
            . '.alte-pager{padding:10px 4px;color:#6c757d;font-size:.84em}';
    }
}
