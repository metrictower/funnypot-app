<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Skins;

use Funnypot\App\Render\AbstractSkin;
use Funnypot\App\Render\Fake\FakeCron;
use Funnypot\App\Render\Fake\FakeFiles;
use Funnypot\App\Render\Fake\FakeInfra;
use Funnypot\App\Render\Fake\FakeLog;
use Funnypot\App\Render\Fake\FakeSecrets;
use Funnypot\App\Render\Fake\MinerRig;
use Funnypot\App\Render\Fake\ServerProfile;
use Funnypot\App\Render\PageSlots;
use Funnypot\App\Render\PathSegments;
use Funnypot\App\Render\VisualPersona;

/**
 * A hand-authored lookalike of an AdminLTE/Bootstrap-style server control panel. Structural resemblance
 * only — no upstream AdminLTE/Bootstrap markup or CSS bytes are reproduced.
 *
 * This is the honeypot's flagship "juicy host" panel: a fixed sidebar whose every link leads to a
 * different deterministic, INERT, bait-filled sub-page (system info, backups, users, API keys, cron,
 * processes, logs, files). The current page is chosen from the request path's last segment, so a
 * crawler following the nav stays inside one coherent site and finds a fresh rabbit hole on each click.
 * All data comes from the Fake\* generators seeded off the persona, so the whole host identity agrees;
 * it is frozen per deploy so the cached page is byte-identical. Every downloadable link keeps its
 * archive extension so it routes to the decoy-archive handler.
 *
 * It is the broadest matcher of the skins, so it is registered last in the SkinSet — more specific
 * product analogs (WordPress, phpMyAdmin, Grafana) get first refusal.
 */
final class AdminLteSkin extends AbstractSkin
{
    /** Fixed sidebar — each label slugs to a view the panel can render (see viewFor()). */
    private const NAV = [
        'Dashboard', 'System Info', 'Databases', 'Backups', 'Users',
        'API Keys', 'Cron', 'Processes', 'Logs', 'Files',
    ];

    public function matches(string $path): bool
    {
        // Each token must BE a whole path segment (or that segment plus a file extension) so the skin
        // does not swallow paths it has no business claiming. panel/console/cp keep the whole /panel/*
        // subtree in this one skin as a crawler follows the sidebar; administrator is Joomla's admin path.
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
        $seed = $persona->seed();
        $sp = ServerProfile::fromSeed($seed);
        $company = $this->esc($persona->company());
        $appName = $this->esc($slots->appName() !== '' ? $slots->appName() : 'Control Panel');
        $view = $this->viewFor($path);
        $title = $slots->pageTitle() !== '' ? $slots->pageTitle() : $this->viewTitle($view);

        $html = '<div class="alte-wrapper">';

        $html .= '<nav class="alte-navbar"><span class="alte-brand">' . $company . '</span>'
            . '<span class="alte-app">' . $appName . ' &middot; ' . $this->esc($sp->hostname()) . '</span></nav>';

        $html .= '<aside class="alte-sidebar"><ul class="alte-nav-sidebar">';
        foreach (self::NAV as $label) {
            $html .= '<li class="alte-nav-item">' . $this->navHtml([$label], 'alte-nav-link', $navBase) . '</li>';
        }
        $html .= '</ul></aside>';

        $html .= '<div class="alte-content-wrapper"><section class="alte-content">';

        // The model's heading/intro (when present) becomes a small page header above the deterministic
        // sections, so an LLM-shaped page still reads coherently on a templated-miss path.
        if ($slots->heading() !== '' || $slots->intro() !== '') {
            $html .= '<div class="alte-card"><div class="alte-card-body">';
            if ($slots->heading() !== '') {
                $html .= '<div class="alte-card-header">' . $this->esc($slots->heading()) . '</div>';
            }
            if ($slots->intro() !== '') {
                $html .= '<p class="alte-intro">' . $this->esc($slots->intro()) . '</p>';
            }
            $html .= '</div></div>';
        }

        $html .= $this->statCards($sp);
        $html .= $this->sectionFor($view, $sp, $persona, $navBase);

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

    /** Map the request path's last segment to a panel view; unknown/root falls to the dashboard. */
    private function viewFor(string $path): string
    {
        $segs = array_values(array_filter(explode('/', $path), static function (string $s): bool {
            return $s !== '';
        }));
        $last = $segs === [] ? '' : strtolower((string) preg_replace('/[^a-z0-9]+/', '-', strtolower(end($segs))));
        $map = [
            'system-info' => 'system', 'system' => 'system',
            'databases' => 'db', 'database' => 'db', 'users' => 'db', 'db' => 'db',
            'backups' => 'backups', 'backup' => 'backups',
            'api-keys' => 'keys', 'keys' => 'keys', 'tokens' => 'keys',
            'cron' => 'cron', 'jobs' => 'cron',
            'processes' => 'processes', 'ps' => 'processes',
            'logs' => 'logs', 'log' => 'logs',
            'files' => 'files', 'filemanager' => 'files',
        ];
        return $map[$last] ?? 'dashboard';
    }

    private function viewTitle(string $view): string
    {
        $t = [
            'system' => 'System Information', 'db' => 'Databases', 'backups' => 'Backups',
            'keys' => 'API Keys', 'cron' => 'Scheduled Tasks', 'processes' => 'Processes',
            'logs' => 'Logs', 'files' => 'File Manager', 'dashboard' => 'Dashboard',
        ];
        return $t[$view] ?? 'Dashboard';
    }

    private function statCards(ServerProfile $sp): string
    {
        $cpu = $sp->cpu();
        $mem = $sp->memory();
        $stg = $sp->storage();
        $live = $sp->liveStats(0);
        $upd = $sp->pendingUpdates();
        return $this->statCardsHtml([
            ['label' => 'CPU load', 'value' => $live['cpuPct'] . '%', 'sub' => $cpu['cores'] . ' cores / ' . $cpu['threads'] . ' threads'],
            ['label' => 'Memory', 'value' => $live['memUsedGib'] . ' / ' . $mem['totalGib'] . ' GiB'],
            ['label' => 'Load average', 'value' => $live['load1'] . ', ' . $live['load5'] . ', ' . $live['load15']],
            ['label' => 'Uptime', 'value' => $sp->uptimeDays() . ' days'],
            ['label' => 'Data volume', 'value' => $stg['usedPct'] . '% of ' . $stg['usableTb'] . ' TB', 'sub' => 'RAID-6'],
            ['label' => 'Pending updates', 'value' => (string) $upd['total'], 'sub' => $upd['security'] . ' security'],
        ], 'alte-stats', 'alte-st');
    }

    private function sectionFor(string $view, ServerProfile $sp, VisualPersona $persona, string $navBase): string
    {
        switch ($view) {
            case 'system':
                return $this->systemCard($sp);
            case 'backups':
                return $this->backupsCard($sp, $navBase);
            case 'db':
                return $this->lootCard($sp, $persona);
            case 'keys':
                return $this->keysCard($persona->seed());
            case 'cron':
                return $this->cronCard($persona->seed());
            case 'processes':
                return $this->processesCard($persona->seed());
            case 'logs':
                return $this->logsCard($persona->seed());
            case 'files':
                return $this->filesCard($persona->seed(), $navBase);
            default:
                // Dashboard: a summary of the most tempting rabbit holes.
                return $this->systemCard($sp) . $this->backupsCard($sp, $navBase) . $this->lootCard($sp, $persona);
        }
    }

    private function card(string $header, string $body, string $headerExtra = ''): string
    {
        $extra = $headerExtra !== '' ? '<span class="alte-muted">' . $this->esc($headerExtra) . '</span>' : '';
        return '<div class="alte-card"><div class="alte-card-header">' . $this->esc($header) . $extra . '</div>'
            . '<div class="alte-card-body">' . $body . '</div></div>';
    }

    private function systemCard(ServerProfile $sp): string
    {
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
        return $this->card('System Information', $kv, $sp->chassis()['vendor'] . ' ' . $sp->chassis()['product']);
    }

    private function backupsCard(ServerProfile $sp, string $navBase): string
    {
        $rows = [];
        foreach ($sp->backups() as $b) {
            $rows[] = ['file' => $b['name'], 'cells' => [$b['size'], $b['age'], 'Download']];
        }
        $table = $this->downloadTableHtml(['File', 'Size', 'Created', ''], $rows, $navBase, '/backups', ' class="alte-table"', 'alte-dl');
        return $this->card('Backups', $table, 'Keep last 7 · retain 30 days');
    }

    private function lootCard(ServerProfile $sp, VisualPersona $persona): string
    {
        $rows = $sp->lootUsers($persona->domain());
        $total = $sp->lootRowCount('users');
        $table = $this->tableHtml(['id', 'username', 'email', 'role', 'password_hash'], $rows, ' class="alte-table"');
        $table .= '<div class="alte-pager">Showing 1&ndash;' . count($rows) . ' of ' . number_format($total) . ' rows</div>';
        return $this->card('users', $table, 'appdb · InnoDB');
    }

    private function keysCard(int $seed): string
    {
        $fs = FakeSecrets::fromSeed($seed);
        $rows = [];
        foreach ($fs->keys() as $k) {
            $rows[] = [$k['label'], $k['masked'], $k['created'], $k['lastUsed']];
        }
        $keys = $this->tableHtml(['Name', 'Key', 'Created', 'Last used'], $rows, ' class="alte-table"');
        $env = $this->kvTableHtml($fs->envVars(), ' class="alte-kv"');
        return $this->card('API Keys', $keys, 'Reveal to copy')
            . $this->card('.env', $env, 'application environment');
    }

    private function cronCard(int $seed): string
    {
        $rows = [];
        foreach (FakeCron::fromSeed($seed)->cronJobs() as $c) {
            $rows[] = [$c['schedule'], $c['user'], $c['command']];
        }
        return $this->card('Scheduled Tasks', $this->tableHtml(['Schedule', 'User', 'Command'], $rows, ' class="alte-table alte-mono"'), 'crontab');
    }

    private function processesCard(int $seed): string
    {
        $rows = [];
        foreach (FakeCron::fromSeed($seed)->processes() as $p) {
            $rows[] = [$p['pid'], $p['user'], $p['cpu'], $p['mem'], $p['command']];
        }
        $ps = $this->tableHtml(['PID', 'User', '%CPU', '%MEM', 'Command'], $rows, ' class="alte-table alte-mono"');
        // Miner lure: the box looks already-compromised and actively mining — a rabbit hole in itself.
        $mr = MinerRig::fromSeed($seed);
        $s = $mr->summary();
        $miner = $this->kvTableHtml([
            ['Status', 'ACTIVE — ' . $s['coin'] . ' (' . $s['algo'] . ')'],
            ['Pool', $s['pool']],
            ['Wallet', $s['wallet']],
            ['Hashrate', $s['totalHashrate'] . ' · ' . $s['workersOnline'] . ' workers'],
            ['Unpaid balance', $s['unpaidBalance'] . ' (~' . $s['estDailyUsd'] . '/day)'],
        ], ' class="alte-kv"');
        return $this->card('Processes', $ps, 'ps aux')
            . $this->card('Miner detected', $miner, 'lfd: suspicious process');
    }

    private function logsCard(int $seed): string
    {
        $log = FakeLog::fromSeed($seed);
        return $this->card('auth.log', $this->preScrollHtml($log->authLog(400), 'alte-log'), '/var/log/auth.log')
            . $this->card('access.log', $this->preScrollHtml($log->accessLog(200), 'alte-log'), '/var/log/nginx/access.log');
    }

    private function filesCard(int $seed, string $navBase): string
    {
        $ff = FakeFiles::fromSeed($seed);
        $out = '';
        foreach ($ff->dirs() as $dir) {
            $rows = '';
            foreach ($ff->listing($dir) as $f) {
                $name = $f['name'];
                $label = $f['isDir'] ? $this->esc($name . '/') : $this->esc($name);
                // Only downloadable files become links (they keep their extension -> decoy-archive handler);
                // dirs and text lures render as plain text.
                if ($f['isDownload'] && preg_match('/^[A-Za-z0-9._-]+$/', $name) === 1 && strpos($name, '..') === false) {
                    $label = '<a class="alte-dl" href="' . $this->esc($navBase . '/files/download/' . $name) . '">' . $this->esc($name) . '</a>';
                }
                $rows .= '<tr><td>' . $label . '</td><td>' . $this->esc($f['size']) . '</td><td>' . $this->esc($f['modified'])
                    . '</td><td>' . $this->esc($f['perms']) . '</td><td>' . $this->esc($f['owner']) . '</td></tr>';
            }
            $table = '<table class="alte-table alte-mono"><thead><tr><th>Name</th><th>Size</th><th>Modified</th><th>Perms</th><th>Owner</th></tr></thead><tbody>'
                . $rows . '</tbody></table>';
            $out .= $this->card($dir, $table, 'file manager');
        }
        return $out;
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
            . '.alte-app{color:#6c757d;font-size:.9em}'
            . '.alte-sidebar{position:fixed;top:52px;bottom:0;left:0;width:210px;background:#2f3640;'
            . 'padding-top:10px;box-sizing:border-box;overflow-y:auto}'
            . '.alte-nav-sidebar{list-style:none;margin:0;padding:0}'
            . '.alte-nav-item{margin:0}'
            . '.alte-nav-link{display:block;padding:10px 16px;color:#c9ccd1;text-decoration:none}'
            . '.alte-nav-link:hover{background:#3b4148;color:#fff}'
            . '.alte-content-wrapper{margin-left:210px;padding-top:52px;box-sizing:border-box}'
            . '.alte-content{padding:20px}'
            . '.alte-card{background:#fff;border:1px solid #d7dbdf;border-radius:4px;margin-bottom:20px}'
            . '.alte-card-header{padding:10px 14px;border-bottom:1px solid #d7dbdf;font-weight:bold;'
            . 'color:#2c3136;display:flex;justify-content:space-between;align-items:center}'
            . '.alte-card-body{padding:14px}'
            . '.alte-intro{color:#5b636a}'
            . '.alte-muted{font-weight:normal;color:#9aa1a8;font-size:.82em}'
            . '.alte-table{border-collapse:collapse;width:100%;margin-top:4px}'
            . '.alte-table th,.alte-table td{border:1px solid #eef1f3;padding:6px 10px;text-align:left;font-size:.88em}'
            . '.alte-table th{background:#f7f9fa;color:#6c757d}'
            . '.alte-mono td{font-family:monospace;font-size:.82em;white-space:nowrap}'
            . '.alte-flash{margin-top:12px;padding:8px 12px;background:#eaf2f6;border-left:4px solid #3b7ea1}'
            . '.alte-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:20px}'
            . '.alte-st{background:#fff;border:1px solid #d7dbdf;border-radius:4px;padding:14px 16px}'
            . '.alte-st-v{font-size:1.5em;font-weight:bold;color:#2c3136}'
            . '.alte-st-l{color:#6c757d;font-size:.82em;margin-top:2px}'
            . '.alte-st-sub{color:#9aa1a8;font-size:.74em;margin-top:4px}'
            . '.alte-kv{border-collapse:collapse;width:100%}'
            . '.alte-kv th{width:150px;text-align:left;color:#6c757d;font-weight:600;vertical-align:top;'
            . 'padding:6px 10px;border-bottom:1px solid #eef1f3}'
            . '.alte-kv td{padding:6px 10px;border-bottom:1px solid #eef1f3;font-size:.9em}'
            . '.alte-dl{color:#3b7ea1;text-decoration:none;font-family:monospace}'
            . '.alte-dl:hover{text-decoration:underline}'
            . '.alte-pager{padding:10px 4px;color:#6c757d;font-size:.84em}'
            . '.alte-log{background:#1b1e21;color:#c9ccd1;padding:12px;border-radius:4px;overflow-x:auto;'
            . 'font-size:.78em;line-height:1.5;max-height:520px;overflow-y:auto;margin:0}';
    }
}
