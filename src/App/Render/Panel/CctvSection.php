<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\Cctv;
use Funnypot\Core\Support\VisualPersona;

/**
 * CCTV / Cameras (spec §C.4). One of the physical-power lures: a camera GRID of inline-SVG placeholders
 * (never an <img>/feed/socket — spec E10/S5, and CSP-clean), per-camera DETAIL with PTZ controls, an
 * RTSP/NVR bait string, and a recordings list that downloads to the decoy-archive handler.
 *
 * Route grammar within the module (module slug = `cctv`):
 *   /<mount>/cctv                         grid landing
 *   /<mount>/cctv/nvr                      NVR array overview
 *   /<mount>/cctv/events                   camera-plane event log
 *   /<mount>/cctv/<camId>                  camera detail (default sub-tab = live)
 *   /<mount>/cctv/<camId>/<subtab>         live | recordings | settings | nvr | events
 *   /<mount>/cctv/<camId>/<verb>/<arg>     control leaf -> controlResultCard (ptz/preset/snapshot/reboot/
 *                                          record queued; purge/disable guarded soft-deny)
 *
 * Cameras cross-reference Building rooms/controllers via Fake\Cctv, so a camera names the same room,
 * floor, zone and NVR that appear in every other building module. Everything is INERT and deterministic
 * per seed; the only reflected value (a control `arg`) reaches HTML only through the escaping helpers.
 */
final class CctvSection extends AbstractPanelSection
{
    /** Sub-tabs on a camera detail page. */
    private const TABS = ['live', 'recordings', 'settings', 'nvr', 'events'];

    /** Control verbs that resolve to a canned "queued" receipt. */
    private const QUEUED_VERBS = ['ptz', 'preset', 'snapshot', 'reboot', 'record', 'focus', 'zoom'];

    /** Sensitive verbs that resolve to a guarded soft-deny (never "done"). */
    private const GUARDED_VERBS = ['purge', 'disable', 'wipe', 'export'];

    /** Cameras per grid page. */
    private const PER_PAGE = 12;

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $cctv = Cctv::fromSeed($persona->seed());
        $camId = $route['section'];
        $verbOrTab = $route['entity'];
        $arg = $route['subtab'];

        if ($camId === '' || $camId === 'cameras') {
            return $this->landing($cctv, $navBase, $route['page']);
        }
        if ($camId === 'nvr') {
            return $this->nvrOverview($cctv, $navBase);
        }
        if ($camId === 'events') {
            return $this->eventsLog($cctv, $navBase);
        }

        $cam = $cctv->camera($camId);
        if ($verbOrTab !== '' && !in_array($verbOrTab, self::TABS, true)) {
            return $this->controlLeaf($cctv, $cam, $verbOrTab, $arg, $navBase, $persona->seed());
        }
        $tab = in_array($verbOrTab, self::TABS, true) ? $verbOrTab : 'live';
        return $this->cameraDetail($cctv, $cam, $tab, $navBase);
    }

    // --- landing: the camera grid ---

    private function landing(Cctv $cctv, string $navBase, int $page): string
    {
        $s = $cctv->summary();
        $tiles = $this->statCardsHtml([
            ['label' => 'Cameras', 'value' => (string) $s['total'], 'sub' => $s['recording'] . ' recording'],
            ['label' => 'Online', 'value' => $s['online'] . ' / ' . $s['total']],
            ['label' => 'No signal', 'value' => (string) $s['offline'], 'sub' => $s['offline'] === 0 ? 'all clear' : 'needs attention'],
            ['label' => 'NVR arrays', 'value' => (string) $s['nvrCount']],
            ['label' => 'Storage', 'value' => $s['usedTb'] . ' / ' . $s['capacityTb'] . ' TB'],
        ], 'fp-tiles', 'fp-tile');

        $cams = $cctv->cameras();
        $total = count($cams);
        $pages = (int) max(1, (int) ceil($total / self::PER_PAGE));
        $page = $page < 1 ? 1 : ($page > $pages ? $pages : $page);
        $slice = array_slice($cams, ($page - 1) * self::PER_PAGE, self::PER_PAGE);

        $grid = '<div class="fp-cam-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px">';
        foreach ($slice as $i => $c) {
            // Global position (not the page-local slice key) so the every-third-camera pattern is stable
            // across pages and each page still shows its share of test cards.
            $grid .= $this->cameraTile($c, $navBase, false, (($page - 1) * self::PER_PAGE) + $i);
        }
        $grid .= '</div>';

        $from = $total === 0 ? 0 : (($page - 1) * self::PER_PAGE) + 1;
        $to = min($total, $page * self::PER_PAGE);
        $pager = '<div class="fp-pager">Showing ' . $from . '&ndash;' . $to . ' of ' . $total . ' cameras'
            . $this->pagerLinks($navBase . '/cctv', $page, $pages) . '</div>';

        $quick = '<p class="alte-intro">'
            . '<a class="fp-dl" href="' . $this->esc($navBase . '/cctv/nvr') . '">NVR arrays</a> &middot; '
            . '<a class="fp-dl" href="' . $this->esc($navBase . '/cctv/events') . '">Event log</a></p>';

        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'CCTV'))
            . $tiles
            . $this->card('Live wall', $grid . $pager, $total . ' cameras')
            . $quick
            . $this->card('Recent events', $this->preScrollHtml($cctv->events(24), 'alte-log'), 'camera plane');
    }

    // --- camera detail + sub-tabs ---

    private function cameraDetail(Cctv $cctv, array $cam, string $tab, string $navBase): string
    {
        $crumbs = [['Corevance', $navBase], ['CCTV', $navBase . '/cctv'], [$cam['name'], '']];
        $base = $navBase . '/cctv/' . $cam['id'];

        $info = $this->kvTableHtml([
            ['Camera ID', $cam['id']],
            ['Location', $this->locationLabel($cam)],
            ['Status', ucfirst($cam['status'])],
            ['Model', $cam['model']],
            ['Resolution', $cam['resolution'] . ' @ ' . $cam['fps'] . ' fps'],
            ['Codec', $cam['codec']],
            ['IP address', $cam['ip'] . ':' . $cam['port']],
            ['RTSP URL', $cam['rtsp']],
            ['Recorder', $cam['nvr'] . ' · ' . $cam['channel']],
            ['Retention', $cam['retentionDays'] . ' days'],
            ['PTZ', $cam['ptz'] ? 'Supported' : 'Fixed'],
        ], ' class="alte-kv"');

        $body = $this->breadcrumbHtml($crumbs)
            . $this->tabStrip($base, $tab)
            . '<div class="alte-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px">'
            . $this->card('Stream', $this->cameraTile($cam, $navBase, true, $this->cameraIndex($cctv, $cam['id'])), $cam['status'] === 'online' ? 'live' : $cam['status'])
            . $this->card('Details', $info, $cam['model'])
            . '</div>';

        return $body . $this->tabBody($cctv, $cam, $tab, $base, $navBase);
    }

    private function tabStrip(string $base, string $active): string
    {
        $html = '<div class="fp-tabs" style="display:flex;gap:6px;flex-wrap:wrap;margin:12px 0;border-bottom:1px solid #d7dbdf">';
        foreach (self::TABS as $t) {
            $isOn = $t === $active;
            $style = 'padding:6px 12px;text-decoration:none;font-size:.85em;border:1px solid #d7dbdf;border-bottom:none;'
                . 'border-radius:4px 4px 0 0;'
                . ($isOn ? 'background:#fff;color:#2c3136;font-weight:600' : 'background:#eef1f3;color:#5b636a');
            $html .= '<a href="' . $this->esc($base . '/' . $t) . '" style="' . $style . '">' . $this->esc(ucfirst($t)) . '</a>';
        }
        return $html . '</div>';
    }

    private function tabBody(Cctv $cctv, array $cam, string $tab, string $base, string $navBase): string
    {
        switch ($tab) {
            case 'recordings':
                return $this->recordingsTab($cctv, $cam, $navBase);
            case 'settings':
                return $this->settingsTab($cam, $base);
            case 'nvr':
                return $this->cameraNvrTab($cctv, $cam, $navBase);
            case 'events':
                return $this->card('Events', $this->preScrollHtml($this->cameraEvents($cctv, $cam), 'alte-log'), $cam['id']);
            default:
                return $this->liveTab($cam, $base);
        }
    }

    /** Live tab: the placeholder plus the PTZ pad and canned camera controls. */
    private function liveTab(array $cam, string $base): string
    {
        $controls = $cam['ptz'] ? $this->ptzPad($base) : '<p class="fp-muted">Fixed camera &mdash; no PTZ.</p>';
        $presets = $cam['ptz'] ? $this->presetButtons($base) : '';
        $actions = '<p class="alte-intro">'
            . $this->actionLink($base . '/snapshot/now', 'Snapshot')
            . $this->actionLink($base . '/reboot/soft', 'Reboot')
            . $this->actionLink($base . '/record/toggle', 'Toggle recording')
            . $this->actionLink($base . '/purge/all', 'Purge footage')
            . '</p>';
        return $this->card('PTZ & controls', $controls . $presets . $actions, $cam['id']);
    }

    private function ptzPad(string $base): string
    {
        $btn = function (string $dir, string $label) use ($base) {
            return '<a href="' . $this->esc($base . '/ptz/' . $dir) . '" style="display:inline-flex;'
                . 'align-items:center;justify-content:center;width:44px;height:44px;margin:2px;border:1px solid #d7dbdf;'
                . 'border-radius:4px;background:#eef1f3;color:#2c3136;text-decoration:none;font-weight:600">'
                . $this->esc($label) . '</a>';
        };
        return '<div class="fp-ptz" style="display:inline-grid;grid-template-columns:repeat(3,44px);gap:0;margin-bottom:10px">'
            . '<span></span>' . $btn('up', '▲') . '<span></span>'
            . $btn('left', '◀') . $btn('home', '⌂') . $btn('right', '▶')
            . '<span></span>' . $btn('down', '▼') . '<span></span>'
            . '</div>'
            . '<div style="margin-bottom:10px">' . $this->actionLink($base . '/zoom/in', 'Zoom +')
            . $this->actionLink($base . '/zoom/out', 'Zoom -')
            . $this->actionLink($base . '/focus/near', 'Focus near')
            . $this->actionLink($base . '/focus/far', 'Focus far') . '</div>';
    }

    private function presetButtons(string $base): string
    {
        $names = ['Rack row', 'Doorway', 'Parking gate', 'Wide'];
        $html = '<div style="margin-bottom:10px">';
        foreach ($names as $i => $n) {
            $html .= $this->actionLink($base . '/preset/' . ($i + 1), 'Preset: ' . $n);
        }
        return $html . '</div>';
    }

    private function recordingsTab(Cctv $cctv, array $cam, string $navBase): string
    {
        $rows = [];
        foreach ($cctv->recordings($cam['id']) as $r) {
            $rows[] = ['file' => $r['file'], 'cells' => [$r['start'], $r['duration'], $r['size'], $r['trigger']]];
        }
        $sub = '/cctv/' . $cam['id'] . '/recordings';
        $table = $this->downloadTableHtml(
            ['Clip', 'Start', 'Duration', 'Size', 'Trigger'],
            $rows,
            $navBase,
            $sub,
            ' class="alte-table"',
            'fp-dl'
        );
        return $this->card('Recordings', $table, $cam['retentionDays'] . '-day retention');
    }

    private function settingsTab(array $cam, string $base): string
    {
        $kv = $this->kvTableHtml([
            ['Stream profile', 'main (' . $cam['resolution'] . ', ' . $cam['codec'] . ')'],
            ['Substream', 'sub (720p, H.264, 15 fps)'],
            ['Bitrate mode', 'VBR'],
            ['Frame rate', $cam['fps'] . ' fps'],
            ['Day/Night', 'Auto (IR-cut)'],
            ['Motion detection', 'Enabled'],
            ['Privacy masks', '0 zones'],
            ['OSD timestamp', 'On'],
        ], ' class="alte-kv"');
        $actions = '<p class="alte-intro">'
            . $this->actionLink($base . '/reboot/soft', 'Reboot')
            . $this->actionLink($base . '/disable/stream', 'Disable camera')
            . $this->actionLink($base . '/export/config', 'Export config')
            . '</p>';
        return $this->card('Settings', $kv . $actions, $cam['id']);
    }

    private function cameraNvrTab(Cctv $cctv, array $cam, string $navBase): string
    {
        foreach ($cctv->nvrArrays() as $n) {
            if ($n['id'] === $cam['nvr']) {
                return $this->card('Recorder', $this->nvrDetail($n, $navBase), $n['model']);
            }
        }
        return $this->card('Recorder', '<p class="fp-muted">Recorder ' . $this->esc($cam['nvr']) . ' not enumerated.</p>', $cam['nvr']);
    }

    // --- NVR overview ---

    private function nvrOverview(Cctv $cctv, string $navBase): string
    {
        $cards = '';
        foreach ($cctv->nvrArrays() as $n) {
            $cards .= $this->card($n['id'], $this->nvrDetail($n, $navBase), $n['model']);
        }
        $crumbs = [['Corevance', $navBase], ['CCTV', $navBase . '/cctv'], ['NVR arrays', '']];
        return $this->breadcrumbHtml($crumbs) . $cards;
    }

    private function nvrDetail(array $n, string $navBase): string
    {
        $pct = $n['totalTb'] > 0 ? (int) round($n['usedTb'] / $n['totalTb'] * 100) : 0;
        $gauge = $this->gaugeHtml('Storage', $pct, $n['usedTb'] . ' / ' . $n['totalTb'] . ' TB');
        $kv = $this->kvTableHtml([
            ['Model', $n['model']],
            ['IP address', $n['ip']],
            ['Protocol', $n['protocol']],
            ['Health', ucfirst($n['health'])],
            ['Cameras', (string) $n['cameras']],
            ['Retention', $n['retentionDays'] . ' days'],
            ['Capacity', $n['usedTb'] . ' TB used of ' . $n['totalTb'] . ' TB'],
        ], ' class="alte-kv"');
        return '<div class="alte-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px">'
            . '<div>' . $gauge . '</div><div>' . $kv . '</div></div>';
    }

    // --- events log ---

    private function eventsLog(Cctv $cctv, string $navBase): string
    {
        $crumbs = [['Corevance', $navBase], ['CCTV', $navBase . '/cctv'], ['Event log', '']];
        $pane = $this->preScrollHtml($cctv->events(120), 'alte-log');
        $total = number_format($cctv->eventBufferTotal());
        return $this->breadcrumbHtml($crumbs)
            . $this->card('Camera events', $pane . '<div class="fp-pager">Showing 1&ndash;120 of ' . $total . ' events</div>', 'motion · tamper · signal');
    }

    /** This camera's own event tail — always scoped to the camera, never another camera's ids. @return list<string> */
    private function cameraEvents(Cctv $cctv, array $cam): array
    {
        return $cctv->cameraEventsFor($cam['id'], 24);
    }

    // --- control leaf ---

    private function controlLeaf(Cctv $cctv, array $cam, string $verb, string $arg, string $navBase, int $seed): string
    {
        $crumbs = [['Corevance', $navBase], ['CCTV', $navBase . '/cctv'],
                   [$cam['name'], $navBase . '/cctv/' . $cam['id']], ['Command', '']];
        $target = $cam['name'] . ' (' . $cam['id'] . ')';

        if (in_array($verb, self::GUARDED_VERBS, true)) {
            return $this->breadcrumbHtml($crumbs) . $this->guardedCard($verb, $arg, $target, $cam, $seed);
        }

        // Queued (canned) receipt. The command ref mixes the persona seed so it varies per deploy (D.5);
        // the reflected arg is escaped by the helper.
        $jobId = 'cmd-' . substr(hash('sha256', $seed . '|cctvcmd|' . $cam['id'] . '|' . $verb . '|' . $arg), 0, 8);
        $action = $this->verbLabel($verb, $arg);
        $card = $this->controlResultCard($action . ' — ' . $target, [
            ['Camera', $cam['id']],
            ['Recorder', $cam['nvr'] . ' · ' . $cam['channel']],
            ['Command', $verb . ($arg !== '' ? ' ' . $arg : '')],
            ['Status', 'Queued to ' . $cam['nvr'] . '; applies at next controller poll (~15 s).'],
            ['Job', $jobId],
        ]);
        return $this->breadcrumbHtml($crumbs) . $card;
    }

    /** The sensitive-verb wall: reads like footage-integrity / dual-control policy, never returns "done". */
    private function guardedCard(string $verb, string $arg, string $target, array $cam, int $seed): string
    {
        $req = 'FAC-CMD-' . strtoupper(substr(hash('sha256', $seed . '|cctvcmd|' . $cam['id'] . '|' . $verb . '|' . $arg), 0, 6));
        $map = [
            'purge' => 'Purge footage DENIED — evidentiary hold. Retention is enforced by the recorder;'
                . ' a purge needs dual authorization (Security + Facilities) and a case reference.',
            'wipe' => 'Wipe DENIED — evidentiary hold. Bulk deletion is disabled on this recorder by policy.',
            'disable' => 'Disable DENIED — camera is on the protected life-safety group; disabling needs'
                . ' Security desk approval and a maintenance window.',
            'export' => 'Export DENIED — configuration export requires an operator role above your level.',
        ];
        $msg = isset($map[$verb]) ? $map[$verb] : 'Command DENIED — additional authorization required.';
        return '<div class="fp-result-card" style="background:#fff;border:1px solid #d7dbdf;border-left:4px solid #b23b3b;'
            . 'border-radius:4px;margin:16px 0">'
            . '<div class="fp-result-head" style="padding:10px 14px;border-bottom:1px solid #eef1f3;display:flex;align-items:center;gap:8px">'
            . $this->pillHtml('Denied', 'crit')
            . '<span style="font-weight:600;color:#2c3136">' . $this->esc($target) . '</span></div>'
            . '<div class="fp-result-body" style="padding:12px 14px">'
            . '<p style="margin:0 0 10px">' . $this->esc($msg) . '</p>'
            . $this->kvTableHtml([
                ['Requested', $verb . ($arg !== '' ? ' ' . $arg : '')],
                ['Request ref', $req],
                ['Routed to', 'Security desk'],
                ['State', 'Unchanged (interlock)'],
            ], ' class="alte-kv"')
            . '</div></div>';
    }

    // --- inline camera tile (SVG placeholder — never <img src>, CSP-clean) ---

    private function cameraTile(array $cam, string $navBase, bool $large, int $index = 0): string
    {
        $w = $large ? 480 : 320;
        $h = $large ? 270 : 180;
        $scene = $this->cameraScene($cam, $index);
        $bg = $scene === 'live' ? '#2c3136' : '#0a0a0a';

        // The picture: a live crosshair viewport, an SMPTE colour-bar calibration card, or TV snow on a
        // dead/tampered feed. Bars + snow are procedural SVG (rects / feTurbulence) — never an <img> (S5).
        if ($scene === 'bars') {
            $inner = $this->smpteBarsSvg($w, $h);
        } elseif ($scene === 'static') {
            $label = $cam['status'] === 'tampering' ? 'SIGNAL DISTURBED' : 'NO SIGNAL';
            $bw = $large ? 200 : 140;
            $inner = $this->staticSvg($w, $h, $cam['id'])
                . '<rect x="' . ($w / 2 - $bw / 2) . '" y="' . ($h / 2 - 17) . '" width="' . $bw . '" height="34" fill="#000" opacity="0.55"/>'
                . '<text x="' . ($w / 2) . '" y="' . ($h / 2 + 6) . '" text-anchor="middle" font-family="monospace" font-size="' . ($large ? 20 : 15) . '" fill="#e3e6e8" letter-spacing="2">' . $label . '</text>';
        } else {
            // A faint framing crosshair so the placeholder reads as a live viewport, not a blank box.
            $cx = $w / 2;
            $cy = $h / 2;
            $inner = '<circle cx="' . $cx . '" cy="' . $cy . '" r="' . ($large ? 34 : 22) . '" fill="none" stroke="#3f464d" stroke-width="1"/>'
                . '<line x1="' . ($cx - ($large ? 46 : 30)) . '" y1="' . $cy . '" x2="' . ($cx + ($large ? 46 : 30)) . '" y2="' . $cy . '" stroke="#3f464d" stroke-width="1"/>'
                . '<line x1="' . $cx . '" y1="' . ($cy - ($large ? 46 : 30)) . '" x2="' . $cx . '" y2="' . ($cy + ($large ? 46 : 30)) . '" stroke="#3f464d" stroke-width="1"/>';
        }

        // REC only on a live, recording camera — a test card or dead feed is not a live recording.
        $rec = '';
        if ($scene === 'live' && $cam['recording']) {
            $rec = '<circle cx="' . ($w - 58) . '" cy="18" r="5" fill="#b23b3b"/>'
                . '<text x="' . ($w - 48) . '" y="22" font-family="monospace" font-size="12" fill="#e3e6e8">REC</text>';
        }

        $svg = '<svg viewBox="0 0 ' . $w . ' ' . $h . '" preserveAspectRatio="xMidYMid meet" '
            . 'style="width:100%;height:auto;display:block;background:' . $bg . ';border-radius:4px" role="img">'
            . '<rect x="0" y="0" width="' . $w . '" height="' . $h . '" fill="' . $bg . '"/>'
            . $inner
            . '<text x="10" y="20" font-family="monospace" font-size="12" fill="#c9ccd1">' . $this->esc($cam['timecode']) . '</text>'
            . $rec
            . '<text x="10" y="' . ($h - 12) . '" font-family="monospace" font-size="' . ($large ? 14 : 12) . '" fill="#e3e6e8">'
            . $this->esc($this->truncate($cam['name'], $large ? 44 : 26)) . '</text>'
            . '<text x="' . ($w - 10) . '" y="' . ($h - 12) . '" text-anchor="end" font-family="monospace" font-size="11" fill="#8a9199">'
            . $this->esc($cam['id']) . '</text>'
            . '</svg>';

        if ($large) {
            return '<div class="fp-cam-tile">' . $svg . '</div>';
        }
        // Grid tiles link to the camera detail.
        $href = $this->esc($navBase . '/cctv/' . $cam['id']);
        return '<a class="fp-cam-tile" href="' . $href . '" style="text-decoration:none;color:inherit;display:block">'
            . $svg
            . '<div style="font-size:.82em;color:#2c3136;margin-top:4px;font-weight:600">' . $this->esc($cam['name']) . '</div>'
            . '<div style="font-size:.74em;color:#9aa1a8">' . $this->esc($this->locationLabel($cam)) . '</div>'
            . '</a>';
    }

    /** Which picture the tile shows: TV snow for a dead/tampered feed, an SMPTE card for every third
     *  online camera (by grid position), else the live crosshair viewport.
     *
     *  Scene is by POSITION, not a hash of the id, on purpose: a hash can cluster all the bar cameras onto
     *  later pages, leaving the first (default) page with none. Position guarantees an evenly-spread mix on
     *  every page, and is fully deterministic per seed (the camera order is fixed per seed). */
    private function cameraScene(array $cam, int $index): string
    {
        if (in_array($cam['status'], ['no-signal', 'offline', 'tampering'], true)) {
            return 'static';
        }
        if ($cam['status'] === 'online' && $index % 3 === 0) {
            return 'bars';
        }
        return 'live';
    }

    /** A camera's position in the estate, so the detail page shows the SAME scene as the grid tile. A
     *  fuzzed/synthetic camera not in the list falls to 0 (its own detail still renders). */
    private function cameraIndex(Cctv $cctv, string $camId): int
    {
        foreach ($cctv->cameras() as $i => $c) {
            if ($c['id'] === $camId) {
                return $i;
            }
        }
        return 0;
    }

    /** SMPTE-style colour bars as SVG rects (never <img>, CSP-clean): 7 top bars, a reverse castellation
     *  strip, and a PLUGE row. */
    private function smpteBarsSvg(int $w, int $h): string
    {
        $topH = (int) round($h * 0.67);
        $midH = (int) round($h * 0.08);
        $botY = $topH + $midH;
        $col = $w / 7;

        $top = ['#bfbfbf', '#bfbf00', '#00bfbf', '#00bf00', '#bf00bf', '#bf0000', '#0000bf'];
        $mid = ['#0000bf', '#131313', '#bf00bf', '#131313', '#00bfbf', '#131313', '#bfbfbf'];

        // Each bar sits at its exact fraction and is drawn 0.5px wider so opaque neighbours overlap (no
        // sub-pixel seam); the final half-pixel spill past the right edge is clipped by the SVG viewport.
        $g = '<g class="fp-scene-bars">';
        for ($i = 0; $i < 7; $i++) {
            $x = round($i * $col, 2);
            $cw = round($col + 0.5, 2);
            $g .= '<rect x="' . $x . '" y="0" width="' . $cw . '" height="' . $topH . '" fill="' . $top[$i] . '"/>';
            $g .= '<rect x="' . $x . '" y="' . $topH . '" width="' . $cw . '" height="' . $midH . '" fill="' . $mid[$i] . '"/>';
        }
        // Lower band: -I, 100% white, +Q, black, the 3-step PLUGE, black. Positions accumulate the true
        // widths (sum to $w); each rect overlaps the next by 0.5px, so no seam and the spill is clipped.
        $bot = [['#0a1a3a', 5], ['#ffffff', 5], ['#2a0a4a', 5], ['#131313', 5], ['#000000', 1], ['#131313', 1], ['#1c1c1c', 1], ['#131313', 5]];
        $x = 0.0;
        foreach ($bot as [$c, $units]) {
            $bw = $w * $units / 28;
            $g .= '<rect x="' . round($x, 2) . '" y="' . $botY . '" width="' . round($bw + 0.5, 2) . '" height="' . ($h - $botY) . '" fill="' . $c . '"/>';
            $x += $bw;
        }

        return $g . '</g>';
    }

    /** Procedural TV static (SVG feTurbulence, desaturated) — no image, CSP-clean, deterministic per id. */
    private function staticSvg(int $w, int $h, string $camId): string
    {
        $fid = 'fp-snow-' . substr(hash('sha256', $camId), 0, 10);
        $seed = abs(crc32($camId)) % 100;

        return '<defs><filter id="' . $fid . '" x="0" y="0" width="100%" height="100%">'
            . '<feTurbulence type="fractalNoise" baseFrequency="0.9" numOctaves="3" seed="' . $seed . '" stitchTiles="stitch" result="n"/>'
            . '<feColorMatrix in="n" type="saturate" values="0"/>'
            . '</filter></defs>'
            . '<rect x="0" y="0" width="' . $w . '" height="' . $h . '" filter="url(#' . $fid . ')" opacity="0.75"/>';
    }

    // --- helpers ---

    private function actionLink(string $href, string $label): string
    {
        return '<a class="fp-dl" href="' . $this->esc($href) . '" style="margin-right:10px">' . $this->esc($label) . '</a>';
    }

    private function locationLabel(array $cam): string
    {
        if ($cam['area'] === 'Exterior') {
            return 'Exterior';
        }
        if ($cam['floor'] === '') {
            return $cam['area'];
        }
        return 'Floor ' . $cam['floor'] . ' · ' . $cam['zone'] . ($cam['room'] !== '' ? ' · ' . $cam['room'] : '');
    }

    private function verbLabel(string $verb, string $arg): string
    {
        switch ($verb) {
            case 'ptz':
                return 'PTZ move ' . ($arg !== '' ? $arg : '');
            case 'preset':
                return 'Recall preset ' . ($arg !== '' ? $arg : '');
            case 'snapshot':
                return 'Snapshot';
            case 'reboot':
                return 'Reboot';
            case 'record':
                return 'Toggle recording';
            case 'zoom':
                return 'Zoom ' . $arg;
            case 'focus':
                return 'Focus ' . $arg;
            default:
                return ucfirst($verb);
        }
    }

    private function truncate(string $s, int $max): string
    {
        if (strlen($s) <= $max) {
            return $s;
        }
        return rtrim(substr($s, 0, $max - 1)) . '…';
    }

    private function pagerLinks(string $base, int $page, int $pages): string
    {
        if ($pages <= 1) {
            return '';
        }
        $out = ' &middot; ';
        if ($page > 1) {
            $out .= '<a class="fp-dl" href="' . $this->esc($base . '/p' . ($page - 1)) . '">Prev</a> ';
        }
        if ($page < $pages) {
            $out .= '<a class="fp-dl" href="' . $this->esc($base . '/p' . ($page + 1)) . '">Next</a>';
        }
        return $out . ' (page ' . $page . ' of ' . $pages . ')';
    }
}
