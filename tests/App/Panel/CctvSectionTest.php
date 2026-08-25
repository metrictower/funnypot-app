<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Building;
use Funnypot\App\Render\Fake\Cctv;
use Funnypot\App\Render\Panel\CctvSection;
use Funnypot\Core\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

/**
 * The CCTV module (spec §C.4): the Fake\Cctv estate generator and the CctvSection renderer. Verifies the
 * five-rung ladder (grid -> detail -> sub-tabs -> control leaf), the INERT/SAFE invariants (no <img>/feed,
 * RFC1918 only, guarded soft-deny on sensitive verbs), determinism, and escape-by-construction.
 */
final class CctvSectionTest extends TestCase
{
    /** Anything outside RFC1918 10.x is a leak of real routable space (spec SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    /** @return array{module:string,section:string,entity:string,subtab:string,action:string,arg:string,page:int,filter:string} */
    private function route(string $section = '', string $entity = '', string $subtab = '', int $page = 1): array
    {
        return [
            'module' => 'cctv', 'section' => $section, 'entity' => $entity, 'subtab' => $subtab,
            'action' => '', 'arg' => '', 'page' => $page, 'filter' => $section,
        ];
    }

    private function render(array $route, int $seed = 7): string
    {
        return (new CctvSection())->render($route, VisualPersona::fromSeed($seed), '/admin');
    }

    // --- generator ---

    public function test_generator_is_deterministic(): void
    {
        $a = Cctv::fromSeed(11);
        $b = Cctv::fromSeed(11);
        self::assertSame($a->cameras(), $b->cameras());
        self::assertSame($a->nvrArrays(), $b->nvrArrays());
        self::assertSame($a->recordings('cam-g-01'), $b->recordings('cam-g-01'));
        self::assertSame($a->summary(), $b->summary());
    }

    public function test_cameras_never_empty_and_have_full_shape(): void
    {
        for ($seed = 0; $seed < 15; $seed++) {
            $cams = Cctv::fromSeed($seed)->cameras();
            self::assertNotEmpty($cams, "seed $seed cameras");
            foreach ($cams as $c) {
                self::assertSame(
                    ['id', 'name', 'area', 'floor', 'zone', 'room', 'model', 'resolution', 'codec',
                     'fps', 'ip', 'port', 'rtsp', 'nvr', 'channel', 'status', 'recording', 'ptz',
                     'retentionDays', 'timecode'],
                    array_keys($c)
                );
                self::assertMatchesRegularExpression('/^cam-[a-z0-9-]+$/', $c['id'], 'camera id is a slug');
                self::assertStringStartsWith('10.0.70.', $c['ip'], 'camera on the CCTV fabric');
                self::assertStringStartsWith('rtsp://10.0.70.', $c['rtsp']);
                self::assertContains($c['status'], ['online', 'no-signal', 'offline', 'tampering']);
            }
        }
    }

    public function test_room_cameras_cross_reference_building(): void
    {
        $seed = 5;
        $bld = Building::fromSeed($seed);
        $rooms = [];
        foreach ($bld->floors() as $f) {
            foreach ($bld->roomsFor($f['code']) as $r) {
                $rooms[$r['id']] = true;
            }
        }
        $ctrlIds = [];
        foreach ($bld->controllers() as $c) {
            $ctrlIds[$c['id']] = true;
        }
        foreach (Cctv::fromSeed($seed)->cameras() as $c) {
            if ($c['room'] !== '') {
                self::assertArrayHasKey($c['room'], $rooms, 'camera room exists in Building');
            }
            self::assertArrayHasKey($c['nvr'], $ctrlIds, 'camera NVR is a real controller');
        }
    }

    public function test_camera_lookup_never_dead_ends(): void
    {
        $cctv = Cctv::fromSeed(3);
        $known = $cctv->cameras()[0]['id'];
        self::assertSame($known, $cctv->camera($known)['id']);
        // An unknown/fuzzed slug still returns a plausible camera (spec D.4).
        $synth = $cctv->camera('cam-does-not-exist-999');
        self::assertSame('cam-does-not-exist-999', $synth['id']);
        self::assertStringStartsWith('10.0.70.', $synth['ip']);
    }

    public function test_recordings_are_zip_suffixed_and_link_safe(): void
    {
        foreach (Cctv::fromSeed(8)->recordings('cam-g-02') as $r) {
            self::assertStringEndsWith('.mp4.zip', $r['file'], 'download routes to decoy-archive handler');
            self::assertMatchesRegularExpression('/^[A-Za-z0-9._-]+$/', $r['file'], 'filename is link-safe');
        }
    }

    /** recordings() must walk strictly backward from DEPLOY_EPOCH: never a future clip, never a repeated
     *  or backward-jumping start time (spec E11 — the newest clip used to be hardcoded into hour 23..10,
     *  past a frozen "now" of 01:46, on every seed). */
    public function test_recordings_are_never_future_and_strictly_monotonic(): void
    {
        for ($seed = 0; $seed < 8; $seed++) {
            $cctv = Cctv::fromSeed($seed);
            $camId = $cctv->cameras()[0]['id'];
            $prevEpoch = null;
            foreach ($cctv->recordings($camId) as $r) {
                self::assertMatchesRegularExpression(
                    '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/',
                    $r['start'],
                    "seed $seed: recording start carries a full date"
                );
                $epoch = strtotime($r['start'] . ' UTC');
                self::assertLessThanOrEqual(Cctv::deployEpoch(), $epoch, "seed $seed: recording must not start in the future: {$r['start']}");
                if ($prevEpoch !== null) {
                    self::assertLessThan($prevEpoch, $epoch, "seed $seed: recordings must be strictly newest-first");
                }
                $prevEpoch = $epoch;
            }
        }
    }

    /** The burned live-view timecode must never read later than the frozen "now" (spec E11 — it used to be
     *  a fully random time-of-day, future on ~93% of cameras). */
    public function test_camera_timecode_is_never_future(): void
    {
        for ($seed = 0; $seed < 10; $seed++) {
            foreach (Cctv::fromSeed($seed)->cameras() as $c) {
                $epoch = strtotime($c['timecode'] . ' UTC');
                self::assertLessThanOrEqual(Cctv::deployEpoch(), $epoch, "seed $seed: {$c['id']} timecode must not be in the future: {$c['timecode']}");
            }
        }
    }

    public function test_generator_emits_no_public_ip(): void
    {
        for ($seed = 0; $seed < 12; $seed++) {
            $cctv = Cctv::fromSeed($seed);
            $blob = json_encode([$cctv->cameras(), $cctv->nvrArrays(), $cctv->events(30)]);
            self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, (string) $blob, "seed $seed");
        }
    }

    /** events() must walk strictly backward from DEPLOY_EPOCH: never a future row, never a repeated or
     *  backward-jumping date (spec E11 — the newest event used to be hardcoded to hour 23, past a frozen
     *  "now" of 01:46). */
    public function test_events_are_never_future_and_strictly_monotonic(): void
    {
        for ($seed = 0; $seed < 8; $seed++) {
            $cctv = Cctv::fromSeed($seed);
            $prevEpoch = null;
            foreach ($cctv->events(60) as $line) {
                self::assertMatchesRegularExpression(
                    '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}  /',
                    $line,
                    "seed $seed: event line carries a date+time: $line"
                );
                $epoch = strtotime(substr($line, 0, 19) . ' UTC');
                self::assertLessThanOrEqual(Cctv::deployEpoch(), $epoch, "seed $seed: event must not be in the future: $line");
                if ($prevEpoch !== null) {
                    self::assertLessThan($prevEpoch, $epoch, "seed $seed: events must be strictly newest-first: $line");
                }
                $prevEpoch = $epoch;
            }
        }
    }

    /** A per-camera event tail must hold the same never-future, strictly-descending invariant as events(). */
    public function test_camera_events_for_are_never_future_and_strictly_monotonic(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $cctv = Cctv::fromSeed($seed);
            $camId = $cctv->cameras()[0]['id'];
            $prevEpoch = null;
            foreach ($cctv->cameraEventsFor($camId, 40) as $line) {
                $epoch = strtotime(substr($line, 0, 19) . ' UTC');
                self::assertLessThanOrEqual(Cctv::deployEpoch(), $epoch, "seed $seed: camera event must not be in the future: $line");
                if ($prevEpoch !== null) {
                    self::assertLessThan($prevEpoch, $epoch, "seed $seed: camera events must be strictly newest-first: $line");
                }
                $prevEpoch = $epoch;
            }
        }
    }

    // --- section: landing ---

    public function test_landing_renders_grid_and_is_deterministic(): void
    {
        $a = $this->render($this->route());
        $b = $this->render($this->route());
        self::assertSame($a, $b, 'same seed -> byte-identical');
        self::assertStringContainsString('fp-cam-grid', $a);
        self::assertStringContainsString('cameras', $a);
        self::assertStringContainsString('/admin/cctv/nvr', $a);
    }

    public function test_landing_has_no_external_image_or_feed(): void
    {
        $html = $this->render($this->route());
        self::assertStringNotContainsString('<img', $html, 'camera tiles are inline SVG only (spec S5)');
        self::assertStringNotContainsString('http://', $html);
        self::assertStringNotContainsString('https://', $html);
        self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $html);
    }

    // --- section: detail + sub-tabs ---

    public function test_camera_detail_shows_rtsp_and_recorder(): void
    {
        $cctv = Cctv::fromSeed(7);
        $cam = $cctv->cameras()[0];
        $html = $this->render($this->route($cam['id']));
        self::assertStringContainsString('rtsp://10.0.70.', $html);
        self::assertStringContainsString($cam['nvr'], $html);
        self::assertStringContainsString('Recordings', $html); // sub-tab strip present
    }

    public function test_recordings_tab_links_zip_downloads(): void
    {
        $cctv = Cctv::fromSeed(7);
        $cam = $cctv->cameras()[0];
        $html = $this->render($this->route($cam['id'], 'recordings'));
        self::assertStringContainsString('.mp4.zip', $html);
        self::assertStringContainsString('/admin/cctv/' . $cam['id'] . '/recordings/', $html);
    }

    public function test_nvr_overview_renders_storage_gauge(): void
    {
        $html = $this->render($this->route('nvr'));
        self::assertStringContainsString('fp-gauge', $html);
        self::assertStringContainsString('TB', $html);
    }

    // --- section: control leaves ---

    public function test_queued_control_returns_canned_receipt_not_state_change(): void
    {
        $cctv = Cctv::fromSeed(7);
        $cam = $cctv->cameras()[0];
        $html = $this->render($this->route($cam['id'], 'ptz', 'up'));
        self::assertStringContainsString('Queued', $html);
        self::assertStringContainsString('fp-result-card', $html);
        self::assertStringNotContainsStringIgnoringCase('done', $html);
    }

    public function test_sensitive_verb_is_soft_denied(): void
    {
        $cctv = Cctv::fromSeed(7);
        $cam = $cctv->cameras()[0];
        $html = $this->render($this->route($cam['id'], 'purge', 'all'));
        self::assertStringContainsString('Denied', $html);
        self::assertStringContainsString('Unchanged', $html);
        self::assertStringNotContainsStringIgnoringCase('purged', $html);
    }

    public function test_command_ref_and_job_id_vary_per_deploy(): void
    {
        // I3: both the guarded command ref and the queued job id mix the persona seed, so two deploys never
        // share the same FAC-CMD/cmd- handle for the same camera+verb (a cross-deploy fingerprint otherwise).
        // A fixed (synthetic) camera id isolates the seed as the only varying input.
        $guarded = $this->route('cam-x-01', 'purge', 'all');
        $refA = $this->grab('/FAC-CMD-[0-9A-F]{6}/', $this->render($guarded, 1));
        $refB = $this->grab('/FAC-CMD-[0-9A-F]{6}/', $this->render($guarded, 2));
        self::assertNotSame('', $refA, 'a guarded command ref must render');
        self::assertNotSame($refA, $refB, 'guarded command ref must vary per deploy');

        $queued = $this->route('cam-x-01', 'snapshot', 'now');
        $jobA = $this->grab('/cmd-[0-9a-f]{8}/', $this->render($queued, 1));
        $jobB = $this->grab('/cmd-[0-9a-f]{8}/', $this->render($queued, 2));
        self::assertNotSame('', $jobA, 'a queued job id must render');
        self::assertNotSame($jobA, $jobB, 'queued job id must vary per deploy');
    }

    /** First match of $pattern in $html, or '' if none. */
    private function grab(string $pattern, string $html): string
    {
        return preg_match($pattern, $html, $m) === 1 ? $m[0] : '';
    }

    public function test_reflected_arg_is_escaped(): void
    {
        // A control arg is the one attacker-influenced value that reaches HTML; it must be escaped.
        $cctv = Cctv::fromSeed(7);
        $cam = $cctv->cameras()[0];
        $html = $this->render($this->route($cam['id'], 'ptz', '<script>alert(1)</script>'));
        self::assertStringNotContainsString('<script>alert(1)</script>', $html);
        self::assertStringContainsString('&lt;script&gt;', $html);
    }

    public function test_unknown_camera_still_renders_detail(): void
    {
        $html = $this->render($this->route('cam-fuzzed-42'));
        self::assertStringContainsString('cam-fuzzed-42', $html);
        self::assertStringContainsString('rtsp://10.0.70.', $html);
    }
}
