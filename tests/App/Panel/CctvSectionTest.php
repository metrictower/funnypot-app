<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Building;
use Funnypot\App\Render\Fake\Cctv;
use Funnypot\App\Render\Panel\CctvSection;
use Funnypot\App\Render\VisualPersona;
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

    public function test_generator_emits_no_public_ip(): void
    {
        for ($seed = 0; $seed < 12; $seed++) {
            $cctv = Cctv::fromSeed($seed);
            $blob = json_encode([$cctv->cameras(), $cctv->nvrArrays(), $cctv->events(30)]);
            self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, (string) $blob, "seed $seed");
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
