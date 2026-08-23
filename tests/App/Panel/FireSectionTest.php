<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Safety;
use Funnypot\App\Render\Panel\FireSection;
use Funnypot\App\Render\VisualPersona;
use PHPUnit\Framework\TestCase;

/**
 * FireSection is flagship lure #2: it must render deep and coherent, escape every reflected value, and
 * — the load-bearing invariant — NEVER return real success on a life-safety verb. These tests pin that
 * a guarded verb only ever soft-denies (interlock / dual-auth, state UNCHANGED), a mild verb only ever
 * queues/schedules, the PIN field is never reflected, output is deterministic per seed, and no routable
 * IP ever leaks.
 */
final class FireSectionTest extends TestCase
{
    /** Anything outside RFC1918 10.x is a leak of real routable space (spec SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    private const NAV = '/admin';

    private FireSection $section;

    protected function setUp(): void
    {
        $this->section = new FireSection();
    }

    /** @return array{module:string,section:string,entity:string,subtab:string,action:string,arg:string,page:int,filter:string} */
    private function route(string $section = '', string $entity = '', string $subtab = '', string $action = '', int $page = 1): array
    {
        return [
            'module' => 'fire', 'section' => $section, 'entity' => $entity, 'subtab' => $subtab,
            'action' => $action, 'arg' => '', 'page' => $page, 'filter' => $entity,
        ];
    }

    private function render(array $route, int $seed = 7): string
    {
        return $this->section->render($route, VisualPersona::fromSeed($seed), self::NAV);
    }

    // --- landing ---

    public function test_landing_renders_panel_and_sections(): void
    {
        $html = $this->render($this->route());
        self::assertStringContainsString('Fire &amp; Life Safety', $html);
        self::assertStringContainsString('FACP-01', $html);
        self::assertStringContainsString('NORMAL', $html);            // panel is never in live alarm
        self::assertStringContainsString(self::NAV . '/fire/zones', $html);
        self::assertStringContainsString(self::NAV . '/fire/detectors', $html);
        self::assertStringContainsString(self::NAV . '/fire/incidents', $html);
    }

    // --- determinism ---

    public function test_same_seed_and_route_is_byte_identical(): void
    {
        $r = $this->route('zones');
        self::assertSame($this->render($r, 11), $this->render($r, 11));
    }

    public function test_different_seeds_differ(): void
    {
        $r = $this->route();
        self::assertNotSame($this->render($r, 1), $this->render($r, 2));
    }

    // --- depth: zones list + detail ---

    public function test_zones_list_and_detail_render(): void
    {
        $list = $this->render($this->route('zones'));
        self::assertStringContainsString('Suppression zones', $list);

        $safety = Safety::fromSeed(7);
        $zones = $safety->zones();
        self::assertNotEmpty($zones);
        $id = $zones[0]['id'];
        $detail = $this->render($this->route('zones', $id));
        self::assertStringContainsString($this->esc($zones[0]['name']), $detail);
        self::assertStringContainsString('Suppression agent', $detail);
        // Detail exposes the guarded controls.
        self::assertStringContainsString(self::NAV . '/fire/zones/' . $id . '/disable', $detail);
    }

    public function test_unknown_zone_still_renders_detail(): void
    {
        // A fuzzed/unknown slug must not 404 in-panel (spec D.4).
        $html = $this->render($this->route('zones', 'zone-does-not-exist-9x'));
        self::assertNotSame('', $html);
        self::assertStringContainsString('Suppression agent', $html);
    }

    // --- the life-safety invariant: guarded verbs never succeed ---

    public function test_guarded_step1_shows_warning_and_pin_form(): void
    {
        $safety = Safety::fromSeed(7);
        $id = $safety->zones()[0]['id'];
        $html = $this->render($this->route('zones', $id, 'disable'));
        self::assertStringContainsString('type="password"', $html);          // PIN field present
        self::assertStringContainsString('dual-authorization', $html);
        self::assertStringContainsString('does not change', $html);           // interlock alibi
        // method=post so the PIN never lands in a URL/query string.
        self::assertMatchesRegularExpression('/method="post"/i', $html);
        $this->assertNoLifeSafetySuccess($html);
    }

    public function test_guarded_apply_is_soft_denied_not_done(): void
    {
        $safety = Safety::fromSeed(7);
        foreach (['disable', 'manual-release', 'disarm'] as $verb) {
            $id = $safety->zones()[0]['id'];
            $html = $this->render($this->route('zones', $id, $verb, 'apply'));
            self::assertStringContainsString('DENIED', $html);
            self::assertStringContainsString('UNCHANGED', $html);
            self::assertStringContainsString('Denied', $html);               // crit pill label
            self::assertStringContainsString('CMD-', $html);                 // ticketed command id
            $this->assertNoLifeSafetySuccess($html);
        }
    }

    public function test_building_wide_disable_is_soft_denied(): void
    {
        $html = $this->render($this->route('disable-suppression'));
        self::assertStringContainsString('DENIED', $html);
        self::assertStringContainsString('UNCHANGED', $html);
        self::assertStringContainsString('site-wide', $html);
        $this->assertNoLifeSafetySuccess($html);
    }

    // --- mild verbs queue, never "done" ---

    public function test_mild_verb_queues_and_never_says_done(): void
    {
        $safety = Safety::fromSeed(7);
        $id = $safety->zones()[0]['id'];
        $drill = $this->render($this->route('zones', $id, 'drill'));
        self::assertStringContainsString('Queued', $drill);                  // controlResultCard pill
        self::assertStringContainsString('scheduled', strtolower($drill));
        self::assertStringContainsString('NOT notified', $drill);            // test-mode safety copy
        $this->assertNoLifeSafetySuccess($drill);

        $siteDrill = $this->render($this->route('drill'));
        self::assertStringContainsString('site-wide', $siteDrill);
        $this->assertNoLifeSafetySuccess($siteDrill);
    }

    // --- pagination: detectors + incidents ---

    public function test_detector_pages_render_and_clamp(): void
    {
        $p1 = $this->render($this->route('detectors', '', '', '', 1));
        $p2 = $this->render($this->route('detectors', '', '', '', 2));
        self::assertStringContainsString('SLC detector loops', $p1);
        self::assertNotSame($p1, $p2, 'different pages must differ');
        // A wildly out-of-range page clamps to the last page rather than emptying/erroring.
        $huge = $this->render($this->route('detectors', '', '', '', 99999));
        self::assertNotSame('', $huge);
        self::assertStringContainsString('SLC detector loops', $huge);
    }

    public function test_incident_log_renders(): void
    {
        $html = $this->render($this->route('incidents'));
        self::assertStringContainsString('Incident log', $html);
        self::assertStringContainsString('FIRE-2026-', $html);
    }

    // --- escaping ---

    public function test_reflected_slug_is_escaped(): void
    {
        // The zone entity slot is the one attacker-shaped value that reaches the detail page (as the
        // synthesized zone name). It must be escaped, never break out.
        $html = $this->render($this->route('zones', '<script>alert(1)</script>'));
        self::assertStringNotContainsString('<script>alert(1)</script>', $html);
        self::assertStringContainsString('&lt;script&gt;', $html);
    }

    // --- safety: no routable IP anywhere, across seeds and routes ---

    public function test_no_public_ip_across_seeds_and_routes(): void
    {
        $routes = [
            $this->route(),
            $this->route('zones'),
            $this->route('detectors'),
            $this->route('sprinklers'),
            $this->route('emergency-lighting'),
            $this->route('incidents'),
        ];
        for ($seed = 0; $seed < 12; $seed++) {
            $safety = Safety::fromSeed($seed);
            $id = $safety->zones()[0]['id'];
            $probe = $routes;
            $probe[] = $this->route('zones', $id);
            $probe[] = $this->route('zones', $id, 'disable', 'apply');
            foreach ($probe as $r) {
                $html = $this->render($r, $seed);
                self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $html, "seed $seed route {$r['section']}/{$r['entity']}");
            }
        }
    }

    // --- helpers ---

    /** No life-safety page may ever imply the physical state changed. */
    private function assertNoLifeSafetySuccess(string $html): void
    {
        $lower = strtolower($html);
        foreach (['suppression disabled', 'suppression released', 'disarmed successfully',
                  'activated', 'released successfully', 'now disabled', 'successfully disabled'] as $bad) {
            self::assertStringNotContainsString($bad, $lower, "life-safety verb must never report success: $bad");
        }
    }

    private function esc(string $v): string
    {
        return htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
