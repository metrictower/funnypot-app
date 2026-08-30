<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Render\Panel\DeviceConsoleSection;
use Funnypot\App\Render\Panel\PanelRegistry;
use Funnypot\App\Render\PanelRoute;
use Funnypot\Core\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

/**
 * The in-chrome device-console panel section (FP-0155): it renders a believable read-only console for a
 * device path, escapes a reflected id, and — via the registry guard — never captures a real panel module.
 */
final class DeviceConsoleSectionTest extends TestCase
{
    private const SEED = 987654321;

    private function persona(): VisualPersona
    {
        return VisualPersona::fromSeed(self::SEED);
    }

    private function render(string $path): string
    {
        $section = new DeviceConsoleSection();

        return $section->render(PanelRoute::parse($path), $this->persona(), '/console');
    }

    public function test_device_console_renders_the_read_only_console(): void
    {
        $html = $this->render('/console/pos-dev-ams-08');

        self::assertStringContainsString('Point-of-Sale Terminal', $html);
        self::assertStringContainsString('pos-dev-ams-08', $html);
        self::assertStringContainsString('monitor@pos-dev-ams-08', $html, 'the terminal prompt should be present');
        self::assertStringContainsString('access denied', $html, 'a privileged verb must be soft-denied');
        self::assertStringContainsString('Command execution is disabled', $html, 'the read-only notice must be shown');
        // Never a live exec surface: the only form is a GET that reloads the same read-only page.
        self::assertStringNotContainsString('method="post"', strtolower($html));
    }

    public function test_reflected_id_is_escaped(): void
    {
        // Bypass PanelRoute's slugging (which would neutralise this upstream) to prove the section itself
        // escapes the id it echoes — defense in depth. The id carries a `pos` token so it renders the
        // device-detail view (which echoes the id), not the landing.
        $route = [
            'module' => 'pos-<script>alert(1)</script>-01', 'section' => '', 'entity' => '', 'subtab' => '',
            'action' => '', 'arg' => '', 'page' => 1, 'filter' => '',
        ];
        $html = (new DeviceConsoleSection())->render($route, $this->persona(), '/console');

        self::assertStringNotContainsString('<script>alert(1)</script>', $html, 'the raw id must never reach HTML');
        self::assertStringContainsString('&lt;script&gt;', $html, 'the id must be HTML-escaped');
    }

    public function test_fleet_landing_lists_reachable_device_links(): void
    {
        // The canonical slug, the empty root, AND every alias that reaches this section without a module
        // rewrite (op-consoles/terminals/fleet-consoles) must render the landing, not a bogus device named
        // after the alias. The split is "not device-shaped -> landing".
        foreach (['/console/consoles', '/console', '/console/terminals', '/console/op-consoles', '/console/fleet-consoles'] as $path) {
            $html = $this->render($path);
            self::assertStringContainsString('Operational consoles', $html, "landing for {$path}");
            self::assertStringContainsString('<a href="/console/', $html, 'each device must be a reachable link');
            self::assertStringNotContainsString('access denied', $html, "{$path} must be the fleet list, not a device console");
        }
    }

    public function test_registry_guard_never_captures_a_real_module(): void
    {
        $registry = new PanelRegistry();
        // Registered modules (and their aliases) resolve to a real section — the device dispatch is gated
        // on !has(), so these are never treated as device consoles.
        foreach (['hr', 'employees', 'bank', 'cctv', 'consoles', 'dashboard', ''] as $module) {
            self::assertTrue($registry->has($module) || $module === '', "'{$module}' must resolve to a registered section");
        }
        // A device-shaped slug is NOT registered, so the skin's `!has() && looksLikeDevice()` routes it to
        // the console.
        self::assertFalse($registry->has('pos-dev-ams-08'));
        self::assertFalse($registry->has('mainframe07'));
    }
}
