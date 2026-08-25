<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Network;
use Funnypot\App\Render\Fake\Org;
use Funnypot\App\Render\Panel\NetworkSection;
use Funnypot\App\Render\PanelRoute;
use Funnypot\Core\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class NetworkSectionTest extends TestCase
{
    /** Render a panel path through the section exactly as the skin would (parse -> render). */
    private function render(string $path, int $seed = 7): string
    {
        $route = PanelRoute::parse($path);
        return (new NetworkSection())->render($route, VisualPersona::fromSeed($seed), '/admin');
    }

    /**
     * Every dotted-quad in the output must be RFC1918 (10.x) or a TEST-NET documentation block
     * (192.0.2 / 198.51.100 / 203.0.113). Anything else is a leak of real routable space.
     */
    private function assertOnlySafeIps(string $html): void
    {
        preg_match_all('/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/', $html, $m);
        foreach ($m[0] as $ip) {
            $safe = strpos($ip, '10.') === 0
                || strpos($ip, '192.0.2.') === 0
                || strpos($ip, '198.51.100.') === 0
                || strpos($ip, '203.0.113.') === 0;
            self::assertTrue($safe, 'non-safe IP leaked: ' . $ip);
        }
    }

    // --- routing / depth ---

    public function test_landing_shows_tiles_and_jump_links(): void
    {
        $html = $this->render('/admin/network');
        self::assertStringContainsString('Network', $html);
        self::assertStringContainsString('Managed devices', $html);
        self::assertStringContainsString('href="/admin/network/devices"', $html);
        self::assertStringContainsString('href="/admin/network/vpn"', $html);
        self::assertStringContainsString('href="/admin/network/voip"', $html);
    }

    public function test_unknown_section_falls_back_to_landing(): void
    {
        // A 404 inside a deep panel is a tell; an unknown section renders the landing.
        $html = $this->render('/admin/network/not-a-real-section');
        self::assertStringContainsString('Managed devices', $html);
    }

    public function test_device_list_paginates_with_pagerHtml(): void
    {
        $p1 = $this->render('/admin/network/devices');
        $p2 = $this->render('/admin/network/devices/p2');
        self::assertStringContainsString('page 1 / ', $p1);
        self::assertStringContainsString('page 2 / ', $p2);
        self::assertNotSame($p1, $p2, 'different pages render different rows');
        self::assertStringContainsString('href="/admin/network/devices/', $p1);
        self::assertStringContainsString('devices', $p1);
    }

    public function test_device_detail_subtabs_render(): void
    {
        foreach (['', '/config', '/interfaces', '/vlans'] as $sub) {
            $html = $this->render('/admin/network/devices/sw-core-01' . $sub);
            self::assertStringContainsString('sw-core-01', $html, "subtab $sub");
            self::assertNotSame('', trim($html), "subtab $sub non-empty");
        }
    }

    public function test_unknown_device_slug_still_renders_a_plausible_detail(): void
    {
        // A fuzzed slug must not dead-end.
        $html = $this->render('/admin/network/devices/sw-does-not-exist-9999');
        self::assertStringContainsString('fp-card', $html);
        self::assertStringContainsString('Running config', $html);
    }

    // --- running-config: inert, masked, escaped ---

    public function test_running_config_masks_secrets_and_escapes(): void
    {
        $html = $this->render('/admin/network/devices/sw-core-01/config');
        // The masked-secret marker proves both the mask AND escape-by-construction: the literal '<'
        // in "<masked>" reaches output only as its escaped entity.
        self::assertStringContainsString('&lt;masked&gt;', $html);
        self::assertStringNotContainsString('snmp-server community <masked>', $html);
        // Service fabric hosts appear (coherent infra), all RFC1918.
        self::assertStringContainsString('10.0.5.30', $html); // syslog
        self::assertStringContainsString('10.0.5.11', $html); // tacacs
    }

    // --- inert controls ---

    public function test_reboot_is_a_guarded_soft_denial(): void
    {
        $html = $this->render('/admin/network/devices/sw-core-01/reboot');
        self::assertStringContainsString('Denied', $html);
        self::assertStringContainsString('not executed', $html);
        self::assertStringNotContainsString('Queued', $html);
    }

    public function test_ping_and_traceroute_are_canned_inert_output(): void
    {
        $ping = $this->render('/admin/network/devices/sw-core-01/ping');
        self::assertStringContainsString('ping statistics', $ping);
        self::assertStringContainsString('no state change', $ping);

        $trace = $this->render('/admin/network/devices/sw-core-01/traceroute');
        self::assertStringContainsString('Traceroute', $trace);
        self::assertStringContainsString('no state change', $trace);
    }

    // --- VPN ---

    public function test_vpn_alias_and_section_render_sessions_and_accounts(): void
    {
        foreach (['/admin/vpn', '/admin/network/vpn'] as $path) {
            $html = $this->render($path);
            self::assertStringContainsString('VPN accounts', $html);
            self::assertStringContainsString('Active sessions', $html);
            // The standing MFA-off service-account bait.
            self::assertStringContainsString('svc-backup', $html);
            self::assertStringContainsString('MFA off', $html);
            $this->assertOnlySafeIps($html);
        }
    }

    // --- VoIP + cross-coherence with the Org roster ---

    public function test_voip_alias_and_extensions_match_org_roster(): void
    {
        $org = Org::fromSeed(7, VisualPersona::fromSeed(7)->domain());
        $people = $org->people(3);

        foreach (['/admin/voip', '/admin/network/voip'] as $path) {
            $html = $this->render($path);
            self::assertStringContainsString('Extensions', $html);
            self::assertStringContainsString('Call log (CDR)', $html);
            self::assertStringContainsString('Voicemail', $html);
            // The extension directory reuses the Org roster's own ext + name (one headcount).
            self::assertStringContainsString($people[0]['ext'], $html);
            self::assertStringContainsString($people[0]['name'], $html);
            // External call parties stay in the reserved fictional 555-01xx range.
            self::assertStringContainsString('+1-555-01', $html);
        }
    }

    // --- VLANs ---

    public function test_vlan_plan_renders_the_full_fabric(): void
    {
        $html = $this->render('/admin/network/vlans');
        self::assertStringContainsString('Quarantine', $html);
        self::assertStringContainsString('10.0.99.0/24', $html);
        self::assertStringContainsString('Employees', $html);
        self::assertStringContainsString('10.0.20.0/23', $html);
    }

    // --- cross-coherence with Building ---

    public function test_device_location_references_a_building_room(): void
    {
        $html = $this->render('/admin/network/devices/sw-core-01');
        // Location names a real Building room id (room-<floor>-NN) on a real floor.
        self::assertMatchesRegularExpression('/room-[a-z0-9]+-\d{2}/', $html);
    }

    // --- safety: no routable IPs anywhere across the module ---

    public function test_no_public_ips_leak_across_module_surfaces(): void
    {
        foreach ([
            '/admin/network',
            '/admin/network/devices',
            '/admin/network/devices/sw-core-01/config',
            '/admin/network/devices/sw-core-01/interfaces',
            '/admin/network/vpn',
            '/admin/network/voip',
            '/admin/network/vlans',
        ] as $path) {
            $this->assertOnlySafeIps($this->render($path));
        }
    }

    // --- determinism ---

    public function test_render_is_byte_identical_per_seed(): void
    {
        foreach (['/admin/network', '/admin/network/devices', '/admin/network/vpn', '/admin/network/voip'] as $path) {
            self::assertSame($this->render($path, 42), $this->render($path, 42), 'stable per seed: ' . $path);
        }
    }

    public function test_generator_is_deterministic(): void
    {
        $a = Network::fromSeed(11, 'example.test');
        $b = Network::fromSeed(11, 'example.test');
        self::assertSame($a->devices(), $b->devices());
        self::assertSame($a->vpnSessions(), $b->vpnSessions());
        self::assertSame($a->callLog(40), $b->callLog(40));
        self::assertSame($a->vlans(), $b->vlans());
    }
}
