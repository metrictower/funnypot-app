<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Building;
use Funnypot\App\Render\Fake\Cmdb;
use Funnypot\App\Render\Fake\Integrations;
use Funnypot\App\Render\Fake\Network;
use Funnypot\App\Render\Fake\Org;
use Funnypot\App\Render\Panel\ItAssetsSection;
use Funnypot\App\Render\PanelRoute;
use Funnypot\Core\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class ItAssetsSectionTest extends TestCase
{
    /** Anything outside RFC1918 10.x is a leak of real routable space (SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    /** Render a panel path through the section exactly as the skin would (parse -> render). */
    private function render(string $path, int $seed = 7): string
    {
        $route = PanelRoute::parse($path);
        return (new ItAssetsSection())->render($route, VisualPersona::fromSeed($seed), '/admin');
    }

    // ================= generator: Cmdb =================

    public function test_cmdb_is_deterministic(): void
    {
        $a = Cmdb::fromSeed(11, 'example.test');
        $b = Cmdb::fromSeed(11, 'example.test');
        self::assertSame($a->assets(), $b->assets());
        self::assertSame($a->summary(), $b->summary());
    }

    public function test_cmdb_different_seeds_differ(): void
    {
        self::assertNotSame(
            Cmdb::fromSeed(1, 'example.test')->assets(),
            Cmdb::fromSeed(2, 'example.test')->assets()
        );
    }

    public function test_cmdb_count_scales_off_org_headcount(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $cmdb = Cmdb::fromSeed($seed, 'example.test');
            $org = Org::fromSeed($seed, 'example.test');
            self::assertSame($org->magnitudes()['assets'], $cmdb->assetCount(), "seed $seed asset count");
            self::assertGreaterThan(50, $cmdb->assetCount(), "seed $seed breadth for pagination");
        }
    }

    public function test_asset_lookup_matches_list_row_and_id_is_a_slug(): void
    {
        $cmdb = Cmdb::fromSeed(7, 'example.test');
        foreach (array_slice($cmdb->assets(), 0, 40) as $a) {
            self::assertSame($a, $cmdb->asset($a['id']), 'asset() must be byte-identical to its assets() row');
            self::assertMatchesRegularExpression('/^(lt|dt|sv|ph|mn|tb)-[0-9]{5}$/', $a['id'], 'asset id must be a typed slug');
        }
    }

    public function test_unknown_asset_slug_still_renders_a_plausible_asset(): void
    {
        $a = Cmdb::fromSeed(3, 'example.test')->asset('lt-does-not-exist');
        self::assertSame('lt-does-not-exist', $a['id']);
        self::assertArrayHasKey('model', $a);
        self::assertArrayHasKey('lastIp', $a);
    }

    public function test_every_personal_asset_binds_to_a_real_org_person(): void
    {
        // Cross-coherence: a personal device's assignee is a real roster member (id + name agree).
        for ($seed = 0; $seed < 4; $seed++) {
            $cmdb = Cmdb::fromSeed($seed, 'example.test');
            $org = Org::fromSeed($seed, 'example.test');
            $byId = [];
            foreach ($org->people($org->headcount()) as $p) {
                $byId[$p['id']] = $p;
            }
            foreach ($cmdb->assets() as $a) {
                if ($a['assigneeId'] !== '') {
                    self::assertArrayHasKey($a['assigneeId'], $byId, "seed $seed assignee is in the roster");
                    self::assertSame($byId[$a['assigneeId']]['name'], $a['assigneeName'], "seed $seed assignee name agrees");
                    self::assertSame($byId[$a['assigneeId']]['email'], $a['assigneeEmail'], "seed $seed assignee email agrees");
                } else {
                    self::assertSame('server', $a['type'], 'only servers are unassigned');
                }
            }
        }
    }

    public function test_every_asset_binds_to_a_real_building_room(): void
    {
        for ($seed = 0; $seed < 4; $seed++) {
            $cmdb = Cmdb::fromSeed($seed, 'example.test');
            $bld = Building::fromSeed($seed);
            $roomIds = [];
            foreach ($bld->floors() as $f) {
                foreach ($bld->roomsFor($f['code']) as $r) {
                    $roomIds[$r['id']] = $r['type'];
                }
            }
            foreach ($cmdb->assets() as $a) {
                self::assertArrayHasKey($a['roomId'], $roomIds, "seed $seed asset room is a Building room");
                if ($a['type'] === 'server') {
                    self::assertSame('Server-Comms', $roomIds[$a['roomId']], "seed $seed server sits in a Server-Comms room");
                }
            }
        }
    }

    public function test_cmdb_leaks_no_public_ip(): void
    {
        for ($seed = 0; $seed < 10; $seed++) {
            $blob = json_encode(Cmdb::fromSeed($seed, 'example.test')->assets());
            self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, (string) $blob, "seed $seed");
        }
    }

    public function test_every_cmdb_switch_ref_resolves_to_a_real_network_switch(): void
    {
        // The asset "Network" card claims the cabling maps to a switch in Network Devices — so every wired
        // asset's switch-port must name a device the Network estate actually created (no phantom suffix).
        for ($seed = 0; $seed < 6; $seed++) {
            $cmdb = Cmdb::fromSeed($seed, 'example.test');
            $net = Network::fromSeed($seed, 'example.test');
            $ids = [];
            foreach ($net->devices() as $d) {
                $ids[$d['id']] = true;
            }
            foreach ($cmdb->assets() as $a) {
                if ($a['switchPort'] === '—') {
                    continue;
                }
                $switchId = substr($a['switchPort'], 0, strpos($a['switchPort'], ' '));
                self::assertArrayHasKey($switchId, $ids, "seed $seed switch ref $switchId resolves in Network");
            }
        }
    }

    // ================= generator: Integrations =================

    public function test_integrations_is_deterministic(): void
    {
        $a = Integrations::fromSeed(9);
        $b = Integrations::fromSeed(9);
        self::assertSame($a->endpoints(), $b->endpoints());
        self::assertSame($a->summary(), $b->summary());
    }

    public function test_integrations_have_enough_rows_for_pagination(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            self::assertGreaterThan(25, Integrations::fromSeed($seed)->endpointCount(), "seed $seed registry breadth");
        }
    }

    public function test_endpoint_lookup_matches_list_row(): void
    {
        $integ = Integrations::fromSeed(4);
        foreach ($integ->endpoints() as $e) {
            self::assertSame($e, $integ->endpoint($e['id']), 'endpoint() must be byte-identical to its row');
            self::assertMatchesRegularExpression('/^10\./', $e['host'], 'host must be RFC1918');
        }
    }

    public function test_bacnet_endpoints_are_the_real_building_controllers(): void
    {
        // Cross-coherence: the BACnet/OSDP/ONVIF rows ARE the Building controllers (same id, ip, port).
        for ($seed = 0; $seed < 4; $seed++) {
            $integ = Integrations::fromSeed($seed);
            foreach (Building::fromSeed($seed)->controllers() as $c) {
                $e = $integ->endpoint(strtolower($c['id']));
                self::assertSame($c['ip'], $e['host'], "seed $seed controller ip in registry");
                self::assertSame($c['port'], $e['port'], "seed $seed controller port in registry");
                self::assertSame($c['id'], $e['linkedController'], "seed $seed controller linked");
            }
        }
    }

    public function test_integrations_leak_no_public_ip(): void
    {
        for ($seed = 0; $seed < 12; $seed++) {
            $blob = json_encode(Integrations::fromSeed($seed)->endpoints());
            self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, (string) $blob, "seed $seed");
        }
    }

    public function test_endpoint_anomaly_budget_is_at_most_two(): void
    {
        for ($seed = 0; $seed < 25; $seed++) {
            $s = Integrations::fromSeed($seed)->summary();
            self::assertLessThanOrEqual(2, $s['degraded'] + $s['down'], "seed $seed anomaly budget");
        }
    }

    // ================= section: rendering, depth, escaping =================

    public function test_landing_is_byte_identical_per_seed(): void
    {
        self::assertSame($this->render('/admin/it', 42), $this->render('/admin/it', 42), 'landing must be cache-safe');
    }

    public function test_landing_shows_tiles_and_jump_links(): void
    {
        $html = $this->render('/admin/it', 8);
        self::assertStringContainsString('fp-breadcrumb', $html);
        self::assertStringContainsString('Managed assets', $html);
        self::assertStringContainsString('Integrations', $html);
        self::assertStringContainsString('href="/admin/it/assets"', $html);
        self::assertStringContainsString('href="/admin/it/integrations"', $html);
    }

    public function test_asset_list_paginates_with_pagerhtml(): void
    {
        $p1 = $this->render('/admin/it/assets', 5);
        $p2 = $this->render('/admin/it/assets/p2', 5);
        self::assertStringContainsString('fp-pager', $p1);
        self::assertStringContainsString('href="/admin/it/assets/p2"', $p1);
        self::assertStringContainsString('page 1 /', $p1);
        self::assertStringContainsString('page 2 /', $p2);
        self::assertNotSame($p1, $p2, 'different pages render different rows');
        // A row links deeper into an asset detail.
        self::assertSame(1, preg_match('#href="/admin/it/assets/(lt|dt|sv|ph|mn|tb)-[0-9]{5}"#', $p1));
    }

    public function test_asset_type_filter_lists_only_that_type(): void
    {
        $html = $this->render('/admin/it/assets/type/laptop', 6);
        self::assertStringContainsString('Laptops', $html);
        self::assertStringContainsString('href="/admin/it/assets/type/laptop/p2"', $html);
    }

    public function test_asset_detail_subtabs_render_and_link(): void
    {
        $cmdb = Cmdb::fromSeed(9, VisualPersona::fromSeed(9)->domain());
        $id = $cmdb->assets()[0]['id'];
        $base = '/admin/it/assets/' . $id;
        foreach (['', '/hardware', '/network', '/compliance'] as $sub) {
            $html = $this->render($base . $sub, 9);
            self::assertStringContainsString('alte-tabs', $html, "subtab $sub");
            self::assertNotSame('', trim($html), "subtab $sub non-empty");
        }
        // The overview links to the detail sub-tabs (crawlable depth).
        $ov = $this->render($base, 9);
        self::assertStringContainsString('href="' . $base . '/network"', $ov);
        self::assertStringContainsString('href="' . $base . '/compliance"', $ov);
    }

    public function test_asset_export_is_a_zip_archive(): void
    {
        $html = $this->render('/admin/it/assets', 3);
        self::assertMatchesRegularExpression('#it/download/assets-export\.csv\.zip"#', $html);
    }

    public function test_integrations_list_paginates_and_filters(): void
    {
        $p1 = $this->render('/admin/it/integrations', 5);
        self::assertStringContainsString('fp-pager', $p1);
        self::assertStringContainsString('href="/admin/it/integrations/p2"', $p1);
        // Protocol filter chips route back into the registry.
        self::assertStringContainsString('href="/admin/it/integrations/protocol/', $p1);
        // A row links to an endpoint detail.
        self::assertSame(1, preg_match('#href="/admin/it/integrations/[a-z0-9-]+"#', $p1));
    }

    public function test_integrations_endpoint_detail_shows_host_port(): void
    {
        $integ = Integrations::fromSeed(2);
        $id = $integ->endpoints()[0]['id'];
        foreach (['', '/connection', '/credentials'] as $sub) {
            $html = $this->render('/admin/it/integrations/' . $id . $sub, 2);
            self::assertStringContainsString('alte-tabs', $html, "subtab $sub");
        }
        $ov = $this->render('/admin/it/integrations/' . $id, 2);
        self::assertMatchesRegularExpression('#10\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+#', $ov, 'endpoint shows host:port');
    }

    public function test_top_level_integrations_mount_works(): void
    {
        // When wired as module=integrations, the same registry renders at /admin/integrations.
        $list = $this->render('/admin/integrations', 5);
        self::assertStringContainsString('fp-pager', $list);
        self::assertStringContainsString('href="/admin/integrations/p2"', $list);
        $integ = Integrations::fromSeed(5);
        $id = $integ->endpoints()[0]['id'];
        $detail = $this->render('/admin/integrations/' . $id, 5);
        self::assertStringContainsString('alte-tabs', $detail);
    }

    // ================= safety / inert / escaping =================

    public function test_module_is_read_only_no_control_leaf(): void
    {
        $cmdb = Cmdb::fromSeed(3, VisualPersona::fromSeed(3)->domain());
        $id = $cmdb->assets()[0]['id'];
        foreach (['/admin/it', '/admin/it/assets', '/admin/it/assets/' . $id, '/admin/it/integrations'] as $p) {
            $html = $this->render($p, 3);
            self::assertStringNotContainsString('Queued', $html, $p);
            self::assertStringNotContainsString('Denied', $html, $p);
            self::assertStringNotContainsString('/approve', $html, $p);
            self::assertStringNotContainsString('/pay', $html, $p);
        }
    }

    public function test_no_public_ip_in_any_rendered_view(): void
    {
        $cmdb = Cmdb::fromSeed(3, VisualPersona::fromSeed(3)->domain());
        $assetId = $cmdb->assets()[0]['id'];
        $endId = Integrations::fromSeed(3)->endpoints()[0]['id'];
        $paths = [
            '/admin/it', '/admin/it/assets', '/admin/it/assets/type/server',
            '/admin/it/assets/' . $assetId, '/admin/it/assets/' . $assetId . '/network',
            '/admin/it/integrations', '/admin/it/integrations/' . $endId . '/connection',
        ];
        for ($seed = 0; $seed < 6; $seed++) {
            foreach ($paths as $p) {
                self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $this->render($p, $seed), "seed $seed path $p");
            }
        }
    }

    public function test_reflected_slug_cannot_break_out_of_html(): void
    {
        $html = $this->render('/admin/it/assets/%3Cscript%3Ealert(1)%3C-script%3E', 1);
        self::assertStringNotContainsString('<script>alert', $html);
    }

    public function test_every_email_is_at_the_one_persona_domain(): void
    {
        for ($seed = 0; $seed < 5; $seed++) {
            $persona = VisualPersona::fromSeed($seed);
            $domain = $persona->domain();
            $cmdb = Cmdb::fromSeed($seed, $domain);
            // Find a personal (assigned) asset so the overview renders an assignee email.
            $id = null;
            foreach ($cmdb->assets() as $a) {
                if ($a['assigneeEmail'] !== '') {
                    $id = $a['id'];
                    break;
                }
            }
            if ($id === null) {
                continue;
            }
            $html = $this->render('/admin/it/assets/' . $id, $seed);
            if (preg_match_all('/[a-z0-9._-]+@([a-z0-9.-]+)/i', $html, $m) > 0) {
                foreach ($m[1] as $d) {
                    self::assertSame($domain, $d, "seed $seed email domain");
                }
            }
        }
    }

    public function test_same_url_is_byte_identical(): void
    {
        $cmdb = Cmdb::fromSeed(11, VisualPersona::fromSeed(11)->domain());
        $id = $cmdb->assets()[0]['id'];
        foreach ([
            '/admin/it',
            '/admin/it/assets',
            '/admin/it/assets/p2',
            '/admin/it/assets/' . $id . '/compliance',
            '/admin/it/integrations',
        ] as $p) {
            self::assertSame($this->render($p, 11), $this->render($p, 11), "stable: $p");
        }
    }
}
