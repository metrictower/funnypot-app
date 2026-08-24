<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Building;
use Funnypot\App\Render\Fake\Helpdesk;
use Funnypot\App\Render\Fake\ItServices;
use Funnypot\App\Render\Fake\Network;
use Funnypot\App\Render\Fake\Org;
use Funnypot\App\Render\Panel\ItServicesSection;
use Funnypot\App\Render\PanelRoute;
use Funnypot\App\Render\VisualPersona;
use PHPUnit\Framework\TestCase;

final class ItServicesSectionTest extends TestCase
{
    /** Any address outside RFC1918 10.x is a leak of real routable space (spec SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    /** Render a panel path through the section exactly as the skin would (parse -> render). */
    private function render(string $path, int $seed = 7): string
    {
        $route = PanelRoute::parse($path);
        return (new ItServicesSection())->render($route, VisualPersona::fromSeed($seed), '/admin');
    }

    // --- routing / depth ---

    public function test_helpdesk_landing_lists_tickets(): void
    {
        $html = $this->render('/admin/helpdesk');
        self::assertStringContainsString('Helpdesk tickets', $html);
        self::assertStringContainsString('href="/admin/helpdesk/hd-', $html);
        // Every sub-area is reachable from the landing (the graph has no leaves).
        self::assertStringContainsString('href="/admin/helpdesk/printers"', $html);
        self::assertStringContainsString('href="/admin/helpdesk/certs"', $html);
    }

    public function test_each_area_landing_renders(): void
    {
        $areas = [
            'printers' => 'Printer status',
            'licenses' => 'Software licences',
            'mdm' => 'Enrolled endpoints',
            'mail' => 'Mailboxes',
            'certs' => 'Certificates',
        ];
        foreach ($areas as $area => $needle) {
            $html = $this->render('/admin/helpdesk/' . $area);
            self::assertStringContainsString($needle, $html, "area $area");
        }
    }

    public function test_alias_root_reaches_the_same_area(): void
    {
        // Entered via the area root alias, the slots shift up one but resolve to the same sub-area.
        self::assertStringContainsString('Printer status', $this->render('/admin/printers'));
        self::assertStringContainsString('Certificates', $this->render('/admin/certificates'));
        self::assertStringContainsString('Mailboxes', $this->render('/admin/mail'));
        // A detail id under an alias root resolves too (slot shift is handled).
        $html = $this->render('/admin/printers/mfp-g-01');
        self::assertStringContainsString('alte-card', $html);
    }

    public function test_ticket_detail_and_subtabs_render(): void
    {
        foreach (['', '/comments', '/attachments'] as $sub) {
            $html = $this->render('/admin/helpdesk/hd-2026-100001' . $sub);
            self::assertStringContainsString('HD-2026-100001', $html, "subtab $sub");
            self::assertNotSame('', trim($html), "subtab $sub non-empty");
        }
    }

    public function test_unknown_ids_still_render_a_plausible_detail(): void
    {
        // A fuzzed id must not dead-end (a 404 inside the panel is a tell).
        foreach ([
            '/admin/helpdesk/hd-does-not-exist-9999',
            '/admin/helpdesk/printers/prn-nope-77',
            '/admin/helpdesk/licenses/lic-nope',
            '/admin/helpdesk/mdm/dev-nope',
            '/admin/helpdesk/mail/mbx-nope',
            '/admin/helpdesk/certs/cert-nope',
        ] as $p) {
            self::assertStringContainsString('alte-card', $this->render($p), $p);
        }
    }

    public function test_lists_use_reachable_pager(): void
    {
        // Every list carries a pagerHtml "page N / M" so deep pages are crawlable.
        foreach (['/admin/helpdesk', '/admin/helpdesk/printers', '/admin/helpdesk/licenses',
                  '/admin/helpdesk/mdm', '/admin/helpdesk/mail', '/admin/helpdesk/certs'] as $base) {
            self::assertStringContainsString('page 1 / ', $this->render($base), $base);
        }
        // The tickets corpus is thousands deep, so page 2 exists and differs from page 1.
        $p1 = $this->render('/admin/helpdesk');
        $p2 = $this->render('/admin/helpdesk/p2');
        self::assertStringContainsString('page 2 / ', $p2);
        self::assertNotSame($p1, $p2, 'ticket pages differ');
    }

    public function test_all_downloads_end_in_zip(): void
    {
        // Every download under the panel mount must end .zip/.tar.gz (spec E8).
        foreach (['/admin/helpdesk/hd-2026-100001/attachments', '/admin/helpdesk/certs/cert-1001'] as $p) {
            $html = $this->render($p);
            self::assertMatchesRegularExpression('/helpdesk\/download\/[A-Za-z0-9._-]+\.(zip|tar\.gz)"/', $html, $p);
        }
    }

    // --- inert controls: mild verbs queue, destructive verbs deny (never "done") ---

    public function test_printer_release_is_a_canned_queue(): void
    {
        $html = $this->render('/admin/helpdesk/printers/mfp-g-01/release/job-12345');
        self::assertStringContainsString('Queued', $html);
        self::assertStringContainsString('ITS-CMD-', $html);
        self::assertStringNotContainsString('Denied', $html);
    }

    public function test_mdm_remote_wipe_is_a_guarded_soft_deny(): void
    {
        $html = $this->render('/admin/helpdesk/mdm/dev-20001/wipe');
        self::assertStringContainsString('Denied', $html);
        self::assertStringContainsStringIgnoringCase('second', $html);
        self::assertStringContainsString('ITS-CMD-', $html);
        self::assertStringNotContainsString('Queued', $html);
        self::assertStringContainsStringIgnoringCase('no data has been erased', $html);
    }

    public function test_mdm_fleet_run_script_is_a_guarded_soft_deny(): void
    {
        $html = $this->render('/admin/helpdesk/mdm/run-script');
        self::assertStringContainsString('Denied', $html);
        self::assertStringNotContainsString('Queued', $html);
        self::assertStringContainsStringIgnoringCase('no code has run', $html);
    }

    public function test_mail_search_purge_never_deletes(): void
    {
        $html = $this->render('/admin/helpdesk/mail/search-purge');
        self::assertStringContainsString('Denied', $html);
        self::assertStringContainsStringIgnoringCase('no messages were removed', $html);
        self::assertStringNotContainsString('Queued', $html);
    }

    public function test_mail_add_forwarding_is_a_canned_queue(): void
    {
        $html = $this->render('/admin/helpdesk/mail/mbx-1001/add-forwarding');
        self::assertStringContainsString('Queued', $html);
        self::assertStringNotContainsString('Denied', $html);
    }

    public function test_license_reveal_is_a_non_validating_dummy(): void
    {
        $html = $this->render('/admin/helpdesk/licenses/lic-1001/reveal');
        // The reveal is a placeholder in the right shape (trailing EXAMP group), never a real key.
        self::assertStringContainsString('EXAMP', $html);
    }

    // --- escaping: nothing reflected can break out of HTML ---

    public function test_no_control_path_emits_a_raw_script_injection(): void
    {
        // Slugging strips angle brackets before routing; a reflected arg is escaped by kvTableHtml.
        foreach ([
            '/admin/helpdesk/printers/mfp-g-01/release/%3Cscript%3Ealert(1)%3C-script%3E',
            '/admin/helpdesk/%3Cscript%3Ealert(1)%3C-script%3E',
        ] as $p) {
            self::assertStringNotContainsString('<script>alert', $this->render($p), $p);
        }
    }

    // --- determinism ---

    public function test_same_url_is_byte_identical(): void
    {
        foreach ([
            '/admin/helpdesk',
            '/admin/helpdesk/hd-2026-100005',
            '/admin/helpdesk/hd-2026-100005/comments',
            '/admin/helpdesk/printers',
            '/admin/helpdesk/printers/mfp-g-01/queue',
            '/admin/helpdesk/licenses/lic-1003',
            '/admin/helpdesk/mdm/dev-20003',
            '/admin/helpdesk/mail/mbx-1002',
            '/admin/helpdesk/certs/cert-1004',
        ] as $p) {
            self::assertSame($this->render($p, 11), $this->render($p, 11), "stable: $p");
        }
    }

    // --- safety invariants ---

    public function test_no_public_ip_in_any_view(): void
    {
        $paths = [
            '/admin/helpdesk', '/admin/helpdesk/hd-2026-100001',
            '/admin/helpdesk/printers/mfp-g-01', '/admin/helpdesk/printers/mfp-g-01/scan',
            '/admin/helpdesk/mdm', '/admin/helpdesk/mdm/dev-20001',
            '/admin/helpdesk/mail', '/admin/helpdesk/mail/mbx-1001',
            '/admin/helpdesk/certs/cert-1001',
        ];
        for ($seed = 0; $seed < 6; $seed++) {
            foreach ($paths as $p) {
                self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $this->render($p, $seed), "seed $seed path $p");
            }
        }
    }

    public function test_license_key_and_smtp_account_are_masked(): void
    {
        $lic = $this->render('/admin/helpdesk/licenses/lic-1001');
        self::assertStringContainsString('••••', $lic, 'licence key masked at rest');
        $scan = $this->render('/admin/helpdesk/printers/mfp-g-01/scan');
        self::assertStringContainsString('••••', $scan, 'scan SMTP account masked');
    }

    // --- cross-coherence with Org and Building ---

    public function test_ticket_people_are_real_roster_members(): void
    {
        for ($seed = 0; $seed < 4; $seed++) {
            $org = Org::fromSeed($seed);
            $names = [];
            foreach ($org->people($org->headcount()) as $p) {
                $names[$p['name']] = true;
            }
            $hd = Helpdesk::fromSeed($seed, 'example.test');
            for ($i = 0; $i < 20; $i++) {
                $t = $hd->ticketAt($i);
                self::assertArrayHasKey($t['requester'], $names, "seed $seed ticket $i requester in roster");
                self::assertArrayHasKey($t['assignee'], $names, "seed $seed ticket $i assignee in roster");
            }
        }
    }

    public function test_printer_location_is_a_real_building_room(): void
    {
        for ($seed = 0; $seed < 4; $seed++) {
            $roomNames = [];
            $bld = Building::fromSeed($seed);
            foreach ($bld->floors() as $f) {
                foreach ($bld->roomsFor($f['code']) as $r) {
                    $roomNames[$r['name']] = true;
                }
            }
            $it = ItServices::fromSeed($seed, 'example.test');
            for ($i = 0; $i < $it->printerCount(); $i++) {
                $loc = $it->printerAt($i)['location'];
                $name = trim(substr($loc, 0, strpos($loc, ' (Floor')));
                self::assertArrayHasKey($name, $roomNames, "seed $seed printer $i room in Building");
            }
        }
    }

    public function test_mdm_owner_and_ip_come_from_the_roster(): void
    {
        for ($seed = 0; $seed < 4; $seed++) {
            $org = Org::fromSeed($seed, 'example.test');
            $roster = $org->people($org->headcount());
            $n = count($roster);
            $names = [];
            foreach ($roster as $p) {
                $names[$p['name']] = true;
            }
            $it = ItServices::fromSeed($seed, 'example.test');
            // The device owner is the roster member at index (i mod N); its last-IP is that person's
            // employee-VLAN address (compared by index, since display names are not unique).
            for ($i = 0; $i < 30; $i++) {
                $d = $it->mdmDeviceAt($i);
                self::assertArrayHasKey($d['owner'], $names, "seed $seed device $i owner in roster");
                self::assertSame($roster[$i % $n]['ip'], $d['ip'], "seed $seed device $i ip == owner VLAN ip");
            }
        }
    }

    public function test_every_printer_ip_falls_in_a_declared_vlan_subnet(): void
    {
        // "One IP fabric": a printer's address must sit inside a subnet Network actually declares, or it is
        // an undeclared segment that contradicts the VLAN plan rendered elsewhere.
        for ($seed = 0; $seed < 6; $seed++) {
            $it = ItServices::fromSeed($seed, 'example.test');
            $subnets = [];
            foreach (Network::fromSeed($seed, 'example.test')->vlans() as $v) {
                $subnets[] = $v['subnet'];
            }
            for ($i = 0; $i < $it->printerCount(); $i++) {
                $ip = $it->printerAt($i)['ip'];
                $inSome = false;
                foreach ($subnets as $cidr) {
                    if ($this->ipInCidr($ip, $cidr)) {
                        $inSome = true;
                        break;
                    }
                }
                self::assertTrue($inSome, "seed $seed printer $i ip $ip in a declared VLAN subnet");
            }
        }
    }

    /** True when an IPv4 dotted address sits inside a CIDR block (used to check the one-fabric invariant). */
    private function ipInCidr(string $ip, string $cidr): bool
    {
        $parts = explode('/', $cidr);
        $net = ip2long($parts[0]);
        $bits = (int) $parts[1];
        $addr = ip2long($ip);
        if ($net === false || $addr === false) {
            return false;
        }
        $mask = $bits === 0 ? 0 : (-1 << (32 - $bits)) & 0xFFFFFFFF;
        return ($addr & $mask) === ($net & $mask);
    }

    public function test_magnitudes_reconcile_with_headcount(): void
    {
        for ($seed = 0; $seed < 4; $seed++) {
            $org = Org::fromSeed($seed, 'example.test');
            $it = ItServices::fromSeed($seed, 'example.test');
            $mags = $org->magnitudes();
            self::assertSame($mags['mailboxes'], $it->mailboxCount(), "seed $seed mailboxes == N");
            self::assertSame($mags['mdmEnrolled'], $it->mdmCount(), "seed $seed endpoints == assets");
            $s = $it->mdmSummary();
            self::assertSame($s['enrolled'], $s['compliant'] + $s['atRisk'] + $s['nonCompliant'], "seed $seed compliance closes");
        }
    }

    public function test_mailbox_addresses_are_at_the_one_persona_domain(): void
    {
        for ($seed = 0; $seed < 5; $seed++) {
            $persona = VisualPersona::fromSeed($seed);
            $domain = $persona->domain();
            $it = ItServices::fromSeed($seed, $domain);
            for ($i = 0; $i < 20; $i++) {
                $addr = $it->mailboxAt($i)['address'];
                self::assertStringEndsWith('@' . $domain, $addr, "seed $seed mailbox $i at one domain");
            }
        }
    }

    public function test_ticket_and_mdm_detail_emails_are_at_the_one_domain(): void
    {
        // These pages carry only the org's own addresses (no external-forwarding anomaly), so every
        // email must be at the persona domain — one host = one domain.
        for ($seed = 0; $seed < 5; $seed++) {
            $domain = VisualPersona::fromSeed($seed)->domain();
            foreach (['/admin/helpdesk/hd-2026-100001', '/admin/helpdesk/mdm/dev-20001'] as $p) {
                $html = $this->render($p, $seed);
                if (preg_match_all('/[a-z0-9._-]+@([a-z0-9.-]+)/i', $html, $m) > 0) {
                    foreach ($m[1] as $d) {
                        self::assertSame($domain, $d, "seed $seed path $p email domain");
                    }
                }
            }
        }
    }

    public function test_budgeted_suspicious_external_forwarding_rule_exists(): void
    {
        // Exactly one mailbox carries the planted external forwarding rule (the anomaly); its target is a
        // clearly-fake reserved (.example) domain, never the persona domain.
        for ($seed = 0; $seed < 5; $seed++) {
            $domain = VisualPersona::fromSeed($seed)->domain();
            $it = ItServices::fromSeed($seed, $domain);
            $sus = $it->mailboxAt($it->suspiciousMailboxIndex());
            $found = false;
            foreach ($sus['forwarding'] as $f) {
                if ($f['suspicious']) {
                    $found = true;
                    self::assertStringEndsWith('.example', substr($f['to'], strpos($f['to'], '@') + 1), "seed $seed external target reserved");
                    self::assertStringNotContainsString('@' . $domain, $f['to'], "seed $seed target not persona domain");
                }
            }
            self::assertTrue($found, "seed $seed suspicious mailbox carries the external rule");
        }
    }

    // --- generator determinism ---

    public function test_generators_are_deterministic(): void
    {
        $a = ItServices::fromSeed(5, 'example.test');
        $b = ItServices::fromSeed(5, 'example.test');
        self::assertSame($a->printerAt(0), $b->printerAt(0));
        self::assertSame($a->licenseAt(0), $b->licenseAt(0));
        self::assertSame($a->mdmDeviceAt(0), $b->mdmDeviceAt(0));
        self::assertSame($a->mailboxAt(0), $b->mailboxAt(0));
        self::assertSame($a->certAt(0), $b->certAt(0));
        self::assertSame(
            Helpdesk::fromSeed(5, 'example.test')->ticketAt(0),
            Helpdesk::fromSeed(5, 'example.test')->ticketAt(0)
        );
    }

    public function test_license_seats_used_never_exceed_total(): void
    {
        for ($seed = 0; $seed < 4; $seed++) {
            $it = ItServices::fromSeed($seed, 'example.test');
            for ($i = 0; $i < $it->licenseCount(); $i++) {
                $l = $it->licenseAt($i);
                self::assertLessThanOrEqual($l['seatsTotal'], $l['seatsUsed'], "seed $seed lic $i seats");
            }
        }
    }

    public function test_id_round_trips_to_the_same_record(): void
    {
        $it = ItServices::fromSeed(3, 'example.test');
        self::assertSame($it->printerAt(4), $it->printerById($it->printerAt(4)['id']));
        self::assertSame($it->licenseAt(4), $it->licenseById($it->licenseAt(4)['id']));
        self::assertSame($it->mdmDeviceAt(4), $it->mdmDeviceById($it->mdmDeviceAt(4)['id']));
        self::assertSame($it->mailboxAt(4), $it->mailboxById($it->mailboxAt(4)['id']));
        self::assertSame($it->certAt(4), $it->certById($it->certAt(4)['id']));
        $hd = Helpdesk::fromSeed(3, 'example.test');
        self::assertSame($hd->ticketAt(9), $hd->ticketByIdSlug($hd->ticketAt(9)['id']));
    }
}
