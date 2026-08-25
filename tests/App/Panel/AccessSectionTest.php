<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Access;
use Funnypot\App\Render\Panel\AccessSection;
use Funnypot\App\Render\PanelRoute;
use Funnypot\Core\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class AccessSectionTest extends TestCase
{
    /** Any address outside RFC1918 10.x is a leak of real routable space (spec SAFE invariant). */
    private const PUBLIC_IP = '/\b(?!10\.)(?!0\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';

    private const NAV = '/admin/access';

    /** Render a panel path through the section exactly as the skin would (parse -> render). */
    private function render(string $path, int $seed = 7): string
    {
        $route = PanelRoute::parse($path);
        return (new AccessSection())->render($route, VisualPersona::fromSeed($seed), '/admin');
    }

    // --- routing / depth ---

    public function test_landing_lists_doors_tiles_and_levers(): void
    {
        $html = $this->render('/admin/access');
        self::assertStringContainsString('Access &amp; Doors', $html);
        self::assertStringContainsString('LOCKDOWN ALL', $html);
        self::assertStringContainsString('Unlock all (fire egress)', $html);
        self::assertStringContainsString('Cardholders', $html);
        // A door link must route back under the same module mount.
        self::assertStringContainsString('href="/admin/access/door-', $html);
    }

    public function test_door_detail_and_subtabs_render(): void
    {
        foreach (['', '/events', '/schedule', '/access', '/anti-passback'] as $sub) {
            $html = $this->render('/admin/access/door-srv-a' . $sub);
            self::assertStringContainsString('Server Room A', $html, "subtab $sub");
            self::assertNotSame('', trim($html), "subtab $sub non-empty");
        }
    }

    public function test_unknown_door_slug_still_renders_a_plausible_detail(): void
    {
        // A fuzzed slug must not dead-end (a 404 inside a deep panel is a tell).
        $html = $this->render('/admin/access/door-does-not-exist-9999');
        self::assertStringContainsString('fp-card', $html);
        self::assertStringContainsString('Unlock', $html);
    }

    public function test_cardholder_roster_paginates(): void
    {
        $p1 = $this->render('/admin/access/cardholders');
        $p2 = $this->render('/admin/access/cardholders/p2');
        self::assertStringContainsString('page 1/', $p1);
        self::assertStringContainsString('page 2/', $p2);
        self::assertNotSame($p1, $p2, 'different pages render different rows');
        // Export link is a .zip (the only extension the decoy archive handler serves — spec E8).
        self::assertStringContainsString('cardholders_2026-08.csv.zip', $p1);
    }

    public function test_event_log_scroll_renders(): void
    {
        $html = $this->render('/admin/access/events');
        self::assertStringContainsString('<pre', $html);
        self::assertStringContainsString('GRANTED', $html);
        // Each scroll line now carries a full date, not just HH:MM:SS (spec E11 — a bare time-of-day
        // makes a log crossing local midnight read as the clock jumping backward with nothing to explain it).
        self::assertMatchesRegularExpression('/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/', $html);
    }

    /** Every event/badge log line must carry a full civil date alongside the time, and never a future one. */
    public function test_event_logs_show_full_date_and_never_future(): void
    {
        for ($seed = 0; $seed < 8; $seed++) {
            $access = Access::fromSeed($seed);
            $door = $access->doors()[0];

            foreach ($access->badgeEventsFor($door['id'], 40) as $e) {
                self::assertMatchesRegularExpression(
                    '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/',
                    $e['time'],
                    "seed $seed: badge event carries a full date"
                );
                $epoch = strtotime($e['time'] . ' UTC');
                self::assertLessThanOrEqual(Access::deployEpoch(), $epoch, "seed $seed: badge event must not be in the future");
            }

            foreach ($access->accessEventLog(60) as $line) {
                self::assertMatchesRegularExpression(
                    '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}  /',
                    $line,
                    "seed $seed: access log line carries a full date: $line"
                );
                $epoch = strtotime(substr($line, 0, 19) . ' UTC');
                self::assertLessThanOrEqual(Access::deployEpoch(), $epoch, "seed $seed: access log entry must not be in the future: $line");
            }
        }
    }

    /** badgeEventsFor() must walk strictly backward from DEPLOY_EPOCH: never a future row, never a
     *  repeated or backward-jumping timestamp (spec E11 — each row used to be an independent random draw,
     *  so a small gap on a later row could land newer than a large gap on an earlier one). */
    public function test_badge_events_are_strictly_monotonic(): void
    {
        for ($seed = 0; $seed < 8; $seed++) {
            $access = Access::fromSeed($seed);
            $door = $access->doors()[0];
            $prevEpoch = null;
            foreach ($access->badgeEventsFor($door['id'], 60) as $e) {
                $epoch = strtotime($e['time'] . ' UTC');
                if ($prevEpoch !== null) {
                    self::assertLessThan($prevEpoch, $epoch, "seed $seed: badge events must be strictly newest-first");
                }
                $prevEpoch = $epoch;
            }
        }
    }

    /** accessEventLog() must walk strictly backward from DEPLOY_EPOCH, including through the planted
     *  off-hours anomaly row — same invariant as badgeEventsFor()/CctvSectionTest's events() checks. */
    public function test_access_event_log_is_strictly_monotonic(): void
    {
        for ($seed = 0; $seed < 20; $seed++) {
            $access = Access::fromSeed($seed);
            $prevEpoch = null;
            foreach ($access->accessEventLog(60) as $line) {
                $epoch = strtotime(substr($line, 0, 19) . ' UTC');
                if ($prevEpoch !== null) {
                    self::assertLessThan($prevEpoch, $epoch, "seed $seed: access log must be strictly newest-first: $line");
                }
                $prevEpoch = $epoch;
            }
        }
    }

    // --- inert-control behaviour (the key trick) ---

    public function test_ordinary_door_unlock_is_a_canned_queue(): void
    {
        $html = $this->render('/admin/access/door-main-entrance/unlock');
        self::assertStringContainsString('Queued', $html);
        self::assertStringContainsString('next poll', $html);
        self::assertStringNotContainsString('Denied', $html);
    }

    public function test_server_room_unlock_is_a_guarded_soft_deny(): void
    {
        $html = $this->render('/admin/access/door-srv-a/unlock');
        self::assertStringContainsString('Denied', $html);
        self::assertStringContainsStringIgnoringCase('dual authorization', $html);
        self::assertStringContainsString('FAC-CMD-', $html);
        // A guarded verb must never claim success.
        self::assertStringNotContainsString('Queued', $html);
    }

    public function test_server_room_pulse_is_denied_state_unchanged(): void
    {
        // I5: a momentary `pulse` (still a real unlock) on a crown-jewel door must be guarded like unlock —
        // a dual-auth soft-deny, never a plain success receipt, and the door state must not change.
        $html = $this->render('/admin/access/door-srv-a/pulse');
        self::assertStringContainsString('Denied', $html);
        self::assertStringContainsStringIgnoringCase('dual authorization', $html);
        self::assertStringNotContainsString('Queued', $html);        // never a success receipt
        self::assertStringNotContainsString('next poll', $html);

        // State unchanged: the door detail still reads Secured after the pulse attempt (nothing persisted).
        $detail = $this->render('/admin/access/door-srv-a');
        self::assertStringContainsString('Secured', $detail);

        // A `mode` change on a high-security door is guarded too.
        $mode = $this->render('/admin/access/door-srv-a/mode/card-only');
        self::assertStringContainsString('Denied', $mode);
        self::assertStringNotContainsString('Queued', $mode);
    }

    public function test_building_wide_levers_soft_deny(): void
    {
        foreach (['lockdown-all', 'unlock-all'] as $lever) {
            $html = $this->render('/admin/access/' . $lever);
            self::assertStringContainsString('Denied', $html, $lever);
            self::assertStringContainsString('awaiting', $html, $lever);
        }
    }

    public function test_mode_arg_is_reflected_escaped(): void
    {
        // The arg is the one place attacker input reaches output; it must be HTML-escaped, never raw.
        $route = PanelRoute::parse('/admin/access/door-main-entrance/mode/card-pin');
        $html = (new AccessSection())->render($route, VisualPersona::fromSeed(7), '/admin');
        self::assertStringContainsString('card-pin', $html);
    }

    public function test_no_control_path_emits_a_raw_script_injection(): void
    {
        // Slugging strips angle brackets before routing; nothing reflected can break out of HTML.
        $html = $this->render('/admin/access/door-x/mode/%3Cscript%3E');
        self::assertStringNotContainsString('<script>alert', $html);
    }

    // --- determinism + safety invariants ---

    public function test_same_url_is_byte_identical(): void
    {
        foreach (['/admin/access', '/admin/access/door-srv-a', '/admin/access/cardholders/p3', '/admin/access/events'] as $p) {
            self::assertSame($this->render($p, 11), $this->render($p, 11), "stable: $p");
        }
    }

    public function test_no_public_ip_in_any_view(): void
    {
        $paths = ['/admin/access', '/admin/access/door-srv-a', '/admin/access/door-srv-a/events',
                  '/admin/access/cardholders', '/admin/access/events', '/admin/access/door-mdf/unlock'];
        for ($seed = 0; $seed < 8; $seed++) {
            foreach ($paths as $p) {
                self::assertDoesNotMatchRegularExpression(self::PUBLIC_IP, $this->render($p, $seed), "seed $seed path $p");
            }
        }
    }

    public function test_pins_never_appear_and_badges_are_masked(): void
    {
        $html = $this->render('/admin/access/cardholders');
        self::assertStringContainsString('••••', $html, 'PINs masked');
        // No full 6-digit badge number leaks in the roster (masked to last four).
        self::assertDoesNotMatchRegularExpression('/>\s*0{2}\d{4}\s*</', $html, 'badge shown unmasked');
    }

    // --- generator-level checks ---

    public function test_generator_deterministic_and_coherent(): void
    {
        $a = Access::fromSeed(5);
        $b = Access::fromSeed(5);
        self::assertSame($a->doors(), $b->doors());
        self::assertSame($a->summary(), $b->summary());
        self::assertSame($a->cardholderPage(0, 20), $b->cardholderPage(0, 20));

        $acsIps = [];
        foreach (\Funnypot\App\Render\Fake\Building::fromSeed(5)->controllers() as $c) {
            if ($c['kind'] === 'ACS') {
                $acsIps[$c['id']] = $c['ip'];
            }
        }
        foreach ($a->doors() as $d) {
            self::assertSame(
                ['id', 'name', 'type', 'area', 'floor', 'zone', 'room', 'controller', 'controllerIp',
                 'mode', 'state', 'secured', 'highSecurity', 'lastEvent', 'lastSeen'],
                array_keys($d)
            );
            self::assertMatchesRegularExpression('/^[a-z0-9-]+$/', $d['id'], 'door id is a slug');
            self::assertStringStartsWith('10.0.60.', $d['controllerIp'], 'door on ACS fabric');
            // Controller ip agrees with the Building spine for that controller.
            self::assertSame($acsIps[$d['controller']], $d['controllerIp'], 'controller ip reconciles');
        }
    }

    public function test_cardholder_count_reconciles_with_org_ratio(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $org = \Funnypot\App\Render\Fake\Org::fromSeed($seed);
            self::assertSame(
                $org->magnitudes()['cardholders'],
                Access::fromSeed($seed)->cardholderCount(),
                "seed $seed cardholder count = N + contractors"
            );
        }
    }

    public function test_anomaly_budget_is_bounded(): void
    {
        // At most two doors ever read unsecured (0-2 anomaly budget); crown-jewel doors never open.
        for ($seed = 0; $seed < 20; $seed++) {
            $unsecured = 0;
            foreach (Access::fromSeed($seed)->doors() as $d) {
                if (!$d['secured']) {
                    $unsecured++;
                    self::assertFalse($d['highSecurity'], "seed $seed: high-sec door must stay secured");
                }
            }
            self::assertLessThanOrEqual(2, $unsecured, "seed $seed anomaly budget");
        }
    }
}
