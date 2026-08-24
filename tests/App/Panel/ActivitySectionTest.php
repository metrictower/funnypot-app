<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\Access;
use Funnypot\App\Render\Fake\Activity;
use Funnypot\App\Render\Fake\Org;
use Funnypot\App\Render\Panel\ActivitySection;
use Funnypot\App\Render\PanelRoute;
use Funnypot\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class ActivitySectionTest extends TestCase
{
    /** Every source address must be RFC1918 or documentation TEST-NET (RFC 5737); anything else leaks
     *  real routable space (spec SAFE invariant). */
    private const IP = '/\b\d{1,3}(?:\.\d{1,3}){3}\b/';
    private const IP_ALLOWED = '/^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|198\.51\.100\.|203\.0\.113\.)/';

    /** Render a panel path through the section exactly as the skin would (parse -> render). */
    private function render(string $path, int $seed = 7): string
    {
        $route = PanelRoute::parse($path);
        return (new ActivitySection())->render($route, VisualPersona::fromSeed($seed), '/admin');
    }

    private function activity(int $seed = 7): Activity
    {
        return Activity::fromSeed($seed, VisualPersona::fromSeed($seed)->domain());
    }

    // --- routing / rendering ---

    public function test_landing_renders_tiles_filters_and_timeline(): void
    {
        $html = $this->render('/admin/activity');
        self::assertStringContainsString('Activity Feed', $html);
        self::assertStringContainsString('Sign-in', $html);      // a filter chip label
        self::assertStringContainsString('<table', $html);       // the timeline
        self::assertStringContainsString('page 1 /', $html);     // the pager
    }

    public function test_rows_deep_link_back_under_the_mount(): void
    {
        $html = $this->render('/admin/activity');
        // Every event links back into a module under the same panel mount.
        self::assertStringContainsString('href="/admin/', $html);
        // The known deep-link families all appear across a page of mixed events.
        self::assertMatchesRegularExpression('#href="/admin/(hr/employees|access|finance/ap|facilities/work-orders|fire|sensors|helpdesk/certs|hvac|lighting)#', $html);
    }

    public function test_filter_bar_links_to_each_type(): void
    {
        $html = $this->render('/admin/activity');
        foreach ($this->activity()->typeSlugs() as $slug) {
            self::assertStringContainsString('href="/admin/activity/' . $slug . '"', $html, "filter chip $slug");
        }
    }

    public function test_type_filter_narrows_the_feed_to_one_type(): void
    {
        // A door-filtered view: every rendered event is an Access event, so it deep-links into /access.
        $events = $this->activity()->feed(1, 40, 'door')['events'];
        self::assertNotSame([], $events);
        foreach ($events as $e) {
            self::assertSame('door', $e['type']);
            self::assertStringStartsWith('/access/', $e['link']);
        }
        // The rendered filtered page shows its own crumb and does not 404.
        $html = $this->render('/admin/activity/door');
        self::assertStringContainsString('Access', $html);
        self::assertStringContainsString('<table', $html);
    }

    /** Headline tiles must read as historical windows, not present-state — "Alarms"~300-750 used to be
     *  presented as if it were the same concept as Dashboard's "Active alarms: 0-3" current-state gauge. */
    public function test_headline_tiles_are_labeled_as_historical_windows(): void
    {
        $html = $this->render('/admin/activity');
        foreach (['Sign-ins (30 d)', 'Access events (30 d)', 'Approval events (30 d)',
                  'Alarm events (30 d)', 'Cert expiries (30 d)'] as $label) {
            self::assertStringContainsString($label, $html, "tile labeled as a historical window: $label");
        }
        // The bare present-tense label must not appear (it would read as the same concept as Dashboard's
        // current-state "Active alarms" tile).
        self::assertStringNotContainsString('Approvals pending', $html);
    }

    public function test_pagination_advances(): void
    {
        $p1 = $this->render('/admin/activity');
        $p2 = $this->render('/admin/activity/p2');
        self::assertStringContainsString('page 1 /', $p1);
        self::assertStringContainsString('page 2 /', $p2);
        self::assertNotSame($p1, $p2, 'different pages render different rows');

        // A filtered page paginates in the path too (/activity/<type>/pN).
        $f2 = $this->render('/admin/activity/signin/p2');
        self::assertStringContainsString('page 2 /', $f2);
    }

    // --- monotonic timestamps (the core invariant) ---

    public function test_timestamps_are_strictly_monotonic_descending(): void
    {
        for ($seed = 0; $seed < 6; $seed++) {
            $feed = $this->activity($seed)->feed(1, 60, '');
            $prev = null;
            foreach ($feed['events'] as $e) {
                if ($prev !== null) {
                    self::assertLessThan($prev, $e['epoch'], "seed $seed: epochs strictly descending");
                }
                $prev = $e['epoch'];
            }
        }
    }

    public function test_timestamps_stay_descending_across_a_page_boundary(): void
    {
        $act = $this->activity();
        $p1 = $act->feed(1, 50, '');
        $p2 = $act->feed(2, 50, '');
        $lastOfP1 = end($p1['events'])['epoch'];
        $firstOfP2 = $p2['events'][0]['epoch'];
        self::assertLessThan($lastOfP1, $firstOfP2, 'page 2 continues strictly below page 1');
    }

    public function test_filtered_subsequence_is_strictly_descending(): void
    {
        $feed = $this->activity(3)->feed(1, 30, 'door');
        $prev = null;
        foreach ($feed['events'] as $e) {
            if ($prev !== null) {
                self::assertLessThan($prev, $e['epoch']);
            }
            $prev = $e['epoch'];
        }
    }

    // --- entities resolve (coherence) ---

    public function test_every_event_names_a_resolvable_org_person(): void
    {
        for ($seed = 0; $seed < 5; $seed++) {
            $org = Org::fromSeed($seed);
            foreach ($this->activity($seed)->feed(1, 40, '')['events'] as $e) {
                self::assertNotNull($org->person($e['actorId']), "seed $seed actor {$e['actorId']} resolves");
                self::assertSame($org->person($e['actorId'])['name'], $e['actor'], 'actor name agrees with roster');
            }
        }
    }

    public function test_door_events_reference_a_real_door(): void
    {
        for ($seed = 0; $seed < 5; $seed++) {
            $doorIds = [];
            foreach (Access::fromSeed($seed)->doors() as $d) {
                $doorIds[$d['id']] = true;
            }
            foreach ($this->activity($seed)->feed(1, 60, 'door')['events'] as $e) {
                self::assertArrayHasKey($e['entityId'], $doorIds, "seed $seed door {$e['entityId']} is in the estate");
            }
        }
    }

    // --- determinism + safety ---

    public function test_same_url_is_byte_identical(): void
    {
        foreach (['/admin/activity', '/admin/activity/door', '/admin/activity/p3', '/admin/activity/signin/p2'] as $p) {
            self::assertSame($this->render($p, 11), $this->render($p, 11), "stable: $p");
        }
    }

    public function test_generator_is_deterministic(): void
    {
        $a = Activity::fromSeed(5, 'example.test');
        $b = Activity::fromSeed(5, 'example.test');
        self::assertSame($a->total(), $b->total());
        self::assertSame($a->feed(1, 50, '')['events'], $b->feed(1, 50, '')['events']);
        self::assertSame($a->feed(2, 50, 'door')['events'], $b->feed(2, 50, 'door')['events']);
    }

    public function test_filtered_total_reconciles_with_the_weight_table(): void
    {
        // The per-type counts must sum to no more than the whole-stream total (fixed weights, sum 100).
        $act = $this->activity();
        $sum = 0;
        foreach ($act->typeCounts() as $c) {
            $sum += $c['count'];
            self::assertGreaterThan(0, $c['count']);
        }
        // Rounding can nudge the sum by a few counts; it must stay within a handful of the total.
        self::assertLessThanOrEqual($act->total() + count($act->typeSlugs()), $sum);
    }

    public function test_no_disallowed_ip_in_any_view(): void
    {
        $paths = ['/admin/activity', '/admin/activity/signin', '/admin/activity/door', '/admin/activity/alarm'];
        for ($seed = 0; $seed < 8; $seed++) {
            foreach ($paths as $p) {
                $html = $this->render($p, $seed);
                if (preg_match_all(self::IP, $html, $m) > 0) {
                    foreach ($m[0] as $ip) {
                        self::assertMatchesRegularExpression(self::IP_ALLOWED, $ip, "seed $seed path $p ip $ip");
                    }
                }
            }
        }
    }

    public function test_unknown_filter_falls_back_and_reflects_nothing_raw(): void
    {
        // A fuzzed section slot must not 404 and must not reflect an injection: slugging strips brackets
        // before routing, and an unknown filter renders the unfiltered stream.
        $html = $this->render('/admin/activity/%3Cscript%3Ealert(1)%3C-script%3E');
        self::assertStringNotContainsString('<script>alert', $html);
        self::assertStringContainsString('Activity Feed', $html);
        self::assertStringContainsString('<table', $html);
    }

    public function test_no_php_time_functions_are_used_in_the_generator(): void
    {
        // The frozen-clock invariant: no wall-clock source in the generator (a shifting feed is a tell).
        // Strip comments first — the doc comments legitimately name time()/date() when explaining why
        // they are avoided, so only real code tokens are checked.
        $src = file_get_contents(dirname(__DIR__, 3) . '/src/App/Render/Fake/Activity.php');
        self::assertIsString($src);
        $code = '';
        foreach (token_get_all($src) as $tok) {
            if (is_array($tok)) {
                if ($tok[0] === T_COMMENT || $tok[0] === T_DOC_COMMENT) {
                    continue;
                }
                $code .= $tok[1];
            } else {
                $code .= $tok;
            }
        }
        foreach (['time(', 'date(', 'gmdate(', 'mt_rand(', 'rand(', 'shuffle('] as $banned) {
            self::assertStringNotContainsString($banned, $code, "generator must not call $banned");
        }
    }
}
