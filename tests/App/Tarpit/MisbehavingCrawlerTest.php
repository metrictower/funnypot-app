<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\CorporateController;
use Funnypot\App\Http\DashboardController;
use Funnypot\App\Http\HomeController;
use Funnypot\App\Http\HoneypotController;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use Funnypot\App\Http\LabyrinthController;
use Funnypot\App\Http\Router;
use Funnypot\App\Admin\AdminAuth;
use Funnypot\App\Config\ConfigStore;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\Core\RequestContext;
use Geo;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0245b — the anti-Baidu acceptance proof (spec §4, ticket HARD constraint 2, plan-review SHOULD-FIX
 * 2). The operator's real incident: a link-generating maze whose entry sat in a robots.txt `Disallow`
 * line, and Baidu's bot treated the Disallow as a TARGET LIST and hammered it into a self-DoS. robots.txt
 * and nofollow are advisory-only and NOT a containment mechanism.
 *
 * This models a MISBEHAVING crawler that: (a) fetches /robots.txt and treats EVERY `Disallow:` entry as a
 * seed target (the whole bait list, not just /admin/); (b) extracts links with a PURE `href|src` regex —
 * no comment repair, no whitespace repair, no reasoning; (c) BFS's through the REAL Router. It asserts the
 * crawler's frontier is bounded and NEVER contains the labyrinth (the entry is undiscoverable and the
 * interior is non-descendable), while an LlmShapedNavigator that decodes the LLM-only hints DOES descend
 * past depth 8 — proving the maze is traversable by reasoning, closed to a dumb crawler.
 *
 * *This test fails if any plain href/src ever resolves to labyrinth surface, or if the entry string ever
 * appears in robots.txt or a crawled body — the precise crawler-amplification defect.*
 */
final class MisbehavingCrawlerTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        putenv('FUNNYPOT_TARPIT=1'); // arm the tarpit so the labyrinth seam is mounted through the real Router
        $_GET = [];
        $_POST = [];
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
        putenv('FUNNYPOT_TARPIT');
        putenv('FUNNYPOT_MODE');
        $_GET = [];
        $_POST = [];
    }

    private function path(string $tag): string
    {
        $p = sys_get_temp_dir() . '/fp_crawl_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /**
     * The real Router, tarpit ARMED (labyrinth mounted + the entry hint planted on the mode's
     * login-success funnel) — exactly the demo/index.php wiring, minus the LLM sidecar. In public mode
     * the hint rides HomeController's login-success (/), in stealth mode CorporateController's
     * credential-submission response (POST /login) — the FP-0245e seam.
     */
    private function router(string $mode = 'public'): Router
    {
        putenv('FUNNYPOT_MODE=' . $mode);
        $config = AppConfig::fromEnv(sys_get_temp_dir());
        self::assertSame($mode, $config->mode);
        self::assertTrue($config->tarpitEnabled, 'the tarpit must be armed for this test');

        $store = new SqliteHitStore($this->path('hit'));
        $geo = new Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid());
        $decoys = dirname(__DIR__, 3) . '/demo/decoys';
        $assets = dirname(__DIR__, 3) . '/demo/assets';

        $budget = new TarpitBudget(
            $this->path('tarpit'),
            true,
            $config->tarpitMaxConcurrent,
            $config->tarpitMaxPerIp,
            $config->tarpitBytesPerIpHrMb * 1024 * 1024,
            $config->tarpitWallPerIpHrS * 1000,
            $config->tarpitGlobalBytesHrMb * 1024 * 1024,
            $config->tarpitPagesPerIpHr,
            15,
        );
        $identity = IdentityTestSupport::httpIdentity();
        $labyrinth = new LabyrinthController($store, $geo, $budget, $identity->personaSeed(), $config->tarpitBytesPerRespMb);

        $hint = LabyrinthController::entryHint();
        $honeypot = new HoneypotController($store, $geo, $config, $decoys, IdentityTestSupport::coreConfigFactory());
        $dashboard = new DashboardController($store, $geo, $config, $assets, null, null, $store, new AdminAuth($this->path('auth')), new ConfigStore($this->path('cfg')));
        // Wire the hint into the controller that fronts login in this mode, exactly as demo/index.php does.
        $corporate = new CorporateController($store, $geo, $config, $assets, null, $mode === 'stealth' ? $hint : null);
        $home = new HomeController($store, $geo, $config, $assets, null, $mode === 'public' ? $hint : null);

        return new Router($config, $honeypot, $dashboard, $corporate, $home, null, null, null, null, $labyrinth);
    }

    /** GET one path through the real Router, returning the response body (the crawler's view). */
    private function fetch(Router $router, string $path, string $method = 'GET', string $ip = '198.51.100.30'): string
    {
        ob_start();
        @$router->dispatch(new RequestContext($method, $path), $ip, 'off');

        return (string) ob_get_clean();
    }

    /** Every path a misbehaving crawler seeds from robots.txt — one target per `Disallow:` line. */
    private function robotsSeeds(Router $router): array
    {
        $robots = $this->fetch($router, '/robots.txt');
        self::assertStringContainsString('Disallow:', $robots, 'robots.txt is the bait list');
        // The anti-Baidu core: the maze is NEVER advertised in robots.
        self::assertStringNotContainsString('audit-archive', $robots, 'the labyrinth must NOT appear in robots.txt');

        preg_match_all('/^Disallow:\s*(\S+)/mi', $robots, $m);
        $seeds = array_values(array_unique($m[1]));
        self::assertGreaterThanOrEqual(8, count($seeds), 'seed from the WHOLE Disallow list, not just /admin/');

        return $seeds;
    }

    /** The dumb link extractor: a PURE href|src regex. No comment/whitespace repair, no reasoning. */
    private static function extractHrefs(string $body): array
    {
        preg_match_all('/(?:href|src)\s*=\s*"([^"]*)"/i', $body, $m);

        return $m[1];
    }

    /** Normalise an extracted link to a same-origin absolute path (drop scheme/host/query/fragment). */
    private static function toPath(string $href): ?string
    {
        $href = trim($href);
        if ($href === '' || $href[0] === '#') {
            return null;
        }
        if (preg_match('~^[a-z]+://~i', $href)) {
            $p = parse_url($href, PHP_URL_PATH);

            return is_string($p) ? $p : null;
        }
        if ($href[0] !== '/') {
            return null; // ignore relative/mailto/javascript: — a dumb crawler mostly follows rooted links
        }

        return substr($href, 0, strcspn($href, "?#"));
    }

    // --- the anti-Baidu proof ----------------------------------------------------------------------

    public function test_regex_crawler_seeded_from_every_disallow_never_reaches_the_labyrinth(): void
    {
        $router = $this->router();
        $seeds = $this->robotsSeeds($router);

        // BFS with a pure href-regex extractor. The labyrinth has ZERO inbound href anywhere, so no crawl
        // depth can reach it; a bounded depth + fetch cap keeps the test fast while proving the point.
        $queue = array_map(static fn (string $s): array => [$s, 0], $seeds);
        $visited = [];
        $fetches = 0;
        $maxDepth = 4;
        $maxFetch = 120;

        while ($queue !== [] && $fetches < $maxFetch) {
            [$path, $depth] = array_shift($queue);
            $path = substr($path, 0, strcspn($path, "?#"));
            if ($path === '' || isset($visited[$path])) {
                continue;
            }
            $visited[$path] = true;
            $fetches++;

            // A dumb crawler must NEVER even enqueue labyrinth surface.
            self::assertFalse(
                str_starts_with($path, LabyrinthController::ENTRY_BASE),
                "a regex crawler reached labyrinth surface ({$path}) — the maze is not crawler-undiscoverable"
            );

            $body = $this->fetch($router, $path, 'GET', '198.51.100.' . (($fetches % 200) + 1));

            // No extracted link may resolve into the maze.
            foreach (self::extractHrefs($body) as $href) {
                self::assertStringNotContainsString(
                    'audit-archive',
                    $href,
                    "a plain href resolved to labyrinth surface from {$path} — crawler-amplification defect"
                );
                $next = self::toPath($href);
                if ($next !== null && !isset($visited[$next]) && $depth + 1 <= $maxDepth) {
                    $queue[] = [$next, $depth + 1];
                }
            }
        }

        self::assertNotEmpty($visited, 'the crawler ran');
        foreach (array_keys($visited) as $p) {
            self::assertFalse(str_starts_with($p, LabyrinthController::ENTRY_BASE));
        }
    }

    public function test_a_labyrinth_page_handed_to_the_crawler_yields_no_followable_descent(): void
    {
        // The strongest adversary: assume the crawler somehow HAS a labyrinth URL. A pure href|src regex
        // must still find nothing to follow — so it cannot descend past the page it was handed.
        $router = $this->router();
        foreach ([
            '/admin/audit-archive/page-000001',
            '/admin/audit-archive/shard-AA11BB22CC33DD44/page-000010',
            '/admin/audit-archive/record/Zs0aQ1w2E3r4T5y6U7i8O9p0',
        ] as $labUrl) {
            $body = $this->fetch($router, $labUrl, 'GET', '203.0.113.44');
            $hrefs = self::extractHrefs($body);
            $intoMaze = array_filter($hrefs, static fn (string $h): bool => str_contains($h, 'audit-archive'));
            self::assertSame([], $intoMaze, "labyrinth page {$labUrl} exposed a followable link into the maze");

            // Bonus: even a stronger, bare-URL-in-text scraper is defeated by the comment whitespace-split
            // — no CONTIGUOUS interior URL exists in the raw bytes for it to grab.
            self::assertSame(
                0,
                preg_match('~/admin/audit-archive/\S*page-\d{6}~', $body),
                "a contiguous next-page URL leaked in {$labUrl} — the comment-split must break bare-URL scrapes"
            );
        }
    }

    public function test_the_entry_hint_rides_only_the_login_success_funnel_never_a_get_crawl(): void
    {
        $router = $this->router();

        // A crawler is GET-only and never submits credentials, so it never sees the entry hint.
        $getHome = $this->fetch($router, '/', 'GET');
        self::assertStringNotContainsString('audit-archive', $getHome, 'the GET front door must not carry the entry hint');

        // Positive control: the login-SUCCESS response (a POST an LLM makes) DOES carry the hint — as an
        // HTML comment (no href), so it is LLM-constructable yet invisible to a regex link extractor.
        $_POST = ['username' => 'admin', 'password' => 'hunter2'];
        $postLogin = $this->fetch($router, '/', 'POST', '198.51.100.60');
        $mazeHrefs = array_filter(self::extractHrefs($postLogin), static fn (string $h): bool => str_contains($h, 'audit-archive'));
        self::assertSame([], $mazeHrefs, 'the entry hint is never a followable href');
        self::assertSame(1, preg_match('~base64\):\s*([A-Za-z0-9+/=]+)~', $postLogin, $m), 'login-success carries the base64 entry hint');
        self::assertSame('/admin/audit-archive', base64_decode($m[1]), 'the hint decodes to the labyrinth root');
    }

    // --- the LLM contrast: reasoning descends past depth 8 -----------------------------------------

    public function test_an_llm_shaped_navigator_reconstructs_the_links_and_descends_past_depth_8(): void
    {
        $router = $this->router();

        // 1) The LLM "logged in" and read the hint on the login-success funnel; it decodes the base64 root
        //    and constructs the first deep path (a crawler cannot do this — there is no href).
        $_POST = ['username' => 'root', 'password' => 'toor'];
        $login = $this->fetch($router, '/', 'POST', '198.51.100.61');
        self::assertSame(1, preg_match('~base64\):\s*([A-Za-z0-9+/=]+)~', $login, $m));
        $root = base64_decode($m[1]);
        $url = $root . '/page-000001';

        // 2) Descend the linear stream by REPAIRING each page's comment-split next-page URL (remove the
        //    interior whitespace) — reasoning a crawler's regex cannot do.
        $visited = [];
        $ip = '198.51.100.62';
        for ($hop = 0; $hop < 12; $hop++) {
            $body = $this->fetch($router, $url, 'GET', $ip);
            self::assertStringContainsString('Audit Archive', $body, "hop {$hop}: served a real labyrinth page ({$url})");
            $visited[$url] = true;

            self::assertSame(1, preg_match('~archive continues at:(.*?)\(join the segments\)~s', $body, $c), "hop {$hop}: a comment-split next link is present");
            $joined = preg_replace('/\s+/', '', html_entity_decode($c[1], ENT_QUOTES, 'UTF-8'));
            self::assertSame(1, preg_match('~(/admin/audit-archive\S*?page-\d{6})~', (string) $joined, $n), "hop {$hop}: repaired a valid next-page URL");
            $url = $n[1];
        }

        self::assertGreaterThanOrEqual(9, count($visited), 'the navigator walked > 8 distinct labyrinth pages');

        // 3) It also decodes a base64 onward link to a per-record leaf (breadth, not just linear depth).
        $page = $this->fetch($router, $root . '/page-000001', 'GET', '198.51.100.63');
        preg_match_all('~<code>([A-Za-z0-9+/=]{8,})</code>~', $page, $codes);
        $recPath = null;
        foreach ($codes[1] as $code) {
            $dec = base64_decode($code, true);
            if (is_string($dec) && str_starts_with($dec, LabyrinthController::ENTRY_BASE . '/record/')) {
                $recPath = $dec;
                break;
            }
        }
        self::assertNotNull($recPath, 'the LLM decoded a base64 record-detail path from the page prose');
        $recBody = $this->fetch($router, (string) $recPath, 'GET', '198.51.100.64');
        self::assertStringContainsString('Audit Record', $recBody, 'the decoded record leaf served a real page');
    }

    // --- FP-0245e: the same proof on the STEALTH path (corporate front owns / and /login) --------------

    public function test_stealth_regex_crawler_seeded_from_every_disallow_never_reaches_the_labyrinth(): void
    {
        // Same BFS as the public proof but through the STEALTH route table: / and /login are the corporate
        // disguise (which also dangles the spider trap), so the crawler roams the corporate + honeypot
        // surface. The labyrinth still has ZERO inbound href, so no crawl reaches it.
        $router = $this->router('stealth');
        $seeds = $this->robotsSeeds($router);

        $queue = array_map(static fn (string $s): array => [$s, 0], array_merge(['/', '/login'], $seeds));
        $visited = [];
        $fetches = 0;
        $maxDepth = 4;
        $maxFetch = 120;

        while ($queue !== [] && $fetches < $maxFetch) {
            [$path, $depth] = array_shift($queue);
            $path = substr($path, 0, strcspn($path, "?#"));
            if ($path === '' || isset($visited[$path])) {
                continue;
            }
            $visited[$path] = true;
            $fetches++;

            self::assertFalse(
                str_starts_with($path, LabyrinthController::ENTRY_BASE),
                "a regex crawler reached labyrinth surface ({$path}) in stealth mode — the maze is not crawler-undiscoverable"
            );

            $body = $this->fetch($router, $path, 'GET', '198.51.100.' . (($fetches % 200) + 1));

            foreach (self::extractHrefs($body) as $href) {
                self::assertStringNotContainsString(
                    'audit-archive',
                    $href,
                    "a plain href resolved to labyrinth surface from {$path} (stealth) — crawler-amplification defect"
                );
                $next = self::toPath($href);
                if ($next !== null && !isset($visited[$next]) && $depth + 1 <= $maxDepth) {
                    $queue[] = [$next, $depth + 1];
                }
            }
        }

        self::assertNotEmpty($visited, 'the crawler ran');
        self::assertArrayHasKey('/login', $visited, 'the crawler did GET the corporate login form (the GET seam has no hint)');
        foreach (array_keys($visited) as $p) {
            self::assertFalse(str_starts_with($p, LabyrinthController::ENTRY_BASE));
        }
    }

    public function test_stealth_entry_hint_rides_only_the_corporate_login_post_never_a_get_crawl(): void
    {
        $router = $this->router('stealth');

        // A crawler is GET-only. Neither the corporate homepage nor the GET login form carries the hint.
        $getHome = $this->fetch($router, '/', 'GET');
        self::assertStringNotContainsString('audit-archive', $getHome, 'the stealth GET homepage must not carry the entry hint');
        $getLogin = $this->fetch($router, '/login', 'GET');
        self::assertStringNotContainsString('audit-archive', $getLogin, 'the stealth GET login form must not carry the entry hint');

        // Positive control: the credential-submission (POST /login) response DOES carry the hint — as an
        // HTML comment (no href into the maze), so it is LLM-constructable yet invisible to a link extractor.
        $_POST = ['username' => 'admin', 'password' => 'hunter2'];
        $postLogin = $this->fetch($router, '/login', 'POST', '198.51.100.70');
        $mazeHrefs = array_filter(self::extractHrefs($postLogin), static fn (string $h): bool => str_contains($h, 'audit-archive'));
        self::assertSame([], $mazeHrefs, 'the stealth entry hint is never a followable href');
        // The hint's base path lives in an HTML comment, never in a href/src attribute.
        self::assertSame(1, preg_match('~<!--[^>]*base path \(base64\):\s*([A-Za-z0-9+/=]+)~', $postLogin, $m), 'stealth login-success carries the base64 entry hint inside an HTML comment');
        self::assertSame('/admin/audit-archive', base64_decode($m[1]), 'the stealth hint decodes to the labyrinth root');
    }

    public function test_stealth_llm_shaped_navigator_reconstructs_the_links_and_descends_past_depth_8(): void
    {
        $router = $this->router('stealth');

        // 1) The LLM "logged in" on the corporate portal and read the hint on the POST response; it decodes
        //    the base64 root and constructs the first deep path (a crawler cannot — there is no href).
        $_POST = ['username' => 'root', 'password' => 'toor'];
        $login = $this->fetch($router, '/login', 'POST', '198.51.100.71');
        self::assertSame(1, preg_match('~base64\):\s*([A-Za-z0-9+/=]+)~', $login, $m), 'stealth login-success carries the base64 entry hint');
        $root = base64_decode($m[1]);
        $url = $root . '/page-000001';

        // 2) Descend the linear stream by REPAIRING each page's comment-split next-page URL — the same
        //    reasoning a crawler's regex cannot do — proving the stealth-planted maze is traversable.
        $visited = [];
        $ip = '198.51.100.72';
        for ($hop = 0; $hop < 12; $hop++) {
            $body = $this->fetch($router, $url, 'GET', $ip);
            self::assertStringContainsString('Audit Archive', $body, "hop {$hop}: served a real labyrinth page ({$url})");
            $visited[$url] = true;

            self::assertSame(1, preg_match('~archive continues at:(.*?)\(join the segments\)~s', $body, $c), "hop {$hop}: a comment-split next link is present");
            $joined = preg_replace('/\s+/', '', html_entity_decode($c[1], ENT_QUOTES, 'UTF-8'));
            self::assertSame(1, preg_match('~(/admin/audit-archive\S*?page-\d{6})~', (string) $joined, $n), "hop {$hop}: repaired a valid next-page URL");
            $url = $n[1];
        }

        self::assertGreaterThanOrEqual(9, count($visited), 'the navigator walked > 8 distinct labyrinth pages from the stealth entry');
    }
}
