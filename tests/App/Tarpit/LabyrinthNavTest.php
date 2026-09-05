<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit;

use Funnypot\App\Http\LabyrinthController;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\Tarpit\LlmOnlyLink;
use Funnypot\Core\RequestContext;
use Geo;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0245b — the LLM-only labyrinth handler's own invariants (spec §8, plan-review SHOULD-FIX 4 & 6):
 * the FIXED rows-per-page bound (a deep page does no more work than page 1), deterministic/coherent
 * content, off-by-default, budget-gated shed-to-404, fail-safe on a storage fault, and that NO page ever
 * exposes a plain crawler-followable link into the maze. The anti-Baidu crawler-vs-LLM contrast lives in
 * {@see MisbehavingCrawlerTest}.
 */
final class LabyrinthNavTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
    }

    private function path(string $tag): string
    {
        $p = sys_get_temp_dir() . '/fp_lab_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /**
     * A labyrinth wired to a real (enabled) budget + hit store, with a capturing emitter so a test sees
     * the exact status/headers/body without emitting real HTTP.
     *
     * @param array<string,int> $over budget overrides
     * @param int $latencyMs server latency knob (a no-op sleeper is wired, so it only arms client pacing)
     * @param string $pacingScript the service-worker bytes to serve (empty = pacing off)
     * @return array{0:LabyrinthController,1:array<string,mixed>&object,2:SqliteHitStore}
     */
    private function make(array $over = [], bool $enabled = true, ?string $budgetPath = null, int $personaSeed = 4242, int $latencyMs = 0, string $pacingScript = ''): array
    {
        $cap = new class {
            public int $status = 0;
            /** @var array<string,string> */
            public array $headers = [];
            public string $body = '';
        };
        $emit = static function (int $s, array $h, string $b) use ($cap): void {
            $cap->status = $s;
            $cap->headers = $h;
            $cap->body = $b;
        };
        $budget = new TarpitBudget(
            $budgetPath ?? $this->path('budget'),
            $enabled,
            $over['maxConcurrent'] ?? 4,
            $over['maxPerIp'] ?? 1,
            $over['bytesPerIpHr'] ?? 64 * 1024 * 1024,
            $over['wallPerIpHrMs'] ?? 120 * 1000,
            $over['globalBytesHr'] ?? 1024 * 1024 * 1024,
            $over['pagesPerIpHr'] ?? 2000,
            15,
            null,
            $latencyMs,
            static function (int $ms): void {
                // no-op sleeper: these tests are about bytes, never about real waiting
            },
        );
        $store = new SqliteHitStore($this->path('hits'));
        $geo = new Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid());
        $lab = new LabyrinthController($store, $geo, $budget, $personaSeed, 8, null, $emit, null, $latencyMs, $pacingScript);

        return [$lab, $cap, $store];
    }

    /** The first app fingerprint-denylist hit in $t (leak-IN literals/patterns + leak-OUT own vocabulary), or null when clean. */
    private static function fingerprintHit(string $t): ?string
    {
        static $d = null;
        $d ??= require dirname(__DIR__, 3) . '/resources/app-fingerprint-denylist.php';
        $literals = array_values((array) ($d['literals'] ?? []));
        $patterns = array_values((array) ($d['patterns'] ?? []));
        $ownVocabulary = array_values((array) ($d['own_vocabulary'] ?? []));
        $ownVocabularyPattern = '/(?<![a-zA-Z0-9])(' . implode('|', $ownVocabulary) . ')(?![a-zA-Z0-9])/i';
        foreach ($literals as $n) {
            if ($n !== '' && stripos($t, (string) $n) !== false) {
                return 'lit:' . $n;
            }
        }
        foreach ($patterns as $p) {
            if (@preg_match('~' . $p . '~i', $t) === 1) {
                return 'pat:' . $p;
            }
        }
        if (preg_match($ownVocabularyPattern, $t, $m) === 1) {
            return 'own_vocabulary:' . strtolower($m[0]);
        }

        return null;
    }

    private function get(LabyrinthController $lab, string $path, string $ip = '203.0.113.9'): void
    {
        $lab->handle(new RequestContext('GET', $path), $ip);
    }

    // --- SHOULD-FIX 6: the FIXED rows-per-page bound -----------------------------------------------

    public function test_deep_page_renders_the_same_byte_size_as_page_one(): void
    {
        [$lab, $cap] = $this->make();

        $this->get($lab, '/admin/audit-archive/page-000001', '198.51.100.1');
        self::assertSame(200, $cap->status);
        $len1 = strlen($cap->body);

        $this->get($lab, '/admin/audit-archive/page-000800', '198.51.100.2');
        self::assertSame(200, $cap->status);
        $len800 = strlen($cap->body);

        self::assertSame(
            $len1,
            $len800,
            'a deep page (page-000800) must render the same byte size as page-000001 — the per-page work '
            . 'is bounded; the infinite-ness lives in the NUMBER of pages, never the size of one page'
        );
    }

    public function test_deep_page_within_a_shard_stream_also_holds_the_bound(): void
    {
        [$lab, $cap] = $this->make();
        $shard = 'shard-AB12CD34EF56GH78';

        $this->get($lab, '/admin/audit-archive/' . $shard . '/page-000001', '198.51.100.3');
        $a = strlen($cap->body);
        $this->get($lab, '/admin/audit-archive/' . $shard . '/page-004096', '198.51.100.4');
        $b = strlen($cap->body);

        self::assertSame($a, $b, 'within one shard, a deep page is byte-identical in size to page 1');
    }

    // --- determinism / coherence (spec §8.1, plan test #4) -----------------------------------------

    public function test_same_path_is_byte_identical_on_revisit(): void
    {
        [$lab, $cap] = $this->make();
        $this->get($lab, '/admin/audit-archive/page-000042', '198.51.100.5');
        $first = $cap->body;
        $this->get($lab, '/admin/audit-archive/page-000042', '198.51.100.6');
        self::assertSame($first, $cap->body, 'same labyrinth path ⇒ byte-identical page (survives dedup)');
    }

    public function test_deeper_page_is_fresh_content_but_names_the_same_persona(): void
    {
        [$lab, $cap] = $this->make();
        $this->get($lab, '/admin/audit-archive/page-000001', '198.51.100.7');
        $p1 = $cap->body;
        $this->get($lab, '/admin/audit-archive/page-000900', '198.51.100.8');
        $p900 = $cap->body;

        self::assertNotSame($p1, $p900, 'a deeper page ⇒ fresh rows (novelty on advance)');
        // The per-deploy persona identity (title chrome) is constant across pages (cross-kind coherence).
        self::assertStringContainsString('Audit Archive', $p1);
        self::assertStringContainsString('Audit Archive', $p900);
        preg_match('~<h1>(.*?) &middot; Audit Archive</h1>~', $p1, $m1);
        preg_match('~<h1>(.*?) &middot; Audit Archive</h1>~', $p900, $m9);
        self::assertNotEmpty($m1[1] ?? '');
        self::assertSame($m1[1], $m9[1] ?? '', 'the same persona/company names the archive on every page');
    }

    // --- off-by-default / budget-gated / fail-safe -------------------------------------------------

    public function test_off_by_default_the_route_is_inert_and_404s(): void
    {
        [$lab, $cap] = $this->make(enabled: false);
        $this->get($lab, '/admin/audit-archive/page-000001', '198.51.100.9');

        self::assertSame(404, $cap->status, 'master switch off ⇒ guard() null ⇒ bounded 404, no labyrinth');
        self::assertNoAuditArchive($cap->body);
    }

    public function test_over_the_hourly_page_budget_sheds_to_a_bounded_404(): void
    {
        // pagesPerIpHr = 1: the first hit serves, the second is over budget ⇒ shed.
        [$lab, $cap] = $this->make(['pagesPerIpHr' => 1]);

        $this->get($lab, '/admin/audit-archive/page-000001', '192.0.2.50');
        self::assertSame(200, $cap->status, 'first hit within budget');

        $this->get($lab, '/admin/audit-archive/page-000002', '192.0.2.50');
        self::assertSame(404, $cap->status, 'second hit is over the per-IP hourly page cap ⇒ bounded 404');
        self::assertStringContainsString('404 Not Found', $cap->body);
    }

    public function test_global_concurrency_full_sheds_to_a_bounded_404(): void
    {
        // maxConcurrent = 1, and pre-occupy the single slot with a DIFFERENT IP that never releases, so
        // guard() sees FULL for our request ⇒ shed. (release() runs in finally on the happy path; here we
        // hold a slot out-of-band to model a concurrent in-flight tarpit request.)
        $bpath = $this->path('budget');
        [$lab, $cap] = $this->make(['maxConcurrent' => 1], budgetPath: $bpath);
        $occupier = new TarpitBudget($bpath, true, 1, 4, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15);
        $held = $occupier->acquire('10.0.0.1');
        self::assertSame(TarpitBudget::WON, $held['status']);

        $this->get($lab, '/admin/audit-archive/page-000001', '10.0.0.2');
        self::assertSame(404, $cap->status, 'no free slot ⇒ bounded 404 (never a slow page)');

        $occupier->release($held['slot']);
    }

    public function test_fail_safe_on_a_storage_fault_never_500s(): void
    {
        // Point the budget at an unopenable path (a file used as a directory component) so the db() open
        // throws; guard() must fail CLOSED (null) ⇒ bounded 404, never a 500 and never a labyrinth page.
        $blocker = sys_get_temp_dir() . '/fp_lab_block_' . bin2hex(random_bytes(6));
        file_put_contents($blocker, 'x');
        $this->tmp[] = $blocker;
        [$lab, $cap] = $this->make(budgetPath: $blocker . '/nope/x.sqlite');

        $this->get($lab, '/admin/audit-archive/page-000001', '192.0.2.77');
        self::assertSame(404, $cap->status, 'a budget-store fault ⇒ no labyrinth, a bounded 404 (fail-closed)');
    }

    // --- no plain crawler-followable link anywhere (spec §4 / invariant 4) -------------------------

    public function test_no_page_exposes_a_followable_link_into_the_maze(): void
    {
        [$lab, $cap] = $this->make();
        foreach ([
            '/admin/audit-archive',
            '/admin/audit-archive/page-000001',
            '/admin/audit-archive/page-013337',
            '/admin/audit-archive/shard-ZZ99YY88XX77WW66/page-000007',
            '/admin/audit-archive/record/abcDEF012ghiJKL345mnoPQR',
        ] as $p) {
            $this->get($lab, $p, '198.51.100.20');
            self::assertSame(200, $cap->status, "served: {$p}");
            self::assertFalse(
                LlmOnlyLink::containsFollowableLink($cap->body),
                "labyrinth page {$p} must expose NO plain href/src — a regex crawler must find nothing to follow"
            );
            self::assertSame(
                0,
                preg_match('~(?:href|src)\s*=\s*"[^"]*audit-archive~i', $cap->body),
                "no href/src may resolve to labyrinth surface on {$p}"
            );
        }
    }

    // --- no fingerprint self-tell in the rendered maze (FP-0245c review fold-in) -------------------

    /**
     * The `+/=`→`-_0` token remap can rarely (~1/2000 pages) place a `-`/`_` boundary around a 6-digit
     * run, so a rendered token could read as a bare CRS-rule id — a self-tell now the labyrinth is live.
     * The token path is routed through the SAME systemic clean-gate as the polluters; assert that across
     * a sweep of seeds AND deep pages/shards/records NO rendered page trips the app fingerprint denylist.
     * (Fable found seed 5 / page 29 before the fix; this sweep covers it and a broad range.)
     *
     * FP-0112 review #3: this is a real unauthenticated GET surface (LabyrinthController), so it must
     * be scanned for own_vocabulary (leak-OUT — this project's own name) too, not just literals/patterns
     * (leak-IN — someone else's vocabulary). Both directions run on every rendered page below.
     */
    public function test_no_rendered_page_trips_the_fingerprint_denylist_across_seeds_and_depth(): void
    {
        $scan = static fn (string $t): ?string => self::fingerprintHit($t);

        $seeds = [5, 4242, 99991, 1, 2, 3, 7, 13, 42];
        $ipN = 0;
        foreach ($seeds as $seed) {
            [$lab, $cap] = $this->make(personaSeed: $seed);
            // A spread of page indices (incl. the fable offender 29), a shard stream, and a record leaf.
            for ($page = 1; $page <= 40; $page++) {
                $this->get($lab, '/admin/audit-archive/page-' . str_pad((string) $page, 6, '0', STR_PAD_LEFT), '203.0.113.' . ($ipN++ % 250 + 1));
                $hit = $scan($cap->body);
                self::assertNull($hit, "fingerprint self-tell on seed {$seed} page {$page}: {$hit}");
            }
            $this->get($lab, '/admin/audit-archive/shard-ABCD1234EFGH5678/page-000029', '198.51.100.1');
            self::assertNull($scan($cap->body), "fingerprint self-tell on seed {$seed} shard page");
            $this->get($lab, '/admin/audit-archive/record/abcDEF012ghiJKL345mnoPQR', '198.51.100.2');
            self::assertNull($scan($cap->body), "fingerprint self-tell on seed {$seed} record leaf");
        }
    }

    // --- the served pacing worker + its registration reveal nothing about the trap -----------------

    /** The real on-disk worker source, exactly the bytes the composition root hands the controller. */
    private static function pacingWorkerSource(): string
    {
        $path = dirname(__DIR__, 3) . '/src/App/Tarpit/aa-sw.js';
        self::assertFileExists($path, 'the pacing worker must live at the path demo/index.php reads');

        return (string) file_get_contents($path);
    }

    /**
     * The worker is served VERBATIM to an unauthenticated GET, so its bytes are a de-cloak surface: no
     * strategy word, no knob name, no ticket id, no comment of any kind, and nothing on the fingerprint
     * denylist (either direction) may appear in the body or the headers. The one functional literal it
     * must keep is the intercept prefix `/admin/export/` — a real path set, not a tell — which is why
     * the bare word "export" is deliberately NOT on the banned list (the identifier EXPORT_PREFIX is).
     */
    public function test_served_pacing_worker_reveals_no_tarpit_or_strategy_strings(): void
    {
        $src = self::pacingWorkerSource();
        [$lab, $cap] = $this->make(latencyMs: 750, pacingScript: $src);
        $this->get($lab, LabyrinthController::PACING_SW_PATH, '198.51.100.30');

        self::assertSame(200, $cap->status);
        self::assertStringContainsString('javascript', $cap->headers['Content-Type'] ?? '');
        self::assertSame($src, $cap->body, 'served byte-for-byte from the source file');
        // Sanity: still the real worker (a rewrite cannot make this pass vacuously).
        self::assertStringContainsString("addEventListener('fetch'", $cap->body);
        self::assertStringContainsString('/admin/export/', $cap->body, 'the functional intercept prefix stays');
        self::assertStringNotContainsString('tarpit', strtolower(LabyrinthController::PACING_SW_PATH), 'the served path names no strategy');

        foreach (['tarpit', 'polluter', 'pacing', 'paced', 'byte-cap', 'FUNNYPOT_TARPIT', 'FP-0245', 'DownloadRouter',
            'client-side theater', 'EXPORT_PREFIX', 'attacker', 'honeypot', 'slow-drip', 'php-fpm', ] as $banned) {
            self::assertStringNotContainsStringIgnoringCase($banned, $cap->body, "served worker must not contain '{$banned}'");
        }
        self::assertSame(0, preg_match('~(^|[^:])//|/\*~m', $cap->body), 'the served worker carries no comments at all');
        self::assertNull(self::fingerprintHit($cap->body), 'the served worker trips no fingerprint denylist entry');
        foreach ($cap->headers as $name => $value) {
            self::assertNull(self::fingerprintHit($name . ': ' . $value), "header {$name} is fingerprint-clean");
        }
    }

    /**
     * The registration snippet in page source is the other half of the de-cloak: it must name the
     * neutral worker path and carry the interval as an opaque token — never `?i=<ms>` or the literal
     * configured latency — while still round-tripping to the configured ms through the exact decode
     * the worker implements (base36, XOR the shared mask), so the paced experience is unchanged.
     */
    public function test_pacing_registration_snippet_leaks_no_raw_latency_ms(): void
    {
        $src = self::pacingWorkerSource();
        [$lab, $cap] = $this->make(latencyMs: 1234, pacingScript: $src);
        $this->get($lab, '/admin/audit-archive/page-000001', '198.51.100.31');
        self::assertSame(200, $cap->status);

        self::assertSame(1, preg_match('~serviceWorker\.register\("([^"]+)"~', $cap->body, $m), 'the registration snippet is present');
        $swUrl = $m[1];
        self::assertStringEndsWith(
            '/aa-sw.js?' . LabyrinthController::PACING_PARAM . '=' . LabyrinthController::encodePacingInterval(1234),
            $swUrl
        );
        self::assertStringNotContainsString('tarpit', strtolower($swUrl));
        self::assertStringNotContainsString('?i=', $cap->body, 'the old readable interval key is gone');
        self::assertStringNotContainsString('1234', $swUrl, 'the raw latency-ms never appears in the registration URL');

        // Round-trip through the worker's own decode (parseInt(v, 36) ^ mask): pacing itself is unchanged.
        parse_str((string) parse_url($swUrl, PHP_URL_QUERY), $q);
        $token = (string) ($q[LabyrinthController::PACING_PARAM] ?? '');
        self::assertMatchesRegularExpression('/^[0-9a-z]{1,8}$/', $token, 'an opaque base36 token, not a number');
        self::assertSame(1234, ((int) base_convert($token, 36, 10)) ^ LabyrinthController::PACING_MASK);
        // The cap clamps before encoding, exactly as the old raw value was clamped.
        self::assertSame(
            LabyrinthController::encodePacingInterval(TarpitBudget::LATENCY_HARD_CAP_MS),
            LabyrinthController::encodePacingInterval(99_999)
        );

        // Both ends stay in lock-step: the worker reads the same key and XORs the same mask.
        self::assertStringContainsString("searchParams.get('" . LabyrinthController::PACING_PARAM . "')", $src);
        self::assertStringContainsString('parseInt(q,36)', $src);
        self::assertStringContainsString('^' . LabyrinthController::PACING_MASK, $src);

        // And the whole page — registration snippet included — is fingerprint-clean.
        self::assertNull(self::fingerprintHit($cap->body));
    }

    public function test_entry_hint_carries_no_href_and_decodes_to_the_root(): void
    {
        $hint = LabyrinthController::entryHint();
        self::assertFalse(LlmOnlyLink::containsFollowableLink($hint), 'the entry hint is a comment, never a href');
        self::assertStringContainsString('<!--', $hint, 'the entry hint is an HTML comment (crawler-invisible surface)');
        self::assertSame(1, preg_match('~base64\):\s*([A-Za-z0-9+/=]+)~', $hint, $m), 'hint carries a base64 blob');
        self::assertSame('/admin/audit-archive', base64_decode($m[1]), 'the base64 decodes to the labyrinth root');
    }

    /** A tiny custom assertion helper — the disabled route must never render a labyrinth page. */
    private static function assertNoAuditArchive(string $body): void
    {
        self::assertStringNotContainsString('Audit Archive', $body, 'the disabled route must not render the maze');
    }
}
