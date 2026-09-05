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
use RuntimeException;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0245d — the tarpit-latency layer. Latency is the riskiest tarpit lever: a server-side sleep pins a
 * php-fpm worker for its whole duration, and this stack has only ~16 workers across 40+ ports, so an
 * uncapped sleep is a self-DoS. This suite proves the layer is safe:
 *
 *   1. THE self-DoS bound — the sleep happens ONLY while a TarpitBudget slot is held, so the number of
 *      workers ever sleeping at once can never exceed MAX_CONCURRENT (a shed request is served
 *      immediately, never delayed). Proven with a barrier-synced multi-process storm (precedent:
 *      {@see TarpitBudgetTest::test_global_cap_holds_across_concurrent_processes}).
 *   2. Hard clamp — any configured latency is clamped ≤ LATENCY_HARD_CAP_MS regardless of config.
 *   3. Off by default + master-switch-off ⇒ zero latency.
 *   4. Charged to the wall ledger ⇒ an IP over its hourly wall budget gets NO further latency (served
 *      immediately, a bounded 404).
 *   5. Fail-safe — a sleeper fault adds no latency and never becomes a 500 / slow failure.
 *   6. Client pacing — the service worker is a static asset (no slot, no server latency), registered via
 *      a no-href snippet (crawler-undiscoverable), byte-identity of the page preserved, inert when off.
 */
final class TarpitLatencyTest extends TestCase
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

    private function path(string $tag = 'lat'): string
    {
        $p = sys_get_temp_dir() . '/fp_tarpit_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    // --- applyLatency() unit invariants ------------------------------------------------------------

    /** Default 0 ⇒ no sleep at all (the regression guard the plan's verification names). */
    public function test_default_off_applies_no_latency(): void
    {
        $slept = [];
        $b = new TarpitBudget($this->path(), true, 4, 1, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15, null, 0, function (int $ms) use (&$slept): void {
            $slept[] = $ms;
        });
        self::assertSame(0, $b->applyLatency(), 'latency 0 ⇒ 0 ms slept');
        self::assertSame([], $slept, 'the sleeper is never invoked when latency is off');
    }

    /** Master switch off ⇒ latency inert even if a value is configured (defence in depth). */
    public function test_master_switch_off_applies_no_latency(): void
    {
        $slept = [];
        $b = new TarpitBudget($this->path(), false, 4, 1, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15, null, 500, function (int $ms) use (&$slept): void {
            $slept[] = $ms;
        });
        self::assertSame(0, $b->applyLatency());
        self::assertSame([], $slept);
    }

    /** A configured value is honoured as a SINGLE sleep inside the jitter band just below it, and the
     *  ms actually slept is returned. (Default random jitter here; the deterministic band test is below.) */
    public function test_configured_latency_sleeps_once_within_the_band_below_the_configured_ms(): void
    {
        $slept = [];
        $b = new TarpitBudget($this->path(), true, 4, 1, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15, null, 750, function (int $ms) use (&$slept): void {
            $slept[] = $ms;
        });
        $returned = $b->applyLatency();
        self::assertCount(1, $slept, 'a single bounded sleep, never a per-byte drip');
        self::assertSame($slept[0], $returned, 'the returned ms is what was really slept');
        self::assertGreaterThanOrEqual(750 - 75, $returned, 'band = min(200, ms/10) below the value');
        self::assertLessThanOrEqual(750, $returned, 'never above the configured ms');
    }

    /** Clamp: a wild config value is capped at LATENCY_HARD_CAP_MS by TarpitBudget itself (a second wall
     *  behind AppConfig's clamp) so an operator typo can never pin a worker near nginx's 15 s timeout.
     *  Full-band jitter injected so the sleep lands exactly ON the cap — the band tops out at the cap,
     *  never above it. */
    public function test_latency_is_hard_clamped_regardless_of_config(): void
    {
        $slept = [];
        $b = new TarpitBudget($this->path(), true, 4, 1, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15, null, 99999, function (int $ms) use (&$slept): void {
            $slept[] = $ms;
        }, static fn (int $ceil): int => $ceil);
        self::assertSame(TarpitBudget::LATENCY_HARD_CAP_MS, $b->applyLatency());
        self::assertSame([TarpitBudget::LATENCY_HARD_CAP_MS], $slept);
        self::assertLessThanOrEqual(2000, TarpitBudget::LATENCY_HARD_CAP_MS, 'the hard cap stays well under nginx fastcgi_read_timeout 15s and the 15s slot TTL');
    }

    /**
     * The jitter band (the SleepDecoy pattern): a band of min(MAX_JITTER_MS, ms/10) is reserved BELOW
     * the effective ms and the injected jitter added back, so the sleep varies in [ms - band, ms]
     * instead of being one constant (a uniform-timing tell) — and an out-of-band jitter source is
     * clamped so the total can never exceed the (capped) ms. The jitter is never consulted when
     * latency is off.
     */
    public function test_apply_latency_is_jittered_within_the_band_below_the_cap(): void
    {
        $slept = [];
        $asked = [];
        $next = 0;
        $jitter = function (int $ceil) use (&$asked, &$next): int {
            $asked[] = $ceil;

            return $next;
        };
        // latency 2000 (the cap): band = min(200, 200) = 200 ⇒ sleeps in [1800, 2000].
        $b = new TarpitBudget($this->path(), true, 4, 1, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15, null, 2000, function (int $ms) use (&$slept): void {
            $slept[] = $ms;
        }, $jitter);

        $next = 0;
        self::assertSame(1800, $b->applyLatency(), 'zero jitter ⇒ the bottom of the band');
        $next = 200;
        self::assertSame(2000, $b->applyLatency(), 'full jitter ⇒ exactly the cap, never above');
        $next = 57;
        self::assertSame(1857, $b->applyLatency(), 'in-band jitter is added to the base');
        $next = 9999;
        self::assertSame(2000, $b->applyLatency(), 'an out-of-band jitter source is clamped to the band ceiling');
        $next = -50;
        self::assertSame(1800, $b->applyLatency(), 'a negative jitter is clamped to zero');
        self::assertSame([1800, 2000, 1857, 2000, 1800], $slept, 'the sleeper saw the jittered values — no longer a constant');
        self::assertSame([200, 200, 200, 200, 200], $asked, 'the band ceiling handed to the jitter source is MAX_JITTER_MS at the cap');

        // A small latency gets a proportionally small band (ms/10), so it still varies but stays close.
        $asked = [];
        $small = new TarpitBudget($this->path(), true, 4, 1, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15, null, 80, static function (int $ms): void {
        }, $jitter);
        $next = 8;
        self::assertSame(80, $small->applyLatency());
        self::assertSame([8], $asked, 'band = 80/10');

        // Off (latency 0) and master-switch-off never consult the jitter source at all.
        $asked = [];
        $off = new TarpitBudget($this->path(), true, 4, 1, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15, null, 0, static function (int $ms): void {
        }, $jitter);
        $masterOff = new TarpitBudget($this->path(), false, 4, 1, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15, null, 500, static function (int $ms): void {
        }, $jitter);
        self::assertSame(0, $off->applyLatency());
        self::assertSame(0, $masterOff->applyLatency());
        self::assertSame([], $asked, 'no jitter draw when no latency is applied');
    }

    /** Fail-safe extends to the jitter source: a jitter fault adds NO latency and never throws. */
    public function test_fail_safe_a_jitter_fault_adds_no_latency_and_never_throws(): void
    {
        $slept = [];
        $b = new TarpitBudget($this->path(), true, 4, 1, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15, null, 500, function (int $ms) use (&$slept): void {
            $slept[] = $ms;
        }, static function (int $ceil): int {
            throw new RuntimeException('entropy source blew up');
        });
        self::assertSame(0, $b->applyLatency());
        self::assertSame([], $slept, 'a jitter fault degrades to no sleep at all, never a slow/500 failure');
    }

    /** Fail-safe: a sleeper fault adds NO latency and never propagates (a tarpit must never fail slow). */
    public function test_fail_safe_a_sleeper_fault_adds_no_latency_and_never_throws(): void
    {
        $b = new TarpitBudget($this->path(), true, 4, 1, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15, null, 500, function (int $ms): void {
            throw new RuntimeException('clock blew up mid-sleep');
        });
        self::assertSame(0, $b->applyLatency(), 'a sleeper fault degrades to zero added latency, no exception');
    }

    // --- THE self-DoS bound: at most MAX_CONCURRENT workers ever sleep at once ----------------------

    /**
     * THE test (plan §0245d verification). LATENCY on, MAX_CONCURRENT=4, a barrier-synced storm of 12
     * distinct-IP workers each running the EXACT controller sequence: guard() first, and applyLatency()
     * ONLY when a slot was won, then release. Every child stamps the wall-clock window it actually spent
     * sleeping; the parent proves that at NO instant do more than MAX_CONCURRENT sleep windows overlap.
     *
     * This fails if latency is ever applied outside a held slot (e.g. before guard, or on the shed path):
     * all 12 would then sleep concurrently and the overlap would be 12, not 4 — the self-DoS the whole
     * piece is gated to prevent.
     */
    public function test_at_most_max_concurrent_workers_ever_sleep_at_once(): void
    {
        if (!function_exists('proc_open')) {
            self::markTestSkipped('proc_open unavailable');
        }
        $maxConcurrent = 4;
        $latencyMs = 500;               // long enough that all winners' sleep windows overlap on release
        $path = $this->path('storm');
        // Warm the schema in the parent so 12 cold writers don't race the first CREATE (see the 0245a
        // concurrency test — a cold create racing writers can fail-closed to FULL and skew the counts).
        $warm = new TarpitBudget($path, true, $maxConcurrent, 1, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15, static fn (): int => 1_000_000, $latencyMs);
        self::assertSame(0, $warm->inflightCount());

        $autoload = dirname(__DIR__, 3) . '/vendor/autoload.php';
        $child = $path . '.child.php';
        $go = $path . '.go';
        $this->tmp[] = $child;
        $this->tmp[] = $go;
        // The child mirrors LabyrinthController/PolluterController EXACTLY: guard() first; only a non-null
        // slot reaches applyLatency() (a real usleep — the default sleeper); release() after. It records
        // the true [start,end] of its sleep window (or SKIP when it was shed and never slept).
        file_put_contents($child, "<?php\n"
            . 'require ' . var_export($autoload, true) . ";\n"
            . "use Funnypot\\App\\Storage\\TarpitBudget;\n"
            . '$b = new TarpitBudget(' . var_export($path, true)
            . ", true, {$maxConcurrent}, 1, " . PHP_INT_MAX . ', ' . PHP_INT_MAX . ', ' . PHP_INT_MAX . ', ' . PHP_INT_MAX
            . ", 15, static fn(): int => 1000000, {$latencyMs});\n"
            . '$go = ' . var_export($go, true) . ";\n"
            . 'touch(' . var_export($path, true) . " . '.ready.' . \$argv[1]);\n"
            . "while (!file_exists(\$go)) { usleep(200); }\n"
            . "\$slot = \$b->guard('10.0.0.' . \$argv[1]);\n"
            . "if (\$slot !== null) {\n"
            . "  \$start = microtime(true);\n"
            . "  \$b->applyLatency();\n"
            . "  \$end = microtime(true);\n"
            . "  \$b->release(\$slot);\n"
            . "  \$out = 'SLEEP ' . \$start . ' ' . \$end;\n"
            . "} else {\n"
            . "  \$out = 'SKIP';\n"
            . "}\n"
            . 'file_put_contents(' . var_export($path, true) . " . '.out.' . \$argv[1], \$out);\n");

        $n = 12;
        $procs = [];
        for ($i = 0; $i < $n; $i++) {
            $this->tmp[] = $path . '.ready.' . $i;
            $this->tmp[] = $path . '.out.' . $i;
            $p = proc_open([PHP_BINARY, $child, (string) $i], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            self::assertIsResource($p);
            $procs[] = [$p, $pipes];
        }
        // Barrier: wait for all children to be ready, then release them together so the winners race into
        // their sleep windows at the same instant (maximising any illegitimate overlap the bug would show).
        $deadline = microtime(true) + 20;
        $ready = 0;
        do {
            $ready = 0;
            for ($i = 0; $i < $n; $i++) {
                if (file_exists($path . '.ready.' . $i)) {
                    $ready++;
                }
            }
            if ($ready === $n) {
                break;
            }
            usleep(1000);
        } while (microtime(true) < $deadline);
        self::assertSame($n, $ready, 'all child processes must reach the barrier');
        touch($go);
        foreach ($procs as [$p, $pipes]) {
            foreach ($pipes as $pipe) {
                @stream_get_contents($pipe);
                @fclose($pipe);
            }
            proc_close($p);
        }

        // Collect the sleep windows and the count of workers that never slept.
        $windows = [];
        $slept = 0;
        $skipped = 0;
        for ($i = 0; $i < $n; $i++) {
            $out = @file_get_contents($path . '.out.' . $i);
            self::assertNotFalse($out, "child $i recorded no result");
            if (strncmp($out, 'SLEEP ', 6) === 0) {
                [, $start, $end] = explode(' ', $out);
                $windows[] = [(float) $start, (float) $end];
                $slept++;
            } else {
                $skipped++;
            }
        }

        // Exactly MAX_CONCURRENT workers won a slot and therefore slept; the rest were shed WITHOUT delay.
        self::assertSame($maxConcurrent, $slept, 'only slot-holders may sleep');
        self::assertSame($n - $maxConcurrent, $skipped, 'every shed request is served immediately, never delayed');

        // The core assertion: sweep the sleep windows and prove no instant is covered by more than
        // MAX_CONCURRENT of them. A sweep over interval endpoints (start = +1, end = -1) yields the peak.
        $events = [];
        foreach ($windows as [$s, $e]) {
            $events[] = [$s, 1];
            $events[] = [$e, -1];
        }
        usort($events, static function (array $a, array $b): int {
            if ($a[0] === $b[0]) {
                return $a[1] <=> $b[1]; // process ends before starts at an exact tie (conservative)
            }

            return $a[0] <=> $b[0];
        });
        $cur = 0;
        $peak = 0;
        foreach ($events as [, $delta]) {
            $cur += $delta;
            $peak = max($peak, $cur);
        }
        self::assertLessThanOrEqual(
            $maxConcurrent,
            $peak,
            "at most MAX_CONCURRENT ({$maxConcurrent}) workers may be in the latency sleep at once — a higher "
            . 'overlap means a request slept without holding a slot (the self-DoS the piece is gated to prevent)'
        );
    }

    // --- charged to the wall ledger ⇒ over-budget IP served immediately (no latency) ----------------

    /**
     * The slept ms is inside the wall window the controller charges, so repeated latency accrues in the
     * per-IP hourly wall ledger; once an IP is over its wall budget, guard() sheds it (a bounded 404)
     * WITHOUT any further latency. Uses a real (short) sleep so the charged wall_ms genuinely reflects it.
     */
    public function test_latency_is_charged_to_the_wall_ledger_then_the_ip_is_served_immediately(): void
    {
        $latencyMs = 80;
        $wallBudgetMs = 30; // one latency-bearing hit already blows this hourly wall budget
        $budgetPath = $this->path('ledger');
        // Real default sleeper: applyLatency() really sleeps, so the controller's hrtime wall window
        // (which spans applyLatency) charges ≈80 ms — the whole point being that latency IS wall time.
        $budget = new TarpitBudget($budgetPath, true, 4, 1, PHP_INT_MAX, $wallBudgetMs, PHP_INT_MAX, PHP_INT_MAX, 15, null, $latencyMs);
        [$lab, $cap] = $this->labyrinth($budget);

        $ip = '203.0.113.55';
        $t0 = microtime(true);
        $lab->handle(new RequestContext('GET', '/admin/audit-archive/page-000001'), $ip);
        $firstMs = (microtime(true) - $t0) * 1000;
        self::assertSame(200, $cap->status, 'first hit is served');
        self::assertGreaterThanOrEqual(70, $firstMs, 'the first hit actually incurred the server latency');

        // Second hit for the SAME IP: it is now over its hourly wall budget (the 80 ms was charged), so
        // guard() sheds it to a bounded 404 — and crucially with NO added latency (served immediately).
        $t1 = microtime(true);
        $lab->handle(new RequestContext('GET', '/admin/audit-archive/page-000002'), $ip);
        $secondMs = (microtime(true) - $t1) * 1000;
        self::assertSame(404, $cap->status, 'an IP over its hourly wall budget is shed to a bounded 404');
        self::assertLessThan(40, $secondMs, 'the shed hit is served immediately — no latency for an over-budget IP');
    }

    /** Fail-safe at the controller: a sleeper fault still yields a normal 200 page, never a 500. */
    public function test_controller_stays_200_when_the_sleeper_faults(): void
    {
        $budget = new TarpitBudget($this->path('fault'), true, 4, 1, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15, null, 500, function (int $ms): void {
            throw new RuntimeException('sleep fault');
        });
        [$lab, $cap] = $this->labyrinth($budget);
        $lab->handle(new RequestContext('GET', '/admin/audit-archive/page-000001'), '198.51.100.9');
        self::assertSame(200, $cap->status, 'a sleeper fault never becomes a 500 or an empty response');
        self::assertNotSame('', $cap->body);
    }

    // --- client-side pacing (service worker) --------------------------------------------------------

    /** With pacing armed, the SW is a static asset: served without consuming a slot and without latency. */
    public function test_service_worker_is_served_static_without_a_slot_or_latency(): void
    {
        $slept = [];
        // A single-slot budget with a recording sleeper: if serving the SW took a slot or slept, we'd see it.
        $budget = new TarpitBudget($this->path('sw'), true, 1, 1, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15, null, 500, function (int $ms) use (&$slept): void {
            $slept[] = $ms;
        });
        [$lab, $cap] = $this->labyrinth($budget, 500, "// injected sw fixture\n");

        $lab->handle(new RequestContext('GET', LabyrinthController::PACING_SW_PATH . '?' . LabyrinthController::PACING_PARAM . '=' . LabyrinthController::encodePacingInterval(500)), '198.51.100.10');
        self::assertSame(200, $cap->status);
        self::assertStringContainsString('javascript', $cap->headers['Content-Type'] ?? '');
        self::assertSame('/admin/', $cap->headers['Service-Worker-Allowed'] ?? '');
        self::assertSame("// injected sw fixture\n", $cap->body, 'the SW body is the injected pacing script verbatim');
        self::assertSame([], $slept, 'serving the SW must not incur server latency');
        self::assertSame(0, $budget->inflightCount(), 'serving the SW must not hold a TarpitBudget slot');
    }

    /** Pacing armed ⇒ pages carry the SW registration, but it is NOT a crawler-followable link, and the
     *  page byte-size stays identical across depth (the registration is a fixed constant snippet). */
    public function test_registration_is_injected_but_not_followable_and_preserves_byte_identity(): void
    {
        $budget = new TarpitBudget($this->path('reg'), true, 4, 1, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15, null, 500, function (int $ms): void {
            // no-op sleeper so timing stays cheap
        });
        [$lab, $cap] = $this->labyrinth($budget, 500, "// sw\n");

        $lab->handle(new RequestContext('GET', '/admin/audit-archive/page-000001'), '198.51.100.11');
        $p1 = $cap->body;
        self::assertStringContainsString('serviceWorker', $p1, 'the registration snippet is present when pacing is on');
        self::assertStringContainsString(LabyrinthController::PACING_SW_PATH, $p1);
        self::assertFalse(LlmOnlyLink::containsFollowableLink($p1), 'the SW registration exposes NO href/src — invisible to a regex crawler');
        self::assertSame(0, preg_match('~(?:href|src)\s*=\s*"[^"]*audit-archive~i', $p1), 'no href/src resolves to labyrinth surface');

        $lab->handle(new RequestContext('GET', '/admin/audit-archive/page-000800'), '198.51.100.11');
        self::assertSame(strlen($p1), strlen($cap->body), 'the fixed registration snippet keeps every page byte-identical across depth');
    }

    /** Pacing OFF (default): no registration snippet, and the SW path renders a normal budgeted page. */
    public function test_pacing_off_is_fully_inert(): void
    {
        $budget = new TarpitBudget($this->path('off'), true, 4, 1, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15);
        [$lab, $cap] = $this->labyrinth($budget, 0, ''); // latency 0, no pacing script

        $lab->handle(new RequestContext('GET', '/admin/audit-archive/page-000001'), '198.51.100.12');
        self::assertStringNotContainsString('serviceWorker', $cap->body, 'no registration snippet when pacing is off');

        // The SW path is not intercepted: it falls through to a normal (budget-gated) maze page.
        $lab->handle(new RequestContext('GET', LabyrinthController::PACING_SW_PATH), '198.51.100.13');
        self::assertSame(200, $cap->status);
        self::assertStringContainsString('Audit Archive', $cap->body, 'the SW path renders a normal maze page when pacing is off');
    }

    // --- helper -------------------------------------------------------------------------------------

    /**
     * A labyrinth wired to the given budget + a capturing emitter.
     *
     * @return array{0:LabyrinthController,1:object}
     */
    private function labyrinth(TarpitBudget $budget, int $latencyMs = 0, string $pacingScript = ''): array
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
        $store = new SqliteHitStore($this->path('hits'));
        $geo = new Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid());
        $lab = new LabyrinthController($store, $geo, $budget, 4242, 8, null, $emit, null, $latencyMs, $pacingScript);

        return [$lab, $cap];
    }
}
