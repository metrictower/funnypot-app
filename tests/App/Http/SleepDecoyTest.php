<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\SleepDecoy;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * FP-0228 — the honoured-SLEEP decoy policy. Deterministic: the sleeper and the clock are INJECTED, so
 * nothing ever really sleeps and no wall time is read. The suite proves the operator's design:
 *
 *   (a) small-probe CORRELATION — requested {0,1,2}s ⇒ measured delay tracks it (Pearson corr high,
 *       slope ≈ 1), so lonkero's analyze_calibrated_sleep confirms; large n clamps to the per-req cap.
 *   (b) BUDGET EXHAUSTION — after the per-IP hourly wall budget is spent (honoured sleep rides wall_ms),
 *       the next probe is served with ZERO delay.
 *   (c) REPLENISH — the budget recovers when the hour bucket rolls over (and does NOT reset early).
 *   (e) FAIL-SAFE — a sleeper fault / a broken budget store ⇒ no delay, no throw, slot still released.
 *   + off-by-default, the sqli/rce class gate (benign never delayed), and the slot-held-while-sleeping
 *     invariant (the self-DoS bound is proven end-to-end in {@see SleepDecoyConcurrencyTest}).
 */
final class SleepDecoyTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];
    /** @var array<string,string|false> */
    private array $savedEnv = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        foreach (['FUNNYPOT_SLEEP_DECOY', 'FUNNYPOT_SLEEP_PER_REQ_CAP_MS'] as $k) {
            $this->savedEnv[$k] = getenv($k);
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->savedEnv as $k => $v) {
            if ($v === false) {
                putenv($k);
            } else {
                putenv("$k=$v");
            }
        }
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
    }

    private function path(string $tag = 'decoy'): string
    {
        $p = sys_get_temp_dir() . '/fp_sleepdecoy_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /** @param callable(int):void $sleeper */
    private function budget(callable $sleeper, ?callable $clock = null, int $wallMsBudget = PHP_INT_MAX, int $maxConcurrent = 8, int $maxPerIp = 4, ?string $path = null): TarpitBudget
    {
        return new TarpitBudget(
            $path ?? $this->path(),
            true,
            $maxConcurrent,
            $maxPerIp,
            PHP_INT_MAX,
            $wallMsBudget,
            PHP_INT_MAX,
            PHP_INT_MAX,
            15,
            $clock,
            0,      // latencyMs unused — SleepDecoy drives applyLatencyMs() with the per-request value
            $sleeper
        );
    }

    private function config(bool $on = true, int $cap = 2000): AppConfig
    {
        putenv('FUNNYPOT_SLEEP_DECOY=' . ($on ? '1' : '0'));
        putenv('FUNNYPOT_SLEEP_PER_REQ_CAP_MS=' . $cap);

        return AppConfig::fromEnv(sys_get_temp_dir() . '/fp-sleepdecoy-cfg');
    }

    /** A SQLi SLEEP(n) probe (classifies sqli, carries an n-second structure). */
    private static function sqliSleep(int $n): RequestContext
    {
        return new RequestContext('GET', '/products.php', 'id=1 AND SLEEP(' . $n . ')', [], null);
    }

    // --- (a) small-probe correlation ----------------------------------------------------------------

    public function test_small_probe_delay_correlates_with_requested_seconds(): void
    {
        $sleeps = [];
        $sleeper = static function (int $ms) use (&$sleeps): void {
            $sleeps[] = $ms;
        };
        $budget = $this->budget($sleeper, static fn (): int => 1_000_000);
        // A small, deterministic jitter (≤200 ms) so the test is realistic but reproducible — it cancels
        // in the slope, exactly as network jitter does in lonkero's regression.
        $jit = [10, 120, 60];
        $ji = 0;
        $jitter = static function (int $cap) use (&$jit, &$ji): int {
            return $cap > 0 ? $jit[$ji++ % count($jit)] : 0;
        };
        $decoy = new SleepDecoy($budget, $this->config(true, 2000), new AttackClassifier(), $jitter);

        $ip = '198.51.100.7';
        $measured = [];
        foreach ([0, 1, 2] as $n) {
            $samples = [];
            for ($k = 0; $k < 3; $k++) { // median of 3, as lonkero samples each point
                $before = count($sleeps);
                $decoy->maybeDelay(self::sqliSleep($n), $ip);
                $samples[] = count($sleeps) > $before ? (int) end($sleeps) : 0;
            }
            sort($samples);
            $measured[] = $samples[1] / 1000.0; // median, in seconds
        }

        $requested = [0.0, 1.0, 2.0];
        [$corr, $slope] = self::pearsonAndSlope($requested, $measured);

        self::assertGreaterThan(0.95, $corr, 'measured delay must correlate with requested seconds (>0.95)');
        self::assertGreaterThanOrEqual(0.7, $slope, 'slope in lonkero confirm band (0.7,1.5)');
        self::assertLessThanOrEqual(1.5, $slope, 'slope in lonkero confirm band (0.7,1.5)');
        self::assertTrue($measured[0] <= $measured[1] && $measured[1] <= $measured[2], 'monotonic non-decreasing');

        // Large n clamps to the per-request cap (2000 ms), regardless of jitter — the accepted residual
        // tell (slope degrades for large n).
        $before = count($sleeps);
        $decoy->maybeDelay(self::sqliSleep(10), $ip);
        self::assertGreaterThan($before, count($sleeps), 'a large-n probe is still honoured');
        self::assertSame(2000, (int) end($sleeps), 'a 10 s SLEEP is clamped to the 2000 ms per-request cap');
    }

    // --- (b) budget exhaustion ----------------------------------------------------------------------

    public function test_budget_exhausts_then_serves_immediately_with_zero_delay(): void
    {
        $sleeps = [];
        $sleeper = static function (int $ms) use (&$sleeps): void {
            $sleeps[] = $ms;
        };
        // 60 s per-IP hourly wall budget, frozen bucket, 2 s honoured per probe, no jitter (exactness).
        $budget = $this->budget($sleeper, static fn (): int => 1_000_000, 60_000);
        $decoy = new SleepDecoy($budget, $this->config(true, 2000), new AttackClassifier(), static fn (int $c): int => 0);

        $ip = '203.0.113.9';
        for ($i = 0; $i < 30; $i++) { // 30 × 2 s = 60 s ⇒ budget exactly spent
            $decoy->maybeDelay(self::sqliSleep(2), $ip);
        }
        self::assertCount(30, $sleeps, 'all 30 probes within budget are honoured');
        self::assertSame(60_000, array_sum($sleeps), '30 × 2000 ms of honoured sleep charged to the wall ledger');

        // The 31st probe: the IP is now over its hourly wall budget ⇒ served immediately, ZERO delay.
        $decoy->maybeDelay(self::sqliSleep(2), $ip);
        self::assertCount(30, $sleeps, 'the over-budget probe is served immediately — no further sleep');
        self::assertSame(0, $budget->inflightForIp($ip), 'no slot is left held after an over-budget probe');
    }

    // --- (c) replenish / expiry ---------------------------------------------------------------------

    public function test_budget_replenishes_when_the_hour_bucket_rolls_over(): void
    {
        $sleeps = [];
        $now = 3_600; // hour bucket 1
        $budget = $this->budget(
            static function (int $ms) use (&$sleeps): void {
                $sleeps[] = $ms;
            },
            static function () use (&$now): int {
                return $now;
            },
            60_000
        );
        $decoy = new SleepDecoy($budget, $this->config(true, 2000), new AttackClassifier(), static fn (int $c): int => 0);

        $ip = '203.0.113.10';
        for ($i = 0; $i < 30; $i++) {
            $decoy->maybeDelay(self::sqliSleep(2), $ip);
        }
        self::assertCount(30, $sleeps);

        // Still in the SAME bucket ⇒ NOT replenished (no early reset).
        $decoy->maybeDelay(self::sqliSleep(2), $ip);
        self::assertCount(30, $sleeps, 'the budget must not reset within the same hour bucket');

        // Advance the clock past the hour boundary ⇒ a fresh bucket ⇒ honoured again.
        $now = 7_300; // hour bucket 2
        $decoy->maybeDelay(self::sqliSleep(2), $ip);
        self::assertCount(31, $sleeps, 'the budget replenishes once the hour bucket rolls over');
    }

    // --- (e) fail-safe ------------------------------------------------------------------------------

    public function test_a_sleeper_fault_adds_no_delay_and_never_throws(): void
    {
        $budget = $this->budget(static function (int $ms): void {
            throw new RuntimeException('sleep blew up');
        });
        $decoy = new SleepDecoy($budget, $this->config(true, 2000), new AttackClassifier(), static fn (int $c): int => 0);

        $ip = '198.51.100.20';
        $decoy->maybeDelay(self::sqliSleep(2), $ip); // must not throw
        self::assertSame(0, $budget->inflightForIp($ip), 'the slot is released even when the sleeper faults');
    }

    public function test_a_broken_budget_store_yields_no_delay_and_never_throws(): void
    {
        $sleeps = [];
        // A path that is an existing DIRECTORY ⇒ the store cannot open it as a DB file ⇒ every budget
        // call fails closed (guard() → null) ⇒ no delay. The whole thing must degrade silently (never a
        // throw into the serve path). (A merely-missing path is no good: Sqlite::open mkdir's it.)
        $badPath = sys_get_temp_dir();
        $budget = $this->budget(
            static function (int $ms) use (&$sleeps): void {
                $sleeps[] = $ms;
            },
            static fn (): int => 1_000_000,
            PHP_INT_MAX,
            8,
            4,
            $badPath
        );
        $decoy = new SleepDecoy($budget, $this->config(true, 2000), new AttackClassifier(), static fn (int $c): int => 0);

        $decoy->maybeDelay(self::sqliSleep(2), '198.51.100.21'); // must not throw
        self::assertSame([], $sleeps, 'a broken budget store fails closed to NO delay');
    }

    // --- off by default + the class gate ------------------------------------------------------------

    public function test_off_by_default_never_delays(): void
    {
        $sleeps = [];
        $budget = $this->budget(static function (int $ms) use (&$sleeps): void {
            $sleeps[] = $ms;
        });
        $decoy = new SleepDecoy($budget, $this->config(false), new AttackClassifier(), static fn (int $c): int => 0);

        $decoy->maybeDelay(self::sqliSleep(2), '198.51.100.30');
        self::assertSame([], $sleeps, 'with FUNNYPOT_SLEEP_DECOY off, a SLEEP probe is never honoured');
        self::assertSame(0, $budget->inflightCount(), 'off ⇒ no slot is even taken');
    }

    public function test_benign_and_non_sqli_rce_probes_are_never_delayed(): void
    {
        $sleeps = [];
        $budget = $this->budget(static function (int $ms) use (&$sleeps): void {
            $sleeps[] = $ms;
        });
        $decoy = new SleepDecoy($budget, $this->config(true, 2000), new AttackClassifier(), static fn (int $c): int => 0);

        // No time-based structure at all ⇒ baseline traffic.
        $decoy->maybeDelay(new RequestContext('GET', '/index.php', 'id=42&name=bob'), '198.51.100.31');
        // A structure SleepProbe reads but the classifier does NOT tag sqli/rce (bare ;sleep cmdi) ⇒ the
        // class gate refuses it.
        $decoy->maybeDelay(new RequestContext('GET', '/x', 'q=a;sleep 5'), '198.51.100.31');
        self::assertSame([], $sleeps, 'benign / non-sqli-rce probes are never delayed');
    }

    public function test_an_rce_time_based_probe_is_honoured(): void
    {
        $sleeps = [];
        $budget = $this->budget(static function (int $ms) use (&$sleeps): void {
            $sleeps[] = $ms;
        });
        $decoy = new SleepDecoy($budget, $this->config(true, 2000), new AttackClassifier(), static fn (int $c): int => 0);

        // $(sleep 2) is an RCE tell the classifier catches AND a time-based structure SleepProbe reads.
        $decoy->maybeDelay(new RequestContext('GET', '/cgi', 'x=$(sleep 2)'), '198.51.100.32');
        self::assertSame([2000], $sleeps, 'a time-based RCE probe is honoured too');
    }

    // --- slot-held-while-sleeping (the self-DoS seam, single-process check) --------------------------

    public function test_the_sleep_runs_only_while_a_slot_is_held(): void
    {
        $ip = '198.51.100.40';
        $heldDuringSleep = null;
        // A budget instance whose sleeper inspects the SAME budget's slot table AT sleep time.
        $budget = null;
        $budget = $this->budget(static function (int $ms) use (&$budget, &$heldDuringSleep, $ip): void {
            $heldDuringSleep = $budget->inflightForIp($ip);
        });
        $decoy = new SleepDecoy($budget, $this->config(true, 2000), new AttackClassifier(), static fn (int $c): int => 0);

        $decoy->maybeDelay(self::sqliSleep(1), $ip);
        self::assertSame(1, $heldDuringSleep, 'a slot is held for this IP at the instant of the honoured sleep');
        self::assertSame(0, $budget->inflightForIp($ip), 'and released immediately afterwards (finally)');
    }

    /**
     * @param float[] $x
     * @param float[] $y
     * @return array{0:float,1:float} [pearson correlation, regression slope dy/dx]
     */
    private static function pearsonAndSlope(array $x, array $y): array
    {
        $n = count($x);
        $mx = array_sum($x) / $n;
        $my = array_sum($y) / $n;
        $sxy = 0.0;
        $sxx = 0.0;
        $syy = 0.0;
        for ($i = 0; $i < $n; $i++) {
            $dx = $x[$i] - $mx;
            $dy = $y[$i] - $my;
            $sxy += $dx * $dy;
            $sxx += $dx * $dx;
            $syy += $dy * $dy;
        }
        $corr = ($sxx > 0 && $syy > 0) ? $sxy / sqrt($sxx * $syy) : 0.0;
        $slope = $sxx > 0 ? $sxy / $sxx : 0.0;

        return [$corr, $slope];
    }
}
