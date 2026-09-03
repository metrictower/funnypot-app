<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use PHPUnit\Framework\TestCase;

/**
 * FP-0250 2.9 — the dashboard's decoy-404 branches (feed/handleLogin/loginForm/shell/recording) must be
 * TIMING-indistinguishable from a genuine honeypot miss, not just byte/header-identical (2.6/2.8). Before
 * this fix, every decoy branch called HoneypotController::serveBelievable404() directly, skipping the
 * latencyMs/jitterMs delay a real miss pays inside HoneypotController::handle() (serveDelay(), plus the
 * engine detect/respond pass, a store->append() write, and a geo->lookup()) — so the hidden dashboard path
 * answered several ms FASTER than a random-unmapped-path control on every plain GET, a latency oracle an
 * attacker can exploit by medianing a few dozen timed requests per candidate path.
 *
 * This is a STATISTICAL test over the real `php -S` wire (see {@see DashboardHttpServerTrait}) — wide
 * tolerance by design, so it is robust on a noisy CI box. It is not trying to measure microseconds; it is
 * trying to catch a systematic ~20+ms gap between "answered before the engine/store/geo pass ran" and
 * "answered after it ran". Reverting the HoneypotController::serveDelayFor() calls in DashboardController's
 * decoy branches (2.9) makes this test fail: the decoy median collapses to a few ms while the miss median
 * stays anchored to the configured jitter, well outside TOLERANCE_MS.
 */
final class DashboardDecoyTimingTest extends TestCase
{
    use DashboardHttpServerTrait;

    private const PASS = 'operator-secret-pw-timing';
    private const SAMPLES = 30;

    // jitterMs defaults to 40 (0-40ms uniform, ~20ms mean, ~11.5ms stdev); with SAMPLES=30 the median's
    // standard error is a couple of ms, so a healthy pair of medians lands well inside this band. The gap
    // this test exists to catch (delay fully skipped on the decoy path) is ~20ms — comfortably outside it.
    private const TOLERANCE_MS = 15.0;

    protected function setUp(): void
    {
        if (!function_exists('proc_open')) {
            self::markTestSkipped('proc_open disabled — cannot spawn the built-in server');
        }
        if (PHP_BINARY === '' || !is_executable(PHP_BINARY)) {
            self::markTestSkipped('no usable PHP CLI binary to run the built-in server');
        }
    }

    protected function tearDown(): void
    {
        $this->dashboardCleanupTmpDirs();
    }

    public function test_decoy_404_and_genuine_miss_latency_distributions_overlap(): void
    {
        $root = dirname(__DIR__, 3);
        $index = $root . '/demo/index.php';
        $data = $this->dashboardTempDir('fpdt_data');
        $docroot = $this->dashboardTempDir('fpdt_doc');
        $env = $this->dashboardBootEnv($data, [
            'FUNNYPOT_MODE' => 'stealth',
            'FUNNYPOT_PUBLIC_VIEW' => 'none',
            'FUNNYPOT_ADMIN_PASSWORD' => self::PASS,
            // Left unset deliberately: FUNNYPOT_LATENCY_MS/FUNNYPOT_JITTER_MS keep their production
            // defaults (0 / 40) — this test exercises the SAME config-driven delay an operator ships with.
        ]);
        [$proc, $pipes, $port] = $this->startDashboardServer($index, $docroot, $env);

        try {
            // Bare GET of the hidden dashboard path, unauthenticated, public_view=none: DashboardController
            // ::shell()'s decoy-404 branch (FP-0250 2.8/2.9).
            $decoyPath = '/__fp/';
            // A path with no product/template match anywhere: falls through HoneypotController::handle()
            // to its own believable-404 branch (the genuine-miss control this test compares against).
            $missPath = '/no/such/path/timing-control-xyz';

            // Warm-up requests (outside the timed loop) so opcache/autoload cold-start cost never leaks
            // into either sample set.
            $this->dashboardHttpRequest('127.0.0.1', $port, 'GET', $decoyPath);
            $this->dashboardHttpRequest('127.0.0.1', $port, 'GET', $missPath);

            $decoySamples = $this->timedSamples($port, $decoyPath, self::SAMPLES);
            $missSamples = $this->timedSamples($port, $missPath, self::SAMPLES);

            $decoyMedian = $this->median($decoySamples);
            $missMedian = $this->median($missSamples);
            $delta = abs($decoyMedian - $missMedian);

            self::assertLessThanOrEqual(
                self::TOLERANCE_MS,
                $delta,
                sprintf(
                    'decoy-404 median (%.2fms) and genuine-miss median (%.2fms) diverge by %.2fms,'
                        . ' more than the %sms tolerance — the dashboard decoy path is answering faster'
                        . ' than a real miss, a timing oracle (FP-0250 2.9 regression)',
                    $decoyMedian,
                    $missMedian,
                    $delta,
                    self::TOLERANCE_MS
                )
            );
        } finally {
            $this->stopDashboardServer($proc, $pipes);
        }
    }

    /** @return float[] wall-clock milliseconds for $count sequential GETs of $path */
    private function timedSamples(int $port, string $path, int $count): array
    {
        $samples = [];
        for ($i = 0; $i < $count; $i++) {
            $start = microtime(true);
            $this->dashboardHttpRequest('127.0.0.1', $port, 'GET', $path);
            $samples[] = (microtime(true) - $start) * 1000.0;
        }

        return $samples;
    }

    /** @param float[] $values */
    private function median(array $values): float
    {
        sort($values);
        $n = count($values);
        self::assertGreaterThan(0, $n, 'no samples collected');
        $mid = intdiv($n, 2);

        return $n % 2 === 0 ? ($values[$mid - 1] + $values[$mid]) / 2.0 : $values[$mid];
    }
}
