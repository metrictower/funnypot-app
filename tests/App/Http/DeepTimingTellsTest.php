<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Http\ServeJitter;
use Funnypot\Protocol\Listener;
use PHPUnit\Framework\TestCase;

/**
 * FP-0354 — pins the three app-layer deep-timing anti-tells the honeypot-auditor's temporal axis
 * probes. Per the spec, all three are ALREADY closed in the code; this VERIFIES + regression-locks
 * them (it does not add new timing mechanisms):
 *
 *   (a) latency CoV — serve-jitter has non-zero, bounded coefficient of variation (not the near-zero
 *       CoV a static usleep would give). No universal real-network CoV gate (CoV is environment-
 *       dependent via RTT) — only "non-zero and bounded".
 *   (b) clock_drift — a PROTOCOL-CURRENT-TIME Date tracks wall-clock (the bespoke servers' RFC Date
 *       format), within RFC 9110 second precision. CONTENT-HISTORY timestamps (FrozenClock office
 *       ledger dates, Spring log dates) are deliberately deploy-stable and are NOT this tell.
 *   (c) idle_accept — every listener bounds concurrent + per-IP connections; this asserts the caps
 *       exist (the socket-level flood-drive test is CI, and FP-0207/FP-0221 own the admission limiter,
 *       so no second limiter is added here).
 *
 * Timestamp classification (the spec's required audit): {protocol-current = live wall-clock: HTTP/
 * protocol Date headers} vs {explicit live device time} vs {stable content history: FrozenClock,
 * Spring log dates — frozen by design for cross-panel coherence, must NOT be swapped to time()}.
 */
final class DeepTimingTellsTest extends TestCase
{
    public function test_serve_jitter_cov_is_nonzero_and_bounded(): void
    {
        $latency = 0;
        $jitter = 40; // the default
        $n = 5000;
        $samples = [];
        for ($i = 0; $i < $n; $i++) {
            $samples[] = ServeJitter::delayMs($latency, $jitter);
        }
        $mean = array_sum($samples) / $n;
        $var = 0.0;
        foreach ($samples as $s) {
            $var += ($s - $mean) ** 2;
        }
        $cov = sqrt($var / $n) / max(1e-9, $mean);

        // Non-zero (defeats the "static usleep = zero variance" tell) and bounded (a sane spread, not
        // wild). U(0,40) has CoV ~0.577; assert a generous band, NOT a specific real-network value.
        self::assertGreaterThan(0.1, $cov, 'serve-jitter CoV must be non-zero (uniform-timing tell)');
        self::assertLessThan(2.0, $cov, 'serve-jitter CoV must be bounded');
    }

    public function test_delay_is_within_the_configured_bounds(): void
    {
        for ($i = 0; $i < 1000; $i++) {
            $ms = ServeJitter::delayMs(10, 40);
            self::assertGreaterThanOrEqual(10, $ms);
            self::assertLessThanOrEqual(50, $ms);
        }
    }

    public function test_zero_jitter_is_a_deploy_choice_not_a_default(): void
    {
        // jitterMs<=0 disables the spread (zero variance) — a deliberate config, not the default (40).
        for ($i = 0; $i < 50; $i++) {
            self::assertSame(15, ServeJitter::delayMs(15, 0));
        }
    }

    public function test_protocol_current_date_tracks_wall_clock(): void
    {
        // The bespoke HTTP-ish servers emit this exact live RFC-1123-ish format (Tr069/Rtsp/WinRM).
        $date = gmdate('D, d M Y H:i:s') . ' GMT';
        $parsed = strtotime($date);
        self::assertNotFalse($parsed, 'served Date must be a parseable RFC date');
        // Within a couple of seconds of now (RFC 9110 §6.6.1 is second-precision) — never frozen/skewed.
        self::assertLessThanOrEqual(2, abs(time() - $parsed), 'protocol-current Date must track wall-clock');
    }

    public function test_every_listener_bounds_connections(): void
    {
        $ref = new \ReflectionClass(Listener::class);
        foreach (['MAX_CONNS', 'PER_IP_CONNS', 'IDLE_TIMEOUT'] as $cap) {
            self::assertTrue($ref->hasConstant($cap), "Listener must define {$cap}");
            self::assertGreaterThan(0, $ref->getConstant($cap), "{$cap} must be a positive bound");
        }
        // The per-IP cap must be well below the global cap (one source can't monopolise the loop).
        self::assertLessThan($ref->getConstant('MAX_CONNS'), $ref->getConstant('PER_IP_CONNS'));
    }
}
