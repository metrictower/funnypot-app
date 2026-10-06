<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

/**
 * FP-0354 (latency-CoV deep-timing tell): the serve-delay computation, extracted from
 * HoneypotController::serveDelayFor() so the delay DISTRIBUTION is unit-testable without actually
 * sleeping. A honeypot whose responses are suspiciously uniform in time (near-zero coefficient of
 * variation) reads as synthetic; funnypot's served delay is `latencyMs + U(0, jitterMs)`, which has a
 * non-zero, bounded CoV by construction (jitterMs defaults to 40 → a ~20 ms-mean uniform term). This
 * class holds the pure `delayMs()` math; the controller keeps the usleep.
 *
 * Note (per the FP-0354 spec): the residual refinement is only the jitter SHAPE — uniform is flat where
 * real service latency is right-skewed — and the spec scopes that as "only if cheap+coherent", NOT a
 * universal CoV gate (CoV depends on network RTT, which raises the mean not the variance, so the same
 * correct server scores differently per environment). So this keeps the existing uniform jitter and only
 * pins that its CoV is non-zero and bounded.
 */
final class ServeJitter
{
    /**
     * The per-response delay in milliseconds: a fixed floor plus a uniform jitter term. Deterministic
     * only in distribution — each call draws a fresh U(0, jitterMs). jitterMs<=0 disables the jitter
     * (zero variance — a deploy choice; the default 40 gives the anti-uniformity spread).
     */
    public static function delayMs(int $latencyMs, int $jitterMs): int
    {
        $latencyMs = max(0, $latencyMs);

        return $latencyMs + ($jitterMs > 0 ? random_int(0, $jitterMs) : 0);
    }
}
