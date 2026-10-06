<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * Per-apparent-source command/connection admission throttle for the TEXT/TCP honeypot servers
 * (FP-0221). SSH, TELNET and MSSQL each write one store row per command/query, so a single flooding
 * IP is an unbounded *logging* sink — they have connection caps but no per-IP RATE limit. This is the
 * shared automatic defense (the ticket's "one helper, not four bespoke buckets"), mirroring the SIP
 * call-admission bucket: the first burst of commands from a source is admitted (interactive intel is
 * preserved), then a sustained flood is dropped and its per-command logging collapses to a periodic
 * rollup until the source goes quiet.
 *
 * Standalone + injectable (not the UdpResponseBucket trait) so each server holds one instance and the
 * whole thing is unit-testable without a socket. The clock is injectable for deterministic tests.
 * Disabled (always admit, no state) when burst <= 0, so a deployment can turn it off.
 *
 * Bounded: the per-IP map is LRU-capped (maxIps). Unlike UdpResponseBucket, a new source is seeded
 * with the FULL burst, not depleted: a TCP source IP cannot be spoofed (it completed a 3-way
 * handshake), so there is no spoofed-source eviction-cycling reflection gain to defend against here —
 * and a full-burst seed preserves the first `burst` commands of every real connection as intel. The
 * LRU is therefore pure memory-bounding. `seed` stays configurable for callers that want otherwise.
 */
final class PerIpAdmissionThrottle
{
    /** @var array<string, array{tokens: float, last: float, dropped: int, windowStart: float, lastRollup: float}> */
    private array $buckets = [];

    private float $seed;

    /** @var callable():float */
    private $clock;

    public function __construct(
        private float $burst,
        private float $ratePerSec,
        ?float $seed = null,
        private int $maxIps = 4096,
        private float $rollupSecs = 60.0,
        ?callable $clock = null
    ) {
        // Default: a new TCP source gets a full burst of intel capture (see class doc).
        $this->seed = $seed ?? $burst;
        $this->clock = $clock ?? static fn (): float => microtime(true);
    }

    public function enabled(): bool
    {
        return $this->burst > 0;
    }

    /**
     * Admit (or drop) one command/connection from $ip. Returns an AdmissionDecision: when dropped, its
     * rollup fields are set on the first drop of a flood and then at most once per `rollupSecs`, carrying
     * the suppressed-command count for that window so the caller logs ONE rollup row instead of one per
     * command. A granted call debits one token; a drop debits nothing.
     */
    public function admit(string $ip): AdmissionDecision
    {
        if (!$this->enabled()) {
            return AdmissionDecision::admitted();
        }

        $now = ($this->clock)();
        $this->ensure($ip, $now);
        $b = &$this->buckets[$ip];

        $elapsed = max(0.0, $now - $b['last']);
        $b['tokens'] = min($this->burst, $b['tokens'] + $elapsed * $this->ratePerSec);
        $b['last'] = $now;

        if ($b['tokens'] >= 1.0) {
            $b['tokens'] -= 1.0;
            // A token is available again: the flood (if any) has ended — reset the drop-run so the next
            // drop starts a fresh rollup window and per-command logging resumes below the threshold.
            $b['dropped'] = 0;
            $b['windowStart'] = 0.0;
            $b['lastRollup'] = 0.0;

            return AdmissionDecision::admitted();
        }

        // Dropped: accumulate the suppressed count and decide whether to emit a rollup now. `dropped`
        // and `windowStart` are BOTH per-window (reset together on each emit) so a logged rollup's
        // count and sinceMs share one time base — a consumer's count/sinceMs rate is correct every
        // window, not just the first. Recovery (an admit) ends the run; the tail lost on recovery is
        // bounded in TIME to < rollupSecs (its count is drop-rate dependent, not bounded).
        $b['dropped']++;
        if ($b['windowStart'] === 0.0) {
            $b['windowStart'] = $now;
        }
        if ($b['lastRollup'] === 0.0 || ($now - $b['lastRollup']) >= $this->rollupSecs) {
            $count = $b['dropped'];
            $sinceMs = (int) round(($now - $b['windowStart']) * 1000);
            $b['lastRollup'] = $now;
            $b['dropped'] = 0;       // next window counts afresh …
            $b['windowStart'] = $now; // … from now, so sinceMs matches that fresh count

            return AdmissionDecision::droppedWithRollup($count, $sinceMs);
        }

        return AdmissionDecision::droppedSilently();
    }

    /** Ensure a bucket for $ip, seeded depleted; LRU-evict the least-recently-touched when full. */
    private function ensure(string $ip, float $now): void
    {
        if (isset($this->buckets[$ip])) {
            return;
        }
        if (count($this->buckets) >= $this->maxIps) {
            $oldestKey = null;
            $oldestAt = INF;
            foreach ($this->buckets as $k => $b) {
                if ($b['last'] < $oldestAt) {
                    $oldestAt = $b['last'];
                    $oldestKey = $k;
                }
            }
            if ($oldestKey !== null) {
                unset($this->buckets[$oldestKey]);
            }
        }
        $this->buckets[$ip] = [
            'tokens' => $this->seed,
            'last' => $now,
            'dropped' => 0,
            'windowStart' => 0.0,
            'lastRollup' => 0.0,
        ];
    }

    /** Number of source IPs currently tracked (for tests / introspection). */
    public function trackedIps(): int
    {
        return count($this->buckets);
    }
}
