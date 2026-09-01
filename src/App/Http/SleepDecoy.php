<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\Core\RequestContext;
use Throwable;

/**
 * The time-based blind-injection decoy (FP-0228). It honours an attacker's `SLEEP(n)` / `WAITFOR
 * DELAY` / time-based command injection just enough to satisfy a scanner's calibrated-SLEEP
 * confirmation (lonkero's analyze_calibrated_sleep: corr>0.95 + slope∈(0.7,1.5) over a small {0,1,2}s
 * set), while being strictly bounded so it can NEVER DoS the honeypot. It is a specialisation of
 * FP-0245's 0245d latency layer: instead of a fixed configured latency, the honoured delay is
 * min(requested seconds, per-request cap) metered against FP-0245's per-IP wall-time ledger.
 *
 * The two self-DoS guards, both riding FP-0245's ONE {@see TarpitBudget} (no competing budget — plan
 * SHOULD-FIX 2):
 *   1. CONCURRENCY — the honoured usleep runs ONLY while holding a tarpit_slot ({@see TarpitBudget::guard()}
 *      won a slot, released in finally), so at most MAX_CONCURRENT workers ever sleep at once. This is
 *      the load-bearing pool guard: a probe that cannot win a slot is served IMMEDIATELY, no delay.
 *   2. PER-IP CUMULATIVE BUDGET — the slept ms is charged to the SAME tarpit_ledger.wall_ms via
 *      {@see TarpitBudget::charge()}; guard() checks {@see TarpitBudget::overBudget()} first, so once an
 *      IP's honoured sleep (plus any labyrinth wall time) reaches the hourly wall budget
 *      (FUNNYPOT_TARPIT_WALL_PER_IP_HR_S — the operator's ~60s allowance), it is served immediately with
 *      ZERO delay. The hour bucket replenishes the budget on a rolling window.
 *
 * Off by default (FUNNYPOT_SLEEP_DECOY); only honours on the respond + gate-open + isolated-origin serve
 * path (the standalone controller's posture), only when a sleep STRUCTURE is present AND the probe
 * classifies sqli/rce (benign traffic is never delayed), and it FAILS SAFE: any budget-store fault ⇒ no
 * delay, never a 500 (the whole body is a try/catch, and guard()/overBudget() already fail closed).
 * Structure-only + latency-only: honouring a SLEEP executes NOTHING and adds NO bytes to the response.
 */
final class SleepDecoy
{
    /** Ceiling on the jitter band; the honoured delay reserves this much headroom below the per-request
     *  cap so even a capped response varies instead of being a constant (a uniform-timing tell). */
    private const MAX_JITTER_MS = 200;

    /** @var callable(int):int an injectable jitter source (band-ceiling ms → jitter ms); tests pass a spy/0. */
    private $jitter;

    /**
     * @param callable(int):int|null $jitter band-ceiling-ms → added jitter-ms in [0, ceiling]; defaults
     *        to random_int(0, ceiling). Small enough that it never breaks the {0,1,2}s correlation (it
     *        cancels in the slope), applied BELOW the cap so the honoured delay is not a uniform tell.
     *        Injectable so the correlation test is deterministic.
     */
    public function __construct(
        private TarpitBudget $budget,
        private AppConfig $config,
        private AttackClassifier $classifier,
        ?callable $jitter = null
    ) {
        $this->jitter = $jitter ?? static fn (int $ceil): int => $ceil > 0 ? random_int(0, $ceil) : 0;
    }

    /**
     * Honour a time-based blind-injection SLEEP on this probe with a metered, slot-gated, budget-bounded
     * delay — or return immediately (no delay) when any precondition fails. Safe to call on EVERY serve
     * path (served fake, panel, LLM, 404): it self-gates on the sleep structure + attack class, so a
     * benign or non-sleep request costs one regex and returns. Classifies INDEPENDENTLY of the
     * controller's fall-through payload class (which is null on served paths — plan SHOULD-FIX 1).
     */
    public function maybeDelay(RequestContext $r, string $ip): void
    {
        if (!$this->config->sleepDecoy) {
            return; // off by default
        }

        // The WHOLE body is fail-safe: the parse + classify are pure preg (they cannot realistically
        // throw), but keeping them inside the catch makes "never a 500" airtight against future edits.
        try {
            $seconds = SleepProbe::requestedSeconds($r);
            if ($seconds === null) {
                return; // no time-based structure ⇒ baseline traffic, never delayed
            }

            // Independent classification (NOT the controller's $payloadClass, which is null on served
            // paths). The time-based structures are themselves sqli/rce tells, so this only ever gates
            // OUT a probe whose structure matched but whose class is neither — "benign never delayed".
            $class = $this->classifier->classify($r);
            if ($class !== 'sqli' && $class !== 'rce') {
                return;
            }

            // CONCURRENCY + PER-IP BUDGET in one seam: guard() checks overBudget() (per-IP hourly wall)
            // then wins a slot, or returns null (over budget / pool full / master switch off / any
            // storage fault) ⇒ served immediately, no delay. The usleep runs ONLY inside the held slot.
            $slot = $this->budget->guard($ip);
            if ($slot === null) {
                return;
            }
            try {
                $capMs = max(0, $this->config->sleepPerReqCapMs);
                // Reserve headroom for jitter BELOW the cap, so even a capped response (SLEEP(2)+ at the
                // 2000 ms cap) still VARIES instead of being a constant 2000 ms tell. The jitter cancels
                // in lonkero's slope on the small {0,1,2} calibration set.
                $jitterCeil = min(self::MAX_JITTER_MS, intdiv(max(1, $capMs), 10));
                $baseMs = min($seconds * 1000, max(0, $capMs - $jitterCeil));
                $sleptMs = $this->budget->applyLatencyMs($baseMs + ($this->jitter)($jitterCeil));
                // Charge the honoured sleep as wall time on the SAME ledger (rides wall_ms, not a second
                // budget) so it accrues toward the per-IP hourly allowance and trips overBudget() later.
                if ($sleptMs > 0) {
                    $this->budget->charge($ip, 0, $sleptMs, 0);
                }
            } finally {
                $this->budget->release($slot);
            }
        } catch (Throwable $e) {
            // Fail-safe: any fault adds NO delay and never propagates into the serve path (never a 500).
        }
    }
}
