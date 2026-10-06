<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol;

use Funnypot\Protocol\PerIpAdmissionThrottle;
use PHPUnit\Framework\TestCase;

final class PerIpAdmissionThrottleTest extends TestCase
{
    private float $now = 1000.0;

    private function throttle(float $burst, float $rate, ?float $seed = null, int $maxIps = 4096, float $rollup = 60.0): PerIpAdmissionThrottle
    {
        return new PerIpAdmissionThrottle($burst, $rate, $seed, $maxIps, $rollup, fn (): float => $this->now);
    }

    public function test_disabled_when_burst_not_positive(): void
    {
        $t = $this->throttle(0, 10);
        self::assertFalse($t->enabled());
        for ($i = 0; $i < 1000; $i++) {
            self::assertTrue($t->admit('1.1.1.1')->admitted);
        }
        self::assertSame(0, $t->trackedIps(), 'disabled throttle keeps no state');
    }

    public function test_full_burst_of_intel_admitted_then_dropped(): void
    {
        $t = $this->throttle(5, 1); // seed defaults to burst = 5
        for ($i = 0; $i < 5; $i++) {
            self::assertTrue($t->admit('2.2.2.2')->admitted, "command {$i} within burst");
        }
        // Burst drained, no time passed -> next is dropped.
        self::assertFalse($t->admit('2.2.2.2')->admitted);
    }

    public function test_refill_readmits_over_time(): void
    {
        $t = $this->throttle(3, 2); // 2 tokens/sec
        for ($i = 0; $i < 3; $i++) {
            self::assertTrue($t->admit('3.3.3.3')->admitted);
        }
        self::assertFalse($t->admit('3.3.3.3')->admitted); // drained
        $this->now += 1.0; // +1s => +2 tokens
        self::assertTrue($t->admit('3.3.3.3')->admitted);
        self::assertTrue($t->admit('3.3.3.3')->admitted);
        self::assertFalse($t->admit('3.3.3.3')->admitted);
    }

    public function test_interactive_pace_never_throttled(): void
    {
        // A human/scanner typing ~1 cmd/sec against a 2/sec refill stays admitted indefinitely.
        $t = $this->throttle(5, 2);
        for ($i = 0; $i < 50; $i++) {
            self::assertTrue($t->admit('4.4.4.4')->admitted, "interactive command {$i}");
            $this->now += 1.0;
        }
    }

    public function test_flood_rollup_first_drop_then_periodic(): void
    {
        $t = $this->throttle(1, 0.0001, null, 4096, 60.0); // tiny refill => everything after the seed floods
        self::assertTrue($t->admit('5.5.5.5')->admitted); // seed token

        // First drop emits a rollup immediately (count 1) to signal the flood started.
        $d = $t->admit('5.5.5.5');
        self::assertFalse($d->admitted);
        self::assertTrue($d->hasRollup());
        self::assertSame(1, $d->floodCount);

        // Subsequent drops within the 60s window are silent (folded into the window).
        for ($i = 0; $i < 10; $i++) {
            $s = $t->admit('5.5.5.5');
            self::assertFalse($s->admitted);
            self::assertFalse($s->hasRollup(), "drop {$i} should be silent within the window");
        }

        // Past the window -> one rollup carrying the window's suppressed count (the 10 silent + this one).
        $this->now += 61.0;
        $r = $t->admit('5.5.5.5');
        self::assertFalse($r->admitted);
        self::assertTrue($r->hasRollup());
        self::assertSame(11, $r->floodCount);
        self::assertGreaterThan(0, $r->floodSinceMs);
    }

    public function test_recovery_resets_the_flood_run(): void
    {
        $t = $this->throttle(1, 1.0, null, 4096, 60.0);
        self::assertTrue($t->admit('6.6.6.6')->admitted); // seed token
        $d1 = $t->admit('6.6.6.6'); // drained -> first drop of the run -> emits a rollup
        self::assertFalse($d1->admitted);
        self::assertTrue($d1->hasRollup());
        self::assertSame(1, $d1->floodCount);

        $this->now += 2.0; // refill -> this admit succeeds and RESETS the drop-run
        self::assertTrue($t->admit('6.6.6.6')->admitted);

        // A new drop after recovery starts a FRESH rollup window (emits immediately again).
        $d2 = $t->admit('6.6.6.6');
        self::assertFalse($d2->admitted);
        self::assertTrue($d2->hasRollup(), 'post-recovery drop starts a new run and emits');
        self::assertSame(1, $d2->floodCount);
    }

    public function test_rollup_count_and_sinceMs_share_a_per_window_base(): void
    {
        // Regression for the time-base mismatch: from window 2 on, floodSinceMs must be the per-window
        // duration (matching the per-window floodCount), NOT cumulative-since-flood-start.
        $t = $this->throttle(1, 0.0001, null, 4096, 60.0);
        self::assertTrue($t->admit('9.9.9.9')->admitted); // seed

        $w1 = $t->admit('9.9.9.9'); // first drop -> emits (window 1, instantaneous)
        self::assertTrue($w1->hasRollup());
        self::assertSame(0, $w1->floodSinceMs);

        // window 2: drops over ~61s, then an emit
        for ($i = 0; $i < 3; $i++) { $this->now += 10.0; self::assertFalse($t->admit('9.9.9.9')->hasRollup()); }
        $this->now += 31.0; // total 61s since the window-1 emit
        $w2 = $t->admit('9.9.9.9');
        self::assertTrue($w2->hasRollup());
        self::assertSame(4, $w2->floodCount);            // 3 silent + this one
        self::assertSame(61000, $w2->floodSinceMs);      // per-window, not cumulative

        // window 3: another ~61s -> sinceMs must RESET to the window, not grow to ~122s
        for ($i = 0; $i < 2; $i++) { $this->now += 20.0; self::assertFalse($t->admit('9.9.9.9')->hasRollup()); }
        $this->now += 21.0;
        $w3 = $t->admit('9.9.9.9');
        self::assertTrue($w3->hasRollup());
        self::assertSame(3, $w3->floodCount);
        self::assertSame(61000, $w3->floodSinceMs);      // NOT 122000
    }

    public function test_negative_clock_does_not_corrupt_the_bucket(): void
    {
        $t = $this->throttle(2, 1);
        self::assertTrue($t->admit('1.2.3.4')->admitted);
        self::assertTrue($t->admit('1.2.3.4')->admitted); // drained (burst 2)
        $this->now -= 100.0;                              // clock jumps backward
        self::assertFalse($t->admit('1.2.3.4')->admitted, 'negative elapsed is clamped; no phantom refill');
    }

    public function test_negative_burst_is_disabled(): void
    {
        $t = $this->throttle(-5, 10);
        self::assertFalse($t->enabled());
        self::assertTrue($t->admit('1.1.1.1')->admitted);
        self::assertSame(0, $t->trackedIps());
    }

    public function test_lru_evicts_the_oldest_not_the_survivor(): void
    {
        // maxIps=2. Touch 'old' first, then 'keep' (newer), then 'new' forces an eviction. The OLDEST
        // ('old') must go; 'keep' must survive — proven by its bucket still being drained on re-admit
        // (a wrongly-evicted 'keep' would be re-seeded a full burst and admit).
        $t = $this->throttle(1, 0.0001, null, 2);
        $t->admit('old');                    // t=1000, drained
        $this->now += 1.0; $t->admit('keep'); // t=1001, drained, newer than 'old'
        $this->now += 1.0; $t->admit('new');  // t=1002, map full -> evict oldest 'old'
        self::assertSame(2, $t->trackedIps());
        self::assertFalse($t->admit('keep')->admitted, "survivor kept its drained bucket (not re-seeded)");
    }

    public function test_lru_eviction_bounds_the_map(): void
    {
        $t = $this->throttle(5, 1, null, 3); // cap 3 IPs
        foreach (['a', 'b', 'c', 'd', 'e'] as $ip) {
            $t->admit($ip);
            $this->now += 1.0; // distinct 'last' so eviction order is deterministic
        }
        self::assertSame(3, $t->trackedIps(), 'map is LRU-capped at maxIps');
    }

    public function test_sources_are_independent(): void
    {
        $t = $this->throttle(2, 0.0001);
        self::assertTrue($t->admit('7.7.7.7')->admitted);
        self::assertTrue($t->admit('7.7.7.7')->admitted);
        self::assertFalse($t->admit('7.7.7.7')->admitted); // 7.7.7.7 drained
        // A different source is unaffected.
        self::assertTrue($t->admit('8.8.8.8')->admitted);
        self::assertTrue($t->admit('8.8.8.8')->admitted);
    }
}
