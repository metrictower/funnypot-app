<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Analytics;

use Funnypot\App\Analytics\AttackerHeat;
use PHPUnit\Framework\TestCase;

final class AttackerHeatTest extends TestCase
{
    private float $now = 1000.0;

    private function heat(float $halfLife = 300.0): AttackerHeat
    {
        return new AttackerHeat($halfLife, fn (): float => $this->now);
    }

    public function test_weighted_events_accrue(): void
    {
        $h = $this->heat();
        self::assertSame(5.0, $h->observe('1.1.1.1', 'honeytoken'));
        self::assertSame(8.0, $h->observe('1.1.1.1', 'attack_class')); // +3
        self::assertSame(8.5, $h->observe('1.1.1.1', 'http_4xx'));      // +0.5
    }

    public function test_unknown_event_is_a_no_op_weight(): void
    {
        $h = $this->heat();
        $h->observe('2.2.2.2', 'decoy'); // 1.0
        self::assertSame(1.0, $h->observe('2.2.2.2', 'bogus-type'), 'unknown event adds 0, never inflates');
    }

    public function test_untracked_source_is_cold_zero(): void
    {
        $h = $this->heat();
        self::assertSame(0.0, $h->heat('9.9.9.9'));
        self::assertSame('cold', $h->tier('9.9.9.9'));
        self::assertFalse($h->isHot('9.9.9.9'));
    }

    public function test_heat_decays_by_half_over_one_half_life(): void
    {
        $h = $this->heat(300.0);
        $h->observe('3.3.3.3', 'honeytoken'); // 5.0
        $this->now += 300.0;                   // one half-life
        self::assertEqualsWithDelta(2.5, $h->heat('3.3.3.3'), 1e-9, 'halves over one half-life');
        $this->now += 300.0;                   // two half-lives
        self::assertEqualsWithDelta(1.25, $h->heat('3.3.3.3'), 1e-9);
    }

    public function test_decay_then_increment_composes(): void
    {
        $h = $this->heat(300.0);
        $h->observe('4.4.4.4', 'attack_class'); // 3.0
        $this->now += 300.0;                     // -> 1.5
        self::assertSame(4.5, $h->observe('4.4.4.4', 'attack_class')); // 1.5 + 3.0
    }

    public function test_tiers_and_isHot(): void
    {
        $h = $this->heat();
        $src = '5.5.5.5';
        self::assertSame('cold', $h->tier($src));
        $h->observe($src, 'attack_class'); // 3.0 -> warm
        self::assertSame('warm', $h->tier($src));
        $h->observe($src, 'honeytoken');   // +5 = 8.0 -> hot
        self::assertSame('hot', $h->tier($src));
        self::assertTrue($h->isHot($src));
        for ($i = 0; $i < 5; $i++) {
            $h->observe($src, 'attack_class'); // climb past 20 -> scalding
        }
        self::assertSame('scalding', $h->tier($src));
    }

    public function test_heat_is_clamped(): void
    {
        $h = $this->heat(1e9); // negligible decay
        for ($i = 0; $i < 10000; $i++) {
            $h->observe('6.6.6.6', 'honeytoken');
        }
        self::assertLessThanOrEqual(1000.0, $h->heat('6.6.6.6'), 'heat is clamped, never overflows');
    }

    public function test_sources_independent(): void
    {
        $h = $this->heat();
        $h->observe('7.7.7.7', 'honeytoken');
        self::assertSame(0.0, $h->heat('8.8.8.8'));
    }

    public function test_lru_bounds_tracked_sources(): void
    {
        $h = $this->heat();
        for ($i = 0; $i < 4096 + 100; $i++) {
            $this->now += 0.001;
            $h->observe('src-' . $i, 'decoy');
        }
        self::assertLessThanOrEqual(4096, $h->trackedSources());
    }

    public function test_lru_evicts_the_oldest_not_the_newest(): void
    {
        // Fill to cap, then one more source: the OLDEST (src-0) must be evicted, a recent one survives.
        $h = $this->heat(1e9); // negligible decay so survival is observable via heat()
        for ($i = 0; $i < 4096; $i++) {
            $this->now += 0.001;
            $h->observe('src-' . $i, 'honeytoken');
        }
        $this->now += 0.001;
        $h->observe('fresh', 'decoy'); // forces one eviction
        self::assertSame(0.0, $h->heat('src-0'), 'oldest source was evicted');
        self::assertGreaterThan(0.0, $h->heat('src-4095'), 'a recent source survived');
        self::assertGreaterThan(0.0, $h->heat('fresh'));
    }

    public function test_negative_clock_does_not_grow_heat(): void
    {
        $h = $this->heat(300.0);
        $h->observe('n.n.n.n', 'honeytoken'); // 5.0
        $this->now -= 100.0;                    // clock jumps backward
        self::assertSame(5.0, $h->heat('n.n.n.n'), 'negative elapsed is clamped; heat never grows');
    }

    public function test_nonpositive_half_life_disables_decay_without_error(): void
    {
        foreach (array(0.0, -5.0) as $hl) {
            $h = $this->heat($hl);
            $h->observe('z.z.z.z', 'honeytoken'); // 5.0
            $this->now += 10000.0;
            self::assertSame(5.0, $h->heat('z.z.z.z'), "halfLife {$hl}: no decay, no div-by-zero/NaN");
        }
    }

    public function test_heat_read_does_not_mutate_stored_value(): void
    {
        $h = $this->heat(300.0);
        $h->observe('r.r.r.r', 'attack_class'); // 3.0
        $this->now += 300.0;                     // one half-life
        // Two reads at the same clock are stable, and neither writes back the decay...
        self::assertEqualsWithDelta(1.5, $h->heat('r.r.r.r'), 1e-9);
        self::assertEqualsWithDelta(1.5, $h->heat('r.r.r.r'), 1e-9);
        // ...so a later observe() decays the ORIGINAL 3.0 once (to 1.5) + adds, not a double-decayed value.
        self::assertSame(4.5, $h->observe('r.r.r.r', 'attack_class'));
    }
}
