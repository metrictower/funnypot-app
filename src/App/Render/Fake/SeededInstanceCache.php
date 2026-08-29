<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Process-wide memo for the seeded fake-data generators.
 *
 * Each generator is a pure, immutable function of its constructor args (seed, plus domain/count where
 * it takes one) and the frozen deploy epoch: the same key always yields byte-identical data. Every
 * panel render rebuilds these from scratch, and the shared roster build is O(N^2), so caching the
 * built instance turns repeated fromSeed() calls into O(1) lookups.
 *
 * A using class gets its OWN cache — trait static properties are per-using-class, so keys never
 * collide across generators. The map is bounded so a long-lived worker that sees many distinct seeds
 * cannot grow without limit.
 */
trait SeededInstanceCache
{
    /** @var array<string, self> */
    private static $seededCache = [];

    /**
     * The cached instance for $key, built once via $build. The frozen epoch is folded into the key so
     * a mid-process clock change never serves data from a stale epoch.
     */
    private static function seededInstance(string $key, callable $build): self
    {
        $k = $key . '@' . FrozenClock::epoch();
        if (!isset(self::$seededCache[$k])) {
            // Keep only a small window of recent instances. The win is reusing an instance across the
            // many renders of ONE request/test (same seed); holding more than a handful just wastes
            // memory in a long-lived worker or a whole-suite serial run.
            if (count(self::$seededCache) >= 12) { // small recent-instance window
                array_shift(self::$seededCache); // insertion-order eviction
            }
            self::$seededCache[$k] = $build();
        }

        return self::$seededCache[$k];
    }
}
