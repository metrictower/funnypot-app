<?php

declare(strict_types=1);

namespace Funnypot\Shell\Fs;

/**
 * Deterministic, stateless draw primitive for path-seeded generation. fnv1a64 is the only fast
 * non-crypto hash guaranteed on PHP 8.0 (xxh3/murmur3 are 8.1+) and is byte-stable across builds.
 * Draws are counter-based: any value is a pure function of (seed, index) with no shared PRNG state.
 * Only bitwise/modulo on hash output — never + - * / (silent int->float promotion breaks determinism);
 * always mask before % (guards the negative-index trap on signed 64-bit ints).
 */
final class Draw
{
    /** Bit-exact determinism needs 64-bit ints; unpack('J') falls back to lossy float on 32-bit. */
    public static function assertEnv(): void
    {
        if (PHP_INT_SIZE !== 8) {
            throw new \RuntimeException('FakeFilesystem requires 64-bit PHP');
        }
    }

    /** Fold arbitrary material into 8 raw seed bytes. */
    public static function seed(string $material): string
    {
        return hash('fnv1a64', $material, true);
    }

    /** i-th non-negative 63-bit draw from a seed. i must be < 2^32 (pack('N')). */
    public static function at(string $seed, int $i): int
    {
        $bytes = hash('fnv1a64', $seed . pack('N', $i), true);

        return unpack('J', $bytes)[1] & PHP_INT_MAX; // de-sign to [0, 2^63-1]
    }

    public static function intBelow(string $seed, int $i, int $n): int
    {
        return $n > 0 ? self::at($seed, $i) % $n : 0;
    }

    /**
     * @param array<int,mixed> $pool
     * @return mixed
     */
    public static function pick(string $seed, int $i, array $pool)
    {
        return $pool === [] ? null : $pool[self::at($seed, $i) % count($pool)];
    }

    public static function chance(string $seed, int $i, int $numerator, int $denominator): bool
    {
        return $denominator > 0 && self::at($seed, $i) % $denominator < $numerator;
    }

    /** Log-ish heavy tail: mostly small, occasional large, within [min, max] inclusive. */
    public static function heavyTailedInt(string $seed, int $i, int $min, int $max): int
    {
        if ($max <= $min) {
            return $min;
        }
        $span = $max - $min;
        // Guard the reduction's multiply (scaled <= 999) against int->float promotion, which would be
        // determinism-fatal and an intdiv TypeError. Clamp span so scaled*span stays a native int.
        // Degrade, never fault (the web path must never 500).
        $cap = intdiv(PHP_INT_MAX, 1000);
        if ($span > $cap) {
            $span = $cap;
        }
        $u = self::at($seed, $i) % 1000;    // 0..999
        $scaled = intdiv($u * $u, 999);     // 0..999 inclusive, skewed low
        return $min + intdiv($scaled * $span, 999); // inclusive of max
    }
}
