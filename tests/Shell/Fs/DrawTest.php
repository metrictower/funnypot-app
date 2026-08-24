<?php

declare(strict_types=1);

namespace Funnypot\Tests\Shell\Fs;

use Funnypot\Shell\Fs\Draw;
use PHPUnit\Framework\TestCase;

final class DrawTest extends TestCase
{
    public function test_at_is_deterministic_and_non_negative(): void
    {
        $s = Draw::seed("host\0dev\0/home");
        for ($i = 0; $i < 500; $i++) {
            $v = Draw::at($s, $i);
            self::assertGreaterThanOrEqual(0, $v);
            self::assertSame($v, Draw::at($s, $i)); // stable
        }
    }

    public function test_intBelow_never_negative_or_out_of_range(): void
    {
        $s = Draw::seed('x');
        for ($i = 0; $i < 1000; $i++) {
            $v = Draw::intBelow($s, $i, 7);
            self::assertGreaterThanOrEqual(0, $v);
            self::assertLessThan(7, $v);
        }
    }

    public function test_different_seeds_diverge(): void
    {
        self::assertNotSame(Draw::at(Draw::seed('a'), 0), Draw::at(Draw::seed('b'), 0));
    }

    public function test_heavy_tailed_within_bounds(): void
    {
        $s = Draw::seed('sz');
        for ($i = 0; $i < 1000; $i++) {
            $v = Draw::heavyTailedInt($s, $i, 10, 1_000_000);
            self::assertGreaterThanOrEqual(10, $v);
            self::assertLessThanOrEqual(1_000_000, $v);
        }
    }

    public function test_heavy_tailed_survives_huge_span_without_overflow(): void
    {
        // The clamp must keep scaled*span a native int (no intdiv TypeError / float promotion).
        $v = Draw::heavyTailedInt(Draw::seed('big'), 3, 0, PHP_INT_MAX);
        self::assertGreaterThanOrEqual(0, $v);
    }
}
