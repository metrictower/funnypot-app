<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit;

use Funnypot\App\Tarpit\SeededStream;
use PHPUnit\Framework\TestCase;

/**
 * The asymmetry acceptance test (FP-0245 §1): server memory stays flat while the generated output
 * grows ~8000x. This is the exact defect the ticket guards — a tarpit that materialises its artifact
 * is O(output) memory and self-DoSes the 16-worker pool; the streamed generator is O(block).
 *
 * Methodology (plan-review SHOULD-FIX 1): memory_get_peak_usage() is monotonic per process, so the
 * runs are isolated with memory_reset_peak_usage() (PHP 8.2+) between them, and the drain SUMS
 * strlen() and DISCARDS every chunk — it never accumulates into a string/array (which would make the
 * <1 MiB-delta assertion self-defeating), and it never routes through a StreamEmitter (whose test
 * capture buffer would itself grow with the output). If the runtime predates 8.2 the test is skipped
 * rather than asserting a vacuous delta.
 */
final class TarpitLoadTest extends TestCase
{
    /** Drain the generator, counting bytes and discarding them — the honest O(block) measurement. */
    private function drain(SeededStream $s, int $cap): int
    {
        $bytes = 0;
        foreach ($s->chunks(0xC0FFEE, 'log', $cap) as $chunk) {
            $bytes += strlen($chunk);
        }

        return $bytes;
    }

    public function test_peak_memory_is_flat_while_output_grows(): void
    {
        if (!function_exists('memory_reset_peak_usage')) {
            self::markTestSkipped('flat-memory assertion needs PHP 8.2+ memory_reset_peak_usage()');
        }
        $s = new SeededStream();

        // Warm up: fault in the class, opcodes and interned strings so their one-time cost does not
        // land inside the first measured window.
        $this->drain($s, 1024);

        memory_reset_peak_usage();
        $small = $this->drain($s, 1024);                  // 1 KiB
        $peakSmall = memory_get_peak_usage();

        memory_reset_peak_usage();
        $mid = $this->drain($s, 1024 * 1024);             // 1 MiB
        $peakMid = memory_get_peak_usage();

        memory_reset_peak_usage();
        $large = $this->drain($s, 8 * 1024 * 1024);       // 8 MiB
        $peakLarge = memory_get_peak_usage();

        // The output really did grow.
        self::assertSame(1024, $small);
        self::assertSame(1024 * 1024, $mid);
        self::assertSame(8 * 1024 * 1024, $large);

        // ...yet peak memory did not track it. An 8000x larger output costs < 1 MiB more peak — the
        // generator holds one block at a time, never the artifact. (O(block), not O(output).)
        self::assertLessThan(
            1024 * 1024,
            $peakLarge - $peakSmall,
            'peak memory grew with output size — the artifact is being materialized (self-DoS defect)'
        );
        // And the 1 MiB and 8 MiB runs peak within a block or two of each other.
        self::assertLessThan(1024 * 1024, abs($peakLarge - $peakMid));
    }
}
