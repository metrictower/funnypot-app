<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit;

use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\Tarpit\SeededStream;
use PHPUnit\Framework\TestCase;

/**
 * The tarpit generator core (FP-0245a): deterministic + offset-addressable bytes, a hard byte cap,
 * a client-hangup halt, and the wall-clock fabrication deadline that keeps a streamed response inside
 * its TarpitBudget slot TTL. (The flat-memory asymmetry proof lives in {@see TarpitLoadTest}, which
 * needs process-level peak-memory control.)
 */
final class SeededStreamTest extends TestCase
{
    public function test_deterministic_and_offset_addressable(): void
    {
        $s = new SeededStream();

        // Same (seed,label,window) => identical bytes forever (coherent on revisit).
        self::assertSame($s->bytesAt(9, 'log', 0, 4096), $s->bytesAt(9, 'log', 0, 4096));

        // A narrow window equals the matching slice of a wider window that contains it — the O(1)
        // Range property: any byte's value depends only on its absolute offset. The key at "line
        // ~1.4M" is served without fabricating the preceding bytes.
        $narrow = $s->bytesAt(9, 'log', 1_400_000, 64);
        $wide = $s->bytesAt(9, 'log', 1_399_936, 128);
        self::assertSame($narrow, substr($wide, 1_400_000 - 1_399_936, 64));

        // A different label => different bytes (novelty-on-advance); a different seed diverges too.
        self::assertNotSame($s->bytesAt(9, 'log', 0, 256), $s->bytesAt(9, 'audit', 0, 256));
        self::assertNotSame($s->bytesAt(9, 'log', 0, 256), $s->bytesAt(10, 'log', 0, 256));

        // Degenerate windows are safe.
        self::assertSame('', $s->bytesAt(9, 'log', 0, 0));
        self::assertSame('', $s->bytesAt(9, 'log', -5, 10));
    }

    public function test_bytes_are_crlf_and_size_safe(): void
    {
        $b = (new SeededStream())->bytesAt(3, 'x', 0, 10_000);
        self::assertSame(10_000, strlen($b));
        self::assertStringNotContainsString("\r", $b);
        self::assertStringNotContainsString("\n", $b);
    }

    public function test_chunks_honor_byte_cap_exactly(): void
    {
        $s = new SeededStream();
        $total = 0;
        $chunks = 0;
        foreach ($s->chunks(7, 'export', 8 * 1024 * 1024) as $c) {
            $total += strlen($c);
            $chunks++;
        }
        self::assertSame(8 * 1024 * 1024, $total);
        // Per-chunk work is constant (each raw block is one BLOCK), so chunk count scales with the cap
        // — the streamed-generator shape, never a single materialized blob.
        self::assertGreaterThan(1, $chunks);
    }

    public function test_cap_scales_linearly_with_bytes(): void
    {
        $s = new SeededStream();
        $count = static function (int $cap) use ($s): int {
            $n = 0;
            foreach ($s->chunks(1, 'x', $cap) as $c) {
                $n++;
            }

            return $n;
        };
        // 8x the cap => ~8x the chunks (constant per-chunk work), the O(1)-per-byte property.
        self::assertSame(8 * $count(SeededStream::BLOCK * 4), $count(SeededStream::BLOCK * 32));
    }

    public function test_stream_stops_when_connection_aborted(): void
    {
        $s = new SeededStream();
        $captured = '';
        $emitter = new StreamEmitter(static function (string $b) use (&$captured): void {
            $captured .= $b;
        }, 0);

        // The stub reports the client hung up on the first check — emission must halt within one chunk,
        // far below the 8 MiB cap (the DownloadRouter connection_aborted() precedent).
        $aborted = static fn (): int => 1;
        $sent = $s->stream($emitter, 1, 'x', 8 * 1024 * 1024, null, $aborted);

        self::assertLessThanOrEqual(SeededStream::BLOCK, $sent);
        self::assertSame(strlen($captured), $sent);
    }

    public function test_stream_returns_bytes_emitted_and_respects_cap(): void
    {
        $s = new SeededStream();
        $captured = '';
        $emitter = new StreamEmitter(static function (string $b) use (&$captured): void {
            $captured .= $b;
        }, 0);
        $cap = SeededStream::BLOCK * 10;
        $sent = $s->stream($emitter, 2, 'log', $cap, null, static fn (): int => 0);

        self::assertSame($cap, $sent);
        self::assertSame($cap, strlen($captured));
    }

    // --- wall-clock deadline: a slow reader cannot outlive its slot ----------------------------------

    /**
     * A slow reader cannot hold a php-fpm worker past the TarpitBudget slot TTL: the stream ends at the
     * wall-clock deadline regardless of how many bytes the cap would still allow. The injected clock
     * reads 0 at the start, 1 ms after the first chunk, then past DEADLINE_MS — and the client never
     * hangs up, so only the deadline can stop it.
     */
    public function test_stream_stops_at_the_wall_clock_deadline_regardless_of_bytes(): void
    {
        $s = new SeededStream();
        $captured = '';
        $emitter = new StreamEmitter(static function (string $b) use (&$captured): void {
            $captured .= $b;
        }, 0);
        $reads = 0;
        $now = static function () use (&$reads): float {
            return ++$reads <= 2 ? (float) ($reads - 1) : (float) SeededStream::DEADLINE_MS;
        };
        $sent = $s->stream($emitter, 1, 'x', 8 * 1024 * 1024, null, static fn (): int => 0, null, $now);

        self::assertSame(2 * SeededStream::BLOCK, $sent, 'the stream ends at the deadline, far below the 8 MiB cap');
        self::assertSame($sent, strlen($captured), 'the returned count is what was really emitted (the ledger charge)');
    }

    /**
     * The deadline is a check-then-act on the clock, run after each chunk, so crossing it costs at most
     * the ONE chunk that was in flight. A clock that is already past the deadline on its first read
     * after the start pins that bound exactly; a coarse stepping clock against an explicit short
     * deadline shows the crossing chunk is always the last one.
     */
    public function test_stream_deadline_overshoot_is_at_most_one_chunk(): void
    {
        $s = new SeededStream();
        $emitter = new StreamEmitter(static function (string $b): void {
        }, 0);

        $reads = 0;
        $jump = static function () use (&$reads): float {
            return $reads++ === 0 ? 0.0 : 1e9; // start at 0, then far past the deadline on every check
        };
        $sent = $s->stream($emitter, 1, 'x', 8 * 1024 * 1024, null, static fn (): int => 0, null, $jump);
        self::assertSame(SeededStream::BLOCK, $sent, 'exactly one chunk past a crossed deadline — the check-then-act bound');

        // Explicit 50 ms deadline, clock stepping 30 ms per read: the deadline falls inside chunk 2's
        // window (30 → 60), so chunk 2 is emitted and is the last — never a third.
        $t = 0.0;
        $stepping = static function () use (&$t): float {
            $t += 30.0;

            return $t - 30.0;
        };
        $sent = $s->stream($emitter, 1, 'x', 8 * 1024 * 1024, null, static fn (): int => 0, 50, $stepping);
        self::assertSame(2 * SeededStream::BLOCK, $sent);
    }

    /**
     * The three per-response time bounds must nest inside the slot-reap TTL (15 s, TarpitBudget's
     * default and what demo/index.php passes): the pre-byte latency sleep plus the fabrication deadline
     * has to leave margin, or a legitimate response could outlive its slot and soften the ceiling.
     */
    public function test_deadline_plus_latency_cap_fit_inside_the_slot_ttl(): void
    {
        self::assertLessThan(15_000, SeededStream::DEADLINE_MS + TarpitBudget::LATENCY_HARD_CAP_MS, 'sleep + deadline must stay under the 15 s slot TTL');
        self::assertGreaterThan(TarpitBudget::LATENCY_HARD_CAP_MS, SeededStream::DEADLINE_MS, 'the deadline must dwarf the latency sleep, not compete with it');
    }

    public function test_block_fn_shapes_output(): void
    {
        $s = new SeededStream();
        // A formatter that prefixes each block index — proves the skin seam 0245b/c build on.
        $fn = static fn (int $k, string $raw): string => "#{$k}\n";
        $out = '';
        foreach ($s->chunks(1, 'x', 100, $fn) as $c) {
            $out .= $c;
        }
        self::assertStringStartsWith("#0\n#1\n", $out);
        self::assertSame(100, strlen($out)); // still hard-capped
    }
}
