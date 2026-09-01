<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit;

use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\Tarpit\SeededStream;
use PHPUnit\Framework\TestCase;

/**
 * The tarpit generator core (FP-0245a): deterministic + offset-addressable bytes, a hard byte cap,
 * and a client-hangup halt. (The flat-memory asymmetry proof lives in {@see TarpitLoadTest}, which
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
