<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Fpm;

use Funnypot\Protocol\Fpm\FastCgiRecord;
use PHPUnit\Framework\TestCase;

/**
 * Pure codec tests (FP-0204 Phase 1): header framing, padding consumption, record split across reads,
 * PARAMS 1/4-byte length encoding, and the memory bounds. No socket.
 */
final class FastCgiRecordTest extends TestCase
{
    public function test_encode_decode_round_trip(): void
    {
        $wire = FastCgiRecord::encode(FastCgiRecord::TYPE_STDOUT, 1, 'hello');
        [$records, $consumed] = FastCgiRecord::decode($wire);

        self::assertCount(1, $records);
        self::assertSame(\strlen($wire), $consumed);
        self::assertSame(FastCgiRecord::TYPE_STDOUT, $records[0]->type);
        self::assertSame(1, $records[0]->requestId);
        self::assertSame('hello', $records[0]->content);
    }

    public function test_encode_pads_to_eight_byte_boundary(): void
    {
        // content 'hello' = 5 bytes → padding 3 → total 8 header + 8 = 16.
        $wire = FastCgiRecord::encode(FastCgiRecord::TYPE_STDOUT, 1, 'hello');
        self::assertSame(16, \strlen($wire));
        self::assertSame(3, \ord($wire[6]), 'paddingLength header byte');
    }

    public function test_requestId_is_preserved_big_endian(): void
    {
        $wire = FastCgiRecord::encode(FastCgiRecord::TYPE_END_REQUEST, 0x1234, '');
        self::assertSame(0x12, \ord($wire[2]));
        self::assertSame(0x34, \ord($wire[3]));
        [$records] = FastCgiRecord::decode($wire);
        self::assertSame(0x1234, $records[0]->requestId);
    }

    public function test_record_split_across_reads_waits_for_the_rest(): void
    {
        $wire = FastCgiRecord::encode(FastCgiRecord::TYPE_PARAMS, 1, 'abcdefghij');
        $head = \substr($wire, 0, 10); // header + 2 content bytes only
        [$records, $consumed] = FastCgiRecord::decode($head);
        self::assertSame([], $records, 'incomplete record yields nothing');
        self::assertSame(0, $consumed, 'nothing consumed until the whole record arrives');

        // The remaining bytes complete it.
        [$records2, $consumed2] = FastCgiRecord::decode($wire);
        self::assertCount(1, $records2);
        self::assertSame(\strlen($wire), $consumed2);
        self::assertSame('abcdefghij', $records2[0]->content);
    }

    public function test_split_across_reads_with_padding(): void
    {
        // content 'abc' (3) → padding 5. A buffer holding header+content but NOT the padding must NOT
        // emit the record (else the next record's bytes would be misread — the desync the codec guards).
        $wire = FastCgiRecord::encode(FastCgiRecord::TYPE_STDIN, 1, 'abc');
        self::assertSame(16, \strlen($wire));
        $withoutPadding = \substr($wire, 0, 11); // 8 header + 3 content, 0 of 5 padding
        [$records, $consumed] = FastCgiRecord::decode($withoutPadding);
        self::assertSame([], $records);
        self::assertSame(0, $consumed);

        // Full record (with padding) decodes and consumes exactly its 16 bytes, leaving the next intact.
        $next = FastCgiRecord::encode(FastCgiRecord::TYPE_STDIN, 1, '');
        [$records2, $consumed2] = FastCgiRecord::decode($wire . $next);
        self::assertCount(2, $records2);
        self::assertSame(16, FastCgiRecord::HEADER_LEN + 3 + 5);
        self::assertSame('abc', $records2[0]->content);
        self::assertSame('', $records2[1]->content);
        self::assertSame(\strlen($wire . $next), $consumed2);
    }

    public function test_multiple_records_in_one_buffer(): void
    {
        $buf = FastCgiRecord::encode(FastCgiRecord::TYPE_PARAMS, 1, 'a')
            . FastCgiRecord::encode(FastCgiRecord::TYPE_PARAMS, 1, 'bb')
            . FastCgiRecord::encode(FastCgiRecord::TYPE_STDIN, 1, '');
        [$records, $consumed] = FastCgiRecord::decode($buf);
        self::assertCount(3, $records);
        self::assertSame(\strlen($buf), $consumed);
    }

    public function test_bad_version_throws(): void
    {
        $wire = FastCgiRecord::encode(FastCgiRecord::TYPE_STDIN, 1, 'x');
        $wire[0] = \chr(9); // corrupt version
        $this->expectException(\RuntimeException::class);
        FastCgiRecord::decode($wire);
    }

    public function test_params_short_length_encoding(): void
    {
        // name 'X' (1), value 'Y' (1), both 1-byte lengths.
        $stream = \chr(1) . \chr(1) . 'X' . 'Y';
        self::assertSame(['X' => 'Y'], FastCgiRecord::decodeParams($stream));
    }

    public function test_params_four_byte_length_encoding(): void
    {
        $name = 'PHP_VALUE';
        $value = \str_repeat('a', 200); // > 127 → 4-byte length
        $stream = self::nv($name, $value);
        $params = FastCgiRecord::decodeParams($stream);
        self::assertSame($value, $params[$name]);
    }

    public function test_params_later_key_wins(): void
    {
        $stream = self::nv('K', 'first') . self::nv('K', 'second');
        self::assertSame('second', FastCgiRecord::decodeParams($stream)['K']);
    }

    public function test_params_pair_count_is_bounded(): void
    {
        $stream = '';
        for ($i = 0; $i < 1000; $i++) {
            $stream .= self::nv('k' . $i, 'v');
        }
        $params = FastCgiRecord::decodeParams($stream, 256);
        self::assertLessThanOrEqual(256, \count($params));
    }

    public function test_params_oversize_value_skipped_but_stream_stays_aligned(): void
    {
        // An over-limit value is skipped, but the following well-formed pair must still decode.
        $stream = self::nv('BIG', \str_repeat('a', 5000)) . self::nv('OK', 'yes');
        $params = FastCgiRecord::decodeParams($stream, 256, 1024, 1024);
        self::assertArrayNotHasKey('BIG', $params);
        self::assertSame('yes', $params['OK'], 'alignment preserved after skipping an oversize pair');
    }

    public function test_params_truncated_pair_stops_cleanly(): void
    {
        // Declares a 10-byte value but supplies 3 — must not read past the buffer.
        $stream = \chr(1) . \chr(10) . 'K' . 'abc';
        self::assertSame([], FastCgiRecord::decodeParams($stream));
    }

    /** Encode one FastCGI name-value pair with correct 1/4-byte length prefixes. */
    private static function nv(string $name, string $value): string
    {
        return self::len(\strlen($name)) . self::len(\strlen($value)) . $name . $value;
    }

    private static function len(int $n): string
    {
        if ($n < 128) {
            return \chr($n);
        }

        return \chr((($n >> 24) & 0x7F) | 0x80)
            . \chr(($n >> 16) & 0xFF)
            . \chr(($n >> 8) & 0xFF)
            . \chr($n & 0xFF);
    }
}
