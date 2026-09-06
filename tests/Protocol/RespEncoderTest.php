<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol;

use Funnypot\Protocol\RespEncoder;
use Funnypot\Protocol\RespReply;
use PHPUnit\Framework\TestCase;

/**
 * The RESP encoder: scalar/aggregate framing, exact RESP2↔RESP3 downgrades (map→array, set→array,
 * verbatim→bulk, versioned nulls), and a length measurement that abandons early without building the
 * bytes.
 */
final class RespEncoderTest extends TestCase
{
    private RespEncoder $enc;

    protected function setUp(): void
    {
        $this->enc = new RespEncoder();
    }

    public function test_scalars(): void
    {
        self::assertSame("+OK\r\n", $this->enc->encode(RespReply::simple('OK'), 2));
        self::assertSame("-ERR bad\r\n", $this->enc->encode(RespReply::error('ERR bad'), 2));
        self::assertSame(":42\r\n", $this->enc->encode(RespReply::int(42), 2));
        self::assertSame("\$3\r\nabc\r\n", $this->enc->encode(RespReply::bulk('abc'), 2));
    }

    public function test_binary_safe_bulk(): void
    {
        $v = "a\x00b\r\nc";
        self::assertSame("\$" . strlen($v) . "\r\n" . $v . "\r\n", $this->enc->encode(RespReply::bulk($v), 3));
    }

    public function test_null_bulk_is_versioned(): void
    {
        self::assertSame("\$-1\r\n", $this->enc->encode(RespReply::nullBulk(), 2));
        self::assertSame("_\r\n", $this->enc->encode(RespReply::nullBulk(), 3));
    }

    public function test_null_array_is_versioned(): void
    {
        self::assertSame("*-1\r\n", $this->enc->encode(RespReply::nullArray(), 2));
        self::assertSame("_\r\n", $this->enc->encode(RespReply::nullArray(), 3));
    }

    public function test_array_nesting(): void
    {
        $reply = RespReply::array([RespReply::int(1), RespReply::bulk('x')]);
        self::assertSame("*2\r\n:1\r\n\$1\r\nx\r\n", $this->enc->encode($reply, 2));
    }

    public function test_map_downgrades_to_flat_array_in_resp2(): void
    {
        $map = RespReply::map([[RespReply::bulk('k'), RespReply::bulk('v')]]);
        self::assertSame("*2\r\n\$1\r\nk\r\n\$1\r\nv\r\n", $this->enc->encode($map, 2));
        self::assertSame("%1\r\n\$1\r\nk\r\n\$1\r\nv\r\n", $this->enc->encode($map, 3));
    }

    public function test_set_downgrades_to_array_in_resp2(): void
    {
        $set = RespReply::set([RespReply::simple('a'), RespReply::simple('b')]);
        self::assertSame("*2\r\n+a\r\n+b\r\n", $this->enc->encode($set, 2));
        self::assertSame("~2\r\n+a\r\n+b\r\n", $this->enc->encode($set, 3));
    }

    public function test_verbatim_downgrades_to_bulk_in_resp2(): void
    {
        $v = RespReply::verbatim("line1\nline2", 'txt');
        self::assertSame("\$11\r\nline1\nline2\r\n", $this->enc->encode($v, 2));
        // RESP3 verbatim carries the "txt:" prefix and a length that counts it.
        self::assertSame("=15\r\ntxt:line1\nline2\r\n", $this->enc->encode($v, 3));
    }

    public function test_encoded_length_matches_encode(): void
    {
        $reply = RespReply::array([
            RespReply::bulk('hello'),
            RespReply::map([[RespReply::bulk('k'), RespReply::int(7)]]),
            RespReply::nullBulk(),
        ]);
        foreach ([2, 3] as $ver) {
            $bytes = $this->enc->encode($reply, $ver);
            self::assertSame(strlen($bytes), $this->enc->encodedLength($reply, $ver, 1 << 20));
        }
    }

    public function test_encoded_length_aborts_early_over_cap(): void
    {
        // A huge array should be measured as "over cap" without ever building it.
        $items = [];
        for ($i = 0; $i < 100000; $i++) {
            $items[] = RespReply::bulk(str_repeat('x', 64));
        }
        $reply = RespReply::array($items);
        $cap = 32768;
        $len = $this->enc->encodedLength($reply, 2, $cap);
        self::assertGreaterThan($cap, $len, 'the measured length must exceed the cap');
    }
}
