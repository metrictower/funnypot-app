<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Redis;

use Funnypot\Protocol\Redis\RedisConfig;
use Funnypot\Protocol\Redis\RedisConnection;
use PHPUnit\Framework\TestCase;

/**
 * The per-connection resource bounds — where the interactive Redis honeypot's DoS resistance lives.
 * The single output queue never exceeds its high-water mark however many frames are pipelined, at
 * most 16 commands run per pump tick, an over-large reply becomes one bounded error with no partial
 * materialisation, a malformed multibulk closes the link, and the per-connection command / input
 * caps trip cleanly. (The socket accept/idle/blocklist plumbing mirrors the covered MssqlServer /
 * SipServer pattern and is enforced by ReportableAssertionLintTest.)
 */
final class RedisConnectionSecurityTest extends TestCase
{
    use RedisTestFrames;

    private function conn(): RedisConnection
    {
        return new RedisConnection($this->redisConfig(42), 1, '203.0.113.5');
    }

    public function test_at_most_16_commands_run_per_tick(): void
    {
        $conn = $this->conn();
        $conn->feed(str_repeat("PING\r\n", 20));
        $conn->pump();
        // 16 tiny +PONG replies, the remaining 4 frames left buffered for the next tick.
        self::assertSame(str_repeat("+PONG\r\n", 16), $conn->outbuf);
        $conn->outbuf = '';
        $conn->pump();
        self::assertSame(str_repeat("+PONG\r\n", 4), $conn->outbuf);
    }

    public function test_output_queue_never_exceeds_high_water_under_a_pipelined_flood(): void
    {
        $conn = $this->conn();
        // One ~64 KiB read of INFO frames — enough that, if every reply were concatenated, the output
        // would be megabytes. Draining after each tick, the queue must never pass the high-water mark.
        $frame = "*1\r\n\$4\r\nINFO\r\n";
        $conn->feed(str_repeat($frame, (int) ceil(65536 / strlen($frame))));
        $ticks = 0;
        do {
            $conn->pump();
            self::assertLessThanOrEqual(
                RedisConfig::OUTPUT_HIGH_WATER,
                strlen($conn->outbuf),
                'the single output queue must never exceed its high-water mark'
            );
            $produced = $conn->outbuf !== '';
            $conn->outbuf = ''; // simulate the server flushing to a fast reader
            $ticks++;
        } while ($produced && $ticks < 5000);
        self::assertLessThan(5000, $ticks, 'the buffered frames must fully drain, not loop forever');
    }

    public function test_oversized_reply_becomes_a_bounded_error_and_closes(): void
    {
        $conn = $this->conn();
        // Store one 16 KiB value, then MGET it many times: the semantic reply would be megabytes.
        $conn->feed($this->respArray(['SET', 'big', str_repeat('Z', RedisConfig::MAX_VALUE_BYTES)]));
        $conn->pump();
        $conn->outbuf = '';
        $conn->feed($this->respArray(array_merge(['MGET'], array_fill(0, 50, 'big'))));
        $conn->pump();
        self::assertSame("-ERR response exceeds configured limit\r\n", $conn->outbuf, 'no partial RESP frame, just the bounded error');
        self::assertTrue($conn->wantsClose());
    }

    public function test_malformed_multibulk_returns_wire_error_and_closes(): void
    {
        $conn = $this->conn();
        $conn->feed("*1\r\n\$999999999\r\n"); // bulk length past the frame cap
        $conn->pump();
        self::assertStringStartsWith('-ERR Protocol error', $conn->outbuf);
        self::assertTrue($conn->wantsClose());
    }

    public function test_command_cap_closes_the_connection(): void
    {
        $conn = $this->conn();
        // Feed and drain more than the per-connection command cap.
        for ($i = 0; $i <= RedisConfig::MAX_COMMANDS + 20; $i++) {
            $conn->feed("PING\r\n");
            $conn->pump();
            $conn->outbuf = '';
            if ($conn->wantsClose()) {
                break;
            }
        }
        self::assertTrue($conn->wantsClose(), 'the connection closes at the command cap');
    }

    public function test_input_buffer_overflow_closes(): void
    {
        $conn = $this->conn();
        // A client that floods without ever letting us drain: 200 KiB of un-parseable partial input.
        $conn->feed(str_repeat('x', 200000));
        self::assertTrue($conn->wantsClose());
    }

    public function test_incomplete_frame_is_held_not_executed(): void
    {
        $conn = $this->conn();
        $conn->feed("*3\r\n\$3\r\nSET\r\n\$1\r\nk\r\n\$3\r\nab"); // value + trailing CRLF not arrived
        $conn->pump();
        self::assertSame('', $conn->outbuf, 'an incomplete frame produces no reply');
        $conn->feed("c\r\n");
        $conn->pump();
        self::assertSame("+OK\r\n", $conn->outbuf);
    }
}
