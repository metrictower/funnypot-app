<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol;

use Funnypot\Protocol\RespCommand;
use Funnypot\Protocol\RespParser;
use Funnypot\Protocol\RespProtocolException;
use PHPUnit\Framework\TestCase;

/**
 * The binary-safe incremental RESP parser: every valid frame parses when complete and never before,
 * argument boundaries and raw bytes survive, and every malformed shape is rejected without consuming
 * the offending frame's un-arrived bytes.
 */
final class RespParserTest extends TestCase
{
    private function parser(): RespParser
    {
        return new RespParser();
    }

    /** @return list<string> */
    private function drain(RespParser $p, string &$buf): array
    {
        $out = [];
        while (($cmd = $p->parse($buf)) !== null) {
            if (!$cmd->isEmpty()) {
                $out[] = implode("\x00", $cmd->args());
            }
        }

        return $out;
    }

    public function test_multibulk_command_parses_with_boundaries(): void
    {
        $buf = "*3\r\n\$3\r\nSET\r\n\$3\r\nfoo\r\n\$3\r\nbar\r\n";
        $cmd = $this->parser()->parse($buf);
        self::assertInstanceOf(RespCommand::class, $cmd);
        self::assertSame(['SET', 'foo', 'bar'], $cmd->args());
        self::assertSame('', $buf, 'the whole frame is consumed');
    }

    public function test_inline_command_parses_and_strips_cr(): void
    {
        $buf = "PING\r\n";
        $cmd = $this->parser()->parse($buf);
        self::assertSame(['PING'], $cmd->args());
    }

    public function test_inline_supports_quotes_and_hex_escapes(): void
    {
        $buf = "SET k \"a b\\x00c\"\r\n";
        $cmd = $this->parser()->parse($buf);
        self::assertNotNull($cmd);
        self::assertSame(['SET', 'k', "a b\x00c"], $cmd->args());
    }

    public function test_bulk_values_are_binary_safe(): void
    {
        // A value carrying a space, a NUL and an embedded CRLF must survive intact.
        $value = "a b\x00c\r\nd";
        $buf = "*2\r\n\$3\r\nGET\r\n\$" . strlen($value) . "\r\n" . $value . "\r\n";
        $cmd = $this->parser()->parse($buf);
        self::assertNotNull($cmd);
        self::assertSame($value, $cmd->args()[1]);
    }

    public function test_pipelined_frames_parse_one_at_a_time(): void
    {
        $buf = "PING\r\n*1\r\n\$4\r\nQUIT\r\n";
        $p = $this->parser();
        self::assertSame(['PING'], $p->parse($buf)->args());
        self::assertSame(['QUIT'], $p->parse($buf)->args());
        self::assertNull($p->parse($buf));
        self::assertSame('', $buf);
    }

    public function test_every_byte_split_of_a_frame_is_reassembled(): void
    {
        $frame = "*2\r\n\$4\r\nECHO\r\n\$5\r\nhello\r\n";
        for ($cut = 1; $cut < strlen($frame); $cut++) {
            $p = $this->parser();
            $buf = substr($frame, 0, $cut);
            $partial = $p->parse($buf);
            self::assertNull($partial, "must not parse a frame cut at byte {$cut}");
            self::assertSame(substr($frame, 0, $cut), $buf, "must not consume an incomplete frame (cut {$cut})");
            $buf .= substr($frame, $cut);
            $cmd = $p->parse($buf);
            self::assertNotNull($cmd, "must complete once the rest arrives (cut {$cut})");
            self::assertSame(['ECHO', 'hello'], $cmd->args());
        }
    }

    public function test_incomplete_frame_is_left_untouched(): void
    {
        $buf = "*2\r\n\$4\r\nECHO\r\n\$5\r\nhel";
        $before = $buf;
        self::assertNull($this->parser()->parse($buf));
        self::assertSame($before, $buf);
    }

    public function test_rejects_non_decimal_multibulk_length(): void
    {
        $this->expectException(RespProtocolException::class);
        $buf = "*x\r\n\$3\r\nabc\r\n";
        $this->parser()->parse($buf);
    }

    public function test_rejects_oversized_bulk_length(): void
    {
        $this->expectException(RespProtocolException::class);
        $buf = "*1\r\n\$999999999\r\n";
        $this->parser()->parse($buf);
    }

    public function test_rejects_negative_bulk_length(): void
    {
        $this->expectException(RespProtocolException::class);
        $buf = "*1\r\n\$-5\r\nabcde\r\n";
        $this->parser()->parse($buf);
    }

    public function test_rejects_excess_argv(): void
    {
        $p = new RespParser(RespParser::DEFAULT_MAX_FRAME, 4);
        $this->expectException(RespProtocolException::class);
        $buf = "*5\r\n\$1\r\na\r\n\$1\r\nb\r\n\$1\r\nc\r\n\$1\r\nd\r\n\$1\r\ne\r\n";
        $p->parse($buf);
    }

    public function test_rejects_missing_dollar_prefix(): void
    {
        $this->expectException(RespProtocolException::class);
        $buf = "*1\r\nPING\r\n";
        $this->parser()->parse($buf);
    }

    public function test_rejects_unbalanced_inline_quotes(): void
    {
        $this->expectException(RespProtocolException::class);
        $buf = "SET k \"unterminated\r\n";
        $this->parser()->parse($buf);
    }

    public function test_empty_multibulk_is_ignored_not_error(): void
    {
        $buf = "*0\r\nPING\r\n";
        $p = $this->parser();
        $empty = $p->parse($buf);
        self::assertNotNull($empty);
        self::assertTrue($empty->isEmpty());
        self::assertSame(['PING'], $p->parse($buf)->args());
    }

    public function test_blank_inline_line_is_ignored(): void
    {
        $buf = "\r\nPING\r\n";
        $p = $this->parser();
        self::assertTrue($p->parse($buf)->isEmpty());
        self::assertSame(['PING'], $p->parse($buf)->args());
    }

    public function test_oversized_inline_without_terminator_is_rejected(): void
    {
        $p = new RespParser(64, 128);
        $this->expectException(RespProtocolException::class);
        $buf = str_repeat('A', 200); // no CRLF, exceeds the frame cap
        $p->parse($buf);
    }
}
