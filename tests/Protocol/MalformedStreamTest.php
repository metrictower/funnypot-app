<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol;

use Funnypot\Protocol\MalformedStream;
use PHPUnit\Framework\TestCase;

/**
 * The malformed-style byte generator: the opening burst is genuinely invalid UTF-8 carrying working
 * OSC-52 read+write sequences, later frames reuse the troll art, the stream is bounded, and the
 * inbound clipboard reply parses back cleanly.
 */
final class MalformedStreamTest extends TestCase
{
    protected function tearDown(): void
    {
        putenv('FUNNYPOT_STYLE');
    }

    public function test_enabled_only_for_malformed_style(): void
    {
        putenv('FUNNYPOT_STYLE=malformed');
        self::assertTrue(MalformedStream::enabled());
        putenv('FUNNYPOT_STYLE=taunt');
        self::assertFalse(MalformedStream::enabled());
        putenv('FUNNYPOT_STYLE');
        self::assertFalse(MalformedStream::enabled());
    }

    public function test_opening_burst_is_invalid_utf8(): void
    {
        $b = MalformedStream::openingBurst();
        self::assertFalse(mb_check_encoding($b, 'UTF-8'), 'burst must be invalid UTF-8');
        self::assertStringContainsString("\x00", $b, 'burst carries embedded NULs');
    }

    public function test_burst_carries_working_osc52_write_and_read(): void
    {
        $b = MalformedStream::openingBurst();
        // WRITE: base64("access denied :)") BEL-terminated.
        self::assertStringContainsString("\x1b]52;c;YWNjZXNzIGRlbmllZCA6KQ==\x07", $b);
        // READ query: BEL-terminated.
        self::assertStringContainsString("\x1b]52;c;?\x07", $b);
        // NOT a literal backslash-a (the PHP `\a` trap — must be real BEL 0x07).
        self::assertStringNotContainsString('\\a', $b);
    }

    public function test_frame0_is_burst_later_frames_are_troll_art(): void
    {
        self::assertSame(MalformedStream::openingBurst(), MalformedStream::frame(0));
        $f1 = MalformedStream::frame(1);
        self::assertNotSame('', $f1);
        // Reuses the SKULL/TROLL animation, NOT the taunt's "ENABLE REVERSE CONNECTION" login flash.
        self::assertStringNotContainsString('ENABLE REVERSE', $f1);
    }

    public function test_stream_is_bounded(): void
    {
        self::assertSame(120, MalformedStream::CAP_FRAMES);
        self::assertFalse(MalformedStream::done(119));
        self::assertTrue(MalformedStream::done(120));
        self::assertTrue(MalformedStream::done(500));
    }

    public function test_parse_clipboard_round_trip_and_null_cases(): void
    {
        $reply = "\x1b]52;c;" . base64_encode('aws_secret=AKIAEXAMPLE') . "\x07";
        self::assertSame('aws_secret=AKIAEXAMPLE', MalformedStream::parseClipboard($reply));

        // ST-terminated form is also accepted.
        $stForm = "\x1b]52;c;" . base64_encode('x') . "\x1b\\";
        self::assertSame('x', MalformedStream::parseClipboard($stForm));

        self::assertNull(MalformedStream::parseClipboard("\x1b]52;c;?\x07"), 'the query echo is not a value');
        self::assertNull(MalformedStream::parseClipboard('no osc here'));
        self::assertNull(MalformedStream::parseClipboard(''));
    }

    public function test_parse_clipboard_caps_length(): void
    {
        $huge = str_repeat('A', 100000);
        $reply = "\x1b]52;c;" . base64_encode($huge) . "\x07";
        $got = MalformedStream::parseClipboard($reply);
        self::assertNotNull($got);
        self::assertLessThanOrEqual(4096, strlen((string) $got));
    }
}
