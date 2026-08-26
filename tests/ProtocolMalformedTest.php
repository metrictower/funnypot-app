<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\ProtocolEmulator;
use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\ProtocolTemplateSet;
use PHPUnit\Framework\TestCase;

/**
 * Malformed style at the emulator/driver level: a TCP connection is answered on connect with the
 * malformed trickle (not a banner/login), the frame stream is bounded and self-closes at the cap, an
 * inbound OSC-52 clipboard reply is captured for intel, and none of this fires unless the style is on.
 */
final class ProtocolMalformedTest extends TestCase
{
    protected function tearDown(): void
    {
        putenv('FUNNYPOT_STYLE');
    }

    private function emu(string $id): ProtocolEmulator
    {
        $set = ProtocolTemplateSet::fromFile(__DIR__ . '/../resources/compiled/funnypot-protocols.php');
        $e = $set->emulator($id);
        self::assertNotNull($e, "protocol {$id} not compiled");

        return $e;
    }

    public function test_connect_starts_the_trickle_instead_of_a_banner(): void
    {
        putenv('FUNNYPOT_STYLE=malformed');
        $e = $this->emu('redis');
        $s = new ProtocolSession(7);

        $burst = $e->banner($s);
        self::assertNotSame('', $burst);
        self::assertFalse(mb_check_encoding($burst, 'UTF-8'), 'connect burst is malformed bytes');
        self::assertTrue($s->trolling, 'connect engages the frame pump');
        self::assertTrue($e->isTrolling($s));
    }

    public function test_frames_cycle_then_cap_and_close(): void
    {
        putenv('FUNNYPOT_STYLE=malformed');
        $e = $this->emu('redis');
        $s = new ProtocolSession(1);
        $e->banner($s);

        // Pump frames; each is non-empty until the cap.
        for ($i = 0; $i < 5; $i++) {
            self::assertNotSame('', $e->trollFrame($s));
        }
        // Jump to the cap: the next pull closes the session and yields nothing more.
        $s->trollFrame = 120; // == MalformedStream::CAP_FRAMES
        $tail = $e->trollFrame($s);
        self::assertSame('', $tail);
        self::assertTrue($s->close, 'bounded: the stream self-terminates at the cap');
        self::assertFalse($e->isTrolling($s), 'listener stops pumping once closed');
    }

    public function test_inbound_osc52_reply_is_captured_as_clipboard_intel(): void
    {
        putenv('FUNNYPOT_STYLE=malformed');
        $e = $this->emu('redis');
        $s = new ProtocolSession(3);
        $e->banner($s); // trolling

        $reply = "\x1b]52;c;" . base64_encode('id_rsa BEGIN PRIVATE KEY...') . "\x07";
        $out = $e->feed($reply, $s);
        self::assertSame('', $out, 'inbound is consumed, not echoed');
        self::assertSame('id_rsa BEGIN PRIVATE KEY...', $s->clipboardCapture);
    }

    public function test_off_by_default_and_under_taunt(): void
    {
        // No style: redis is silent on connect (normal behaviour), never trolling.
        $e = $this->emu('redis');
        $s = new ProtocolSession(9);
        self::assertSame('', $e->banner($s));
        self::assertFalse($s->trolling);

        // Taunt style must NOT trigger the malformed connect burst.
        putenv('FUNNYPOT_STYLE=taunt');
        $e2 = $this->emu('redis');
        $s2 = new ProtocolSession(9);
        self::assertSame('', $e2->banner($s2), 'taunt does not start the malformed connect trickle');
        self::assertFalse($s2->trolling);
    }
}
