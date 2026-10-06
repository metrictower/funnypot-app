<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Minecraft;

use Funnypot\Protocol\Minecraft\VarInt;
use PHPUnit\Framework\TestCase;

/** FP-0206 Phase 1: bounded VarInt + packet framing. No socket. */
final class VarIntTest extends TestCase
{
    public function test_single_byte_values(): void
    {
        foreach ([0, 1, 2, 127] as $v) {
            $off = 0;
            self::assertSame($v, VarInt::read(VarInt::write($v), $off));
            self::assertSame(1, $off);
        }
    }

    public function test_multi_byte_values(): void
    {
        foreach ([128, 255, 25565, 2097151, 2147483647] as $v) {
            $off = 0;
            self::assertSame($v, VarInt::read(VarInt::write($v), $off), "round-trip {$v}");
        }
    }

    public function test_negative_is_five_bytes_and_round_trips(): void
    {
        $wire = VarInt::write(-1);
        self::assertSame(5, \strlen($wire));
        $off = 0;
        self::assertSame(-1, VarInt::read($wire, $off));
    }

    public function test_truncated_varint_returns_null(): void
    {
        $off = 0;
        self::assertNull(VarInt::read("\x80", $off), 'continuation bit set but no next byte');
    }

    public function test_overlong_varint_rejected(): void
    {
        // 6 bytes all with continuation bit — must be rejected, not read forever.
        $off = 0;
        self::assertNull(VarInt::read("\x80\x80\x80\x80\x80\x80", $off));
    }

    public function test_read_string_caps_length(): void
    {
        $off = 0;
        // declares length 1000 but cap is 10 -> null, offset unchanged
        $buf = VarInt::write(1000) . str_repeat('a', 1000);
        self::assertNull(VarInt::readString($buf, $off, 10));
        self::assertSame(0, $off, 'offset rewound on reject');
    }

    public function test_read_string_requires_all_bytes(): void
    {
        $off = 0;
        $buf = VarInt::write(50) . 'short'; // declares 50, only 5 present
        self::assertNull(VarInt::readString($buf, $off, 100));
    }

    public function test_read_string_negative_length_rejected(): void
    {
        $off = 0;
        $buf = VarInt::write(-1) . 'xxxx';
        self::assertNull(VarInt::readString($buf, $off, 100), 'negative declared length rejected');
    }

    public function test_read_string_happy_path(): void
    {
        $off = 0;
        self::assertSame('mc.corp.local', VarInt::readString(VarInt::writeString('mc.corp.local'), $off));
    }

    public function test_packet_split_across_reads_returns_null(): void
    {
        // A packet of payload length 10 but only part present.
        $payload = VarInt::write(0x00) . str_repeat('x', 9); // id + 9 bytes = 10 bytes
        $full = VarInt::write(\strlen($payload)) . $payload;
        $partial = \substr($full, 0, 5);
        $off = 0;
        self::assertNull(VarInt::readPacket($partial, $off), 'incomplete packet waits');
        self::assertSame(0, $off);

        $off = 0;
        $p = VarInt::readPacket($full, $off);
        self::assertSame(0x00, $p['id']);
        self::assertSame(\strlen($full), $off);
    }

    public function test_packet_absurd_length_throws(): void
    {
        $off = 0;
        $buf = VarInt::write(2000000000) . 'xx'; // ~2e9 declared
        $this->expectException(\RuntimeException::class);
        VarInt::readPacket($buf, $off, 65536);
    }

    public function test_packet_zero_length_throws(): void
    {
        $off = 0;
        $this->expectException(\RuntimeException::class);
        VarInt::readPacket(VarInt::write(0), $off);
    }
}
