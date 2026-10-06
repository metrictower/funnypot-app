<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Minecraft;

/**
 * Pure Minecraft VarInt + packet-framing codec (FP-0206). No I/O, no state — fully unit-testable.
 *
 * A Minecraft VarInt is a 32-bit value, 7 bits per byte, high bit = continuation, at most 5 bytes. The
 * reference decoder in the wild reads past the buffer end and never caps the offset; this one is
 * defensively bounded on EVERY axis — buffer-end checks, a 5-byte ceiling, and length validation
 * (`0 <= n <= $cap`) at PARSE time — so a crafted frame can neither over-read nor allocate on a declared
 * length. Reads return null on truncation/overflow rather than throwing on a bad index.
 */
final class VarInt
{
    private const MAX_BYTES = 5;

    /**
     * Read a VarInt at $offset, advancing it. Returns null if the buffer is exhausted mid-VarInt or the
     * VarInt exceeds 5 bytes. The value is masked to 32 bits (two's complement, as Minecraft uses it).
     */
    public static function read(string $buf, int &$offset): ?int
    {
        $len = \strlen($buf);
        $result = 0;
        $numRead = 0;
        do {
            if ($offset >= $len) {
                return null; // truncated
            }
            $read = \ord($buf[$offset]);
            $offset++;
            $result |= ($read & 0x7F) << (7 * $numRead);
            $numRead++;
            if ($numRead > self::MAX_BYTES) {
                return null; // over-long VarInt — reject, never keep reading
            }
        } while (($read & 0x80) !== 0);

        // Interpret as 32-bit signed (Minecraft VarInts are 32-bit two's complement).
        $result &= 0xFFFFFFFF;
        if ($result >= 0x80000000) {
            $result -= 0x100000000;
        }

        return $result;
    }

    /** Encode an int as a VarInt (lower 32 bits). */
    public static function write(int $value): string
    {
        $value &= 0xFFFFFFFF;
        $out = '';
        do {
            $byte = $value & 0x7F;
            $value >>= 7;
            if ($value !== 0) {
                $byte |= 0x80;
            }
            $out .= \chr($byte);
        } while ($value !== 0);

        return $out;
    }

    /**
     * Read a VarInt-length-prefixed UTF-8 string at $offset, advancing it. The declared length is validated
     * `0 <= len <= $cap` BEFORE any read, and the buffer must actually hold it — otherwise null (no
     * over-allocation, no over-read). $cap bounds a hostile length.
     */
    public static function readString(string $buf, int &$offset, int $cap = 32767): ?string
    {
        $save = $offset;
        $len = self::read($buf, $offset);
        if ($len === null || $len < 0 || $len > $cap) {
            $offset = $save;

            return null;
        }
        if ($offset + $len > \strlen($buf)) {
            $offset = $save;

            return null; // not all present
        }
        $s = \substr($buf, $offset, $len);
        $offset += $len;

        return $s;
    }

    /** Encode a VarInt-length-prefixed string. */
    public static function writeString(string $s): string
    {
        return self::write(\strlen($s)) . $s;
    }

    /**
     * Frame one complete packet from $buf at $offset: read the outer Packet-Length VarInt, require that many
     * bytes present (a packet split across TCP reads yields null — wait for more), validate
     * `0 < length <= $cap` at parse time, then split into { id, payload }. Advances $offset past the whole
     * packet on success. Returns null when incomplete; throws nothing.
     *
     * @return array{id:int, payload:string}|null
     */
    public static function readPacket(string $buf, int &$offset, int $cap = 65536): ?array
    {
        $save = $offset;
        $length = self::read($buf, $offset);
        if ($length === null) {
            $offset = $save;

            return null; // length VarInt not yet complete
        }
        if ($length <= 0 || $length > $cap) {
            // Protocol-impossible declared length — signal a hard reject to the caller (close the conn).
            throw new \RuntimeException('Minecraft: bad packet length ' . $length);
        }
        if ($offset + $length > \strlen($buf)) {
            $offset = $save;

            return null; // whole packet not buffered yet
        }
        $end = $offset + $length;
        $id = self::read($buf, $offset);
        if ($id === null || $offset > $end) {
            throw new \RuntimeException('Minecraft: bad packet id');
        }
        $payload = \substr($buf, $offset, $end - $offset);
        $offset = $end;

        return ['id' => $id, 'payload' => $payload];
    }
}
