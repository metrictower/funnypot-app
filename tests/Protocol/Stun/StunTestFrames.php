<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Stun;

/**
 * Byte builders for the STUN tests: the 20-byte header, attributes (with 4-byte padding) and the
 * Binding Request / arbitrary message a scanner or NAT-discovery client would send. Kept minimal —
 * just enough structure for the honeypot's parser to exercise every field it reads.
 */
trait StunTestFrames
{
    private const MAGIC = "\x21\x12\xA4\x42";

    /** A fixed, distinctive 12-byte transaction id. */
    private static function txid(): string
    {
        return "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";
    }

    /** One STUN attribute: type(2), length(2), value, padded to a 4-byte boundary. */
    private static function attr(int $type, string $value): string
    {
        $len = strlen($value);
        $pad = (4 - ($len % 4)) % 4;

        return pack('n', $type) . pack('n', $len) . $value . str_repeat("\x00", $pad);
    }

    private static function softwareAttr(string $s): string
    {
        return self::attr(0x8022, $s);
    }

    /** A full STUN message with the given 14-bit message type. */
    private static function message(int $type, string $txid, string $attrs = ''): string
    {
        return pack('n', $type) . pack('n', strlen($attrs)) . self::MAGIC . $txid . $attrs;
    }

    private static function bindingRequest(string $txid, string $attrs = ''): string
    {
        return self::message(0x0001, $txid, $attrs);
    }
}
