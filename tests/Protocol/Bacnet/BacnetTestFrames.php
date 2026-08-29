<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Bacnet;

/**
 * Byte builders for the BACnet/IP tests: BVLC + NPDU envelopes and the Who-Is / ReadProperty request
 * messages an OT scanner would send. Kept minimal — just enough structure for the honeypot's parser
 * to exercise every field it reads.
 *
 * A "routed" envelope carries the destination + source network addressing and hop count a message
 * picks up when it transits a BACnet router; it is also how a test inflates a request past the
 * anti-amplification cap so the believable reply (I-Am / ReadProperty-ACK) is allowed through.
 */
trait BacnetTestFrames
{
    private static function bvlc(int $func, string $npdu): string
    {
        return chr(0x81) . chr($func) . pack('n', strlen($npdu) + 4) . $npdu;
    }

    private static function npduSimple(string $apdu): string
    {
        return "\x01\x00" . $apdu; // version 1, control 0 (no addressing)
    }

    private static function npduRouted(string $apdu): string
    {
        // control 0x28 = destination present + source present.
        $extra = "\xff\xff" . "\x00"        // DNET = global broadcast, DLEN = 0
            . "\x00\x01" . "\x01" . "\x0a"  // SNET = 1, SLEN = 1, SADR = 0x0A
            . "\xff";                       // hop count
        return "\x01\x28" . $extra . $apdu;
    }

    /** A context-tagged primitive (value length assumed <= 4). */
    private static function ctx(int $tagNumber, string $value): string
    {
        return chr((($tagNumber & 0x0F) << 4) | 0x08 | strlen($value)) . $value;
    }

    /** Minimal big-endian unsigned bytes. */
    private static function ube(int $v): string
    {
        if ($v <= 0) {
            return "\x00";
        }
        $b = '';
        while ($v > 0) {
            $b = chr($v & 0xFF) . $b;
            $v >>= 8;
        }

        return $b;
    }

    private static function objectIdBytes(int $type, int $instance): string
    {
        return pack('N', (($type & 0x3FF) << 22) | ($instance & 0x3FFFFF));
    }

    private static function whoIsApdu(?int $low, ?int $high): string
    {
        $apdu = "\x10\x08"; // unconfirmed-request, Who-Is
        if ($low !== null && $high !== null) {
            $apdu .= self::ctx(0, self::ube($low)) . self::ctx(1, self::ube($high));
        }

        return $apdu;
    }

    private static function readPropertyApdu(int $invokeId, int $objType, int $objInst, int $propId, ?int $arrayIndex = null): string
    {
        // confirmed-request: flags(0), maxSegs/maxApdu(0x05), invokeId, service(0x0C readProperty).
        $apdu = "\x00\x05" . chr($invokeId & 0xFF) . "\x0c"
            . self::ctx(0, self::objectIdBytes($objType, $objInst))
            . self::ctx(1, self::ube($propId));
        if ($arrayIndex !== null) {
            $apdu .= self::ctx(2, self::ube($arrayIndex));
        }

        return $apdu;
    }

    private static function confirmedApdu(int $invokeId, int $service, string $data = ''): string
    {
        return "\x00\x05" . chr($invokeId & 0xFF) . chr($service & 0xFF) . $data;
    }

    private static function datagramWhoIs(?int $low = null, ?int $high = null, bool $routed = false): string
    {
        $apdu = self::whoIsApdu($low, $high);

        return self::bvlc(0x0b, $routed ? self::npduRouted($apdu) : self::npduSimple($apdu)); // broadcast
    }

    private static function datagramReadProperty(int $invokeId, int $objType, int $objInst, int $propId, ?int $arrayIndex = null, bool $routed = false): string
    {
        $apdu = self::readPropertyApdu($invokeId, $objType, $objInst, $propId, $arrayIndex);

        return self::bvlc(0x0a, $routed ? self::npduRouted($apdu) : self::npduSimple($apdu)); // unicast
    }

    private static function datagramConfirmed(int $invokeId, int $service, string $data = '', bool $routed = false): string
    {
        $apdu = self::confirmedApdu($invokeId, $service, $data);

        return self::bvlc(0x0a, $routed ? self::npduRouted($apdu) : self::npduSimple($apdu));
    }
}
