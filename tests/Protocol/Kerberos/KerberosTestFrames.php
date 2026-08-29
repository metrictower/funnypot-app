<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Kerberos;

/**
 * Byte builders for the Kerberos tests: ASN.1 DER TLVs and the AS-REQ ([APPLICATION 10]) message an
 * enumeration / AS-REP-roasting tool sends. Kept minimal — just enough of the KDC-REQ / KDC-REQ-BODY
 * structure to exercise every field the honeypot parses, plus a few extra body fields (kdc-options,
 * till, nonce, etype) to prove the parser ignores what it does not capture.
 */
trait KerberosTestFrames
{
    private static function der(int $tag, string $value): string
    {
        return chr($tag) . self::derlen(strlen($value)) . $value;
    }

    private static function derlen(int $n): string
    {
        if ($n < 0x80) {
            return chr($n);
        }
        $b = '';
        while ($n > 0) {
            $b = chr($n & 0xFF) . $b;
            $n >>= 8;
        }

        return chr(0x80 | strlen($b)) . $b;
    }

    private static function int(int $n): string
    {
        $b = '';
        while (true) {
            $b = chr($n & 0xFF) . $b;
            $n >>= 8;
            $top = ord($b[0]);
            if ($n === 0 && ($top & 0x80) === 0) {
                break;
            }
            if ($n === -1 && ($top & 0x80) !== 0) {
                break;
            }
        }

        return self::der(0x02, $b);
    }

    private static function genString(string $s): string
    {
        return self::der(0x1B, $s);
    }

    private static function genTime(): string
    {
        return self::der(0x18, gmdate('YmdHis') . 'Z');
    }

    /** Explicit context member [n] wrapping an already-encoded TLV. */
    private static function ctx(int $n, string $inner): string
    {
        return self::der(0xA0 | $n, $inner);
    }

    /**
     * PrincipalName ::= SEQUENCE { [0] INTEGER name-type, [1] SEQUENCE OF GeneralString name-string }.
     *
     * @param list<string> $parts
     */
    private static function principal(int $type, array $parts): string
    {
        $strs = '';
        foreach ($parts as $p) {
            $strs .= self::genString($p);
        }

        return self::der(0x30, self::ctx(0, self::int($type)) . self::ctx(1, self::der(0x30, $strs)));
    }

    /**
     * A full AS-REQ message (no TCP length prefix).
     *
     * @param list<string> $cnameParts
     * @param list<string> $snameParts
     */
    private static function asReq(
        string $realm,
        array $cnameParts,
        array $snameParts,
        int $cnameType = 1,
        int $snameType = 2,
        int $msgType = 10
    ): string {
        $kdcOptions = self::ctx(0, self::der(0x03, "\x00\x40\x00\x00\x00")); // BIT STRING flags
        $till = self::ctx(5, self::genTime());
        $nonce = self::ctx(7, self::int(1818848256 & 0x7FFFFFFF));
        $etype = self::ctx(8, self::der(0x30, self::int(18) . self::int(17) . self::int(23)));

        $body = self::der(
            0x30,
            $kdcOptions
            . self::ctx(1, self::principal($cnameType, $cnameParts))
            . self::ctx(2, self::genString($realm))
            . self::ctx(3, self::principal($snameType, $snameParts))
            . $till
            . $nonce
            . $etype
        );

        $kdcReq = self::der(
            0x30,
            self::ctx(1, self::int(5))        // pvno
            . self::ctx(2, self::int($msgType)) // msg-type
            . self::ctx(4, $body)             // req-body
        );

        return self::der(0x6A, $kdcReq); // [APPLICATION 10] AS-REQ
    }

    /** Prefix a message with the 4-byte big-endian length Kerberos uses over TCP. */
    private static function framed(string $msg): string
    {
        return pack('N', strlen($msg)) . $msg;
    }
}
