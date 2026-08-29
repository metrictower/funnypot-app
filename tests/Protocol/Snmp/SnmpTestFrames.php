<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Snmp;

/**
 * Byte builders for the SNMP tests: BER TLVs and the v1/v2c GET / GETNEXT / GETBULK / SET request
 * messages a scanner would send. Kept minimal — just enough structure for the honeypot's parser to
 * exercise every field it reads. Request varbinds carry the standard NULL value.
 */
trait SnmpTestFrames
{
    private static function tlv(int $tag, string $value): string
    {
        return chr($tag) . self::berlen(strlen($value)) . $value;
    }

    private static function berlen(int $n): string
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

        return self::tlv(0x02, $b);
    }

    private static function octet(string $s): string
    {
        return self::tlv(0x04, $s);
    }

    private static function oid(string $dotted): string
    {
        $p = array_map('intval', explode('.', $dotted));
        $body = self::b128($p[0] * 40 + $p[1]);
        for ($i = 2; $i < count($p); $i++) {
            $body .= self::b128($p[$i]);
        }

        return self::tlv(0x06, $body);
    }

    private static function b128(int $v): string
    {
        $o = chr($v & 0x7F);
        $v >>= 7;
        while ($v > 0) {
            $o = chr(($v & 0x7F) | 0x80) . $o;
            $v >>= 7;
        }

        return $o;
    }

    /** One request varbind: SEQUENCE { OID, NULL }. */
    private static function varbindNull(string $dotted): string
    {
        return self::tlv(0x30, self::oid($dotted) . "\x05\x00");
    }

    /**
     * A full SNMP request message.
     *
     * @param list<string> $oids
     */
    private static function request(int $pduTag, int $version, string $community, int $reqId, array $oids, int $f1 = 0, int $f2 = 0): string
    {
        $vbs = '';
        foreach ($oids as $o) {
            $vbs .= self::varbindNull($o);
        }
        $vbl = self::tlv(0x30, $vbs);
        $pdu = self::tlv($pduTag, self::int($reqId) . self::int($f1) . self::int($f2) . $vbl);

        return self::tlv(0x30, self::int($version) . self::octet($community) . $pdu);
    }

    /** @param list<string> $oids */
    private static function getReq(int $version, string $community, int $reqId, array $oids): string
    {
        return self::request(0xA0, $version, $community, $reqId, $oids);
    }

    /** @param list<string> $oids */
    private static function getNextReq(int $version, string $community, int $reqId, array $oids): string
    {
        return self::request(0xA1, $version, $community, $reqId, $oids);
    }

    /** @param list<string> $oids */
    private static function getBulkReq(int $version, string $community, int $reqId, int $nonRep, int $maxRep, array $oids): string
    {
        return self::request(0xA5, $version, $community, $reqId, $oids, $nonRep, $maxRep);
    }

    /** @param list<string> $oids */
    private static function setReq(int $version, string $community, int $reqId, array $oids): string
    {
        return self::request(0xA3, $version, $community, $reqId, $oids);
    }
}
