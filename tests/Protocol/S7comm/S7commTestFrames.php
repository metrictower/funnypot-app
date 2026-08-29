<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\S7comm;

/**
 * Byte builders for the S7comm tests: TPKT / COTP framing plus the S7comm Job and Userdata PDUs a
 * PLC scanner (plcscan, nmap s7-info, snap7) sends — Connection Request, Setup Communication,
 * Read / Write Var and Read SZL. Kept minimal, just enough structure for the honeypot's parser to
 * exercise every field it reads.
 */
trait S7commTestFrames
{
    private static function tpkt(string $payload): string
    {
        return "\x03\x00" . pack('n', strlen($payload) + 4) . $payload;
    }

    /** COTP Data TPDU wrapping an S7comm PDU. */
    private static function cotpData(string $s7): string
    {
        return self::tpkt("\x02\xf0\x80" . $s7);
    }

    /**
     * COTP Connection Request with TPDU-size and TSAP parameters, as a real client opens with.
     */
    private static function connectionRequest(int $srcRef = 0x0004, int $dstRef = 0x0000, int $srcTsap = 0x0100, int $dstTsap = 0x0102): string
    {
        $params = "\xc0\x01\x0a"                       // TPDU size = 1024 (2^10)
            . "\xc1\x02" . pack('n', $srcTsap)         // source TSAP
            . "\xc2\x02" . pack('n', $dstTsap);        // destination TSAP (rack/slot)
        // LI = fixed part (type + refs + class = 6) + params.
        $li = 6 + strlen($params);
        $cotp = chr($li) . "\xe0" . pack('n', $dstRef) . pack('n', $srcRef) . "\x00" . $params;

        return self::tpkt($cotp);
    }

    /** S7comm header for a Job/Userdata request (10 bytes). */
    private static function s7Header(int $rosctr, int $pduRef, int $paramLen, int $dataLen): string
    {
        return "\x32" . chr($rosctr) . "\x00\x00" . pack('n', $pduRef) . pack('n', $paramLen) . pack('n', $dataLen);
    }

    /** S7comm Setup Communication Job PDU (function 0xF0). */
    private static function setupCommunication(int $pduRef = 0x0100, int $reqPdu = 480): string
    {
        $param = "\xf0\x00" . pack('n', 1) . pack('n', 1) . pack('n', $reqPdu);

        return self::cotpData(self::s7Header(0x01, $pduRef, strlen($param), 0) . $param);
    }

    /**
     * A single S7ANY variable specification for Read/Write Var.
     */
    private static function s7AnyItem(int $transport, int $count, int $db, int $area, int $byte, int $bit = 0): string
    {
        $addr = ($byte << 3) | ($bit & 0x7);
        $body = "\x10" . chr($transport) . pack('n', $count) . pack('n', $db) . chr($area)
            . chr(($addr >> 16) & 0xFF) . chr(($addr >> 8) & 0xFF) . chr($addr & 0xFF);

        return "\x12" . chr(strlen($body)) . $body;
    }

    /**
     * Read Var Job PDU (function 0x04) reading one S7ANY item.
     */
    private static function readVar(int $transport, int $count, int $db, int $area, int $byte, int $bit = 0, int $pduRef = 0x0200): string
    {
        $item = self::s7AnyItem($transport, $count, $db, $area, $byte, $bit);
        $param = "\x04\x01" . $item; // function 0x04, item count 1

        return self::cotpData(self::s7Header(0x01, $pduRef, strlen($param), 0) . $param);
    }

    /**
     * Write Var Job PDU (function 0x05) writing one S7ANY item (the value is inert to the honeypot).
     */
    private static function writeVar(int $transport, int $count, int $db, int $area, int $byte, string $value, int $bit = 0, int $pduRef = 0x0300): string
    {
        $item = self::s7AnyItem($transport, $count, $db, $area, $byte, $bit);
        $param = "\x05\x01" . $item; // function 0x05, item count 1
        // Data item: return code 0x00, transport 0x04 (byte/word/dword), length in bits, value.
        $data = "\x00\x04" . pack('n', strlen($value) * 8) . $value;

        return self::cotpData(self::s7Header(0x01, $pduRef, strlen($param), strlen($data)) . $param . $data);
    }

    /**
     * Read SZL Userdata PDU for the given SZL-ID / index (CPU functions, subfunction Read SZL).
     */
    private static function readSzl(int $szlId, int $szlIndex = 0x0000, int $pduRef = 0x0400): string
    {
        // Userdata parameter: head(00 01 12), length(0x04), method(0x11 request), type|funcgroup
        // (0x44 = request + CPU functions), subfunc(0x01 read SZL), sequence(0x00).
        $param = "\x00\x01\x12\x04\x11\x44\x01\x00";
        // Data: return code 0xFF, transport 0x09 (octet string), length(4), SZL-ID(2), SZL-index(2).
        $data = "\xff\x09\x00\x04" . pack('n', $szlId) . pack('n', $szlIndex);

        return self::cotpData(self::s7Header(0x07, $pduRef, strlen($param), strlen($data)) . $param . $data);
    }
}
