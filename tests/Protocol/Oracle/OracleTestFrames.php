<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Oracle;

/**
 * Byte builders for the Oracle TNS tests: the 8-byte TNS header, a CONNECT packet whose connect
 * descriptor sits at the standard offset 58 with its length/offset fields filled in, and a listener
 * command probe. Kept minimal — just enough structure for the honeypot's parsers to exercise every
 * field they read.
 */
trait OracleTestFrames
{
    /** The 8-byte TNS header: length(2 BE), checksum(2), type(1), reserved(1), header checksum(2). */
    private static function tnsHeader(int $type, int $totalLen): string
    {
        return pack('n', $totalLen) . pack('n', 0) . chr($type) . chr(0) . pack('n', 0);
    }

    /**
     * A TNS CONNECT packet with the connect descriptor placed at offset 58, and the connect-data
     * length/offset fields set to point at it — the layout a standard Oracle client sends.
     */
    private static function connectPacket(string $descriptor): string
    {
        $body = pack('n', 0x013A)              // version
            . pack('n', 0x012C)               // version (compatible)
            . pack('n', 0x0000)               // service options
            . pack('n', 8192)                 // SDU
            . pack('n', 32767)                // TDU
            . pack('n', 0x4F98)               // NT protocol characteristics
            . pack('n', 0x0000)               // line turnaround
            . pack('n', 0x0001)               // value of 1 in hardware
            . pack('n', strlen($descriptor))  // connect data length
            . pack('n', 58)                   // connect data offset
            . pack('N', 0x00000000)           // max connect data receivable
            . chr(0x41) . chr(0x41)           // connect flags 0 / 1
            . pack('N', 0)                    // cross facility 0
            . pack('N', 0)                    // cross facility 1
            . str_repeat("\x00", 8)           // connection id 1
            . str_repeat("\x00", 8);          // connection id 2

        $total = 8 + strlen($body) + strlen($descriptor);

        return self::tnsHeader(0x01, $total) . $body . $descriptor;
    }

    /** A tnscmd/lsnrctl style control probe: a CONNECT whose connect data is a listener COMMAND. */
    private static function commandPacket(string $command): string
    {
        return self::connectPacket('(CONNECT_DATA=(COMMAND=' . $command . '))');
    }

    /** The TNS packet type byte (offset 4). */
    private static function tnsType(string $packet): int
    {
        return ord($packet[4]);
    }
}
