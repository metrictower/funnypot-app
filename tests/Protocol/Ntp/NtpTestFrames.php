<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Ntp;

/**
 * Byte builders for the NTP tests: the 48-byte client/server packet and the tiny mode-6 / mode-7
 * abuse requests a scanner would send. Kept minimal — just enough structure for the honeypot's parser
 * to exercise every field it reads.
 */
trait NtpTestFrames
{
    /** Leading byte: LI(2) | VN(3) | Mode(3). */
    private static function leadByte(int $li, int $vn, int $mode): int
    {
        return (($li & 0x03) << 6) | (($vn & 0x07) << 3) | ($mode & 0x07);
    }

    /**
     * A full 48-byte NTP packet. Only the fields the honeypot reads are settable; everything else is
     * zero-filled. The transmit timestamp (t3) is placed at bytes 40-47.
     */
    private static function ntpPacket(
        int $vn,
        int $mode,
        int $txSeconds = 0,
        int $txFraction = 0,
        int $stratum = 0,
        int $poll = 0,
        int $precision = 0,
        int $li = 0
    ): string {
        $b0 = self::leadByte($li, $vn, $mode);

        // header(4) + rootDelay(4) + rootDisp(4) + refid(4) + refTs(8) + originate(8) + receive(8) = 40
        // bytes precede the transmit timestamp; only the header bytes carry test-set values.
        $head = chr($b0) . chr($stratum & 0xFF) . chr($poll & 0xFF) . chr($precision & 0xFF);
        $middle = str_repeat("\x00", 4 + 4 + 4 + 8 + 8 + 8); // through the receive timestamp
        $tx = pack('N', $txSeconds & 0xFFFFFFFF) . pack('N', $txFraction & 0xFFFFFFFF);

        return $head . $middle . $tx;
    }

    /** A normal mode-3 client time query. */
    private static function clientRequest(int $vn = 4, int $txSeconds = 0, int $txFraction = 0, int $poll = 0): string
    {
        return self::ntpPacket($vn, 3, $txSeconds, $txFraction, 0, $poll, 0);
    }

    /** A mode-7 (private) monlist request — the CVE-2013-5211 reflection vector. */
    private static function monlistRequest(int $reqCode = 42): string
    {
        // flags: VN 2, mode 7; then auth/seq=0, implementation=3 (IMPL_XNTPD), request code.
        return chr(self::leadByte(0, 2, 7)) . "\x00" . chr(3) . chr($reqCode & 0xFF) . str_repeat("\x00", 4);
    }

    /** A mode-6 (control) request — the other reflection vector. */
    private static function controlRequest(int $opcode = 2): string
    {
        // flags: VN 2, mode 6; then response/opcode byte (opcode in the low 5 bits).
        return chr(self::leadByte(0, 2, 6)) . chr($opcode & 0x1F) . str_repeat("\x00", 10);
    }

    /** Big-endian 32-bit read from a packet at $off. */
    private static function be32At(string $b, int $off): int
    {
        return (ord($b[$off]) << 24) | (ord($b[$off + 1]) << 16) | (ord($b[$off + 2]) << 8) | ord($b[$off + 3]);
    }
}
