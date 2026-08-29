<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Dnp3;

use Funnypot\Protocol\Dnp3\Dnp3Server;

/**
 * Byte builders for the DNP3 tests: the data-link frames and application fragments a SCADA scanner
 * (nmap dnp3-info, an ICS enumeration tool) sends — link-status / reset requests and READ / control
 * application requests. Frames are assembled through the server's own CRC helpers so the header and
 * per-block CRCs match what a real DNP3 receiver expects; a dedicated test pins the CRC value itself.
 */
trait Dnp3TestFrames
{
    /** A link-layer request frame (PRM=1, DIR=1 master-sourced) carrying no user data. */
    private static function linkRequest(int $func, int $dest = 1024, int $source = 5): string
    {
        $control = 0xC0 | ($func & 0x0F); // DIR=1, PRM=1

        return Dnp3Server::assembleFrame($control, $dest, $source, '');
    }

    /** A user-data frame wrapping an application fragment (UNCONFIRMED by default). */
    private static function appFrame(string $appPayload, int $dest = 1024, int $source = 5, bool $confirmed = false, int $transportSeq = 0): string
    {
        $transport = chr(0xC0 | ($transportSeq & 0x3F)); // FIR|FIN, single segment
        $userData = $transport . $appPayload;
        $control = 0xC0 | ($confirmed ? 0x03 : 0x04); // DIR=1, PRM=1, (un)confirmed user data

        return Dnp3Server::assembleFrame($control, $dest, $source, $userData);
    }

    /** The application header: FIR|FIN application control with a sequence, then the function code. */
    private static function appHeader(int $func, int $seq = 0): string
    {
        return chr(0xC0 | ($seq & 0x0F)) . chr($func);
    }

    /** An object header with qualifier 0x06 (all objects, no range) — how class reads are framed. */
    private static function objAll(int $group, int $var): string
    {
        return chr($group) . chr($var) . chr(0x06);
    }

    /** An object header with qualifier 0x00 (8-bit start/stop range). */
    private static function objRange8(int $group, int $var, int $start, int $stop): string
    {
        return chr($group) . chr($var) . chr(0x00) . chr($start) . chr($stop);
    }

    /** A class-0 poll: READ of group 60 variation 1, all objects. */
    private static function readClass0(int $dest = 1024, int $source = 5, int $seq = 0): string
    {
        return self::appFrame(self::appHeader(0x01, $seq) . self::objAll(60, 1), $dest, $source);
    }

    /** A READ of one object group over an 8-bit range. */
    private static function readRange(int $group, int $var, int $start, int $stop, int $dest = 1024, int $source = 5): string
    {
        return self::appFrame(self::appHeader(0x01) . self::objRange8($group, $var, $start, $stop), $dest, $source);
    }

    /** An arbitrary application-function frame carrying the given (already-encoded) object bytes. */
    private static function appFunc(int $func, string $objects = '', int $dest = 1024, int $source = 5): string
    {
        return self::appFrame(self::appHeader($func) . $objects, $dest, $source);
    }
}
