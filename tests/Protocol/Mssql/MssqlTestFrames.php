<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Mssql;

/**
 * Byte builders for the MSSQL tests: TDS packet framing, a PRELOGIN request, and a LOGIN7 request
 * with a properly laid-out offset table and the obfuscated password a real client sends. Kept
 * minimal — just enough structure for the honeypot's parsers to exercise every field it reads.
 */
trait MssqlTestFrames
{
    /** Wraps a body in the 8-byte TDS packet header (type, status EOM, length big-endian). */
    private static function tdsPacket(int $type, string $body): string
    {
        $len = strlen($body) + 8;

        return chr($type) . chr(0x01) . pack('n', $len) . pack('n', 0) . chr(1) . chr(0) . $body;
    }

    /** ASCII string to UTF-16LE (null-interleaved). */
    private static function u16le(string $s): string
    {
        $out = '';
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $out .= $s[$i] . "\x00";
        }

        return $out;
    }

    /**
     * Obfuscates a plaintext password the way a real client does: UTF-16LE, then per byte
     * swap-nibbles(b) XOR 0xA5. The server reverses this to recover the cleartext.
     */
    private static function encodePassword(string $plain): string
    {
        $u = self::u16le($plain);
        $out = '';
        $len = strlen($u);
        for ($i = 0; $i < $len; $i++) {
            $b = ord($u[$i]);
            $b = (((($b << 4) & 0xF0) | (($b >> 4) & 0x0F)) ^ 0xA5) & 0xFF;
            $out .= chr($b);
        }

        return $out;
    }

    /** A TDS PRELOGIN request advertising a VERSION and the client's ENCRYPTION option. */
    private static function preloginRequest(int $encryption = 0x00): string
    {
        $version = "\x0b\x00\x10\xe0\x00\x00"; // arbitrary client version bytes
        $enc = chr($encryption);

        $offset = 2 * 5 + 1; // two option entries + terminator
        $tokens = chr(0x00) . pack('n', $offset) . pack('n', strlen($version));
        $offset += strlen($version);
        $tokens .= chr(0x01) . pack('n', $offset) . pack('n', 1);
        $tokens .= chr(0xFF); // terminator

        return self::tdsPacket(0x12, $tokens . $version . $enc);
    }

    /**
     * A TDS LOGIN7 request. Lays out the full offset table (fixed part 36 bytes + table 58 bytes)
     * with the string data beginning at offset 94, the password obfuscated as on the wire.
     */
    private static function login7Request(
        string $host,
        string $user,
        string $password,
        string $app,
        string $lib,
        string $database
    ): string {
        $hostU = self::u16le($host);
        $userU = self::u16le($user);
        $passObf = self::encodePassword($password);
        $appU = self::u16le($app);
        $libU = self::u16le($lib);
        $dbU = self::u16le($database);

        // Place the variable data starting at offset 94 and record each field's byte offset.
        $data = '';
        $place = static function (string $bytes) use (&$data): int {
            $ib = 94 + strlen($data);
            $data .= $bytes;

            return $ib;
        };
        $ibHost = $place($hostU);
        $ibUser = $place($userU);
        $ibPass = $place($passObf);
        $ibApp = $place($appU);
        $ibLib = $place($libU);
        $ibDb = $place($dbU);

        // Lengths in the table are UTF-16 character counts (ASCII here, so == strlen of the plaintext).
        $table = pack('v', $ibHost) . pack('v', strlen($host))
            . pack('v', $ibUser) . pack('v', strlen($user))
            . pack('v', $ibPass) . pack('v', strlen($password))
            . pack('v', $ibApp) . pack('v', strlen($app))
            . pack('v', 0) . pack('v', 0)            // ServerName (empty)
            . pack('v', 0) . pack('v', 0)            // Extension / Unused
            . pack('v', $ibLib) . pack('v', strlen($lib)) // CltIntName (client library)
            . pack('v', 0) . pack('v', 0)            // Language (empty)
            . pack('v', $ibDb) . pack('v', strlen($database))
            . str_repeat("\x00", 6)                  // ClientID (MAC)
            . pack('v', 0) . pack('v', 0)            // SSPI
            . pack('v', 0) . pack('v', 0)            // AtchDBFile
            . pack('v', 0) . pack('v', 0)            // ChangePassword
            . pack('V', 0);                          // cbSSPILong

        $recordLen = 94 + strlen($data);
        $fixed = pack('V', $recordLen)     // Length
            . pack('V', 0x74000004)        // TDSVersion (7.4)
            . pack('V', 4096)              // PacketSize
            . pack('V', 0x07000000)        // ClientProgVer
            . pack('V', 4321)              // ClientPID
            . pack('V', 0)                 // ConnectionID
            . chr(0) . chr(0) . chr(0) . chr(0) // OptionFlags1-3 + TypeFlags
            . pack('V', 0)                 // ClientTimeZone
            . pack('V', 0);                // ClientLCID

        return self::tdsPacket(0x10, $fixed . $table . $data);
    }

    /** Strips the 8-byte TDS header, returning the packet body. */
    private static function tdsBody(string $packet): string
    {
        return substr($packet, 8);
    }

    /** A TDS packet with an explicit status byte (0x01 = EOM; 0x00 = a non-final continuation packet). */
    private static function tdsPacketStatus(int $type, string $body, int $status): string
    {
        $len = strlen($body) + 8;

        return chr($type) . chr($status) . pack('n', $len) . pack('n', 0) . chr(1) . chr(0) . $body;
    }

    /**
     * The ALL_HEADERS block (MS-TDS 2.2.5.2) that prefixes a SQLBATCH/RPC body: a DWORD TotalLength
     * over a single 18-byte Transaction Descriptor header.
     */
    private static function allHeaders(): string
    {
        $hdr = pack('V', 18) . pack('v', 0x0002) . pack('P', 0) . pack('V', 1);

        return pack('V', strlen($hdr) + 4) . $hdr;
    }

    /** A SQLBATCH (0x01) request: ALL_HEADERS + the SQL text as UTF-16LE. */
    private static function sqlBatch(string $sql, bool $withHeaders = true): string
    {
        return self::tdsPacket(0x01, ($withHeaders ? self::allHeaders() : '') . self::u16le($sql));
    }

    /** An RPC (0x03) request calling sp_executesql (ProcID 10) with the statement as an NVARCHAR param. */
    private static function rpcExecuteSql(string $sql): string
    {
        $body = self::allHeaders()
            . pack('v', 0xFFFF) . pack('v', 10) . pack('v', 0) // ProcID sentinel, sp_executesql, OptionFlags
            . self::rpcNVarcharParam('', $sql);

        return self::tdsPacket(0x03, $body);
    }

    /** One NVARCHAR RPC parameter: name (B_VARCHAR), status, NVARCHAR type + collation, USHORT-length value. */
    private static function rpcNVarcharParam(string $name, string $value): string
    {
        $u = self::u16le($value);

        return chr(strlen($name)) . self::u16le($name)
            . chr(0)                        // status flags
            . chr(0xE7)                     // NVARCHARTYPE
            . pack('v', 8000)               // maxlen
            . "\x09\x04\xD0\x00\x34"        // collation
            . pack('v', strlen($u)) . $u;   // actual byte length + UTF-16LE value
    }
}
