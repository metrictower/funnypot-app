<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Mssql;

/**
 * Pure encoders for the TDS response tokens (MS-TDS 2.2.7) the honeypot emits: LOGINACK, ENVCHANGE,
 * INFO/ERROR, COLMETADATA, ROW, RETURNSTATUS and DONE. Each method returns just the token bytes; the
 * server wraps them in the 8-byte TDS packet header (see {@see MssqlServer::tdsPacket()}).
 *
 * All multi-byte token fields are little-endian (only the packet-header length is big-endian). String
 * conventions: B_VARCHAR = 1-byte character count + UTF-16LE bytes; US_VARCHAR = USHORT character
 * count + UTF-16LE bytes. Persona/message text is ASCII, so a NUL-interleave is a sufficient UTF-16LE.
 */
final class MssqlTokens
{
    // Response token ids (MS-TDS 2.2.7).
    private const TOKEN_COLMETADATA = 0x81;
    private const TOKEN_ERROR = 0xAA;
    private const TOKEN_INFO = 0xAB;
    private const TOKEN_LOGINACK = 0xAD;
    private const TOKEN_ROW = 0xD1;
    private const TOKEN_ENVCHANGE = 0xE3;
    private const TOKEN_RETURNSTATUS = 0x79;
    private const TOKEN_DONE = 0xFD;

    // ENVCHANGE record types (MS-TDS 2.2.7.9).
    private const ENV_DATABASE = 0x01;
    private const ENV_LANGUAGE = 0x02;
    private const ENV_PACKETSIZE = 0x04;

    // Canonical 5-byte collation for SQL_Latin1_General_CP1_CI_AS (LCID 0x0409, sort id 0x34).
    private const COLLATION = "\x09\x04\xD0\x00\x34";

    /**
     * LOGINACK (0xAD): the token that tells a client the login succeeded. Interface 0x01 (SQL_TSQL),
     * the negotiated TDS version, the server program name and its version.
     */
    public static function loginAck(MssqlConfig $cfg): string
    {
        $data = chr(0x01)                        // Interface = SQL_TSQL
            . pack('V', 0x74000004)              // TDSVersion (LE) — wire bytes 04 00 00 74 = TDS 7.4
            . self::bVarchar('Microsoft SQL Server') // ProgName (authentic server ident, not a brand leak)
            . chr($cfg->versionMajor & 0xFF)
            . chr($cfg->versionMinor & 0xFF)
            . chr(($cfg->versionBuild >> 8) & 0xFF)
            . chr($cfg->versionBuild & 0xFF);

        return chr(self::TOKEN_LOGINACK) . pack('v', strlen($data)) . $data;
    }

    /**
     * The ENVCHANGE tokens sent on login: database context, language and packet size. Emitted as three
     * separate 0xE3 tokens (one record each) exactly as a real server does.
     */
    public static function envChangeLogin(string $database): string
    {
        return self::envRecord(self::ENV_DATABASE, $database, '')
            . self::envRecord(self::ENV_LANGUAGE, 'us_english', '')
            . self::envRecord(self::ENV_PACKETSIZE, '4096', '4096');
    }

    /** A single ENVCHANGE (0xE3) token: type, then New and Old values as B_VARCHAR. */
    public static function envRecord(int $type, string $new, string $old): string
    {
        $data = chr($type) . self::bVarchar($new) . self::bVarchar($old);

        return chr(self::TOKEN_ENVCHANGE) . pack('v', strlen($data)) . $data;
    }

    /** INFO (0xAB): an informational message (class 0). */
    public static function info(int $number, int $state, int $class, string $msg, string $server, int $line = 1): string
    {
        return self::message(self::TOKEN_INFO, $number, $state, $class, $msg, $server, $line);
    }

    /** ERROR (0xAA): a fatal message (class >= 11); identical layout to INFO. */
    public static function error(int $number, int $state, int $class, string $msg, string $server, int $line = 1): string
    {
        return self::message(self::TOKEN_ERROR, $number, $state, $class, $msg, $server, $line);
    }

    /**
     * COLMETADATA (0x81) describing N nvarchar(4000) columns — one row encoder covers every recon
     * answer because tools render nvarchar generically.
     *
     * @param list<string> $names
     */
    public static function colMetadataNVarchar(array $names): string
    {
        $out = chr(self::TOKEN_COLMETADATA) . pack('v', count($names));
        foreach ($names as $name) {
            $out .= pack('V', 0)          // UserType
                . pack('v', 0x0009)       // Flags (nullable)
                . chr(0xE7)               // TYPE = NVARCHARTYPE
                . pack('v', 8000)         // maxlen in bytes (nvarchar(4000))
                . self::COLLATION         // 5-byte collation
                . self::bVarchar($name);  // ColName
        }

        return $out;
    }

    /**
     * ROW (0xD1) for an all-nvarchar row. A null cell is the 0xFFFF charbin NULL; otherwise a USHORT
     * byte length precedes the UTF-16LE bytes.
     *
     * @param list<?string> $values
     */
    public static function row(array $values): string
    {
        $out = chr(self::TOKEN_ROW);
        foreach ($values as $v) {
            if ($v === null) {
                $out .= pack('v', 0xFFFF);
                continue;
            }
            $bytes = self::utf16le($v);
            $out .= pack('v', strlen($bytes)) . $bytes;
        }

        return $out;
    }

    /** RETURNSTATUS (0x79): the return code of a stored procedure (0 = success). */
    public static function returnStatus(int $status): string
    {
        return chr(self::TOKEN_RETURNSTATUS) . pack('V', $status);
    }

    /**
     * DONE (0xFD): Status, CurCmd, DoneRowCount (ULONGLONG for TDS 7.2+). A result set closes with
     * status DONE_COUNT (0x0010) and a row count; a message-only reply closes with 0x0000 and 0.
     */
    public static function done(int $status, int $rowCount): string
    {
        return chr(self::TOKEN_DONE)
            . pack('v', $status)
            . pack('v', 0)          // CurCmd
            . pack('P', $rowCount); // ULONGLONG
    }

    // ---- Internal helpers --------------------------------------------------------------------

    private static function message(int $tokenId, int $number, int $state, int $class, string $msg, string $server, int $line): string
    {
        $data = pack('V', $number)
            . chr($state & 0xFF)
            . chr($class & 0xFF)
            . self::usVarchar($msg)     // MsgText
            . self::bVarchar($server)   // ServerName
            . chr(0)                    // ProcName (empty)
            . pack('V', $line);         // LineNumber

        return chr($tokenId) . pack('v', strlen($data)) . $data;
    }

    /** B_VARCHAR: 1-byte character count + UTF-16LE bytes. */
    private static function bVarchar(string $s): string
    {
        return chr(strlen($s) & 0xFF) . self::utf16le($s);
    }

    /** US_VARCHAR: USHORT character count + UTF-16LE bytes. */
    private static function usVarchar(string $s): string
    {
        return pack('v', strlen($s)) . self::utf16le($s);
    }

    /** ASCII string to UTF-16LE (NUL-interleave; persona text is ASCII, so no mbstring dependency). */
    private static function utf16le(string $s): string
    {
        $out = '';
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $out .= $s[$i] . "\x00";
        }

        return $out;
    }
}
