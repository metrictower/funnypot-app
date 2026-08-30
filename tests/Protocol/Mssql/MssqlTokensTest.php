<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Mssql;

use Funnypot\Protocol\Mssql\MssqlConfig;
use Funnypot\Protocol\Mssql\MssqlTokens;
use PHPUnit\Framework\TestCase;

final class MssqlTokensTest extends TestCase
{
    use MssqlTestFrames;

    public function test_login_ack_token_shape(): void
    {
        $token = MssqlTokens::loginAck(new MssqlConfig(versionMajor: 15, versionMinor: 0, versionBuild: 2000));

        self::assertSame(0xAD, ord($token[0]), 'LOGINACK token id is 0xAD (not 0xAA)');
        $len = ord($token[1]) | (ord($token[2]) << 8);
        self::assertSame($len, strlen($token) - 3, 'the USHORT length covers the token data');
        // Interface byte 0x01, then TDSVersion little-endian 04 00 00 74 (TDS 7.4).
        self::assertSame(0x01, ord($token[3]));
        self::assertSame("\x04\x00\x00\x74", substr($token, 4, 4));
        // ProgName and ProgVersion (build 2000 = 0x07D0).
        self::assertStringContainsString(self::u16le('Microsoft SQL Server'), $token);
        self::assertStringContainsString("\x0f\x00\x07\xd0", $token, 'ProgVersion 15.0.2000');
    }

    public function test_env_change_login_records(): void
    {
        $env = MssqlTokens::envChangeLogin('master');
        // Three ENVCHANGE (0xE3) tokens: database, language, packet size.
        self::assertSame(0xE3, ord($env[0]));
        self::assertSame(3, substr_count($env, "\xE3"), 'a token id per record is present at minimum');
        self::assertStringContainsString(self::u16le('master'), $env);
        self::assertStringContainsString(self::u16le('us_english'), $env);
        self::assertStringContainsString(self::u16le('4096'), $env);
    }

    public function test_info_and_error_share_layout(): void
    {
        $info = MssqlTokens::info(5701, 2, 0, "Changed database context to 'master'.", 'SQL01');
        self::assertSame(0xAB, ord($info[0]), 'INFO token id 0xAB');
        self::assertStringContainsString(pack('V', 5701), $info);
        self::assertStringContainsString(self::u16le("Changed database context to 'master'."), $info);

        $err = MssqlTokens::error(18456, 1, 14, "Login failed for user 'sa'.", 'SQL01');
        self::assertSame(0xAA, ord($err[0]), 'ERROR token id 0xAA');
        self::assertStringContainsString(pack('V', 18456), $err);
    }

    public function test_colmetadata_and_row_and_null(): void
    {
        $meta = MssqlTokens::colMetadataNVarchar(['name', 'database_id']);
        self::assertSame(0x81, ord($meta[0]), 'COLMETADATA token id 0x81');
        self::assertSame(2, ord($meta[1]) | (ord($meta[2]) << 8), 'column count');
        self::assertStringContainsString("\xE7", $meta, 'NVARCHAR type byte present');
        self::assertStringContainsString(self::u16le('database_id'), $meta);

        $row = MssqlTokens::row(['master', '1']);
        self::assertSame(0xD1, ord($row[0]), 'ROW token id 0xD1');
        self::assertStringContainsString(self::u16le('master'), $row);

        // A NULL cell is the 0xFFFF charbin NULL.
        $nullRow = MssqlTokens::row([null]);
        self::assertSame("\xD1\xFF\xFF", $nullRow);
    }

    public function test_done_token(): void
    {
        $done = MssqlTokens::done(0x0010, 5);
        self::assertSame(0xFD, ord($done[0]));
        self::assertSame(13, strlen($done), 'DONE = token + status(2) + curcmd(2) + rowcount(8)');
        self::assertSame(0x0010, ord($done[1]) | (ord($done[2]) << 8));
        self::assertSame("\x05\x00\x00\x00\x00\x00\x00\x00", substr($done, 5, 8), 'ULONGLONG rowcount');
    }
}
