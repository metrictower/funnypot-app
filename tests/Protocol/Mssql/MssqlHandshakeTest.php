<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Mssql;

use Funnypot\Protocol\Mssql\MssqlConfig;
use Funnypot\Protocol\Mssql\MssqlServer;
use Funnypot\Protocol\Mssql\MssqlSession;
use PHPUnit\Framework\TestCase;

final class MssqlHandshakeTest extends TestCase
{
    use MssqlTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    private function newServer(?MssqlConfig $config = null): MssqlServer
    {
        $this->events = [];

        return new MssqlServer($config ?? new MssqlConfig(), function (array $e): void {
            $this->events[] = $e;
        });
    }

    public function test_prelogin_is_answered_advertising_encrypt_not_sup(): void
    {
        $server = $this->newServer(new MssqlConfig(serverName: 'SQL01', versionMajor: 15, versionMinor: 0, versionBuild: 2000));
        $session = new MssqlSession('203.0.113.9', 51000, 1);

        $session->inbuf .= self::preloginRequest(0x00); // client offered ENCRYPT_OFF
        $server->processInbound($session);

        self::assertNotSame('', $session->outbuf, 'a PRELOGIN response must be queued');
        self::assertSame(MssqlSession::STATE_LOGIN, $session->state);

        // The response body parses back as a PRELOGIN whose ENCRYPTION option is ENCRYPT_NOT_SUP (2).
        $body = self::tdsBody($session->outbuf);
        $parsed = MssqlServer::parsePrelogin($body);
        self::assertSame(0x02, $parsed['encryption'], 'server must advertise ENCRYPT_NOT_SUP');

        // The advertised version bytes appear in the response.
        self::assertStringContainsString("\x0f\x00\x07\xd0", $body, 'advertised version 15.0.2000');
    }

    public function test_login7_captures_credentials_and_denies(): void
    {
        $server = $this->newServer(new MssqlConfig(serverName: 'SQL01', interaction: 'low'));
        $session = new MssqlSession('203.0.113.9', 51000, 1);

        // PRELOGIN first.
        $session->inbuf .= self::preloginRequest();
        $server->processInbound($session);
        $session->outbuf = '';

        // LOGIN7 with the credential material.
        $session->inbuf .= self::login7Request(
            host: 'ATTACKER-PC',
            user: 'sa',
            password: 'P@ssw0rd!',
            app: 'sqlcmd',
            lib: 'ODBC',
            database: 'master'
        );
        $server->processInbound($session);

        // --- captured intel on the session ---
        self::assertSame('sa', $session->username);
        self::assertSame('P@ssw0rd!', $session->password);
        self::assertSame('ATTACKER-PC', $session->hostname);
        self::assertSame('sqlcmd', $session->appName);
        self::assertSame('ODBC', $session->libName);
        self::assertSame('master', $session->database);

        // --- login event ---
        $login = $this->eventOfType('mssql_login');
        self::assertNotNull($login);
        self::assertSame('critical', $login['severity']);
        self::assertSame('sa', $login['user']);
        self::assertSame('P@ssw0rd!', $login['password']);
        self::assertStringContainsString('user=sa', $login['path']);
        self::assertStringContainsString('host=ATTACKER-PC', $login['path']);
        self::assertStringContainsString('app=sqlcmd', $login['path']);
        self::assertStringContainsString('password=P@ssw0rd!', $login['path']);

        // --- logon denied with a TDS ERROR token, connection finished ---
        $body = self::tdsBody($session->outbuf);
        self::assertSame(0xAA, ord($body[0]), 'TDS ERROR token');
        // The error number (18456) and the login-failed message are present.
        self::assertStringContainsString(pack('V', 18456), $body);
        $msg = (string) mb_convert_encoding("Login failed for user 'sa'.", 'UTF-16LE', 'UTF-8');
        self::assertStringContainsString($msg, $body);
        // A DONE token follows the ERROR token.
        self::assertStringContainsString(chr(0xFD), $body);

        self::assertTrue($session->close);
        self::assertSame(MssqlSession::STATE_DONE, $session->state);
    }

    public function test_high_mode_accepts_login_and_keeps_session_open(): void
    {
        // Default (high) mode: the login is accepted (mock-auth) and the session stays open.
        $server = $this->newServer(new MssqlConfig(serverName: 'SQL01')); // interaction defaults to high
        $session = new MssqlSession('203.0.113.9', 51000, 1);

        $session->inbuf .= self::preloginRequest();
        $server->processInbound($session);
        $session->outbuf = '';

        $session->inbuf .= self::login7Request('ATTACKER-PC', 'sa', 'sa', 'sqlcmd', 'ODBC', 'master');
        $server->processInbound($session);

        // The credential is still captured.
        self::assertNotNull($this->eventOfType('mssql_login'));
        self::assertSame('sa', $session->username);

        // A login-success token stream is queued: LOGINACK (0xAD), not an ERROR (0xAA).
        $body = self::tdsBody($session->outbuf);
        self::assertSame(0xAD, ord($body[0]), 'first token must be LOGINACK 0xAD');
        self::assertNotSame(0xAA, ord($body[0]), 'high mode must not send an ERROR token');
        // ProgName the client reads back.
        self::assertStringContainsString(self::u16le('Microsoft SQL Server'), $body);
        // ENVCHANGE (0xE3) and DONE (0xFD) are present.
        self::assertStringContainsString(chr(0xE3), $body);
        self::assertSame(0xFD, ord(substr($body, -13, 1)), 'stream ends with a DONE token');

        // The session is authenticated and NOT closed.
        self::assertSame(MssqlSession::STATE_SESSION, $session->state);
        self::assertFalse($session->close);
        self::assertSame('sa', $session->authUser);
        self::assertSame('master', $session->currentDb);
    }

    public function test_login7_without_prelogin_is_still_captured(): void
    {
        // A tool that skips PRELOGIN and sends LOGIN7 directly must still have its credential harvested.
        $server = $this->newServer(new MssqlConfig(interaction: 'low'));
        $session = new MssqlSession('192.0.2.50', 60000, 1);

        $session->inbuf .= self::login7Request('WS1', 'admin', 'hunter2', 'GoSqlClient', 'go-mssqldb', 'tempdb');
        $server->processInbound($session);

        self::assertSame('admin', $session->username);
        self::assertSame('hunter2', $session->password);
        self::assertNotNull($this->eventOfType('mssql_login'));
        self::assertTrue($session->close);
    }

    public function test_password_deobfuscation_round_trips(): void
    {
        // The obfuscation is reversible: swap-nibbles(b) XOR 0xA5 on encode, XOR then swap on decode.
        foreach (['', 'a', 'P@ssw0rd!', 'Aa1!zZ9~', 'longer-password-1234567890'] as $plain) {
            $obf = self::encodePassword($plain);
            self::assertSame($plain, MssqlServer::decodePassword($obf));
        }
    }

    public function test_unknown_tds_type_closes_cleanly(): void
    {
        // A client that opens with a TLS ClientHello (0x16) instead of PRELOGIN is unmodelled: log
        // and drop, never crash.
        $server = $this->newServer();
        $session = new MssqlSession('192.0.2.1', 5000, 1);

        $session->inbuf .= self::tdsPacket(0x16, str_repeat("\x00", 40));
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('mssql_unknown'));
    }

    public function test_partial_tds_packet_is_buffered_until_complete(): void
    {
        $server = $this->newServer();
        $session = new MssqlSession('192.0.2.2', 5001, 1);

        $prelogin = self::preloginRequest();
        // Feed only the header and a fragment: nothing should be parsed yet.
        $session->inbuf .= substr($prelogin, 0, 6);
        $server->processInbound($session);
        self::assertSame('', $session->outbuf);
        self::assertSame(MssqlSession::STATE_PRELOGIN, $session->state);

        // Deliver the remainder: the PRELOGIN now parses and is answered.
        $session->inbuf .= substr($prelogin, 6);
        $server->processInbound($session);
        self::assertNotSame('', $session->outbuf);
        self::assertSame(MssqlSession::STATE_LOGIN, $session->state);
    }

    public function test_bad_packet_length_closes(): void
    {
        $server = $this->newServer();
        $session = new MssqlSession('192.0.2.3', 5002, 1);

        // A declared length below the 8-byte header is impossible — log and close.
        $session->inbuf .= chr(0x12) . chr(0x01) . pack('n', 4) . pack('n', 0) . chr(1) . chr(0);
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('mssql_unknown'));
    }

    /**
     * @return array<string,mixed>|null
     */
    private function eventOfType(string $type): ?array
    {
        foreach ($this->events as $e) {
            if (($e['event'] ?? '') === $type) {
                return $e;
            }
        }

        return null;
    }
}
