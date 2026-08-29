<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Oracle;

use Funnypot\Protocol\Oracle\OracleConfig;
use Funnypot\Protocol\Oracle\OracleServer;
use Funnypot\Protocol\Oracle\OracleSession;
use PHPUnit\Framework\TestCase;

final class OracleHandshakeTest extends TestCase
{
    use OracleTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    private function newServer(?OracleConfig $config = null): OracleServer
    {
        $this->events = [];

        return new OracleServer($config ?? new OracleConfig(), function (array $e): void {
            $this->events[] = $e;
        });
    }

    private function eventOfType(string $type): ?array
    {
        foreach ($this->events as $e) {
            if (($e['event'] ?? '') === $type) {
                return $e;
            }
        }

        return null;
    }

    public function test_connect_with_service_name_is_captured_and_refused(): void
    {
        $server = $this->newServer(new OracleConfig(version: '11.2.0.4.0'));
        $session = new OracleSession('203.0.113.9', 51000, 1);

        $descriptor = '(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=10.0.0.5)(PORT=1521))'
            . '(CONNECT_DATA=(SERVICE_NAME=ORCL)(CID=(PROGRAM=sqlplus)(HOST=attacker-pc)(USER=oracle))))';
        $session->inbuf .= self::connectPacket($descriptor);
        $server->processInbound($session);

        // --- captured intel on the session ---
        self::assertSame('ORCL', $session->service);
        self::assertNull($session->sid);
        self::assertSame('sqlplus', $session->program);
        self::assertSame('attacker-pc', $session->host);
        self::assertSame('oracle', $session->user);

        // --- connect event ---
        $connect = $this->eventOfType('oracle_connect');
        self::assertNotNull($connect);
        self::assertSame('high', $connect['severity']);
        self::assertSame('ORCL', $connect['service']);
        self::assertSame('oracle', $connect['user']);
        self::assertStringContainsString('service=ORCL', $connect['path']);
        self::assertStringContainsString('user=oracle', $connect['path']);

        // --- reply is a TNS REFUSE naming the unknown service; connection finished ---
        self::assertNotSame('', $session->outbuf, 'a refuse must be queued');
        self::assertSame(0x04, self::tnsType($session->outbuf), 'TNS REFUSE');
        self::assertStringContainsString('(ERR=12514)', $session->outbuf);
        self::assertStringContainsString('(CODE=12514)', $session->outbuf);
        self::assertTrue($session->close);
        self::assertSame(OracleSession::STATE_DONE, $session->state);
    }

    public function test_connect_with_sid_is_refused_with_12505(): void
    {
        $server = $this->newServer();
        $session = new OracleSession('203.0.113.9', 51000, 1);

        $descriptor = '(DESCRIPTION=(CONNECT_DATA=(SID=XE)(CID=(PROGRAM=jdbc)(USER=scott))))';
        $session->inbuf .= self::connectPacket($descriptor);
        $server->processInbound($session);

        self::assertSame('XE', $session->sid);
        self::assertNull($session->service);
        self::assertSame('scott', $session->user);

        self::assertSame(0x04, self::tnsType($session->outbuf));
        self::assertStringContainsString('(ERR=12505)', $session->outbuf, 'unknown SID error');
        self::assertTrue($session->close);
    }

    public function test_version_command_probe_returns_banner(): void
    {
        $server = $this->newServer(new OracleConfig(version: '11.2.0.4.0', alias: 'LISTENER'));
        $session = new OracleSession('198.51.100.7', 40000, 1);

        $session->inbuf .= self::commandPacket('version');
        $server->processInbound($session);

        $connect = $this->eventOfType('oracle_connect');
        self::assertNotNull($connect);
        self::assertSame('version', $connect['command']);
        self::assertStringContainsString('listener command: version', $connect['path']);

        // The reply is a TNS DATA packet leaking the persona version banner + VSNNUM.
        self::assertSame(0x06, self::tnsType($session->outbuf), 'TNS DATA');
        self::assertStringContainsString('11.2.0.4.0', $session->outbuf);
        self::assertStringContainsString('VSNNUM=186647552', $session->outbuf);
        self::assertStringContainsString('ALIAS=LISTENER', $session->outbuf);
        self::assertTrue($session->close);
    }

    public function test_ping_command_reports_alive(): void
    {
        $server = $this->newServer();
        $session = new OracleSession('198.51.100.7', 40001, 1);

        $session->inbuf .= self::commandPacket('ping');
        $server->processInbound($session);

        self::assertSame('ping', $this->eventOfType('oracle_connect')['command'] ?? null);
        // ping is answered with a refuse carrying ERR=0 (the listener is alive).
        self::assertSame(0x04, self::tnsType($session->outbuf));
        self::assertStringContainsString('(ERR=0)', $session->outbuf);
        self::assertTrue($session->close);
    }

    public function test_mutating_command_is_refused_as_unauthorized(): void
    {
        $server = $this->newServer();
        $session = new OracleSession('198.51.100.7', 40002, 1);

        $session->inbuf .= self::commandPacket('reload');
        $server->processInbound($session);

        self::assertSame('reload', $this->eventOfType('oracle_connect')['command'] ?? null);
        self::assertSame(0x04, self::tnsType($session->outbuf));
        self::assertStringContainsString('(ERR=1190)', $session->outbuf, 'command not authorized');
        self::assertTrue($session->close);
    }

    public function test_accept_mode_sends_accept_then_captures_native_data(): void
    {
        $server = $this->newServer(new OracleConfig(mode: OracleConfig::MODE_ACCEPT));
        $session = new OracleSession('192.0.2.10', 5000, 1);

        $descriptor = '(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORCL)(CID=(PROGRAM=nmap)(USER=root))))';
        $session->inbuf .= self::connectPacket($descriptor);
        $server->processInbound($session);

        self::assertSame(0x02, self::tnsType($session->outbuf), 'TNS ACCEPT');
        self::assertSame(OracleSession::STATE_ACCEPTED, $session->state);
        self::assertFalse($session->close);

        // A native follow-up (no readable descriptor) is captured as unmodelled and closes cleanly.
        $session->outbuf = '';
        $session->inbuf .= self::tnsHeader(0x06, 12) . "\x00\x00" . "\x01\x02\x03\x04";
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('oracle_unknown'));
        self::assertTrue($session->close);
        self::assertSame(OracleSession::STATE_DONE, $session->state);
    }

    public function test_resend_mode_asks_once_then_refuses(): void
    {
        $server = $this->newServer(new OracleConfig(mode: OracleConfig::MODE_RESEND));
        $session = new OracleSession('192.0.2.11', 5001, 1);

        $descriptor = '(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORCL)))';
        $connect = self::connectPacket($descriptor);

        $session->inbuf .= $connect;
        $server->processInbound($session);
        self::assertSame(0x0B, self::tnsType($session->outbuf), 'first reply is a TNS RESEND');
        self::assertFalse($session->close);
        self::assertSame(OracleSession::STATE_INIT, $session->state);

        // The resent CONNECT is refused rather than resending again.
        $session->outbuf = '';
        $session->inbuf .= $connect;
        $server->processInbound($session);
        self::assertSame(0x04, self::tnsType($session->outbuf), 'resent CONNECT is refused');
        self::assertTrue($session->close);
    }

    public function test_unknown_packet_type_closes_cleanly(): void
    {
        // A TLS ClientHello or junk opening byte is unmodelled: log and drop, never crash.
        $server = $this->newServer();
        $session = new OracleSession('192.0.2.1', 5000, 1);

        $session->inbuf .= self::tnsHeader(0x16, 12) . str_repeat("\x00", 4);
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('oracle_unknown'));
    }

    public function test_partial_packet_is_buffered_until_complete(): void
    {
        $server = $this->newServer();
        $session = new OracleSession('192.0.2.2', 5001, 1);

        $packet = self::connectPacket('(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORCL)))');

        // Feed only the header and a fragment: nothing should be parsed yet.
        $session->inbuf .= substr($packet, 0, 10);
        $server->processInbound($session);
        self::assertSame('', $session->outbuf);
        self::assertSame(OracleSession::STATE_INIT, $session->state);

        // Deliver the remainder: the CONNECT now parses and is answered.
        $session->inbuf .= substr($packet, 10);
        $server->processInbound($session);
        self::assertNotSame('', $session->outbuf);
        self::assertSame(0x04, self::tnsType($session->outbuf));
    }

    public function test_bad_packet_length_closes(): void
    {
        $server = $this->newServer();
        $session = new OracleSession('192.0.2.3', 5002, 1);

        // A declared length below the 8-byte header is impossible — log and close.
        $session->inbuf .= pack('n', 4) . pack('n', 0) . chr(0x01) . chr(0) . pack('n', 0);
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('oracle_unknown'));
    }

    public function test_never_serves_a_session_only_refuses_or_leaks_banner(): void
    {
        // Inert invariant: whatever the client sends, the reply is only ever a control packet
        // (REFUSE/ACCEPT/RESEND/DATA banner) — never a granted connection.
        $server = $this->newServer();
        $session = new OracleSession('203.0.113.50', 44444, 1);

        $session->inbuf .= self::connectPacket('(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=PROD)(CID=(USER=sys))))');
        $server->processInbound($session);

        self::assertSame(0x04, self::tnsType($session->outbuf));
        self::assertTrue($session->close);
        // No event ever claims a successful login/session.
        foreach ($this->events as $e) {
            self::assertNotSame('oracle_login', $e['event'] ?? '');
        }
    }
}
