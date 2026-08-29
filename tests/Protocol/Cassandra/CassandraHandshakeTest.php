<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Cassandra;

use Funnypot\Protocol\Cassandra\CassandraConfig;
use Funnypot\Protocol\Cassandra\CassandraServer;
use Funnypot\Protocol\Cassandra\CassandraSession;
use PHPUnit\Framework\TestCase;

final class CassandraHandshakeTest extends TestCase
{
    use CassandraTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    private function newServer(?CassandraConfig $config = null): CassandraServer
    {
        $this->events = [];

        return new CassandraServer($config ?? new CassandraConfig(), function (array $e): void {
            $this->events[] = $e;
        });
    }

    public function test_options_is_answered_with_supported(): void
    {
        $server = $this->newServer(new CassandraConfig(cqlVersion: '3.4.5'));
        $session = new CassandraSession('203.0.113.9', 51000, 1);

        $session->inbuf .= self::optionsRequest(4, 7);
        $server->processInbound($session);

        self::assertNotSame('', $session->outbuf, 'a SUPPORTED response must be queued');

        // Response direction bit set, opcode SUPPORTED (0x06), stream echoed.
        self::assertSame(0x84, self::frameVersion($session->outbuf), 'response version with direction bit');
        self::assertSame(0x06, self::frameOpcode($session->outbuf));
        self::assertSame(7, self::frameStream($session->outbuf), 'stream id echoed');

        // The advertised CQL version appears in the SUPPORTED multimap body.
        self::assertStringContainsString('3.4.5', self::frameBody($session->outbuf));
        self::assertStringContainsString('CQL_VERSION', self::frameBody($session->outbuf));

        // Not yet authenticated; connection stays open for STARTUP.
        self::assertFalse($session->close);
        self::assertSame(CassandraSession::STATE_INIT, $session->state);
    }

    public function test_startup_is_answered_with_authenticate(): void
    {
        $server = $this->newServer(new CassandraConfig());
        $session = new CassandraSession('203.0.113.9', 51000, 1);

        $session->inbuf .= self::startupRequest(['CQL_VERSION' => '3.0.0'], 4, 3);
        $server->processInbound($session);

        self::assertNotSame('', $session->outbuf, 'an AUTHENTICATE response must be queued');
        self::assertSame(0x03, self::frameOpcode($session->outbuf), 'AUTHENTICATE opcode');
        self::assertSame(3, self::frameStream($session->outbuf));
        self::assertSame(CassandraSession::STATE_AUTH, $session->state);

        // The AUTHENTICATE body names PasswordAuthenticator so the driver sends its credential.
        $body = self::frameBody($session->outbuf);
        $p = 0;
        $authClass = self::readCqlString($body, $p);
        self::assertSame('org.apache.cassandra.auth.PasswordAuthenticator', $authClass);
    }

    public function test_auth_response_captures_credentials_and_denies(): void
    {
        $server = $this->newServer(new CassandraConfig());
        $session = new CassandraSession('203.0.113.9', 51000, 1);

        // STARTUP first.
        $session->inbuf .= self::startupRequest(['CQL_VERSION' => '3.0.0'], 4, 1);
        $server->processInbound($session);
        $session->outbuf = '';

        // AUTH_RESPONSE with the SASL PLAIN credential.
        $session->inbuf .= self::authResponse('cassandra', 'S3cr3t!', 4, 1);
        $server->processInbound($session);

        // --- captured intel on the session ---
        self::assertSame('cassandra', $session->username);
        self::assertSame('S3cr3t!', $session->password);

        // --- auth event ---
        $auth = $this->eventOfType('cassandra_auth');
        self::assertNotNull($auth);
        self::assertSame('critical', $auth['severity']);
        self::assertSame('cassandra', $auth['user']);
        self::assertSame('S3cr3t!', $auth['password']);
        self::assertStringContainsString('user=cassandra', $auth['path']);
        self::assertStringContainsString('password=S3cr3t!', $auth['path']);

        // --- denied with an ERROR frame (bad credentials), connection finished ---
        self::assertSame(0x00, self::frameOpcode($session->outbuf), 'ERROR opcode');
        $body = self::frameBody($session->outbuf);
        self::assertSame(0x0100, (ord($body[0]) << 24) | (ord($body[1]) << 16) | (ord($body[2]) << 8) | ord($body[3]), 'bad-credentials code');

        self::assertTrue($session->close);
        self::assertSame(CassandraSession::STATE_DONE, $session->state);
    }

    public function test_auth_response_without_startup_is_still_captured(): void
    {
        // A tool that skips STARTUP and sends AUTH_RESPONSE directly must still have its credential
        // harvested (maximise intel, like the other emulators).
        $server = $this->newServer();
        $session = new CassandraSession('192.0.2.50', 60000, 1);

        $session->inbuf .= self::authResponse('admin', 'hunter2');
        $server->processInbound($session);

        self::assertSame('admin', $session->username);
        self::assertSame('hunter2', $session->password);
        self::assertNotNull($this->eventOfType('cassandra_auth'));
        self::assertTrue($session->close);
    }

    public function test_options_then_startup_then_auth_full_flow(): void
    {
        $server = $this->newServer();
        $session = new CassandraSession('198.51.100.7', 40000, 1);

        // A driver commonly opens with OPTIONS, then STARTUP, then AUTH_RESPONSE — pipelined here.
        $session->inbuf .= self::optionsRequest(4, 1);
        $session->inbuf .= self::startupRequest(['CQL_VERSION' => '3.4.5', 'DRIVER_NAME' => 'DataStax Python Driver'], 4, 2);
        $server->processInbound($session);
        $session->outbuf = '';

        $session->inbuf .= self::authResponse('root', 'toor', 4, 3);
        $server->processInbound($session);

        self::assertSame('root', $session->username);
        self::assertSame('toor', $session->password);
        self::assertNotNull($this->eventOfType('cassandra_startup'));
        self::assertNotNull($this->eventOfType('cassandra_auth'));
    }

    public function test_unknown_opcode_closes_cleanly(): void
    {
        // A QUERY (0x07) before auth is unmodelled: log and drop, never crash.
        $server = $this->newServer();
        $session = new CassandraSession('192.0.2.1', 5000, 1);

        $session->inbuf .= self::cqlFrame(4, 0x00, 1, 0x07, "\x00\x00\x00\x00");
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('cassandra_unknown'));
    }

    public function test_partial_frame_is_buffered_until_complete(): void
    {
        $server = $this->newServer();
        $session = new CassandraSession('192.0.2.2', 5001, 1);

        $startup = self::startupRequest(['CQL_VERSION' => '3.0.0']);
        // Feed only the header and a fragment: nothing should be parsed yet.
        $session->inbuf .= substr($startup, 0, 9);
        $server->processInbound($session);
        self::assertSame('', $session->outbuf);
        self::assertSame(CassandraSession::STATE_INIT, $session->state);

        // Deliver the remainder: the STARTUP now parses and is answered with AUTHENTICATE.
        $session->inbuf .= substr($startup, 9);
        $server->processInbound($session);
        self::assertNotSame('', $session->outbuf);
        self::assertSame(CassandraSession::STATE_AUTH, $session->state);
    }

    public function test_unsupported_protocol_version_closes(): void
    {
        // Protocol v2 (0x02) used a different fixed header; out of scope — log and close.
        $server = $this->newServer();
        $session = new CassandraSession('192.0.2.3', 5002, 1);

        $session->inbuf .= self::cqlFrame(2, 0x00, 1, 0x05, '');
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('cassandra_unknown'));
    }

    public function test_response_direction_frame_closes(): void
    {
        // A frame with the response direction bit set is not a valid request — log and close.
        $server = $this->newServer();
        $session = new CassandraSession('192.0.2.4', 5003, 1);

        $frame = self::cqlFrame(4, 0x00, 1, 0x05, '');
        $frame[0] = chr(0x84); // set the direction bit
        $session->inbuf .= $frame;
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('cassandra_unknown'));
    }

    public function test_oversize_frame_length_closes(): void
    {
        $server = $this->newServer();
        $session = new CassandraSession('192.0.2.5', 5004, 1);

        // A declared body length far beyond the buffer cap must log and close, not allocate.
        $session->inbuf .= chr(0x04) . chr(0x00) . pack('n', 1) . chr(0x01) . pack('N', 0x00100000);
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('cassandra_unknown'));
    }

    public function test_compressed_body_closes(): void
    {
        // We advertise no compression; a frame flagged compressed carries a body we cannot decode.
        $server = $this->newServer();
        $session = new CassandraSession('192.0.2.6', 5005, 1);

        $session->inbuf .= self::cqlFrame(4, 0x01, 1, 0x01, "\x00\x00\x00\x00");
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('cassandra_unknown'));
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
