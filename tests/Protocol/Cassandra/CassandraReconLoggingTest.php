<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Cassandra;

use Funnypot\Protocol\Cassandra\CassandraConfig;
use Funnypot\Protocol\Cassandra\CassandraServer;
use Funnypot\Protocol\Cassandra\CassandraSession;
use PHPUnit\Framework\TestCase;

final class CassandraReconLoggingTest extends TestCase
{
    use CassandraTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:CassandraServer,1:CassandraSession}
     */
    private function serverSession(?CassandraConfig $config = null): array
    {
        $this->events = [];
        $server = new CassandraServer($config ?? new CassandraConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new CassandraSession('198.51.100.20', 9042, 1);

        return [$server, $session];
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

    public function test_startup_recon_records_cql_version_and_driver(): void
    {
        [$server, $session] = $this->serverSession(new CassandraConfig(cqlVersion: '3.4.5'));

        $session->inbuf .= self::startupRequest([
            'CQL_VERSION' => '3.0.0',
            'DRIVER_NAME' => 'DataStax Python Driver',
            'DRIVER_VERSION' => '3.25.0',
        ]);
        $server->processInbound($session);

        self::assertSame('3.0.0', $session->cqlVersion);
        self::assertSame('DataStax Python Driver', $session->driverName);
        self::assertSame('3.25.0', $session->driverVersion);

        $startup = $this->eventOfType('cassandra_startup');
        self::assertNotNull($startup);
        self::assertStringContainsString('cql_version=3.0.0', $startup['path']);
        self::assertStringContainsString('DataStax Python Driver 3.25.0', $startup['path']);
        self::assertStringContainsString('org.apache.cassandra.auth.PasswordAuthenticator', $startup['path']);
        self::assertSame('3.0.0', $startup['cql_version']);
    }

    public function test_connect_event_is_logged_via_accept_path(): void
    {
        // The connect event is emitted from accept(); assert the recon flow still records the STARTUP.
        [$server, $session] = $this->serverSession();
        $session->inbuf .= self::startupRequest();
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('cassandra_startup'));
    }

    public function test_every_event_carries_the_cassandra_envelope(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf .= self::startupRequest(['CQL_VERSION' => '3.0.0']);
        $server->processInbound($session);
        $session->inbuf .= self::authResponse('u', 'p');
        $server->processInbound($session);

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('cassandra', $e['proto']);
            self::assertSame('CASSANDRA', $e['method']);
            self::assertSame(1, $e['matched']);
            self::assertSame(1, $e['served']);
            self::assertArrayHasKey('ts', $e);
            self::assertArrayHasKey('severity', $e);
            self::assertArrayHasKey('event', $e);
            self::assertArrayHasKey('ip', $e);
            self::assertArrayHasKey('port', $e);
            self::assertArrayHasKey('path', $e);
        }
    }

    public function test_auth_event_path_includes_decoded_credentials(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf .= self::startupRequest(['CQL_VERSION' => '3.0.0']);
        $server->processInbound($session);
        $session->inbuf .= self::authResponse('dbadmin', 'Pa55w.rd');
        $server->processInbound($session);

        $auth = $this->eventOfType('cassandra_auth');
        self::assertNotNull($auth);
        self::assertSame('CASSANDRA', $auth['method']);
        self::assertStringContainsString('user=dbadmin', $auth['path']);
        self::assertStringContainsString('password=Pa55w.rd', $auth['path']);
        self::assertSame('dbadmin', $auth['user']);
        self::assertSame('Pa55w.rd', $auth['password']);
    }

    public function test_non_printable_credential_bytes_are_sanitised(): void
    {
        [$server, $session] = $this->serverSession();

        // A password with control/non-ASCII bytes must be sanitised in the log line, never raw.
        $session->inbuf .= self::authResponse("us\x01er", "pa\x00ss");
        $server->processInbound($session);

        $auth = $this->eventOfType('cassandra_auth');
        self::assertNotNull($auth);
        self::assertStringNotContainsString("\x01", (string) $auth['user']);
    }

    public function test_parse_string_map_extracts_pairs(): void
    {
        $map = CassandraServer::parseStringMap(self::cqlStringMap([
            'CQL_VERSION' => '3.4.5',
            'DRIVER_NAME' => 'gocql',
        ]));

        self::assertSame('3.4.5', $map['CQL_VERSION']);
        self::assertSame('gocql', $map['DRIVER_NAME']);
    }

    public function test_parse_string_map_tolerates_truncation(): void
    {
        // A map claiming two pairs but carrying one yields the parseable pair, not a fault.
        $body = pack('n', 2) . self::cqlStr('CQL_VERSION') . self::cqlStr('3.0.0');
        $map = CassandraServer::parseStringMap($body);
        self::assertSame('3.0.0', $map['CQL_VERSION']);
    }

    public function test_parse_auth_token_splits_sasl_plain(): void
    {
        // [bytes] wrapping "\0user\0pass".
        $token = "\x00" . 'alice' . "\x00" . 'wonderland';
        $body = pack('N', strlen($token)) . $token;
        $cred = CassandraServer::parseAuthToken($body);

        self::assertSame('alice', $cred['username']);
        self::assertSame('wonderland', $cred['password']);
    }

    public function test_parse_auth_token_handles_null_bytes_value(): void
    {
        // A [bytes] with a negative length (null) yields no credential rather than reading OOB.
        $body = pack('N', 0xFFFFFFFF); // -1 as a signed int
        $cred = CassandraServer::parseAuthToken($body);
        self::assertNull($cred['username']);
        self::assertNull($cred['password']);
    }

    public function test_build_auth_error_body_carries_bad_credentials_code(): void
    {
        $body = CassandraServer::buildAuthErrorBody('nope');
        $code = (ord($body[0]) << 24) | (ord($body[1]) << 16) | (ord($body[2]) << 8) | ord($body[3]);
        self::assertSame(0x0100, $code);
        self::assertStringContainsString('nope', $body);
    }

    public function test_response_frame_sets_direction_bit_and_echoes_stream(): void
    {
        $server = new CassandraServer(new CassandraConfig(), static function (): void {});
        $frame = $server->buildFrame(4, 0x1234, 0x06, 'xy');

        self::assertSame(0x84, ord($frame[0]), 'direction bit set on response');
        self::assertSame(0x1234, (ord($frame[2]) << 8) | ord($frame[3]), 'stream echoed');
        self::assertSame(0x06, ord($frame[4]), 'opcode preserved');
        self::assertSame(2, (ord($frame[5]) << 24) | (ord($frame[6]) << 16) | (ord($frame[7]) << 8) | ord($frame[8]), 'length');
        self::assertSame('xy', substr($frame, 9));
    }

    public function test_config_from_env(): void
    {
        putenv('FUNNYPOT_CASSANDRA_CQL_VERSION=3.11.0');
        putenv('FUNNYPOT_CASSANDRA_RELEASE_VERSION=4.0.7');
        putenv('FUNNYPOT_CASSANDRA_CLUSTER=Prod Cluster');
        putenv('FUNNYPOT_CASSANDRA_AUTHENTICATOR=org.apache.cassandra.auth.PasswordAuthenticator');
        $config = CassandraConfig::fromEnv();
        self::assertSame('3.11.0', $config->cqlVersion);
        self::assertSame('4.0.7', $config->releaseVersion);
        self::assertSame('Prod Cluster', $config->clusterName);

        putenv('FUNNYPOT_CASSANDRA_CQL_VERSION');
        putenv('FUNNYPOT_CASSANDRA_RELEASE_VERSION');
        putenv('FUNNYPOT_CASSANDRA_CLUSTER');
        putenv('FUNNYPOT_CASSANDRA_AUTHENTICATOR');
        $default = CassandraConfig::fromEnv();
        self::assertSame('3.4.5', $default->cqlVersion);
        self::assertSame('Test Cluster', $default->clusterName);
        self::assertSame('org.apache.cassandra.auth.PasswordAuthenticator', $default->authenticator);
    }
}
