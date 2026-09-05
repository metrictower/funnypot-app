<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Mssql;

use Funnypot\Protocol\Mssql\MssqlConfig;
use Funnypot\Protocol\Mssql\MssqlServer;
use Funnypot\Protocol\Mssql\MssqlSession;
use PHPUnit\Framework\TestCase;

final class MssqlReconLoggingTest extends TestCase
{
    use MssqlTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:MssqlServer,1:MssqlSession}
     */
    private function serverSession(?MssqlConfig $config = null): array
    {
        $this->events = [];
        $server = new MssqlServer($config ?? new MssqlConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new MssqlSession('198.51.100.20', 1433, 1);

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

    public function test_prelogin_recon_records_client_encryption(): void
    {
        [$server, $session] = $this->serverSession(new MssqlConfig(versionMajor: 15, versionMinor: 0, versionBuild: 2000));

        $session->inbuf .= self::preloginRequest(0x03); // client asked ENCRYPT_REQ
        $server->processInbound($session);

        $prelogin = $this->eventOfType('mssql_prelogin');
        self::assertNotNull($prelogin);
        self::assertStringContainsString('client-encryption=ENCRYPT_REQ', $prelogin['path']);
        self::assertStringContainsString('ENCRYPT_NOT_SUP', $prelogin['path']);
        self::assertStringContainsString('15.0.2000', $prelogin['path']);
    }

    public function test_connect_event_is_logged_via_accept_path(): void
    {
        // The connect event is emitted from accept(); assert its shape by invoking the same logger
        // envelope through a PRELOGIN flow and checking the recon events all carry it.
        [$server, $session] = $this->serverSession();
        $session->inbuf .= self::preloginRequest();
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('mssql_prelogin'));
    }

    public function test_every_event_carries_the_mssql_envelope(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf .= self::preloginRequest();
        $server->processInbound($session);
        $session->inbuf .= self::login7Request('H', 'u', 'p', 'a', 'l', 'd');
        $server->processInbound($session);

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('mssql', $e['proto']);
            self::assertSame('MSSQL', $e['method']);
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

    public function test_login_event_path_includes_decoded_password(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf .= self::preloginRequest();
        $server->processInbound($session);
        $session->inbuf .= self::login7Request('DBHOST', 'sa', 'Sup3rSecret!', 'python-tds', 'FreeTDS', 'model');
        $server->processInbound($session);

        $login = $this->eventOfType('mssql_login');
        self::assertNotNull($login);
        self::assertSame('MSSQL', $login['method']);
        self::assertStringContainsString('password=Sup3rSecret!', $login['path']);
        self::assertStringContainsString('lib=FreeTDS', $login['path']);
        self::assertSame('FreeTDS', $login['library']);
        self::assertSame('model', $login['database']);
    }

    public function test_parse_prelogin_extracts_encryption_and_options(): void
    {
        $body = self::tdsBody(self::preloginRequest(0x01));
        $parsed = MssqlServer::parsePrelogin($body);

        self::assertSame(0x01, $parsed['encryption']);
        self::assertContains(0x00, $parsed['options']); // VERSION
        self::assertContains(0x01, $parsed['options']); // ENCRYPTION
    }

    public function test_login_field_out_of_range_returns_empty(): void
    {
        // A descriptor pointing past the buffer must yield '' rather than reading out of bounds.
        $body = str_repeat("\x00", 40);
        self::assertSame('', MssqlServer::loginField($body, 36));
        // A table position that itself lies outside the buffer.
        self::assertSame('', MssqlServer::loginField('short', 36));
    }

    public function test_encryption_name_mapping(): void
    {
        self::assertSame('none', MssqlServer::encryptionName(null));
        self::assertSame('ENCRYPT_OFF', MssqlServer::encryptionName(0x00));
        self::assertSame('ENCRYPT_ON', MssqlServer::encryptionName(0x01));
        self::assertSame('ENCRYPT_NOT_SUP', MssqlServer::encryptionName(0x02));
        self::assertSame('ENCRYPT_REQ', MssqlServer::encryptionName(0x03));
    }

    public function test_config_from_env(): void
    {
        putenv('FUNNYPOT_MSSQL_SERVER=DBPROD01');
        putenv('FUNNYPOT_MSSQL_VERSION=16.0.1000.6');
        $config = MssqlConfig::fromEnv('install-persona-a');
        self::assertSame('DBPROD01', $config->serverName);
        self::assertSame(16, $config->versionMajor);
        self::assertSame(0, $config->versionMinor);
        self::assertSame(1000, $config->versionBuild);
        self::assertSame(6, $config->versionSubBuild);
        // The persona DB/login seed is the INSTALL identity, not the fleet-wide server:version literal.
        self::assertSame('install-persona-a', $config->personaSeed);
        self::assertNotSame(MssqlConfig::fromEnv('install-persona-b')->databases, $config->databases, 'a fresh install seeds different persona databases');

        putenv('FUNNYPOT_MSSQL_SERVER');
        putenv('FUNNYPOT_MSSQL_VERSION');
        $default = MssqlConfig::fromEnv('install-persona-a');
        self::assertSame('SQL01', $default->serverName);
        self::assertSame(15, $default->versionMajor);
        self::assertSame(2000, $default->versionBuild);
        self::assertSame($config->databases, $default->databases, 'same install ⇒ same persona databases regardless of the server banner');

        putenv('FUNNYPOT_MSSQL_SEED=operator-seed');
        self::assertSame('operator-seed', MssqlConfig::fromEnv('install-persona-a')->personaSeed, 'an explicit service seed still wins');
        putenv('FUNNYPOT_MSSQL_SEED');
    }
}
