<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Oracle;

use Funnypot\Protocol\Oracle\OracleConfig;
use Funnypot\Protocol\Oracle\OracleServer;
use Funnypot\Protocol\Oracle\OracleSession;
use PHPUnit\Framework\TestCase;

final class OracleReconLoggingTest extends TestCase
{
    use OracleTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:OracleServer,1:OracleSession}
     */
    private function serverSession(?OracleConfig $config = null): array
    {
        $this->events = [];
        $server = new OracleServer($config ?? new OracleConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new OracleSession('198.51.100.20', 1521, 1);

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

    public function test_parse_connect_descriptor_extracts_all_fields(): void
    {
        $descriptor = '(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=10.0.0.5)(PORT=1521))'
            . '(CONNECT_DATA=(SERVICE_NAME=ORCL)(CID=(PROGRAM=sqlplus@kali)(HOST=kali)(USER=root))))';
        $intel = OracleServer::parseConnectDescriptor($descriptor);

        self::assertSame('ORCL', $intel['service']);
        self::assertNull($intel['sid']);
        self::assertSame('sqlplus@kali', $intel['program']);
        self::assertSame('kali', $intel['host'], 'HOST must be the CID host, not the ADDRESS host');
        self::assertSame('root', $intel['user']);
        self::assertNull($intel['command']);
    }

    public function test_host_and_user_are_scoped_to_the_cid_block(): void
    {
        // The ADDRESS block also carries a HOST (the listener's own host); it must not shadow the
        // client's announced HOST inside the CID.
        $descriptor = '(DESCRIPTION=(ADDRESS=(HOST=dbserver.internal)(PORT=1521))'
            . '(CONNECT_DATA=(SID=XE)(CID=(HOST=workstation-42)(USER=administrator))))';
        $intel = OracleServer::parseConnectDescriptor($descriptor);

        self::assertSame('workstation-42', $intel['host']);
        self::assertSame('administrator', $intel['user']);
        self::assertSame('XE', $intel['sid']);
    }

    public function test_service_name_preferred_over_bare_service_key(): void
    {
        // SERVICE_NAME must not be confused with the shorter SERVICE key, and vice versa.
        self::assertSame('ORCL', OracleServer::parseConnectDescriptor('(CONNECT_DATA=(SERVICE_NAME=ORCL))')['service']);
        self::assertSame('bar', OracleServer::parseConnectDescriptor('(CONNECT_DATA=(SERVICE=bar))')['service']);
    }

    public function test_command_probe_is_parsed(): void
    {
        $intel = OracleServer::parseConnectDescriptor('(CONNECT_DATA=(COMMAND=status))');
        self::assertSame('status', $intel['command']);
    }

    public function test_extract_descriptor_uses_length_and_offset(): void
    {
        $descriptor = '(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORCL)))';
        $packet = self::connectPacket($descriptor);

        self::assertSame($descriptor, OracleServer::extractDescriptor($packet));
    }

    public function test_extract_descriptor_falls_back_to_first_paren(): void
    {
        // A packet whose length/offset fields are zero still yields the descriptor via the fallback.
        $descriptor = '(DESCRIPTION=(CONNECT_DATA=(SID=XE)))';
        $packet = self::tnsHeader(0x01, 8 + 20 + strlen($descriptor)) . str_repeat("\x00", 20) . $descriptor;

        self::assertSame($descriptor, OracleServer::extractDescriptor($packet));
    }

    public function test_extract_descriptor_empty_when_no_descriptor(): void
    {
        $packet = self::tnsHeader(0x01, 8) ;
        self::assertSame('', OracleServer::extractDescriptor($packet));
    }

    public function test_every_event_carries_the_oracle_envelope(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf .= self::connectPacket('(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORCL)(CID=(USER=oracle))))');
        $server->processInbound($session);

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('oracle', $e['proto']);
            self::assertSame('ORACLE', $e['method']);
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

    public function test_connect_event_path_includes_sid_and_user(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf .= self::connectPacket('(DESCRIPTION=(CONNECT_DATA=(SID=PROD)(CID=(PROGRAM=metasploit)(USER=hacker))))');
        $server->processInbound($session);

        $connect = $this->eventOfType('oracle_connect');
        self::assertNotNull($connect);
        self::assertSame('high', $connect['severity']);
        self::assertSame('PROD', $connect['sid']);
        self::assertStringContainsString('sid=PROD', $connect['path']);
        self::assertStringContainsString('program=metasploit', $connect['path']);
        self::assertStringContainsString('user=hacker', $connect['path']);
    }

    public function test_bare_descriptor_without_target_is_medium_severity(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf .= self::connectPacket('(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=1.2.3.4)(PORT=1521)))');
        $server->processInbound($session);

        $connect = $this->eventOfType('oracle_connect');
        self::assertNotNull($connect);
        self::assertSame('medium', $connect['severity']);
    }

    public function test_attacker_supplied_control_bytes_are_sanitized_in_the_log(): void
    {
        [$server, $session] = $this->serverSession();

        $descriptor = "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=OR\x01\x02CL)(CID=(USER=r\x00oot))))";
        $session->inbuf .= self::connectPacket($descriptor);
        $server->processInbound($session);

        $connect = $this->eventOfType('oracle_connect');
        self::assertNotNull($connect);
        // Non-printable bytes are replaced so the event stream stays log-safe.
        self::assertDoesNotMatchRegularExpression('/[\x00-\x08\x0e-\x1f]/', $connect['path']);
    }

    public function test_config_from_env(): void
    {
        putenv('FUNNYPOT_ORACLE_VERSION=19.0.0.0.0');
        putenv('FUNNYPOT_ORACLE_ALIAS=PRODLSNR');
        putenv('FUNNYPOT_ORACLE_MODE=accept');
        $config = OracleConfig::fromEnv();
        self::assertSame('19.0.0.0.0', $config->version);
        self::assertSame('PRODLSNR', $config->alias);
        self::assertSame(OracleConfig::MODE_ACCEPT, $config->mode);

        putenv('FUNNYPOT_ORACLE_VERSION');
        putenv('FUNNYPOT_ORACLE_ALIAS');
        putenv('FUNNYPOT_ORACLE_MODE');
        $default = OracleConfig::fromEnv();
        self::assertSame('11.2.0.4.0', $default->version);
        self::assertSame('LISTENER', $default->alias);
        self::assertSame(OracleConfig::MODE_REFUSE, $default->mode);
    }

    public function test_invalid_mode_falls_back_to_refuse(): void
    {
        putenv('FUNNYPOT_ORACLE_MODE=bogus');
        self::assertSame(OracleConfig::MODE_REFUSE, OracleConfig::fromEnv()->mode);
        putenv('FUNNYPOT_ORACLE_MODE');
    }

    public function test_vsnnum_encoding_matches_known_versions(): void
    {
        self::assertSame(186647552, (new OracleConfig(version: '11.2.0.4.0'))->vsnnum());
        self::assertSame(186647040, (new OracleConfig(version: '11.2.0.2.0'))->vsnnum());
    }

    public function test_version_banner_carries_the_persona_version(): void
    {
        $config = new OracleConfig(version: '12.2.0.1.0');
        self::assertStringContainsString('12.2.0.1.0', $config->versionBanner());
    }
}
