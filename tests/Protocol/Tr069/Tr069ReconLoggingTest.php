<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Tr069;

use Funnypot\Protocol\Tr069\Tr069Config;
use Funnypot\Protocol\Tr069\Tr069Server;
use Funnypot\Protocol\Tr069\Tr069Session;
use PHPUnit\Framework\TestCase;

/**
 * Every event carries the logEvent envelope (proto=cwmp, method=CWMP, matched/served, ts, severity),
 * recon captures the client fingerprint + SOAPAction, an Inform is parsed for the claimed identity, and
 * Tr069Config::fromEnv reads/defaults its persona.
 */
final class Tr069ReconLoggingTest extends TestCase
{
    use Tr069TestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:Tr069Server,1:Tr069Session}
     */
    private function serverSession(?Tr069Config $config = null): array
    {
        $this->events = [];
        $server = new Tr069Server($config ?? new Tr069Config(), function (array $e): void {
            $this->events[] = $e;
        });

        return [$server, new Tr069Session('198.51.100.44', 45001, 1)];
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

    public function test_every_event_carries_the_cwmp_envelope(): void
    {
        [$server, $session] = $this->serverSession();
        $session->inbuf = self::getParameterValuesRequest(['User-Agent' => 'Hakai/2.0']);
        $server->processInbound($session);

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('cwmp', $e['proto']);
            self::assertSame('CWMP', $e['method']);
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

    public function test_user_agent_and_soap_action_captured_on_probe(): void
    {
        [$server, $session] = $this->serverSession();
        $session->inbuf = self::setNtpServersRequest('pool.ntp.org', [
            'User-Agent' => 'Mozi/1.0',
        ]);
        $server->processInbound($session);

        $probe = $this->eventOfType('cwmp_probe');
        self::assertNotNull($probe);
        self::assertSame('Mozi/1.0', $probe['user_agent']);
        self::assertStringContainsString('SetNTPServers', $probe['soap_action']);
    }

    public function test_inform_records_device_identity_and_events(): void
    {
        [$server, $session] = $this->serverSession();
        $session->inbuf = self::informRequest('00AA11', 'Gateway-X', 'SN-12345');
        $server->processInbound($session);

        $inform = $this->eventOfType('cwmp_inform');
        self::assertNotNull($inform);
        self::assertSame('00AA11', $inform['oui']);
        self::assertSame('Gateway-X', $inform['product_class']);
        self::assertSame('SN-12345', $inform['serial']);
        self::assertStringContainsString('0 BOOTSTRAP', $inform['event_codes']);
        self::assertStringContainsString('1 BOOT', $inform['event_codes']);
        self::assertStringContainsString('InformResponse', $session->outbuf);
    }

    public function test_getparametervalues_is_a_recon_probe(): void
    {
        [$server, $session] = $this->serverSession();
        $session->inbuf = self::getParameterValuesRequest();
        $server->processInbound($session);

        $probe = $this->eventOfType('cwmp_probe');
        self::assertNotNull($probe);
        self::assertSame('GetParameterValues', $probe['rpc']);
    }

    public function test_config_from_env_reads_persona(): void
    {
        putenv('FUNNYPOT_CWMP_SERVER=RomPager/4.07 UPnP/1.0');
        putenv('FUNNYPOT_CWMP_MODEL=DSL-2750B');
        putenv('FUNNYPOT_CWMP_FIRMWARE=1.05');
        putenv('FUNNYPOT_CWMP_OUI=001B11');
        putenv('FUNNYPOT_CWMP_REALM=GatewayAuth');
        putenv('FUNNYPOT_CWMP_MODE=low');

        $config = Tr069Config::fromEnv();
        self::assertSame('DSL-2750B', $config->model);
        self::assertSame('1.05', $config->firmware);
        self::assertSame('001B11', $config->manufacturerOui);
        self::assertSame('GatewayAuth', $config->realm);
        self::assertSame(Tr069Config::MODE_LOW, $config->mode);

        foreach (['SERVER', 'MODEL', 'FIRMWARE', 'OUI', 'REALM', 'MODE'] as $k) {
            putenv('FUNNYPOT_CWMP_' . $k);
        }

        $default = Tr069Config::fromEnv();
        self::assertSame('VMG3312-B10A', $default->model);
        self::assertSame(Tr069Config::MODE_HIGH, $default->mode);
    }

    public function test_path_from_uri_variants(): void
    {
        self::assertSame('/UD/act', Tr069Server::pathFromUri('/UD/act?1'));
        self::assertSame('/cwmp', Tr069Server::pathFromUri('http://host:7547/cwmp'));
        self::assertSame('/', Tr069Server::pathFromUri('http://host:7547'));
    }

    public function test_malformed_request_parses_to_null(): void
    {
        self::assertNull(Tr069Server::parseRequest("NO-HTTP-LINE\r\n\r\n"));
        self::assertNull(Tr069Server::parseRequest(''));
    }
}
