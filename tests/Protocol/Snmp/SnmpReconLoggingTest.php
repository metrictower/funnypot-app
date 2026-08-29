<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Snmp;

use Funnypot\Protocol\Snmp\SnmpConfig;
use Funnypot\Protocol\Snmp\SnmpServer;
use Funnypot\Protocol\Snmp\SnmpSession;
use PHPUnit\Framework\TestCase;

final class SnmpReconLoggingTest extends TestCase
{
    use SnmpTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:SnmpServer,1:SnmpSession}
     */
    private function serverSession(?SnmpConfig $config = null): array
    {
        $this->events = [];
        $server = new SnmpServer($config ?? new SnmpConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new SnmpSession('198.51.100.7', 161, 1);

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

    public function test_every_event_carries_the_snmp_envelope(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::getReq(1, 'public', 1, ['1.3.6.1.2.1.1.1.0']);
        $server->processInbound($session);

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('snmp', $e['proto']);
            self::assertSame('SNMP', $e['method']);
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

    public function test_private_community_is_captured_at_high_severity(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::getReq(1, 'private', 2, ['1.3.6.1.2.1.1.5.0']);
        $server->processInbound($session);

        $get = $this->eventOfType('snmp_get');
        self::assertNotNull($get);
        self::assertSame('private', $get['community']);
        self::assertSame('high', $get['severity']);
    }

    public function test_response_never_exceeds_request_datagram(): void
    {
        // A tiny GET whose believable response would be larger must be capped so it can never amplify.
        [$server, $session] = $this->serverSession();

        $req = self::getReq(1, 'public', 3, ['1.3.6.1.2.1.1.1.0']);
        $session->inbuf = $req;
        $server->processInbound($session);

        self::assertNotSame('', $session->outbuf, 'a valid GET is still answered');
        self::assertLessThanOrEqual(
            strlen($req),
            strlen($session->outbuf),
            'anti-amplification: the reply is never larger than the request'
        );
    }

    public function test_getbulk_is_not_expanded_into_a_table(): void
    {
        [$server] = $this->serverSession();

        // A single-varbind GETBULK asking for 1000 repetitions must NOT return 1000 rows.
        $req = SnmpServer::parseMessage(self::getBulkReq(1, 'public', 4, 0, 1000, ['1.3.6.1.2.1.1']));
        self::assertNotNull($req);

        $resp = $server->buildResponse($req);
        $parsed = SnmpServer::parseMessage($resp);
        self::assertNotNull($parsed);
        self::assertCount(1, $parsed['oids'], 'GETBULK repetition count is ignored (single GETNEXT)');
    }

    public function test_getbulk_reply_on_the_wire_is_capped_to_request_size(): void
    {
        [$server, $session] = $this->serverSession();

        $req = self::getBulkReq(1, 'public', 5, 0, 5000, ['1.3.6.1.2.1.1']);
        $session->inbuf = $req;
        $server->processInbound($session);

        self::assertLessThanOrEqual(strlen($req), strlen($session->outbuf));

        $get = $this->eventOfType('snmp_get');
        self::assertNotNull($get);
        self::assertStringContainsString('GETBULK', $get['path']);
    }

    public function test_unparseable_datagram_logs_unknown_and_sends_nothing(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = "\x30\x82\xFF\xFFnot-real-ber";
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('snmp_unknown'));
        self::assertSame('', $session->outbuf);
    }

    public function test_non_request_pdu_is_recorded_without_reply(): void
    {
        [$server, $session] = $this->serverSession();

        // A GetResponse (0xA2) inbound is not a request — never reply (no reflection primitive).
        $session->inbuf = self::request(0xA2, 1, 'public', 6, ['1.3.6.1.2.1.1.1.0']);
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('snmp_unknown'));
        self::assertSame('', $session->outbuf);
    }

    public function test_unsupported_version_is_recorded_without_reply(): void
    {
        [$server, $session] = $this->serverSession();

        // SNMPv3 (version field = 3) is out of scope: record the probe, never reply.
        $session->inbuf = self::getReq(3, 'public', 7, ['1.3.6.1.2.1.1.1.0']);
        $server->processInbound($session);

        $unknown = $this->eventOfType('snmp_unknown');
        self::assertNotNull($unknown);
        self::assertStringContainsString('version 3', $unknown['path']);
        self::assertSame('', $session->outbuf);
    }

    public function test_config_from_env_reads_persona(): void
    {
        putenv('FUNNYPOT_SNMP_SYSNAME=core-sw-01');
        putenv('FUNNYPOT_SNMP_SYSDESCR=Cisco IOS Software');
        putenv('FUNNYPOT_SNMP_UPTIME_SECONDS=3600');

        $config = SnmpConfig::fromEnv();
        self::assertSame('core-sw-01', $config->sysName);
        self::assertSame('Cisco IOS Software', $config->sysDescr);
        // ~3600s of uptime => ~360000 TimeTicks; allow slack for wall-clock drift during the test.
        self::assertGreaterThanOrEqual(360000, $config->sysUpTimeTicks());
        self::assertLessThan(370000, $config->sysUpTimeTicks());

        putenv('FUNNYPOT_SNMP_SYSNAME');
        putenv('FUNNYPOT_SNMP_SYSDESCR');
        putenv('FUNNYPOT_SNMP_UPTIME_SECONDS');
    }
}
