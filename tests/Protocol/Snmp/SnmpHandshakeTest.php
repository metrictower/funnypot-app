<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Snmp;

use Funnypot\Protocol\Snmp\SnmpConfig;
use Funnypot\Protocol\Snmp\SnmpServer;
use Funnypot\Protocol\Snmp\SnmpSession;
use PHPUnit\Framework\TestCase;

final class SnmpHandshakeTest extends TestCase
{
    use SnmpTestFrames;

    private const OID_SYS_DESCR = '1.3.6.1.2.1.1.1.0';
    private const OID_SYS_OBJECT_ID = '1.3.6.1.2.1.1.2.0';

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
        $session = new SnmpSession('192.0.2.10', 43210, 1);

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

    public function test_get_request_is_parsed_and_community_and_oids_captured(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::getReq(1, 'public', 0x01020304, [self::OID_SYS_DESCR]);
        $server->processInbound($session);

        self::assertSame(1, $session->version);
        self::assertSame('public', $session->community);
        self::assertSame(0xA0, $session->pduTag);
        self::assertSame([self::OID_SYS_DESCR], $session->oids);

        $get = $this->eventOfType('snmp_get');
        self::assertNotNull($get);
        self::assertSame('public', $get['community']);
        self::assertStringContainsString(self::OID_SYS_DESCR, $get['oids']);
        self::assertStringContainsString('community=public', $get['path']);
        self::assertStringContainsString('GET', $get['path']);
    }

    public function test_build_response_returns_believable_sysdescr_for_get(): void
    {
        $config = new SnmpConfig(sysDescr: 'RouterOS RB750 6.48');
        [$server] = $this->serverSession($config);

        $req = SnmpServer::parseMessage(self::getReq(1, 'public', 0x11223344, [self::OID_SYS_DESCR]));
        self::assertNotNull($req);

        $resp = $server->buildResponse($req);
        $parsed = SnmpServer::parseMessage($resp);

        self::assertNotNull($parsed);
        self::assertSame(0xA2, $parsed['pduTag'], 'response PDU is GetResponse');
        self::assertSame(1, $parsed['version'], 'version echoed');
        self::assertSame('public', $parsed['community'], 'community echoed');
        self::assertSame($req['requestIdBytes'], $parsed['requestIdBytes'], 'request-id echoed byte-for-byte');
        self::assertSame(0, $parsed['field1'], 'error-status noError');
        self::assertSame([self::OID_SYS_DESCR], $parsed['oids']);
        self::assertStringContainsString('RouterOS RB750 6.48', $resp, 'the device sysDescr value is returned');
    }

    public function test_getnext_walks_from_group_prefix_to_sysdescr(): void
    {
        [$server] = $this->serverSession();

        // GETNEXT of the system group prefix must return the first leaf, sysDescr.0.
        $req = SnmpServer::parseMessage(self::getNextReq(1, 'public', 5, ['1.3.6.1.2.1.1']));
        self::assertNotNull($req);

        $parsed = SnmpServer::parseMessage($server->buildResponse($req));
        self::assertNotNull($parsed);
        self::assertSame([self::OID_SYS_DESCR], $parsed['oids'], 'GETNEXT returns the next OID name');
    }

    public function test_getnext_from_sysdescr_returns_sysobjectid(): void
    {
        [$server] = $this->serverSession();

        $req = SnmpServer::parseMessage(self::getNextReq(1, 'public', 6, [self::OID_SYS_DESCR]));
        self::assertNotNull($req);

        $parsed = SnmpServer::parseMessage($server->buildResponse($req));
        self::assertNotNull($parsed);
        self::assertSame([self::OID_SYS_OBJECT_ID], $parsed['oids']);
    }

    public function test_v1_get_of_unknown_oid_returns_nosuchname(): void
    {
        [$server] = $this->serverSession();

        $req = SnmpServer::parseMessage(self::getReq(0, 'public', 7, ['1.3.6.1.2.1.99.0']));
        self::assertNotNull($req);

        $parsed = SnmpServer::parseMessage($server->buildResponse($req));
        self::assertNotNull($parsed);
        self::assertSame(0xA2, $parsed['pduTag']);
        self::assertSame(2, $parsed['field1'], 'v1 error-status = noSuchName(2)');
    }

    public function test_v2c_get_of_unknown_oid_returns_nosuchobject_exception(): void
    {
        [$server] = $this->serverSession();

        $req = SnmpServer::parseMessage(self::getReq(1, 'public', 8, ['1.3.6.1.2.1.99.0']));
        self::assertNotNull($req);

        $resp = $server->buildResponse($req);
        $parsed = SnmpServer::parseMessage($resp);
        self::assertNotNull($parsed);
        self::assertSame(0, $parsed['field1'], 'v2c keeps error-status noError');
        // The varbind value is the noSuchObject exception (context tag 0x80, empty).
        self::assertStringContainsString("\x80\x00", $resp);
    }

    public function test_set_request_is_captured_high_severity_and_refused_inert(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::setReq(1, 'private', 9, ['1.3.6.1.2.1.1.5.0']);
        $server->processInbound($session);

        // Captured as a write attempt at high severity — but nothing is ever applied.
        $set = $this->eventOfType('snmp_set');
        self::assertNotNull($set);
        self::assertSame('high', $set['severity']);
        self::assertSame('private', $set['community']);

        // The response refuses the write: notWritable(17) under v2c.
        self::assertNotSame('', $session->outbuf);
        $parsed = SnmpServer::parseMessage($session->outbuf);
        self::assertNotNull($parsed);
        self::assertSame(0xA2, $parsed['pduTag']);
        self::assertSame(17, $parsed['field1'], 'v2c SET refused with notWritable(17)');
    }

    public function test_oid_encode_decode_roundtrip(): void
    {
        foreach ([self::OID_SYS_DESCR, '1.3.6.1.4.1.8072.3.2.10', '1.3.6.1.2.1.1'] as $oid) {
            self::assertSame($oid, SnmpServer::decodeOid(SnmpServer::encodeOid($oid)));
        }
    }
}
