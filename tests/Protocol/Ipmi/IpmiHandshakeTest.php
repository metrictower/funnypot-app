<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Ipmi;

use Funnypot\Protocol\Ipmi\IpmiConfig;
use Funnypot\Protocol\Ipmi\IpmiServer;
use Funnypot\Protocol\Ipmi\IpmiSession;
use PHPUnit\Framework\TestCase;

final class IpmiHandshakeTest extends TestCase
{
    use IpmiTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:IpmiServer,1:IpmiSession}
     */
    private function serverSession(?IpmiConfig $config = null): array
    {
        $this->events = [];
        $server = new IpmiServer($config ?? new IpmiConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new IpmiSession('192.0.2.10', 40123, 1);

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

    /** The 2's-complement checksum property: bytes plus their checksum sum to zero mod 256. */
    private static function sumMod256(string $bytes): int
    {
        $sum = 0;
        for ($i = 0, $n = strlen($bytes); $i < $n; $i++) {
            $sum += ord($bytes[$i]);
        }

        return $sum & 0xFF;
    }

    public function test_get_channel_auth_cap_is_parsed_and_captured(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::getChannelAuthCapDatagram();
        $server->processInbound($session);

        self::assertSame(0x00, $session->authType, 'IPMI 1.5 (auth none) session format');
        self::assertSame(0x06, $session->netFn, 'App network function');
        self::assertSame(0x38, $session->cmd, 'Get Channel Auth Cap command');

        $caps = $this->eventOfType('ipmi_auth_caps');
        self::assertNotNull($caps);
        self::assertStringContainsString('Get Channel Authentication Capabilities', $caps['path']);
        self::assertStringContainsString('ADMINISTRATOR', $caps['path']);
    }

    public function test_auth_cap_response_advertises_the_persona_and_is_wellformed(): void
    {
        $config = new IpmiConfig(channel: 1, authTypeSupport: 0x17, extCapabilities: 0x02);

        $resp = IpmiServer::buildGetChannelAuthCapResponse($config, 0x04);
        $parsed = IpmiServer::parseIpmi15($resp);

        self::assertNotNull($parsed);
        self::assertSame(0x07, $parsed['netFn'], 'App response network function');
        self::assertSame(0x38, $parsed['cmd']);
        $data = $parsed['data'];
        self::assertSame(9, strlen($data), 'completion code + 8 response data bytes');
        self::assertSame(0x00, ord($data[0]), 'completion code success');
        self::assertSame(0x01, ord($data[1]), 'channel echoed');
        self::assertSame(0x17, ord($data[2]), 'auth type support: none/MD2/MD5/straight');
        self::assertSame(0x02, ord($data[4]), 'extended capabilities: IPMI v2.0');
    }

    public function test_auth_cap_response_checksums_are_valid(): void
    {
        $resp = IpmiServer::buildGetChannelAuthCapResponse(new IpmiConfig(), 0x04);

        // Strip the RMCP(4) + session header(10) to reach the IPMI LAN message.
        $msg = substr($resp, 14);
        self::assertGreaterThanOrEqual(9, strlen($msg));

        // chk1 covers the first two bytes; chk2 covers from rsAddr through the last data byte.
        self::assertSame(0, self::sumMod256(substr($msg, 0, 3)), 'header checksum valid');
        self::assertSame(0, self::sumMod256(substr($msg, 3)), 'data checksum valid');
    }

    public function test_rakp1_username_is_parsed(): void
    {
        $datagram = self::rakp1Datagram('root', 4);
        $rmcpPlus = IpmiServer::parseRmcpPlus($datagram);

        self::assertNotNull($rmcpPlus);
        self::assertSame(0x12, $rmcpPlus['payloadType'], 'RAKP Message 1');

        $rakp1 = IpmiServer::parseRakp1($rmcpPlus['payload']);
        self::assertNotNull($rakp1);
        self::assertSame('root', $rakp1['username']);
        self::assertSame(4, $rakp1['priv']);
    }

    public function test_rakp2_reply_is_wellformed_when_it_fits(): void
    {
        $consoleSid = "\xc0\xc1\xc2\xc3";
        $resp = IpmiServer::buildRakp2(0, 0x00, $consoleSid, str_repeat("\x33", 16), str_repeat("\x44", 16), str_repeat("\x55", 20));

        $parsed = IpmiServer::parseRmcpPlus($resp);
        self::assertNotNull($parsed);
        self::assertSame(0x13, $parsed['payloadType'], 'RAKP Message 2');
        $p = $parsed['payload'];
        self::assertSame(60, strlen($p), 'tag+status+reserved+consoleSid+random+guid+authCode');
        self::assertSame(0x00, ord($p[1]), 'status: no errors');
        self::assertSame($consoleSid, substr($p, 4, 4), 'console session id echoed');
    }

    public function test_open_session_request_is_parsed(): void
    {
        $datagram = self::openSessionDatagram(1, 4, "\xd0\xd1\xd2\xd3");
        $rmcpPlus = IpmiServer::parseRmcpPlus($datagram);

        self::assertNotNull($rmcpPlus);
        self::assertSame(0x10, $rmcpPlus['payloadType'], 'Open Session Request');

        $os = IpmiServer::parseOpenSessionRequest($rmcpPlus['payload']);
        self::assertNotNull($os);
        self::assertSame(1, $os['tag']);
        self::assertSame(4, $os['maxPriv']);
        self::assertSame("\xd0\xd1\xd2\xd3", $os['consoleSessionId']);
    }

    public function test_get_session_challenge_username_is_parsed(): void
    {
        $parsed = IpmiServer::parseIpmi15(self::getSessionChallengeDatagram('operator'));
        self::assertNotNull($parsed);
        self::assertSame(0x39, $parsed['cmd']);

        $gsc = IpmiServer::parseGetSessionChallenge($parsed['data']);
        self::assertSame('operator', $gsc['username']);
        self::assertSame(0x02, $gsc['authType']);
    }
}
