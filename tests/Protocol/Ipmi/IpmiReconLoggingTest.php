<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Ipmi;

use Funnypot\Protocol\Ipmi\IpmiConfig;
use Funnypot\Protocol\Ipmi\IpmiServer;
use Funnypot\Protocol\Ipmi\IpmiSession;
use PHPUnit\Framework\TestCase;

final class IpmiReconLoggingTest extends TestCase
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
        $session = new IpmiSession('198.51.100.7', 623, 1);

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

    public function test_every_event_carries_the_ipmi_envelope(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::getChannelAuthCapDatagram();
        $server->processInbound($session);

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('ipmi', $e['proto']);
            self::assertSame('IPMI', $e['method']);
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

    public function test_rakp1_username_captured_as_high_severity_intel(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::rakp1Datagram('admin');
        $server->processInbound($session);

        self::assertSame('admin', $session->username, 'the harvested username is held on the session');

        $rakp = $this->eventOfType('ipmi_rakp');
        self::assertNotNull($rakp);
        self::assertSame('admin', $rakp['username']);
        self::assertSame('high', $rakp['severity']);
        self::assertStringContainsString('RAKP Message 1', $rakp['path']);
    }

    public function test_rakp1_is_inert_and_never_authenticates(): void
    {
        // A minimal RAKP Message 1 is answered by nothing on the wire (the RAKP2 reply is larger than
        // the request, so the anti-amplification cap drops it) — but the username is still captured.
        [$server, $session] = $this->serverSession();

        $req = self::rakp1Datagram('admin');
        $session->inbuf = $req;
        $server->processInbound($session);

        self::assertLessThanOrEqual(strlen($req), strlen($session->outbuf), 'anti-amplification holds');
        self::assertNotNull($this->eventOfType('ipmi_rakp'));
        self::assertSame('admin', $session->username);
    }

    public function test_open_session_request_is_captured(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::openSessionDatagram();
        $server->processInbound($session);

        $rakp = $this->eventOfType('ipmi_rakp');
        self::assertNotNull($rakp);
        self::assertStringContainsString('Open Session Request', $rakp['path']);
    }

    public function test_get_session_challenge_username_is_captured(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::getSessionChallengeDatagram('sysadmin');
        $server->processInbound($session);

        $rakp = $this->eventOfType('ipmi_rakp');
        self::assertNotNull($rakp);
        self::assertSame('sysadmin', $rakp['username']);
        self::assertStringContainsString('Get Session Challenge', $rakp['path']);
    }

    public function test_activate_session_is_captured_without_granting(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::activateSessionDatagram();
        $server->processInbound($session);

        $rakp = $this->eventOfType('ipmi_rakp');
        self::assertNotNull($rakp);
        self::assertStringContainsString('Activate Session', $rakp['path']);
        self::assertSame('', $session->outbuf, 'a session is never activated');
    }

    public function test_rakp3_draws_an_integrity_failure_never_a_session(): void
    {
        // A RAKP Message 3 must never yield a RAKP Message 4 success. Padded so the reply fits the cap
        // and we can inspect it.
        [$server, $session] = $this->serverSession();

        $req = self::rakp3Datagram() . str_repeat("\x00", 8);
        $session->inbuf = $req;
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('ipmi_rakp'));
        if ($session->outbuf !== '') {
            $parsed = IpmiServer::parseRmcpPlus($session->outbuf);
            self::assertNotNull($parsed);
            self::assertSame(0x15, $parsed['payloadType'], 'RAKP Message 4');
            self::assertNotSame(0x00, ord($parsed['payload'][1]), 'status is a failure, never success');
        }
    }

    public function test_auth_cap_reply_never_exceeds_request_datagram(): void
    {
        // A minimal probe: the believable response is larger, so it is dropped rather than amplified.
        [$server, $session] = $this->serverSession();

        $req = self::getChannelAuthCapDatagram();
        $session->inbuf = $req;
        $server->processInbound($session);

        self::assertLessThanOrEqual(strlen($req), strlen($session->outbuf), 'anti-amplification: reply <= request');
        self::assertNotNull($this->eventOfType('ipmi_auth_caps'), 'the probe is still captured');
    }

    public function test_auth_cap_reply_is_sent_when_the_request_is_large_enough(): void
    {
        // A padded request leaves room for the believable reply under the cap.
        [$server, $session] = $this->serverSession();

        $req = self::getChannelAuthCapDatagram(16);
        $session->inbuf = $req;
        $server->processInbound($session);

        self::assertNotSame('', $session->outbuf, 'the believable auth-cap reply is emitted');
        self::assertLessThanOrEqual(strlen($req), strlen($session->outbuf));

        $parsed = IpmiServer::parseIpmi15($session->outbuf);
        self::assertNotNull($parsed);
        self::assertSame(0x38, $parsed['cmd'], 'the reply is a Get Channel Auth Cap response');
    }

    public function test_non_rmcp_datagram_logs_unknown_and_sends_nothing(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = "\x01\x02\x03\x04not-rmcp";
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('ipmi_unknown'));
        self::assertSame('', $session->outbuf);
    }

    public function test_asf_presence_ping_is_recorded_without_reply(): void
    {
        [$server, $session] = $this->serverSession();

        // RMCP class 0x06 = ASF (presence ping): recon, but not IPMI — capture, never reply.
        $session->inbuf = "\x06\x00\xff\x06" . "\x00\x00\x11\xbe" . "\x80\x00\x00\x00";
        $server->processInbound($session);

        $unknown = $this->eventOfType('ipmi_unknown');
        self::assertNotNull($unknown);
        self::assertStringContainsString('ASF', $unknown['path']);
        self::assertSame('', $session->outbuf);
    }

    public function test_truncated_ipmi_message_logs_unknown_without_faulting(): void
    {
        [$server, $session] = $this->serverSession();

        // Valid RMCP + auth-none header but a runt IPMI message: must degrade, never crash.
        $session->inbuf = "\x06\x00\xff\x07" . "\x00" . "\x00\x00\x00\x00" . "\x00\x00\x00\x00" . "\x03" . "\x20\x18\xc8";
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('ipmi_unknown'));
        self::assertSame('', $session->outbuf);
    }

    public function test_config_from_env_reads_persona(): void
    {
        putenv('FUNNYPOT_IPMI_CHANNEL=2');
        putenv('FUNNYPOT_IPMI_AUTH_SUPPORT=0x15');
        putenv('FUNNYPOT_IPMI_EXT_CAPS=0x03');

        $config = IpmiConfig::fromEnv('install-persona-a');
        self::assertSame(2, $config->channel);
        self::assertSame(0x15, $config->authTypeSupport);
        self::assertSame(0x03, $config->extCapabilities);
        self::assertSame(16, strlen($config->guid), 'the GUID is always 16 bytes');
        // The BMC GUID follows the install identity: stable per install, different across installs,
        // never the retired fleet-wide constant; an explicit FUNNYPOT_IPMI_GUID still wins.
        self::assertSame($config->guid, IpmiConfig::fromEnv('install-persona-a')->guid);
        self::assertNotSame($config->guid, IpmiConfig::fromEnv('install-persona-b')->guid);
        self::assertNotSame(hex2bin('2d1a5c9f8b7e4a3d0c6f1e8b2a4d7c90'), $config->guid);
        putenv('FUNNYPOT_IPMI_GUID=00112233445566778899aabbccddeeff');
        self::assertSame(hex2bin('00112233445566778899aabbccddeeff'), IpmiConfig::fromEnv('install-persona-a')->guid);
        putenv('FUNNYPOT_IPMI_GUID');

        putenv('FUNNYPOT_IPMI_CHANNEL');
        putenv('FUNNYPOT_IPMI_AUTH_SUPPORT');
        putenv('FUNNYPOT_IPMI_EXT_CAPS');
    }
}
