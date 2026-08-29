<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Stun;

use Funnypot\Protocol\Stun\StunConfig;
use Funnypot\Protocol\Stun\StunServer;
use Funnypot\Protocol\Stun\StunSession;
use PHPUnit\Framework\TestCase;

final class StunReconLoggingTest extends TestCase
{
    use StunTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:StunServer,1:StunSession}
     */
    private function serverSession(string $ip = '198.51.100.7', int $port = 40000, ?StunConfig $config = null): array
    {
        $this->events = [];
        $server = new StunServer($config ?? new StunConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new StunSession($ip, $port, 1);

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

    public function test_every_event_carries_the_stun_envelope(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::bindingRequest(self::txid(), self::softwareAttr('scanner/1'));
        $server->processInbound($session);

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('stun', $e['proto']);
            self::assertSame('STUN', $e['method']);
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

    public function test_binding_request_logs_mapped_address_and_software(): void
    {
        [$server, $session] = $this->serverSession('203.0.113.9', 55123);

        $session->inbuf = self::bindingRequest(self::txid(), self::softwareAttr('friendly-scanner'));
        $server->processInbound($session);

        $binding = $this->eventOfType('stun_binding');
        self::assertNotNull($binding);
        self::assertSame('STUN', $binding['method']);
        self::assertSame('203.0.113.9:55123', $binding['mapped']);
        self::assertStringContainsString('203.0.113.9:55123', $binding['path']);
        self::assertSame('friendly-scanner', $binding['software']);
        self::assertStringContainsString('friendly-scanner', $binding['path']);
    }

    public function test_response_never_exceeds_request_datagram(): void
    {
        // A request padded past the 32-byte minimum response is answered, but the reply is still
        // capped so it can never amplify.
        [$server, $session] = $this->serverSession();

        $req = self::bindingRequest(self::txid(), self::softwareAttr('padding-to-make-it-large-enough'));
        $session->inbuf = $req;
        $server->processInbound($session);

        self::assertNotSame('', $session->outbuf, 'a large-enough Binding Request is answered');
        self::assertLessThanOrEqual(
            strlen($req),
            strlen($session->outbuf),
            'anti-amplification: the reply is never larger than the request'
        );
    }

    public function test_bare_binding_request_is_captured_but_not_reflected(): void
    {
        // A bare 20-byte Binding Request is smaller than any valid response, so nothing is emitted
        // (a spoofed source pulls no reflected packet) — yet the probe is still captured as intel.
        [$server, $session] = $this->serverSession();

        $req = self::bindingRequest(self::txid());
        self::assertSame(20, strlen($req));
        $session->inbuf = $req;
        $server->processInbound($session);

        self::assertSame('', $session->outbuf, 'anti-amplification: no reply larger than the request');
        self::assertNotNull($this->eventOfType('stun_binding'), 'the probe is still logged');
    }

    public function test_software_default_is_dropped_when_it_would_amplify(): void
    {
        // The configured SOFTWARE would push the reply over a modest request; it is dropped so the
        // XOR-MAPPED-ADDRESS still comes back within the size cap.
        [$server, $session] = $this->serverSession('192.0.2.10', 44444, new StunConfig(software: 'coturn-4.5.2'));

        // 8-byte attribute value => request is exactly 32 bytes, the size of a bare response.
        $req = self::bindingRequest(self::txid(), self::attr(0x0024, "\x00\x00\x00\x00\x00\x00\x00\x00"));
        self::assertSame(32, strlen($req));
        $session->inbuf = $req;
        $server->processInbound($session);

        self::assertNotSame('', $session->outbuf);
        self::assertLessThanOrEqual(strlen($req), strlen($session->outbuf));

        $parsed = StunServer::parseMessage($session->outbuf);
        self::assertNotNull($parsed);
        self::assertArrayHasKey(0x0020, $parsed['attributes'], 'XOR-MAPPED-ADDRESS survives');
        self::assertArrayNotHasKey(0x8022, $parsed['attributes'], 'SOFTWARE dropped to stay within the cap');
    }

    public function test_unparseable_datagram_logs_unknown_and_sends_nothing(): void
    {
        [$server, $session] = $this->serverSession();

        // Right size, wrong magic cookie.
        $session->inbuf = pack('n', 0x0001) . pack('n', 0) . "\x00\x00\x00\x00" . self::txid();
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('stun_unknown'));
        self::assertSame('', $session->outbuf);
    }

    public function test_non_binding_request_message_is_recorded_without_reply(): void
    {
        [$server, $session] = $this->serverSession();

        // A Binding Success Response (0x0101) inbound is not a request — never reply (no reflection).
        $session->inbuf = self::message(0x0101, self::txid());
        $server->processInbound($session);

        $unknown = $this->eventOfType('stun_unknown');
        self::assertNotNull($unknown);
        self::assertStringContainsString('0x0101', $unknown['path']);
        self::assertSame('', $session->outbuf);
    }

    public function test_config_from_env_reads_software(): void
    {
        putenv('FUNNYPOT_STUN_SOFTWARE=Nimbus TURN 2.1');
        self::assertSame('Nimbus TURN 2.1', StunConfig::fromEnv()->software);

        // An explicitly empty value disables the attribute.
        putenv('FUNNYPOT_STUN_SOFTWARE=');
        self::assertSame('', StunConfig::fromEnv()->software);

        // Unset falls back to the sane default.
        putenv('FUNNYPOT_STUN_SOFTWARE');
        self::assertSame('coturn-4.5.2', StunConfig::fromEnv()->software);
    }
}
