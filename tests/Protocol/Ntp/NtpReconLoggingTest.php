<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Ntp;

use Funnypot\Protocol\Ntp\NtpConfig;
use Funnypot\Protocol\Ntp\NtpServer;
use Funnypot\Protocol\Ntp\NtpSession;
use PHPUnit\Framework\TestCase;

final class NtpReconLoggingTest extends TestCase
{
    use NtpTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:NtpServer,1:NtpSession}
     */
    private function serverSession(?NtpConfig $config = null): array
    {
        $this->events = [];
        $server = new NtpServer($config ?? new NtpConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new NtpSession('198.51.100.7', 55123, 1);

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

    public function test_every_event_carries_the_ntp_envelope(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::clientRequest(4, 0xE4000000, 0);
        $server->processInbound($session);

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('ntp', $e['proto']);
            self::assertSame('NTP', $e['method']);
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

    public function test_client_request_logged_as_ntp_client(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::clientRequest(4, 0xE4000000, 0, 6);
        $server->processInbound($session);

        $ev = $this->eventOfType('ntp_client');
        self::assertNotNull($ev);
        self::assertSame('low', $ev['severity']);
        self::assertStringContainsString('mode=3', $ev['path']);
    }

    public function test_monlist_mode7_is_high_severity_and_dropped(): void
    {
        [$server, $session] = $this->serverSession();

        $req = self::monlistRequest(42); // REQ_MON_GETLIST
        $session->inbuf = $req;
        $server->processInbound($session);

        $ev = $this->eventOfType('ntp_monlist_probe');
        self::assertNotNull($ev, 'the amplification probe is captured');
        self::assertSame('high', $ev['severity']);
        self::assertStringContainsString('MONLIST', $ev['path']);
        self::assertStringContainsString('reqcode=42', $ev['path']);

        // CRITICAL: the reflection vector is never answered.
        self::assertSame('', $session->outbuf, 'mode 7 monlist is dropped, never reflected');
    }

    public function test_control_mode6_is_high_severity_and_dropped(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::controlRequest(2);
        $server->processInbound($session);

        $ev = $this->eventOfType('ntp_monlist_probe');
        self::assertNotNull($ev);
        self::assertSame('high', $ev['severity']);
        self::assertStringContainsString('mode 6 (control)', $ev['path']);
        self::assertSame('', $session->outbuf, 'mode 6 control is dropped, never reflected');
    }

    public function test_server_mode4_inbound_is_unknown_and_unanswered(): void
    {
        [$server, $session] = $this->serverSession();

        // A mode-4 server packet arriving inbound is not a request; record it, never reply.
        $session->inbuf = self::ntpPacket(4, 4, 0xE4000000, 0);
        $server->processInbound($session);

        $ev = $this->eventOfType('ntp_unknown');
        self::assertNotNull($ev);
        self::assertStringContainsString('mode 4', $ev['path']);
        self::assertSame('', $session->outbuf);
    }

    public function test_short_client_packet_is_unknown_and_unanswered(): void
    {
        [$server, $session] = $this->serverSession();

        // Mode 3 but only a few bytes: not a valid time query.
        $session->inbuf = chr(self::leadByte(0, 4, 3)) . "\x00\x00";
        $server->processInbound($session);

        $ev = $this->eventOfType('ntp_unknown');
        self::assertNotNull($ev);
        self::assertStringContainsString('short client packet', $ev['path']);
        self::assertSame('', $session->outbuf);
    }

    public function test_broadcast_mode5_is_unknown_and_unanswered(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::ntpPacket(4, 5, 0xE4000000, 0);
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('ntp_unknown'));
        self::assertSame('', $session->outbuf);
    }

    public function test_empty_datagram_produces_no_event_and_no_reply(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = '';
        $server->processInbound($session);

        self::assertEmpty($this->events);
        self::assertSame('', $session->outbuf);
    }
}
