<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Bacnet;

use Funnypot\Protocol\Bacnet\BacnetConfig;
use Funnypot\Protocol\Bacnet\BacnetServer;
use Funnypot\Protocol\Bacnet\BacnetSession;
use PHPUnit\Framework\TestCase;

final class BacnetReconLoggingTest extends TestCase
{
    use BacnetTestFrames;

    private const OBJ_DEVICE = 8;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    /**
     * @return array{0:BacnetServer,1:BacnetSession}
     */
    private function serverSession(?BacnetConfig $config = null): array
    {
        $this->events = [];
        $server = new BacnetServer($config ?? new BacnetConfig(), function (array $e): void {
            $this->events[] = $e;
        });
        $session = new BacnetSession('198.51.100.9', 47808, 1);

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

    public function test_every_event_carries_the_bacnet_envelope(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::datagramWhoIs(0, 4194303, routed: true);
        $server->processInbound($session);

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('bacnet', $e['proto']);
            self::assertSame('BACNET', $e['method']);
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

    public function test_i_am_reply_never_exceeds_the_who_is_request(): void
    {
        [$server, $session] = $this->serverSession();

        $req = self::datagramWhoIs(0, 4194303, routed: true);
        $session->inbuf = $req;
        $server->processInbound($session);

        self::assertNotSame('', $session->outbuf);
        self::assertLessThanOrEqual(
            strlen($req),
            strlen($session->outbuf),
            'anti-amplification: the reply is never larger than the request'
        );
    }

    public function test_small_who_is_is_logged_but_draws_no_reply(): void
    {
        // A minimal broadcast Who-Is is too small to hold an I-Am under the anti-amplification cap, so
        // no reply is emitted — but the discovery probe is still captured.
        [$server, $session] = $this->serverSession();

        $req = self::datagramWhoIs(null, null, routed: false);
        $session->inbuf = $req;
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('bacnet_whois'));
        self::assertSame('', $session->outbuf, 'a tiny Who-Is cannot be amplified into an I-Am');
    }

    public function test_small_read_property_downgrades_to_size_safe_abort(): void
    {
        // A minimal ReadProperty of a long-string property would produce an ACK larger than the
        // request; the reply degrades to a tiny Abort (buffer-overflow) that respects the cap.
        [$server, $session] = $this->serverSession(new BacnetConfig(deviceInstance: 260001, objectName: 'LONG_DEVICE_NAME_0001'));

        $req = self::datagramReadProperty(5, self::OBJ_DEVICE, 260001, 77, routed: false);
        $session->inbuf = $req;
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('bacnet_read'));
        self::assertNotSame('', $session->outbuf);
        self::assertLessThanOrEqual(strlen($req), strlen($session->outbuf), 'anti-amplification holds');

        $apdu = BacnetServer::extractApdu($session->outbuf);
        self::assertNotNull($apdu);
        self::assertSame(0x7, (ord($apdu[0]) >> 4) & 0x0F, 'abort-pdu');
        self::assertSame(1, ord($apdu[2]), 'abort reason = buffer-overflow');
    }

    public function test_write_property_is_captured_and_refused_never_applied(): void
    {
        [$server, $session] = $this->serverSession();

        // WriteProperty (0x0F) is not modelled: INERT — captured and refused with a Reject.
        $session->inbuf = self::datagramConfirmed(3, 0x0F, str_repeat("\x00", 8), routed: true);
        $server->processInbound($session);

        $unknown = $this->eventOfType('bacnet_unknown');
        self::assertNotNull($unknown);
        self::assertStringContainsString('confirmed service 0x0F', $unknown['path']);

        $apdu = BacnetServer::extractApdu($session->outbuf);
        self::assertNotNull($apdu);
        self::assertSame(0x6, (ord($apdu[0]) >> 4) & 0x0F, 'reject-pdu');
        self::assertSame(9, ord($apdu[2]), 'reject reason = unrecognized-service');
    }

    public function test_non_bacnet_datagram_is_logged_unknown_and_sends_nothing(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = 'not a bacnet packet at all';
        $server->processInbound($session);

        $unknown = $this->eventOfType('bacnet_unknown');
        self::assertNotNull($unknown);
        self::assertStringContainsString('bad BVLC type', $unknown['path']);
        self::assertSame('', $session->outbuf);
    }

    public function test_network_layer_message_has_no_apdu_and_draws_no_reply(): void
    {
        [$server, $session] = $this->serverSession();

        // NPDU control bit 7 set = network-layer (routing) message: no APDU to model.
        $npdu = "\x01\x80\x00"; // version, control (network message), message type
        $session->inbuf = self::bvlc(0x0b, $npdu);
        $server->processInbound($session);

        $unknown = $this->eventOfType('bacnet_unknown');
        self::assertNotNull($unknown);
        self::assertStringContainsString('no APDU', $unknown['path']);
        self::assertSame('', $session->outbuf);
    }

    public function test_inbound_i_am_is_recorded_without_reply(): void
    {
        // An inbound I-Am is a peer announcement, not a request: record it, never reply.
        [$server, $session] = $this->serverSession();

        $apdu = "\x10\x00" . str_repeat("\x00", 10);
        $session->inbuf = self::bvlc(0x0b, self::npduSimple($apdu));
        $server->processInbound($session);

        $unknown = $this->eventOfType('bacnet_unknown');
        self::assertNotNull($unknown);
        self::assertStringContainsString('unconfirmed service 0x00', $unknown['path']);
        self::assertSame('', $session->outbuf);
    }

    public function test_forwarded_npdu_who_is_reaches_the_parser(): void
    {
        // A Forwarded-NPDU (BVLC 0x04) prefixes the NPDU with a 6-byte originating B/IP address.
        [$server, $session] = $this->serverSession();

        $originAddr = "\xc0\xa8\x01\x0a\xba\xc0"; // 192.168.1.10:47808
        $npdu = self::npduSimple(self::whoIsApdu(0, 4194303));
        $session->inbuf = self::bvlc(0x04, $originAddr . $npdu);
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('bacnet_whois'));
    }

    public function test_config_from_env_reads_persona(): void
    {
        putenv('FUNNYPOT_BACNET_DEVICE_ID=12345');
        putenv('FUNNYPOT_BACNET_VENDOR_ID=999');
        putenv('FUNNYPOT_BACNET_VENDOR_NAME=Acme Controls');
        putenv('FUNNYPOT_BACNET_MODEL=RTU-9000');

        $config = BacnetConfig::fromEnv();
        self::assertSame(12345, $config->deviceInstance);
        self::assertSame(999, $config->vendorId);
        self::assertSame('Acme Controls', $config->vendorName);
        self::assertSame('RTU-9000', $config->modelName);
        self::assertSame('DEVICE_12345', $config->objectName, 'object name defaults from the device id');

        putenv('FUNNYPOT_BACNET_DEVICE_ID');
        putenv('FUNNYPOT_BACNET_VENDOR_ID');
        putenv('FUNNYPOT_BACNET_VENDOR_NAME');
        putenv('FUNNYPOT_BACNET_MODEL');
    }

    public function test_malformed_read_property_is_logged_unknown(): void
    {
        [$server, $session] = $this->serverSession();

        // ReadProperty confirmed-request header but a truncated / non-context service body.
        $session->inbuf = self::bvlc(0x0a, self::npduRouted("\x00\x05\x11\x0c\x21\x01"));
        $server->processInbound($session);

        $unknown = $this->eventOfType('bacnet_unknown');
        self::assertNotNull($unknown);
        self::assertStringContainsString('malformed ReadProperty', $unknown['path']);
        self::assertSame('', $session->outbuf);
    }
}
