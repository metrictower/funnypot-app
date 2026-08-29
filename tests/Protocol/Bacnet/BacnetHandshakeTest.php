<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Bacnet;

use Funnypot\Protocol\Bacnet\BacnetConfig;
use Funnypot\Protocol\Bacnet\BacnetServer;
use Funnypot\Protocol\Bacnet\BacnetSession;
use PHPUnit\Framework\TestCase;

final class BacnetHandshakeTest extends TestCase
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
        $session = new BacnetSession('192.0.2.50', 47808, 1);

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

    /**
     * Walks the application tags of an APDU from $pos, returning each tag descriptor in order.
     *
     * @return array<int,array{tag:int,context:bool,opening:bool,closing:bool,value:string}>
     */
    private static function tags(string $apdu, int $pos): array
    {
        $out = [];
        while ($pos < strlen($apdu)) {
            $t = BacnetServer::readTag($apdu, $pos);
            if ($t === null) {
                break;
            }
            $out[] = $t;
        }

        return $out;
    }

    public function test_who_is_is_captured_and_answered_with_i_am(): void
    {
        $config = new BacnetConfig(deviceInstance: 260001, vendorId: 260, maxApdu: 1476, segmentation: 3);
        [$server, $session] = $this->serverSession($config);

        // A routed broadcast Who-Is sweeping the whole instance range.
        $session->inbuf = self::datagramWhoIs(0, 4194303, routed: true);
        $server->processInbound($session);

        $whois = $this->eventOfType('bacnet_whois');
        self::assertNotNull($whois);
        self::assertSame(0, $session->whoIsLow);
        self::assertSame(4194303, $session->whoIsHigh);
        self::assertStringContainsString('range=0-4194303', $whois['path']);

        // The reply is a well-formed I-Am announcing the persona device.
        self::assertNotSame('', $session->outbuf, 'a Who-Is large enough to hold an I-Am is answered');
        $apdu = BacnetServer::extractApdu($session->outbuf);
        self::assertNotNull($apdu);
        self::assertSame(0x1, (ord($apdu[0]) >> 4) & 0x0F, 'unconfirmed-request');
        self::assertSame(0x00, ord($apdu[1]), 'service = I-Am');

        $tags = self::tags($apdu, 2);
        self::assertCount(4, $tags, 'I-Am carries objectId, maxApdu, segmentation, vendorId');

        [$type, $instance] = BacnetServer::decodeObjectId($tags[0]['value']);
        self::assertSame(self::OBJ_DEVICE, $type);
        self::assertSame(260001, $instance);
        self::assertSame(1476, BacnetServer::decodeUnsigned($tags[1]['value']), 'max APDU length');
        self::assertSame(3, BacnetServer::decodeUnsigned($tags[2]['value']), 'segmentation = no-segmentation');
        self::assertSame(260, BacnetServer::decodeUnsigned($tags[3]['value']), 'vendor id');
    }

    public function test_global_who_is_without_range_is_captured(): void
    {
        [$server, $session] = $this->serverSession();

        $session->inbuf = self::datagramWhoIs(null, null, routed: true);
        $server->processInbound($session);

        $whois = $this->eventOfType('bacnet_whois');
        self::assertNotNull($whois);
        self::assertNull($session->whoIsLow);
        self::assertNull($session->whoIsHigh);
        self::assertStringContainsString('range=global', $whois['path']);
    }

    public function test_who_is_range_excluding_device_draws_no_i_am(): void
    {
        // Instance 260001 is outside 1..100, so a real device stays silent — but the probe is logged.
        [$server, $session] = $this->serverSession(new BacnetConfig(deviceInstance: 260001));

        $session->inbuf = self::datagramWhoIs(1, 100, routed: true);
        $server->processInbound($session);

        self::assertNotNull($this->eventOfType('bacnet_whois'));
        self::assertSame('', $session->outbuf);
    }

    public function test_read_property_of_device_returns_value_and_captures_recon(): void
    {
        $config = new BacnetConfig(deviceInstance: 260001, vendorId: 260);
        [$server, $session] = $this->serverSession($config);

        // Routed ReadProperty of the Device object's vendor-identifier (a short value that fits the cap).
        $session->inbuf = self::datagramReadProperty(0x42, self::OBJ_DEVICE, 260001, 120, routed: true);
        $server->processInbound($session);

        $read = $this->eventOfType('bacnet_read');
        self::assertNotNull($read);
        self::assertSame(self::OBJ_DEVICE, $session->readObjectType);
        self::assertSame(260001, $session->readObjectInstance);
        self::assertSame(120, $session->readPropertyId);
        self::assertStringContainsString('obj=device:260001', $read['path']);
        self::assertStringContainsString('prop=vendor-identifier', $read['path']);

        // The ComplexACK echoes the object + property and carries the vendor id value.
        $apdu = BacnetServer::extractApdu($session->outbuf);
        self::assertNotNull($apdu);
        self::assertSame(0x3, (ord($apdu[0]) >> 4) & 0x0F, 'complex-ack');
        self::assertSame(0x42, ord($apdu[1]), 'invoke id echoed');
        self::assertSame(0x0C, ord($apdu[2]), 'service ack = readProperty');

        $tags = self::tags($apdu, 3);
        // context 0 object id, context 1 property id, opening 3, application value, closing 3.
        self::assertTrue($tags[0]['context'] && $tags[0]['tag'] === 0);
        [$type, $instance] = BacnetServer::decodeObjectId($tags[0]['value']);
        self::assertSame(self::OBJ_DEVICE, $type);
        self::assertSame(260001, $instance);
        self::assertTrue($tags[1]['context'] && $tags[1]['tag'] === 1);
        self::assertSame(120, BacnetServer::decodeUnsigned($tags[1]['value']));
        self::assertTrue($tags[2]['opening'], 'value opening tag 3');
        self::assertSame(260, BacnetServer::decodeUnsigned($tags[3]['value']), 'vendor id value');
        self::assertTrue($tags[4]['closing'], 'value closing tag 3');
    }

    public function test_read_property_object_name_returns_the_char_string(): void
    {
        // A short object-name keeps the ACK under the anti-amplification cap so the value is returned.
        $config = new BacnetConfig(deviceInstance: 260001, objectName: 'D1');
        [$server, $session] = $this->serverSession($config);

        $session->inbuf = self::datagramReadProperty(7, self::OBJ_DEVICE, 260001, 77, routed: true);
        $server->processInbound($session);

        $apdu = BacnetServer::extractApdu($session->outbuf);
        self::assertNotNull($apdu);
        self::assertSame(0x3, (ord($apdu[0]) >> 4) & 0x0F, 'complex-ack');

        $tags = self::tags($apdu, 3);
        // The character-string value carries a leading encoding byte (0 = UTF-8) then the text.
        $charString = $tags[3]['value'];
        self::assertSame("\x00", $charString[0], 'char-string encoding byte = ANSI/UTF-8');
        self::assertSame('D1', substr($charString, 1));
    }

    public function test_read_property_of_unknown_object_returns_unknown_object_error(): void
    {
        [$server, $session] = $this->serverSession(new BacnetConfig(deviceInstance: 260001));

        // analog-input:0 does not exist — a sparse device answers unknown-object (captures point recon).
        $session->inbuf = self::datagramReadProperty(9, 0, 0, 85, routed: true);
        $server->processInbound($session);

        $read = $this->eventOfType('bacnet_read');
        self::assertNotNull($read);
        self::assertStringContainsString('obj=analog-input:0', $read['path']);

        $apdu = BacnetServer::extractApdu($session->outbuf);
        self::assertNotNull($apdu);
        self::assertSame(0x5, (ord($apdu[0]) >> 4) & 0x0F, 'error-pdu');
        $tags = self::tags($apdu, 3); // after PDU type, invoke id, service choice
        self::assertSame(1, BacnetServer::decodeUnsigned($tags[0]['value']), 'error-class = object');
        self::assertSame(31, BacnetServer::decodeUnsigned($tags[1]['value']), 'error-code = unknown-object');
    }

    public function test_read_unknown_property_of_device_returns_unknown_property_error(): void
    {
        [$server, $session] = $this->serverSession(new BacnetConfig(deviceInstance: 260001));

        // present-value (85) is not a Device-object property — unknown-property.
        $session->inbuf = self::datagramReadProperty(10, self::OBJ_DEVICE, 260001, 85, routed: true);
        $server->processInbound($session);

        $apdu = BacnetServer::extractApdu($session->outbuf);
        self::assertNotNull($apdu);
        self::assertSame(0x5, (ord($apdu[0]) >> 4) & 0x0F, 'error-pdu');
        $tags = self::tags($apdu, 3);
        self::assertSame(2, BacnetServer::decodeUnsigned($tags[0]['value']), 'error-class = property');
        self::assertSame(32, BacnetServer::decodeUnsigned($tags[1]['value']), 'error-code = unknown-property');
    }

    public function test_object_id_roundtrip(): void
    {
        foreach ([[8, 260001], [0, 0], [2, 4194302], [5, 12345]] as [$type, $inst]) {
            [$dt, $di] = BacnetServer::decodeObjectId(pack('N', (($type & 0x3FF) << 22) | ($inst & 0x3FFFFF)));
            self::assertSame($type, $dt);
            self::assertSame($inst, $di);
        }
    }
}
