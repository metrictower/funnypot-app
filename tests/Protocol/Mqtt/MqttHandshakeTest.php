<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Mqtt;

use Funnypot\Protocol\Mqtt\MqttConfig;
use Funnypot\Protocol\Mqtt\MqttServer;
use Funnypot\Protocol\Mqtt\MqttSession;
use PHPUnit\Framework\TestCase;

final class MqttHandshakeTest extends TestCase
{
    use MqttTestFrames;

    /** @var array<int,array<string,mixed>> */
    private array $events = [];

    private function newServer(?MqttConfig $config = null): MqttServer
    {
        $this->events = [];

        return new MqttServer($config ?? new MqttConfig(), function (array $e): void {
            $this->events[] = $e;
        });
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

    public function test_connect_captures_credentials_and_returns_accepted_connack(): void
    {
        $server = $this->newServer();
        $session = new MqttSession('203.0.113.7', 50000, 1);
        $session->inbuf .= self::connect('paho-scanner', 'admin', 's3cret');
        $server->processInbound($session);

        self::assertSame('paho-scanner', $session->clientId);
        self::assertSame('admin', $session->username);
        self::assertSame('s3cret', $session->password);
        self::assertSame(4, $session->protocolLevel);
        self::assertSame(MqttSession::STATE_CONNECTED, $session->state);

        $connect = $this->eventOfType('mqtt_connect');
        self::assertNotNull($connect);
        self::assertSame('admin', $connect['username']);
        self::assertSame('s3cret', $connect['password']);
        self::assertStringContainsString('client-id=paho-scanner', $connect['path']);
        self::assertSame('high', $connect['severity']);

        // CONNACK: 0x20, remaining length 2, ack flags 0x00, return code 0x00 (accepted).
        self::assertSame("\x20\x02\x00\x00", $session->outbuf);
        self::assertFalse($session->close);
    }

    public function test_connect_without_credentials_is_medium_severity(): void
    {
        $server = $this->newServer();
        $session = new MqttSession('203.0.113.7', 50000, 1);
        $session->inbuf .= self::connect('anon-client');
        $server->processInbound($session);

        self::assertNull($session->username);
        self::assertNull($session->password);

        $connect = $this->eventOfType('mqtt_connect');
        self::assertNotNull($connect);
        self::assertSame('medium', $connect['severity']);
        self::assertArrayNotHasKey('username', $connect);
    }

    public function test_mqtt5_connack_carries_property_length_byte(): void
    {
        $server = $this->newServer();
        $session = new MqttSession('198.51.100.5', 51000, 1);
        $session->inbuf .= self::connect('v5-client', 'u', 'p', 5);
        $server->processInbound($session);

        self::assertSame(5, $session->protocolLevel);
        // CONNACK v5: 0x20, remaining length 3, ack flags 0x00, reason 0x00, property length 0x00.
        self::assertSame("\x20\x03\x00\x00\x00", $session->outbuf);
        self::assertSame('u', $session->username);
        self::assertSame('p', $session->password);
    }

    public function test_subscribe_captures_topics_and_grants_qos0(): void
    {
        $server = $this->newServer();
        $session = new MqttSession('203.0.113.7', 50000, 1);
        $session->inbuf .= self::connect('c1');
        $server->processInbound($session);
        $session->outbuf = '';

        $session->inbuf .= self::subscribe(0x000A, ['$SYS/#', 'sensors/+/temp']);
        $server->processInbound($session);

        $sub = $this->eventOfType('mqtt_subscribe');
        self::assertNotNull($sub);
        self::assertSame(10, $sub['packet_id']);
        self::assertSame(['$SYS/#', 'sensors/+/temp'], $sub['topics']);
        self::assertStringContainsString('$SYS/#', $sub['path']);

        // SUBACK: 0x90, remaining length 4, packet id 0x000A, two granted-QoS0 codes 0x00 0x00.
        self::assertSame("\x90\x04\x00\x0a\x00\x00", $session->outbuf);
    }

    public function test_publish_qos0_captures_payload_and_sends_no_ack(): void
    {
        $server = $this->newServer();
        $session = new MqttSession('203.0.113.7', 50000, 1);
        $session->inbuf .= self::connect('c1');
        $server->processInbound($session);
        $session->outbuf = '';

        $session->inbuf .= self::publish('cmd/exec', 'rm -rf /', 0);
        $server->processInbound($session);

        $pub = $this->eventOfType('mqtt_publish');
        self::assertNotNull($pub);
        self::assertSame('cmd/exec', $pub['topic']);
        self::assertSame('rm -rf /', $pub['payload']);
        self::assertSame(0, $pub['qos']);
        self::assertSame(8, $pub['payload_len']);

        // QoS 0 PUBLISH is fire-and-forget: no acknowledgement.
        self::assertSame('', $session->outbuf);
    }

    public function test_publish_qos1_captures_payload_and_pubacks(): void
    {
        $server = $this->newServer();
        $session = new MqttSession('203.0.113.7', 50000, 1);
        $session->inbuf .= self::connect('c1');
        $server->processInbound($session);
        $session->outbuf = '';

        $session->inbuf .= self::publish('telemetry', 'value=42', 1, 0x0021);
        $server->processInbound($session);

        $pub = $this->eventOfType('mqtt_publish');
        self::assertNotNull($pub);
        self::assertSame('telemetry', $pub['topic']);
        self::assertSame('value=42', $pub['payload']);
        self::assertSame(1, $pub['qos']);

        // PUBACK: 0x40, remaining length 2, packet id 0x0021.
        self::assertSame("\x40\x02\x00\x21", $session->outbuf);
    }

    public function test_pingreq_gets_pingresp(): void
    {
        $server = $this->newServer();
        $session = new MqttSession('203.0.113.7', 50000, 1);
        $session->inbuf .= self::connect('c1');
        $server->processInbound($session);
        $session->outbuf = '';

        $session->inbuf .= self::pingreq();
        $server->processInbound($session);

        // PINGRESP: 0xD0 0x00.
        self::assertSame("\xd0\x00", $session->outbuf);
        self::assertFalse($session->close);
    }

    public function test_disconnect_finishes_the_session(): void
    {
        $server = $this->newServer();
        $session = new MqttSession('203.0.113.7', 50000, 1);
        $session->inbuf .= self::connect('c1');
        $server->processInbound($session);
        $session->outbuf = '';

        $session->inbuf .= self::disconnect();
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertSame(MqttSession::STATE_DONE, $session->state);
        self::assertSame('', $session->outbuf);
    }

    public function test_first_packet_not_connect_closes_cleanly(): void
    {
        // A client that opens with PUBLISH instead of CONNECT is a protocol violation: log and drop.
        $server = $this->newServer();
        $session = new MqttSession('192.0.2.9', 40000, 1);
        $session->inbuf .= self::publish('t', 'x', 0);
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('mqtt_unknown'));
        self::assertNull($this->eventOfType('mqtt_publish'));
    }

    public function test_partial_packet_is_buffered_until_complete(): void
    {
        $server = $this->newServer();
        $session = new MqttSession('192.0.2.2', 5001, 1);

        $connect = self::connect('slowclient', 'user', 'pass');
        // Feed the fixed-header byte and a fragment first: nothing should be parsed yet.
        $session->inbuf .= substr($connect, 0, 5);
        $server->processInbound($session);
        self::assertNull($session->clientId);
        self::assertSame(MqttSession::STATE_WAIT_CONNECT, $session->state);

        // Deliver the remainder: the CONNECT now parses.
        $session->inbuf .= substr($connect, 5);
        $server->processInbound($session);
        self::assertSame('slowclient', $session->clientId);
        self::assertSame('user', $session->username);
    }

    public function test_two_publishes_in_one_read_are_both_captured(): void
    {
        // The framing must consume back-to-back packets delivered in a single read.
        $server = $this->newServer();
        $session = new MqttSession('203.0.113.7', 50000, 1);
        $session->inbuf .= self::connect('c1')
            . self::publish('a/b', 'one', 0)
            . self::publish('c/d', 'two', 0);
        $server->processInbound($session);

        $publishes = array_values(array_filter(
            $this->events,
            static fn (array $e): bool => ($e['event'] ?? '') === 'mqtt_publish'
        ));
        self::assertCount(2, $publishes);
        self::assertSame('a/b', $publishes[0]['topic']);
        self::assertSame('c/d', $publishes[1]['topic']);
    }
}
