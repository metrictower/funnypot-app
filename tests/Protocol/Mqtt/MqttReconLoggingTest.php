<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Mqtt;

use Funnypot\Protocol\Mqtt\MqttConfig;
use Funnypot\Protocol\Mqtt\MqttServer;
use Funnypot\Protocol\Mqtt\MqttSession;
use PHPUnit\Framework\TestCase;

final class MqttReconLoggingTest extends TestCase
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

    public function test_every_event_carries_the_mqtt_envelope(): void
    {
        $server = $this->newServer();
        $session = new MqttSession('198.51.100.20', 1883, 1);
        $session->inbuf .= self::connect('c1', 'u', 'p')
            . self::subscribe(1, ['a/#'])
            . self::publish('a/b', 'hi', 1, 2);
        $server->processInbound($session);

        self::assertNotEmpty($this->events);
        foreach ($this->events as $e) {
            self::assertSame('MQTT', $e['method']);
            self::assertSame('mqtt', $e['proto']);
            self::assertSame(1, $e['matched']);
            self::assertSame(1, $e['served']);
            self::assertArrayHasKey('ts', $e);
            self::assertArrayHasKey('severity', $e);
            self::assertArrayHasKey('ip', $e);
            self::assertArrayHasKey('port', $e);
            self::assertArrayHasKey('path', $e);
        }

        // The three intel events are all present.
        self::assertNotNull($this->eventOfType('mqtt_connect'));
        self::assertNotNull($this->eventOfType('mqtt_subscribe'));
        self::assertNotNull($this->eventOfType('mqtt_publish'));
    }

    public function test_publish_payload_is_capped_in_the_log(): void
    {
        $server = $this->newServer(new MqttConfig(payloadLogCap: 16));
        $session = new MqttSession('203.0.113.7', 50000, 1);
        $session->inbuf .= self::connect('c1');
        $server->processInbound($session);

        $big = str_repeat('A', 5000);
        $session->inbuf .= self::publish('flood', $big, 0);
        $server->processInbound($session);

        $pub = $this->eventOfType('mqtt_publish');
        self::assertNotNull($pub);
        self::assertSame(5000, $pub['payload_len']); // full length is recorded
        self::assertSame(16, strlen($pub['payload'])); // logged bytes are capped
    }

    public function test_non_printable_topic_and_payload_are_sanitised(): void
    {
        $server = $this->newServer();
        $session = new MqttSession('203.0.113.7', 50000, 1);
        $session->inbuf .= self::connect('c1');
        $server->processInbound($session);

        $session->inbuf .= self::publish("bin\x00\x01topic", "pay\x00load", 0);
        $server->processInbound($session);

        $pub = $this->eventOfType('mqtt_publish');
        self::assertNotNull($pub);
        self::assertSame('bin..topic', $pub['topic']);
        self::assertSame('pay.load', $pub['payload']);
    }

    public function test_malformed_varint_logs_unknown_and_closes(): void
    {
        // Five continuation bytes exceed the 4-byte Remaining Length maximum.
        $server = $this->newServer();
        $session = new MqttSession('192.0.2.1', 5000, 1);
        $session->inbuf .= chr(self::connectByte()) . "\xFF\xFF\xFF\xFF\xFF";
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('mqtt_unknown'));
    }

    public function test_unmodelled_packet_type_logs_unknown_and_closes(): void
    {
        $server = $this->newServer();
        $session = new MqttSession('192.0.2.1', 5000, 1);
        $session->inbuf .= self::connect('c1');
        $server->processInbound($session);
        $session->outbuf = '';

        // Type 10 = UNSUBSCRIBE, which the honeypot does not model.
        $session->inbuf .= self::packet(10, 0x02, pack('n', 5) . self::mqttStr('a/#'));
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertNotNull($this->eventOfType('mqtt_unknown'));
    }

    public function test_parse_connect_reads_all_fields(): void
    {
        $body = substr(self::connect('cid', 'bob', 'pw', 4), 2); // strip fixed header (type + 1-byte remlen)
        $parsed = MqttServer::parseConnect($body);

        self::assertNotNull($parsed);
        self::assertSame('MQTT', $parsed['protocolName']);
        self::assertSame(4, $parsed['protocolLevel']);
        self::assertSame('cid', $parsed['clientId']);
        self::assertSame('bob', $parsed['username']);
        self::assertSame('pw', $parsed['password']);
        self::assertSame(60, $parsed['keepAlive']);
    }

    public function test_parse_connect_rejects_truncated_input(): void
    {
        self::assertNull(MqttServer::parseConnect("\x00\x04MQT")); // protocol name length lies
        self::assertNull(MqttServer::parseConnect(''));
    }

    public function test_parse_subscribe_reads_multiple_filters(): void
    {
        $body = pack('n', 7) . self::mqttStr('x/y') . chr(0x01) . self::mqttStr('z') . chr(0x02);
        $parsed = MqttServer::parseSubscribe($body, 4);

        self::assertNotNull($parsed);
        self::assertSame(7, $parsed['packetId']);
        self::assertCount(2, $parsed['topics']);
        self::assertSame('x/y', $parsed['topics'][0]['filter']);
        self::assertSame(1, $parsed['topics'][0]['qos']);
        self::assertSame('z', $parsed['topics'][1]['filter']);
    }

    public function test_parse_subscribe_rejects_empty_topic_list(): void
    {
        self::assertNull(MqttServer::parseSubscribe(pack('n', 1), 4)); // packet id but no filters
    }

    public function test_parse_publish_qos0_has_no_packet_id(): void
    {
        $body = self::mqttStr('a/b') . 'payload-bytes';
        $parsed = MqttServer::parsePublish($body, 0, 4);

        self::assertNotNull($parsed);
        self::assertSame('a/b', $parsed['topic']);
        self::assertNull($parsed['packetId']);
        self::assertSame('payload-bytes', $parsed['payload']);
    }

    public function test_parse_publish_qos1_reads_packet_id(): void
    {
        $body = self::mqttStr('a/b') . pack('n', 0x1234) . 'data';
        $parsed = MqttServer::parsePublish($body, 1, 4);

        self::assertNotNull($parsed);
        self::assertSame(0x1234, $parsed['packetId']);
        self::assertSame('data', $parsed['payload']);
    }

    public function test_encode_varint_matches_spec_boundaries(): void
    {
        self::assertSame("\x00", MqttServer::encodeVarint(0));
        self::assertSame("\x7f", MqttServer::encodeVarint(127));
        self::assertSame("\x80\x01", MqttServer::encodeVarint(128));
        self::assertSame("\xff\x7f", MqttServer::encodeVarint(16383));
        self::assertSame("\x80\x80\x01", MqttServer::encodeVarint(16384));
    }

    public function test_build_connack_shapes(): void
    {
        self::assertSame("\x20\x02\x00\x00", MqttServer::buildConnack(4, 0, false));
        self::assertSame("\x20\x02\x01\x00", MqttServer::buildConnack(4, 0, true)); // session present
        self::assertSame("\x20\x03\x00\x00\x00", MqttServer::buildConnack(5, 0, false));
    }

    public function test_config_from_env(): void
    {
        putenv('FUNNYPOT_MQTT_PAYLOAD_CAP=64');
        putenv('FUNNYPOT_MQTT_SESSION_PRESENT=1');
        $config = MqttConfig::fromEnv();
        self::assertSame(64, $config->payloadLogCap);
        self::assertTrue($config->sessionPresent);
        self::assertSame(0, $config->connackCode);

        putenv('FUNNYPOT_MQTT_PAYLOAD_CAP');
        putenv('FUNNYPOT_MQTT_SESSION_PRESENT');
        $default = MqttConfig::fromEnv();
        self::assertSame(256, $default->payloadLogCap);
        self::assertFalse($default->sessionPresent);
    }

    /** The MQTT control byte for a CONNECT (type 1, flags 0), for crafting malformed headers. */
    private static function connectByte(): int
    {
        return 1 << 4;
    }
}
