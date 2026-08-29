<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Mqtt;

/**
 * Byte builders for the MQTT tests: the fixed-header framing plus the CONNECT / SUBSCRIBE / PUBLISH
 * / PINGREQ packets a scanner would send. Kept deliberately minimal — just enough structure for the
 * honeypot's parsers to exercise every field it reads, across both MQTT 3.1.1 (level 4) and 5.0.
 */
trait MqttTestFrames
{
    /** MQTT variable-length integer (Remaining Length / property length style). */
    private static function varint(int $n): string
    {
        $out = '';
        do {
            $b = $n % 128;
            $n = intdiv($n, 128);
            if ($n > 0) {
                $b |= 0x80;
            }
            $out .= chr($b);
        } while ($n > 0);

        return $out;
    }

    /** MQTT length-prefixed field: 2-byte big-endian length + bytes (UTF-8 string or binary data). */
    private static function mqttStr(string $s): string
    {
        return pack('n', strlen($s)) . $s;
    }

    /** Wraps a body in the MQTT fixed header (type high nibble + flags low nibble, Remaining Length). */
    private static function packet(int $type, int $flags, string $body): string
    {
        return chr(($type << 4) | ($flags & 0x0F)) . self::varint(strlen($body)) . $body;
    }

    private static function connect(
        string $clientId,
        ?string $user = null,
        ?string $pass = null,
        int $level = 4,
        string $protoName = 'MQTT'
    ): string {
        $flags = 0x02; // clean session
        if ($user !== null) {
            $flags |= 0x80;
        }
        if ($pass !== null) {
            $flags |= 0x40;
        }

        $vh = self::mqttStr($protoName) . chr($level) . chr($flags) . pack('n', 60);
        if ($level >= 5) {
            $vh .= self::varint(0); // no CONNECT properties
        }

        $payload = self::mqttStr($clientId);
        if ($user !== null) {
            $payload .= self::mqttStr($user);
        }
        if ($pass !== null) {
            $payload .= self::mqttStr($pass);
        }

        return self::packet(1, 0, $vh . $payload);
    }

    /**
     * @param list<string> $filters
     */
    private static function subscribe(int $packetId, array $filters, int $level = 4): string
    {
        $vh = pack('n', $packetId);
        if ($level >= 5) {
            $vh .= self::varint(0); // no SUBSCRIBE properties
        }
        $payload = '';
        foreach ($filters as $f) {
            $payload .= self::mqttStr($f) . chr(0x00); // requested QoS 0
        }

        return self::packet(8, 0x02, $vh . $payload);
    }

    private static function publish(
        string $topic,
        string $payload,
        int $qos = 0,
        int $packetId = 0,
        int $level = 4,
        bool $retain = false
    ): string {
        $flags = ($qos << 1) | ($retain ? 1 : 0);
        $vh = self::mqttStr($topic);
        if ($qos > 0) {
            $vh .= pack('n', $packetId);
        }
        if ($level >= 5) {
            $vh .= self::varint(0); // no PUBLISH properties
        }

        return self::packet(3, $flags, $vh . $payload);
    }

    private static function pingreq(): string
    {
        return chr(12 << 4) . chr(0x00);
    }

    private static function disconnect(): string
    {
        return chr(14 << 4) . chr(0x00);
    }
}
