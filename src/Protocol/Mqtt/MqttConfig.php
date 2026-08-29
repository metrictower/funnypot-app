<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Mqtt;

/**
 * Configuration for the low-interaction MQTT broker honeypot (port 1883).
 *
 * The service parses just enough MQTT 3.1.1 / 5.0 to keep a client talking and harvest what it
 * offers — credentials in CONNECT, the topics it subscribes to, and the payloads it publishes.
 * It never brokers or delivers a message and never grants a real session, so every value here is
 * cosmetic: it shapes the believable "accept everything" broker the box presents, never real access.
 *
 * Accepting the connection (CONNACK return code 0) is the default because a refusal ends the
 * exchange before any subscribe/publish intel appears.
 */
final class MqttConfig
{
    public function __construct(
        // CONNACK return / reason code. 0 = accepted; keeping it 0 makes the client keep talking.
        public int $connackCode = 0,
        // CONNACK session-present flag. False is the unremarkable "fresh session" posture.
        public bool $sessionPresent = false,
        // Cap on how many PUBLISH payload bytes are recorded, so a flood cannot bloat the log.
        public int $payloadLogCap = 256
    ) {
    }

    public static function fromEnv(): self
    {
        $codeRaw = getenv('FUNNYPOT_MQTT_CONNACK');
        $code = ($codeRaw !== false && $codeRaw !== '') ? (int) $codeRaw : 0;

        $spRaw = getenv('FUNNYPOT_MQTT_SESSION_PRESENT');
        $sessionPresent = ($spRaw !== false) ? filter_var($spRaw, FILTER_VALIDATE_BOOLEAN) : false;

        $capRaw = getenv('FUNNYPOT_MQTT_PAYLOAD_CAP');
        $cap = ($capRaw !== false && $capRaw !== '') ? max(0, (int) $capRaw) : 256;

        return new self(
            connackCode: $code,
            sessionPresent: $sessionPresent,
            payloadLogCap: $cap
        );
    }
}
