<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Mqtt;

/**
 * Tracks the exchange phase, buffers, and captured intel for one MQTT connection.
 *
 * The phases follow the tier-1 capture path: the client must open with CONNECT (its credentials
 * and negotiated protocol level are captured there), after which every SUBSCRIBE / PUBLISH is
 * harvested. Nothing is ever brokered or delivered.
 */
final class MqttSession
{
    // Awaiting the CONNECT packet (per MQTT it must be the first packet on the wire).
    public const STATE_WAIT_CONNECT = 0;
    // CONNECT captured; harvesting SUBSCRIBE / PUBLISH.
    public const STATE_CONNECTED = 1;
    // Connection finished (client disconnected or protocol violation); nothing more to model.
    public const STATE_DONE = 2;

    public int $state = self::STATE_WAIT_CONNECT;
    public string $inbuf = '';
    public string $outbuf = '';

    // Protocol level from CONNECT (4 = 3.1.1, 5 = 5.0). Decides whether later packets carry the
    // MQTT 5.0 property blocks that must be skipped to reach the fields we read.
    public int $protocolLevel = 0;
    public ?string $protocolName = null;
    public ?string $clientId = null;
    // Credentials the client offered in CONNECT, if the username / password flags were set.
    public ?string $username = null;
    public ?string $password = null;
    public int $keepAlive = 0;
    public bool $connectSeen = false;

    public bool $close = false;
    public int $lastActiveTime;

    public function __construct(
        public readonly string $ip,
        public readonly int $port,
        public readonly int $id
    ) {
        $this->lastActiveTime = time();
    }
}
