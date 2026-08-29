<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Stun;

/**
 * State for one inbound STUN datagram.
 *
 * STUN over UDP is connectionless, so a "session" here is a single request/response exchange rather
 * than a persistent connection: the raw datagram lands in inbuf, the parser fills the captured
 * fields, and any answer is queued in outbuf. Modelling it as a session keeps the shape identical to
 * the other UDP emulators (inbuf/outbuf, lastActiveTime, close) so the run loop and tests read the
 * same way.
 */
final class StunSession
{
    public string $inbuf = '';
    public string $outbuf = '';

    /** STUN message type of the request (e.g. 0x0001 Binding Request). */
    public ?int $messageType = null;

    /** The 12-byte transaction id, echoed verbatim in the response. */
    public ?string $transactionId = null;

    /** The SOFTWARE attribute the client advertised, if any (intel — the tool behind the probe). */
    public ?string $software = null;

    /** The source address we reflected back as XOR-MAPPED-ADDRESS ("ip:port"). */
    public ?string $mappedAddress = null;

    public int $lastActiveTime;
    public bool $close = false;

    public function __construct(
        public readonly string $ip,
        public readonly int $port,
        public readonly int $id
    ) {
        $this->lastActiveTime = time();
    }
}
