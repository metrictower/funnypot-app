<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Coap;

/**
 * State for one inbound CoAP datagram.
 *
 * CoAP over UDP is connectionless, so a "session" here is a single request/response exchange rather
 * than a persistent connection: the raw datagram lands in inbuf, the parser fills the captured
 * fields, and any answer is queued in outbuf. Modelling it as a session keeps the shape identical to
 * the TCP emulators (inbuf/outbuf, lastActiveTime, close) so the run loop and tests read the same way.
 */
final class CoapSession
{
    public string $inbuf = '';
    public string $outbuf = '';

    /** Message type: 0 CON (confirmable), 1 NON (non-confirmable), 2 ACK, 3 RST. */
    public ?int $type = null;

    /** Raw 8-bit code byte (class in the top 3 bits, detail in the low 5). */
    public ?int $code = null;

    /** Human-readable method: GET / POST / PUT / DELETE, or the c.dd code for anything else. */
    public ?string $method = null;

    /** 16-bit message id — echoed on the reply so it matches the request. */
    public ?int $messageId = null;

    /** 0-8 byte token — echoed on the reply so the client can correlate it. */
    public string $token = '';

    /** Assembled Uri-Path (the resource the attacker probed), e.g. "/.well-known/core". */
    public ?string $path = null;

    /** Assembled Uri-Query, '&'-joined ('' when none). */
    public ?string $query = null;

    /** Request payload bytes (the data a POST/PUT tried to push). */
    public string $payload = '';

    /** Byte length of the received datagram — the ceiling every reply is capped to (anti-amplification). */
    public int $requestLength = 0;

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
