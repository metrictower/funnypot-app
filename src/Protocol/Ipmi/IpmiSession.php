<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ipmi;

/**
 * State for one inbound IPMI/RMCP datagram.
 *
 * IPMI over UDP is connectionless, so a "session" here is a single request/response exchange rather
 * than a persistent connection: the raw datagram lands in inbuf, the parser fills the captured
 * fields, and any answer is queued in outbuf. Modelling it as a session keeps the shape identical to
 * the TCP emulators (inbuf/outbuf, lastActiveTime, close) so the run loop and tests read the same way.
 *
 * The honeypot is stateless across datagrams by design: it never actually establishes an IPMI session,
 * so each datagram is captured independently. The RMCP+ auth flow is intel to harvest, not a handshake
 * to complete.
 */
final class IpmiSession
{
    public string $inbuf = '';
    public string $outbuf = '';

    /** IPMI session auth-type/format byte (0x00 none .. 0x06 RMCP+/IPMI 2.0). */
    public ?int $authType = null;

    /** RMCP+ payload type (e.g. 0x10 Open Session Req, 0x12 RAKP Message 1), when authType is RMCP+. */
    public ?int $payloadType = null;

    /** IPMI 1.5 message network function and command, when a legacy IPMI message is carried. */
    public ?int $netFn = null;
    public ?int $cmd = null;

    /** The username harvested from a RAKP Message 1 or a Get Session Challenge — the auth intel. */
    public ?string $username = null;

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
