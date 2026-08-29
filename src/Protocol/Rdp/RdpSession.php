<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Rdp;

/**
 * Tracks the connection phase, buffers and parsed intel for one RDP connection.
 *
 * The phases follow the tier-1 capture path: read the X.224 Connection Request, answer with a
 * Connection Confirm, then walk the MCS connection sequence just far enough to receive the Client
 * Info PDU that carries the credential. Nothing is ever authenticated.
 */
final class RdpSession
{
    // Awaiting the X.224 Connection Request (the first PDU on the wire).
    public const STATE_WAIT_CONNECTION_REQUEST = 0;
    // Connection Confirm sent; walking the MCS sequence up to the credential PDU.
    public const STATE_MCS = 1;
    // Credential captured or connection finished; nothing more to do.
    public const STATE_DONE = 2;

    public int $state = self::STATE_WAIT_CONNECTION_REQUEST;
    public string $inbuf = '';
    public string $outbuf = '';

    // The username a brute-forcer advertises in the mstshash routing cookie, if any.
    public ?string $mstshash = null;
    // The security protocols the client asked for in the RDP Negotiation Request (bit flags).
    public int $requestedProtocols = 0;
    public bool $sawNegotiationRequest = false;

    public bool $close = false;

    public float $connectTime;
    public int $lastActiveTime;

    public function __construct(
        public readonly string $ip,
        public readonly int $port,
        public readonly int $id
    ) {
        $this->connectTime = microtime(true);
        $this->lastActiveTime = time();
    }
}
