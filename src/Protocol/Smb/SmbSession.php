<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Smb;

/**
 * Tracks the SMB2 exchange state, buffers, and the per-session NTLM server challenge for one
 * connection. The challenge is what a captured NTLMv2 response is computed against, so it must be
 * held for the life of the session to reconstruct the crackable hash from the AUTHENTICATE.
 */
final class SmbSession
{
    public const STATE_NEGOTIATE = 0;      // awaiting SMB2 NEGOTIATE (the client speaks first)
    public const STATE_SESSION_SETUP = 1;  // negotiated; awaiting SESSION_SETUP / NTLM exchange
    public const STATE_DONE = 2;           // credential captured (or denied); nothing more to model

    public int $state = self::STATE_NEGOTIATE;
    public string $inbuf = '';
    public string $outbuf = '';

    /** Random 8-byte NTLM server challenge sent in the CHALLENGE; the NTLMv2 response is keyed to it. */
    public string $serverChallenge = '';

    /** Opaque 8-byte SessionId echoed back to the client. Cosmetic — never backs a real session. */
    public string $sessionId = '';

    public bool $denied = false;

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
