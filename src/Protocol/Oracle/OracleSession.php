<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Oracle;

/**
 * Tracks the TNS exchange state, buffers and captured recon for one Oracle listener connection.
 *
 * The phases follow the tier-1 capture path: read the client CONNECT, harvest its connect descriptor
 * (target SERVICE_NAME/SID and the announced PROGRAM/HOST/USER), then answer with a plausible TNS
 * packet. A database connection is never granted.
 */
final class OracleSession
{
    public const STATE_INIT = 0;     // awaiting the TNS CONNECT (the client speaks first)
    public const STATE_ACCEPTED = 1; // TNS ACCEPT sent (accept mode); awaiting the native follow-up
    public const STATE_DONE = 2;     // captured and answered; nothing more to model

    public int $state = self::STATE_INIT;
    public string $inbuf = '';
    public string $outbuf = '';

    // Captured connect-descriptor intel.
    public ?string $descriptor = null; // the raw connect descriptor string
    public ?string $service = null;    // SERVICE_NAME / SERVICE — the DB service the attacker seeks
    public ?string $sid = null;        // SID — the target instance the attacker seeks
    public ?string $program = null;    // client PROGRAM announced in the CID
    public ?string $host = null;       // client HOST announced in the CID (the attacker's machine)
    public ?string $user = null;       // OS USER announced in the CID
    public ?string $command = null;    // listener control COMMAND (ping/version/status/...) if present

    // Set once a RESEND has been sent, so a resent CONNECT is refused rather than looping.
    public bool $resendSent = false;

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
