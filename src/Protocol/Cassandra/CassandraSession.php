<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Cassandra;

/**
 * Tracks the CQL handshake state, buffers, and the captured recon/credential intel for one
 * Cassandra connection.
 *
 * The phases follow the tier-1 capture path: optionally answer OPTIONS with SUPPORTED, answer
 * STARTUP with AUTHENTICATE (naming PasswordAuthenticator) so the driver sends its credential, then
 * receive the AUTH_RESPONSE whose SASL PLAIN token is decoded and logged. Nothing is ever
 * authenticated.
 */
final class CassandraSession
{
    public const STATE_INIT = 0; // awaiting the first frame (OPTIONS or STARTUP; the client speaks first)
    public const STATE_AUTH = 1; // STARTUP answered with AUTHENTICATE; awaiting AUTH_RESPONSE
    public const STATE_DONE = 2; // credential captured (and denied); nothing more to model

    public int $state = self::STATE_INIT;
    public string $inbuf = '';
    public string $outbuf = '';

    // Captured STARTUP recon: the CQL version and driver the client announced.
    public ?string $cqlVersion = null;
    public ?string $driverName = null;
    public ?string $driverVersion = null;

    // Captured AUTH_RESPONSE credential (cleartext, from the SASL PLAIN token).
    public ?string $username = null;
    public ?string $password = null;

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
