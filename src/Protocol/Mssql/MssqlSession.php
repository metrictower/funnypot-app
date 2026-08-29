<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Mssql;

/**
 * Tracks the TDS exchange state, buffers, and the captured login intel for one MSSQL connection.
 *
 * The phases follow the tier-1 capture path: answer the client's PRELOGIN advertising
 * ENCRYPT_NOT_SUP (so it proceeds unencrypted), then receive the LOGIN7 packet whose obfuscated
 * password is decoded and logged. Nothing is ever authenticated.
 */
final class MssqlSession
{
    public const STATE_PRELOGIN = 0; // awaiting the TDS PRELOGIN (the client speaks first)
    public const STATE_LOGIN = 1;    // PRELOGIN answered; awaiting LOGIN7
    public const STATE_DONE = 2;     // credential captured (and denied); nothing more to model

    public int $state = self::STATE_PRELOGIN;
    public string $inbuf = '';
    public string $outbuf = '';

    // Captured LOGIN7 fields (cleartext once the password is de-obfuscated).
    public ?string $username = null;
    public ?string $password = null;
    public ?string $hostname = null;
    public ?string $appName = null;
    public ?string $libName = null;
    public ?string $database = null;

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
