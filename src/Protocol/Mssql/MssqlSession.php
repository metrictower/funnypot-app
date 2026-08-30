<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Mssql;

/**
 * Tracks the TDS exchange state, buffers, and the captured intel for one MSSQL connection.
 *
 * PRELOGIN is answered advertising ENCRYPT_NOT_SUP (so the client proceeds unencrypted); the LOGIN7
 * password is de-obfuscated and logged. In `low` mode the logon is then denied. In `high` mode the
 * logon is accepted (mock-auth — never verified) and the session advances to STATE_SESSION, where
 * SQLBATCH / RPC requests are answered with fabricated recon result-sets and the xp_cmdshell/RCE
 * chain is trapped. Nothing is ever authenticated for real and no attacker input is ever executed.
 */
final class MssqlSession
{
    public const STATE_PRELOGIN = 0; // awaiting the TDS PRELOGIN (the client speaks first)
    public const STATE_LOGIN = 1;    // PRELOGIN answered; awaiting LOGIN7
    public const STATE_DONE = 2;     // finished (credential captured + denied, or closing)
    public const STATE_SESSION = 3;  // login accepted (high mode); handling batches / RPC

    // A single request message may span several TDS packets; cap the reassembly buffer so a looping
    // or oversized batch cannot grow memory unbounded.
    public const SESSION_MSG_CAP = 262144;

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

    // Accepted session state (high mode only).
    public ?string $authUser = null;    // login accepted for this session
    public string $currentDb = 'master'; // current database context (tracked via ENVCHANGE)
    public bool $xpCmdshellEnabled = false; // flipped by sp_configure 'xp_cmdshell',1 — intel/story only, inert

    // Message reassembly across TDS packets: a non-final packet clears the STATUS_EOM bit, so the
    // body is accumulated by type until EOM before it is dispatched.
    public ?int $msgType = null;
    public string $msgBuf = '';

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
