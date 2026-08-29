<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Winrm;

/**
 * Per-connection state, buffers and captured intel for one WinRM connection.
 *
 * WinRM rides on HTTP, so a connection is a stream of HTTP request messages rather than a fixed
 * handshake — and NTLM authentication spans several requests on one persistent connection (the
 * type-1 NEGOTIATE, our type-2 CHALLENGE, then the type-3 AUTHENTICATE that carries the username).
 * This holds the read/write buffers, the last-seen client fingerprint (User-Agent), and the close
 * flag. Nothing is ever authenticated and no command is ever run.
 */
final class WinrmSession
{
    public string $inbuf = '';
    public string $outbuf = '';

    // The client tool's User-Agent, first seen (WinRM scanners and PowerShell announce themselves).
    public ?string $userAgent = null;

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
