<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Tr069;

/**
 * Per-connection state, buffers and captured intel for one TR-069 / CWMP connection.
 *
 * CWMP rides on HTTP, so a connection is a stream of HTTP request messages framed by Content-Length
 * rather than a fixed handshake. This holds the read/write buffers, the last-seen client fingerprint
 * (User-Agent) and SOAPAction, and the close flag. Nothing is ever authenticated, no command is ever
 * run, and no captured download URL is ever fetched.
 */
final class Tr069Session
{
    public string $inbuf = '';
    public string $outbuf = '';

    // The client tool's User-Agent, first seen (worm droppers and scanners announce themselves).
    public ?string $userAgent = null;

    // The last SOAPAction header seen, used as a fallback for the RPC method.
    public ?string $soapAction = null;

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
