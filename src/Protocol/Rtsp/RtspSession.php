<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Rtsp;

/**
 * Per-connection state, buffers and captured intel for one RTSP connection.
 *
 * RTSP is an HTTP-like text protocol, so a connection is a stream of request messages rather than a
 * fixed handshake. This holds the read/write buffers, the last-seen client fingerprint (User-Agent),
 * the stream path an attacker is probing, and any credentials harvested from an Authorization header.
 * Nothing is ever authenticated and no real media is ever served.
 */
final class RtspSession
{
    public string $inbuf = '';
    public string $outbuf = '';

    // The most recent stream path requested (e.g. /Streaming/Channels/101) — fingerprints the camera
    // model the attacker is targeting.
    public ?string $streamPath = null;
    // The client tool's User-Agent, first seen (RTSP scanners announce themselves here).
    public ?string $userAgent = null;
    // A synthetic session id handed out on SETUP so PLAY/TEARDOWN look answered; never a real session.
    public ?string $rtspSessionId = null;

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
