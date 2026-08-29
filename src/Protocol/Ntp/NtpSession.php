<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ntp;

/**
 * State for one inbound NTP datagram.
 *
 * NTP over UDP is connectionless, so a "session" here is a single request/response exchange rather
 * than a persistent connection: the raw datagram lands in inbuf, the parser fills the captured
 * fields, and any answer is queued in outbuf. Modelling it as a session keeps the shape identical to
 * the other emulators (inbuf/outbuf, lastActiveTime, close) so the run loop and tests read the same.
 */
final class NtpSession
{
    public string $inbuf = '';
    public string $outbuf = '';

    /** NTP protocol version from the leading byte (VN field, 0-7). */
    public ?int $version = null;

    /** NTP mode from the leading byte (3 = client, 4 = server, 6 = control, 7 = private). */
    public ?int $mode = null;

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
