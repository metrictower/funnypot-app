<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Adb;

/**
 * Per-connection state for one ADB conversation.
 *
 * ADB frames every message as a 24-byte header plus an optional payload, and multiplexes logical
 * streams over the one TCP connection by local-id / remote-id pairs. The honeypot keeps just enough
 * state to answer the connect, accept the streams a botnet opens, and harvest the service strings and
 * pushed bytes they carry. Nothing is ever executed.
 */
final class AdbSession
{
    public string $inbuf = '';
    public string $outbuf = '';

    /** True once the A_CNXN handshake has been answered. */
    public bool $connected = false;

    /** The client's advertised protocol version and max payload, captured from its A_CNXN. */
    public ?int $clientVersion = null;
    public ?int $clientMaxData = null;

    /** The client's connect banner (its "host::features=..." identity), captured from A_CNXN. */
    public ?string $clientBanner = null;

    /**
     * Open streams: the client's local-id => the id we assigned on our side. A stream stays here while
     * we expect more data (e.g. a sync push streaming a payload) and is dropped once either side closes.
     *
     * @var array<int,int>
     */
    public array $streams = [];

    /** Monotonic id allocator for streams we accept; ADB stream ids must be non-zero. */
    public int $nextLocalId = 1;

    /** Bounds how many pushed-data writes we log per connection so a flood can't flood the event log. */
    public int $pushedLogCount = 0;

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
