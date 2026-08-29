<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Dnp3;

/**
 * State and captured recon for one DNP3 connection.
 *
 * DNP3 has no connection handshake of its own: the master simply sends data-link frames, so a
 * "session" here buffers the TCP byte stream (inbuf/outbuf) and holds the fields the honeypot exists
 * to capture — the master's link addresses, the link/application function codes, and the object
 * groups it enumerates. Nothing is ever authenticated, no real point is read, and no control is
 * actuated. Modelling it as a session keeps the shape identical to the other TCP emulators so the run
 * loop and tests read the same way.
 */
final class Dnp3Session
{
    public string $inbuf = '';
    public string $outbuf = '';

    // Link-layer addresses from the last frame: SOURCE is the master, DESTINATION the outstation it
    // addressed (an address sweep shows up as varying destinations) — reconnaissance intel.
    public ?int $sourceAddress = null;
    public ?int $destAddress = null;

    // Last data-link function code (low nibble of the control octet) and application function code.
    public ?int $lastLinkFunction = null;
    public ?int $lastAppFunction = null;

    // Application sequence number of the last request, echoed in our response.
    public int $appSeq = 0;

    // Our own transport-layer sequence, advanced per response frame we emit.
    public int $outstationTransportSeq = 0;

    // Cleared once the first application response has carried the device-restart indication.
    public bool $restartReported = false;

    /**
     * Object headers enumerated in the last application request (group/variation/qualifier). This is
     * the point-map recon we exist to capture.
     *
     * @var list<array{group:int,variation:int,qualifier:int}>
     */
    public array $readObjects = [];

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
