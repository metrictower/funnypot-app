<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Bacnet;

/**
 * State for one inbound BACnet/IP datagram.
 *
 * BACnet/IP over UDP is connectionless, so a "session" here is a single request/response exchange
 * rather than a persistent connection: the raw datagram lands in inbuf, the parser fills the
 * captured fields, and any answer is queued in outbuf. Modelling it as a session keeps the shape
 * identical to the TCP emulators (inbuf/outbuf, lastActiveTime, close) so the run loop and tests
 * read the same way.
 */
final class BacnetSession
{
    public string $inbuf = '';
    public string $outbuf = '';

    /** BVLC function code of the received message (e.g. 0x0A original-unicast, 0x0B broadcast). */
    public ?int $bvlcFunction = null;

    /** APDU type nibble (0=confirmed-request, 1=unconfirmed-request, ...). */
    public ?int $apduType = null;

    /** Service choice byte (e.g. 0x08 Who-Is, 0x0C ReadProperty). */
    public ?int $service = null;

    /** Confirmed-request invoke id, echoed on any response. */
    public ?int $invokeId = null;

    // Who-Is: the optional device-instance range the scanner is probing (null = "everybody").
    public ?int $whoIsLow = null;
    public ?int $whoIsHigh = null;

    // ReadProperty: the object + property being enumerated (device/point recon).
    public ?int $readObjectType = null;
    public ?int $readObjectInstance = null;
    public ?int $readPropertyId = null;
    public ?int $readArrayIndex = null;

    /** Byte length of the received datagram — the ceiling every reply is capped to (anti-amplification). */
    public int $requestLength = 0;

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
