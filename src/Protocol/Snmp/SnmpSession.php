<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Snmp;

/**
 * State for one inbound SNMP datagram.
 *
 * SNMP over UDP is connectionless, so a "session" here is a single request/response exchange rather
 * than a persistent connection: the raw datagram lands in inbuf, the parser fills the captured
 * fields, and any answer is queued in outbuf. Modelling it as a session keeps the shape identical to
 * the TCP emulators (inbuf/outbuf, lastActiveTime, close) so the run loop and tests read the same way.
 */
final class SnmpSession
{
    public string $inbuf = '';
    public string $outbuf = '';

    /** SNMP version on the wire: 0 = v1, 1 = v2c. */
    public ?int $version = null;

    /** The community string the client offered — the SNMP "password" brute-forcers spray. */
    public ?string $community = null;

    /** BER tag of the request PDU (e.g. 0xA0 GetRequest, 0xA1 GetNext, 0xA5 GetBulk). */
    public ?int $pduTag = null;

    /** Dotted OIDs the request asked about. */
    public array $oids = [];

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
