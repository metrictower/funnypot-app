<?php

declare(strict_types=1);

namespace Funnypot\Protocol\S7comm;

/**
 * Tracks the connection phase, buffers and captured recon for one S7comm connection.
 *
 * The phases follow the tier-1 capture path: read the COTP Connection Request, answer with a
 * Connection Confirm, then serve S7comm Job / Userdata PDUs (Setup Communication, Read/Write Var,
 * SZL identity reads) just far enough to log the enumeration an attacker performs. Nothing is ever
 * authenticated, no real memory is read, and no write is ever applied.
 */
final class S7commSession
{
    // Awaiting the COTP Connection Request (the first PDU on the wire).
    public const STATE_WAIT_COTP_CR = 0;
    // Connection Confirm sent; serving S7comm Job / Userdata PDUs.
    public const STATE_CONNECTED = 1;
    // Connection finished; nothing more to do.
    public const STATE_DONE = 2;

    public int $state = self::STATE_WAIT_COTP_CR;
    public string $inbuf = '';
    public string $outbuf = '';

    // COTP TSAPs from the Connection Request: the destination TSAP encodes the rack/slot the client
    // is reaching for, which is reconnaissance intel.
    public ?int $srcTsap = null;
    public ?int $dstTsap = null;
    public ?int $tpduSizeCode = null;

    // PDU size negotiated in Setup Communication, once seen.
    public ?int $negotiatedPduSize = null;

    /**
     * Memory areas an attacker enumerated via Read/Write Var — each entry is the parsed address
     * (area, DB number, byte/bit offset, element count, transport size). This is the PLC-memory
     * recon we exist to capture.
     *
     * @var list<array{op:string,area:int,db:int,byte:int,bit:int,count:int,transport:int}>
     */
    public array $reads = [];

    // SZL identity reads seen (SZL-ID => index), for tests and intel.
    /** @var list<array{id:int,index:int}> */
    public array $szlReads = [];

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
