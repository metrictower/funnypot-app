<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Kerberos;

/**
 * Buffers and captured intel for one Kerberos TCP connection.
 *
 * Kerberos over TCP frames every message with a 4-byte big-endian length prefix, so a connection may
 * carry a stream of AS-REQs (an enumeration tool pipelines many). The parser fills the captured
 * client-principal / realm / service-name fields per request; nothing is ever authenticated and no
 * ticket is ever issued.
 */
final class KerberosSession
{
    public string $inbuf = '';
    public string $outbuf = '';
    public bool $close = false;

    /** The client principal (cname) the last AS-REQ tried, e.g. "administrator". */
    public ?string $cname = null;
    /** The realm the last AS-REQ named. */
    public ?string $realm = null;
    /** The requested service (sname), e.g. "krbtgt/CORP.LOCAL". */
    public ?string $sname = null;

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
