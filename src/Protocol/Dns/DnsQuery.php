<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Dns;

/** Immutable decoded DNS query (header + first question + EDNS hint). Pure value object. */
final class DnsQuery
{
    public function __construct(
        public int $id,
        public string $qname,   // lowercased dotted name ('' = root)
        public int $qtype,
        public int $qclass,
        public bool $rd,        // recursion desired (echoed back)
        public int $ednsBufsize // advertised EDNS0 UDP payload size, 0 if none
    ) {
    }

    public function isChaos(): bool
    {
        return $this->qclass === DnsMessage::CLASS_CH;
    }

    public function isAmplificationProne(): bool
    {
        return $this->qtype === DnsMessage::TYPE_ANY
            || $this->qtype === DnsMessage::TYPE_TXT
            || $this->ednsBufsize > 512
            || $this->qname === ''; // root-zone query
    }
}
