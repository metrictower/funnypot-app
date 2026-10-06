<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Dns;

/**
 * Pure RFC 1035 / RFC 6891 DNS wire codec — the message layer of the DNS honeypot (FP-0182). No I/O,
 * no state: decode a query buffer into a {@see DnsQuery}, encode response records. Fully unit-testable.
 *
 * Decode is defensively bounded everywhere: QNAME ≤255 bytes, labels ≤63, pointer jumps are capped AND
 * must move strictly backward (so a crafted compression loop can neither hang nor grow memory), and the
 * question count is capped. Nothing here opens a socket, resolves, executes, or reflects input.
 */
final class DnsMessage
{
    public const HEADER_LEN = 12;

    /** QTYPEs this honeypot distinguishes. */
    public const TYPE_A = 1;
    public const TYPE_NS = 2;
    public const TYPE_SOA = 6;
    public const TYPE_TXT = 16;
    public const TYPE_AAAA = 28;
    public const TYPE_OPT = 41;   // EDNS0 pseudo-RR
    public const TYPE_AXFR = 252;
    public const TYPE_ANY = 255;

    /** QCLASSes. */
    public const CLASS_IN = 1;
    public const CLASS_CH = 3;    // CHAOS (version.bind / id.server)

    /** RCODEs. */
    public const RCODE_NOERROR = 0;
    public const RCODE_SERVFAIL = 2;
    public const RCODE_NXDOMAIN = 3;
    public const RCODE_REFUSED = 5;

    private const MAX_NAME = 255;
    private const MAX_LABEL = 63;
    private const MAX_POINTERS = 64; // hard cap on compression jumps, independent of the backward rule

    /**
     * Decode the header + first question of a query. Returns null if the buffer is too short or malformed
     * (the caller drops it). Only the first question is used (QDCOUNT>1 is rare and bounded away).
     */
    public static function decodeQuery(string $wire): ?DnsQuery
    {
        if (\strlen($wire) < self::HEADER_LEN) {
            return null;
        }
        $id = (\ord($wire[0]) << 8) | \ord($wire[1]);
        $flags = (\ord($wire[2]) << 8) | \ord($wire[3]);
        $qdcount = (\ord($wire[4]) << 8) | \ord($wire[5]);
        $arcount = (\ord($wire[10]) << 8) | \ord($wire[11]);

        if ($qdcount < 1) {
            return null;
        }

        $offset = self::HEADER_LEN;
        $qname = self::decodeName($wire, $offset);
        if ($qname === null || \strlen($wire) < $offset + 4) {
            return null;
        }
        $qtype = (\ord($wire[$offset]) << 8) | \ord($wire[$offset + 1]);
        $qclass = (\ord($wire[$offset + 2]) << 8) | \ord($wire[$offset + 3]);
        $offset += 4;

        // EDNS detection: an OPT RR (type 41) in the additional section advertises a larger UDP buffer.
        // We only need to KNOW it is present (to shape a bounded reply), not fully parse it — and we cap
        // the additional-section walk so a forged ARCOUNT can't drive work.
        $ednsBufsize = self::scanEdns($wire, $offset, $arcount);

        $rd = ($flags & 0x0100) !== 0;

        return new DnsQuery($id, $qname, $qtype, $qclass, $rd, $ednsBufsize);
    }

    /**
     * Decode a domain name starting at $offset, advancing $offset past it (for the FIRST occurrence; a
     * pointer does not advance past the pointer's 2 bytes in the caller's stream beyond its own position).
     * Returns the lowercased dotted name, or null on malformed/looping input.
     */
    public static function decodeName(string $wire, int &$offset): ?string
    {
        $labels = [];
        $len = \strlen($wire);
        $jumped = false;
        $jumps = 0;
        $pos = $offset;
        $nameLen = 0;

        while ($pos < $len) {
            $b = \ord($wire[$pos]);

            if (($b & 0xC0) === 0xC0) { // compression pointer
                if ($pos + 1 >= $len) {
                    return null;
                }
                $target = (($b & 0x3F) << 8) | \ord($wire[$pos + 1]);
                // Must point strictly BEFORE this pointer's own byte — rejects self-reference, forward
                // pointers, and loops. MAX_POINTERS + the 255 name cap are the independent backstops.
                if ($target >= $pos) {
                    return null;
                }
                if (++$jumps > self::MAX_POINTERS) {
                    return null;
                }
                if (!$jumped) {
                    $offset = $pos + 2; // the name in the caller's stream ends after the pointer
                    $jumped = true;
                }
                $pos = $target;
                continue;
            }

            if ($b === 0) { // root — end of name
                if (!$jumped) {
                    $offset = $pos + 1;
                }

                return $labels === [] ? '' : \strtolower(\implode('.', $labels));
            }

            if ($b > self::MAX_LABEL) {
                return null; // top bits not a valid length and not a pointer
            }
            if ($pos + 1 + $b > $len) {
                return null;
            }
            $nameLen += $b + 1;
            if ($nameLen > self::MAX_NAME) {
                return null;
            }
            $labels[] = \substr($wire, $pos + 1, $b);
            $pos += 1 + $b;
        }

        return null; // ran off the end without a root terminator
    }

    /** Bounded scan for an EDNS OPT RR in the additional section; returns advertised UDP size or 0. */
    private static function scanEdns(string $wire, int $offset, int $arcount): int
    {
        $len = \strlen($wire);
        $count = \min($arcount, 8); // cap the walk — a forged ARCOUNT cannot drive work
        for ($i = 0; $i < $count; $i++) {
            $scan = $offset;
            $name = self::decodeName($wire, $scan);
            if ($name === null || $len < $scan + 10) {
                return 0;
            }
            $type = (\ord($wire[$scan]) << 8) | \ord($wire[$scan + 1]);
            $classField = (\ord($wire[$scan + 2]) << 8) | \ord($wire[$scan + 3]);
            $rdlen = (\ord($wire[$scan + 8]) << 8) | \ord($wire[$scan + 9]);
            if ($type === self::TYPE_OPT) {
                return $classField; // OPT CLASS field carries the requestor's UDP payload size
            }
            $offset = $scan + 10 + $rdlen;
            if ($offset > $len) {
                return 0;
            }
        }

        return 0;
    }

    /** Encode a domain name (no compression — always safe, never larger than the source). */
    public static function encodeName(string $name): string
    {
        if ($name === '') {
            return "\x00";
        }
        $out = '';
        foreach (\explode('.', $name) as $label) {
            $label = \substr($label, 0, self::MAX_LABEL);
            $out .= \chr(\strlen($label)) . $label;
        }

        return $out . "\x00";
    }

    /**
     * Build a response header + echoed question. $ancount answer RRs follow (appended by the caller).
     * $tc truncates (TC bit) for the anti-amplification downgrade.
     */
    public static function encodeResponse(DnsQuery $q, int $rcode, int $ancount, bool $tc = false): string
    {
        $flags = 0x8000;            // QR=1 (response)
        if ($q->rd) {
            $flags |= 0x0100;       // echo RD
        }
        if ($tc) {
            $flags |= 0x0200;       // TC=1
        }
        $flags |= ($rcode & 0x0F);

        $header = \chr(($q->id >> 8) & 0xFF) . \chr($q->id & 0xFF)
            . \chr(($flags >> 8) & 0xFF) . \chr($flags & 0xFF)
            . "\x00\x01"                                   // QDCOUNT = 1 (echoed question)
            . \chr(($ancount >> 8) & 0xFF) . \chr($ancount & 0xFF)
            . "\x00\x00"                                   // NSCOUNT
            . "\x00\x00";                                  // ARCOUNT (OPT dropped on the downgrade path)

        $question = self::encodeName($q->qname)
            . \chr(($q->qtype >> 8) & 0xFF) . \chr($q->qtype & 0xFF)
            . \chr(($q->qclass >> 8) & 0xFF) . \chr($q->qclass & 0xFF);

        return $header . $question;
    }

    /** Encode one answer RR: name, type, class, ttl, rdata. */
    public static function encodeRr(string $name, int $type, int $class, int $ttl, string $rdata): string
    {
        return self::encodeName($name)
            . \chr(($type >> 8) & 0xFF) . \chr($type & 0xFF)
            . \chr(($class >> 8) & 0xFF) . \chr($class & 0xFF)
            . \pack('N', $ttl)
            . \chr((\strlen($rdata) >> 8) & 0xFF) . \chr(\strlen($rdata) & 0xFF)
            . $rdata;
    }

    /** A-record rdata from a dotted IPv4 (invalid input → 0.0.0.0, never throws). */
    public static function rdataA(string $ipv4): string
    {
        $packed = @\inet_pton($ipv4);
        if ($packed === false || \strlen($packed) !== 4) {
            return "\x00\x00\x00\x00";
        }

        return $packed;
    }

    /** TXT rdata: one or more length-prefixed character-strings (each ≤255). */
    public static function rdataTxt(string $text): string
    {
        $out = '';
        foreach (\str_split($text, 255) as $chunk) {
            $out .= \chr(\strlen($chunk)) . $chunk;
        }

        return $out === '' ? "\x00" : $out;
    }
}
