<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Dns;

use Funnypot\Protocol\Dns\DnsMessage;
use Funnypot\Protocol\Dns\DnsQuery;
use PHPUnit\Framework\TestCase;

/**
 * FP-0182 Phase 1: pure wire codec — header/question decode, pointer decompression + its loop guard,
 * length caps, response encode. No socket.
 */
final class DnsMessageTest extends TestCase
{
    /** A standard query: header + QNAME + QTYPE + QCLASS. */
    private static function query(string $name, int $qtype = DnsMessage::TYPE_A, int $qclass = DnsMessage::CLASS_IN): string
    {
        $q = "\x12\x34"      // id
            . "\x01\x00"     // flags: RD=1
            . "\x00\x01"     // QDCOUNT=1
            . "\x00\x00\x00\x00\x00\x00"; // AN/NS/AR = 0
        $q .= DnsMessage::encodeName($name)
            . \chr(($qtype >> 8) & 0xFF) . \chr($qtype & 0xFF)
            . \chr(($qclass >> 8) & 0xFF) . \chr($qclass & 0xFF);

        return $q;
    }

    public function test_decode_basic_a_query(): void
    {
        $decoded = DnsMessage::decodeQuery(self::query('example.com'));
        self::assertInstanceOf(DnsQuery::class, $decoded);
        self::assertSame(0x1234, $decoded->id);
        self::assertSame('example.com', $decoded->qname);
        self::assertSame(DnsMessage::TYPE_A, $decoded->qtype);
        self::assertSame(DnsMessage::CLASS_IN, $decoded->qclass);
        self::assertTrue($decoded->rd);
    }

    public function test_qname_is_lowercased(): void
    {
        $decoded = DnsMessage::decodeQuery(self::query('ExAmPle.COM'));
        self::assertSame('example.com', $decoded->qname);
    }

    public function test_chaos_and_axfr_types(): void
    {
        $c = DnsMessage::decodeQuery(self::query('version.bind', DnsMessage::TYPE_TXT, DnsMessage::CLASS_CH));
        self::assertTrue($c->isChaos());
        $a = DnsMessage::decodeQuery(self::query('corp.internal', DnsMessage::TYPE_AXFR));
        self::assertSame(DnsMessage::TYPE_AXFR, $a->qtype);
    }

    public function test_too_short_buffer_is_null(): void
    {
        self::assertNull(DnsMessage::decodeQuery("\x00\x00"));
    }

    public function test_valid_backward_compression_decodes(): void
    {
        // Build: at offset 12 the name "a.example.com"; then a second name that is "www" + pointer to 12.
        $wire = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        $base = \strlen($wire); // 12
        $wire .= DnsMessage::encodeName('a.example.com'); // occupies from offset 12
        $ptrOffset = \strlen($wire);
        // A compressed name: label 'www' then a pointer back to offset 12.
        $compressed = "\x03www" . \chr(0xC0 | (($base >> 8) & 0x3F)) . \chr($base & 0xFF);
        $pos = $ptrOffset;
        $name = DnsMessage::decodeName($wire . $compressed, $pos);
        self::assertSame('www.a.example.com', $name);
    }

    public function test_compression_loop_is_rejected_no_hang(): void
    {
        // A pointer at offset 12 that targets itself (12) — not strictly backward → rejected, no hang.
        $wire = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            . "\xC0\x0C"; // pointer to offset 12 (itself)
        $pos = 12;
        self::assertNull(DnsMessage::decodeName($wire, $pos), 'self/forward pointer rejected');
    }

    public function test_forward_pointer_rejected(): void
    {
        // Name at offset 12 points forward to offset 20 — must be rejected (only strictly-backward allowed).
        $wire = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            . "\xC0\x14"   // offset 12: pointer to 20 (forward)
            . "\x00\x00\x00\x00"
            . "\x01a\x00";  // offset 20: a label
        $pos = 12;
        self::assertNull(DnsMessage::decodeName($wire, $pos));
    }

    public function test_oversize_name_rejected(): void
    {
        // Many max labels exceeding 255 total.
        $wire = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        for ($i = 0; $i < 6; $i++) {
            $wire .= \chr(63) . \str_repeat('a', 63); // 4*64 = 256 > 255
        }
        $wire .= "\x00";
        $pos = 12;
        self::assertNull(DnsMessage::decodeName($wire, $pos));
    }

    public function test_edns_bufsize_detected_and_capped_arcount(): void
    {
        // Question + an OPT RR (type 41) in the additional section advertising 4096.
        $wire = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00"
            . "\xFF\xFF"; // ARCOUNT = 65535 (forged — walk must be capped, not driven)
        $wire .= DnsMessage::encodeName('isc.org') . "\x00\xFF" . "\x00\x01"; // ANY IN
        // OPT RR: root name, type 41, CLASS=4096 (udp size), ttl 0, rdlen 0
        $wire .= "\x00" . "\x00\x29" . "\x10\x00" . "\x00\x00\x00\x00" . "\x00\x00";
        $decoded = DnsMessage::decodeQuery($wire);
        self::assertNotNull($decoded);
        self::assertSame(4096, $decoded->ednsBufsize);
        self::assertTrue($decoded->isAmplificationProne());
    }

    public function test_response_encode_round_trips_through_decode_shape(): void
    {
        $q = DnsMessage::decodeQuery(self::query('example.com'));
        $rr = DnsMessage::encodeRr('example.com', DnsMessage::TYPE_A, DnsMessage::CLASS_IN, 60, DnsMessage::rdataA('203.0.113.5'));
        $resp = DnsMessage::encodeResponse($q, DnsMessage::RCODE_NOERROR, 1) . $rr;
        // QR bit set, id echoed, ANCOUNT=1.
        self::assertSame(0x1234, (\ord($resp[0]) << 8) | \ord($resp[1]));
        self::assertSame(0x80, \ord($resp[2]) & 0x80, 'QR=1');
        self::assertSame(1, (\ord($resp[6]) << 8) | \ord($resp[7]), 'ANCOUNT=1');
    }

    public function test_tc_truncated_response_sets_bit_and_zero_answers(): void
    {
        $q = DnsMessage::decodeQuery(self::query('example.com'));
        $resp = DnsMessage::encodeResponse($q, DnsMessage::RCODE_NOERROR, 0, true);
        self::assertSame(0x02, \ord($resp[2]) & 0x02, 'TC=1');
        self::assertSame(0, (\ord($resp[6]) << 8) | \ord($resp[7]), 'ANCOUNT=0');
    }

    public function test_rdata_a_invalid_is_zero(): void
    {
        self::assertSame("\x00\x00\x00\x00", DnsMessage::rdataA('not-an-ip'));
        self::assertSame("\xCB\x00\x71\x05", DnsMessage::rdataA('203.0.113.5'));
    }
}
