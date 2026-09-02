<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\Ssh\Transport;
use PHPUnit\Framework\TestCase;

/**
 * FP-0291 §4.8 — delayed zlib@openssh.com compression at the {@see Transport} layer. Compression is
 * applied to the payload only, before padding/encryption, as one zlib stream per direction for the
 * connection's life (OpenSSH compress.c). The send side deflates with Z_PARTIAL_FLUSH; the receive
 * side inflates in bounded slices so a zip bomb is caught by the output cap, not by exhausting memory.
 *
 * Every assertion fails at baseline (the compression methods did not exist).
 */
final class SshCompressionTest extends TestCase
{
    /** @return array{0:Transport,1:Transport} [sender, receiver] both compressing, no encryption. */
    private function pair(): array
    {
        $send = new Transport();
        $recv = new Transport();
        $send->enableSendCompression();
        $recv->enableRecvCompression();

        return [$send, $recv];
    }

    public function test_round_trip_over_mixed_payload_sizes(): void
    {
        [$send, $recv] = $this->pair();
        $payloads = [];
        $payloads[] = "\x05";                       // 1 byte
        $payloads[] = str_repeat('a', 32768);       // highly compressible
        for ($i = 0; $i < 48; $i++) {
            $payloads[] = "\x5a" . random_bytes(1 + ($i * 37) % 900); // incompressible, varying length
        }

        $buffer = '';
        foreach ($payloads as $p) {
            $buffer .= $send->frame($p);
        }
        foreach ($payloads as $i => $p) {
            $got = $recv->next($buffer);
            self::assertSame($p, $got, "payload #{$i} round-trips through one compression stream");
        }
        self::assertSame('', $buffer, 'the buffer is fully consumed');
    }

    public function test_highly_compressible_payload_actually_shrinks_on_the_wire(): void
    {
        [$send] = $this->pair();
        $wire = $send->frame(str_repeat('a', 32768));
        self::assertLessThan(1024, strlen($wire), '32 KiB of one byte compresses to well under 1 KiB on the wire');
    }

    public function test_packet_length_is_computed_on_the_compressed_payload(): void
    {
        [$send] = $this->pair();
        $payload = str_repeat('a', 1000);
        $wire = $send->frame($payload);

        // PlainCipher: the 4-byte length field is cleartext. It must equal 1 (padlen byte) + pad +
        // the COMPRESSED payload length — i.e. padding was computed after compression, not before.
        $lenField = unpack('N', substr($wire, 0, 4))[1];
        $ref = deflate_init(ZLIB_ENCODING_DEFLATE, ['level' => 6]);
        $compressed = deflate_add($ref, $payload, ZLIB_PARTIAL_FLUSH);
        $expectedPad = Transport::padLen(strlen($compressed), 8, 0);
        self::assertSame(1 + $expectedPad + strlen($compressed), $lenField, 'packet_length ≡ compressed size + pad + 1');
        self::assertLessThan(strlen($payload), strlen($compressed), 'the payload did compress');
    }

    public function test_one_stream_per_direction_a_missed_packet_desyncs_the_next(): void
    {
        [$send] = $this->pair();
        $p1 = str_repeat('a', 200);
        $p2 = 'the-second-payload-distinct-bytes';
        $buffer = $send->frame($p1) . $send->frame($p2);

        // A receiver that skips packet 1 cannot correctly inflate packet 2: compression is one stream
        // across the whole direction, not reset per packet.
        $recv = new Transport();
        $recv->enableRecvCompression();
        // Feed only packet 2's wire bytes (packet 1's inflate context is missing).
        $second = substr($buffer, $this->firstPacketWireLen($p1));
        try {
            $got = $recv->next($second);
            self::assertNotSame($p2, $got, 'inflating packet 2 without packet 1 does not reproduce it');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString('decompression', $e->getMessage());
        }
    }

    public function test_zip_bomb_is_bounded_before_full_allocation(): void
    {
        // A small compressed payload that inflates to > 262144 bytes must throw, not allocate ~MBs.
        $bombSource = str_repeat("\x00", 400000);
        $ctx = deflate_init(ZLIB_ENCODING_DEFLATE, ['level' => 9]);
        $bomb = deflate_add($ctx, $bombSource, ZLIB_SYNC_FLUSH);
        self::assertLessThan(4096, strlen($bomb), 'the bomb is tiny on the wire');

        // Sender does NOT compress: the wire payload is the raw zlib bomb bytes; the receiver, which
        // DOES have recv compression on, tries to inflate them and must hit the output bound.
        $sender = new Transport();
        $wire = $sender->frame($bomb);
        $recv = new Transport();
        $recv->enableRecvCompression();

        $before = memory_get_peak_usage(true);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('decompression bound');
        try {
            $recv->next($wire);
        } finally {
            self::assertLessThan(8 * 1024 * 1024, memory_get_peak_usage(true) - $before, 'the bomb never fully allocated');
        }
    }

    private function firstPacketWireLen(string $payload): int
    {
        // Re-derive the wire length of a single deflated packet under a fresh stream (the first packet
        // of a stream is what a receiver would consume first).
        $t = new Transport();
        $t->enableSendCompression();

        return strlen($t->frame($payload));
    }
}
