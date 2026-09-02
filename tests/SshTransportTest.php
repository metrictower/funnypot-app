<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\Ssh\Buf;
use Funnypot\Protocol\Ssh\Cipher\CipherSuite;
use Funnypot\Protocol\Ssh\Ctr;
use Funnypot\Protocol\Ssh\HostKey;
use Funnypot\Protocol\Ssh\Reader;
use Funnypot\Protocol\Ssh\Transport;
use PHPUnit\Framework\TestCase;

/**
 * Independent-correctness checks for the pure-PHP SSH crypto/wire layer: the hand-rolled AES-CTR
 * keystream is validated against OpenSSL's own aes-*-ctr, the wire codecs round-trip, the host key
 * signs verifiably, and the binary packet transport frames/deframes in both plaintext and
 * encrypted modes. These guard the primitives that real `ssh` interop depends on.
 */
final class SshTransportTest extends TestCase
{
    /** Our streaming CTR must match OpenSSL's one-shot aes-{128,192,256}-ctr for any length and IV. */
    public function test_ctr_matches_openssl_reference(): void
    {
        $iv = substr(hash('sha256', 'ctr-iv', true), 0, 16);
        foreach ([16 => 'aes-128-ctr', 24 => 'aes-192-ctr', 32 => 'aes-256-ctr'] as $keyLen => $method) {
            $key = substr(hash('sha512', "ctr-key-{$keyLen}", true), 0, $keyLen);
            foreach ([1, 15, 16, 17, 64, 200] as $len) {
                $data = random_bytes($len);
                $ours = (new Ctr($key, $iv))->crypt($data);
                $ref = openssl_encrypt($data, $method, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
                self::assertSame(bin2hex($ref), bin2hex($ours), "{$method} length {$len}");
            }
        }
    }

    /**
     * The one-shot counter advance (+ceil(len/16)) must carry across a partial final block AND a
     * 128-bit counter wrap: counter ff*15‖fe, a 17-byte call (2 blocks → wraps to 00..00) then 83.
     */
    public function test_ctr_counter_advance_wraps_across_128_bits(): void
    {
        $key = random_bytes(32);
        $iv = str_repeat("\xff", 15) . "\xfe";
        $c = new Ctr($key, $iv);
        $d1 = random_bytes(17);
        $d2 = random_bytes(83);
        $o1 = $c->crypt($d1);
        $o2 = $c->crypt($d2);
        // Reference: 17 bytes consume 2 full keystream blocks (32 bytes), so d2 starts at counter+2.
        $ref = openssl_encrypt(
            $d1 . str_repeat("\x00", 32 - 17) . $d2,
            'aes-256-ctr',
            $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );
        self::assertSame(bin2hex(substr($ref, 0, 17)), bin2hex($o1), 'first call');
        self::assertSame(bin2hex(substr($ref, 32, 83)), bin2hex($o2), 'second call after wrap');
    }

    /** A non-standard aes key length must throw, not silently truncate (the old aes-192 gap). */
    public function test_ctr_rejects_bad_key_length(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Ctr(random_bytes(20), str_repeat("\x00", 16));
    }

    public function test_ctr_is_symmetric(): void
    {
        $key = random_bytes(32);
        $iv = random_bytes(16);
        $plain = random_bytes(128);
        $cipher = (new Ctr($key, $iv))->crypt($plain);
        $back = (new Ctr($key, $iv))->crypt($cipher);
        self::assertSame($plain, $back);
        self::assertNotSame($plain, $cipher);
    }

    public function test_wire_types_round_trip(): void
    {
        $bytes = (new Buf())
            ->byte(42)
            ->bool(true)
            ->uint32(0xDEADBEEF)
            ->string('hello world')
            ->nameList(['aes256-ctr', 'aes128-ctr'])
            ->get();

        $r = new Reader($bytes);
        self::assertSame(42, $r->byte());
        self::assertTrue($r->bool());
        self::assertSame(0xDEADBEEF, $r->uint32());
        self::assertSame('hello world', $r->string());
        self::assertSame(['aes256-ctr', 'aes128-ctr'], $r->nameList());
    }

    public function test_mpint_encoding_matches_rfc4251_examples(): void
    {
        // Positive value whose top bit is set gets a 0x00 sign byte prepended.
        self::assertSame('00000005' . '00' . 'ff112233', bin2hex(Buf::mpintOf("\xff\x11\x22\x33")));
        // Leading zero bytes are stripped.
        self::assertSame('00000001' . '09', bin2hex(Buf::mpintOf("\x00\x00\x09")));
        // Zero is the empty string.
        self::assertSame('00000000', bin2hex(Buf::mpintOf("\x00")));
    }

    public function test_reader_rejects_truncated_string(): void
    {
        $this->expectException(\RuntimeException::class);
        (new Reader("\x00\x00\x00\x10short"))->string(); // claims 16 bytes, has 5
    }

    public function test_host_key_signature_verifies(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'fpk');
        self::assertNotFalse($path);
        unlink($path);
        try {
            $hostKey = HostKey::load($path);
            self::assertFileExists($path, 'host key is persisted on first use');

            // Reloading the same path yields a stable key (no client host-key warnings).
            $again = HostKey::load($path);
            self::assertSame($hostKey->publicBlob(), $again->publicBlob());

            $hash = random_bytes(32);
            $blob = $hostKey->sign($hash);
            $r = new Reader($blob);
            self::assertSame('ssh-ed25519', $r->string());
            $sig = $r->string();

            $pub = new Reader($hostKey->publicBlob());
            self::assertSame('ssh-ed25519', $pub->string());
            $pubKey = $pub->string();
            self::assertTrue(sodium_crypto_sign_verify_detached($sig, $hash, $pubKey));
        } finally {
            @unlink($path);
        }
    }

    public function test_transport_plaintext_round_trip(): void
    {
        $send = new Transport();
        $recv = new Transport();
        $payload = "\x14" . random_bytes(30);
        $buffer = $send->frame($payload);
        self::assertSame(0, strlen($buffer) % 8, 'plaintext packets are 8-byte aligned');
        self::assertSame($payload, $recv->next($buffer));
        self::assertSame('', $buffer, 'buffer fully consumed');
    }

    public function test_transport_encrypted_round_trip_and_partial_reads(): void
    {
        $key = random_bytes(32);
        $iv = random_bytes(16);
        $mac = random_bytes(32);
        $send = new Transport();
        $recv = new Transport();
        $send->enableSend(CipherSuite::build('aes256-ctr', 'hmac-sha2-256', $key, $iv, $mac));
        $recv->enableRecv(CipherSuite::build('aes256-ctr', 'hmac-sha2-256', $key, $iv, $mac));

        // Three packets in sequence exercise the shared, advancing sequence numbers.
        for ($i = 0; $i < 3; $i++) {
            $payload = chr(90 + $i) . random_bytes(10 + $i * 40);
            $wire = $send->frame($payload);
            self::assertSame(0, (strlen($wire) - 32) % 16, 'ciphertext (excluding MAC) is block-aligned');
            // A partial buffer must yield null until the whole packet (and MAC) has arrived.
            $head = substr($wire, 0, 10);
            self::assertNull($recv->next($head));
            $buf = $wire;
            self::assertSame($payload, $recv->next($buf));
            self::assertSame('', $buf);
        }
    }

    public function test_transport_rejects_tampered_mac(): void
    {
        $key = random_bytes(32);
        $iv = random_bytes(16);
        $mac = random_bytes(32);
        $send = new Transport();
        $recv = new Transport();
        $send->enableSend(CipherSuite::build('aes256-ctr', 'hmac-sha2-256', $key, $iv, $mac));
        $recv->enableRecv(CipherSuite::build('aes256-ctr', 'hmac-sha2-256', $key, $iv, $mac));

        $wire = $send->frame("\x05payload");
        $wire[strlen($wire) - 1] = $wire[strlen($wire) - 1] ^ "\x01"; // flip a MAC bit
        $this->expectException(\RuntimeException::class);
        $recv->next($wire);
    }
}
