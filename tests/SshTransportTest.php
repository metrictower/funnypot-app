<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\Ssh\Buf;
use Funnypot\Protocol\Ssh\Cipher\CipherSuite;
use Funnypot\Protocol\Ssh\Ctr;
use Funnypot\Protocol\Ssh\HostKey\Ed25519;
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
            $hostKey = Ed25519::load($path);
            self::assertFileExists($path, 'host key is persisted on first use');

            // Reloading the same path yields a stable key (no client host-key warnings).
            $again = Ed25519::load($path);
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

    // --- FP-0290 §4.1: the strict-kex sequence-number reset is per-direction and changes the wire ---

    /**
     * Four reset combinations per cipher class. Both sides frame/consume three plaintext packets
     * (KEXINIT/REPLY/NEWKEYS → seq 3) then switch ciphers with the reset flags under test; the first
     * encrypted packet opens iff both directions agree on the next sequence number. For a
     * sequence-dependent cipher (E&M / ETM covers the MAC over BE32(seq); chacha uses seq as the
     * nonce) only TT and FF agree — TF/FT garble (MAC failure or bad length). GCM's per-packet state
     * is its own IV invocation counter, not the SSH sequence number, so all four open.
     *
     * Non-vacuous by construction: at baseline enableSend/enableRecv silently ignore the extra bool
     * (PHP accepts extra args to a user method), so no reset happens and the TF/FT rows open — the
     * expectException then fails. A no-op reset cannot pass this matrix.
     *
     * @dataProvider strictResetMatrix
     */
    public function test_strict_kex_reset_is_per_direction_and_changes_the_wire(
        string $cipher,
        string $mac,
        bool $serverReset,
        bool $clientReset,
        bool $expectOpen
    ): void {
        $send = new Transport();
        $recv = new Transport();
        for ($i = 0; $i < 3; $i++) {
            $p = chr(20 + $i) . random_bytes(8);
            $buf = $send->frame($p);
            self::assertSame($p, $recv->next($buf), 'plaintext KEX packet round-trips');
        }
        [$sc, $rc] = $this->cipherPair($cipher, $mac);
        $send->enableSend($sc, $serverReset);
        $recv->enableRecv($rc, $clientReset);

        $payload = "\x07" . random_bytes(16); // models the first encrypted packet (EXT_INFO)
        $wire = $send->frame($payload);

        if ($expectOpen) {
            self::assertSame($payload, $recv->next($wire), 'first encrypted packet opens when both directions agree');

            return;
        }
        $this->expectException(\RuntimeException::class); // S2: message differs by cipher (MAC vs bad length)
        $recv->next($wire);
    }

    /** @return array<string,array{0:string,1:string,2:bool,3:bool,4:bool}> */
    public static function strictResetMatrix(): array
    {
        $rows = [];
        foreach (self::seqDependentCiphers() as $label => [$cipher, $mac]) {
            $rows["{$label}: TT opens"] = [$cipher, $mac, true, true, true];
            $rows["{$label}: FF opens (legacy continuous)"] = [$cipher, $mac, false, false, true];
            $rows["{$label}: TF throws"] = [$cipher, $mac, true, false, false];
            $rows["{$label}: FT throws"] = [$cipher, $mac, false, true, false];
        }
        // GCM opens in all four — documents that its IV counter, not the seq, is its per-packet state.
        foreach ([true, false] as $s) {
            foreach ([true, false] as $c) {
                $tag = ($s ? 'T' : 'F') . ($c ? 'T' : 'F');
                $rows["aes256-gcm: {$tag} opens (IV counter, not seq)"] = ['aes256-gcm@openssh.com', 'hmac-sha2-256', $s, $c, true];
            }
        }

        return $rows;
    }

    /**
     * S1 — asymmetric "fresh receiver / fresh sender" rows that pin the reset target to EXACTLY 0,
     * not merely "some value both sides share" (TT alone opens even if both reset to 1). One side
     * resets after three packets; the other is a fresh Transport whose counter is 0 by construction.
     *
     * @dataProvider seqDependentCipherRows
     */
    public function test_strict_kex_reset_targets_exactly_zero(string $cipher, string $mac): void
    {
        // Row 1: a sender that framed 3 packets then reset (outSeq→0) must agree with a FRESH
        // receiver whose inSeq is 0 by construction (it never consumed anything). Pins outSeq === 0.
        $send = new Transport();
        for ($i = 0; $i < 3; $i++) {
            $send->frame(chr(20 + $i) . random_bytes(8));
        }
        [$sc, $rc] = $this->cipherPair($cipher, $mac);
        $send->enableSend($sc, true);
        $freshRecv = new Transport();
        $freshRecv->enableRecv($rc, false);
        $payload = "\x07" . random_bytes(16);
        $wire = $send->frame($payload);
        self::assertSame($payload, $freshRecv->next($wire), 'reset sender (outSeq→0) agrees with a fresh receiver at 0');

        // Row 2 (mirror): a receiver that consumed 3 packets then reset (inSeq→0) must agree with a
        // fresh sender whose outSeq is 0 by construction. A throwaway advancer pushes the 3 packets
        // so the real sender stays fresh. Pins inSeq === 0.
        $advancer = new Transport();
        $recv = new Transport();
        for ($i = 0; $i < 3; $i++) {
            $p = chr(20 + $i) . random_bytes(8);
            $buf = $advancer->frame($p);
            self::assertSame($p, $recv->next($buf));
        }
        [$sc2, $rc2] = $this->cipherPair($cipher, $mac);
        $recv->enableRecv($rc2, true);
        $freshSend = new Transport();
        $freshSend->enableSend($sc2, false);
        $payload2 = "\x07" . random_bytes(16);
        $wire2 = $freshSend->frame($payload2);
        self::assertSame($payload2, $recv->next($wire2), 'reset receiver (inSeq→0) agrees with a fresh sender at 0');
    }

    public function test_last_in_seq_tracks_consumed_packets(): void
    {
        $send = new Transport();
        $recv = new Transport();
        for ($i = 0; $i < 3; $i++) {
            $p = chr(20 + $i) . random_bytes(8);
            $buf = $send->frame($p);
            self::assertSame($p, $recv->next($buf));
            self::assertSame($i, $recv->lastInSeq(), "lastInSeq === {$i} after the packet at seq {$i}");
        }
        // Under strict kex both counters reset at NEWKEYS; the next consumed packet is seq 0 again.
        [$sc, $rc] = $this->cipherPair('aes256-ctr', 'hmac-sha2-256');
        $send->enableSend($sc, true);
        $recv->enableRecv($rc, true);
        $payload = "\x07" . random_bytes(16);
        $wire = $send->frame($payload);
        self::assertSame($payload, $recv->next($wire));
        self::assertSame(0, $recv->lastInSeq(), 'lastInSeq is 0 again after the inbound reset');
    }

    /** @return array<string,array{0:string,1:string}> */
    public static function seqDependentCipherRows(): array
    {
        $rows = [];
        foreach (self::seqDependentCiphers() as $label => $pair) {
            $rows[$label] = $pair;
        }

        return $rows;
    }

    /** @return array<string,array{0:string,1:string}> cipher classes whose wire depends on the sequence number */
    private static function seqDependentCiphers(): array
    {
        return [
            'aes256-ctr E&M' => ['aes256-ctr', 'hmac-sha2-256'],
            'aes128-ctr ETM' => ['aes128-ctr', 'hmac-sha2-256-etm@openssh.com'],
            'chacha20-poly1305' => ['chacha20-poly1305@openssh.com', 'hmac-sha2-256'],
        ];
    }

    /**
     * A matched send/recv cipher pair sharing key material.
     *
     * @return array{0:\Funnypot\Protocol\Ssh\Cipher\PacketCipher,1:\Funnypot\Protocol\Ssh\Cipher\PacketCipher}
     */
    private function cipherPair(string $cipher, string $mac): array
    {
        $key = random_bytes(CipherSuite::keyLen($cipher));
        $iv = CipherSuite::ivLen($cipher) > 0 ? random_bytes(CipherSuite::ivLen($cipher)) : '';
        $macKey = random_bytes(CipherSuite::macKeyLen($mac));

        return [
            CipherSuite::build($cipher, $mac, $key, $iv, $macKey),
            CipherSuite::build($cipher, $mac, $key, $iv, $macKey),
        ];
    }
}
