<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\Ssh\Cipher\ChaChaPoly;
use Funnypot\Protocol\Ssh\Cipher\CipherSuite;
use Funnypot\Protocol\Ssh\Cipher\CtrHmac;
use Funnypot\Protocol\Ssh\Cipher\Gcm;
use Funnypot\Protocol\Ssh\Cipher\Poly1305;
use Funnypot\Protocol\Ssh\Ctr;
use Funnypot\Protocol\Ssh\HostKey;
use Funnypot\Protocol\Ssh\Reader;
use Funnypot\Protocol\Ssh\SshConnection;
use Funnypot\Protocol\Ssh\Transport;
use PHPUnit\Framework\TestCase;

/**
 * Independent-correctness checks for the SSH packet-cipher / MAC layer (FP-0288): RFC 8439
 * Poly1305 and ChaCha20 vectors, the libsodium chacha20-poly1305 oracle, AES-GCM NIST vectors,
 * seal/open round-trips per cipher class, the aadlen-aware padding rule, verify-before-decrypt
 * for ETM/GCM/chacha, and a HASSH pin proving this ticket moved no served bytes. Every new
 * assertion names its fixture and fails at baseline (the classes did not exist).
 */
final class SshCipherTest extends TestCase
{
    // --- §4.1 Poly1305 (RFC 8439 §2.5.2 + A.3 edge vectors) ---

    public function test_poly1305_rfc8439_2_5_2(): void
    {
        $key = hex2bin('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b');
        self::assertSame(
            'a8061dc1305136c6c22b8baf0c0127a9',
            bin2hex(Poly1305::mac($key, 'Cryptographic Forum Research Group'))
        );
    }

    /**
     * RFC 8439 A.3 hex-defined vectors, bytes taken from the RFC (not the prose paraphrase). These
     * are the carry-edge cases (#5/#6/#8/#9 hit the 2^130-5 boundary that the finalisation
     * sign-mask governs; the arithmetic-shift porting hazard fails #6/#8/#9 by +4).
     *
     * @dataProvider poly1305A3Vectors
     */
    public function test_poly1305_rfc8439_a3(string $keyHex, string $msgHex, string $tagHex): void
    {
        self::assertSame($tagHex, bin2hex(Poly1305::mac(hex2bin($keyHex), hex2bin($msgHex))));
    }

    /** @return array<string,array{0:string,1:string,2:string}> */
    public static function poly1305A3Vectors(): array
    {
        $z16 = str_repeat('00', 16);
        $z15 = str_repeat('00', 15);

        // The 375-byte IETF text (#2/#3) and the 127-byte Jabberwocky text (#4), as message hex.
        $ietf = '416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465'
            . '642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e2061'
            . '7320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d44726166'
            . '74206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e'
            . '2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f'
            . '6e7369646572656420616e20224945544620436f6e747269627574696f6e222e205375636820'
            . '73746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20'
            . '494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420'
            . '656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e7920'
            . '74696d65206f7220706c6163652c207768696368206172652061646472657373656420746f';
        $jabber = '2754776173206272696c6c69672c20616e642074686520736c6974687920746f766573'
            . '0a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c20'
            . '6d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65'
            . '207261746873206f757467726162652e';

        return [
            '#1 zero key, 64 zero bytes' => [str_repeat('00', 32), str_repeat('00', 64), $z16],
            '#2 IETF text, r=0' => [$z16 . '36e5f6b5c5e06070f0efca96227a863e', $ietf, '36e5f6b5c5e06070f0efca96227a863e'],
            '#3 IETF text, s=0' => ['36e5f6b5c5e06070f0efca96227a863e' . $z16, $ietf, 'f3477e7cd95417af89a6b8794c310cf0'],
            '#4 Jabberwocky multi-block' => [
                '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0',
                $jabber,
                '4541669a7eaaee61e708dc7cbcc5eb62',
            ],
            '#5 partial reduction' => ['02' . $z15 . $z16, str_repeat('ff', 16), '03' . $z15],
            '#6 s add overflow mod 2^128' => ['02' . $z15 . str_repeat('ff', 16), '02' . $z15, '03' . $z15],
            '#7 all-ones limb carry' => [
                '01' . $z15 . $z16,
                str_repeat('ff', 16) . 'f0' . str_repeat('ff', 15) . '11' . $z15,
                '05' . $z15,
            ],
            '#8 result exactly 2^130-5' => [
                '01' . $z15 . $z16,
                str_repeat('ff', 16) . 'fb' . str_repeat('fe', 15) . str_repeat('01', 16),
                $z16,
            ],
            '#9 result exactly 2^130-6' => ['02' . $z15 . $z16, 'fd' . str_repeat('ff', 15), 'fa' . str_repeat('ff', 15)],
            '#10 131-bit intermediate' => [
                '01000000000000000400000000000000' . $z16,
                'e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000' . $z16 . '01' . $z15,
                '14' . str_repeat('00', 7) . '55' . str_repeat('00', 7),
            ],
            '#11 131-bit final' => [
                '01000000000000000400000000000000' . $z16,
                'e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000' . $z16,
                '13' . $z15,
            ],
        ];
    }

    public function test_poly1305_rejects_short_key(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Poly1305::mac(str_repeat("\x00", 16), 'x');
    }

    // --- §4.1 ChaCha20 keystream ---

    public function test_chacha20_keystream_rfc_vector(): void
    {
        // key 00..01, nonce 0102030405060708, counter 1 (via ChaChaPoly's OpenSSL wrapper).
        $key = str_repeat("\x00", 31) . "\x01";
        $nonce = hex2bin('0102030405060708');
        $ks = $this->chacha20($key, 1, $nonce, str_repeat("\x00", 64));
        self::assertSame(
            '3de041a6e0468d10ca8c7c08569162e0de1bc36c88afdc213a568bc4b704af5c',
            substr(bin2hex($ks), 0, 64)
        );
    }

    /** The OpenSSL 'chacha20' counter is a true 64-bit block counter (no wrap at 2^32). */
    public function test_chacha20_counter_is_64_bit(): void
    {
        $key = random_bytes(32);
        $nonce = random_bytes(8);
        $crossing = substr($this->chacha20($key, (1 << 32) - 1, $nonce, str_repeat("\x00", 128)), 64);
        self::assertSame(
            bin2hex($this->chacha20($key, 1 << 32, $nonce, str_repeat("\x00", 64))),
            bin2hex($crossing),
            'block after 2^32-1 == block 2^32'
        );
        self::assertNotSame(
            bin2hex($this->chacha20($key, 0, $nonce, str_repeat("\x00", 64))),
            bin2hex($crossing),
            'did not wrap to counter 0'
        );
    }

    /**
     * The strongest primitive cross-check: libsodium's ORIGINAL (8-byte-nonce) chacha20-poly1305
     * equals OpenSSL-chacha ciphertext ‖ our pure-PHP Poly1305 over aad‖LE64‖ct‖LE64. This
     * independently validates the OpenSSL IV layout at ctr 0 and 1, the Poly1305 key = keystream
     * block 0, and Poly1305 itself, against a library we do not control.
     */
    public function test_chacha20poly1305_sodium_oracle(): void
    {
        for ($i = 0; $i < 50; $i++) {
            $key = random_bytes(32);
            $nonce = random_bytes(8);
            // random_bytes(0) throws ValueError in PHP 8, so guard the 0-length case (|m|=0 and
            // |aad|=0 both flow correctly through the sodium call and the OpenSSL chacha helper).
            $mLen = random_int(0, 300);
            $aadLen = random_int(0, 100);
            $m = $mLen === 0 ? '' : random_bytes($mLen);
            $aad = $aadLen === 0 ? '' : random_bytes($aadLen);

            $ref = sodium_crypto_aead_chacha20poly1305_encrypt($m, $aad, $nonce, $key);
            $polyKey = substr($this->chacha20($key, 0, $nonce, str_repeat("\x00", 32)), 0, 32);
            $ct = $this->chacha20($key, 1, $nonce, $m);
            $mac = Poly1305::mac($polyKey, $aad . pack('P', strlen($aad)) . $ct . pack('P', strlen($ct)));

            self::assertSame(bin2hex($ref), bin2hex($ct . $mac), "oracle case {$i}");
        }
    }

    // --- §4.1 AES-GCM (NIST GCM spec test cases, the runtime primitive) ---

    public function test_aes_gcm_nist_vectors(): void
    {
        $p = hex2bin('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72'
            . '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39');
        $a = hex2bin('feedfacedeadbeeffeedfacedeadbeefabaddad2');
        $iv = hex2bin('cafebabefacedbaddecaf888');

        // Test Case 4 (AES-128).
        $tag = '';
        $c = openssl_encrypt($p, 'aes-128-gcm', hex2bin('feffe9928665731c6d6a8f9467308308'), OPENSSL_RAW_DATA, $iv, $tag, $a, 16);
        self::assertSame('5bc94fbc3221a5db94fae95ae7121a47', bin2hex($tag), 'TC4 tag');
        self::assertSame(
            '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e'
            . '21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091',
            bin2hex($c),
            'TC4 ciphertext'
        );

        // Test Case 16 (AES-256, the case-4 key doubled).
        $tag2 = '';
        openssl_encrypt($p, 'aes-256-gcm', hex2bin('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308'), OPENSSL_RAW_DATA, $iv, $tag2, $a, 16);
        self::assertSame('76fc6ece0f4e1768cddf8853bb2d551b', bin2hex($tag2), 'TC16 tag');
    }

    public function test_gcm_rejects_non_128_256_key(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Gcm(random_bytes(24), random_bytes(12)); // no SSH name maps to aes-192-gcm
    }

    // --- §4.2 seal → open round trips, one row per cipher class ---

    /** @dataProvider cipherRows */
    public function test_seal_open_round_trip(string $cipher, string $mac): void
    {
        [$send, $recv] = $this->transportPair($cipher, $mac);

        foreach ([1, 50, 1000] as $len) {
            $payload = chr($len & 0xff) . random_bytes($len);
            $wire = $send->frame($payload);

            // Partial buffers on the SAME receiver: nothing consumed, then the full packet opens
            // (the head-then-body caching is exactly this incremental-arrival path).
            $one = substr($wire, 0, 1);
            self::assertNull($recv->next($one), 'one byte is not enough');
            self::assertSame(1, strlen($one), 'partial buffer untouched');
            $short = substr($wire, 0, strlen($wire) - 1);
            self::assertNull($recv->next($short), 'one byte short of complete');

            $buf = $wire;
            self::assertSame($payload, $recv->next($buf), "{$cipher}/{$mac} len {$len}");
            self::assertSame('', $buf, 'buffer fully consumed');
        }
    }

    /** @dataProvider cipherRows */
    public function test_seal_open_rejects_tampered_tag(string $cipher, string $mac): void
    {
        [$send, $recv] = $this->transportPair($cipher, $mac);
        $wire = $send->frame("\x14payload-under-test");
        $wire[strlen($wire) - 1] = $wire[strlen($wire) - 1] ^ "\x01"; // flip a MAC/tag bit
        $this->expectException(\RuntimeException::class);
        $recv->next($wire);
    }

    /** @return array<string,array{0:string,1:string}> */
    public static function cipherRows(): array
    {
        return [
            'aes128-ctr E&M sha1' => ['aes128-ctr', 'hmac-sha1'],
            'aes192-ctr E&M sha256' => ['aes192-ctr', 'hmac-sha2-256'],
            'aes256-ctr E&M sha512' => ['aes256-ctr', 'hmac-sha2-512'],
            'aes128-ctr ETM sha256' => ['aes128-ctr', 'hmac-sha2-256-etm@openssh.com'],
            'aes256-ctr ETM sha512' => ['aes256-ctr', 'hmac-sha2-512-etm@openssh.com'],
            'aes128-gcm' => ['aes128-gcm@openssh.com', 'hmac-sha2-256'],
            'aes256-gcm' => ['aes256-gcm@openssh.com', 'hmac-sha2-256'],
            'chacha20-poly1305' => ['chacha20-poly1305@openssh.com', 'hmac-sha2-256'],
        ];
    }

    // --- §4.3 the aadlen-aware padding rule ---

    /**
     * The corrected §2.2 KAT table (payload → pad → packet_length). The payload-12 ETM/GCM and
     * chacha rows are the ones the plan-review fixed (they exercise the pad<4 → +block step).
     *
     * @dataProvider padLenVectors
     */
    public function test_pad_len_kat(int $payload, int $block, int $aad, int $pad, int $packetLen): void
    {
        self::assertSame($pad, Transport::padLen($payload, $block, $aad), 'pad');
        self::assertSame($packetLen, 1 + $payload + $pad, 'packet_length');
    }

    /** @return array<string,array{0:int,1:int,2:int,3:int,4:int}> */
    public static function padLenVectors(): array
    {
        return [
            // E&M / AES (block 16, aad 0)
            'E&M p1' => [1, 16, 0, 10, 12],
            'E&M p11' => [11, 16, 0, 16, 28],
            'E&M p12' => [12, 16, 0, 15, 28],
            // ETM / GCM (block 16, aad 4)
            'ETM p1' => [1, 16, 4, 14, 16],
            'ETM p11' => [11, 16, 4, 4, 16],
            'ETM p12 (+block)' => [12, 16, 4, 19, 32],
            'ETM p15' => [15, 16, 4, 16, 32],
            // chacha (block 8, aad 4)
            'chacha p1' => [1, 8, 4, 6, 8],
            'chacha p5 (+block)' => [5, 8, 4, 10, 16],
            'chacha p7' => [7, 8, 4, 8, 16],
            'chacha p12 (+block)' => [12, 8, 4, 11, 24],
            // plain (block 8, aad 0)
            'plain p1' => [1, 8, 0, 10, 12],
        ];
    }

    public function test_pad_len_property(): void
    {
        foreach ([[16, 0], [16, 4], [8, 4], [8, 0]] as [$block, $aad]) {
            for ($payload = 0; $payload <= 64; $payload++) {
                $pad = Transport::padLen($payload, $block, $aad);
                self::assertGreaterThanOrEqual(4, $pad, "block {$block} aad {$aad} payload {$payload}");
                self::assertLessThan($block + 4, $pad);
                self::assertSame(0, ((4 - $aad) + 1 + $payload + $pad) % $block, 'aligned');
            }
        }
    }

    /**
     * Non-vacuity: a 1-byte chacha payload frames to packet_length 8 under the new rule (the old
     * length-included block-16 rule would give 12), and the receiver rejects a hand-built chacha
     * packet whose length field decrypts to 12 (12 % 8 != 0) — i.e. we reject what a real client
     * rejects.
     */
    public function test_chacha_padding_is_not_the_old_rule(): void
    {
        $key = random_bytes(64);
        $send = new Transport();
        $send->enableSend(new ChaChaPoly($key));
        $wire = $send->frame("\x14"); // 1-byte payload
        $peeked = (new ChaChaPoly($key))->peekLength(0, substr($wire, 0, 4));
        self::assertSame(8, $peeked, 'new-rule packet_length for a 1-byte chacha payload');

        // Hand-build a packet whose clear length decrypts to 12 (the old-rule value) and feed it.
        $bogus = (new ChaChaPoly($key))->seal(0, pack('N', 12) . str_repeat("\x00", 12));
        $recv = new Transport();
        $recv->enableRecv(new ChaChaPoly($key));
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('ssh: bad packet length');
        $recv->next($bogus);
    }

    public function test_receive_rejects_misaligned_plaintext(): void
    {
        // packet_length 8 → 4+8 = 12, not ≡ 0 (mod 8) → the plaintext alignment MUST now rejects it.
        $recv = new Transport();
        $buffer = pack('N', 8) . str_repeat("\x00", 12);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('ssh: bad packet length');
        $recv->next($buffer);
    }

    public function test_receive_rejects_padlen_below_4(): void
    {
        // A well-aligned plaintext packet whose padlen field is 3 → RFC 4253 §6 MUST reject.
        // packet_length 12 keeps 4+12 ≡ 0 (mod 8) so it passes alignment: 12 = 1 + 8(payload) + 3(pad).
        $recv = new Transport();
        $buffer = pack('N', 12) . chr(3) . str_repeat("\x00", 8) . str_repeat("\x00", 3);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('ssh: bad padding');
        $recv->next($buffer);
    }

    // --- §4.2 cipher-specific state pins ---

    public function test_gcm_iv_increments_per_packet(): void
    {
        $fixed = random_bytes(4);
        $gcm = new Gcm(random_bytes(32), $fixed . str_repeat("\x00", 8));
        for ($n = 1; $n <= 5; $n++) {
            $gcm->seal(0, pack('N', 0) . str_repeat("\x00", 16));
            self::assertSame(bin2hex($fixed . pack('J', $n)), bin2hex($gcm->iv()), "after {$n} packets");
        }
    }

    public function test_gcm_iv_wraps_within_invocation_field(): void
    {
        $fixed = random_bytes(4);
        $gcm = new Gcm(random_bytes(32), $fixed . str_repeat("\xff", 8)); // invocation = 2^64 - 1
        $gcm->seal(0, pack('N', 0) . str_repeat("\x00", 16));
        self::assertSame(bin2hex($fixed . str_repeat("\x00", 8)), bin2hex($gcm->iv()), 'fixed field untouched, invocation wrapped');
    }

    public function test_chacha_nonce_is_the_sequence_number(): void
    {
        $key = random_bytes(64);
        $packet = pack('N', 8) . chr(6) . "\x14" . str_repeat("\x00", 6);
        $c = new ChaChaPoly($key);
        self::assertNotSame(bin2hex($c->seal(0, $packet)), bin2hex($c->seal(1, $packet)), 'seq drives the nonce');
        $wire = $c->seal(0, $packet);
        $this->expectException(\RuntimeException::class);
        (new ChaChaPoly($key))->open(1, $wire); // wrong seq → tag mismatch
    }

    /**
     * ETM verify-before-decrypt, observed at the CtrHmac level (Transport's pktLen cache is
     * poisoned after a throw). Tampering the clear length throws BEFORE the Ctr keystream advances,
     * so the same instance still opens the untampered wire to the exact plaintext.
     */
    public function test_etm_verifies_before_decrypt(): void
    {
        $key = random_bytes(16);
        $iv = random_bytes(16);
        $macKey = random_bytes(32);
        $seal = new CtrHmac(new Ctr($key, $iv), 'sha256', $macKey, true);
        $packet = pack('N', 16) . chr(11) . "\x14\x14\x14\x14" . str_repeat("\x00", 11);
        $wire = $seal->seal(0, $packet);

        $open = new CtrHmac(new Ctr($key, $iv), 'sha256', $macKey, true);
        $tampered = $wire;
        $tampered[0] = $tampered[0] ^ "\x01"; // corrupt the clear length
        try {
            $open->open(0, $tampered);
            self::fail('tampered length must throw');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString('MAC', $e->getMessage());
        }
        // The keystream did not advance on the failed open, so the untampered wire still decrypts.
        self::assertSame($packet, $open->open(0, $wire));
    }

    // --- §4.5 HASSH pin: this ticket moved no served bytes ---

    public function test_served_kexinit_hassh_is_unchanged(): void
    {
        $server = new SshConnection(
            $this->hostKey(),
            new ProtocolSession(1),
            static function (): void {
            },
            'SSH-2.0-OpenSSH_8.9p1',
            0
        );
        $server->onConnect();
        $buffer = $server->takeOut();
        $pos = strpos($buffer, "\r\n");
        self::assertNotFalse($pos);
        $buffer = substr($buffer, $pos + 2);

        $kexInit = (new Transport())->next($buffer);
        self::assertNotNull($kexInit);

        $r = new Reader($kexInit);
        self::assertSame(20, $r->byte(), 'SSH_MSG_KEXINIT');
        $r->uint32();
        $r->uint32();
        $r->uint32();
        $r->uint32(); // 16-byte cookie
        $kex = $r->nameList();
        $r->nameList();          // host key
        $r->nameList();          // enc c2s
        $encS2C = $r->nameList();
        $r->nameList();          // mac c2s
        $macS2C = $r->nameList();
        $r->nameList();          // comp c2s
        $compS2C = $r->nameList();

        $hassh = md5(implode(',', $kex) . ';' . implode(',', $encS2C) . ';' . implode(',', $macS2C) . ';' . implode(',', $compS2C));
        self::assertSame('04e7711cffa95c90b7c5ec4a6b7bdcd1', $hassh, 'HASSHServer unchanged by FP-0288');
    }

    // --- helpers ---

    private function chacha20(string $key, int $ctr, string $nonce8, string $data): string
    {
        return openssl_encrypt($data, 'chacha20', $key, OPENSSL_RAW_DATA, pack('P', $ctr) . $nonce8);
    }

    /** @return array{0:Transport,1:Transport} */
    private function transportPair(string $cipher, string $mac): array
    {
        $ivLen = CipherSuite::ivLen($cipher);
        $key = random_bytes(CipherSuite::keyLen($cipher));
        $iv = $ivLen > 0 ? random_bytes($ivLen) : '';
        $macKey = random_bytes(CipherSuite::macKeyLen($mac));
        $send = new Transport();
        $recv = new Transport();
        $send->enableSend(CipherSuite::build($cipher, $mac, $key, $iv, $macKey));
        $recv->enableRecv(CipherSuite::build($cipher, $mac, $key, $iv, $macKey));

        return [$send, $recv];
    }

    private function hostKey(): HostKey
    {
        $path = tempnam(sys_get_temp_dir(), 'fpc');
        if ($path !== false) {
            @unlink($path);
        }

        return HostKey::load($path ?: sys_get_temp_dir() . '/fpc');
    }
}
