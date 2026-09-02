<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\Ssh\Buf;
use Funnypot\Protocol\Ssh\HostKey\Ecdsa;
use Funnypot\Protocol\Ssh\HostKey\Ed25519;
use Funnypot\Protocol\Ssh\HostKey\HostKeyAlgorithm;
use Funnypot\Protocol\Ssh\HostKey\Rsa;
use Funnypot\Protocol\Ssh\Kex\Dh;
use Funnypot\Protocol\Ssh\Kex\DhGex;
use Funnypot\Protocol\Ssh\Kex\DhGroups;
use Funnypot\Protocol\Ssh\Kex\Ecdh;
use Funnypot\Protocol\Ssh\Kex\KexSuite;
use Funnypot\Protocol\Ssh\KeyDerivation;
use Funnypot\Protocol\Ssh\Reader;
use Funnypot\Protocol\Ssh\SshConnection;
use Funnypot\Protocol\Ssh\Transport;
use PHPUnit\Framework\TestCase;

/**
 * FP-0289 §4.1–4.6 — every kex algorithm KexSuite/FP-0291 will advertise completes a handshake
 * against an independent OpenSSL/sodium peer (shared secret agrees both directions; the exchange
 * hash H is recomputed from a literal RFC layout on the test side, never by calling the
 * implementation's own hash assembly; the host-key signature verifies over that H). The msg-30
 * collision — the top correctness trap — is pinned by construction: the same bytes yield three
 * different outcomes purely from the negotiated object. And FP-0289 moves NO served bytes: the kex
 * and host-key name-lists stay literally what they were.
 *
 * Independent peers use OpenSSL/sodium directly (not the implementation's import/derive code), so a
 * symmetric mistake in both the code and the test's layout is the only residual, closed by FP-0291's
 * real-client interop. Every assertion fails at baseline (the classes did not exist).
 */
final class SshKexTest extends TestCase
{
    private const V_C = 'SSH-2.0-TestClient_1.0';
    private const V_S = 'SSH-2.0-OpenSSH_8.9p1';
    private const I_C = 'client-kexinit-bytes';
    private const I_S = 'server-kexinit-bytes';

    // ---- §4.1 ECDH curve25519 + nistp256/384/521 ----

    /** @dataProvider curve25519Rows */
    public function test_curve25519_derives_shared_secret_both_directions(string $name, string $hostKind): void
    {
        [$hostKey, $verify] = $this->hostKey($hostKind);
        $kex = new Ecdh($name, 'sha256', self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);

        $priv = random_bytes(32);
        $qC = sodium_crypto_scalarmult_base($priv);
        [$kS, $qS, $sig] = $this->parseEcdhReply($kex->handle(30, (new Buf())->byte(30)->string($qC)->get()));

        $kPrime = sodium_crypto_scalarmult($priv, $qS);
        $kMpint = Buf::mpintOf($kPrime);
        $hPrime = hash('sha256', $this->prefix($kS) . Buf::stringOf($qC) . Buf::stringOf($qS) . $kMpint, true);

        $this->assertKexResult($kex, 'sha256', $kMpint, $hPrime, $kS, $hostKey);
        self::assertTrue($verify($hPrime, $sig), 'host-key signature verifies over the test-computed H');
    }

    /** @return array<string,array{0:string,1:string}> */
    public function curve25519Rows(): array
    {
        return [
            'curve25519-sha256 + ed25519' => ['curve25519-sha256', 'ssh-ed25519'],
            'curve25519-sha256@libssh.org + rsa-sha2-512' => ['curve25519-sha256@libssh.org', 'rsa-sha2-512'],
        ];
    }

    /** @dataProvider nistRows */
    public function test_ecdh_nist_derives_shared_secret_both_directions(string $name, int $flen, string $curve, string $hash, string $hostKind): void
    {
        [$hostKey, $verify] = $this->hostKey($hostKind);
        $kex = new Ecdh($name, $hash, self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);

        $client = openssl_pkey_new(['curve_name' => $curve, 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        $cd = openssl_pkey_get_details($client);
        $qC = "\x04" . str_pad($cd['ec']['x'], $flen, "\x00", STR_PAD_LEFT) . str_pad($cd['ec']['y'], $flen, "\x00", STR_PAD_LEFT);

        [$kS, $qS, $sig] = $this->parseEcdhReply($kex->handle(30, (new Buf())->byte(30)->string($qC)->get()));
        self::assertSame(2 * $flen + 1, strlen($qS), 'server point is 04 ‖ x ‖ y at the field length');
        self::assertSame("\x04", $qS[0]);

        $peer = openssl_pkey_get_public($this->spkiPem($qS, $curve));
        self::assertNotFalse($peer, 'server point imports (on-curve)');
        $kPrime = openssl_pkey_derive($peer, $client);
        $kMpint = Buf::mpintOf($kPrime);
        $hPrime = hash($hash, $this->prefix($kS) . Buf::stringOf($qC) . Buf::stringOf($qS) . $kMpint, true);

        $this->assertKexResult($kex, $hash, $kMpint, $hPrime, $kS, $hostKey);
        self::assertTrue($verify($hPrime, $sig));
    }

    /** @return array<string,array{0:string,1:int,2:string,3:string,4:string}> */
    public function nistRows(): array
    {
        return [
            'nistp256 + rsa-sha2-256' => ['ecdh-sha2-nistp256', 32, 'prime256v1', 'sha256', 'rsa-sha2-256'],
            'nistp384 + ecdsa' => ['ecdh-sha2-nistp384', 48, 'secp384r1', 'sha384', 'ecdsa-sha2-nistp256'],
            'nistp521 + ed25519' => ['ecdh-sha2-nistp521', 66, 'secp521r1', 'sha512', 'ssh-ed25519'],
        ];
    }

    public function test_nistp521_server_point_is_always_padded_to_133_bytes(): void
    {
        // ~73% of P-521 keygens have a short coordinate; 20 handshakes unpadded would pass with
        // probability ~0.27^20, so a missing left-pad fails this with near-certainty.
        [$hostKey] = $this->hostKey('ssh-ed25519');
        for ($i = 0; $i < 20; $i++) {
            $kex = new Ecdh('ecdh-sha2-nistp521', 'sha512', self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);
            $client = openssl_pkey_new(['curve_name' => 'secp521r1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
            $cd = openssl_pkey_get_details($client);
            $qC = "\x04" . str_pad($cd['ec']['x'], 66, "\x00", STR_PAD_LEFT) . str_pad($cd['ec']['y'], 66, "\x00", STR_PAD_LEFT);
            [, $qS] = $this->parseEcdhReply($kex->handle(30, (new Buf())->byte(30)->string($qC)->get()));
            self::assertSame(133, strlen($qS), "handshake #{$i}");
            self::assertSame("\x04", $qS[0]);
        }
    }

    // ---- §4.1 fixed-group DH ----

    /** @dataProvider dhRows */
    public function test_dh_fixed_group_derives_shared_secret_both_directions(string $name, int $bits, string $hash, string $hostKind): void
    {
        [$hostKey, $verify] = $this->hostKey($hostKind);
        $kex = new Dh($name, $hash, self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);
        $p = DhGroups::modulus($bits);

        $client = openssl_pkey_new(['dh' => ['p' => $p, 'g' => "\x02", 'priv_key' => random_bytes(64)]]);
        $e = openssl_pkey_get_details($client)['dh']['pub_key'];

        $reply = $this->single($kex->handle(30, (new Buf())->byte(30)->mpint($e)->get()));
        $r = new Reader($reply);
        self::assertSame(31, $r->byte(), 'KEXDH_REPLY');
        $kS = $r->string();
        $f = $r->mpint();
        $sig = $r->string();

        $peer = openssl_pkey_new(['dh' => ['p' => $p, 'g' => "\x02", 'pub_key' => $f]]);
        $kPrime = openssl_pkey_derive($peer, $client);
        $kMpint = Buf::mpintOf($kPrime);
        $hPrime = hash($hash, $this->prefix($kS) . Buf::mpintOf($e) . Buf::mpintOf($f) . $kMpint, true);

        $this->assertKexResult($kex, $hash, $kMpint, $hPrime, $kS, $hostKey);
        self::assertTrue($verify($hPrime, $sig));

        // The derived key schedule uses the kex hash (a sha256 hardcode would break group16/18).
        self::assertSame(
            KeyDerivation::deriveAll($hash, $kMpint, $hPrime, $hPrime, 16, 32, 32),
            $kex->result()->keys(16, 32, 32)
        );
    }

    /** @return array<string,array{0:string,1:int,2:string,3:string}> */
    public function dhRows(): array
    {
        return [
            'group14-sha256 + ecdsa' => ['diffie-hellman-group14-sha256', 2048, 'sha256', 'ecdsa-sha2-nistp256'],
            'group16-sha512 + ed25519' => ['diffie-hellman-group16-sha512', 4096, 'sha512', 'ssh-ed25519'],
            'group18-sha512 + rsa-sha2-512' => ['diffie-hellman-group18-sha512', 8192, 'sha512', 'rsa-sha2-512'],
        ];
    }

    // ---- §4.1 group-exchange (two round trips) ----

    public function test_gex_derives_shared_secret_both_directions(): void
    {
        [$hostKey, $verify] = $this->hostKey('ssh-ed25519');
        $kex = new DhGex('diffie-hellman-group-exchange-sha256', 'sha256', self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);

        // REQUEST (min 2048, n 3072, max 8192) → GROUP.
        $group = $this->single($kex->handle(34, (new Buf())->byte(34)->uint32(2048)->uint32(3072)->uint32(8192)->get()));
        $gr = new Reader($group);
        self::assertSame(31, $gr->byte(), 'KEX_DH_GEX_GROUP');
        $p = $gr->mpint();
        $g = $gr->mpint();
        self::assertSame(
            hash('sha256', DhGroups::modulus(3072), true),
            hash('sha256', $p, true),
            'a request for n=3072 selects the embedded modp_3072 group'
        );
        self::assertSame("\x02", $g);
        self::assertNull($kex->result(), 'GROUP sent, still waiting for INIT');

        // INIT on the chosen p → REPLY.
        $client = openssl_pkey_new(['dh' => ['p' => $p, 'g' => "\x02", 'priv_key' => random_bytes(64)]]);
        $e = openssl_pkey_get_details($client)['dh']['pub_key'];
        $reply = $this->single($kex->handle(32, (new Buf())->byte(32)->mpint($e)->get()));
        $rr = new Reader($reply);
        self::assertSame(33, $rr->byte(), 'KEX_DH_GEX_REPLY');
        $kS = $rr->string();
        $f = $rr->mpint();
        $sig = $rr->string();

        $peer = openssl_pkey_new(['dh' => ['p' => $p, 'g' => "\x02", 'pub_key' => $f]]);
        $kPrime = openssl_pkey_derive($peer, $client);
        $kMpint = Buf::mpintOf($kPrime);
        // RFC 4419: the RAW client min/n/max are hashed, not the clamped/chosen values.
        $hPrime = hash(
            'sha256',
            $this->prefix($kS)
            . (new Buf())->uint32(2048)->uint32(3072)->uint32(8192)->get()
            . Buf::mpintOf($p) . Buf::mpintOf($g) . Buf::mpintOf($e) . Buf::mpintOf($f) . $kMpint,
            true
        );

        $this->assertKexResult($kex, 'sha256', $kMpint, $hPrime, $kS, $hostKey);
        self::assertTrue($verify($hPrime, $sig));
    }

    // ---- §4.2 input validation ----

    /** @dataProvider ecdhBadPointRows */
    public function test_ecdh_rejects_invalid_points(string $name, int $flen, string $qC): void
    {
        [$hostKey] = $this->hostKey('ssh-ed25519');
        $kex = new Ecdh($name, 'sha256', self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);
        $this->expectException(\RuntimeException::class);
        $kex->handle(30, (new Buf())->byte(30)->string($qC)->get());
    }

    /** @return array<string,array{0:string,1:int,2:string}> */
    public function ecdhBadPointRows(): array
    {
        $off256 = "\x04" . str_repeat("\x01", 32) . str_repeat("\x02", 32); // on-format, off-curve
        return [
            'nistp256 off-curve' => ['ecdh-sha2-nistp256', 32, $off256],
            'nistp256 compressed 02' => ['ecdh-sha2-nistp256', 32, "\x02" . str_repeat("\x01", 32)],
            'nistp256 compressed 03' => ['ecdh-sha2-nistp256', 32, "\x03" . str_repeat("\x01", 32)],
            'nistp256 wrong length' => ['ecdh-sha2-nistp256', 32, "\x04" . str_repeat("\x01", 40)],
            'nistp256 empty' => ['ecdh-sha2-nistp256', 32, ''],
            'nistp384 off-curve' => ['ecdh-sha2-nistp384', 48, "\x04" . str_repeat("\x01", 48) . str_repeat("\x02", 48)],
            'nistp521 off-curve' => ['ecdh-sha2-nistp521', 66, "\x04" . str_repeat("\x01", 66) . str_repeat("\x02", 66)],
            'curve25519 wrong length' => ['curve25519-sha256', 32, str_repeat("\x01", 31)],
        ];
    }

    /** @dataProvider dhBadPeerRows */
    public function test_dh_rejects_invalid_peer_values(string $eMpintHex, bool $throws): void
    {
        [$hostKey] = $this->hostKey('ssh-ed25519');
        $kex = new Dh('diffie-hellman-group14-sha256', 'sha256', self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);
        $body = "\x1e" . hex2bin($eMpintHex); // 0x1e = 30, followed by an mpint-encoded e
        if ($throws) {
            $this->expectException(\RuntimeException::class);
            $kex->handle(30, $body);

            return;
        }
        // 0x0F has exactly 4 bits set — the boundary sshd accepts.
        self::assertNotNull($kex->handle(30, $body));
    }

    /** @return array<string,array{0:string,1:bool}> */
    public function dhBadPeerRows(): array
    {
        $p = DhGroups::modulus(2048);
        $mpint = static fn (string $mag): string => bin2hex(Buf::mpintOf($mag));
        return [
            'e=0' => [$mpint("\x00"), true],
            'e=1' => [$mpint("\x01"), true],
            'e=2 (one bit set)' => [$mpint("\x02"), true],
            'e=p-1' => [$mpint(DhGroups::minusOne($p)), true],
            'e=p' => [$mpint($p), true],
            'e=0x07 (three bits set)' => [$mpint("\x07"), true],
            'e=0x0F (four bits set, boundary)' => [$mpint("\x0f"), false],
        ];
    }

    /**
     * FP-0291 M2: an in-range non-subgroup peer value e (passes sshd's dh_pub_is_valid range + popcount,
     * but OpenSSL 3's named-group subgroup check rejects it) must still DERIVE via the g=5 generator
     * retry in {@see \Funnypot\Protocol\Ssh\Kex\DhComputation::dhDerive()} — matching real sshd, which
     * answers with a signed REPLY. No live client is needed: we reproduce the rejection with a direct
     * OpenSSL probe, confirm the alternate generator derives the byte-identical K (generator-independent
     * e^x mod p), then assert the production Dh::handle path completes on the very same e.
     */
    public function test_dh_derive_accepts_non_subgroup_e_via_generator_retry(): void
    {
        $p = DhGroups::modulus(2048);
        $priv = random_bytes(64);
        $ours = openssl_pkey_new(['dh' => ['p' => $p, 'g' => "\x02", 'priv_key' => $priv]]);
        self::assertNotFalse($ours);
        $drain = static function (): void {
            while (openssl_error_string() !== false) {
                // discard
            }
        };

        // Find an in-range value (>= 4 bits set — a 256-byte 0x7f-led magnitude always qualifies and is
        // < the 2048-bit modulus) that the g=2 named path rejects, i.e. a non-subgroup e. ~50% of values
        // qualify, so 400 tries finds one with overwhelming probability.
        $e = null;
        for ($i = 0; $i < 400; $i++) {
            $cand = random_bytes(256);
            $cand[0] = "\x7f";
            if (DhGroups::cmp($cand, "\x01") <= 0 || DhGroups::cmp($cand, DhGroups::minusOne($p)) >= 0) {
                continue;
            }
            $peer = openssl_pkey_new(['dh' => ['p' => $p, 'g' => "\x02", 'pub_key' => $cand]]);
            $drain();
            if ($peer === false) {
                continue;
            }
            $k = openssl_pkey_derive($peer, $ours);
            $drain();
            if ($k === false) {
                $e = $cand; // g=2 rejected it — a non-subgroup e that sshd would accept
                break;
            }
        }
        self::assertNotNull($e, 'expected an in-range non-subgroup e within 400 tries');
        self::assertGreaterThanOrEqual(4, DhGroups::bitsSet($e), 'e passes the popcount gate');
        self::assertSame(-1, DhGroups::cmp($e, DhGroups::minusOne($p)), 'e < p-1');

        // The alternate-generator derivation succeeds and is generator-independent: g=5 == g=7.
        $k5 = openssl_pkey_derive(
            openssl_pkey_new(['dh' => ['p' => $p, 'g' => "\x05", 'pub_key' => $e]]),
            openssl_pkey_new(['dh' => ['p' => $p, 'g' => "\x05", 'priv_key' => $priv]])
        );
        $drain();
        $k7 = openssl_pkey_derive(
            openssl_pkey_new(['dh' => ['p' => $p, 'g' => "\x07", 'pub_key' => $e]]),
            openssl_pkey_new(['dh' => ['p' => $p, 'g' => "\x07", 'priv_key' => $priv]])
        );
        $drain();
        self::assertNotFalse($k5, 'the g=5 retry derives a non-subgroup e');
        self::assertSame(bin2hex((string) $k5), bin2hex((string) $k7), 'K = e^x mod p is generator-independent');

        // The production path: Dh::handle must complete (a KEXDH_REPLY, not null) on the same non-subgroup
        // e — the g=5 retry inside dhDerive is what makes it derive, exactly as sshd does.
        [$hostKey] = $this->hostKey('ssh-ed25519');
        $kex = new Dh('diffie-hellman-group14-sha256', 'sha256', self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);
        $reply = $kex->handle(30, "\x1e" . Buf::mpintOf($e));
        self::assertNotNull($reply, 'a non-subgroup e derives via the g=5 retry (matches sshd dh_pub_is_valid)');
        self::assertSame(31, ord($reply[0][0]), 'KEXDH_REPLY');
    }

    public function test_dh_rejects_negative_mpint(): void
    {
        [$hostKey] = $this->hostKey('ssh-ed25519');
        $kex = new Dh('diffie-hellman-group14-sha256', 'sha256', self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);
        // A top-bit-set first byte with NO 0x00 sign byte is a negative mpint — Reader::mpint throws.
        $negative = (new Buf())->string("\x80\x01\x02\x03")->get();
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('negative mpint');
        $kex->handle(30, "\x1e" . $negative);
    }

    /** @dataProvider gexRangeRows */
    public function test_gex_range_check_on_raw_values(int $min, int $n, int $max, bool $throws): void
    {
        [$hostKey] = $this->hostKey('ssh-ed25519');
        $kex = new DhGex('diffie-hellman-group-exchange-sha256', 'sha256', self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);
        $body = (new Buf())->byte(34)->uint32($min)->uint32($n)->uint32($max)->get();
        if ($throws) {
            $this->expectException(\RuntimeException::class);
            $kex->handle(34, $body);

            return;
        }
        self::assertNotNull($kex->handle(34, $body), 'min below 2048 is allowed (clamped for the group choice)');
    }

    /** @return array<string,array{0:int,1:int,2:int,3:bool}> */
    public function gexRangeRows(): array
    {
        return [
            'max<min' => [8192, 2048, 2048, true],
            'max<min (2)' => [2048, 2048, 1024, true],
            'max<2048' => [1024, 1024, 1024, true],
            'n>max' => [2048, 9000, 8192, true],
            'min below 2048 passes' => [1024, 2048, 8192, false],
        ];
    }

    /** @dataProvider gexChooseRows */
    public function test_gex_group_choice(int $min, int $n, int $max, int $expected): void
    {
        self::assertSame($expected, DhGroups::choose($min, $n, $max));
    }

    /** @return array<string,array{0:int,1:int,2:int,3:int}> */
    public function gexChooseRows(): array
    {
        return [
            'exact 2048' => [2048, 2048, 8192, 2048],
            'exact 3072' => [2048, 3072, 8192, 3072],
            'round up 4097 to 6144' => [2048, 4097, 8192, 6144],
            'top 8192' => [2048, 8192, 8192, 8192],
            'pinned 2048' => [2048, 2048, 2048, 2048],
            'n below min' => [3072, 2048, 4096, 3072],
            'largest below n' => [2048, 7000, 6144, 6144],
        ];
    }

    public function test_gex_choose_throws_when_no_group_fits(): void
    {
        $this->expectException(\RuntimeException::class);
        DhGroups::choose(2560, 2560, 2800); // no embedded size in [2560, 2800]
    }

    // ---- §4.4 the msg-30 collision (same bytes, three outcomes) ----

    public function test_msg30_collision_same_bytes_three_outcomes(): void
    {
        [$hostKey] = $this->hostKey('ssh-ed25519');
        // MUST-FIX #1: a FIXED top-bit-clear literal, so the same bytes read three ways. It is a
        // valid 32-byte curve25519 Q_C AND a valid, positive group-14 e — >1, <p-1, >=4 bits set,
        // AND a quadratic residue mod p14 (the seed '…-1' is chosen so openssl_pkey_derive accepts
        // it; OpenSSL 3 rejects non-residues, so a bare random_bytes(32) would derive only ~50% of
        // runs — flaky in a different way than the negative-mpint hazard MUST-FIX #1 first named).
        $q = hash('sha256', 'fp-0289-msg30-1', true);
        $q[0] = chr(ord($q[0]) & 0x7f);
        $body = "\x1e" . Buf::stringOf($q); // 0x1e = 30, body = string Q_C

        // Ecdh(curve25519): 30 → KEX_ECDH_REPLY (31) with a 32-byte Q_S.
        $ecdh = new Ecdh('curve25519-sha256', 'sha256', self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);
        $reply = $this->single($ecdh->handle(30, $body));
        $er = new Reader($reply);
        self::assertSame(31, $er->byte());
        $er->string();                         // K_S
        self::assertSame(32, strlen($er->string())); // Q_S

        // DhGex: 30 is GEX_REQUEST_OLD, unsupported in 8.9 → null (no reply, no exception).
        $gex = new DhGex('diffie-hellman-group-exchange-sha256', 'sha256', self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);
        self::assertNull($gex->handle(30, $body));

        // Dh(group14): 30 is KEXDH_INIT; the same bytes are read as `mpint e` → KEXDH_REPLY (31)
        // whose second field is a 256-byte mpint f.
        $dh = new Dh('diffie-hellman-group14-sha256', 'sha256', self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);
        $dr = new Reader($this->single($dh->handle(30, $body)));
        self::assertSame(31, $dr->byte());
        $dr->string();                          // K_S
        self::assertSame(256, strlen($dr->mpint())); // f
    }

    public function test_msg30_request_old_body_null_under_gex_but_throws_under_ecdh(): void
    {
        [$hostKey] = $this->hostKey('ssh-ed25519');
        $old = "\x1e" . pack('N', 2048); // a GEX_REQUEST_OLD body (uint32 n), also parseable as nothing valid

        $gex = new DhGex('diffie-hellman-group-exchange-sha256', 'sha256', self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);
        self::assertNull($gex->handle(30, $old), '8.9 does not handle REQUEST_OLD — UNIMPLEMENTED, deliberate');

        $ecdh = new Ecdh('curve25519-sha256', 'sha256', self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);
        $this->expectException(\RuntimeException::class);
        $ecdh->handle(30, $old); // parsed as `string Q_C` of length 2048 → short read
    }

    public function test_msg_routing_and_state_returns_null_for_wrong_messages(): void
    {
        [$hostKey] = $this->hostKey('ssh-ed25519');
        $req = "\x22" . pack('N3', 2048, 3072, 8192); // 0x22 = 34

        $gex = new DhGex('diffie-hellman-group-exchange-sha256', 'sha256', self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);
        self::assertNull($gex->handle(32, "\x20"), '32 before any 34 → null');
        self::assertNotNull($gex->handle(34, $req), '34 → GROUP');

        $ecdh = new Ecdh('curve25519-sha256', 'sha256', self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);
        self::assertNull($ecdh->handle(34, $req), '34 under ECDH → null');

        $dh = new Dh('diffie-hellman-group14-sha256', 'sha256', self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);
        self::assertNull($dh->handle(34, $req), '34 under DH → null');

        // After completion every algorithm returns null for 30/32/34.
        $priv = random_bytes(32);
        $qC = sodium_crypto_scalarmult_base($priv);
        $done = new Ecdh('curve25519-sha256', 'sha256', self::V_C, self::V_S, self::I_C, self::I_S, $hostKey);
        self::assertNotNull($done->handle(30, (new Buf())->byte(30)->string($qC)->get()));
        self::assertNotNull($done->result());
        self::assertNull($done->handle(30, (new Buf())->byte(30)->string($qC)->get()), 'no second kex after completion');
    }

    public function test_wiring_pre_kexinit_message_is_unimplemented_not_signed(): void
    {
        $server = new SshConnection(SshHostKeyFixture::set(), new ProtocolSession(7), static function (): void {
        }, self::V_S, 0);
        $server->onConnect();
        $server->takeOut();                 // drain the banner
        $server->feed(self::V_C . "\r\n");
        $server->takeOut();                 // drain the server KEXINIT (now queued after the client ident line, FP-0290)

        $t = new Transport();
        // An IGNORE (inbound seq 0) then a pre-KEXINIT msg 30 (inbound seq 1): UNIMPLEMENTED must
        // carry the offending packet's real sequence number (1), not a fixed 0. The IGNORE prefix is
        // what makes this non-vacuous — with msg 30 first the value would be 0 either way (§4.8).
        $server->feed($t->frame((new Buf())->byte(2)->string('')->get()));   // MSG_IGNORE
        $server->feed($t->frame((new Buf())->byte(30)->string(random_bytes(32))->get()));

        $out = $server->takeOut();
        $packet = $t->next($out);
        self::assertNotNull($packet);
        self::assertSame(3, ord($packet[0]), 'a kex message before KEXINIT draws UNIMPLEMENTED (not a signed reply)');
        $rseq = new Reader($packet);
        $rseq->byte();
        self::assertSame(1, $rseq->uint32(), 'UNIMPLEMENTED carries the offending packet sequence number');
        self::assertNull($t->next($out), 'exactly one packet');
        self::assertFalse($server->isClosed(), 'the connection stays up');
    }

    public function test_wiring_wrong_kex_messages_are_unimplemented_then_a_proper_init_completes(): void
    {
        $server = new SshConnection(SshHostKeyFixture::set(), new ProtocolSession(7), static function (): void {
        }, self::V_S, 0);
        $server->onConnect();
        $server->takeOut();                 // drain the banner
        $server->feed(self::V_C . "\r\n");
        $server->takeOut();                 // drain the server KEXINIT (now queued after the client ident line, FP-0290)

        $t = new Transport();
        $server->feed($t->frame($this->clientKexInit()));
        $server->takeOut(); // ignore anything the negotiation queued (nothing on the live path)

        // 34 and 32 are not the curve25519 path's message → UNIMPLEMENTED, connection stays up.
        foreach ([34, 32] as $msg) {
            $server->feed($t->frame((new Buf())->byte($msg)->uint32(0)->get()));
            $out = $server->takeOut();
            $packet = $t->next($out);
            self::assertNotNull($packet);
            self::assertSame(3, ord($packet[0]), "msg {$msg} under curve25519 → UNIMPLEMENTED");
            self::assertFalse($server->isClosed());
        }

        // A proper ECDH_INIT then completes the kex (KEX_ECDH_REPLY + NEWKEYS).
        $priv = random_bytes(32);
        $qC = sodium_crypto_scalarmult_base($priv);
        $server->feed($t->frame((new Buf())->byte(30)->string($qC)->get()));
        $out = $server->takeOut();
        $reply = $t->next($out);
        $newkeys = $t->next($out);
        self::assertNotNull($reply);
        self::assertSame(31, ord($reply[0]), 'KEX_ECDH_REPLY');
        self::assertNotNull($newkeys);
        self::assertSame(21, ord($newkeys[0]), 'NEWKEYS');
    }

    // ---- §4.3 embedded moduli are the RFC 3526 groups ----

    public function test_embedded_moduli_match_rfc3526(): void
    {
        $pins = [
            2048 => 'd66436f79bbd6b2e38c0ffbd079be904d2641415e2e67140e09448be9a60890e',
            3072 => '48cf8b092fbce4359d9871abf74f98e25b6163379eaa15cd9087e800c6d1c55c',
            4096 => '4ee95187682bcb230ad26a95205f6920e84708f6251b3894329b09ec23919e33',
            6144 => 'd1bfe6d0925ce7e4da262b62861514a7755e35831e429f343e7b864848657efd',
            8192 => '39ab4feab950a3128fb71accb9fc3965d857012e081998a85996e3ea8b3c3bcf',
        ];
        self::assertSame([2048, 3072, 4096, 6144, 8192], DhGroups::bits());
        self::assertSame("\x02", DhGroups::G);
        foreach ($pins as $bits => $pin) {
            $p = DhGroups::modulus($bits);
            self::assertSame(hex2bin($pin), hash('sha256', $p, true), "modp_{$bits} pin");
            self::assertSame($bits / 8, strlen($p), "modp_{$bits} length");
            self::assertSame(str_repeat("\xff", 8), substr($p, 0, 8), 'top 64 bits all ones');
            self::assertSame(str_repeat("\xff", 8), substr($p, -8), 'bottom 64 bits all ones');
        }
    }

    // ---- §4.6 the served-bytes flip (FP-0291) ----

    public function test_served_lists_are_stage1(): void
    {
        $server = new SshConnection(SshHostKeyFixture::set(), new ProtocolSession(1), static function (): void {
        }, self::V_S, 0);
        $server->onConnect();
        $server->takeOut();                     // drain the banner
        $server->feed(self::V_C . "\r\n");       // KEXINIT is queued after the client ident line (FP-0290)
        $buffer = $server->takeOut();

        $kexInit = (new Transport())->next($buffer);
        self::assertNotNull($kexInit);
        $r = new Reader($kexInit);
        self::assertSame(20, $r->byte());
        $r->uint32();
        $r->uint32();
        $r->uint32();
        $r->uint32(); // 16-byte cookie
        // Full Stage-1 flip (FP-0291 commit 5): the 9 real 8.9p1 kex names in myproposal.h order
        // (== KexSuite::NAMES) with kex-strict-s appended last, and the 4 host-key names (== HostKeySet::ALGORITHMS).
        self::assertSame([
            'curve25519-sha256',
            'curve25519-sha256@libssh.org',
            'ecdh-sha2-nistp256',
            'ecdh-sha2-nistp384',
            'ecdh-sha2-nistp521',
            'diffie-hellman-group-exchange-sha256',
            'diffie-hellman-group16-sha512',
            'diffie-hellman-group18-sha512',
            'diffie-hellman-group14-sha256',
            'kex-strict-s-v00@openssh.com',
        ], $r->nameList(), 'Stage-1 kex list (8.9p1 minus sntrup761, kex-strict-s last)');
        self::assertSame(['rsa-sha2-512', 'rsa-sha2-256', 'ecdsa-sha2-nistp256', 'ssh-ed25519'], $r->nameList(), 'Stage-1 host-key list');
    }

    // ---- helpers ----

    /** @param string[]|null $replies */
    private function single(?array $replies): string
    {
        self::assertIsArray($replies);
        self::assertCount(1, $replies);

        return $replies[0];
    }

    /**
     * Parse a KEX_ECDH_REPLY.
     *
     * @param string[]|null $replies
     * @return array{0:string,1:string,2:string} [K_S, Q_S, sig]
     */
    private function parseEcdhReply(?array $replies): array
    {
        $r = new Reader($this->single($replies));
        self::assertSame(31, $r->byte(), 'KEX_ECDH_REPLY');

        return [$r->string(), $r->string(), $r->string()];
    }

    private function prefix(string $kS): string
    {
        return Buf::stringOf(self::V_C)
            . Buf::stringOf(self::V_S)
            . Buf::stringOf(self::I_C)
            . Buf::stringOf(self::I_S)
            . Buf::stringOf($kS);
    }

    private function assertKexResult(object $kex, string $hash, string $kMpint, string $hPrime, string $kS, HostKeyAlgorithm $hostKey): void
    {
        $result = $kex->result();
        self::assertNotNull($result);
        self::assertSame($hash, $result->hashAlgo);
        self::assertSame($kMpint, $result->kEncoded, 'K is encoded as the mpint the test computed');
        self::assertSame($hPrime, $result->exchangeHash, 'H matches the test-side literal RFC layout');
        self::assertSame($hostKey->publicBlob(), $kS, 'the reply carries K_S = the host public blob');
    }

    /**
     * A host key of the given kind plus a verifier closure (H, sigBlob) -> bool, using an
     * independent OpenSSL/sodium verify (never the implementation's own code).
     *
     * @return array{0:HostKeyAlgorithm,1:callable(string,string):bool}
     */
    private function hostKey(string $kind): array
    {
        switch ($kind) {
            case 'ssh-ed25519':
                $ed = Ed25519::generate();
                $pub = (new Reader($ed->publicBlob()));
                $pub->string();
                $pubKey = $pub->string();
                $verify = static function (string $h, string $sigBlob) use ($pubKey): bool {
                    $r = new Reader($sigBlob);
                    $r->string();

                    return sodium_crypto_sign_verify_detached($r->string(), $h, $pubKey);
                };

                return [$ed, $verify];
            case 'rsa-sha2-256':
            case 'rsa-sha2-512':
                $rsa = Rsa::generate()->withAlgorithm($kind);
                $pubPem = openssl_pkey_get_details(openssl_pkey_get_private($rsa->pem()))['key'];
                $algo = $kind === 'rsa-sha2-512' ? OPENSSL_ALGO_SHA512 : OPENSSL_ALGO_SHA256;
                $verify = static function (string $h, string $sigBlob) use ($pubPem, $algo, $kind): bool {
                    $r = new Reader($sigBlob);

                    return $r->string() === $kind && openssl_verify($h, $r->string(), $pubPem, $algo) === 1;
                };

                return [$rsa, $verify];
            case 'ecdsa-sha2-nistp256':
                $ecdsa = Ecdsa::generate();
                $pubPem = openssl_pkey_get_details(openssl_pkey_get_private($ecdsa->pem()))['key'];
                $verify = function (string $h, string $sigBlob) use ($pubPem): bool {
                    $r = new Reader($sigBlob);
                    if ($r->string() !== 'ecdsa-sha2-nistp256') {
                        return false;
                    }
                    $rs = new Reader($r->string());
                    $der = $this->reDer($rs->mpint(), $rs->mpint());

                    return openssl_verify($h, $der, $pubPem, OPENSSL_ALGO_SHA256) === 1;
                };

                return [$ecdsa, $verify];
            default:
                throw new \RuntimeException("unknown host kind {$kind}");
        }
    }

    /** The test's own DER-SPKI wrapper for an uncompressed EC point (independent of Ecdh's). */
    private function spkiPem(string $point, string $curve): string
    {
        $oids = [
            'prime256v1' => "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
            'secp384r1' => "\x06\x05\x2b\x81\x04\x00\x22",
            'secp521r1' => "\x06\x05\x2b\x81\x04\x00\x23",
        ];
        $ecPub = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $len = static function (int $n): string {
            if ($n < 0x80) {
                return chr($n);
            }
            $b = '';
            while ($n > 0) {
                $b = chr($n & 0xff) . $b;
                $n >>= 8;
            }

            return chr(0x80 | strlen($b)) . $b;
        };
        $seq = static fn (string $c): string => "\x30" . $len(strlen($c)) . $c;
        $bit = static fn (string $c): string => "\x03" . $len(strlen("\x00" . $c)) . "\x00" . $c;
        $spki = $seq($seq($ecPub . $oids[$curve]) . $bit($point));

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private function reDer(string $r, string $s): string
    {
        $int = static function (string $v): string {
            $v = ltrim($v, "\x00");
            if ($v === '') {
                $v = "\x00";
            }
            if (ord($v[0]) & 0x80) {
                $v = "\x00" . $v;
            }

            return "\x02" . chr(strlen($v)) . $v;
        };
        $body = $int($r) . $int($s);

        return "\x30" . chr(strlen($body)) . $body;
    }

    /** A minimal client KEXINIT advertising the server's live single choice. */
    private function clientKexInit(): string
    {
        return (new Buf())
            ->byte(20)
            ->raw(random_bytes(16))
            ->nameList(['curve25519-sha256'])
            ->nameList(['ssh-ed25519'])
            ->nameList(['aes256-ctr'])
            ->nameList(['aes256-ctr'])
            ->nameList(['hmac-sha2-256'])
            ->nameList(['hmac-sha2-256'])
            ->nameList(['none'])
            ->nameList(['none'])
            ->nameList([])
            ->nameList([])
            ->bool(false)
            ->uint32(0)
            ->get();
    }
}
