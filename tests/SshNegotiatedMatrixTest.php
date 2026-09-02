<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\Ssh\Buf;
use Funnypot\Protocol\Ssh\Cipher\CipherSuite;
use Funnypot\Protocol\Ssh\KeyDerivation;
use Funnypot\Protocol\Ssh\Kex\DhGroups;
use Funnypot\Protocol\Ssh\Reader;
use Funnypot\Protocol\Ssh\SshConnection;
use Funnypot\Protocol\Ssh\Transport;
use PHPUnit\Framework\TestCase;

/**
 * FP-0291 §4.4 — the in-memory negotiated end-to-end matrix (FP-0289 OQ2 / FP-0290 OQ1, the hard
 * gate). One row per name the Stage-1 profile advertises (every kex, host key, cipher, MAC, and both
 * compression modes) drives a real {@see SshConnection} through the full flow — version exchange →
 * KEXINIT → the negotiated kex → NEWKEYS → SERVICE_REQUEST → password auth → CHANNEL_OPEN → `exec id`
 * — and asserts the fake shell answers `uid=0(root)` and the login and command are logged. This is the
 * advertise ⇒ implement proof on the wire (no live ssh): a served name that could not complete a
 * handshake would lock out every client that prefers it, which is worse than the fingerprint tell this
 * epic removes. The client peers are independent OpenSSL/sodium (as {@see SshKexTest}); asymmetric
 * per-direction ciphers/MACs are exercised too (RFC 4253 §7.2 A–F sizing).
 */
final class SshNegotiatedMatrixTest extends TestCase
{
    private const V_C = 'SSH-2.0-TestClient_1.0';
    private const V_S = 'SSH-2.0-OpenSSH_8.9p1';

    /**
     * @dataProvider matrixRows
     */
    public function test_negotiated_row_completes_auth_and_exec(
        string $kex,
        string $hostKey,
        string $encC2S,
        string $encS2C,
        string $macC2S,
        string $macS2C,
        string $comp
    ): void {
        $log = [];
        $server = new SshConnection(
            SshHostKeyFixture::set(),
            new ProtocolSession(7),
            static function (string $event, string $detail) use (&$log): void {
                $log[] = $event . ':' . $detail;
            },
            self::V_S,
            0
        );
        $server->onConnect();

        $buffer = $server->takeOut();
        $pos = strpos($buffer, "\r\n");
        self::assertNotFalse($pos);
        $vS = substr($buffer, 0, $pos);

        $transport = new Transport();

        // Client KEXINIT: one name per slot, per-direction as the row dictates. No kex-strict-c / no
        // ext-info-c — this matrix pins the negotiated crypto wiring, not the FP-0290 markers.
        $iC = (new Buf())
            ->byte(20)
            ->raw(random_bytes(16))
            ->nameList([$kex])
            ->nameList([$hostKey])
            ->nameList([$encC2S])
            ->nameList([$encS2C])
            ->nameList([$macC2S])
            ->nameList([$macS2C])
            ->nameList([$comp])
            ->nameList([$comp])
            ->nameList([])
            ->nameList([])
            ->bool(false)
            ->uint32(0)
            ->get();

        // Client identification line first; the server queues its KEXINIT in response (FP-0290 order).
        $server->feed(self::V_C . "\r\n");
        $buffer = $server->takeOut();
        $iS = $transport->next($buffer);
        self::assertNotNull($iS, 'server KEXINIT');
        self::assertSame(20, ord($iS[0]));
        self::assertSame('', $buffer, 'exactly the KEXINIT');

        // Client KEXINIT on the wire, then run the negotiated kex → shared secret K and exchange hash H.
        // $buffer carries whatever the server has flushed but not yet been read (the trailing NEWKEYS).
        $server->feed($transport->frame($iC));
        $buffer = '';
        [$hashAlgo, $kMpint, $h] = $this->runKex($kex, $transport, $server, $vS, $iC, $iS, $buffer);

        // RFC 4253 §7.2 letters A–F, sized per the negotiated names of EACH direction (mirrors
        // KexResult::keysFor on the server); the honeypot client installs the matching pair.
        $ivC2S = KeyDerivation::derive($hashAlgo, $kMpint, $h, $h, 'A', CipherSuite::ivLen($encC2S));
        $ivS2C = KeyDerivation::derive($hashAlgo, $kMpint, $h, $h, 'B', CipherSuite::ivLen($encS2C));
        $keyC2S = KeyDerivation::derive($hashAlgo, $kMpint, $h, $h, 'C', CipherSuite::keyLen($encC2S));
        $keyS2C = KeyDerivation::derive($hashAlgo, $kMpint, $h, $h, 'D', CipherSuite::keyLen($encS2C));
        $macKeyC2S = KeyDerivation::derive($hashAlgo, $kMpint, $h, $h, 'E', CipherSuite::macKeyLen($macC2S));
        $macKeyS2C = KeyDerivation::derive($hashAlgo, $kMpint, $h, $h, 'F', CipherSuite::macKeyLen($macS2C));

        // Consume the server NEWKEYS, send ours, and switch both directions on (no strict reset — the
        // client offered no kex-strict-c).
        $newkeys = $transport->next($buffer);
        self::assertNotNull($newkeys);
        self::assertSame(21, ord($newkeys[0]), 'NEWKEYS');
        $server->feed($transport->frame((new Buf())->byte(21)->get()));
        $transport->enableSend(CipherSuite::build($encC2S, $macC2S, $keyC2S, $ivC2S, $macKeyC2S));
        $transport->enableRecv(CipherSuite::build($encS2C, $macS2C, $keyS2C, $ivS2C, $macKeyS2C));
        self::assertSame('', $server->takeOut(), 'nothing queued after NEWKEYS (no ext-info-c)');

        // SERVICE_REQUEST → SERVICE_ACCEPT.
        $server->feed($transport->frame((new Buf())->byte(5)->string('ssh-userauth')->get()));
        $buffer .= $server->takeOut();
        $accept = $transport->next($buffer);
        self::assertNotNull($accept);
        self::assertSame(6, ord($accept[0]), 'SERVICE_ACCEPT decrypts under the negotiated cipher/MAC');

        // Password auth → USERAUTH_SUCCESS (the delayed-compression switch point).
        $server->feed($transport->frame(
            (new Buf())->byte(50)->string('root')->string('ssh-connection')->string('password')->bool(false)->string('hunter2')->get()
        ));
        $buffer .= $server->takeOut();
        $success = $transport->next($buffer);
        self::assertNotNull($success);
        self::assertSame(52, ord($success[0]), 'USERAUTH_SUCCESS');
        self::assertContains('login:root / hunter2', $log, 'the credential was captured');

        // sshd enables delayed zlib both directions right after the SUCCESS packet is queued; the SUCCESS
        // itself is uncompressed, so the client switches on now, matching the server.
        if ($comp === 'zlib@openssh.com') {
            $transport->enableSendCompression();
            $transport->enableRecvCompression();
        }

        // CHANNEL_OPEN → CONFIRMATION.
        $server->feed($transport->frame(
            (new Buf())->byte(90)->string('session')->uint32(0)->uint32(1 << 20)->uint32(32768)->get()
        ));
        $buffer .= $server->takeOut();
        $conf = $transport->next($buffer);
        self::assertNotNull($conf);
        self::assertSame(91, ord($conf[0]), 'CHANNEL_OPEN_CONFIRMATION');

        // exec id → CHANNEL_DATA carrying uid=0(root).
        $server->feed($transport->frame((new Buf())->byte(98)->uint32(0)->string('exec')->bool(true)->string('id')->get()));
        $buffer .= $server->takeOut();
        $data = '';
        while (($p = $transport->next($buffer)) !== null) {
            if (ord($p[0]) === 94) { // CHANNEL_DATA
                $r = new Reader($p);
                $r->byte();
                $r->uint32();
                $data .= $r->string();
            }
        }
        self::assertStringContainsString('uid=0(root)', $data, 'the fake shell answered `id` over the negotiated transport');
        self::assertContains('command:id', $log, 'the command was logged as intel');
        self::assertFalse($server->isClosed());
    }

    /**
     * Run the client side of the negotiated kex against the server, returning [hashAlgo, K as mpint, H].
     * Independent OpenSSL/sodium peers; the exchange-hash layout is written literally per RFC, never by
     * calling the server's own hash assembly.
     *
     * @return array{0:string,1:string,2:string}
     */
    private function runKex(string $kex, Transport $transport, SshConnection $server, string $vS, string $iC, string $iS, string &$buffer): array
    {
        $prefix = static fn (string $kS): string =>
            Buf::stringOf(self::V_C) . Buf::stringOf($vS) . Buf::stringOf($iC) . Buf::stringOf($iS) . Buf::stringOf($kS);

        if ($kex === 'curve25519-sha256' || $kex === 'curve25519-sha256@libssh.org') {
            $priv = random_bytes(32);
            $qC = sodium_crypto_scalarmult_base($priv);
            $server->feed($transport->frame((new Buf())->byte(30)->string($qC)->get()));
            [$kS, $qS] = $this->replyEcdh($transport, $server, $buffer);
            $k = sodium_crypto_scalarmult($priv, $qS);
            $kMpint = Buf::mpintOf($k);
            $h = hash('sha256', $prefix($kS) . Buf::stringOf($qC) . Buf::stringOf($qS) . $kMpint, true);

            return ['sha256', $kMpint, $h];
        }

        $nist = [
            'ecdh-sha2-nistp256' => ['prime256v1', 'sha256', 32],
            'ecdh-sha2-nistp384' => ['secp384r1', 'sha384', 48],
            'ecdh-sha2-nistp521' => ['secp521r1', 'sha512', 66],
        ];
        if (isset($nist[$kex])) {
            [$curve, $hashAlgo, $flen] = $nist[$kex];
            $client = openssl_pkey_new(['curve_name' => $curve, 'private_key_type' => OPENSSL_KEYTYPE_EC]);
            $cd = openssl_pkey_get_details($client);
            $qC = "\x04" . str_pad($cd['ec']['x'], $flen, "\x00", STR_PAD_LEFT) . str_pad($cd['ec']['y'], $flen, "\x00", STR_PAD_LEFT);
            $server->feed($transport->frame((new Buf())->byte(30)->string($qC)->get()));
            [$kS, $qS] = $this->replyEcdh($transport, $server, $buffer);
            $peer = openssl_pkey_get_public($this->spkiPem($qS, $curve));
            self::assertNotFalse($peer, 'server EC point imports (on-curve)');
            $kMpint = Buf::mpintOf((string) openssl_pkey_derive($peer, $client));
            $h = hash($hashAlgo, $prefix($kS) . Buf::stringOf($qC) . Buf::stringOf($qS) . $kMpint, true);

            return [$hashAlgo, $kMpint, $h];
        }

        $dh = [
            'diffie-hellman-group14-sha256' => [2048, 'sha256'],
            'diffie-hellman-group16-sha512' => [4096, 'sha512'],
            'diffie-hellman-group18-sha512' => [8192, 'sha512'],
        ];
        if (isset($dh[$kex])) {
            [$bits, $hashAlgo] = $dh[$kex];
            $p = DhGroups::modulus($bits);
            $client = openssl_pkey_new(['dh' => ['p' => $p, 'g' => "\x02", 'priv_key' => random_bytes(64)]]);
            $e = openssl_pkey_get_details($client)['dh']['pub_key'];
            $server->feed($transport->frame((new Buf())->byte(30)->mpint($e)->get()));
            [$kS, $f] = $this->replyDh($transport, $server, 31, $buffer);
            $peer = openssl_pkey_new(['dh' => ['p' => $p, 'g' => "\x02", 'pub_key' => $f]]);
            $kMpint = Buf::mpintOf((string) openssl_pkey_derive($peer, $client));
            $h = hash($hashAlgo, $prefix($kS) . Buf::mpintOf($e) . Buf::mpintOf($f) . $kMpint, true);

            return [$hashAlgo, $kMpint, $h];
        }

        if ($kex === 'diffie-hellman-group-exchange-sha256') {
            [$min, $n, $max] = [2048, 3072, 8192];
            $server->feed($transport->frame((new Buf())->byte(34)->uint32($min)->uint32($n)->uint32($max)->get()));
            $buffer .= $server->takeOut();
            $group = $transport->next($buffer);
            self::assertNotNull($group);
            $gr = new Reader($group);
            self::assertSame(31, $gr->byte(), 'KEX_DH_GEX_GROUP');
            $p = $gr->mpint();
            $g = $gr->mpint();
            $client = openssl_pkey_new(['dh' => ['p' => $p, 'g' => $g, 'priv_key' => random_bytes(64)]]);
            $e = openssl_pkey_get_details($client)['dh']['pub_key'];
            $server->feed($transport->frame((new Buf())->byte(32)->mpint($e)->get()));
            [$kS, $f] = $this->replyDh($transport, $server, 33, $buffer);
            $peer = openssl_pkey_new(['dh' => ['p' => $p, 'g' => $g, 'pub_key' => $f]]);
            $kMpint = Buf::mpintOf((string) openssl_pkey_derive($peer, $client));
            $h = hash(
                'sha256',
                $prefix($kS)
                . (new Buf())->uint32($min)->uint32($n)->uint32($max)->get()
                . Buf::mpintOf($p) . Buf::mpintOf($g) . Buf::mpintOf($e) . Buf::mpintOf($f) . $kMpint,
                true
            );

            return ['sha256', $kMpint, $h];
        }

        self::fail("unhandled kex {$kex}");
    }

    /**
     * Read a KEX_ECDH_REPLY (msg 31): [K_S, Q_S]. The trailing NEWKEYS (same server flush) is left in
     * $buffer for the caller to consume.
     *
     * @return array{0:string,1:string}
     */
    private function replyEcdh(Transport $transport, SshConnection $server, string &$buffer): array
    {
        $buffer .= $server->takeOut();
        $reply = $transport->next($buffer);
        self::assertNotNull($reply);
        $r = new Reader($reply);
        self::assertSame(31, $r->byte(), 'KEX_ECDH_REPLY');
        $kS = $r->string();
        $qS = $r->string();
        $r->string(); // signature — a honeypot client does not verify it

        return [$kS, $qS];
    }

    /**
     * Read a fixed-group / GEX DH reply (msg $expect): [K_S, f]. Any trailing NEWKEYS is left in $buffer.
     *
     * @return array{0:string,1:string}
     */
    private function replyDh(Transport $transport, SshConnection $server, int $expect, string &$buffer): array
    {
        $buffer .= $server->takeOut();
        $reply = $transport->next($buffer);
        self::assertNotNull($reply);
        $r = new Reader($reply);
        self::assertSame($expect, $r->byte(), 'DH REPLY');
        $kS = $r->string();
        $f = $r->mpint();
        $r->string(); // signature

        return [$kS, $f];
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

    /**
     * One row per Stage-1 served name (every kex, host key, cipher, MAC, both compression modes), plus a
     * per-direction-asymmetric row. The union of rows covers each advertised name at least once.
     *
     * @return array<string,array{0:string,1:string,2:string,3:string,4:string,5:string,6:string}>
     */
    public function matrixRows(): array
    {
        return [
            // kex, hostKey, encC2S, encS2C, macC2S, macS2C, comp
            'curve25519 + ed25519 + chacha20 + umac-64-etm' => ['curve25519-sha256', 'ssh-ed25519', 'chacha20-poly1305@openssh.com', 'chacha20-poly1305@openssh.com', 'umac-64-etm@openssh.com', 'umac-64-etm@openssh.com', 'none'],
            'curve25519@libssh + rsa-256 + aes128-ctr + hmac-256' => ['curve25519-sha256@libssh.org', 'rsa-sha2-256', 'aes128-ctr', 'aes128-ctr', 'hmac-sha2-256', 'hmac-sha2-256', 'none'],
            'nistp256 + ecdsa + aes128-gcm + hmac-256-etm' => ['ecdh-sha2-nistp256', 'ecdsa-sha2-nistp256', 'aes128-gcm@openssh.com', 'aes128-gcm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'none'],
            'nistp384 + rsa-512 + aes256-gcm + hmac-512-etm' => ['ecdh-sha2-nistp384', 'rsa-sha2-512', 'aes256-gcm@openssh.com', 'aes256-gcm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'none'],
            'nistp521 + ed25519 + aes192-ctr + hmac-sha1-etm' => ['ecdh-sha2-nistp521', 'ssh-ed25519', 'aes192-ctr', 'aes192-ctr', 'hmac-sha1-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'none'],
            'group14 + rsa-256 + aes256-ctr + hmac-512' => ['diffie-hellman-group14-sha256', 'rsa-sha2-256', 'aes256-ctr', 'aes256-ctr', 'hmac-sha2-512', 'hmac-sha2-512', 'none'],
            'group16 + ecdsa + aes256-ctr + umac-128-etm' => ['diffie-hellman-group16-sha512', 'ecdsa-sha2-nistp256', 'aes256-ctr', 'aes256-ctr', 'umac-128-etm@openssh.com', 'umac-128-etm@openssh.com', 'none'],
            'group18 + ed25519 + aes256-ctr + hmac-sha1' => ['diffie-hellman-group18-sha512', 'ssh-ed25519', 'aes256-ctr', 'aes256-ctr', 'hmac-sha1', 'hmac-sha1', 'none'],
            'gex + ed25519 + aes128-ctr + hmac-256' => ['diffie-hellman-group-exchange-sha256', 'ssh-ed25519', 'aes128-ctr', 'aes128-ctr', 'hmac-sha2-256', 'hmac-sha2-256', 'none'],
            'curve25519 + ed25519 + aes256-ctr + umac-64' => ['curve25519-sha256', 'ssh-ed25519', 'aes256-ctr', 'aes256-ctr', 'umac-64@openssh.com', 'umac-64@openssh.com', 'none'],
            'curve25519 + ed25519 + aes256-ctr + umac-128' => ['curve25519-sha256', 'ssh-ed25519', 'aes256-ctr', 'aes256-ctr', 'umac-128@openssh.com', 'umac-128@openssh.com', 'none'],
            'curve25519 + ed25519 + aes128-ctr + zlib' => ['curve25519-sha256', 'ssh-ed25519', 'aes128-ctr', 'aes128-ctr', 'hmac-sha2-256', 'hmac-sha2-256', 'zlib@openssh.com'],
            'asymmetric directions (per-direction sizes)' => ['curve25519-sha256', 'ssh-ed25519', 'aes128-ctr', 'aes256-gcm@openssh.com', 'hmac-sha1', 'hmac-sha2-512-etm@openssh.com', 'none'],
        ];
    }
}
