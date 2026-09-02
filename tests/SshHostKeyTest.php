<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\Ssh\Buf;
use Funnypot\Protocol\Ssh\HostKey\Ecdsa;
use Funnypot\Protocol\Ssh\HostKey\Ed25519;
use Funnypot\Protocol\Ssh\HostKey\HostKeySet;
use Funnypot\Protocol\Ssh\HostKey\Rsa;
use Funnypot\Protocol\Ssh\Kex\KexSuite;
use Funnypot\Protocol\Ssh\Reader;
use PHPUnit\Framework\TestCase;

/**
 * FP-0289 §4.5 — the host-key algorithms (RSA sha2-256/512, ECDSA nistp256, Ed25519) produce the
 * RFC-correct public blob and a signature an independent OpenSSL/sodium verifier accepts, and the
 * HostKeySet persists per-deploy material back-compatibly with the existing ed25519 file. These
 * classes are built here but not advertised until FP-0291; every assertion fails at baseline
 * (the classes did not exist).
 */
final class SshHostKeyTest extends TestCase
{
    public function test_rsa_public_blob_and_sha2_signatures_verify(): void
    {
        $rsa = Rsa::generate();

        $r = new Reader($rsa->publicBlob());
        self::assertSame('ssh-rsa', $r->string(), 'RFC 8332: key type stays ssh-rsa for both SHA-2 names');
        self::assertSame("\x01\x00\x01", $r->mpint(), 'e = 65537');
        $n = $r->mpint();
        self::assertSame(384, strlen($n), '3072-bit modulus is 384 bytes');

        $pubPem = $this->publicPem($rsa->pem());
        $data = 'exchange-hash-stand-in';

        foreach (['rsa-sha2-256' => OPENSSL_ALGO_SHA256, 'rsa-sha2-512' => OPENSSL_ALGO_SHA512] as $name => $algo) {
            $signer = $rsa->withAlgorithm($name);
            self::assertSame($name, $signer->algorithm());
            $sig = new Reader($signer->sign($data));
            self::assertSame($name, $sig->string(), 'the signature blob names the negotiated algorithm');
            $raw = $sig->string();
            self::assertSame(384, strlen($raw), 'PKCS#1 v1.5 signature is 384 bytes for RSA-3072');
            self::assertSame(1, openssl_verify($data, $raw, $pubPem, $algo), "{$name} verifies under its own hash");
        }

        // The hash follows the name: a sha2-256 signature does not verify under SHA-512.
        $sig256 = new Reader((new Rsa($this->privKey($rsa->pem()), 'rsa-sha2-256'))->sign($data));
        $sig256->string();
        self::assertSame(0, openssl_verify($data, $sig256->string(), $pubPem, OPENSSL_ALGO_SHA512));

        // withAlgorithm shares the key: same public blob.
        self::assertSame($rsa->publicBlob(), $rsa->withAlgorithm('rsa-sha2-256')->publicBlob());
    }

    public function test_ecdsa_public_blob_and_signature_verify(): void
    {
        $ecdsa = Ecdsa::generate();

        $r = new Reader($ecdsa->publicBlob());
        self::assertSame('ecdsa-sha2-nistp256', $r->string());
        self::assertSame('nistp256', $r->string());
        $q = $r->string();
        self::assertSame(65, strlen($q), 'Q = 04 ‖ x(32) ‖ y(32)');
        self::assertSame("\x04", $q[0], 'uncompressed point');

        $pubPem = $this->publicPem($ecdsa->pem());
        $data = 'exchange-hash-stand-in';
        // 20 signatures: exercises r/s with and without a leading sign byte (each re-DERed verifies).
        for ($i = 0; $i < 20; $i++) {
            $sig = new Reader($ecdsa->sign($data . $i));
            self::assertSame('ecdsa-sha2-nistp256', $sig->string());
            $rs = new Reader($sig->string());
            $der = $this->reDer($rs->mpint(), $rs->mpint());
            self::assertSame(1, openssl_verify($data . $i, $der, $pubPem, OPENSSL_ALGO_SHA256), "sig #{$i} verifies");
        }
    }

    public function test_ecdsa_der_parser_rejects_trailing_data(): void
    {
        // The parser only ever sees openssl_sign output in production, but a malformed/overlong DER
        // must be rejected, not silently truncated. Reflection reaches the private static so the
        // trailing-data guard is pinned (non-vacuous: the pre-fix parser ignored trailing bytes).
        $ec = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        openssl_sign('data', $der, $ec, OPENSSL_ALGO_SHA256);

        $parse = new \ReflectionMethod(Ecdsa::class, 'parseDerSig');
        $parse->setAccessible(true);

        // A well-formed signature still parses to a non-empty (r, s).
        [$r, $s] = $parse->invoke(null, $der);
        self::assertNotSame('', $r);
        self::assertNotSame('', $s);

        // One trailing byte → rejected.
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('malformed ecdsa signature');
        $parse->invoke(null, $der . "\x00");
    }

    public function test_ecdsa_point_is_always_left_padded_to_65_bytes(): void
    {
        // ~1/128 keys have a short x or y; over 300 generations every Q must still be 65 bytes.
        for ($i = 0; $i < 300; $i++) {
            $r = new Reader(Ecdsa::generate()->publicBlob());
            $r->string();
            $r->string();
            self::assertSame(65, strlen($r->string()));
        }
    }

    public function test_ed25519_blob_and_signature_verify(): void
    {
        $ed = Ed25519::generate();
        self::assertSame('ssh-ed25519', $ed->algorithm());

        $pub = new Reader($ed->publicBlob());
        self::assertSame('ssh-ed25519', $pub->string());
        $pubKey = $pub->string();

        $data = random_bytes(32);
        $sig = new Reader($ed->sign($data));
        self::assertSame('ssh-ed25519', $sig->string());
        self::assertTrue(sodium_crypto_sign_verify_detached($sig->string(), $data, $pubKey));
    }

    public function test_hostkeyset_storage_backcompat_and_stability(): void
    {
        $dir = sys_get_temp_dir() . '/fp-hkset-' . getmypid() . '-' . bin2hex(random_bytes(4));
        @mkdir($dir, 0700, true);
        $edPath = $dir . '/ssh_host_ed25519';
        $rsaPath = $dir . '/ssh_host_rsa_key';
        $ecdsaPath = $dir . '/ssh_host_ecdsa_key';

        try {
            // A pre-existing 96-byte raw ed25519 file (the format shipped before FP-0289).
            $pair = sodium_crypto_sign_keypair();
            $preSecret = sodium_crypto_sign_secretkey($pair);
            $prePublic = sodium_crypto_sign_publickey($pair);
            file_put_contents($edPath, $preSecret . $prePublic);
            $expectedEdBlob = (new Buf())->string('ssh-ed25519')->string($prePublic)->get();

            $set = HostKeySet::load($edPath);
            self::assertSame(
                $expectedEdBlob,
                $set->forAlgorithm('ssh-ed25519')->publicBlob(),
                'the existing ed25519 key is adopted, NOT regenerated (the back-compat AC)'
            );

            // The siblings are generated next to it, persisted, mode 0600, PKCS#8 PEM.
            foreach ([$rsaPath, $ecdsaPath] as $p) {
                self::assertFileExists($p);
                self::assertSame('0600', substr(sprintf('%o', fileperms($p)), -4));
                self::assertStringStartsWith('-----BEGIN PRIVATE KEY-----', (string) file_get_contents($p));
            }

            // A second load returns identical blobs for all three (stable fingerprints on restart).
            $again = HostKeySet::load($edPath);
            foreach (['ssh-ed25519', 'rsa-sha2-512', 'ecdsa-sha2-nistp256'] as $algo) {
                self::assertSame(
                    $set->forAlgorithm($algo)->publicBlob(),
                    $again->forAlgorithm($algo)->publicBlob(),
                    "{$algo} is stable across loads"
                );
            }

            // Corrupt the RSA PEM: the third load regenerates RSA only; ed25519 and ECDSA unchanged.
            file_put_contents($rsaPath, 'not a pem');
            $third = HostKeySet::load($edPath);
            self::assertNotSame(
                $set->forAlgorithm('rsa-sha2-512')->publicBlob(),
                $third->forAlgorithm('rsa-sha2-512')->publicBlob(),
                'a corrupt RSA key is regenerated'
            );
            self::assertSame($set->forAlgorithm('ssh-ed25519')->publicBlob(), $third->forAlgorithm('ssh-ed25519')->publicBlob());
            self::assertSame($set->forAlgorithm('ecdsa-sha2-nistp256')->publicBlob(), $third->forAlgorithm('ecdsa-sha2-nistp256')->publicBlob());
        } finally {
            @unlink($edPath);
            @unlink($rsaPath);
            @unlink($ecdsaPath);
            @rmdir($dir);
        }
    }

    public function test_hostkeyset_algorithm_list_and_unknown_names_throw(): void
    {
        self::assertSame(
            ['rsa-sha2-512', 'rsa-sha2-256', 'ecdsa-sha2-nistp256', 'ssh-ed25519'],
            HostKeySet::ALGORITHMS
        );
        $set = SshHostKeyFixture::set();
        foreach (HostKeySet::ALGORITHMS as $name) {
            self::assertSame($name, $set->forAlgorithm($name)->algorithm());
        }
        // SHA-1 RSA and DSA are not offered by 8.9.
        foreach (['ssh-rsa', 'ssh-dss'] as $unsupported) {
            try {
                $set->forAlgorithm($unsupported);
                self::fail("forAlgorithm('{$unsupported}') must throw");
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('unknown host-key algorithm', $e->getMessage());
            }
        }
    }

    public function test_kexsuite_names_all_create_and_unknown_names_throw(): void
    {
        self::assertSame(
            [
                'curve25519-sha256',
                'curve25519-sha256@libssh.org',
                'ecdh-sha2-nistp256',
                'ecdh-sha2-nistp384',
                'ecdh-sha2-nistp521',
                'diffie-hellman-group-exchange-sha256',
                'diffie-hellman-group16-sha512',
                'diffie-hellman-group18-sha512',
                'diffie-hellman-group14-sha256',
            ],
            KexSuite::NAMES
        );
        $hostKey = SshHostKeyFixture::set()->forAlgorithm('ssh-ed25519');
        foreach (KexSuite::NAMES as $name) {
            $kex = KexSuite::create($name, 'vC', 'vS', 'iC', 'iS', $hostKey);
            self::assertSame($name, $kex->name());
        }
        foreach (['sntrup761x25519-sha512@openssh.com', 'kex-strict-s-v00@openssh.com'] as $unsupported) {
            try {
                KexSuite::create($unsupported, 'vC', 'vS', 'iC', 'iS', $hostKey);
                self::fail("create('{$unsupported}') must throw");
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('unknown kex', $e->getMessage());
            }
        }
    }

    private function privKey(string $pem): \OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_get_private($pem);
        self::assertNotFalse($key);

        return $key;
    }

    /** The public-key PEM extracted from a private PEM, for an independent openssl_verify. */
    private function publicPem(string $privPem): string
    {
        return openssl_pkey_get_details($this->privKey($privPem))['key'];
    }

    /** Re-encode an SSH (r, s) pair as the DER SEQUENCE{INTEGER r, INTEGER s} openssl_verify expects. */
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
}
