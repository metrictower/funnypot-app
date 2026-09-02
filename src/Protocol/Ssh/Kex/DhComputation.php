<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Kex;

/**
 * The finite-field Diffie-Hellman arithmetic shared by {@see Dh} and {@see DhGex}: peer-value
 * validation (sshd dh_pub_is_valid), our ephemeral keypair, and the shared-secret derivation — all
 * on ext-openssl with an embedded modulus, no gmp.
 */
trait DhComputation
{
    /**
     * Reject a client public value the way sshd's dh_pub_is_valid does: 1 < e < p−1 and at least
     * four bits set. OpenSSL itself accepts small values such as e=2, so this pre-check is
     * load-bearing, not belt-and-braces.
     */
    private function validatePeerValue(string $e, string $p): void
    {
        if (
            DhGroups::cmp($e, "\x01") <= 0
            || DhGroups::cmp($e, DhGroups::minusOne($p)) >= 0
            || DhGroups::bitsSet($e) < 4
        ) {
            throw new \RuntimeException('ssh: invalid dh public value');
        }
    }

    /**
     * Our ephemeral DH keypair on modulus $p. We supply a 512-bit private exponent (sshd's own
     * sizing for this suite), which keeps group18 at ~35 ms instead of ~0.5 s. If the running
     * OpenSSL build does not compute the public value from a supplied private exponent (detected at
     * runtime: openssl_pkey_new returns false, or pub_key comes back missing/empty), fall back to
     * letting OpenSSL generate the exponent (default length, slower, correct) — so a PHP 8.0/8.1
     * matrix surprise degrades instead of breaking the handshake.
     *
     * @return array{0:\OpenSSLAsymmetricKey,1:string} [our private key, our public value f (raw)]
     */
    private function dhKeypair(string $p): array
    {
        $ours = openssl_pkey_new(['dh' => ['p' => $p, 'g' => DhGroups::G, 'priv_key' => random_bytes(64)]]);
        $f = '';
        if ($ours !== false) {
            $details = openssl_pkey_get_details($ours);
            $f = $details['dh']['pub_key'] ?? '';
        }
        if ($ours === false || $f === '') {
            self::drainOpensslErrors(); // the priv_key attempt may have left errors before we fall back
            $ours = openssl_pkey_new(['dh' => ['p' => $p, 'g' => DhGroups::G]]);
            if ($ours === false) {
                self::drainOpensslErrors();
                throw new \RuntimeException('ssh: dh keygen failed');
            }
            $details = openssl_pkey_get_details($ours);
            $f = $details['dh']['pub_key'] ?? '';
            if ($f === '') {
                throw new \RuntimeException('ssh: dh keygen produced no public value');
            }
        }

        return [$ours, $f];
    }

    /** Derive the shared secret K from the peer value $e on modulus $p and our private key. */
    private function dhDerive(string $p, string $e, \OpenSSLAsymmetricKey $ours): string
    {
        $peer = openssl_pkey_new(['dh' => ['p' => $p, 'g' => DhGroups::G, 'pub_key' => $e]]);
        if ($peer === false) {
            self::drainOpensslErrors();
            throw new \RuntimeException('ssh: invalid dh public value');
        }
        $k = openssl_pkey_derive($peer, $ours);
        if ($k === false) {
            // A non-residue / out-of-range e is rejected here (OpenSSL 3 checks it); drain so the
            // stale error does not bleed into a later openssl call's error string.
            self::drainOpensslErrors();
            throw new \RuntimeException('ssh: dh derive failed');
        }

        return $k;
    }

    /** Empty the per-thread OpenSSL error queue after a handled failure (as Ecdh does on import). */
    private static function drainOpensslErrors(): void
    {
        while (openssl_error_string() !== false) {
            // discard
        }
    }
}
