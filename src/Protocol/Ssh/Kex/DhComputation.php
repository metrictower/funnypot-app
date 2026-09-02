<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Kex;

/**
 * The finite-field Diffie-Hellman arithmetic shared by {@see Dh} and {@see DhGex}: peer-value
 * validation (sshd dh_pub_is_valid), our ephemeral keypair, and the shared-secret derivation — all
 * on ext-openssl with an embedded modulus, no gmp.
 *
 * OpenSSL 3 recognises the embedded RFC 3526 moduli as named groups and rejects an in-range
 * non-subgroup peer value e that sshd's dh_pub_is_valid (range + popcount only) accepts and completes.
 * {@see dhDerive()} matches sshd exactly by retrying such an e under an alternate generator (g=5), which
 * suppresses OpenSSL's named-group subgroup test while leaving K = e^x mod p unchanged — so the honeypot
 * does not disconnect where a real sshd would answer with a signed REPLY (a probe-able divergence, live
 * now that DH is advertised). Real client values (e = g^x, a subgroup member) complete on the first g=2
 * attempt and never reach the retry.
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
        // First attempt on the RFC 3526 named group (g=2): OpenSSL's stronger subgroup check stays in
        // force for the 100% real-client case (e = g^x is always a subgroup member).
        $peer = openssl_pkey_new(['dh' => ['p' => $p, 'g' => DhGroups::G, 'pub_key' => $e]]);
        if ($peer !== false) {
            $k = openssl_pkey_derive($peer, $ours);
            if ($k !== false) {
                return $k;
            }
        }

        // OpenSSL 3 rejected an e that already passed sshd's range + popcount check (validatePeerValue),
        // i.e. an in-range non-subgroup value. Drain the stale error, then retry with BOTH keys built on
        // the alternate generator g=5 (DhGroups::G_RETRY): OpenSSL then treats the modulus as an anonymous
        // group with no q, skips the subgroup test, and derives the byte-identical K (g plays no part in
        // e^x mod p) — exactly sshd's dh_pub_is_valid semantics. Reusing our own private exponent keeps
        // K consistent with the f already sent to the client.
        self::drainOpensslErrors();
        $details = openssl_pkey_get_details($ours);
        $priv = is_array($details) ? ($details['dh']['priv_key'] ?? '') : '';
        if ($priv !== '') {
            $oursAlt = openssl_pkey_new(['dh' => ['p' => $p, 'g' => DhGroups::G_RETRY, 'priv_key' => $priv]]);
            $peerAlt = openssl_pkey_new(['dh' => ['p' => $p, 'g' => DhGroups::G_RETRY, 'pub_key' => $e]]);
            if ($oursAlt !== false && $peerAlt !== false) {
                $k = openssl_pkey_derive($peerAlt, $oursAlt);
                if ($k !== false) {
                    return $k;
                }
            }
        }

        // Neither path derived — a genuinely malformed e. Drain so the stale error does not bleed into a
        // later openssl call's error string, and fail as before.
        self::drainOpensslErrors();
        throw new \RuntimeException('ssh: dh derive failed');
    }

    /** Empty the per-thread OpenSSL error queue after a handled failure (as Ecdh does on import). */
    private static function drainOpensslErrors(): void
    {
        while (openssl_error_string() !== false) {
            // discard
        }
    }
}
