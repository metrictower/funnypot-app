<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh;

/**
 * curve25519-sha256 key exchange (RFC 8731) plus the RFC 4253 §7.2 key derivation. Given the two
 * version strings, both KEXINIT payloads, the host key and the client's ephemeral public key, it
 * produces the server ephemeral key, the exchange hash H, the host-key signature over H, and the
 * six directional key materials (two IVs, two cipher keys, two MAC keys). libsodium supplies the
 * X25519 and ed25519 primitives; the exchange hash is SHA-256.
 *
 * The result carries enough material for aes256-ctr + hmac-sha2-256 in both directions.
 */
final class Kex
{
    public function __construct(
        public string $serverEphemeralPublic,
        public string $exchangeHash,
        public string $signature,
        public string $ivC2S,
        public string $ivS2C,
        public string $keyC2S,
        public string $keyS2C,
        public string $macC2S,
        public string $macS2C
    ) {
    }

    /**
     * @param string $vC  client identification string (no CRLF)
     * @param string $vS  server identification string (no CRLF)
     * @param string $iC  client SSH_MSG_KEXINIT payload
     * @param string $iS  server SSH_MSG_KEXINIT payload
     * @param string $qC  client ephemeral X25519 public key (32 bytes)
     */
    public static function curve25519(string $vC, string $vS, string $iC, string $iS, HostKey $hostKey, string $qC): self
    {
        if (strlen($qC) !== 32) {
            throw new \RuntimeException('ssh: bad client ephemeral key length');
        }
        $priv = random_bytes(32);
        $qS = sodium_crypto_scalarmult_base($priv);
        $shared = sodium_crypto_scalarmult($priv, $qC); // X25519 shared secret; throws on all-zero output
        $kMpint = Buf::mpintOf($shared);
        $hostBlob = $hostKey->publicBlob();

        $hashInput = Buf::stringOf($vC)
            . Buf::stringOf($vS)
            . Buf::stringOf($iC)
            . Buf::stringOf($iS)
            . Buf::stringOf($hostBlob)
            . Buf::stringOf($qC)
            . Buf::stringOf($qS)
            . $kMpint;
        $h = hash('sha256', $hashInput, true);
        $sig = $hostKey->sign($h);

        // session_id == H for the first (and only) key exchange. Sizes are the aes256-ctr +
        // hmac-sha2-256 material this ticket negotiates; FP-0291 replaces them with the negotiated
        // CipherSuite sizes. For need <= 32 this is bit-identical to the former one-shot formula.
        $k = KeyDerivation::deriveAll('sha256', $kMpint, $h, $h, 16, 32, 32);

        return new self(
            $qS,
            $h,
            $sig,
            $k['ivC2S'],  // IV client->server (AES block)
            $k['ivS2C'],  // IV server->client
            $k['keyC2S'], // key client->server (AES-256)
            $k['keyS2C'], // key server->client
            $k['macC2S'], // MAC key client->server (hmac-sha2-256)
            $k['macS2C']  // MAC key server->client
        );
    }
}
