<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh;

/**
 * RFC 4253 §7.2 key derivation, with the key-expansion extension a one-shot formula lacks. It is
 * driven by {@see Kex\KexResult::keys()}. Each key is HASH(K ‖ H ‖ letter ‖ session_id) truncated to the needed length;
 * when more bytes are needed than one hash produces (a 64-byte hmac-sha2-512 or chacha20-poly1305
 * key under a SHA-256 exchange hash), the output is extended with Kn = HASH(K ‖ H ‖ K1 ‖ … ‖ Kn−1).
 *
 * For need <= hashlen this is bit-identical to the pre-existing one-shot derivation, so callers
 * that independently re-derive short keys keep matching.
 */
final class KeyDerivation
{
    /**
     * @param string $hashAlgo  hash name for {@see hash()} (e.g. 'sha256')
     * @param string $kEncoded  the shared secret as the kex encodes it into the hash (mpint today)
     * @param string $h         the exchange hash H
     * @param string $sessionId the session id (== H for the first key exchange)
     * @param string $letter    the single RFC 4253 §7.2 letter (A–F)
     * @param int    $need      bytes required
     */
    public static function derive(string $hashAlgo, string $kEncoded, string $h, string $sessionId, string $letter, int $need): string
    {
        if ($need === 0) {
            return ''; // chacha20-poly1305 has ivLen 0
        }
        $out = hash($hashAlgo, $kEncoded . $h . $letter . $sessionId, true);
        while (strlen($out) < $need) {
            $out .= hash($hashAlgo, $kEncoded . $h . $out, true);
        }

        return substr($out, 0, $need);
    }

    /**
     * Derive all six directional materials (letters A–F in RFC 4253 §7.2 order).
     *
     * @return array{ivC2S:string,ivS2C:string,keyC2S:string,keyS2C:string,macC2S:string,macS2C:string}
     */
    public static function deriveAll(string $hashAlgo, string $kEncoded, string $h, string $sessionId, int $ivLen, int $keyLen, int $macLen): array
    {
        return [
            'ivC2S' => self::derive($hashAlgo, $kEncoded, $h, $sessionId, 'A', $ivLen),
            'ivS2C' => self::derive($hashAlgo, $kEncoded, $h, $sessionId, 'B', $ivLen),
            'keyC2S' => self::derive($hashAlgo, $kEncoded, $h, $sessionId, 'C', $keyLen),
            'keyS2C' => self::derive($hashAlgo, $kEncoded, $h, $sessionId, 'D', $keyLen),
            'macC2S' => self::derive($hashAlgo, $kEncoded, $h, $sessionId, 'E', $macLen),
            'macS2C' => self::derive($hashAlgo, $kEncoded, $h, $sessionId, 'F', $macLen),
        ];
    }
}
