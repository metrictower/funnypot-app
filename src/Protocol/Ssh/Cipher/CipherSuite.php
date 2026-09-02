<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Cipher;

use Funnypot\Protocol\Ssh\Ctr;

/**
 * The name → sizes → {@see PacketCipher} table for every SSH cipher and MAC the transport can
 * build. `build()` maps a negotiated (cipher, mac) pair to a live cipher; an unknown name throws,
 * so "advertise ⇒ implement" is enforced at build time and never silently. FP-0291 wires the
 * negotiation into this table; this ticket builds only the fixed aes256-ctr + hmac-sha2-256 pair
 * through it while the sibling classes sit vector-tested and ready.
 *
 * For an AEAD cipher (`*-gcm@openssh.com`, `chacha20-poly1305@openssh.com`) the MAC name and key
 * are ignored — OpenSSH still negotiates a MAC name and discards it. macKeyLen() of that negotiated
 * MAC is nonetheless what the KDF is asked for (harmless, matches sshd).
 */
final class CipherSuite
{
    public static function keyLen(string $cipher): int
    {
        return match ($cipher) {
            'aes128-ctr', 'aes128-gcm@openssh.com' => 16,
            'aes192-ctr' => 24,
            'aes256-ctr', 'aes256-gcm@openssh.com' => 32,
            'chacha20-poly1305@openssh.com' => 64,
            default => throw new \InvalidArgumentException("ssh: unknown cipher {$cipher}"),
        };
    }

    public static function ivLen(string $cipher): int
    {
        return match ($cipher) {
            'aes128-ctr', 'aes192-ctr', 'aes256-ctr' => 16,
            'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com' => 12,
            'chacha20-poly1305@openssh.com' => 0,
            default => throw new \InvalidArgumentException("ssh: unknown cipher {$cipher}"),
        };
    }

    public static function blockSize(string $cipher): int
    {
        return match ($cipher) {
            'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com' => 16,
            'chacha20-poly1305@openssh.com' => 8,
            default => throw new \InvalidArgumentException("ssh: unknown cipher {$cipher}"),
        };
    }

    public static function isAead(string $cipher): bool
    {
        return $cipher === 'aes128-gcm@openssh.com'
            || $cipher === 'aes256-gcm@openssh.com'
            || $cipher === 'chacha20-poly1305@openssh.com';
    }

    public static function macKeyLen(string $mac): int
    {
        return self::macSizes($mac)[1];
    }

    public static function macTagLen(string $mac): int
    {
        return self::macSizes($mac)[1];
    }

    public static function isEtm(string $mac): bool
    {
        return substr($mac, -16) === '-etm@openssh.com';
    }

    /**
     * Build the packet cipher for a negotiated (cipher, mac) pair from the derived material.
     * $mac/$macKey are ignored for AEAD ciphers.
     */
    public static function build(string $cipher, string $mac, string $key, string $iv, string $macKey): PacketCipher
    {
        switch ($cipher) {
            case 'aes128-ctr':
            case 'aes192-ctr':
            case 'aes256-ctr':
                return new CtrHmac(new Ctr($key, $iv), self::hmacAlgo($mac), $macKey, self::isEtm($mac));
            case 'aes128-gcm@openssh.com':
            case 'aes256-gcm@openssh.com':
                return new Gcm($key, $iv);
            case 'chacha20-poly1305@openssh.com':
                return new ChaChaPoly($key);
            default:
                throw new \InvalidArgumentException("ssh: unknown cipher {$cipher}");
        }
    }

    /** @return array{0:string,1:int} [hmac algo name, key/tag length in bytes] */
    private static function macSizes(string $mac): array
    {
        $base = self::isEtm($mac) ? substr($mac, 0, -16) : $mac;

        return match ($base) {
            'hmac-sha1' => ['sha1', 20],
            'hmac-sha2-256' => ['sha256', 32],
            'hmac-sha2-512' => ['sha512', 64],
            default => throw new \InvalidArgumentException("ssh: unknown mac {$mac}"),
        };
    }

    private static function hmacAlgo(string $mac): string
    {
        return self::macSizes($mac)[0];
    }
}
