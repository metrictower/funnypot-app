<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Kex;

use Funnypot\Protocol\Ssh\HostKey\HostKeyAlgorithm;

/**
 * The name → {@see KexAlgorithm} table FP-0291 will consult, mirroring
 * {@see \Funnypot\Protocol\Ssh\Cipher\CipherSuite}. `create()` maps a negotiated kex name to a live
 * algorithm; an unknown name throws, so "advertise ⇒ implement" is enforced at create time and
 * never silently. This ticket only ever creates the curve25519-sha256 path (the served lists are
 * unchanged); the rest sit built and both-direction-tested for the flip ticket.
 *
 * kex-strict-{c,s} and ext-info-c are pseudo-algorithm markers, not real kex methods (see
 * KEX_STRICT_* / EXT_INFO_C and {@see isMarker()}); they carry handshake-shape signals and must
 * never be negotiated as a kex — {@see create()} throws on them.
 */
final class KexSuite
{
    // Handshake-shape pseudo-algorithm markers (RFC 8308 / Terrapin PROTOCOL §1.9). Never real kex
    // methods: {@see isMarker()} filters them out of the negotiation candidate set and
    // {@see create()} throws if one ever reaches it.
    public const KEX_STRICT_C = 'kex-strict-c-v00@openssh.com';
    public const KEX_STRICT_S = 'kex-strict-s-v00@openssh.com';
    public const EXT_INFO_C = 'ext-info-c';

    /** The nine real OpenSSH 8.9p1 kex names (sntrup761x25519 is FP-0292; kex-strict is a marker). */
    public const NAMES = [
        'curve25519-sha256',
        'curve25519-sha256@libssh.org',
        'ecdh-sha2-nistp256',
        'ecdh-sha2-nistp384',
        'ecdh-sha2-nistp521',
        'diffie-hellman-group-exchange-sha256',
        'diffie-hellman-group16-sha512',
        'diffie-hellman-group18-sha512',
        'diffie-hellman-group14-sha256',
    ];

    /** True for a handshake-shape pseudo-algorithm marker (never a real, negotiable kex method). */
    public static function isMarker(string $name): bool
    {
        return $name === self::KEX_STRICT_C
            || $name === self::KEX_STRICT_S
            || $name === self::EXT_INFO_C;
    }

    /** The kex hash for a name; throws on any name not in {@see NAMES}. */
    public static function hashAlgo(string $name): string
    {
        return match ($name) {
            'curve25519-sha256',
            'curve25519-sha256@libssh.org',
            'ecdh-sha2-nistp256',
            'diffie-hellman-group-exchange-sha256',
            'diffie-hellman-group14-sha256' => 'sha256',
            'ecdh-sha2-nistp384' => 'sha384',
            'ecdh-sha2-nistp521',
            'diffie-hellman-group16-sha512',
            'diffie-hellman-group18-sha512' => 'sha512',
            default => throw new \InvalidArgumentException("ssh: unknown kex {$name}"),
        };
    }

    /**
     * Build the server-side algorithm for a negotiated kex name; throws on an unadvertised name.
     */
    public static function create(
        string $name,
        string $vC,
        string $vS,
        string $iC,
        string $iS,
        HostKeyAlgorithm $hostKey
    ): KexAlgorithm {
        $hashAlgo = self::hashAlgo($name);
        switch ($name) {
            case 'curve25519-sha256':
            case 'curve25519-sha256@libssh.org':
            case 'ecdh-sha2-nistp256':
            case 'ecdh-sha2-nistp384':
            case 'ecdh-sha2-nistp521':
                return new Ecdh($name, $hashAlgo, $vC, $vS, $iC, $iS, $hostKey);
            case 'diffie-hellman-group14-sha256':
            case 'diffie-hellman-group16-sha512':
            case 'diffie-hellman-group18-sha512':
                return new Dh($name, $hashAlgo, $vC, $vS, $iC, $iS, $hostKey);
            case 'diffie-hellman-group-exchange-sha256':
                return new DhGex($name, $hashAlgo, $vC, $vS, $iC, $iS, $hostKey);
            default:
                throw new \InvalidArgumentException("ssh: unknown kex {$name}");
        }
    }
}
