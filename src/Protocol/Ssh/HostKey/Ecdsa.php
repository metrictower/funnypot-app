<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\HostKey;

use Funnypot\Protocol\Ssh\Buf;

/**
 * An ECDSA host key on NIST P-256 (ext-openssl), algorithm name ecdsa-sha2-nistp256 (RFC 5656
 * §3.1). openssl_sign emits a DER SEQUENCE{INTEGER r, INTEGER s}; the SSH signature blob carries
 * `string( mpint r ‖ mpint s )` instead, so the DER is parsed and re-encoded. The public point Q is
 * left-padded to 32 bytes per coordinate (openssl_pkey_get_details strips leading zeros).
 *
 * Persistence is PKCS#8 PEM only ({@see pem()} = openssl_pkey_export, {@see fromPem()} =
 * openssl_pkey_get_private); OpenSSH's own -----BEGIN OPENSSH PRIVATE KEY----- format is not readable
 * by ext-openssl, and a non-prime256v1 key is rejected since the algorithm name is fixed.
 */
final class Ecdsa implements HostKeyAlgorithm
{
    private const CURVE = 'prime256v1';
    private const FLEN = 32;

    public function __construct(private \OpenSSLAsymmetricKey $key)
    {
    }

    /** A fresh P-256 key. */
    public static function generate(): self
    {
        $key = openssl_pkey_new(['curve_name' => self::CURVE, 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        if ($key === false) {
            throw new \RuntimeException('ssh: ecdsa keygen failed');
        }

        return new self($key);
    }

    /** Reconstruct from a PKCS#8 PEM, or null when it is missing/corrupt/wrong-curve. */
    public static function fromPem(string $pem): ?self
    {
        $key = openssl_pkey_get_private($pem);
        if ($key === false) {
            return null;
        }
        $details = openssl_pkey_get_details($key);
        if (($details['type'] ?? -1) !== OPENSSL_KEYTYPE_EC || ($details['ec']['curve_name'] ?? '') !== self::CURVE) {
            return null;
        }

        return new self($key);
    }

    /** The PKCS#8 PEM for persistence. */
    public function pem(): string
    {
        openssl_pkey_export($this->key, $pem);

        return (string) $pem;
    }

    public function algorithm(): string
    {
        return 'ecdsa-sha2-nistp256';
    }

    /** K_S: string "ecdsa-sha2-nistp256" ‖ string "nistp256" ‖ string Q (04 ‖ pad(x) ‖ pad(y)). */
    public function publicBlob(): string
    {
        $details = openssl_pkey_get_details($this->key);
        $q = "\x04"
            . str_pad($details['ec']['x'], self::FLEN, "\x00", STR_PAD_LEFT)
            . str_pad($details['ec']['y'], self::FLEN, "\x00", STR_PAD_LEFT);

        return (new Buf())
            ->string('ecdsa-sha2-nistp256')
            ->string('nistp256')
            ->string($q)
            ->get();
    }

    /** string "ecdsa-sha2-nistp256" ‖ string( mpint r ‖ mpint s ). */
    public function sign(string $data): string
    {
        if (openssl_sign($data, $der, $this->key, OPENSSL_ALGO_SHA256) === false) {
            throw new \RuntimeException('ssh: ecdsa sign failed');
        }
        [$r, $s] = self::parseDerSig($der);

        return (new Buf())
            ->string('ecdsa-sha2-nistp256')
            ->string((new Buf())->mpint($r)->mpint($s)->get())
            ->get();
    }

    /**
     * Parse a DER SEQUENCE{INTEGER r, INTEGER s}. For P-256 r,s <= 33 bytes and the sequence <= 70,
     * so short-form (one-byte) lengths always suffice; a long-form or non-SEQUENCE header, a declared
     * SEQUENCE length that does not span exactly the buffer, or any trailing byte after s is rejected
     * rather than silently mis-parsed.
     *
     * @return array{0:string,1:string} [r, s] as raw big-endian magnitudes
     */
    private static function parseDerSig(string $der): array
    {
        if (strlen($der) < 8 || ord($der[0]) !== 0x30 || (ord($der[1]) & 0x80) !== 0 || 2 + ord($der[1]) !== strlen($der)) {
            throw new \RuntimeException('ssh: malformed ecdsa signature');
        }
        $off = 2;
        $read = static function (string $der, int &$off): string {
            if ($off + 2 > strlen($der) || ord($der[$off]) !== 0x02 || (ord($der[$off + 1]) & 0x80) !== 0) {
                throw new \RuntimeException('ssh: malformed ecdsa signature');
            }
            $len = ord($der[$off + 1]);
            $off += 2;
            if ($off + $len > strlen($der)) {
                throw new \RuntimeException('ssh: malformed ecdsa signature');
            }
            $v = substr($der, $off, $len);
            $off += $len;

            return $v;
        };
        $r = $read($der, $off);
        $s = $read($der, $off);
        if ($off !== strlen($der)) {
            throw new \RuntimeException('ssh: malformed ecdsa signature'); // trailing data after r,s
        }

        return [$r, $s];
    }
}
