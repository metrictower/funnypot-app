<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\HostKey;

use Funnypot\Protocol\Ssh\Buf;

/**
 * An RSA host key (ext-openssl) signing under rsa-sha2-512 or rsa-sha2-256 (RFC 8332). The key type
 * in the public blob stays "ssh-rsa" for both SHA-2 signature names — only the signature blob names
 * the hash. One key serves both signers: {@see withAlgorithm()} returns a copy bound to the other
 * name.
 *
 * Persistence is PKCS#8 PEM only: {@see pem()} is openssl_pkey_export (which emits
 * -----BEGIN PRIVATE KEY-----) and {@see fromPem()} is openssl_pkey_get_private, so an
 * operator-supplied key file must be PKCS#8 (or the traditional PKCS#1 -----BEGIN RSA PRIVATE KEY-----
 * that openssl_pkey_get_private also reads). OpenSSH's own -----BEGIN OPENSSH PRIVATE KEY----- format
 * is NOT readable by ext-openssl and is not supported; a file in that format reads as corrupt and the
 * key is regenerated.
 */
final class Rsa implements HostKeyAlgorithm
{
    /** @param \OpenSSLAsymmetricKey $key @param string $sigAlgo 'rsa-sha2-512' | 'rsa-sha2-256' */
    public function __construct(private \OpenSSLAsymmetricKey $key, private string $sigAlgo = 'rsa-sha2-512')
    {
    }

    /** A fresh RSA key. Ubuntu 22.04 `ssh-keygen -A` produces 3072-bit; a persona may vary $bits. */
    public static function generate(int $bits = 3072): self
    {
        $key = openssl_pkey_new(['private_key_bits' => $bits, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        if ($key === false) {
            throw new \RuntimeException('ssh: rsa keygen failed');
        }

        return new self($key);
    }

    /** Reconstruct from a PKCS#8 PEM, or null when it is missing/corrupt. */
    public static function fromPem(string $pem): ?self
    {
        $key = openssl_pkey_get_private($pem);
        if ($key === false) {
            return null;
        }
        $details = openssl_pkey_get_details($key);
        if (($details['type'] ?? -1) !== OPENSSL_KEYTYPE_RSA) {
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

    /** A copy of this key bound to the other RSA signature name. */
    public function withAlgorithm(string $sigAlgo): self
    {
        return new self($this->key, $sigAlgo);
    }

    public function algorithm(): string
    {
        return $this->sigAlgo;
    }

    /** K_S: string "ssh-rsa" ‖ mpint e ‖ mpint n (RFC 8332 §3 — key type stays ssh-rsa). */
    public function publicBlob(): string
    {
        $details = openssl_pkey_get_details($this->key);

        return (new Buf())
            ->string('ssh-rsa')
            ->mpint($details['rsa']['e'])
            ->mpint($details['rsa']['n'])
            ->get();
    }

    /** string sigAlgo ‖ string sig (raw PKCS#1 v1.5). */
    public function sign(string $data): string
    {
        $algo = $this->sigAlgo === 'rsa-sha2-512' ? OPENSSL_ALGO_SHA512 : OPENSSL_ALGO_SHA256;
        if (openssl_sign($data, $sig, $this->key, $algo) === false) {
            throw new \RuntimeException('ssh: rsa sign failed');
        }

        return (new Buf())->string($this->sigAlgo)->string($sig)->get();
    }
}
