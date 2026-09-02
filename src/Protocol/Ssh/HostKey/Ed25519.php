<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\HostKey;

use Funnypot\Protocol\Ssh\Buf;

/**
 * The server's ssh-ed25519 host key (libsodium). Generated once and persisted so the key is stable
 * across restarts (a changing host key trips client warnings and is itself a tell). The on-disk
 * format is unchanged from the pre-FP-0289 HostKey class — a 96-byte raw file (secret(64) ‖
 * public(32)) — so an existing storage/ssh_host_ed25519 keeps working byte-for-byte.
 */
final class Ed25519 implements HostKeyAlgorithm
{
    /** @param string $secret 64-byte ed25519 secret key @param string $public 32-byte public key */
    public function __construct(private string $secret, private string $public)
    {
    }

    /** Load the host key from $path, generating and persisting one on first use. */
    public static function load(string $path): self
    {
        $raw = @file_get_contents($path);
        $key = self::fromRaw($raw === false ? '' : $raw);
        if ($key !== null) {
            return $key;
        }

        $key = self::generate();
        @mkdir(dirname($path), 0700, true);
        if (@file_put_contents($path, $key->raw()) !== false) {
            @chmod($path, 0600);
        }

        return $key;
    }

    /** A fresh keypair (no I/O). */
    public static function generate(): self
    {
        $pair = sodium_crypto_sign_keypair();

        return new self(sodium_crypto_sign_secretkey($pair), sodium_crypto_sign_publickey($pair));
    }

    /** Reconstruct from the 96-byte raw file body, or null when it is not that format. */
    public static function fromRaw(string $raw): ?self
    {
        if (strlen($raw) !== 96) {
            return null;
        }

        return new self(substr($raw, 0, 64), substr($raw, 64, 32));
    }

    /** The 96-byte raw file body: secret ‖ public. */
    public function raw(): string
    {
        return $this->secret . $this->public;
    }

    public function algorithm(): string
    {
        return 'ssh-ed25519';
    }

    /** The "ssh-ed25519" public key blob (string algo ‖ string key). */
    public function publicBlob(): string
    {
        return (new Buf())->string('ssh-ed25519')->string($this->public)->get();
    }

    /** Sign $data; returns the "ssh-ed25519" signature blob (string algo ‖ string sig). */
    public function sign(string $data): string
    {
        $sig = sodium_crypto_sign_detached($data, $this->secret);

        return (new Buf())->string('ssh-ed25519')->string($sig)->get();
    }
}
