<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

use InvalidArgumentException;

/**
 * The per-purpose keys of the token-mint account surface, all derived from the one `token-mint/v1`
 * identity key. Each purpose gets its own HMAC key so a value minted for one job (a session cookie)
 * can never verify as another (a CSRF token). There is no derive-by-label method on purpose.
 *
 * Also owns the two keyed hashes the store relies on: the per-source reference (never the raw IP)
 * and the one-way hash every stored secret is kept as (never the raw secret).
 */
final class MintKeys
{
    public const PURPOSES = ['store', 'session', 'csrf', 'token', 'jwt', 'totp', 'password', 'pick'];

    /** @var array<string,string> */
    private array $keys = [];

    public function __construct(string $root)
    {
        if (strlen($root) < 32) {
            throw new InvalidArgumentException('token-mint key must be 32 bytes');
        }
        foreach (self::PURPOSES as $p) {
            $this->keys[$p] = hash_hmac('sha256', 'funnypot-app/token-mint/' . $p . '/v1', $root, true);
        }
    }

    public function key(string $purpose): string
    {
        if (!isset($this->keys[$purpose])) {
            throw new InvalidArgumentException('unknown key purpose');
        }

        return $this->keys[$purpose];
    }

    /** The 16-byte source reference for an IP. Rows are keyed by it; the IP itself is never stored. */
    public function kref(string $ip): string
    {
        return substr(hash_hmac('sha256', "source\0" . $ip, $this->keys['store'], true), 0, 16);
    }

    /** The stored form of a secret (a code, a refresh token, a client secret, a recovery code). */
    public function secretHash(string $secret): string
    {
        return substr(hash_hmac('sha256', "secret\0" . $secret, $this->keys['store']), 0, 40);
    }

    /** A short deterministic hex id under the store key, for public ids and nonces. */
    public function hexId(string $label, int $hexChars): string
    {
        return substr(hash_hmac('sha256', "id\0" . $label, $this->keys['store']), 0, $hexChars);
    }
}
