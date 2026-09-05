<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement;

/**
 * The install-local key every stored engagement identifier is derived under. Nothing in the
 * engagement database is a raw value: episode ids, evidence digests and artifact ids are all
 * versioned, domain-separated HMAC-SHA256 outputs of this key, truncated to no less than 128 bits,
 * so two deployments never share an identifier and no stored id can be reversed to an IP, handle or
 * cookie.
 *
 * Resolution: an explicit FUNNYPOT_ANALYTICS_KEY wins; otherwise a sub-key is derived from the
 * install identity's private `engagement-analytics/v1` key (HttpIdentity::engagementAnalyticsKey()),
 * which every prepared install has. There is deliberately NO fleet-constant fallback: a short/
 * placeholder explicit key, or no install key at all, resolves to null and the caller keeps
 * engagement metrics OFF with a health warning. The public persona seed is never used.
 */
final class AnalyticsKey
{
    public const VERSION = 'v1';

    /** A shorter explicit key is treated as a placeholder, not a key. */
    public const MIN_KEY_BYTES = 16;

    /** Hex chars kept from each HMAC — 128 bits, the floor for every stored id. */
    public const ID_HEX = 32;

    private const DERIVE_LABEL = 'funnypot-engagement-key';

    private function __construct(private string $key)
    {
    }

    /**
     * Null when no usable install-local key material exists — metrics must then stay off.
     *
     * @param string|null $installKey the 32-byte private analytics key from the install identity
     */
    public static function resolve(string $explicit, ?string $installKey): ?self
    {
        if ($explicit !== '') {
            return strlen($explicit) >= self::MIN_KEY_BYTES ? new self($explicit) : null;
        }
        if ($installKey === null || strlen($installKey) < 32) {
            return null;
        }

        return new self(hash_hmac('sha256', self::DERIVE_LABEL . '|' . self::VERSION, $installKey, true));
    }

    /** A key from raw material (tests and the test-support namespace); same placeholder floor. */
    public static function fromRaw(string $material): self
    {
        if (strlen($material) < self::MIN_KEY_BYTES) {
            throw new \InvalidArgumentException('analytics key material too short');
        }

        return new self($material);
    }

    /**
     * A stored identifier for $value in $domain: versioned + domain-separated so the same value in
     * two domains (an evidence digest vs an artifact id) never collides, 128 bits kept.
     */
    public function id(string $domain, string $value): string
    {
        return substr($this->mac($domain, $value), 0, self::ID_HEX);
    }

    /** The full 256-bit hex MAC for $payload in $domain — what {@see SignedHandle} verifies. */
    public function mac(string $domain, string $payload): string
    {
        return hash_hmac('sha256', self::VERSION . '|' . $domain . '|' . $payload, $this->key);
    }
}
