<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement;

/**
 * The authenticated, expiring handle envelope: `1.<issued>.<expires>.<128-bit random hex>.<mac>`,
 * where the MAC is the install-local HMAC over the whole body under a per-purpose domain. An
 * episode handle and an artifact handle share the codec but not the domain, so one can never be
 * presented as the other.
 *
 * verify() is side-effect free: it allocates nothing, touches no store, and rejects before any
 * parsing when the input is oversized. A forged, expired, wrong-version or wrong-domain handle
 * yields null and the caller falls to the next evidence tier — junk can never disable metrics, key
 * a row by attacker-chosen bytes, or gain confidence. Equal-length MACs compare in constant time.
 */
final class SignedHandle
{
    public const DOMAIN_EPISODE = 'episode-handle';
    public const DOMAIN_ARTIFACT = 'artifact-handle';

    public const VERSION = '1';

    /** Longest well-formed handle is 121 chars; anything past this is rejected unparsed. */
    public const MAX_LEN = 160;

    private const RANDOM_BYTES = 16;

    public function __construct(private AnalyticsKey $key)
    {
    }

    /** Mint a handle valid from $now for $ttlSeconds. */
    public function mint(string $domain, int $now, int $ttlSeconds): string
    {
        $body = self::VERSION . '.' . $now . '.' . ($now + max(1, $ttlSeconds)) . '.' . bin2hex(random_bytes(self::RANDOM_BYTES));

        return $body . '.' . $this->key->mac($domain, $body);
    }

    /** The handle's random instance id (32 hex) when valid for $domain at $now, else null. */
    public function verify(string $domain, string $handle, int $now): ?string
    {
        if ($handle === '' || strlen($handle) > self::MAX_LEN) {
            return null;
        }
        if (preg_match('/^(\d{1,3})\.(\d{1,12})\.(\d{1,12})\.([a-f0-9]{32})\.([a-f0-9]{64})$/', $handle, $m) !== 1) {
            return null;
        }
        if ($m[1] !== self::VERSION) {
            return null;
        }
        $body = $m[1] . '.' . $m[2] . '.' . $m[3] . '.' . $m[4];
        if (!hash_equals($this->key->mac($domain, $body), $m[5])) {
            return null;
        }
        $issued = (int) $m[2];
        $expires = (int) $m[3];
        // A handle from the future is as invalid as an expired one: clock rollback must never revive
        // or lengthen anything.
        if ($now < $issued || $now >= $expires) {
            return null;
        }

        return $m[4];
    }
}
