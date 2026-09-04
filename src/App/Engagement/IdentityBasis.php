<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement;

/**
 * The closed set of evidence an episode may be keyed on, in precedence order. Identity here is
 * evidence, never attribution: an episode is a local pseudonymous grouping of requests, not a claim
 * that one IP, cookie or handle is one person.
 *
 *  - EPISODE_HANDLE   a Funnypot-issued, MAC'd, expiring instance handle ({@see SignedHandle}) — the
 *                     only HIGH-confidence basis, because only Funnypot can mint one.
 *  - COOKIE           an integrity-protected, versioned, expiring first-party decoy cookie — MEDIUM.
 *                     Defined so the schema is stable; no cookie meets the bar yet, so the resolver
 *                     never produces it today.
 *  - NETWORK_FALLBACK a keyed digest of peer address + coarse user-agent class — always LOW: NAT and
 *                     shared proxies merge unrelated clients, address/UA rotation splits one client.
 */
final class IdentityBasis
{
    public const EPISODE_HANDLE = 'episode_handle';
    public const COOKIE = 'cookie';
    public const NETWORK_FALLBACK = 'network_fallback';

    /** @return list<string> */
    public static function all(): array
    {
        return [self::EPISODE_HANDLE, self::COOKIE, self::NETWORK_FALLBACK];
    }

    public static function isValid(string $basis): bool
    {
        return in_array($basis, self::all(), true);
    }

    /** The confidence a basis can ever carry — fixed, never raised by other evidence. */
    public static function confidenceOf(string $basis): string
    {
        switch ($basis) {
            case self::EPISODE_HANDLE:
                return Confidence::HIGH;
            case self::COOKIE:
                return Confidence::MEDIUM;
            case self::NETWORK_FALLBACK:
            default:
                return Confidence::LOW;
        }
    }
}
