<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement;

/**
 * Turns raw request evidence into an {@see EpisodeKey}, strongest valid basis first:
 *
 *   1. a verified episode handle  → HIGH, keyed on the handle's random instance id;
 *   2. (cookie — MEDIUM — reserved: no first-party cookie is integrity-protected, versioned AND
 *      expiring yet, so this tier is never produced);
 *   3. network fallback           → LOW, keyed on peer address + coarse user-agent class.
 *
 * An invalid handle is simply skipped — it never becomes a key, never raises confidence, and the
 * request still lands in the network tier, so adding junk cannot switch metrics off. Every digest
 * is an install-local HMAC ({@see AnalyticsKey::id()}) and carries the resolver version, so a change
 * in how evidence is reduced starts fresh episodes instead of silently merging with old ones.
 *
 * Artifact handles are verified the same way but yield only an `artifact_id`: proof that Funnypot
 * issued that object, linking issue/fetch/reuse events across episodes. It is never an identity
 * basis — a copied artifact says nothing about who is holding it.
 */
final class EpisodeResolver
{
    public const VERSION = 'r1';

    private const DOMAIN_EVIDENCE = 'episode-evidence';
    private const DOMAIN_ARTIFACT = 'artifact';

    public function __construct(private AnalyticsKey $key, private SignedHandle $handles)
    {
    }

    public function resolve(?string $episodeHandle, string $peerIp, string $userAgent, int $now): EpisodeKey
    {
        if ($episodeHandle !== null) {
            $instance = $this->handles->verify(SignedHandle::DOMAIN_EPISODE, $episodeHandle, $now);
            if ($instance !== null) {
                return new EpisodeKey(
                    IdentityBasis::EPISODE_HANDLE,
                    Confidence::HIGH,
                    $this->key->id(self::DOMAIN_EVIDENCE, 'handle|' . $instance)
                );
            }
        }

        return new EpisodeKey(
            IdentityBasis::NETWORK_FALLBACK,
            Confidence::LOW,
            $this->key->id(self::DOMAIN_EVIDENCE, 'network|' . self::VERSION . '|' . $peerIp . '|' . self::userAgentClass($userAgent))
        );
    }

    /** The stored artifact id for a verified artifact handle, or null (no id, no identity effect). */
    public function artifactId(string $artifactHandle, int $now): ?string
    {
        $instance = $this->handles->verify(SignedHandle::DOMAIN_ARTIFACT, $artifactHandle, $now);

        return $instance === null ? null : $this->key->id(self::DOMAIN_ARTIFACT, $instance);
    }

    /**
     * A handful of coarse client classes. Deliberately not the raw UA (even keyed): a per-UA key
     * would split one scanner across every UA it rotates, and the class is all the grouping needs.
     */
    public static function userAgentClass(string $userAgent): string
    {
        $ua = strtolower(trim($userAgent));
        if ($ua === '') {
            return 'empty';
        }
        if (str_contains($ua, 'mozilla/')) {
            return 'browser';
        }
        foreach (['curl', 'wget', 'python', 'go-http', 'node', 'java', 'libwww', 'okhttp'] as $lib) {
            if (str_contains($ua, $lib)) {
                return 'library';
            }
        }

        return 'other';
    }
}
