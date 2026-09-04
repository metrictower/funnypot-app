<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Engagement;

use Funnypot\App\Engagement\AnalyticsKey;
use Funnypot\App\Engagement\Confidence;
use Funnypot\App\Engagement\EpisodeResolver;
use Funnypot\App\Engagement\IdentityBasis;
use Funnypot\App\Engagement\SignedHandle;
use PHPUnit\Framework\TestCase;

/**
 * Evidence precedence and its safety properties: only a VALID handle is high confidence; a forged or
 * expired one is ignored (the request keys exactly as it would with no handle at all — no
 * attacker-keyed allocation, no confidence gain); network fallback is always low and coarse; an
 * artifact handle links but never identifies; and no digest carries or correlates raw evidence.
 */
final class EpisodeResolverTest extends TestCase
{
    private const NOW = 1_700_000_000;
    private const IP = '203.0.113.9';

    private function resolver(?string $material = null): EpisodeResolver
    {
        $key = AnalyticsKey::fromRaw($material ?? str_repeat('k', 32));

        return new EpisodeResolver($key, new SignedHandle($key));
    }

    private function codec(?string $material = null): SignedHandle
    {
        return new SignedHandle(AnalyticsKey::fromRaw($material ?? str_repeat('k', 32)));
    }

    public function test_no_handle_is_network_fallback_low_confidence_and_deterministic(): void
    {
        $r = $this->resolver();
        $a = $r->resolve(null, self::IP, 'curl/8.0', self::NOW);
        $b = $r->resolve(null, self::IP, 'curl/8.0', self::NOW + 5);

        self::assertSame(IdentityBasis::NETWORK_FALLBACK, $a->basis);
        self::assertSame(Confidence::LOW, $a->confidence);
        self::assertSame($a->digest, $b->digest, 'same peer + UA class ⇒ same key');
        self::assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $a->digest);
        self::assertStringNotContainsString(self::IP, $a->digest);
    }

    public function test_forged_handle_keys_exactly_like_no_handle_and_gains_nothing(): void
    {
        $r = $this->resolver();
        $plain = $r->resolve(null, self::IP, 'curl/8.0', self::NOW);
        $forged = '1.' . self::NOW . '.' . (self::NOW + 600) . '.' . str_repeat('a', 32) . '.' . str_repeat('b', 64);

        $k = $r->resolve($forged, self::IP, 'curl/8.0', self::NOW);
        self::assertSame(IdentityBasis::NETWORK_FALLBACK, $k->basis, 'a forged handle is ignored, not trusted');
        self::assertSame(Confidence::LOW, $k->confidence);
        self::assertSame($plain->digest, $k->digest, 'no allocation keyed by the supplied bytes — the safe lower basis');

        // Two different forgeries from the same peer still land on the SAME low-basis key.
        $forged2 = '1.' . self::NOW . '.' . (self::NOW + 600) . '.' . str_repeat('c', 32) . '.' . str_repeat('d', 64);
        self::assertSame($plain->digest, $r->resolve($forged2, self::IP, 'curl/8.0', self::NOW)->digest);
    }

    public function test_valid_handle_is_high_confidence_and_expired_falls_back_low(): void
    {
        $r = $this->resolver();
        $h = $this->codec()->mint(SignedHandle::DOMAIN_EPISODE, self::NOW, 60);
        $plain = $r->resolve(null, self::IP, 'curl/8.0', self::NOW);

        $k = $r->resolve($h, self::IP, 'curl/8.0', self::NOW + 1);
        self::assertSame(IdentityBasis::EPISODE_HANDLE, $k->basis);
        self::assertSame(Confidence::HIGH, $k->confidence);
        self::assertNotSame($plain->digest, $k->digest);
        self::assertSame($k->digest, $r->resolve($h, '198.51.100.1', 'Mozilla/5.0', self::NOW + 2)->digest, 'the handle, not the network, is the key');

        $late = $r->resolve($h, self::IP, 'curl/8.0', self::NOW + 60);
        self::assertSame(IdentityBasis::NETWORK_FALLBACK, $late->basis, 'expired ⇒ ignored ⇒ network tier');
        self::assertSame($plain->digest, $late->digest);
    }

    public function test_network_key_is_coarse_in_user_agent(): void
    {
        $r = $this->resolver();
        $curl = $r->resolve(null, self::IP, 'curl/8.0', self::NOW)->digest;
        $wget = $r->resolve(null, self::IP, 'Wget/1.21', self::NOW)->digest;
        $browser = $r->resolve(null, self::IP, 'Mozilla/5.0 (X11; Linux) Chrome/120', self::NOW)->digest;
        $empty = $r->resolve(null, self::IP, '', self::NOW)->digest;

        self::assertSame($curl, $wget, 'two HTTP libraries share one class — a rotated library UA does not split the key');
        self::assertNotSame($curl, $browser);
        self::assertNotSame($curl, $empty);
        self::assertNotSame($curl, $r->resolve(null, '203.0.113.10', 'curl/8.0', self::NOW)->digest, 'another peer is another key');
        self::assertSame('library', EpisodeResolver::userAgentClass('python-requests/2.31'));
        self::assertSame('other', EpisodeResolver::userAgentClass('sqlmap/1.7'));
    }

    public function test_artifact_handle_yields_an_artifact_id_but_never_identity(): void
    {
        $r = $this->resolver();
        $artifact = $this->codec()->mint(SignedHandle::DOMAIN_ARTIFACT, self::NOW, 3600);
        $plain = $r->resolve(null, self::IP, 'curl/8.0', self::NOW);

        $id = $r->artifactId($artifact, self::NOW);
        self::assertNotNull($id);
        self::assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $id);
        self::assertSame($id, $r->artifactId($artifact, self::NOW + 100), 'the same issued object links across requests');
        self::assertNull($r->artifactId($artifact, self::NOW + 3600), 'expired ⇒ no id');
        self::assertNull($r->artifactId('1.1.2.' . str_repeat('a', 32) . '.' . str_repeat('b', 64), self::NOW), 'forged ⇒ no id');

        // Presenting the artifact handle AS an episode handle promotes nothing.
        $asEpisode = $r->resolve($artifact, self::IP, 'curl/8.0', self::NOW);
        self::assertSame(IdentityBasis::NETWORK_FALLBACK, $asEpisode->basis);
        self::assertSame($plain->digest, $asEpisode->digest);
        self::assertNotSame($id, $asEpisode->digest, 'artifact ids and evidence digests live in different domains');
    }

    public function test_cross_secret_variance_same_evidence_two_installs_two_digests(): void
    {
        $a = $this->resolver(str_repeat('a', 32))->resolve(null, self::IP, 'curl/8.0', self::NOW)->digest;
        $b = $this->resolver(str_repeat('b', 32))->resolve(null, self::IP, 'curl/8.0', self::NOW)->digest;

        self::assertNotSame($a, $b, 'no identifier correlates two deployments');
    }
}
