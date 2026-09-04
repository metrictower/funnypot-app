<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Engagement;

use Funnypot\App\Engagement\AnalyticsKey;
use Funnypot\App\Engagement\SignedHandle;
use PHPUnit\Framework\TestCase;

/**
 * The authenticated handle envelope: a valid handle round-trips to its 128-bit instance id; a forged,
 * expired, future-issued, oversized, malformed, re-versioned, wrong-domain or wrong-key handle is
 * rejected, and rejection is a pure null (no throw, no state).
 */
final class SignedHandleTest extends TestCase
{
    private const NOW = 1_700_000_000;

    private function codec(?string $material = null): SignedHandle
    {
        return new SignedHandle(AnalyticsKey::fromRaw($material ?? str_repeat('k', 32)));
    }

    public function test_valid_handle_round_trips_to_a_128_bit_instance_id(): void
    {
        $c = $this->codec();
        $h = $c->mint(SignedHandle::DOMAIN_EPISODE, self::NOW, 600);

        $id = $c->verify(SignedHandle::DOMAIN_EPISODE, $h, self::NOW + 10);
        self::assertNotNull($id);
        self::assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $id, '32 hex = 128 bits of randomness');
        self::assertLessThanOrEqual(SignedHandle::MAX_LEN, strlen($h));
        self::assertSame($id, $c->verify(SignedHandle::DOMAIN_EPISODE, $h, self::NOW + 10), 'verify is deterministic and side-effect free');
    }

    public function test_two_mints_never_share_an_instance_id(): void
    {
        $c = $this->codec();
        $a = $c->verify(SignedHandle::DOMAIN_EPISODE, $c->mint(SignedHandle::DOMAIN_EPISODE, self::NOW, 60), self::NOW);
        $b = $c->verify(SignedHandle::DOMAIN_EPISODE, $c->mint(SignedHandle::DOMAIN_EPISODE, self::NOW, 60), self::NOW);
        self::assertNotSame($a, $b);
    }

    public function test_expired_and_future_issued_handles_are_rejected(): void
    {
        $c = $this->codec();
        $h = $c->mint(SignedHandle::DOMAIN_EPISODE, self::NOW, 60);

        self::assertNull($c->verify(SignedHandle::DOMAIN_EPISODE, $h, self::NOW + 60), 'expiry is exclusive');
        self::assertNull($c->verify(SignedHandle::DOMAIN_EPISODE, $h, self::NOW + 3600));
        self::assertNull($c->verify(SignedHandle::DOMAIN_EPISODE, $h, self::NOW - 1), 'a handle from the future is invalid (clock rollback never revives)');
        self::assertNotNull($c->verify(SignedHandle::DOMAIN_EPISODE, $h, self::NOW + 59));
    }

    public function test_forged_mac_is_rejected(): void
    {
        $c = $this->codec();
        $h = $c->mint(SignedHandle::DOMAIN_EPISODE, self::NOW, 600);
        $last = substr($h, -1);
        $forged = substr($h, 0, -1) . ($last === 'a' ? 'b' : 'a');

        self::assertNull($c->verify(SignedHandle::DOMAIN_EPISODE, $forged, self::NOW));
    }

    public function test_tampered_body_is_rejected(): void
    {
        $c = $this->codec();
        $h = $c->mint(SignedHandle::DOMAIN_EPISODE, self::NOW, 60);
        // Stretch the expiry by editing the body; the MAC no longer covers it.
        $parts = explode('.', $h);
        $parts[2] = (string) ((int) $parts[2] + 86400);
        self::assertNull($c->verify(SignedHandle::DOMAIN_EPISODE, implode('.', $parts), self::NOW + 3600));
    }

    public function test_oversized_malformed_and_reversioned_input_is_rejected_without_throwing(): void
    {
        $c = $this->codec();
        self::assertNull($c->verify(SignedHandle::DOMAIN_EPISODE, '', self::NOW));
        self::assertNull($c->verify(SignedHandle::DOMAIN_EPISODE, str_repeat('1.2.3.', 100), self::NOW), 'oversized: rejected before parsing');
        self::assertNull($c->verify(SignedHandle::DOMAIN_EPISODE, 'not-a-handle', self::NOW));
        self::assertNull($c->verify(SignedHandle::DOMAIN_EPISODE, "1.1.2.\x00" . str_repeat('a', 31) . '.' . str_repeat('b', 64), self::NOW));

        // A correctly MAC'd body under a version the codec does not speak.
        $body = '2.' . self::NOW . '.' . (self::NOW + 60) . '.' . str_repeat('c', 32);
        $h = $body . '.' . AnalyticsKey::fromRaw(str_repeat('k', 32))->mac(SignedHandle::DOMAIN_EPISODE, $body);
        self::assertNull($c->verify(SignedHandle::DOMAIN_EPISODE, $h, self::NOW));
    }

    public function test_domain_separation_an_artifact_handle_is_not_an_episode_handle(): void
    {
        $c = $this->codec();
        $artifact = $c->mint(SignedHandle::DOMAIN_ARTIFACT, self::NOW, 600);

        self::assertNotNull($c->verify(SignedHandle::DOMAIN_ARTIFACT, $artifact, self::NOW));
        self::assertNull($c->verify(SignedHandle::DOMAIN_EPISODE, $artifact, self::NOW), 'the MAC is bound to its domain');
    }

    public function test_cross_secret_variance_a_handle_from_another_install_is_rejected(): void
    {
        $a = $this->codec(str_repeat('a', 32));
        $b = $this->codec(str_repeat('b', 32));
        $h = $a->mint(SignedHandle::DOMAIN_EPISODE, self::NOW, 600);

        self::assertNotNull($a->verify(SignedHandle::DOMAIN_EPISODE, $h, self::NOW));
        self::assertNull($b->verify(SignedHandle::DOMAIN_EPISODE, $h, self::NOW));
    }
}
