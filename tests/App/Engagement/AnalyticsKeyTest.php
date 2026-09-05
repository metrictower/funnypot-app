<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Engagement;

use Funnypot\App\Engagement\AnalyticsKey;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use PHPUnit\Framework\TestCase;

/**
 * The install-local key: an explicit key is used as-is, a placeholder is refused, and without one
 * the key derives from the install identity's private analytics key — so two installs never share
 * an id space and an install with no identity key gets NO key (metrics off) rather than a shared
 * constant.
 */
final class AnalyticsKeyTest extends TestCase
{
    public function test_explicit_key_is_used_and_a_short_placeholder_is_refused(): void
    {
        $install = IdentityTestSupport::deriver()->engagementAnalyticsKey();
        self::assertNotNull(AnalyticsKey::resolve(str_repeat('x', AnalyticsKey::MIN_KEY_BYTES), $install));
        self::assertNull(AnalyticsKey::resolve('changeme', $install), 'a placeholder-length key means NO key, never a weak one');
        self::assertNull(AnalyticsKey::resolve(str_repeat('x', AnalyticsKey::MIN_KEY_BYTES - 1), $install));
    }

    public function test_from_raw_refuses_placeholder_material(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        AnalyticsKey::fromRaw('short');
    }

    public function test_derived_key_is_stable_per_install_and_differs_across_installs(): void
    {
        $a = IdentityTestSupport::deriver('a')->engagementAnalyticsKey();
        $b = IdentityTestSupport::deriver('b')->engagementAnalyticsKey();

        $k1 = AnalyticsKey::resolve('', $a);
        $k2 = AnalyticsKey::resolve('', $a);
        $k3 = AnalyticsKey::resolve('', $b);
        self::assertNotNull($k1);
        self::assertNotNull($k3);

        self::assertSame($k1->id('d', 'v'), $k2->id('d', 'v'), 'same install ⇒ same ids across processes');
        self::assertNotSame($k1->id('d', 'v'), $k3->id('d', 'v'), 'another install ⇒ different ids (cross-master variance)');
        // The stored id is a sub-key derivation, never the raw install key used directly.
        self::assertNotSame(substr(hash_hmac('sha256', 'v1|d|v', $a), 0, 32), $k1->id('d', 'v'));
    }

    public function test_missing_or_short_install_key_yields_no_key(): void
    {
        self::assertNull(AnalyticsKey::resolve('', null), 'no install identity ⇒ metrics off, never a shared constant');
        self::assertNull(AnalyticsKey::resolve('', 'too-short'));
    }

    public function test_ids_are_128_bit_versioned_and_domain_separated(): void
    {
        $k = AnalyticsKey::fromRaw(str_repeat('k', 32));
        $id = $k->id('episode-evidence', 'network|203.0.113.9|library');

        self::assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $id);
        self::assertSame($id, $k->id('episode-evidence', 'network|203.0.113.9|library'), 'deterministic');
        self::assertNotSame($id, $k->id('artifact', 'network|203.0.113.9|library'), 'same value, other domain ⇒ other id');
        self::assertStringNotContainsString('203.0.113.9', $id);
        // Versioned: the MAC input carries the version, so it is not a bare HMAC of the value.
        self::assertNotSame(substr(hash_hmac('sha256', 'network|203.0.113.9|library', str_repeat('k', 32)), 0, 32), $id);
        self::assertSame(64, strlen($k->mac('d', 'p')), 'full MACs keep all 256 bits');
    }
}
