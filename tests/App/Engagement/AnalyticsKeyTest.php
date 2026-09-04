<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Engagement;

use Funnypot\App\Engagement\AnalyticsKey;
use PHPUnit\Framework\TestCase;

/**
 * The install-local key: an explicit key is used as-is, a placeholder is refused, and without one
 * the key derives from the persisted host secret — so two installs never share an id space and an
 * install that cannot persist a secret gets NO key (metrics off) rather than a shared constant.
 */
final class AnalyticsKeyTest extends TestCase
{
    /** @var string[] */
    private array $dirs = [];

    protected function tearDown(): void
    {
        foreach ($this->dirs as $d) {
            @unlink($d . '/fs_secret');
            @rmdir($d);
            @unlink($d);
        }
        $this->dirs = [];
    }

    private function dir(): string
    {
        $d = sys_get_temp_dir() . '/fp_akey_' . bin2hex(random_bytes(6));
        mkdir($d, 0700);
        $this->dirs[] = $d;

        return $d;
    }

    public function test_explicit_key_is_used_and_a_short_placeholder_is_refused(): void
    {
        self::assertNotNull(AnalyticsKey::resolve(str_repeat('x', AnalyticsKey::MIN_KEY_BYTES), $this->dir()));
        self::assertNull(AnalyticsKey::resolve('changeme', $this->dir()), 'a placeholder-length key means NO key, never a weak one');
        self::assertNull(AnalyticsKey::resolve(str_repeat('x', AnalyticsKey::MIN_KEY_BYTES - 1), $this->dir()));
    }

    public function test_from_raw_refuses_placeholder_material(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        AnalyticsKey::fromRaw('short');
    }

    public function test_derived_key_is_stable_per_install_and_differs_across_installs(): void
    {
        if (getenv('FUNNYPOT_FS_SECRET') !== false && getenv('FUNNYPOT_FS_SECRET') !== '') {
            self::markTestSkipped('FUNNYPOT_FS_SECRET is set in this environment; per-directory derivation is not observable');
        }
        $a = $this->dir();
        $b = $this->dir();

        $k1 = AnalyticsKey::resolve('', $a);
        $k2 = AnalyticsKey::resolve('', $a);
        $k3 = AnalyticsKey::resolve('', $b);
        self::assertNotNull($k1);
        self::assertNotNull($k3);
        self::assertFileExists($a . '/fs_secret', 'the host secret was persisted');

        self::assertSame($k1->id('d', 'v'), $k2->id('d', 'v'), 'same install ⇒ same ids across processes');
        self::assertNotSame($k1->id('d', 'v'), $k3->id('d', 'v'), 'another install ⇒ different ids (cross-secret variance)');
    }

    public function test_unpersistable_host_secret_yields_no_key(): void
    {
        if (getenv('FUNNYPOT_FS_SECRET') !== false && getenv('FUNNYPOT_FS_SECRET') !== '') {
            self::markTestSkipped('FUNNYPOT_FS_SECRET is set in this environment');
        }
        $blocker = sys_get_temp_dir() . '/fp_akey_block_' . bin2hex(random_bytes(6));
        file_put_contents($blocker, 'x');
        $this->dirs[] = $blocker;

        // A storage dir that cannot exist (its parent is a file) — HostSecret degrades to a per-process
        // value, which would give every worker its own id space; that must read as "no key".
        self::assertNull(@AnalyticsKey::resolve('', $blocker . '/nope'));
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
