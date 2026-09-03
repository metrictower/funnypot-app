<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Config;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Config\ConfigStore;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * FP-0250 §2.3/§4.2 — the core fix: env is an exposure CEILING a stored override may never loosen. A
 * hijacked/CSRF'd admin session must not be able to unmask or reconfigure the honeypot with one
 * config-set. Covers both directions (write-time rejection AND the read-time clamp of a row that was
 * legitimate when written but has since gone stale-unsafe because the operator tightened env), and the
 * fail-closed-to-safest baseline canonicalization for a garbage env value.
 */
final class ConfigStoreProtectedTest extends TestCase
{
    /** @var string[] */
    private array $tmpDirs = [];

    private const ENV_KEYS = ['FUNNYPOT_PUBLIC_VIEW', 'FUNNYPOT_MODE', 'FUNNYPOT_HIDE_MAIN'];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        foreach (self::ENV_KEYS as $k) {
            putenv($k);
        }
    }

    protected function tearDown(): void
    {
        foreach (self::ENV_KEYS as $k) {
            putenv($k);
        }
        foreach ($this->tmpDirs as $d) {
            foreach (@scandir($d) ?: [] as $f) {
                if ($f !== '.' && $f !== '..') {
                    @unlink($d . '/' . $f);
                }
            }
            @rmdir($d);
        }
        $this->tmpDirs = [];
        if (function_exists('apcu_clear_cache')) {
            apcu_clear_cache();
        }
    }

    private function dbPath(): string
    {
        $dir = sys_get_temp_dir() . '/fp_cfgprot_' . bin2hex(random_bytes(6));
        @mkdir($dir, 0777, true);
        $this->tmpDirs[] = $dir;

        return $dir . '/config.sqlite';
    }

    // --- the ticket's named acceptance test -------------------------------------------------------

    /** Covers both env states named in the plan: env unset (registry default 'none') and env explicitly 'none'. */
    public function test_stored_override_cannot_flip_public_view_none_to_full_below_env_floor(): void
    {
        foreach ([null, 'none'] as $env) {
            $store = new ConfigStore($this->dbPath());
            if ($env !== null) {
                putenv('FUNNYPOT_PUBLIC_VIEW=' . $env);
            }
            $threw = null;
            try {
                $store->set('dashboard.public_view', 'full', 'attacker', '203.0.113.9');
            } catch (RuntimeException $e) {
                $threw = $e;
            }
            self::assertNotNull($threw, 'set(...,full,...) must throw when env=' . var_export($env, true));
            self::assertStringContainsString('protected', $threw->getMessage());
            self::assertSame([], $store->stored(), 'no config override may be written');
            self::assertSame([], $store->audits(5), 'no config audit row');
            self::assertSame('none', $store->snapshot()['dashboard.public_view']);
            putenv('FUNNYPOT_PUBLIC_VIEW');
        }
    }

    public function test_set_allows_tightening_below_a_loose_env_floor(): void
    {
        putenv('FUNNYPOT_PUBLIC_VIEW=full');
        $store = new ConfigStore($this->dbPath());

        $store->set('dashboard.public_view', 'minimal', 'admin', '');
        self::assertSame('minimal', $store->snapshot()['dashboard.public_view']);

        $store->set('dashboard.public_view', 'none', 'admin', '');
        self::assertSame('none', $store->snapshot()['dashboard.public_view']);

        // Tightening all the way back to 'full' (== the ceiling itself) also succeeds — equal is OK.
        $store->set('dashboard.public_view', 'full', 'admin', '');
        self::assertSame('full', $store->snapshot()['dashboard.public_view']);
    }

    public function test_mode_cannot_be_loosened_from_stealth_to_public(): void
    {
        putenv('FUNNYPOT_MODE=stealth');
        $store = new ConfigStore($this->dbPath());
        try {
            $store->set('mode', 'public', 'attacker', '203.0.113.9');
            self::fail('expected a RuntimeException');
        } catch (RuntimeException $e) {
            self::assertStringContainsString('protected', $e->getMessage());
        }
        self::assertSame('stealth', $store->snapshot()['mode']);
        putenv('FUNNYPOT_MODE');

        putenv('FUNNYPOT_MODE=public');
        $store2 = new ConfigStore($this->dbPath());
        $store2->set('mode', 'stealth', 'admin', ''); // tighten: must succeed
        self::assertSame('stealth', $store2->snapshot()['mode']);
    }

    public function test_protected_path_knobs_reject_any_stored_override(): void
    {
        $store = new ConfigStore($this->dbPath());
        foreach (['dashboard_path' => '/moved/', 'funnypot_path' => 'moved'] as $key => $value) {
            try {
                $store->set($key, $value, 'attacker', '203.0.113.9');
                self::fail("expected {$key} set to throw");
            } catch (RuntimeException $e) {
                self::assertStringContainsString('protected', $e->getMessage());
            }
        }
        self::assertSame([], $store->stored());
        // reset() on an absent key stays a no-op, never throws.
        $store->reset('dashboard_path', 'admin', '');
        $store->reset('funnypot_path', 'admin', '');
        self::assertSame([], $store->stored());
    }

    public function test_read_clamps_a_stale_override_that_env_has_since_tightened(): void
    {
        $db = $this->dbPath();
        putenv('FUNNYPOT_PUBLIC_VIEW=full');
        $store = new ConfigStore($db);
        $store->set('dashboard.public_view', 'full', 'admin', ''); // legitimate under the loose floor

        // Operator tightens env (a redeploy) without touching the stored row.
        putenv('FUNNYPOT_PUBLIC_VIEW=none');
        self::assertSame('none', $store->rawForEnv('FUNNYPOT_PUBLIC_VIEW'), 'rawForEnv clamps the now-unsafe stored full back to the ceiling');
        self::assertSame('none', $store->get('dashboard.public_view', 'FUNNYPOT_PUBLIC_VIEW', 'none'));
        self::assertSame('none', $store->snapshot()['dashboard.public_view']);

        // Flip env back to the loose floor: the SAME stored row resolves 'full' again (the clamp is
        // resolution-time, non-destructive — the row itself was never touched or rejected).
        putenv('FUNNYPOT_PUBLIC_VIEW=full');
        self::assertSame('full', $store->snapshot()['dashboard.public_view']);
        self::assertSame('full', $store->stored()['dashboard.public_view'] ?? null, 'the underlying row itself is untouched by the clamp');
    }

    public function test_clamp_is_not_baked_into_the_apcu_snapshot(): void
    {
        if (!function_exists('apcu_fetch')) {
            self::markTestSkipped('APCu not loaded on this box — nothing to prove about the APCu layer here');
        }
        $db = $this->dbPath();
        putenv('FUNNYPOT_PUBLIC_VIEW=full');
        $store = new ConfigStore($db);
        $store->set('dashboard.public_view', 'full', 'admin', '');
        self::assertSame('full', $store->snapshot()['dashboard.public_view']); // caches the raw override at this generation

        // Tighten env WITHOUT a generation bump (no store write) — a second worker sharing the same
        // APCu segment must still clamp on its next resolve, proving the clamp runs on every call
        // rather than being frozen into the cached snapshot at cache-build time.
        putenv('FUNNYPOT_PUBLIC_VIEW=none');
        self::assertSame('none', $store->snapshot()['dashboard.public_view'], 'clamp applies even against a cached (unchanged-generation) raw override');
    }

    public function test_baseline_is_canonicalized_and_garbage_env_fails_to_the_safest_value(): void
    {
        // (a) bool env spellings: FUNNYPOT_HIDE_MAIN=yes -> ceiling coerces to canonical '1'.
        putenv('FUNNYPOT_HIDE_MAIN=yes');
        $store = new ConfigStore($this->dbPath());
        try {
            $store->set('hide_main_page', '0', 'attacker', '203.0.113.9'); // would loosen (visible < hidden)
            self::fail('expected a RuntimeException');
        } catch (RuntimeException $e) {
            self::assertStringContainsString('protected', $e->getMessage());
        }
        $store->set('hide_main_page', 'on', 'admin', ''); // coerces to the same baseline '1' — allowed
        self::assertSame('1', $store->snapshot()['hide_main_page']);
        putenv('FUNNYPOT_HIDE_MAIN');

        // (b) garbage enum: FUNNYPOT_MODE=banana -> AppConfig::build() itself resolves 'public' for that
        // env (only the exact string 'stealth' selects stealth — the documented RUNTIME divergence), but
        // the CEILING computed here falls back to 'stealth' (the safest value), so even 'public' is
        // rejected as a stored override under a garbage env.
        putenv('FUNNYPOT_MODE=banana');
        $garbageStore = new ConfigStore($this->dbPath());
        $cfg = AppConfig::fromEnv(sys_get_temp_dir());
        self::assertSame('public', $cfg->mode, 'sanity: the documented RUNTIME divergence — garbage env runs public');
        try {
            $garbageStore->set('mode', 'public', 'attacker', '203.0.113.9');
            self::fail('expected a RuntimeException — the ceiling for a garbage env is the SAFEST value, not the runtime default');
        } catch (RuntimeException $e) {
            self::assertStringContainsString('protected', $e->getMessage());
        }
        putenv('FUNNYPOT_MODE');
    }

    public function test_end_to_end_appconfig_from_store_over_a_rejected_at_read_override(): void
    {
        $db = $this->dbPath();
        putenv('FUNNYPOT_PUBLIC_VIEW=full');
        $store = new ConfigStore($db);
        $store->set('dashboard.public_view', 'full', 'admin', '');
        putenv('FUNNYPOT_PUBLIC_VIEW=none'); // tighten after the write, like the sibling read-clamp test

        $config = AppConfig::fromStore($store, sys_get_temp_dir());
        self::assertSame('none', $config->dashboardPublicView);
    }

}
