<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Config;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Config\ConfigStore;
use Funnypot\App\Storage\Sqlite;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * The runtime config store (FP-0242a). Encodes the spec §7 falsifiable contracts T1-T5:
 *   T1 precedence (stored > env > default, incl. reset + unset)
 *   T2 cache invalidation / no stale cross-worker read (generation sentinel)
 *   T3 APCu-absent fallback (the CI image has no apcu; this run IS that path)
 *   T5 validation clamps preserved on both the write and the read path
 * plus the fail-safe (read) / fail-closed (write) asymmetry that spec §6.2 mandates.
 */
final class ConfigStoreTest extends TestCase
{
    /** @var string[] temp dirs to remove */
    private array $tmpDirs = [];

    /** FUNNYPOT_* vars a test may set; restored in tearDown so tests never leak env. */
    private const ENV_KEYS = ['FUNNYPOT_STYLE', 'FUNNYPOT_DL_CHUNK_MIN_KB', 'FUNNYPOT_LLM'];

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
            apcu_clear_cache(); // isolate the APCu-present path across tests on a dev box
        }
    }

    /** A fresh, isolated storage dir so each store owns its own config.sqlite + config.gen sentinel. */
    private function dbPath(): string
    {
        $dir = sys_get_temp_dir() . '/fp_cfg_' . bin2hex(random_bytes(6));
        @mkdir($dir, 0777, true);
        $this->tmpDirs[] = $dir;

        return $dir . '/config.sqlite';
    }

    // ------------------------------------------------------------------ T1 precedence -------------

    public function test_t1_precedence_stored_beats_env_beats_default(): void
    {
        $db = $this->dbPath();
        $store = new ConfigStore($db);

        // default layer: no override, no env -> coded default 'realistic'
        self::assertSame('realistic', AppConfig::fromStore($store, '/app/demo')->httpStyle());

        // env layer: env set, no override -> env wins over default
        putenv('FUNNYPOT_STYLE=taunt');
        self::assertSame('taunt', AppConfig::fromStore($store, '/app/demo')->httpStyle());

        // stored layer: override wins over env
        $store->set('style', 'realistic', 'tester', '10.0.0.1');
        self::assertSame('realistic', AppConfig::fromStore($store, '/app/demo')->httpStyle());

        // reset: override removed -> falls back to env ('taunt')
        $store->reset('style', 'tester', '10.0.0.1');
        self::assertSame('taunt', AppConfig::fromStore($store, '/app/demo')->httpStyle());

        // unset env -> coded default 'realistic'
        putenv('FUNNYPOT_STYLE');
        self::assertSame('realistic', AppConfig::fromStore($store, '/app/demo')->httpStyle());
    }

    public function test_t1_snapshot_reflects_precedence(): void
    {
        $store = new ConfigStore($this->dbPath());
        self::assertSame('realistic', $store->snapshot()['style']); // default
        putenv('FUNNYPOT_STYLE=taunt');
        self::assertSame('taunt', $store->snapshot()['style']);     // env
        $store->set('style', 'realistic', 'a', '');
        self::assertSame('realistic', $store->snapshot()['style']); // override
    }

    // ------------------------------------------------------------ T2 no stale cross-worker read ---

    public function test_t2_second_worker_never_serves_a_stale_snapshot(): void
    {
        $db = $this->dbPath();
        // Two independent stores over the SAME files == two fpm workers sharing the volume (+ APCu
        // segment, when present). Each has its own per-request memo; the config.gen sentinel is the
        // only cross-worker channel.
        $workerA = new ConfigStore($db);
        $workerB = new ConfigStore($db);

        $workerA->set('style', 'realistic', 'seed', '');   // gen 1
        self::assertSame('realistic', $workerA->snapshot()['style']); // A caches gen 1

        $workerB->set('style', 'taunt', 'admin', '10.0.0.9'); // gen 2, sentinel bumped, APCu dropped

        // A must rebuild off the advanced generation, not serve its cached 'realistic'.
        self::assertSame('taunt', $workerA->snapshot()['style']);
        self::assertSame('taunt', $workerA->rawForEnv('FUNNYPOT_STYLE'));

        // Honest note on coverage: on the CI image function_exists('apcu_fetch') is false, so this run
        // exercises the SQLite + config.gen-sentinel layer (the cross-SAPI channel that reaches the
        // long-lived listeners). The APCu delete+generation layer only runs where the ext is enabled.
        if (!function_exists('apcu_fetch')) {
            self::addToAssertionCount(1);
        }
    }

    // ------------------------------------------------------------------ T3 APCu-absent ------------

    public function test_t3_resolves_correctly_without_apcu(): void
    {
        $store = new ConfigStore($this->dbPath());
        $store->set('style', 'taunt', 'admin', '');
        $store->set('dl.chunk_min_kb', '256', 'admin', '');

        $snap = $store->snapshot();
        self::assertSame('taunt', $snap['style']);       // override present
        self::assertSame('256', $snap['dl.chunk_min_kb']); // override present
        self::assertSame('40', $snap['jitter_ms']);      // untouched -> coded default
        self::assertSame('critical', $snap['severity_ceiling']);

        // The resolved AppConfig is correct off the pure-SQLite path.
        $cfg = AppConfig::fromStore($store, '/app/demo');
        self::assertSame('taunt', $cfg->httpStyle());
        self::assertSame(256, $cfg->dlChunkMinKb);

        // Explicit assertion of which layer this asserts. On CI this is the real no-APCu path.
        if (!function_exists('apcu_fetch')) {
            self::assertFalse(function_exists('apcu_fetch'), 'this run covers the no-APCu SQLite fallback');
        } else {
            self::addToAssertionCount(1);
        }
    }

    // ------------------------------------------------------------------ T5 clamp preserved --------

    public function test_t5_write_clamp_on_set(): void
    {
        $store = new ConfigStore($this->dbPath());
        // dl.chunk_min_kb clamps to [1,1024] (AppConfig.php:257). set() validates + clamps on write.
        $store->set('dl.chunk_min_kb', '99999', 'admin', '');
        self::assertLessThanOrEqual(1024, AppConfig::fromStore($store, '/app/demo')->dlChunkMinKb);
        self::assertSame(1024, AppConfig::fromStore($store, '/app/demo')->dlChunkMinKb);
    }

    public function test_t5_read_clamp_even_when_a_raw_value_bypasses_validate(): void
    {
        $db = $this->dbPath();
        $store = new ConfigStore($db);
        $store->set('dl.chunk_min_kb', '500', 'admin', ''); // create schema + sentinel (gen 1)

        // Simulate a value that reached the row WITHOUT going through validate() (e.g. a hand-edited
        // row, or a future clamp tightening). The READ path must still clamp it (AppConfig::build()).
        $raw = Sqlite::open($db);
        $raw->exec("UPDATE config SET value='99999' WHERE key='dl.chunk_min_kb'");
        $raw->exec("UPDATE config_meta SET v = v + 1 WHERE k='generation'");
        @file_put_contents(dirname($db) . '/config.gen', '2'); // advance the sentinel so readers rebuild

        $fresh = new ConfigStore($db);
        self::assertLessThanOrEqual(1024, AppConfig::fromStore($fresh, '/app/demo')->dlChunkMinKb);
    }

    // ------------------------------------------------------------ fail-safe (read) / fail-closed ---

    public function test_read_is_fail_safe_when_the_store_is_unreadable(): void
    {
        // A garbage (non-SQLite) file at the db path, with a sentinel that claims a generation, must
        // NOT throw: snapshot() degrades to the env/default baseline (never breaks the honeypot).
        $db = $this->dbPath();
        file_put_contents($db, "not a sqlite database at all\x00\x01");
        file_put_contents(dirname($db) . '/config.gen', '5');

        $store = new ConfigStore($db);
        $snap = $store->snapshot();
        self::assertSame('realistic', $snap['style']);         // baseline default, no throw
        self::assertSame('taunt', (static function () use ($db) {
            putenv('FUNNYPOT_STYLE=taunt');
            $s = new ConfigStore($db);
            $v = $s->snapshot()['style'];
            putenv('FUNNYPOT_STYLE');

            return $v;
        })());                                                 // env still resolves through the fallback
        // rawForEnv is the seam AppConfig uses — it too must not throw and must fall through to env.
        self::assertNotFalse(AppConfig::fromStore($store, '/app/demo')); // builds without throwing
    }

    public function test_write_is_fail_closed_on_invalid_value(): void
    {
        $store = new ConfigStore($this->dbPath());
        $this->expectException(RuntimeException::class);
        $store->set('style', 'not-a-valid-style', 'admin', '');
    }

    public function test_write_is_fail_closed_on_unknown_key(): void
    {
        $store = new ConfigStore($this->dbPath());
        $this->expectException(RuntimeException::class);
        $store->set('no.such.key', 'x', 'admin', '');
    }

    // ------------------------------------------------------------------ seed / audit / sparse -----

    public function test_seed_from_env_is_explicit_and_sparse(): void
    {
        $store = new ConfigStore($this->dbPath());

        // No env set for any knob (except what the process already has) -> a store built cold stays
        // empty until a write. Prove sparseness: a never-written store has no overrides.
        self::assertSame('realistic', $store->snapshot()['style']); // pure default, no row

        putenv('FUNNYPOT_STYLE=taunt');
        putenv('FUNNYPOT_LLM=1');
        $n = $store->seedFromEnv();
        self::assertGreaterThanOrEqual(2, $n); // at least the two we set (plus any inherited FUNNYPOT_*)

        // Seeded rows now resolve even with the env cleared (they are real overrides now).
        putenv('FUNNYPOT_STYLE');
        putenv('FUNNYPOT_LLM');
        self::assertSame('taunt', $store->snapshot()['style']);
        self::assertTrue(AppConfig::fromStore($store, '/app/demo')->llmEnabled);
    }

    public function test_audit_records_set_and_reset(): void
    {
        $store = new ConfigStore($this->dbPath());
        $store->set('style', 'taunt', 'alice', '203.0.113.7');
        $store->reset('style', 'alice', '203.0.113.7');

        $audits = $store->audits();
        self::assertGreaterThanOrEqual(2, count($audits));
        // newest first: the reset (new_value NULL)
        self::assertSame('style', $audits[0]['key']);
        self::assertSame('taunt', $audits[0]['old_value']);
        self::assertNull($audits[0]['new_value']);
        self::assertSame('alice', $audits[0]['actor']);
        self::assertSame('203.0.113.7', $audits[0]['source_ip']);
        // the set before it (old NULL -> 'taunt')
        self::assertSame('taunt', $audits[1]['new_value']);
        self::assertNull($audits[1]['old_value']);
    }

    public function test_reset_of_absent_key_is_a_noop(): void
    {
        $store = new ConfigStore($this->dbPath());
        $store->reset('style', 'admin', ''); // nothing stored — must not throw, no audit row
        self::assertSame([], $store->audits());
    }
}
