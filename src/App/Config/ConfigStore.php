<?php

declare(strict_types=1);

namespace Funnypot\App\Config;

use Funnypot\App\Storage\Sqlite;
use PDO;
use RuntimeException;
use Throwable;

/**
 * Runtime config store: a SQLite table of operator OVERRIDES plus an APCu/sentinel read-cache.
 *
 * The store holds only true overrides (it stays sparse — an unset knob has no row and falls through
 * to env → coded default in {@see AppConfig::build()}). Resolution precedence (spec §2.3):
 * stored override > env seed > coded default. The store never resolves defaults itself; it only
 * supplies overrides, and `AppConfig` applies the same casts/clamps to a stored value as it always
 * has to an env value — so there is one validation path for both sources.
 *
 * Two asymmetric contracts, on purpose (spec §6.2):
 *   - READ ({@see snapshot}/{@see get}/{@see rawForEnv}) is FAIL-SAFE: any DB/cache error falls back
 *     to the env/default baseline and never throws, so the honeypot keeps serving decoys.
 *   - WRITE ({@see set}/{@see reset}/{@see seedFromEnv}) is FAIL-CLOSED: validation/write errors
 *     throw so the admin surface reports them.
 *
 * Hot path (per request, O(1) target), following the {@see \Funnypot\App\ThreatIntel\OperatorBlocklist}
 * snapshot idiom:
 *   1. per-instance memo (one build per request — a store is constructed once per request/process);
 *   2. APCu (`fp.cfg.snapshot` overrides map + `fp.cfg.gen` the generation it was built at), guarded
 *      by function_exists so a box without the ext (see spec §0) still works;
 *   3. SQLite rebuild, overlaid onto the env/default baseline by AppConfig.
 * The cross-process staleness signal is a monotonic generation counter (`config_meta`) mirrored into
 * a sentinel file (`config.gen`) on the same volume: readers compare their cached generation against
 * a cheap read of the sentinel (visible to every process/SAPI on the box, unlike a private APCu
 * segment), and rebuild when it advanced. If the sentinel is absent AND no db file exists, there are
 * no overrides — the fast path returns [] without touching SQLite (the common, never-configured box).
 */
final class ConfigStore
{
    private const APCU_SNAP = 'fp.cfg.snapshot';
    private const APCU_GEN = 'fp.cfg.gen';

    private ConfigRegistry $registry;
    private string $sentinelPath;
    private ?PDO $db = null;

    // APCu keys namespaced by the db path (FP-0242b review nit fable#6): a second config db on the same
    // box can never collide with this one's cached snapshot/generation. Harmless today (one config db in
    // prod) but cheap insurance, and it makes a per-test store isolation-clean when APCu is present.
    private string $apcuSnapKey;
    private string $apcuGenKey;

    /** @var array<string,string>|null per-instance memo of the resolved override map */
    private ?array $memo = null;
    private int $memoGen = -2;

    /**
     * @param string                    $dbPath   path to config.sqlite (its dir is created on write)
     * @param ConfigRegistry|array|null  $registry a ConfigRegistry, a raw entries array, or null for
     *                                             the canonical schema
     * @param string|null               $sentinelPath the cross-process generation sentinel; defaults
     *                                             to `config.gen` beside the db file
     */
    public function __construct(private string $dbPath, $registry = null, ?string $sentinelPath = null)
    {
        if ($registry instanceof ConfigRegistry) {
            $this->registry = $registry;
        } elseif (is_array($registry)) {
            $this->registry = new ConfigRegistry($registry);
        } else {
            $this->registry = new ConfigRegistry();
        }
        $this->sentinelPath = $sentinelPath ?? (dirname($dbPath) . '/config.gen');
        $ns = substr(md5($dbPath), 0, 12);
        $this->apcuSnapKey = self::APCU_SNAP . '.' . $ns;
        $this->apcuGenKey = self::APCU_GEN . '.' . $ns;
    }

    /**
     * Resolve the default config.sqlite path for a demo baseDir, mirroring how `AppConfig::fromEnv`
     * derives its storage dir: the config db sits beside the canonical hit-store db (on the persisted
     * volume), so the sentinel + SQLite files share one volume as spec §3 requires. This is resolved
     * from env WITHOUT building an AppConfig, breaking the chicken-and-egg at the front-controller.
     */
    public static function defaultDbPath(string $baseDir): string
    {
        $store = rtrim($baseDir, '/') . '/storage';
        $db = getenv('FUNNYPOT_DB');
        if ($db === false || $db === '' || $db === 'off') {
            $db = $store . '/funnypot.sqlite';
        }

        return dirname($db) . '/config.sqlite';
    }

    public function registry(): ConfigRegistry
    {
        return $this->registry;
    }

    /** @return array<string,array<string,mixed>> the registry schema (for the admin UI / introspection) */
    public function schema(): array
    {
        return $this->registry->entries();
    }

    // ---------------------------------------------------------------- read (fail-safe) -------------

    /**
     * The fully resolved raw-string map for every registered key: the env/default baseline overlaid
     * with stored overrides. Typing + clamps are applied downstream in {@see AppConfig::build()}, so
     * these are the resolved *source* strings (e.g. an out-of-range stored int appears here verbatim
     * and is clamped on read). Fail-safe: on any error the baseline (env/default) still resolves.
     *
     * @return array<string,string>
     */
    public function snapshot(): array
    {
        $overrides = $this->overrides();
        $out = [];
        foreach ($this->registry->entries() as $key => $e) {
            if (array_key_exists($key, $overrides)) {
                $out[$key] = $this->clampProtected($key, (string) $overrides[$key]);
                continue;
            }
            $env = getenv((string) $e['env']);
            $out[$key] = ($env === false || $env === '') ? (string) $e['default'] : $env;
        }

        return $out;
    }

    /**
     * Resolve one key with full precedence, returning a raw string. Stored override wins; else the
     * env var if set/non-empty; else $default. Fail-safe.
     *
     * @param mixed $default
     */
    public function get(string $key, string $envKey, $default = null): string
    {
        $overrides = $this->overrides();
        if (array_key_exists($key, $overrides)) {
            return $this->clampProtected($key, (string) $overrides[$key]);
        }
        $env = getenv($envKey);
        if ($env !== false && $env !== '') {
            return $env;
        }

        return (string) $default;
    }

    /**
     * getenv()-shaped raw resolver keyed by ENV var name: returns the stored override for the key that
     * env seeds, else the real getenv() value (string, or false when unset). This is the single seam
     * {@see AppConfig::fromStore()} plugs into `AppConfig::build()` — env-only fields (paths/secrets,
     * not in the registry) fall straight through to getenv, so they stay env-sourced. Fail-safe.
     *
     * @return string|false
     */
    public function rawForEnv(string $envKey)
    {
        $key = $this->registry->keyForEnv($envKey);
        if ($key !== null) {
            $overrides = $this->overrides();
            if (array_key_exists($key, $overrides)) {
                return $this->clampProtected($key, (string) $overrides[$key]);
            }
        }

        return getenv($envKey);
    }

    /**
     * The cached override map (key => stored value). Per-instance memo → APCu → SQLite, gated on the
     * generation sentinel. Never throws (fail-safe): a locked/corrupt db returns the last good memo
     * or [] (⇒ env/default baseline everywhere).
     *
     * @return array<string,string>
     */
    private function overrides(): array
    {
        $gen = $this->currentGen();
        if ($gen < 0) {
            // No sentinel and no db file: the store was never written. Nothing to overlay.
            $this->memoGen = $gen;

            return $this->memo = [];
        }
        if ($this->memo !== null && $this->memoGen === $gen) {
            return $this->memo;
        }
        if (function_exists('apcu_fetch')) {
            $ok = false;
            $cached = apcu_fetch($this->apcuSnapKey, $ok);
            $cachedGen = apcu_fetch($this->apcuGenKey);
            if ($ok && is_array($cached) && (int) $cachedGen === $gen) {
                $this->memoGen = $gen;

                return $this->memo = $cached;
            }
        }
        try {
            $rows = [];
            foreach ($this->db()->query('SELECT key, value FROM config') as $row) {
                $rows[(string) $row['key']] = (string) $row['value'];
            }
        } catch (Throwable $e) {
            // Fail-safe: keep the last good snapshot (or empty) and do NOT cache a bad read.
            return $this->memo ?? [];
        }
        if (function_exists('apcu_store')) {
            apcu_store($this->apcuSnapKey, $rows);
            apcu_store($this->apcuGenKey, $gen);
        }
        $this->memoGen = $gen;

        return $this->memo = $rows;
    }

    /**
     * The current generation, read from the cheap cross-process sentinel. -1 when the store has never
     * been written (no sentinel and no db). If the sentinel is missing but a db exists (e.g. a volume
     * restored without the sentinel), fall back to the meta counter so overrides are still honoured.
     */
    private function currentGen(): int
    {
        $raw = @file_get_contents($this->sentinelPath);
        if ($raw !== false && trim($raw) !== '') {
            return (int) trim($raw);
        }
        if (!is_file($this->dbPath)) {
            return -1;
        }
        try {
            $v = $this->db()->query("SELECT v FROM config_meta WHERE k='generation'")->fetchColumn();

            return $v === false ? 0 : (int) $v;
        } catch (Throwable $e) {
            return -1; // unreadable ⇒ treat as no store (fail-safe)
        }
    }

    // ---------------------------------------------------------------- write (fail-closed) ----------

    /**
     * Set (or replace) one override. Validates against the registry (throws on an invalid value —
     * fail-closed), upserts the row, appends an audit entry and bumps the generation in ONE
     * transaction, then publishes the new generation to the sentinel and drops the APCu snapshot.
     *
     * @param mixed $rawValue
     * @throws RuntimeException on an unknown key, a validation failure, or a write error
     */
    public function set(string $key, $rawValue, string $actor, string $sourceIp): void
    {
        // Reject an empty override (FP-0242b review nit fable#3). A stored '' is returned verbatim by
        // get()/snapshot() and then AppConfig::build()'s $str treats '' as "use the default" — so an
        // empty override would SILENTLY MASK a set env var (the env value is lost, the coded default
        // wins) with no way to tell from the resolved value that an override even exists. Clearing an
        // override is a distinct, explicit operation: reset(). This guards every type, not just strings.
        if (is_string($rawValue) ? trim($rawValue) === '' : $rawValue === null) {
            throw new RuntimeException("config set failed: empty value for '{$key}' is not allowed (use reset to clear an override)");
        }
        [$ok, $coerced] = $this->registry->validate($key, $rawValue);
        if (!$ok) {
            throw new RuntimeException($coerced);
        }
        // FP-0250 2.3: env-as-ceiling for protected exposure knobs (fail-closed, BEFORE the txn — no
        // partial write, no generation bump, no sentinel publish on a rejected set). A hijacked admin
        // session must never be able to store a value LESS safe than the environment's own baseline.
        $this->rejectIfLoosensProtectedCeiling($key, $coerced);
        $db = null;
        try {
            $db = $this->db();
            $db->beginTransaction();
            $old = $this->currentValue($db, $key);
            $st = $db->prepare(
                'INSERT INTO config (key, value, updated_at, updated_by) VALUES (:k, :v, :t, :by)
                 ON CONFLICT(key) DO UPDATE SET value = :v, updated_at = :t, updated_by = :by'
            );
            $now = gmdate('c');
            $st->execute([':k' => $key, ':v' => $coerced, ':t' => $now, ':by' => $actor]);
            $this->audit($db, $actor, $key, $old, $coerced, $sourceIp);
            $gen = $this->bumpGeneration($db);
            $db->commit();
        } catch (Throwable $e) {
            if ($db !== null && $db->inTransaction()) {
                $db->rollBack();
            }
            throw new RuntimeException('config set failed: ' . $e->getMessage(), 0, $e);
        }
        $this->publish($gen);
    }

    /**
     * Delete an override, falling the key back to env → default. No-op (and no generation bump) when
     * the key had no override. Fail-closed on a write error.
     *
     * @throws RuntimeException on a write error
     */
    public function reset(string $key, string $actor, string $sourceIp): void
    {
        $db = null;
        try {
            $db = $this->db();
            $db->beginTransaction();
            $old = $this->currentValue($db, $key);
            if ($old === null) {
                $db->commit(); // nothing stored ⇒ nothing to do

                return;
            }
            $db->prepare('DELETE FROM config WHERE key = :k')->execute([':k' => $key]);
            $this->audit($db, $actor, $key, $old, null, $sourceIp);
            $gen = $this->bumpGeneration($db);
            $db->commit();
        } catch (Throwable $e) {
            if ($db !== null && $db->inTransaction()) {
                $db->rollBack();
            }
            throw new RuntimeException('config reset failed: ' . $e->getMessage(), 0, $e);
        }
        $this->publish($gen);
    }

    /**
     * One-time import: for every registry key whose env var is set (non-empty), write a stored row so
     * the current env is materialised into the store. Explicit operator/CLI action only — never called
     * automatically (the store stays sparse). Returns the number of rows written. Fail-closed.
     *
     * @throws RuntimeException on a write error
     */
    public function seedFromEnv(): int
    {
        $db = null;
        $count = 0;
        try {
            $db = $this->db();
            $db->beginTransaction();
            $upsert = $db->prepare(
                'INSERT INTO config (key, value, updated_at, updated_by) VALUES (:k, :v, :t, :by)
                 ON CONFLICT(key) DO UPDATE SET value = :v, updated_at = :t, updated_by = :by'
            );
            $now = gmdate('c');
            foreach ($this->registry->entries() as $key => $e) {
                $env = getenv((string) $e['env']);
                if ($env === false || $env === '') {
                    continue; // unset ⇒ leave it falling through to env/default (sparse)
                }
                [$ok, $coerced] = $this->registry->validate($key, $env);
                if (!$ok) {
                    continue; // a malformed env value would already be clamped/ignored on read
                }
                $old = $this->currentValue($db, $key);
                $upsert->execute([':k' => $key, ':v' => $coerced, ':t' => $now, ':by' => 'env-seed']);
                $this->audit($db, 'system', $key, $old, $coerced, '');
                $count++;
            }
            $gen = $this->bumpGeneration($db);
            $db->commit();
        } catch (Throwable $e) {
            if ($db !== null && $db->inTransaction()) {
                $db->rollBack();
            }
            throw new RuntimeException('config seed failed: ' . $e->getMessage(), 0, $e);
        }
        $this->publish($gen);

        return $count;
    }

    /**
     * The stored override rows only (key => raw stored value) — NOT the resolved baseline. The admin UI
     * uses this to tell a knob's source apart: a key present here is a stored override, else it falls
     * through to env/default. Fail-safe (returns [] on a read fault, like every read path here).
     *
     * @return array<string,string>
     */
    public function stored(): array
    {
        return $this->overrides();
    }

    /** @return list<array<string,mixed>> the audit log, newest first (for the admin UI) */
    public function audits(int $limit = 200): array
    {
        try {
            $st = $this->db()->prepare(
                'SELECT ts, actor, key, old_value, new_value, source_ip FROM config_audit ORDER BY id DESC LIMIT :n'
            );
            $st->bindValue(':n', max(1, $limit), PDO::PARAM_INT);
            $st->execute();

            return $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
        } catch (Throwable $e) {
            return [];
        }
    }

    // ---------------------------------------------------------------- protected knobs (FP-0250 2.3) ---

    /**
     * The public FACE of {@see protectedBaseline()} — the current env-as-ceiling for $key, or null when
     * $key is not a protected knob. Used by {@see \Funnypot\App\Admin\ConfigAdmin::listPayload()} so the
     * admin UI can grey out unreachable options instead of round-tripping a rejected write.
     */
    public function protectedCeiling(string $key): ?string
    {
        return $this->registry->isProtected($key) ? $this->protectedBaseline($key) : null;
    }

    /**
     * The env-as-ceiling baseline for a protected key: the SAME value + precedence `snapshot()` uses
     * (stored overrides play no part here — the ceiling is env/default, on purpose, never itself
     * clamped by a stored value), canonicalized through {@see ConfigRegistry::validate()} exactly as a
     * real write would coerce it. Fail-closed: an uncoercible value, or an ordered knob's value that
     * ends up with no {@see ConfigRegistry::safetyRank()} at all (a garbage enum/bool spelling that
     * validate() itself could not normalise — should not happen given validate()'s own coercion, but
     * this is the last line of defence), resolves to the SAFEST value in `safety_order` rather than to
     * whatever came out of coercion. A protected+UNORDERED key (no `safety_order` — the hidden-path
     * strings) has no notion of "safer": its baseline is simply the coerced env/default value itself.
     *
     * Deliberately diverges from {@see AppConfig::build()}'s OWN garbage-env fallback in one documented
     * case: a garbage FUNNYPOT_MODE resolves to the RUNNING value 'public' there (only the exact string
     * 'stealth' selects stealth), but the CEILING computed here falls back to 'stealth' (the safest
     * value) — so a garbage env can never be leveraged to justify STORING a looser override. The store
     * may then refuse to materialize even the value that is actually running; that is intended (env
     * repair is the fix for a garbage FUNNYPOT_MODE, not a stored override).
     */
    private function protectedBaseline(string $key): string
    {
        $e = $this->registry->get($key);
        if ($e === null) {
            return '';
        }
        $env = (string) ($e['env'] ?? '');
        $raw = $env !== '' ? getenv($env) : false;
        if ($raw === false || $raw === '') {
            $raw = (string) ($e['default'] ?? '');
        }
        [$ok, $coerced] = $this->registry->validate($key, $raw);
        $order = $e['safety_order'] ?? null;
        if (!is_array($order) || $order === []) {
            // Protected + unordered: no "safer" — the baseline is the coerced value itself (a 'string'
            // type never fails validate(), so $ok is always true in practice for this branch).
            return $ok ? $coerced : $raw;
        }
        if (!$ok || $this->registry->safetyRank($key, $coerced) === null) {
            return (string) $order[count($order) - 1]; // fail-closed: the SAFEST value, ascending order
        }

        return $coerced;
    }

    /**
     * Write-side enforcement (FP-0250 2.3): throws when $coerced would store a value LESS safe than
     * the current env-as-ceiling for a protected key. No-op for a non-protected key.
     *
     * @throws RuntimeException when the write would loosen exposure below the environment baseline
     */
    private function rejectIfLoosensProtectedCeiling(string $key, string $coerced): void
    {
        if (!$this->registry->isProtected($key)) {
            return;
        }
        $baseline = $this->protectedBaseline($key);
        $e = $this->registry->get($key);
        $order = $e['safety_order'] ?? null;
        if (!is_array($order) || $order === []) {
            if ($coerced !== $baseline) {
                throw new RuntimeException(
                    "config set failed: '{$key}' is protected: it can only be changed via its environment variable"
                );
            }

            return;
        }
        $rank = $this->registry->safetyRank($key, $coerced);
        $baseRank = $this->registry->safetyRank($key, $baseline);
        if ($rank === null || $baseRank === null || $rank < $baseRank) {
            throw new RuntimeException(
                "config set failed: '{$key}' is protected: a stored value may not be less safe than "
                . "the environment ceiling ('{$baseline}')"
            );
        }
    }

    /**
     * Read-side enforcement (FP-0250 2.3): clamp a resolved value back to the env-as-ceiling baseline
     * when it is a protected key and $value is less safe than the CURRENT env (a row that was a
     * legitimate override when written can become stale-unsafe purely because the operator tightened
     * env afterward — write-time rejection alone cannot catch that). No-op for a non-protected key, or
     * when $value already meets/exceeds the ceiling. Never baked into the APCu/memo snapshot — callers
     * apply this AFTER {@see overrides()} resolves, so it is always evaluated against the live env.
     */
    private function clampProtected(string $key, string $value): string
    {
        if (!$this->registry->isProtected($key)) {
            return $value;
        }
        $baseline = $this->protectedBaseline($key);
        $e = $this->registry->get($key);
        $order = $e['safety_order'] ?? null;
        if (!is_array($order) || $order === []) {
            if ($value === $baseline) {
                return $value;
            }
            error_log("ConfigStore: ignoring a stale/unsafe stored override for protected key '{$key}' (env-only)");

            return $baseline;
        }
        $rank = $this->registry->safetyRank($key, $value);
        $baseRank = $this->registry->safetyRank($key, $baseline);
        if ($rank !== null && $baseRank !== null && $rank >= $baseRank) {
            return $value;
        }
        error_log("ConfigStore: clamping a stale/unsafe stored override for protected key '{$key}' back to the environment ceiling '{$baseline}'");

        return $baseline;
    }

    // ---------------------------------------------------------------- internals --------------------

    private function currentValue(PDO $db, string $key): ?string
    {
        $st = $db->prepare('SELECT value FROM config WHERE key = :k');
        $st->execute([':k' => $key]);
        $v = $st->fetchColumn();

        return $v === false ? null : (string) $v;
    }

    private function audit(PDO $db, string $actor, string $key, ?string $old, ?string $new, string $sourceIp): void
    {
        $st = $db->prepare(
            'INSERT INTO config_audit (ts, actor, key, old_value, new_value, source_ip)
             VALUES (:ts, :actor, :key, :old, :new, :ip)'
        );
        $st->execute([
            ':ts' => gmdate('c'),
            ':actor' => $actor,
            ':key' => $key,
            ':old' => $old,
            ':new' => $new,
            ':ip' => $sourceIp,
        ]);
    }

    /** Bump (or seed) the monotonic generation counter; returns the new value. Caller holds the txn. */
    private function bumpGeneration(PDO $db): int
    {
        $db->exec("INSERT INTO config_meta (k, v) VALUES ('generation', 1) ON CONFLICT(k) DO UPDATE SET v = v + 1");
        $v = $db->query("SELECT v FROM config_meta WHERE k='generation'")->fetchColumn();

        return (int) $v;
    }

    /**
     * Publish a completed write: mirror the new generation into the sentinel (the cross-process
     * signal every SAPI reads) and drop this process's APCu snapshot + local memo so the fpm pool
     * rebuilds on its next read. Best-effort on the sentinel/APCu (the DB is already the source of
     * truth) but done immediately so there is no stale window within the pool.
     */
    private function publish(int $gen): void
    {
        $tmp = $this->sentinelPath . '.tmp';
        $wrote = false;
        if (@file_put_contents($tmp, (string) $gen) !== false) {
            // FP-0250 2.7: 0666 -> 0644 (world-writable let any local user rewrite the generation and
            // cache-poison/stale-config the whole box). The tmp+rename replace path needs directory-
            // write, not file-write, so cross-process (fpm + a CLI listener) publishing is unaffected.
            @chmod($tmp, 0644);
            $wrote = @rename($tmp, $this->sentinelPath); // atomic replace so a reader never sees a half-write
        }
        if (!$wrote) {
            $wrote = @file_put_contents($this->sentinelPath, (string) $gen) !== false;
        }
        // An unwritable sentinel means other processes (fpm workers on their next read, the CLI
        // listeners) never learn the generation advanced and serve the STALE config indefinitely
        // (FP-0242b review nit fable#4). The DB is still the source of truth, so this is best-effort,
        // but it must be OBSERVABLE — an operator diagnosing "my config change didn't take" needs a
        // log line, not silence.
        if (!$wrote) {
            $msg = 'ConfigStore: could not write generation sentinel ' . $this->sentinelPath
                . ' — other processes may serve stale config until it is writable';
            error_log($msg);
            @trigger_error($msg, E_USER_WARNING);
        }
        @chmod($this->sentinelPath, 0644); // FP-0250 2.7 — same rationale as the tmp file above
        if (function_exists('apcu_delete')) {
            apcu_delete($this->apcuSnapKey);
            apcu_delete($this->apcuGenKey);
        }
        // Force this instance to re-read on its next resolve (it just changed the store).
        $this->memo = null;
        $this->memoGen = -2;
    }

    private function db(): PDO
    {
        if ($this->db !== null) {
            return $this->db;
        }
        if (!extension_loaded('pdo_sqlite')) {
            throw new RuntimeException('ConfigStore needs ext-pdo_sqlite');
        }
        $db = Sqlite::open($this->dbPath); // shared WAL/busy_timeout/chmod idiom (docs/DATA-LAYER-DECISION.md)
        $db->exec('CREATE TABLE IF NOT EXISTS config (
            key        TEXT PRIMARY KEY,
            value      TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            updated_by TEXT NOT NULL DEFAULT ""
        )');
        $db->exec('CREATE TABLE IF NOT EXISTS config_meta (
            k TEXT PRIMARY KEY,
            v INTEGER NOT NULL
        )');
        $db->exec('CREATE TABLE IF NOT EXISTS config_audit (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         TEXT NOT NULL,
            actor      TEXT NOT NULL,
            key        TEXT NOT NULL,
            old_value  TEXT,
            new_value  TEXT,
            source_ip  TEXT NOT NULL DEFAULT ""
        )');

        return $this->db = $db;
    }
}
