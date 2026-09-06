<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Redis;

/**
 * A per-connection, string-only, in-memory Redis keyspace: 16 logical DBs, lazy clock-injected
 * expiry, and atomic key-count / value-size / aggregate-byte accounting so a flood of writes can
 * never grow memory past the clamped caps. DB 0 starts from a copy of the deploy base keyspace;
 * DBs 1-15 start empty. Everything here is process-local to one TCP session — one attacker's writes
 * never touch another's lure, and a reconnect resets to the base.
 *
 * Pure: no clock of its own (the current millisecond is passed in), no I/O. `set`/`setMany` preflight
 * their whole delta and reject atomically at a cap, mutating nothing on rejection.
 */
final class RedisDatastore
{
    /** @var array<int,array<string,array{v:string,px:?int}>> value + absolute expiry-ms (null = none) */
    private array $dbs = [];

    private int $keyCount = 0;

    /** Aggregate strlen(key)+strlen(value) across all DBs. */
    private int $byteCount = 0;

    /** @param array<string,string> $base the DB 0 base keyspace */
    public function __construct(array $base = [])
    {
        for ($i = 0; $i < RedisConfig::NUM_DBS; $i++) {
            $this->dbs[$i] = [];
        }
        foreach ($base as $k => $v) {
            $this->dbs[0][(string) $k] = ['v' => (string) $v, 'px' => null];
            $this->keyCount++;
            $this->byteCount += strlen((string) $k) + strlen((string) $v);
        }
    }

    public function keyCount(): int
    {
        return $this->keyCount;
    }

    public function byteCount(): int
    {
        return $this->byteCount;
    }

    /** Expire one key lazily if its deadline has passed. */
    private function expireIfDue(int $db, string $key, int $nowMs): void
    {
        $e = $this->dbs[$db][$key] ?? null;
        if ($e !== null && $e['px'] !== null && $nowMs >= $e['px']) {
            $this->byteCount -= strlen($key) + strlen($e['v']);
            $this->keyCount--;
            unset($this->dbs[$db][$key]);
        }
    }

    public function get(int $db, string $key, int $nowMs): ?string
    {
        $this->expireIfDue($db, $key, $nowMs);

        return isset($this->dbs[$db][$key]) ? $this->dbs[$db][$key]['v'] : null;
    }

    public function exists(int $db, string $key, int $nowMs): bool
    {
        $this->expireIfDue($db, $key, $nowMs);

        return isset($this->dbs[$db][$key]);
    }

    /**
     * The byte/key delta of writing $key=$value, given the current contents. Returns
     * [keyDelta, byteDelta]; keyDelta is 1 for a new key, 0 for a replacement.
     *
     * @return array{0:int,1:int}
     */
    private function writeDelta(int $db, string $key, string $value): array
    {
        if (isset($this->dbs[$db][$key])) {
            return [0, strlen($value) - strlen($this->dbs[$db][$key]['v'])];
        }

        return [1, strlen($key) + strlen($value)];
    }

    /** True if a single value/key is within the per-item caps. */
    public function withinItemCaps(string $key, string $value): bool
    {
        return strlen($key) <= RedisConfig::MAX_KEY_BYTES && strlen($value) <= RedisConfig::MAX_VALUE_BYTES;
    }

    /**
     * Atomically set one key. Returns false (mutating nothing) when an item or aggregate cap would be
     * exceeded. $px is the absolute expiry in ms, or null for no expiry; passing keepTtl preserves an
     * existing expiry.
     */
    public function set(int $db, string $key, string $value, int $nowMs, ?int $px = null, bool $keepTtl = false): bool
    {
        $this->expireIfDue($db, $key, $nowMs);
        if (!$this->withinItemCaps($key, $value)) {
            return false;
        }
        [$keyDelta, $byteDelta] = $this->writeDelta($db, $key, $value);
        if ($this->keyCount + $keyDelta > RedisConfig::MAX_KEYS
            || $this->byteCount + $byteDelta > RedisConfig::MAX_AGGREGATE_BYTES) {
            return false;
        }
        if ($keepTtl && isset($this->dbs[$db][$key])) {
            $px = $this->dbs[$db][$key]['px'];
        }
        $this->dbs[$db][$key] = ['v' => $value, 'px' => $px];
        $this->keyCount += $keyDelta;
        $this->byteCount += $byteDelta;

        return true;
    }

    /**
     * Atomic multi-set (MSET). Preflights every pair's delta against the caps, then applies all or
     * nothing. Later duplicate keys in $pairs win, exactly as Redis MSET does.
     *
     * @param array<int,array{0:string,1:string}> $pairs ordered [key,value] pairs
     */
    public function setManyIn(int $db, array $pairs, int $nowMs): bool
    {
        // Resolve final value per key (last write wins) and expire stale entries first.
        $final = [];
        foreach ($pairs as [$key, $value]) {
            if (!$this->withinItemCaps($key, $value)) {
                return false;
            }
            $this->expireIfDue($db, $key, $nowMs);
            $final[$key] = $value;
        }
        // Compute the aggregate delta of applying $final atop the current DB.
        $keyDelta = 0;
        $byteDelta = 0;
        foreach ($final as $key => $value) {
            [$kd, $bd] = $this->writeDelta($db, $key, $value);
            $keyDelta += $kd;
            $byteDelta += $bd;
        }
        if ($this->keyCount + $keyDelta > RedisConfig::MAX_KEYS
            || $this->byteCount + $byteDelta > RedisConfig::MAX_AGGREGATE_BYTES) {
            return false;
        }
        foreach ($final as $key => $value) {
            [$kd, $bd] = $this->writeDelta($db, $key, $value);
            $this->dbs[$db][$key] = ['v' => $value, 'px' => null];
            $this->keyCount += $kd;
            $this->byteCount += $bd;
        }

        return true;
    }

    /** Delete a key. Returns true if it existed. */
    public function del(int $db, string $key, int $nowMs): bool
    {
        $this->expireIfDue($db, $key, $nowMs);
        if (!isset($this->dbs[$db][$key])) {
            return false;
        }
        $this->byteCount -= strlen($key) + strlen($this->dbs[$db][$key]['v']);
        $this->keyCount--;
        unset($this->dbs[$db][$key]);

        return true;
    }

    /** Set/replace a key's absolute expiry. Returns false when the key is absent. */
    public function setExpiry(int $db, string $key, ?int $px, int $nowMs): bool
    {
        $this->expireIfDue($db, $key, $nowMs);
        if (!isset($this->dbs[$db][$key])) {
            return false;
        }
        $this->dbs[$db][$key]['px'] = $px;

        return true;
    }

    /** Remaining ms until expiry, or null when the key has no expiry, or false when absent. */
    public function pttl(int $db, string $key, int $nowMs): int|null|false
    {
        $this->expireIfDue($db, $key, $nowMs);
        if (!isset($this->dbs[$db][$key])) {
            return false;
        }
        $px = $this->dbs[$db][$key]['px'];

        return $px === null ? null : max(0, $px - $nowMs);
    }

    public function dbsize(int $db, int $nowMs): int
    {
        $this->expireAll($db, $nowMs);

        return count($this->dbs[$db]);
    }

    /** Force-expire every stale key in a DB (used before size/scan snapshots). */
    private function expireAll(int $db, int $nowMs): void
    {
        foreach (array_keys($this->dbs[$db]) as $key) {
            $this->expireIfDue($db, (string) $key, $nowMs);
        }
    }

    /**
     * Live, byte-sorted key names in a DB (after lazy expiry). Used by KEYS/SCAN, which apply the
     * bounded glob matcher on top.
     *
     * @return list<string>
     */
    public function sortedKeys(int $db, int $nowMs): array
    {
        $this->expireAll($db, $nowMs);
        $keys = array_map('strval', array_keys($this->dbs[$db]));
        sort($keys, SORT_STRING);

        return $keys;
    }

    public function flushdb(int $db): void
    {
        foreach ($this->dbs[$db] as $key => $e) {
            $this->byteCount -= strlen((string) $key) + strlen($e['v']);
            $this->keyCount--;
        }
        $this->dbs[$db] = [];
    }

    public function flushall(): void
    {
        for ($i = 0; $i < RedisConfig::NUM_DBS; $i++) {
            $this->flushdb($i);
        }
    }
}
