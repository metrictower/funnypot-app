<?php

declare(strict_types=1);

/**
 * Periodic retention. Prunes the hit store by age (FUNNYPOT_RETAIN_DAYS) and/or on-disk size
 * (FUNNYPOT_RETAIN_GB) — both unset = unbounded, no deletes (the wal is still checkpointed). Also
 * prunes raw-capture.sqlite (FP-0249), the FUNNYPOT_CAPTURE_RAW full-request debug capture, which is
 * bounded by AGE AND SIZE by DEFAULT (FUNNYPOT_RAW_RETAIN_DAYS=7 / FUNNYPOT_RAW_RETAIN_GB=1) since it
 * is opt-in and its whole failure mode is disk fill (~136KB/row worst case). The entrypoint runs this
 * on a timer.
 */

require __DIR__ . '/../vendor/autoload.php';

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Config\ConfigStore;
use Funnypot\App\Engagement\EngagementCaps;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\App\Storage\RawCapture;
use Funnypot\App\Storage\SqliteEngagementStore;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\Storage\TarpitBudget;

// Store-backed config (FP-0242a): the entrypoint respawns this runner each pass, so a live change to
// a value it reads (retention/llm knobs) is picked up on the next pass. Fail-safe: degrades to env.
$config = AppConfig::fromStore(new ConfigStore(ConfigStore::defaultDbPath(__DIR__)), __DIR__);

// LLM cache upkeep runs whenever the responder is on: cap the cache by size (0 = unbounded) and
// reap in-flight locks a crashed generation would otherwise leave held. Independent of hit retention.
if ($config->llmEnabled && is_file($config->llmCacheDb)) {
    try {
        $cache = new LlmFakeCache($config->llmCacheDb);
        // Reap only locks older than the longest a generation could still be running (the request
        // timeout) plus slack — never a live winner, which would break the cap and single-flight.
        $staleSecs = max(15, (int) ceil($config->llmTimeoutMs / 1000) + 30);
        $stale = $cache->reapInflight($staleSecs);
        $evicted = $config->llmCacheMaxBytes > 0 ? $cache->retainBytes($config->llmCacheMaxBytes) : 0;
        if ($stale > 0 || $evicted > 0) {
            fwrite(STDERR, sprintf("retention: llm cache reaped %d locks, evicted %d entries\n", $stale, $evicted));
        }
    } catch (Throwable $e) {
        fwrite(STDERR, 'retention (llm): ' . $e->getMessage() . "\n");
    }
}

// Tarpit upkeep (FP-0245): reap slots a crashed holder left behind and prune stale hourly-ledger
// buckets, on the same timer. acquire() also self-reaps inline, but a fatal/OOM/SIGTERM never runs
// release() or the shutdown handler, so this cron pass is the backstop that keeps the small slot
// pool from wedging. Runs whenever the tarpit OR the FP-0228 sleep decoy is on and the db exists (the
// sleep decoy charges its honoured sleep to the SAME tarpit_ledger.wall_ms rows, so this one prune
// keeps them bounded too — no unbounded state).
if (($config->tarpitEnabled || $config->sleepDecoy) && is_file($config->tarpitDbPath)) {
    try {
        $budget = new TarpitBudget($config->tarpitDbPath, $config->tarpitEnabled || $config->sleepDecoy);
        // A SHORT slot TTL (nginx fastcgi_read_timeout territory), never the 120 s/hr wall budget.
        $reaped = $budget->reap();
        $pruned = $budget->pruneLedger();
        if ($reaped > 0 || $pruned > 0) {
            fwrite(STDERR, sprintf("retention: tarpit reaped %d slots, pruned %d ledger buckets\n", $reaped, $pruned));
        }
    } catch (Throwable $e) {
        fwrite(STDERR, 'retention (tarpit): ' . $e->getMessage() . "\n");
    }
}

// Raw-capture upkeep (FP-0249): guarded on the FILE existing, not on $config->captureRaw — an operator
// who turns capture off after a pentest cleanup (docs/pentest-2026-08-29.md:82) still needs the big file
// left behind pruned, and retention must never CREATE an empty db that capture wouldn't. Bounded by
// default (raw_retain_days=7 / raw_retain_gb=1): see the class docblock for the legacy-VACUUM caveat.
$rawPath = RawCapture::defaultPath($config->dbPath);
if (is_file($rawPath)) {
    try {
        $raw = new RawCapture($rawPath);
        // Unconditional wal checkpoint — disk hygiene independent of whether an age/size knob is set.
        $raw->checkpointWal();
        $rawByAge = $config->rawRetainDays > 0 ? $raw->retainDays($config->rawRetainDays) : 0;
        $rawBySize = $config->rawRetainGb > 0
            ? $raw->retainBytes((int) round($config->rawRetainGb * 1024 * 1024 * 1024))
            : 0;
        if ($rawByAge > 0 || $rawBySize > 0) {
            fwrite(STDERR, sprintf("retention: raw-capture pruned %d by age + %d by size\n", $rawByAge, $rawBySize));
        }
    } catch (Throwable $e) {
        fwrite(STDERR, 'retention (raw-capture): ' . $e->getMessage() . "\n");
    }
}

// Engagement-metrics upkeep: guarded on the FILE existing (like raw capture) so a store left behind
// after the feature is switched off is still pruned, and retention never creates an empty db. Age is
// capped by the hit retention and 30 days (EngagementCaps::retainCeiling), size by the global byte
// ceiling. The request path already enforces the row/byte ceilings inline from O(1) gauges; this pass
// is the bulk reclaim (checkpoint + incremental_vacuum) and recounts those gauges after deleting.
$engPath = SqliteEngagementStore::defaultPath($config->dbPath);
if (is_file($engPath)) {
    try {
        $engCaps = EngagementCaps::fromConfig($config);
        $eng = new SqliteEngagementStore($engPath, $engCaps); // maintenance instance: prunes, never records
        $eng->checkpointWal();
        $engByAge = $eng->retainDays($engCaps->retainDays);
        $engBySize = $eng->retainBytes($engCaps->globalMaxBytes);
        if ($engByAge > 0 || $engBySize > 0) {
            fwrite(STDERR, sprintf("retention: engagement pruned %d by age + %d by size\n", $engByAge, $engBySize));
        }
    } catch (Throwable $e) {
        fwrite(STDERR, 'retention (engagement): ' . $e->getMessage() . "\n");
    }
}

// Hit-store upkeep. NOT constructed with $config->logPath here — that would fire the import-on-empty
// side effect (SqliteHitStore ctor) inside a retention pass, which is not this runner's job.
try {
    $store = new SqliteHitStore($config->dbPath);
    // Unconditional wal checkpoint — disk hygiene independent of whether an age/size knob is set.
    $store->checkpointWal();
    if ($config->retainDays > 0 || $config->retainGb > 0) {
        // Clamp deletes at the rollup watermark (FP-0249) so retention can never delete a hit the
        // rollup fold hasn't reached yet — UNLESS rollups are disabled, in which case the watermark
        // never advances and a clamp would make this a permanent no-op (unbounded disk).
        $clamp = $config->rollupEnabled;
        $byAge = $config->retainDays > 0 ? $store->retainDays($config->retainDays, $clamp) : 0;
        $bySize = $config->retainGb > 0 ? $store->retainBytes((int) round($config->retainGb * 1024 * 1024 * 1024), $clamp) : 0;
        if ($byAge > 0 || $bySize > 0) {
            fwrite(STDERR, sprintf("retention: pruned %d by age + %d by size\n", $byAge, $bySize));
        }
    }
} catch (Throwable $e) {
    fwrite(STDERR, 'retention: ' . $e->getMessage() . "\n");
}
