<?php

declare(strict_types=1);

/**
 * Periodic retention. Prunes the hit store by age (FUNNYPOT_RETAIN_DAYS) and/or on-disk size
 * (FUNNYPOT_RETAIN_GB). Both unset = unbounded, a no-op. The entrypoint runs this on a timer.
 */

require __DIR__ . '/../vendor/autoload.php';

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Config\ConfigStore;
use Funnypot\App\Storage\LlmFakeCache;
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
// pool from wedging. Runs whenever the tarpit is on and its db exists.
if ($config->tarpitEnabled && is_file($config->tarpitDbPath)) {
    try {
        $budget = new TarpitBudget($config->tarpitDbPath, $config->tarpitEnabled);
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

if ($config->retainDays <= 0 && $config->retainGb <= 0) {
    exit(0); // hit store unbounded: nothing more to do
}

try {
    $store = new SqliteHitStore($config->dbPath);
    $byAge = $config->retainDays > 0 ? $store->retainDays($config->retainDays) : 0;
    $bySize = $config->retainGb > 0 ? $store->retainBytes((int) round($config->retainGb * 1024 * 1024 * 1024)) : 0;
    if ($byAge > 0 || $bySize > 0) {
        fwrite(STDERR, sprintf("retention: pruned %d by age + %d by size\n", $byAge, $bySize));
    }
} catch (Throwable $e) {
    fwrite(STDERR, 'retention: ' . $e->getMessage() . "\n");
}
