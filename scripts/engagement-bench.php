#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Warm-local observer benchmark for the engagement recorder: times EngagementRecorder::record()
 * from OUTSIDE the store over N events on a throwaway engagement.sqlite and prints p50/p95/p99/max,
 * drops, the journal mode, PHP version and platform. The engineering budget is p95 ≤ 5 ms; record
 * the run (numbers + platform) in docs/ENGAGEMENT-METRICS.md when it changes.
 *
 *   php scripts/engagement-bench.php [events=2000] [keys=50]
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use Funnypot\App\Engagement\AnalyticsKey;
use Funnypot\App\Engagement\EngagementCaps;
use Funnypot\App\Engagement\EngagementEvent;
use Funnypot\App\Engagement\EngagementRecorder;
use Funnypot\App\Engagement\EpisodeResolver;
use Funnypot\App\Engagement\EventKind;
use Funnypot\App\Engagement\LureId;
use Funnypot\App\Engagement\SignedHandle;
use Funnypot\App\Engagement\Stage;
use Funnypot\App\Storage\SqliteEngagementStore;

$events = max(1000, (int) ($argv[1] ?? 2000));
$keys = max(1, (int) ($argv[2] ?? 50));
$path = sys_get_temp_dir() . '/fp_eng_bench_' . bin2hex(random_bytes(6)) . '.sqlite';

$key = AnalyticsKey::fromRaw(random_bytes(32));
$now = time();
$clock = static function () use (&$now): int {
    return $now;
};
$store = new SqliteEngagementStore($path, new EngagementCaps(), [$key, 'id'], $clock);
$recorder = new EngagementRecorder($store, new EpisodeResolver($key, new SignedHandle($key)), $clock);

$stages = [Stage::DISCOVER, Stage::ENUMERATE, Stage::COLLECT];
$lures = LureId::all();
$mk = static fn (int $i): EngagementEvent => new EngagementEvent(
    $stages[$i % 3],
    EventKind::LURE_FOLLOWED,
    4096 + ($i % 7) * 1024,
    3 + ($i % 5),
    $lures[$i % count($lures)],
    null,
    true,
    0,
    0,
);

// Warm-up: opens the file, creates the schema, primes the page cache + prepared statements.
for ($i = 0; $i < 200; $i++) {
    $recorder->record('198.51.100.' . ($i % $keys), 'curl/8.0', $mk($i));
}

$ms = [];
$drops = 0;
for ($i = 0; $i < $events; $i++) {
    if ($i % 50 === 0) {
        $now++; // a slowly advancing clock so episodes have gaps without ever idling out
    }
    $status = $recorder->record('198.51.100.' . ($i % $keys), 'curl/8.0', $mk($i));
    $ms[] = $recorder->lastCallMs();
    if ($status !== 'recorded') {
        $drops++;
    }
}
sort($ms);
$pct = static fn (float $p): float => round($ms[max(0, (int) ceil($p * count($ms)) - 1)], 3);

$probe = new PDO('sqlite:' . $path);
$mode = (string) $probe->query('PRAGMA journal_mode')->fetchColumn();
$sync = (string) $probe->query('PRAGMA synchronous')->fetchColumn();
unset($probe);

$report = [
    'events' => $events,
    'evidence_keys' => $keys,
    'p50_ms' => $pct(0.50),
    'p95_ms' => $pct(0.95),
    'p99_ms' => $pct(0.99),
    'max_ms' => round(end($ms), 3),
    'drops' => $drops,
    'journal_mode' => $mode,
    'synchronous' => $sync,
    'busy_timeout_ms' => SqliteEngagementStore::BUSY_TIMEOUT_MS,
    'php' => PHP_VERSION,
    'platform' => php_uname('s') . ' ' . php_uname('r') . ' ' . php_uname('m'),
    'storage' => 'temp dir ' . sys_get_temp_dir(),
    'budget_p95_ms' => 5,
    'within_budget' => $pct(0.95) <= 5.0,
];
echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";

foreach (['', '-wal', '-shm'] as $s) {
    @unlink($path . $s);
}
exit($report['within_budget'] ? 0 : 1);
