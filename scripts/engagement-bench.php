#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Synthetic-only warm or connection-cold benchmark. Exit 0: healthy and p95 <= 5 ms;
 * 1: measured drops/budget failure; 2: argument/setup/harness/cleanup error.
 * Usage: php scripts/engagement-bench.php [events=2000] [keys=50] [--cold]
 */
require dirname(__DIR__) . '/vendor/autoload.php';
require __DIR__ . '/support/EngagementBench.php';

use Funnypot\App\Bench\EngagementBench;
use Funnypot\App\Bench\SqliteBenchConnection;
use Funnypot\App\Engagement\AnalyticsKey;
use Funnypot\App\Engagement\EngagementCaps;

$dir = null;
$report = null;
$exitCode = 2;
try {
    // Validate before creating anything; the CLI has no path/production-database option.
    $args = EngagementBench::parseArguments(array_slice($argv, 1));
    $candidate = sys_get_temp_dir() . '/fp_eng_bench_' . bin2hex(random_bytes(8));
    if (!@mkdir($candidate, 0700)) {
        throw new RuntimeException('Cannot create benchmark directory.');
    }
    $dir = $candidate; // Only successful exclusive creation grants cleanup ownership.
    $path = $dir . '/engagement.sqlite';
    $key = AnalyticsKey::fromRaw(random_bytes(32));
    $caps = new EngagementCaps();
    $now = time();
    $clock = static function () use (&$now): int {
        return $now;
    };
    $factory = static fn (): SqliteBenchConnection => new SqliteBenchConnection($path, $caps, $key, $clock, $args['keys']);
    $advance = static function (int $i) use (&$now): void {
        if ($i % 50 === 0) {
            $now++;
        }
    };
    $report = EngagementBench::measure($args['events'], $args['keys'], $args['cold'], $factory, $advance);
    $exitCode = $report['exit_code'];
} catch (Throwable) {
    // Do not retain an exception trace (and its connection references) during cleanup, or print keys/paths.
    fwrite(STDERR, "Engagement benchmark argument/setup/harness error; use [events=2000] [keys=50] [--cold].\n");
} finally {
    unset($factory, $advance, $clock);
    if ($dir !== null) {
        foreach (['', '-wal', '-shm', '-journal'] as $suffix) {
            $ownedFile = $dir . '/engagement.sqlite' . $suffix;
            if ((file_exists($ownedFile) || is_link($ownedFile)) && !@unlink($ownedFile)) {
                $exitCode = 2;
            }
        }
        if (!@rmdir($dir)) {
            $exitCode = 2;
        }
        if ($exitCode === 2 && $report !== null) {
            fwrite(STDERR, "Engagement benchmark cleanup error.\n");
        }
    }
}
if ($report !== null && $exitCode !== 2) {
    echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
}
exit($exitCode);
