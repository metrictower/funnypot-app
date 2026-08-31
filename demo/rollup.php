<?php

declare(strict_types=1);

/**
 * Periodic analytics rollup worker (FP-0243). Folds new raw `hits` rows into the small `rollup`
 * table since a stored watermark, downsamples minute -> hour -> day, and prunes rollup rows past
 * retention -- so the operator analytics view reads O(buckets), flat in total event volume, instead
 * of full-table GROUP BYs on every dashboard tick. The entrypoint runs this on a ~15s timer.
 *
 * Best-effort, exactly like the retention/drain timers: if it dies, analytics goes stale but
 * ingestion and the honeypot are unaffected. It never throws out of here (STDERR only), and each
 * pass is a single transaction, so a crash mid-pass rolls back and the next pass reprocesses with
 * no double count.
 */

require __DIR__ . '/../vendor/autoload.php';

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Storage\SqliteHitStore;

$config = AppConfig::fromEnv(__DIR__);

if (!$config->rollupEnabled) {
    exit(0); // rollups disabled: nothing to do
}

try {
    $store = new SqliteHitStore(
        $config->dbPath,
        null,
        $config->rollupTopK,
        $config->rollupRetainMinH,
        $config->rollupRetainHourD,
        $config->rollupRetainDayD,
    );

    // Loop a bounded number of passes until the backlog drains (foldRollups returns 0). The pass
    // cap keeps a single invocation from running unbounded if ingest outruns us; the timer picks up
    // any remainder on the next tick.
    $folded = 0;
    for ($pass = 0; $pass < 10000; $pass++) {
        $n = $store->foldRollups($config->rollupBatch);
        if ($n === 0) {
            break;
        }
        $folded += $n;
    }

    if ($folded > 0) {
        fwrite(STDERR, sprintf("rollup: folded %d hits\n", $folded));
    }
} catch (Throwable $e) {
    fwrite(STDERR, 'rollup: ' . $e->getMessage() . "\n");
}
