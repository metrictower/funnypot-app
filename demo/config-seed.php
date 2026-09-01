<?php

declare(strict_types=1);

/**
 * One-time seed of the runtime config store (FP-0242a) from the current environment. For each
 * registered knob whose FUNNYPOT_* var is set, this writes a stored override row equal to the env
 * value — materialising "what the container is running right now" into the SQLite config store so an
 * operator can then edit it (via the CLI / SQLite, or the FP-0242b admin UI) without a redeploy.
 *
 *   php demo/config-seed.php
 *
 * NOT wired into entrypoint.sh on purpose: the store is meant to stay SPARSE (only true overrides get
 * rows; every unset knob keeps falling through env -> coded default). Seeding is an explicit operator
 * action. Idempotent — re-running just refreshes the seeded rows to the current env. Prints the count.
 */

require __DIR__ . '/../vendor/autoload.php';

use Funnypot\App\Config\ConfigStore;

$store = new ConfigStore(ConfigStore::defaultDbPath(__DIR__));

try {
    $n = $store->seedFromEnv();
} catch (Throwable $e) {
    fwrite(STDERR, 'config-seed: ' . $e->getMessage() . "\n");
    exit(1);
}

fwrite(STDERR, "config-seed: wrote {$n} override row(s) from the environment\n");
