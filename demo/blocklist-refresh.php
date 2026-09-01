<?php

declare(strict_types=1);

/**
 * Refresh the threat-intel blocklist from the public attacker feeds into intel.db. No-op unless
 * FUNNYPOT_BLOCKLIST is on. The entrypoint runs this at boot and on a timer.
 */

require __DIR__ . '/../vendor/autoload.php';

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Config\ConfigStore;
use Funnypot\App\ThreatIntel\Blocklist;

// Store-backed config (FP-0242a): the entrypoint reruns this at boot and on a timer, so a live change
// to the blocklist knobs is picked up on the next run (own process + sentinel read). Fail-safe.
$config = AppConfig::fromStore(new ConfigStore(ConfigStore::defaultDbPath(__DIR__)), __DIR__);
if (!$config->blocklistEnabled) {
    exit(0);
}

try {
    $result = (new Blocklist($config->intelDbPath, $config->blocklistMinLists))->import();
    fwrite(STDERR, sprintf("blocklist: %d ips from %d feeds\n", $result['ips'], $result['sources']));
} catch (Throwable $e) {
    fwrite(STDERR, 'blocklist: ' . $e->getMessage() . "\n");
}
