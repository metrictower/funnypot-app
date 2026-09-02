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
    $blocklist = new Blocklist($config->intelDbPath, $config->blocklistMinLists);
    $result = $blocklist->import();
    if (!empty($result['skipped'])) {
        // FP-0247 (Fix B): a total feed outage kept the existing intel instead of wiping it.
        fwrite(STDERR, sprintf("blocklist: outage — kept %d existing ips (%d feeds ok)\n", $blocklist->count(), $result['sources']));
    } else {
        fwrite(STDERR, sprintf("blocklist: %d ips from %d feeds\n", $result['ips'], $result['sources']));
        // FP-0247 (Fix B, addendum): a partial outage (few feeds ok) replaces multi-feed corroboration
        // with a single-feed view — surface it so the operator knows corroboration is degraded.
        if ($result['sources'] > 0 && $result['sources'] < 2) {
            fwrite(STDERR, sprintf("blocklist: WARNING only %d feed(s) succeeded — corroboration degraded\n", $result['sources']));
        }
    }
    if ($blocklist->isStale()) {
        fwrite(STDERR, sprintf("blocklist: WARNING data is stale (last good refresh: %s)\n", $blocklist->refreshedAt() ?? 'never'));
    }
} catch (Throwable $e) {
    fwrite(STDERR, 'blocklist: ' . $e->getMessage() . "\n");
}
