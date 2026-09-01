<?php

declare(strict_types=1);

/**
 * Send queued AbuseIPDB reports. The request/connection paths only enqueue (a fast local write);
 * this worker does the actual HTTP POSTs on a timer. No-op unless reporting is enabled + keyed.
 */

require __DIR__ . '/../vendor/autoload.php';

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Config\ConfigStore;
use Funnypot\App\ThreatIntel\AbuseIpdb;

// Store-backed config (FP-0242a): respawned each drain pass, so a live knob change is picked up next
// pass (own process + APCu segment + sentinel read). Fail-safe: degrades to env/default.
$config = AppConfig::fromStore(new ConfigStore(ConfigStore::defaultDbPath(__DIR__)), __DIR__);
if (!$config->abuseIpdbReport || $config->abuseIpdbKey === '') {
    exit(0);
}

try {
    $result = (new AbuseIpdb($config->abuseIpdbKey, $config->intelDbPath, $config->selfIps, $config->abuseIpdbDailyCap, $config->abuseIpdbDedupHours))->drain();
    if ($result['sent'] > 0 || $result['failed'] > 0) {
        fwrite(STDERR, sprintf("abuseipdb: sent %d, failed %d, pending %d\n", $result['sent'], $result['failed'], $result['pending']));
    }
} catch (Throwable $e) {
    fwrite(STDERR, 'abuseipdb: ' . $e->getMessage() . "\n");
}
