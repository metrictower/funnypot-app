<?php

declare(strict_types=1);

/**
 * Start one protocol listener, logging into the same store the dashboard reads — so redis /
 * ftp / smtp / ssh connections and every command an attacker sends show up on the dashboard
 * alongside the HTTP probes.
 *
 *   php demo/listen.php redis 0.0.0.0:6379
 *
 * The demo entrypoint launches one of these per protocol. Runs forever (a select loop).
 */

require __DIR__ . '/../vendor/autoload.php';

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\App\ThreatIntel\ThreatIntelReporter;
use Funnypot\App\Emulation\EmulationPolicy;
use Funnypot\Protocol\Listener;
use Funnypot\Protocol\ProtocolTemplateSet;
use Funnypot\Protocol\Ssh\HostKey;
use Funnypot\Protocol\Ssh\SshServer;

$protocol = $argv[1] ?? '';
$bind = $argv[2] ?? '';
if ($protocol === '' || $bind === '') {
    fwrite(STDERR, "usage: php demo/listen.php <protocol> <host:port>\n");
    exit(2);
}

$config = AppConfig::fromEnv(__DIR__);
@mkdir(dirname($config->logPath), 0777, true);
$store = new SqliteHitStore($config->dbPath, $config->logPath);

// Optional AbuseIPDB reporting: queue the attacker IP (with the port + protocol) as each command /
// login / connection is logged. Enqueue is a local write, so the select loop never blocks; a
// background worker sends the queued reports.
$abuse = ($config->abuseIpdbReport && $config->abuseIpdbKey !== '')
    ? new AbuseIpdb($config->abuseIpdbKey, $config->intelDbPath, $config->selfIps, $config->abuseIpdbDailyCap, $config->abuseIpdbDedupHours)
    : null;
// Threat Intel reporting to our own funnypot-mainnet service (enqueue-only here; a background worker
// drains). Independent of AbuseIPDB; both may be armed at once.
$threatIntel = ($config->threatIntelReport && $config->threatIntelKey !== '')
    ? new ThreatIntelReporter($config->threatIntelUrl, $config->threatIntelKey, $config->intelDbPath, $config->selfIps, $config->threatIntelDailyCap, $config->threatIntelDedupHours)
    : null;
$port = (int) substr($bind, (int) strrpos($bind, ':') + 1);
$categories = AbuseIpdb::categoriesForProtocol($protocol);

$log = static function (array $entry) use ($store, $abuse, $threatIntel, $protocol, $port, $categories): void {
    $store->append($entry);
    if (($abuse !== null || $threatIntel !== null) && !empty($entry['ip'])) {
        $event = (string) ($entry['event'] ?? '');
        $data = trim(substr((string) ($entry['path'] ?? $entry['body'] ?? ''), 0, 100));
        $comment = sprintf('funnypot %s honeypot, port %d: %s %s', strtoupper($protocol), $port, $event, $data);
        $abuse?->enqueue((string) $entry['ip'], $comment, $categories);
        $threatIntel?->enqueue((string) $entry['ip'], $comment, $categories);
    }
};

// Honour the emulation catalog: a service switched off in funnypot-vulns.json does not bind.
// (Toggling a service needs a listener restart — the entrypoint relaunches on redeploy.)
$policy = EmulationPolicy::fromPackage(is_file($config->vulnsPath) ? $config->vulnsPath : null);
if (!$policy->isEnabled('service-' . $protocol)) {
    fwrite(STDERR, "funnypot-listen {$protocol}: disabled in emulation catalog — not binding {$bind}\n");
    exit(0);
}

// The fake shell's host identity: the deploy persona seed (so it's stable per deploy) + a private,
// persisted per-install secret (keys the procedural filesystem against oracle-replay; never committed).
$fsSecret = \Funnypot\Shell\Fs\HostSecret::resolve(__DIR__ . '/storage');
$fsSeed = $config->personaSeed;

// SSH is a full crypto server (pure PHP), not a data-driven emulator: it terminates the
// SSH-2.0 handshake and drops the attacker into the same fake shell telnet uses.
if ($protocol === 'ssh') {
    $keyPath = getenv('FUNNYPOT_SSH_HOSTKEY') ?: __DIR__ . '/storage/ssh_host_ed25519';
    (new SshServer(HostKey::load($keyPath), $log, identitySeed: $fsSeed, secret: $fsSecret))->run($bind);
    exit(0);
}

$set = ProtocolTemplateSet::fromPackage($fsSeed, $fsSecret);
$emulator = $set->emulator($protocol);
if ($emulator === null) {
    fwrite(STDERR, "unknown protocol '{$protocol}' (have: " . implode(', ', $set->ids()) . ")\n");
    exit(2);
}

(new Listener($emulator, $protocol, $log))->run($bind);
