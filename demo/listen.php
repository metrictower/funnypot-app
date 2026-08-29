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
use Funnypot\Protocol\Vnc\VncConfig;
use Funnypot\Protocol\Vnc\VncServer;
use Funnypot\Protocol\Sip\SipConfig;
use Funnypot\Protocol\Sip\SipServer;
use Funnypot\Protocol\Rdp\RdpConfig;
use Funnypot\Protocol\Rdp\RdpServer;
use Funnypot\Protocol\Smb\SmbConfig;
use Funnypot\Protocol\Smb\SmbServer;
use Funnypot\Protocol\Mssql\MssqlConfig;
use Funnypot\Protocol\Mssql\MssqlServer;
use Funnypot\Protocol\Mqtt\MqttConfig;
use Funnypot\Protocol\Mqtt\MqttServer;
use Funnypot\Protocol\Snmp\SnmpConfig;
use Funnypot\Protocol\Snmp\SnmpServer;
use Funnypot\Protocol\Ldap\LdapConfig;
use Funnypot\Protocol\Ldap\LdapServer;
use Funnypot\Protocol\S7comm\S7commConfig;
use Funnypot\Protocol\S7comm\S7commServer;
use Funnypot\Protocol\Adb\AdbConfig;
use Funnypot\Protocol\Adb\AdbServer;
use Funnypot\Protocol\Bacnet\BacnetConfig;
use Funnypot\Protocol\Bacnet\BacnetServer;
use Funnypot\Protocol\Rtsp\RtspConfig;
use Funnypot\Protocol\Rtsp\RtspServer;

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
    // Anti-Spoofing Guard (B2): Only report when verified/reportable (e.g. not unverified UDP)
    if (($entry['reportable'] ?? true) && ($abuse !== null || $threatIntel !== null) && !empty($entry['ip'])) {
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

// VNC is a visual RFB 3.8 framebuffer honeypot: renders deception themes (FBI, Win95, TempleOS),
// injects clipboard, beeps, sets troll cursor, and logs clicks/keys.
if ($protocol === 'vnc') {
    $vncConfig = VncConfig::fromEnv();
    (new VncServer($vncConfig, $log))->run($bind);
    exit(0);
}

// SIP is an Asterisk PBX VoIP honeypot: answers OPTIONS/REGISTER, captures credentials and toll-fraud
// dialed numbers, and streams multi-persona audio tarpits (Lenny, Daisy, Dave, IVR, Fax).
if ($protocol === 'sip') {
    $sipConfig = SipConfig::fromEnv();
    (new SipServer($sipConfig, $log))->listen($bind);
    exit(0);
}

// RDP: X.224/MCS handshake honeypot — logs the mstshash cookie, requested security protocols and any
// credentials, selects a plausible protocol, never grants a session.
if ($protocol === 'rdp') {
    (new RdpServer(RdpConfig::fromEnv(), $log))->run($bind);
    exit(0);
}

// SMB2: NTLMSSP negotiate/session-setup honeypot — logs the negotiated dialect and captured NTLM
// credentials, answers plausibly, shares nothing.
if ($protocol === 'smb') {
    (new SmbServer(SmbConfig::fromEnv(), $log))->run($bind);
    exit(0);
}

// MSSQL/TDS: captures the SQL login (username, de-obfuscated password, host/app/library), then
// returns "login failed"; never authenticates.
if ($protocol === 'mssql') {
    (new MssqlServer(MssqlConfig::fromEnv(), $log))->run($bind);
    exit(0);
}

// MQTT broker honeypot: captures CONNECT creds/client-id + SUBSCRIBE/PUBLISH topics + payloads;
// acks so the client keeps talking, brokers nothing.
if ($protocol === 'mqtt') {
    (new MqttServer(MqttConfig::fromEnv(), $log))->run($bind);
    exit(0);
}

// SNMP agent (UDP): captures the brute-forced community string + requested OIDs; answers the system
// group only, anti-amplification (response never exceeds request, per-IP throttle); serves no real data.
if ($protocol === 'snmp') {
    (new SnmpServer(SnmpConfig::fromEnv(), $log))->run($bind);
    exit(0);
}

// LDAP directory honeypot: captures bind DN + password + search filters; denies by default, returns
// no directory data.
if ($protocol === 'ldap') {
    (new LdapServer(LdapConfig::fromEnv(), $log))->run($bind);
    exit(0);
}

// S7comm: Siemens S7 PLC honeypot (ISO-on-TCP 102) — COTP/S7 handshake, captures PLC memory-read
// and SZL enumeration; returns a plausible S7-1200/300 identity, exposes no real process data.
if ($protocol === 's7comm') {
    (new S7commServer(S7commConfig::fromEnv(), $log))->run($bind);
    exit(0);
}

// ADB: Android Debug Bridge honeypot (5555) — presents an auth-free device, captures the shell/exec
// commands + pushed payloads botnets deliver; executes nothing.
if ($protocol === 'adb') {
    (new AdbServer(AdbConfig::fromEnv(), $log))->run($bind);
    exit(0);
}

// BACnet: building-automation honeypot (UDP 47808) — answers Who-Is/ReadProperty with a persona
// device, captures device/point enumeration; anti-amplification; serves no real building data.
if ($protocol === 'bacnet') {
    (new BacnetServer(BacnetConfig::fromEnv(), $log))->run($bind);
    exit(0);
}

// RTSP: camera/DVR honeypot (554) — captures the requested stream path (camera-model fingerprint) +
// Basic/Digest credentials; returns a plausible SDP but streams no real media.
if ($protocol === 'rtsp') {
    (new RtspServer(RtspConfig::fromEnv(), $log))->run($bind);
    exit(0);
}

$set = ProtocolTemplateSet::fromPackage($fsSeed, $fsSecret);
$emulator = $set->emulator($protocol);
if ($emulator === null) {
    fwrite(STDERR, "unknown protocol '{$protocol}' (have: " . implode(', ', $set->ids()) . ")\n");
    exit(2);
}

(new Listener($emulator, $protocol, $log))->run($bind);
