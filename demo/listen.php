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
use Funnypot\App\Config\ConfigStore;
use Funnypot\App\Identity\IdentityBootstrapException;
use Funnypot\App\Identity\IdentityPaths;
use Funnypot\App\Identity\ShellIdentity;
use Funnypot\App\Identity\SipIdentity;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\App\ThreatIntel\OperatorBlocklist;
use Funnypot\App\ThreatIntel\ReportGate;
use Funnypot\App\ThreatIntel\ThreatIntelReporter;
use Funnypot\App\Emulation\EmulationPolicy;
use Funnypot\Protocol\Listener;
use Funnypot\Protocol\ProtocolTemplateSet;
use Funnypot\Protocol\Ssh\HostKey\HostKeySet;
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
use Funnypot\Protocol\Stun\StunConfig;
use Funnypot\Protocol\Stun\StunServer;
use Funnypot\Protocol\Dnp3\Dnp3Config;
use Funnypot\Protocol\Dnp3\Dnp3Server;
use Funnypot\Protocol\Ipmi\IpmiConfig;
use Funnypot\Protocol\Ipmi\IpmiServer;
use Funnypot\Protocol\Coap\CoapConfig;
use Funnypot\Protocol\Coap\CoapServer;
use Funnypot\Protocol\Kerberos\KerberosConfig;
use Funnypot\Protocol\Kerberos\KerberosServer;
use Funnypot\Protocol\Ntp\NtpConfig;
use Funnypot\Protocol\Ntp\NtpServer;
use Funnypot\Protocol\Cassandra\CassandraConfig;
use Funnypot\Protocol\Cassandra\CassandraServer;
use Funnypot\Protocol\Winrm\WinrmConfig;
use Funnypot\Protocol\Winrm\WinrmServer;
use Funnypot\Protocol\Oracle\OracleConfig;
use Funnypot\Protocol\Oracle\OracleServer;
use Funnypot\Protocol\Tr069\Tr069Config;
use Funnypot\Protocol\Tr069\Tr069Server;

$protocol = $argv[1] ?? '';
$bind = $argv[2] ?? '';
if ($protocol === '' || $bind === '') {
    fwrite(STDERR, "usage: php demo/listen.php <protocol> <host:port>\n");
    exit(2);
}

// Store-backed config (FP-0242a): this listener is long-lived (a select loop), so it reads the store
// once at boot; the protocol knobs it uses are restart-required (spec §4), picked up on respawn.
// Fail-safe: an unreadable store degrades to the env/default baseline.
$config = AppConfig::fromStore(new ConfigStore(ConfigStore::defaultDbPath(__DIR__)), __DIR__);
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
// Operator manual blocklist — read here so every protocol listener drops a blocked source before any
// session/response (silent, reflection-safe). Long-lived loop → the helper caches + reloads periodically,
// so per-packet cost is O(1). Same intel.sqlite the dashboard writes; always active.
$operatorBlock = new OperatorBlocklist($config->intelDbPath);
$port = (int) substr($bind, (int) strrpos($bind, ':') + 1);
$categories = AbuseIpdb::categoriesForProtocol($protocol);

$log = static function (array $entry) use ($store, $abuse, $threatIntel, $protocol, $port, $categories): void {
    $store->append($entry);
    // Anti-Spoofing Guard (FP-0247, Fix A): report only through the fail-closed gate. An event that
    // does not carry an explicit `reportable => true` (e.g. a single spoofable UDP datagram) is NEVER
    // reported. The whole gate + enqueue decision lives in ReportGate so there is one wiring to test.
    if (ReportGate::shouldReport($entry)) {
        ReportGate::maybeReport($entry, $abuse, $threatIntel, $protocol, $port, $categories);
    }
};

// Honour the emulation catalog: a service switched off in funnypot-vulns.json does not bind.
// (Toggling a service needs a listener restart — the entrypoint relaunches on redeploy.)
$policy = EmulationPolicy::fromPackage(is_file($config->vulnsPath) ? $config->vulnsPath : null);
if (!$policy->isEnabled('service-' . $protocol)) {
    fwrite(STDERR, "funnypot-listen {$protocol}: disabled in emulation catalog — not binding {$bind}\n");
    exit(0);
}

// Install identity: each listener loads ONLY the named root-only bundle it consumes (written by
// `identity:prepare` before this process was spawned) — the shell view carries the persona seed plus
// the private filesystem key that defeats oracle-replay of the procedural filesystem; the persona-only
// view carries no key at all. A missing/tampered bundle aborts here, BEFORE any socket binds: no
// listener ever degrades to seed zero, a per-process secret or a fleet-shared persona.
$identityPaths = IdentityPaths::forStorage(dirname($config->dbPath), getenv(IdentityPaths::RUNTIME_ENV) ?: null);
$loadIdentity = static function (callable $loader) use ($identityPaths, $protocol) {
    try {
        return $loader($identityPaths);
    } catch (IdentityBootstrapException $e) {
        fwrite(STDERR, "funnypot-listen {$protocol}: identity bootstrap failed: {$e->errorCode()} ({$e->remedy()}) — not binding\n");
        exit(1);
    }
};
$shellIdentity = static fn (): ShellIdentity => $loadIdentity([ShellIdentity::class, 'load']);
$personaMaterial = static fn (): string => $loadIdentity([SipIdentity::class, 'load'])->personaMaterial();

// SSH is a full crypto server (pure PHP), not a data-driven emulator: it terminates the
// SSH-2.0 handshake and drops the attacker into the same fake shell telnet uses.
if ($protocol === 'ssh') {
    $keyPath = getenv('FUNNYPOT_SSH_HOSTKEY') ?: __DIR__ . '/storage/ssh_host_ed25519';
    $shell = $shellIdentity();
    (new SshServer(HostKeySet::load($keyPath), $log, identitySeed: $shell->personaSeed(), secret: $shell->filesystemKey()))->run($bind);
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
    $sipConfig = SipConfig::fromEnv($loadIdentity([SipIdentity::class, 'load']));
    (new SipServer($sipConfig, $log, null, null, null, $operatorBlock))->listen($bind);
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
    (new SmbServer(SmbConfig::fromEnv($personaMaterial()), $log))->run($bind);
    exit(0);
}

// MSSQL/TDS: captures the SQL login (username, de-obfuscated password, host/app/library). In the
// default high-interaction mode it then accepts the login (mock-auth, never verified), answers recon
// queries with fabricated persona result-sets, and traps the xp_cmdshell / RCE chain — capturing the
// full attacker command while staying 100% inert. FUNNYPOT_MSSQL_MODE=low restores the deny path.
if ($protocol === 'mssql') {
    (new MssqlServer(MssqlConfig::fromEnv($personaMaterial()), $log))->run($bind);
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

// STUN (UDP): NAT-discovery responder that rounds out the VoIP footprint next to SIP. Answers a
// Binding Request with the client's mapped address, logs the probe; anti-amplification, no TURN relay.
if ($protocol === 'stun') {
    (new StunServer(StunConfig::fromEnv(), $log))->run($bind);
    exit(0);
}

// DNP3: SCADA outstation honeypot (20000) — COTP-free DNP3 link/app layer; captures master addresses +
// object enumeration; refuses control functions, actuates nothing.
if ($protocol === 'dnp3') {
    (new Dnp3Server(Dnp3Config::fromEnv(), $log))->run($bind);
    exit(0);
}

// IPMI (UDP): BMC honeypot (623) — captures RAKP usernames (CVE-2013-4786 hash-disclosure vector) +
// auth attempts; never authenticates; anti-amplification.
if ($protocol === 'ipmi') {
    (new IpmiServer(IpmiConfig::fromEnv($personaMaterial()), $log))->run($bind);
    exit(0);
}

// CoAP (UDP): IoT honeypot (5683) — captures method + Uri-Path/Query + payload; refuses writes;
// anti-amplification.
if ($protocol === 'coap') {
    (new CoapServer(CoapConfig::fromEnv(), $log))->run($bind);
    exit(0);
}

// Kerberos: KDC honeypot (88) — captures AS-REQ principal + realm (AS-REP-roast / user enumeration);
// returns KRB-ERROR, issues no ticket.
if ($protocol === 'kerberos') {
    (new KerberosServer(KerberosConfig::fromEnv(), $log))->run($bind);
    exit(0);
}

// NTP (UDP 123): answers a client time query with a plausible stratum-2 server; refuses mode 6/7
// (monlist) so it can never be a reflector; captures the probe. Anti-amplification.
if ($protocol === 'ntp') {
    (new NtpServer(NtpConfig::fromEnv(), $log))->run($bind);
    exit(0);
}

// Cassandra (CQL 9042): OPTIONS/STARTUP/AUTH handshake — captures the driver name/version and the
// SASL PLAIN username/password, then returns bad-credentials; opens no keyspace, serves no data.
if ($protocol === 'cassandra') {
    (new CassandraServer(CassandraConfig::fromEnv(), $log))->run($bind);
    exit(0);
}

// WinRM (HTTP 5985): WS-Management endpoint — challenges Negotiate/Basic, captures Basic cleartext
// and the NTLM type-3 username/domain/workstation; always denies, never runs a command.
if ($protocol === 'winrm') {
    (new WinrmServer(WinrmConfig::fromEnv(), $log))->run($bind);
    exit(0);
}

// Oracle TNS (1521): TNS connect handshake — captures the requested service/SID and connect
// descriptor; returns a plausible refuse/redirect, exposes no database.
if ($protocol === 'oracle') {
    (new OracleServer(OracleConfig::fromEnv(), $log))->run($bind);
    exit(0);
}

// TR-069 / CWMP (HTTP 7547/7548): poses as a vulnerable broadband gateway (CPE) exposing its TR-064 /
// CWMP config service on the WAN port. Accepts the router worm's SOAP command-injection, returns a
// plausible success frame so the worm believes it succeeded, and captures the injected shell command +
// malware C2 download URL as intel. Never runs a command, never fetches a captured URL, never an ACS.
if ($protocol === 'cwmp' || $protocol === 'tr069') {
    (new Tr069Server(Tr069Config::fromEnv(), $log))->run($bind);
    exit(0);
}

$shell = $shellIdentity();
$set = ProtocolTemplateSet::fromPackage($shell->personaSeed(), $shell->filesystemKey());
$emulator = $set->emulator($protocol);
if ($emulator === null) {
    fwrite(STDERR, "unknown protocol '{$protocol}' (have: " . implode(', ', $set->ids()) . ")\n");
    exit(2);
}

(new Listener($emulator, $protocol, $log, $operatorBlock))->run($bind);
