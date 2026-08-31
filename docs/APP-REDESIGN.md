# FunnyPot Standalone-App Redesign — Brainstorm

Status: brainstorm to react to, not final code. funnypot-core (the HTTP nuclei-inversion
engine, `metrictower/funnypot-core` v0.1.0) is FROZEN. This document only redesigns the app
that consumes it.

---

## 1. Vision

FunnyPot becomes a self-hostable, single-binary-feel honeypot appliance that can wear a
disguise. Today `demo/index.php` is a 632-line front controller that is simultaneously a
router, an admin API, an HTML view, a CSS file, a JS file, and the honeypot policy site
(Scout A section 6). The redesign graduates it into a small real app with a clear split
between the honeypot layer (already clean, in funnypot-core plus `src/Protocol`), a typed
ingest boundary, a proper database with retention, an operator dashboard, and threat-intel
enrichment lifted from iCabbiTools. The headline new capability is a STEALTH mode: the
outside world sees a believable "Globex Corporation" corporate site, only bots discover the
trap, and the operator dashboard plus the live honeypot move to hidden paths. All of this
stays optional and env-driven so today's PUBLIC behaviour is still one switch away.

---

## 2. Honeypot modes — STEALTH vs PUBLIC

A single config switch, `FUNNYPOT_MODE=public|stealth` (default `public` to preserve today's
behaviour), selects the whole posture. It is read once in the new `AppConfig::fromEnv()`
(see section 6) and drives routing.

### PUBLIC mode (today's behaviour, preserved)

- What a visitor sees: hit anything and the honeypot answers. funnypot-core synthesizes a
  fake vulnerable response, or a believable nginx 404 (`demo/index.php:176-178`). The
  honeypot "gives itself away" on purpose (gate always open, `demo/index.php:110`).
- Dashboard lives at: bare `GET /` with no query string, or `GET /?feed` (the fragile
  `$_GET === []` discriminator, `demo/index.php:89-102`). We keep this but formalize it.
- Honeypot logic sits: at every other path, inline in the router today.
- Corporate front / spider-trap: not served in this mode (nothing to disguise).

### STEALTH mode (new)

- What a visitor sees: a fake corporate marketing site at `/` ("Welcome to Globex
  Corporation"), a fake employee login at `/login`, and normal-looking 404s elsewhere. A
  human sees a boring company site. There is no honeypot in view.
- Dashboard lives at: a hidden, operator-only path, e.g. `/__fp/` (matches the `/__fp/<name>`
  asset route already planned in `docs/DEMO-DASHBOARD-PLAN.md:40-56`), gated by
  `FUNNYPOT_ADMIN_PASSWORD` (already the admin gate, `demo/index.php:325`).
- Honeypot logic sits: at `/honeypot` (Bob's chosen path) and at the bot-only trap paths the
  corporate site hides. Real honeypot detection/response still runs there via funnypot-core,
  unchanged. The 18 TCP protocol listeners (Scout A section 4) keep running regardless of
  mode; they are not part of the HTTP disguise.
- Corporate front + login + spider-trap: this IS the outward face in stealth mode. Hidden
  links only bots follow lead from the corporate pages to the trap, which scores the IP and
  can escalate (section 3).

Option A — mode is a hard fork in routing (two separate route tables).
  Tradeoff: cleanest separation, easy to reason about; small duplication of the shared
  honeypot dispatch.
Option B — mode is a flag threaded through one router (today's if-chain, extended).
  Tradeoff: less code, but keeps the "one giant if-chain" smell Scout A flagged.

RECOMMENDATION: Option A. A small router class with two registered route tables selected by
`FUNNYPOT_MODE`. Both tables call the same honeypot dispatch function and the same typed
ingest writer, so there is no duplicated honeypot logic, only duplicated wiring. This also
kills the fragile `$_GET === []` dashboard discriminator by giving each concern a real path.

---

## 3. The fake corporate front (stealth mode)

Reuse the iCabbiTools spider-trap technique wholesale. It is almost entirely portable pure
PHP and string logic (Scout B section 5, Scout C section 1).

### Pages

- `/` — "Globex Corporation" homepage: logo, nav (Products / About / Careers / Contact),
  hero banner. Rendered like a real corp site. Mirror the iCabbiTools bait: `robots.txt`
  `Disallow` list pointing at `/admin/`, `/portal/`, `/backend/` (mirrors
  `HoneyPotController::robotsTxt()` at `HoneyPotController.php:336-353` and funnypot's own
  `demo_robots()` at `demo/index.php:253-266`).
- `/login` — "Globex Employee Portal" sign-in, modeled 1:1 on iCabbiTools
  `resources/views/login.blade.php`. The visible form posts to a FAKE endpoint; a hidden
  `style="visibility:hidden"` anchor (`login.blade.php:29`) links to a random trap URL.
- Trap page — the `spider-baby` equivalent (`spider-baby.blade.php`,
  `HoneyPotController::spiderBaby()` at `HoneyPotController.php:288-303`).

### Real vs bot traffic separation (copy the exact iCabbiTools mechanism)

- Hidden bot-only links: `MAD_PATHS = ['frontend','backend','dashboard','controlpanel',
  'console']` (`HoneyPotController.php:22`), each rendered as a unique random slug via
  `ranoNounAdjUrl()` (`HoneyPotController.php:305-307`) so scanners cannot dedup by URL. The
  links sit inside `style="visibility:hidden"` divs and HTML-comment noise so no sighted
  human clicks them but a crawler following hrefs does (Scout C section 1).
- Fake-vs-real endpoint split: the visible form action points at a fake endpoint; only JS
  swaps it to a real one after passing checks (iCabbiTools `routes/web/login.php:4-9`). A
  non-JS bot that submits raw HTML hits the fake endpoint and is scored.
- Scoring on contact: GET the trap = soft signal (+10 in iCabbiTools). POST the trap (filled
  a hidden form) = instant max score plus `badbot=true`, and the trap page escalates into a
  DOM-bomb (`spider-baby.blade.php:26-28`). We map this onto funnypot's existing
  severity/persona plumbing rather than reinventing a scorer (Scout C section 3).

### Theme coexistence (keep the current dark theme)

Two distinct visual skins, never mixed:
- Operator dashboard keeps the current amber-on-near-black monospace identity untouched:
  `--bg:#12100c --panel:#1c1913 --ink:#f3e9d2 --muted:#a8987a --amber:#f0b400 --red:#ff6b5e
  --line:#2e2a20`, `ui-monospace` font (Scout C section 4, `demo/index.php:406-475`). Bob
  likes this; it does not change.
- Globex disguise pages are a separate "corporate SaaS" skin (clean Tabler/BS5-style login
  card look, like iCabbiTools `layouts.modern-unauthenticated`). They are served only to the
  outside world and must look nothing like the operator console.

Option A — extract both skins into real CSS files under `demo/assets/` (or `public/`), drop
the Leaflet CDN by vendoring it (the only external assets today, `demo/index.php:595,628`).
Option B — leave the dark theme inline as a heredoc, add the corporate skin as a second
heredoc.

RECOMMENDATION: Option A. The dark tokens lift into a standalone `.css` with zero visual
change (Scout A section 5), the corporate skin gets its own file, and we finally execute the
file-split half of `docs/DEMO-DASHBOARD-PLAN.md` Phase 1 that never landed.

---

## 4. Data layer — move to a proper database

> DECISION (locked, single-box): SQLite-canonical, one file per concern (`hits.db` /
> `intel.db` / `geo.db`) so a bulk blocklist refresh never locks ingest; an hourly rollup
> table keeps the dashboard tick O(1); retention by days + GB; optional Litestream for
> continuous S3 backup + point-in-time restore. No Redis. Postgres-for-all is deferred until
> there is a second honeypot node (kept cheap by the `HitStore` interface). Full reasoning +
> load numbers: docs/DATA-LAYER-DECISION.md.

> BUILT (FP-0243a): the rollup layer landed as an incremental background worker rather than
> per-ingest counters (an APCu-counters design is unsafe here — the ~40 CLI protocol listeners
> do not share the php-fpm APCu segment, so it would undercount protocol traffic; SQLite/WAL is
> the only cross-process source of truth). `demo/rollup.php` folds new `hits` since a watermark
> into a `rollup` table in `hits.db` on a ~15s timer, at per-minute grain downsampled to hour +
> day, with a top-K cardinality cap so a sprayed dimension can't inflate storage. Reads go
> through a new `Storage\AnalyticsStore` (`breakdown`/`series`/`topN`/`ataglance`), O(buckets)
> and flat in event volume; `append()` is unchanged. The operator analytics **views** over this
> API are FP-0243b.

Today: JSON-lines file is canonical, SQLite is a best-effort mirror that silently no-ops on
any failure (Scout A section 2, `store.php:16-25`). Three divergent row shapes (HTTP hit,
decoy-archive, TCP protocol) all land in one loose `hits` table and consumers `??`-coalesce
everywhere (Scout A section 2).

### Option 1 — SQLite-by-default, canonical (not a mirror)

Make SQLite the single source of truth, drop the JSON-lines file to an optional export.
Tradeoff: zero new infra, WAL mode already handles the concurrent php-fpm + root listener
writers (`store.php` pragmas, umask(0) at `store.php:292-295`); but a single SQLite file
strains past a few hundred writes/sec and one very busy honeypot could bottleneck.

### Option 2 — Postgres/MySQL opt-in via a storage interface

Define a `HitStore` interface with SQLite and Postgres/MySQL implementations, selected by
`FUNNYPOT_DB_DSN`. Tradeoff: real concurrency and retention-by-query at scale; but adds a
dependency and ops burden most single-node deployments do not need.

RECOMMENDATION: Do both, in order. Ship Option 1 first (SQLite canonical behind a `HitStore`
interface, file becomes optional export). Add the Postgres/MySQL implementation behind the
same interface as an opt-in when someone actually needs it. The interface is the important
part; it is what Scout A section 6 point 3 already recommended (interface plus swappable
backends instead of one class branching on `$this->db !== null`).

### Migration path from today's file+sqlite store

1. Keep reading the JSON-lines log as the import source (the existing `?admin=import`
   backfill already does exactly this, Scout A section 1).
2. On first boot of the new version, if the canonical DB is empty and a log exists, run the
   import once to seed it.
3. After that the log is write-optional (kept only if `FUNNYPOT_LOG` is set, for operators
   who want a tail-able file). No data is lost; the log stops being canonical.

### Schema sketch

Split the one loose table into typed tables behind the typed ingest boundary (HttpHit,
DecoyHit, ProtocolHit value objects, Scout A section 6 point 2):

```
hits            id, ts, ip, method, path, ua, matched, severity, served,
                templates(json), style, body, referer, log4shell, honeytoken,
                source ENUM('http','decoy','protocol'), known_attacker BOOL
protocols       id, hit_id FK, proto, port, event('connect'|'login'|'command'),
                data(command/payload text), user, pass
                -- protocol-specific columns instead of overloading `hits.method`
                -- INDEX (proto, event, ts) so "all SSH commands" is an indexed scan (section 6b)
threat_intel    ip PRIMARY, in_blocklists INT, sources(json), abuseipdb_score INT,
                is_tor BOOL, reported_at, checked_at, ttl
geo             ip PRIMARY, cc, city, asn, lat, lon, resolved_at
                -- city/asn are dead columns today (store.php:298-309); make them real or drop
```

Keep enrichment at write time as today (`demo/index.php:157`) so historical rows are stable.
The `known_attacker` flag (section 5) is computed at write time from `threat_intel`.

### Retention / pruning (max-GB or max-days)

Config knobs (both optional, off by default = today's unbounded behaviour):
- `FUNNYPOT_RETAIN_DAYS` — delete hits older than N days.
- `FUNNYPOT_RETAIN_GB` — cap total DB size; when exceeded, delete oldest rows until under cap.

Enforcement options:
Option A — inline on write: every Nth `append()` runs a cheap prune. Tradeoff: no cron
needed, self-contained; adds latency spikes to some requests.
Option B — a periodic prune process (cron or a loop in the entrypoint). Tradeoff: clean, no
request-path cost; needs a scheduler.

RECOMMENDATION: Option B, reusing the existing `?admin=prune` action (`demo/index.php`) as
the prune primitive, invoked by a cron entry the entrypoint installs. Days-based prune is a
simple `DELETE WHERE ts < cutoff`. GB-based prune loops `DELETE ... ORDER BY id ASC LIMIT
10000` until `PRAGMA page_count * page_size` is under the cap, then `VACUUM` (or `pg_total_
relation_size` for Postgres). Note the file-mode byte-offset cursor is invalidated by prune
today (Scout A section 2); moving canonical storage to the DB and using the `id` cursor fixes
that class of bug for free.

---

## 5. Threat intel (port from iCabbiTools)

Portability is graded in Scout B. Summary: fetch/parse and report call-shapes are copy-near-
verbatim pure PHP + Guzzle; the Redis cache design is portable with facade swaps; the full
Laravel orchestration must be rebuilt lightly.

### Blocklist ingestion (PORTABLE)

- Copy `URLBlocklistService::BLOCKLIST_URLS` (~85 sources), `fetchFromUrl()`,
  `extractIpFromLine()` verbatim — pure regex + `filter_var`, no Laravel
  (`app/Services/URLBlocklistService.php:27-299`, Scout B section 1). This already includes
  the AbuseIPDB precomputed list as one of the URLs (no API key needed).

### Cache + refresh for a non-Laravel app (PORTABLE DESIGN, facade swap)

- Reuse the Redis-Set-per-source design: key `ip_blocklist:<source>`, batched SADD of 10,000,
  24h TTL, O(1) `SISMEMBER` lookup, stale-key sweep (`IPBlocklistCacheService.php`, Scout B
  section 2). Swap Laravel facades for a `phpredis`/`predis` client and a PSR-3 logger.
- Refresh: Laravel scheduler `hourlyAt(9)->onOneServer()` becomes a plain cron entry plus a
  Redis `SETNX` lock for the one-run guarantee (Scout B section 2). The entrypoint already
  spawns processes (Scout A section 4), so add one cron.
- Multi-source corroboration rule ports as-is: URL-list sources need appearing in MORE THAN N
  distinct lists (default 2) before flipping banned (`IPBlocklistCacheService.php:41-69`).

Option A — require Redis for the cache. Tradeoff: matches iCabbiTools exactly, fastest; adds
a dependency to a currently-Redis-free app.
Option B — cache blocklists in the same SQLite/Postgres DB (a `threat_intel` membership
table). Tradeoff: no new dependency, one storage system; slower than SISMEMBER but fine at
honeypot volumes.

RECOMMENDATION: Option B for the default single-node build (fold blocklist membership into
the DB, no Redis dependency), with the `HitStore`-style interface allowing a Redis backend
opt-in later for high-volume deployments. This keeps the appliance dependency-light.

### "Known attacker" flag on the dashboard (REBUILD, small)

- Compute at write time: if the client IP is in the blocklist membership set OR has an
  AbuseIPDB score over the dynamic threshold, set `hits.known_attacker = true`.
- Threshold logic ports directly: `getBanThreshold()` returns 60 for Mobile ISP, 40 for
  Data Center/Hosting, 50 default; `exceedsBanThreshold()` applies it
  (`AbuseIPDBService.php:35-62`, Scout B section 3).
- Dashboard renders a badge in the existing badge language (`.served`/`.scan`/`.miss`, Scout
  C section 4) — add a `.known` badge in red, plus a filter and a top-talkers highlight.

### AbuseIPDB reporting (PORTABLE call, REBUILD throttle)

- `reportIP()` is a pure Guzzle POST to `/api/v2/report`, `categories='21'` (Web App Attack),
  ISO-8601 timestamp, `Key` header (`AbuseIPDBService.php:217-253`, Scout B section 4).
  Copy near-verbatim, swap `Cache::` for a DB/Redis TTL store.
- Throttle: per-IP 6h dedup cache key (`<ip>-reported-ip3`, 21600s) bounds volume
  (`AbuseIPDBService.php:219-224`). Add explicit awareness of the ~1000/day free-tier cap,
  which iCabbiTools does NOT guard (Scout B section 4) — a simple daily counter that stops
  reporting when near the cap.
- INVARIANT (Bob, non-negotiable): AbuseIPDB reporting MUST self-exclude our own IP. Add an
  allowlist that always contains the honeypot's own public IP(s) and refuses to report them,
  mirroring iCabbiTools' upstream allowlist check that refuses to report trusted IPs
  (`reportIPWithDetails` allowlist guard, `IPSecurityService.php:882-886`). Resolve our own
  IP at boot (env `FUNNYPOT_SELF_IPS`, plus auto-detect) and hard-skip it before any report
  call. This prevents a self-report feedback loop where the honeypot flags itself.

### Must-rebuild (do NOT port wholesale)

`IPSecurityService` orchestration, Eloquent models (`BlockedIP`, `CheckedIP`, `ReportIP`,
`AllowlistedIP`), Slack buffering, `ShadowBanJob` dispatch, `Settings` feature flags (Scout B
summary). Rebuild only the algorithm against the new `HitStore`/`threat_intel` tables.

---

## 6. App architecture + config

Should the code graduate from the `demo/` front controller into a real app structure? Yes.
Scout A section 6 documents exactly how tangled it is: one file is router + admin API + view
+ CSS + JS + policy site, and `Store`/`Geo` are global-namespace `require`d classes while the
only real namespacing (`Funnypot\...`) lives in the library code.

Option A — full framework (Slim / Laravel). Tradeoff: batteries included; heavy dependency,
against the current no-framework, single-file-deploy ethos.
Option B — a thin hand-rolled app structure: a small router class, PSR-4 autoloaded `App\`
namespace, config object, controllers, storage interface. Tradeoff: keeps the light ethos and
the existing `Honeypot`/`Listener` seams; we write a little plumbing ourselves.

RECOMMENDATION: Option B. Proposed shape:

```
src/                       (funnypot-core stays a composer dep; app code is PSR-4 App\)
  App/
    Config/AppConfig.php        single Config::fromEnv() — one source of truth (see below)
    Http/Router.php             two route tables (public/stealth) selected by FUNNYPOT_MODE
    Http/HoneypotController.php  wraps funnypot-core detect/respond + typed ingest
    Http/DashboardController.php live feed, widgets, admin actions (moved off the router)
    Http/CorporateController.php Globex homepage + fake login + spider-trap (stealth)
    Ingest/HttpHit.php, DecoyHit.php, ProtocolHit.php   typed value objects
    Ingest/HitWriter.php        one validated write path all three sources call
    Storage/HitStore.php        interface; SqliteHitStore, PgHitStore implementations
    ThreatIntel/Blocklist.php, AbuseIPDB.php, Geo.php
  Protocol/                     UNCHANGED — 18 TCP listeners keep running (Scout A section 4)
public/
  index.php                     tiny front controller: bootstrap + Router::dispatch()
  assets/app.css, corporate.css, app.js, leaflet.{css,js}   vendored, no CDN
```

- Routing: `Router` maps paths to controllers; funnypot-core plugs in exactly where it does
  today (`Honeypot::default($config)` then `detect()`/`respond()`, `demo/index.php:105-133`),
  now inside `HoneypotController` instead of the router if-chain.
- funnypot-core plug point unchanged: `Config` value object with the same closures; we only
  move the `getenv()` reads out of the routing function into `AppConfig::fromEnv()`, removing
  the pattern of re-deriving the same default path three times (`FUNNYPOT_VULNS` repeated at
  `demo/index.php:108,360,369`, `listen.php:38`, `vulns-sync.php:18`, Scout A section 3/6).
- Protocol listeners: keep `demo/listen.php`'s per-protocol process model and the shared
  `Store`/`HitWriter` seam (`listen.php:34` passes `fn($e) => $store->append($e)`). They just
  call the new `HitWriter` instead of raw `Store::append`.

### Full config surface

New:
- `FUNNYPOT_MODE` = `public` | `stealth` (default `public`)
- `FUNNYPOT_DB_DSN` — Postgres/MySQL opt-in; unset = SQLite (default)
- `FUNNYPOT_RETAIN_DAYS` — prune hits older than N days (unset = unbounded)
- `FUNNYPOT_RETAIN_GB` — cap DB size in GB (unset = unbounded)
- `FUNNYPOT_BLOCKLIST` = on|off — enable blocklist ingestion (default off)
- `FUNNYPOT_BLOCKLIST_REDIS` — optional Redis DSN for the blocklist cache backend
- `FUNNYPOT_ABUSEIPDB_KEY` — enables reporting + live checks
- `FUNNYPOT_ABUSEIPDB_REPORT` = on|off (default off; requires key)
- `FUNNYPOT_SELF_IPS` — comma list of our own public IPs, always self-excluded from reporting
- `FUNNYPOT_ABUSEIPDB_DAILY_CAP` — report cap guard (default ~1000, free tier)
- `FUNNYPOT_DASHBOARD_PATH` — hidden dashboard path in stealth mode (default `/__fp/`)

Existing (carried forward, unchanged — Scout A section 3): `FUNNYPOT_STYLE`, `FUNNYPOT_LOG`,
`FUNNYPOT_DB`, `FUNNYPOT_GEO_DB`, `FUNNYPOT_POWERED_BY`, `FUNNYPOT_HONEYTOKEN_KEY`,
`FUNNYPOT_CEILING`, `FUNNYPOT_LATENCY_MS`, `FUNNYPOT_JITTER_MS`, `FUNNYPOT_ATTACK`,
`FUNNYPOT_VULNS`, `FUNNYPOT_DECOY_ARCHIVE`, `FUNNYPOT_ADMIN_PASSWORD`, `FUNNYPOT_PROTOCOLS`,
`FUNNYPOT_SSH_HOSTKEY`, `FUNNYPOT_SSH_REJECT_BUDGET`, `FUNNYPOT_CN`, `FUNNYPOT_PUBLIC_DNS`,
`FUNNYPOT_LE_DOMAIN`. Deploy-script-only vars stay separate and out of the app config
(`FUNNYPOT_HOST`, `FUNNYPOT_USER`, `FUNNYPOT_KEY`, `FUNNYPOT_PLATFORM`, `FUNNYPOT_SSH_PORT`,
`FUNNYPOT_SSH_ON_22` — Scout A section 3).

---

## 6b. Dashboard filtering and saved views

Wishlist item (Bob): filter the feed by things that matter, e.g. "show me all SSH commands".

Today every hit lands in one `hits` table that already has `method`, `path`, `body`, `event`,
`severity`, and `cc` (`store.php:299-321`), and the dashboard already does a click-IP filter. So
filtering is mostly a UI + query-param job on top of the typed schema, not new plumbing.

Filter dimensions (all indexed columns from section 4):
- source: http / decoy / protocol.
- protocol + event: `proto=ssh` + `event=command` = "all SSH commands"; `event=login` = credential
  attempts.
- attack class / template id, severity, `known_attacker` flag.
- country (cc), IP or CIDR, time range.
- free-text "contains" on the command/path, user-agent, and body.

Quick views (one-click presets that just set filters): "SSH commands", "Telnet commands",
"Credential attempts", "Known attackers", "Critical only", "By country", plus any saved custom
filter.

Implementation: the live feed (`/?feed`) already pages by an opaque cursor. Add an optional set of
`where` query params that compile to an indexed `WHERE` clause, applied to both the first load and
the delta poll. A dedicated command-stream view (protocol `event=command` rows, newest first,
grouped by session/IP) gives the "watch what they typed" experience for SSH/telnet. The hourly
rollup (section 4) still powers the aggregate widgets; filtered drill-down hits the raw table,
which retention keeps small enough to scan in milliseconds.

Schema dependency: the typed `protocols` table must store the command/payload text (the `data`
column added in section 4), or "see all SSH commands" has nothing to show.

---

## 7. Phased build plan

Each phase is independently shippable, smallest-valuable-first.

Phase 0 — file split (no behaviour change). Execute the un-landed half of
`docs/DEMO-DASHBOARD-PLAN.md` Phase 1: lift the dark theme CSS and JS heredocs into
`public/assets/app.{css,js}`, vendor Leaflet (drop the CDN), serve via `/__fp/<name>`. Pure
refactor, zero visual change (Scout A section 5). Ship it, verify the dashboard looks
identical.

Phase 1 — storage interface + SQLite canonical. Introduce `HitStore` interface, make SQLite
the source of truth, add the typed `HitWriter` and the three value objects, keep the log as
optional export, add the one-time import-on-empty migration (section 4). Reconciles the three
divergent row shapes.

Phase 2 — retention/pruning. `FUNNYPOT_RETAIN_DAYS` / `FUNNYPOT_RETAIN_GB` + cron prune
(section 4). Small, self-contained, immediately valuable for long-running deployments.

Phase 3 — app structure + dashboard filtering. Introduce `App\` PSR-4 namespace, `Router` with the
two route tables, controllers, and `AppConfig::fromEnv()`. Still PUBLIC-mode only. This is the
graduation from the front-controller (section 6). Dashboard gains filtering: query-param `WHERE`
on the feed, quick views ("SSH commands", "credential attempts", "known attackers"), and the
command-stream view (section 6b).

Phase 4 — STEALTH mode + Globex front. Add `FUNNYPOT_MODE=stealth`, the corporate homepage,
fake login, hidden trap links, and trap page, reusing the iCabbiTools spider-trap (section 3).
Honeypot moves to `/honeypot`, dashboard to the hidden path.

Phase 5 — threat intel. Blocklist ingestion + cache + refresh cron, the `known_attacker`
flag and dashboard badge, then AbuseIPDB reporting with the self-exclude invariant and
daily-cap throttle (section 5). Shippable in two sub-steps (ingestion+flag first, reporting
second).

Phase 6 (optional) — Postgres/MySQL backend behind the existing `HitStore` interface, and an
optional Redis blocklist cache. Only when volume demands it.

---

## 8. Open questions / decisions for Bob

1. Default mode: ship `FUNNYPOT_MODE` defaulting to `public` (preserve today) or flip new
   deployments to `stealth`? I recommend defaulting to `public`.
2. Dashboard path in stealth mode: is `/__fp/` acceptable, or do you want a per-deploy random
   or configurable path so the console is unguessable?
3. SQLite canonical vs keep the JSON-lines log canonical: I recommend SQLite canonical with
   the log as optional export. Any reason the tail-able file must stay the source of truth?
4. Redis or no Redis for blocklists: I recommend DB-backed (no new dependency) with Redis as
   an opt-in. Do you want Redis in the base image anyway to match iCabbiTools exactly?
5. Corporate branding: real fictional "Globex Corporation" name/logo, or should it be
   configurable per deployment so multiple honeypots do not share one recognizable front?
6. AbuseIPDB self-IP detection: auto-detect our public IP at boot, or require operators to set
   `FUNNYPOT_SELF_IPS` explicitly? Auto-detect is convenient but can be wrong behind NAT/proxy.
7. Retention default: keep unbounded by default (today's behaviour), or ship a sane default
   cap (e.g. 30 days or 5 GB) so unattended appliances do not fill their disk?
8. Do the dead `city`/`asn` geo columns (`store.php:298-309`) get made real (ASN/city lookup)
   or dropped from the new schema?
9. Should the emulation-catalog editor (vulns toggles) and the new threat-intel controls live
   on the same operator dashboard, or a separate settings page?
