# funnypot: standalone honeypot demo

Runs funnypot as a self-contained honeypot server. Drop it on a box, point traffic at it, and every
scanner that probes it gets served a plausible fake while you watch the hits land on a live
dashboard. Same codebase as the composer library; this just wires it into a front controller.

- `GET /`: a "Welcome to funnypot" homepage + a live dashboard of recent hits (auto-refresh 5s)
- anything else: funnypot detects the scanner probe, serves a fake if it matches, and logs every
  request (detections and non-detections) as JSON lines (to the log file and to stderr, so
  `docker logs` shows them live)

## Run it

**Docker (compose):**

```bash
cd demo
docker compose up --build
```

**Docker (plain run):**

```bash
docker build -f demo/Dockerfile -t funnypot .
docker run --rm -p 8080:8080 funnypot
```

**No Docker (local PHP 8.2+, dev/poke only):**

```bash
# Prepare the install identity once (creates demo/storage/.funnypot/identity + the runtime bundles);
# the front controller reads its bundle from the same runtime dir, so export it for both commands.
# Use a canonical path: the bundle reader lstat()s the parent and refuses a symlink, so /tmp
# (a symlink on macOS) is rejected.
export FUNNYPOT_IDENTITY_RUNTIME_DIR="$PWD/demo/storage/run"
php bin/funnypot identity:prepare
php -S 0.0.0.0:8080 -t demo demo/index.php
```

Then open <http://localhost:8080> for the dashboard.

> Use Docker (nginx + php-fpm) for anything a scanner will actually hit. `php -S` is
> single-process: it serves one request at a time, so a scanner's concurrent flood
> queues up and times out (nuclei then marks the host unresponsive and quits, matching
> almost nothing). The Docker image runs php-fpm with a worker pool + opcache and caches
> the compiled index per worker, so it stays responsive under load.

## Try it

From another shell, act like a scanner:

```bash
curl http://localhost:8080/.git/config          # served a believable fake git config
curl http://localhost:8080/.env                 # served a believable fake .env
curl http://localhost:8080/nope                 # a normal 404 (logged as a non-detection)
curl -O http://localhost:8080/backup.zip        # a nested decoy archive: unzip it to find another zip
nuclei -u http://localhost:8080 -t http/exposures/   # watch dozens light up on the dashboard
```

A `.zip` / `.tar.gz` probe on a path with no template gets a nested decoy archive instead of a
404: peel a layer, find another archive, repeat down to fabricated secrets. It wastes an attacker's
time re-extracting. It's bounded (a few KB, extracts to a few KB), never a decompression bomb.
Rebuild the assets with `scripts/build-decoys.sh`; disable with `FUNNYPOT_DECOY_ARCHIVE=0`.

Watch them appear on the homepage, and stream the raw log with `docker logs -f <container>`.

## Config (env)

| Env | Default | Meaning |
|---|---|---|
| `FUNNYPOT_STYLE` | `realistic` | `minimal` \| `realistic` \| `taunt` |
| `FUNNYPOT_LOG` | `demo/storage/hits.log` | where hit JSON lines are written |
| `FUNNYPOT_DECOY_ARCHIVE` | on | serve a nested decoy archive for `.zip`/`.tar.gz` 404s; `0` to disable |
| `FUNNYPOT_ADMIN_PASSWORD` | unset | first-boot seed for the operator login (Argon2id user + server-side session, FP-0242b). Seeds the first user only while none exists, then goes inert; unset = no operator, dashboard stays gated by `dashboard.public_view` |
| `FUNNYPOT_ADMIN_USER` | `admin` | the operator username. The REAL login is overlaid on the public `/` sign-in decoy (FP-0295): a POST with this exact username is verified (Argon2id) and, on success, redirects to the dashboard — every other credential is the decoy. Set a **non-obvious** value: it gates the slow hash so a username-spray never triggers it, and there is no separate login route to find. Empty disables the overlay |
| `FUNNYPOT_HONEYTOKEN_KEY` | unset | enables the tamper-evident bait cookie (returned-altered = high-signal probe) |
| `FUNNYPOT_DB` | `demo/storage/funnypot.sqlite` | SQLite store path for real all-time stats; `off` = file-only (recent-window stats). The private install identity lives beside it (`<dir>/.funnypot/identity/`) |
| `FUNNYPOT_INSTALL_SECRET_FILE` | unset | protected file (root-owned, 0600/0400, canonical path) holding the one-line install master `funnypot-install-secret-v1:<43 base64url chars>`. Unset = the app creates + persists its own master on first boot. Never accepted on the command line; the entrypoint unsets it before any child starts. See `docs/IDENTITY.md` |
| `FUNNYPOT_INSTALL_SECRET` | unset | the same canonical master as a raw env value, for direct process startup; scrubbed from children. Prefer the file |
| `FUNNYPOT_PERSONA_SEED` | unset | optional **cosmetic** override of the visible persona (company/domain/versions), used verbatim so an existing explicit persona keeps its identity; never feeds a key. Legacy alias `FUNNYPOT_PERSONA_SECRET`. Short/placeholder values only warn (`identity:status`) |
| `FUNNYPOT_IDENTITY_RUNTIME_DIR` | `/run/funnypot` | where `identity:prepare` publishes the scoped runtime bundles (`identity-http/` 0750 root:www-data, `identity-private/` 0700 root) and the TLS links; a path, kept in child env so workers find their bundle |
| `FUNNYPOT_TLS_CERT_FILE` / `FUNNYPOT_TLS_KEY_FILE` | unset | explicit operator TLS pair (both or neither; canonical paths, no symlinks). Served byte-identical, never copied or regenerated. Else a complete legacy `/etc/nginx/funnypot.{crt,key}` pair is served; else a persisted generated decoy cert |
| `FUNNYPOT_CN` / `FUNNYPOT_PUBLIC_DNS` | persona hostname | subject CN / extra DNS SAN of the generated decoy cert (strict lowercase DNS names) |
| `FUNNYPOT_GEO_DB` | `demo/storage/dbip-country.csv.gz` | DB-IP Lite CSV for the GeoIP map/country stats |
| `FUNNYPOT_TARPIT` | off | master switch for the cost-amplification tarpit foundation (opt-in; ship off, flip on after the load test) |
| `FUNNYPOT_TARPIT_DB` | `demo/storage/tarpit.sqlite` | the tarpit's own SQLite file (concurrency slots + hourly per-IP budget ledger) |
| `FUNNYPOT_TARPIT_MAX_CONCURRENT` | `4` | global concurrent tarpit slots (clamped 1–15; ≤ ¼ of the 16 fpm workers so the tarpit never starves real detection) |
| `FUNNYPOT_TARPIT_MAX_PER_IP` | `1` | concurrent slots one IP may hold (clamped 1–15) |
| `FUNNYPOT_TARPIT_BYTES_PER_RESP_MB` | `8` | hard byte cap per streamed tarpit response (clamped 1–512) |
| `FUNNYPOT_TARPIT_BYTES_PER_IP_HR_MB` | `64` | bytes one IP may pull from the tarpit per hour (clamped 1–65536) |
| `FUNNYPOT_TARPIT_WALL_PER_IP_HR_S` | `120` | server wall-time one IP may consume across tarpit hits per hour (clamped 1–3600) |
| `FUNNYPOT_TARPIT_GLOBAL_BYTES_HR_MB` | `1024` | aggregate tarpit egress ceiling per hour; over it, shed all tarpit to 404 (clamped 1–1048576) |
| `FUNNYPOT_TARPIT_PAGES_PER_IP_HR` | `2000` | tarpit pages/responses one IP may fetch per hour (clamped 1–1000000) |
| `FUNNYPOT_TARPIT_LATENCY_MS` | `0` | optional tarpit latency (FP-0245d). `0` = off. A single bounded server sleep applied **only while holding a slot** (so ≤ `MAX_CONCURRENT` workers ever sleep at once), clamped ≤ 2000 ms (well under nginx's 15 s read-timeout) and charged to the wall ledger; also arms the client-side pacing service worker that paces the `/admin/export/*` download in a real browser (the attacker's CPU, not ours) |
| `FUNNYPOT_TARPIT_DECOMP_CAP_MB` | `16` | decompression cap if gzip is ever used (decompressed ≤ this, ratio ≤ 100:1 — a nuisance, never a bomb; clamped 1–64) |
| `FUNNYPOT_SLEEP_DECOY` | off | master switch for the FP-0228 time-based blind-injection SLEEP decoy (opt-in). Honours a recognised SQLi/RCE `SLEEP(n)`/`WAITFOR`/`$(sleep n)` probe with a metered delay so a scanner's calibrated-SLEEP confirmation lands, but bounded: the sleep runs **only while holding a `TarpitBudget` slot** (≤ `MAX_CONCURRENT` workers ever sleep) and the honoured time is charged to the SAME per-IP hourly wall ledger — no second budget |
| `FUNNYPOT_SLEEP_PER_REQ_CAP_MS` | `2000` | per-request honoured-sleep cap in ms; the delay is `min(requested_seconds·1000, cap)`, hard-clamped ≤ 2000 (well under nginx's 15 s read-timeout — a second wall behind `TarpitBudget::LATENCY_HARD_CAP_MS`). The **per-IP cumulative** allowance is `FUNNYPOT_TARPIT_WALL_PER_IP_HR_S` (the shared wall ledger), not a separate knob; once spent, probes are served immediately with zero delay until the hour bucket rolls over |
| `FUNNYPOT_ENGAGEMENT` | off | master switch for engagement episode metrics (opt-in): typed per-hit engagement events from the tarpit producers, grouped into pseudonymous episodes in their own `engagement.sqlite`, surfaced in the analytics panel. Observer-only — never changes a response. See `docs/ENGAGEMENT-METRICS.md` |
| `FUNNYPOT_ANALYTICS_KEY` | unset | install-local key every stored engagement id is HMAC'd under (≥ 16 bytes; shorter = placeholder = metrics stay OFF with a dashboard warning). Unset = a sub-key of the install identity's private `engagement-analytics/v1` key, so each install has its own id space by default. Env-only, never shown in the config panel |
| `FUNNYPOT_ENGAGEMENT_IDLE_GAP_S` | `600` | idle gap that closes an episode (clamped 60–1800) |
| `FUNNYPOT_ENGAGEMENT_LIFETIME_S` | `7200` | absolute episode lifetime; an episode splits at this age regardless of activity (clamped 600–21600) |
| `FUNNYPOT_ENGAGEMENT_MAX_EVENTS` | `2000` | events one episode may hold; further events are dropped and counted (clamped 1–100000) |
| `FUNNYPOT_ENGAGEMENT_MAX_ARTIFACTS` | `256` | artifact-bearing events one episode may hold (clamped 1–10000) |
| `FUNNYPOT_ENGAGEMENT_BYTES_PER_EP_MB` | `2` | retained engagement bytes one episode may hold (clamped 1–64) |
| `FUNNYPOT_ENGAGEMENT_GLOBAL_ROWS` | `250000` | global event-row ceiling, enforced inline on every write (clamped 1000–5000000) |
| `FUNNYPOT_ENGAGEMENT_GLOBAL_BYTES_MB` | `256` | global retained-byte ceiling — inline on writes, and the size cap of the retention pass (clamped 1–4096) |
| `FUNNYPOT_ENGAGEMENT_RETAIN_DAYS` | `30` | age ceiling for engagement rows (clamped 1–30, and never longer than `FUNNYPOT_RETAIN_DAYS` when that is set) |
| `FUNNYPOT_DEV` | off | `1` = a bind-mounted dev tree: the entrypoint restores per-request opcache timestamp validation (production freezes it — see below). Restart-required |
| `FUNNYPOT_LISTENER_HEALTHY_S` | `60` | a listener run shorter than this counts toward the respawn backoff streak; one at least this long resets it |
| `FUNNYPOT_LISTENER_BACKOFF_MAX_S` | `60` | cap on the respawn delay (2, 4, 8, 16, 32, then this) |

## Operating the box: bounds, logs, ports

**The download bait is bounded at nginx, ahead of PHP.** `/__dl/` (the fleet console's "Download
latest backup" — service worker, manifest and the 50 MiB non-JS fallback) is deliberately exempt from
the app's per-IP velocity gate, so `demo/funnypot-location.conf` gives it its own envelope: 2
concurrent transfers per source and 4 in total (at most 4 of the 16 php-fpm workers can ever be held
by slow readers), 6 starts per minute per source (burst 3), 2 MiB/s per connection, and a 4 MiB
FastCGI spool cap (past it the worker is paced by the client instead of nginx spooling 50 MiB to
disk per request). A throttled request gets a short controlled `429` with `Retry-After`, never nginx's
stock page. The numbers live in that one file (zones in `nginx.conf`) and are pinned by
`tests/App/Ops/DownloadLimitsConfigTest` — change them there deliberately. Separately, the bait's
intel rows are capped per actor: 3 per 10 minutes, the rest counted and folded into the next kept row
as `suppressed=N` (`BaitEventLimiter`; APCu-shared across the pool). Serving never depends on that
counter.

**Production opcache never stats source files.** The image is immutable, so `demo/opcache.ini` sets
`opcache.validate_timestamps=0`. For local development with the source bind-mounted (the commented
recipe in `docker-compose.yml`), set `FUNNYPOT_DEV=1`: the entrypoint writes an override ini restoring
per-request revalidation before php-fpm starts, and removes it again on any start without the flag.

**Container logs rotate.** Both `deploy.sh` runs and compose use the `json-file` driver at 5 × 10 MiB.
The persisted hit store on the data volume (`hits.log` + SQLite, retention via `FUNNYPOT_RETAIN_*`) is
the record; `docker logs` is diagnostics and older stdout/stderr is dropped by design.

**Listener respawn backs off.** A listener that keeps exiting is relaunched after 2, 4, 8, 16, 32 then
60 s (one compact line per exit), and the streak resets only after a run stayed up for
`FUNNYPOT_LISTENER_HEALTHY_S`. A permanent bind/config fault therefore logs once a minute, not every
two seconds forever. Port collisions between nginx and a listener are prevented earlier, by the
manifest check below — backoff is the last-resort bound, not the detector.

**One port inventory.** `demo/ports.json` is the source of truth for every `(transport, port)`: who
binds it in the container (nginx, or which listener process), which deploy target publishes it
(`deploy` = the full production set, `compose` = the reduced local profile), and which host-side
aliases forward to it (22 → 2222 when `FUNNYPOT_SSH_ON_22=1`, 5800/5901/5902 → 5900, 5061/5080 →
5060). The nginx `listen`s, entrypoint `spawn`s, Dockerfile `EXPOSE`, `deploy.sh` publish flags and
compose `ports` are views of it:

```bash
php scripts/check-ports.php              # validate + drift/collision check (CI runs the same via PortDriftTest)
php scripts/check-ports.php --format     # rewrite ports.json canonically (sorted, one endpoint per line)
php scripts/check-ports.php --print sg   # the inbound rules the deploy target needs
```

Edit `ports.json` first, then the view; a port may have exactly one container owner (88 is the
Kerberos listener, 5555 the ADB listener — never nginx too, or the two race for the bind at boot and
the port serves whichever won). The security group cannot be read here: before a deploy, diff
`--print sg` against the group's inbound rules (`aws ec2 describe-security-groups --group-ids <sg>
--query 'SecurityGroups[0].IpPermissions'`) and approve any difference explicitly. A wider group is
allowed; a narrower one leaves a decoy unreachable. Ports above 40000 (44818/tcp EtherNet/IP,
47808/udp BACnet) need their own rules if the group is a range.

The dashboard polls a delta feed (`/?feed=1&after=<cursor>`) that returns only rows appended since
the last poll, not the whole tail, and appends them in place; load older pages back through history.
When `pdo_sqlite` is present (it is in the docker image) a SQLite mirror gives real all-time stats
plus top-talkers / source-countries / templates-fired / hourly-activity widgets and an attacker map
(Leaflet, vendored + inlined same-origin, over a simplified world-outline basemap — no raster tile CDN;
FP-0250). For the map + country stats, fetch the free GeoIP data once and
build the table:

```bash
scripts/fetch-geoip.sh                                   # -> demo/storage/dbip-country.csv.gz
# then, with FUNNYPOT_ADMIN_PASSWORD set, click "geoip" on the dashboard (or POST /?admin=geoip)
```

With `FUNNYPOT_ADMIN_PASSWORD` set, prune (retention: keep newest N), clear, and geoip (build the
lookup table) are available behind the password; the public view is unaffected.

> The demo serves a fake to every matched probe (`gate` is always open) and reveals itself on
> the homepage; that's the point of a demo. For real deployment, gate on your own suspicion
> signal and drop the give-away homepage.
