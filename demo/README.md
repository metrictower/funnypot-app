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

**No Docker (local PHP, dev/poke only):**

```bash
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
| `FUNNYPOT_ADMIN_PASSWORD` | unset | enables the dashboard's password-gated admin actions (prune / clear / geoip). Unset = admin disabled, view stays public |
| `FUNNYPOT_HONEYTOKEN_KEY` | unset | enables the tamper-evident bait cookie (returned-altered = high-signal probe) |
| `FUNNYPOT_DB` | `demo/storage/funnypot.sqlite` | SQLite store path for real all-time stats; `off` = file-only (recent-window stats) |
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

The dashboard polls a delta feed (`/?feed=1&after=<cursor>`) that returns only rows appended since
the last poll, not the whole tail, and appends them in place; load older pages back through history.
When `pdo_sqlite` is present (it is in the docker image) a SQLite mirror gives real all-time stats
plus top-talkers / source-countries / templates-fired / hourly-activity widgets and an attacker map
(Leaflet + OSM/CARTO dark tiles). For the map + country stats, fetch the free GeoIP data once and
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
