# Endless Throttled Backup-Download Bait — Design (FP-0036 Phase 6)

**Status:** approved by operator 2026-08-25. **On by default** (disable via `FUNNYPOT_ENDLESS_DOWNLOAD=0`);
deploy still operator-gated (this session deploys nothing).
**Depends on:** the FakeFilesystem engine (`Funnypot\Shell\Fs\*`), `Fleet`, `HostSecret`, `StreamEmitter`,
the `HitStore` intel log, the decoy admin panel (`FleetSection`), and the `Router`/`ConsoleRouter` seam.

## Goal

When a human pokes the decoy admin panel and clicks "Download latest backup", stream them a plausible
`backup.zip` that **never finishes** — a slow, believable-broadband trickle their own browser fabricates,
costing us near-zero bandwidth. They get bored and cancel; we log that they took the bait. Non-browser
clients (curl/wget/scanners) can't run the Service Worker, so they get a small server-capped finite
stream instead — the link is never dead.

## Operator decisions (locked)

- **Endless, cancelable, NOT a bomb.** The stream loops forever until the attacker cancels. No
  auto-decompression crash (a zip bomb is off the table — CFAA-aggressive). A truly endless stream is
  intentionally *not* a valid extractable zip (a zip's central directory lives at the end, which we
  never emit); that is accepted — the point is the time/disk sink, not a working archive.
- **Throttled, variable speed.** Unthrottled client-side generation writes at disk speed (GB/s) — an
  obvious tell, and it fills disk before the attacker reacts. Instead: ~100–200 KB random chunks every
  ~100 ms (~1–2 MB/s), with a sine-eased "breathing" rate that drifts up and down so it reads like a
  real download, not a script.
- **All speed/variability knobs live in central config** (`AppConfig`, env-driven), served to the client
  SW at runtime via the manifest — no hardcoded rates in the JS.
- **On by default.** Active unless `FUNNYPOT_ENDLESS_DOWNLOAD=0`. Deploy stays the operator's call
  (this session ships nothing to prod).

## Central config (AppConfig::fromEnv)

| env | AppConfig field | default | meaning |
|---|---|---|---|
| `FUNNYPOT_ENDLESS_DOWNLOAD` | `endlessDownload` (bool) | `true` | master on/off (default ON; set `0` to disable) |
| `FUNNYPOT_DL_CHUNK_MIN_KB` | `dlChunkMinKb` (int) | `100` | min chunk size |
| `FUNNYPOT_DL_CHUNK_MAX_KB` | `dlChunkMaxKb` (int) | `200` | max chunk size |
| `FUNNYPOT_DL_INTERVAL_MS` | `dlIntervalMs` (int) | `100` | base delay between chunks |
| `FUNNYPOT_DL_VARY_PCT` | `dlVaryPct` (int) | `50` | breathing amplitude (% of base rate) |
| `FUNNYPOT_DL_EASE_PERIOD_S` | `dlEasePeriodS` (int) | `20` | breathing cycle length |
| `FUNNYPOT_DL_FALLBACK_CAP_MB` | `dlFallbackCapMb` (int) | `50` | non-JS server fallback hard cap |

Bounds clamped in `AppConfig` (e.g. chunk 1–1024 KB, interval 10–5000 ms, vary 0–95 %, period 1–600 s,
cap 1–500 MB) so a bad env value can't produce a firehose or a stall.

## Architecture

One new front-controller seam + one panel touch + one SW asset, mirroring `ConsoleRouter`:

```
FleetSection (decoy panel)
  └─ "Download latest backup" button + scoped inline JS
        1. register /__dl/sw.js  (scope "/", Service-Worker-Allowed)
        2. on activate, enable the button
        3. on click: GET /__dl/manifest?host=<h>   ← intel ping (bait taken, logged event=download)
                     then navigate an <iframe>/<a download> to /__dl/backup.zip
DownloadRouter  (gate-exempt, ahead of the honeypot catch-all; only mounted when endlessDownload=on)
  ├─ GET /__dl/sw.js       → the service-worker script (application/javascript, Service-Worker-Allowed:/)
  ├─ GET /__dl/manifest    → JSON {seed, files:[{path,size}...], throttle:{...config...}}  + logs the ping
  └─ GET /__dl/backup.zip  → NON-JS fallback only: HARD-CAPPED finite stream
                              (the SW intercepts this path for browsers, so PHP only sees non-SW clients)
Service worker (/__dl/sw.js, client side)
  └─ fetch handler for /__dl/backup.zip:
        respond with a ReadableStream whose pull() emits procedural zip bytes, throttled per the
        manifest's throttle profile, FOREVER (endless). Bytes fabricated in JS → near-zero server cost.
```

### Why the SW intercepts `/__dl/backup.zip`

The download anchor points at `/__dl/backup.zip` and the saved file is still named `backup.zip` via
`Content-Disposition`. It is deliberately NOT the bare `/backup.zip`: that literal path is already
honeypot surface (nested decoy archive, detection engine, payload classifier, and the app's only
AbuseIPDB / Threat Intel enqueue), so a router seam claiming it would silence every scanner report on
it. Once the SW is active (scope `/`), its `fetch` handler answers the bait path from the
client-generated endless stream. A client with no SW (curl, or a browser on the very first click before
activation) falls through to the server, where `DownloadRouter` serves the capped finite fallback. So browsers get endless-client-gen; everything else gets a bounded
server stream. Both log the ping.

### Zip byte structure (endless, store method)

Reuse the deterministic file list from `FakeFilesystem` (server builds the manifest by walking a seeded
host's `/var/backups`, `/etc`, `/home`, `/srv` and picking plausible files: `.env`, `id_rsa`,
`db_dump.sql`, `wp-config.php`, config archives). The SW emits, per manifest entry, a ZIP **local file
header** (general-purpose bit 3 set → sizes carried in a trailing data descriptor, so we don't need to
know the length up front) followed by **store-method** (uncompressed) bytes generated procedurally in JS
(a seeded xorshift filler, ASCII-ish for config-looking entries). After the manifest is exhausted, the
stream continues with one final unbounded entry (`database-full-dump.sql`) whose store bytes never end and
whose data descriptor + central directory are never written. Result: a stream that looks like a normal zip
starting to download and then just... keeps going.

### Throttle / breathing rate (client + server share the formula)

Effective inter-chunk delay for the *n*-th chunk:

```
base   = intervalMs
phase  = 2*PI * (elapsedSeconds / easePeriodS)
factor = 1 + (varyPct/100) * sin(phase)        // 1 ± varyPct%
delay  = clamp(base / factor, base*0.2, base*5) // faster when factor>1, slower when <1
chunk  = random(chunkMinKb, chunkMaxKb) * 1024
```

The formula is client-side only. The server fallback does NOT pace: pinning a php-fpm worker for the
whole transfer on an unauthenticated route is a self-DoS, and a curl client judges no realism anyway.
It just streams up to `dlFallbackCapMb` as fast as the socket drains, and stops on a client abort.

## Intel

- Manifest fetch logs one hit: `event=download`, `method=GET`, `path=/__dl/backup.zip`,
  `served=true`, `severity=info`, `body=host=<h>` — the "attacker took the bait" signal. Dashboard gets a
  quick-filter **"backup bait"** (`event=download`) mirroring the `shell`/`panel` filters.
- The non-JS fallback GET also logs the same event (so curl pulls are captured too), de-duped by IP within
  a short window is unnecessary — every pull is signal.

## Safety / invariants

1. **Inert.** No real file is read or served; all bytes are procedural. The manifest exposes only fake
   paths from the seeded `FakeFilesystem`, never a real filesystem walk.
2. **Never-500.** `DownloadRouter::handle` resolves everything in a try/catch before the first byte; a
   fault degrades to an empty 200 (or the plain 404 when the feature is off), never a 500.
3. **On by default, cleanly disablable.** `Router` consults `DownloadRouter` only when `endlessDownload`
   is on (the default); with `FUNNYPOT_ENDLESS_DOWNLOAD=0` all `/__dl/*` requests fall
   through to the normal honeypot catch-all (still logged + fake-served like any probe — no behavioural
   tell either way). The bait link in the panel is likewise only rendered when the feature is on.
4. **No fingerprint tells.** `/__dl/sw.js` is served as `application/javascript` with a normal
   `Service-Worker-Allowed` header (every PWA sends it). The bait zip uses `Content-Type: application/zip`
   + `Content-Disposition: attachment; filename="backup.zip"`. The throttle makes the transfer rate
   believable. No scanner/matcher signature strings anywhere.
5. **Cancelable, not a bomb.** The attacker can cancel at any time (it's a normal browser download); we
   never auto-expand or crash them.
6. **Bounded server cost.** Browsers cost us one tiny manifest fetch. Non-JS clients cost us at most
   `dlFallbackCapMb`, streamed unpaced and abandoned as soon as the client hangs up; the bytes are never
   buffered, so a fallback holds only one chunk in memory.

## Testing

- `AppConfig` parses + clamps every new env knob (unit).
- `DownloadRouter::matches` owns exactly `/__dl/sw.js`, `/__dl/manifest`, `/__dl/backup.zip`; nothing
  else — in particular never the bare `/backup.zip`, which stays honeypot surface.
- Manifest JSON: valid shape, files come from the seeded FakeFilesystem for the requested host, throttle
  block echoes the clamped config, and a hit is logged `event=download` (HitStore spy).
- Feature OFF → `DownloadRouter` not mounted → `/__dl/backup.zip` falls through to the honeypot.
- Non-JS fallback: streams ≤ cap bytes, throttled, `application/zip`, never-500 on a broken host.
- SW script: `node --check src/App/Download/sw.js` (no JS test runner; syntax-check only), plus a byte-
  structure assertion on the local-file-header bytes the shared PHP helper emits for the fallback.
- Full suite green + fingerprint gate green before commit.

## Out of scope (this phase)

- A valid, fully-extractable finite archive (the operator chose endless).
- Compression (store method only — compression would need buffering + defeats streaming).
- Wiring the bait link into surfaces other than the fleet console (later, if wanted).
