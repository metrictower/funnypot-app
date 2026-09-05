# Engagement episode metrics

Measures whether a lure keeps a scanner or autonomous agent engaged, without guessing from raw hit
counts. Opt-in (`FUNNYPOT_ENGAGEMENT=1`). Code lives under `src/App/Engagement/` (contract, identity,
resolver, recorder) and `src/App/Storage/SqliteEngagementStore.php` (the store); the operator view is
the **engagement episodes** section of the dashboard's auth-gated analytics panel.

This is a measurement foundation only. It selects no response, runs no experiment, mutates nothing an
attacker sees, and adds no network egress.

## What is recorded

One typed `EngagementEvent` per instrumented hit, emitted by a producer **after** its response decision
exists (today: `LabyrinthController` and `PolluterController`, from their `finally` blocks, wrapped in a
second try/catch so a late fault can never surface as a 500).

| field | contract |
|---|---|
| `ts` | INTEGER UTC epoch from the injected app clock (never the request) |
| `episode_id` | install-local HMAC id, 128 bits |
| `identity_basis` / `identity_confidence` | closed vocabularies (below) |
| `lure_id` | code-owned definition id from `LureId` (labyrinth, polluter_config/log/hostile/shadow); nullable; never identity |
| `artifact_id` | HMAC id of a *verified* issued object; nullable; links issue/fetch/reuse events, never identity |
| `stage` | `discover` → `enumerate` → `auth` → `access` → `collect` → `execute_attempt` → `persist_attempt` → `verify` → `exit` |
| `event_kind` | `lure_issued`, `lure_followed`, `artifact_issued`, `artifact_fetched`, `artifact_reused`, `job_polled`, `tool_turn`, `stage_advanced` |
| `bytes_out` / `server_wall_ms` | measured non-negative integers |
| `server_llm_usage_available` | `1` = observed, `0` = unknown |
| `server_llm_calls` / `server_llm_tokens` | nullable; `NULL` when unknown, `0` only when observed zero (unknown-as-zero is rejected at construction) |
| `attacker_request_units` / `attacker_tool_turns` | observed counts |
| `estimated_context_tokens` | `ceil(bytes_out / 4)` — an **estimate** of the served context, never measured attacker tokens; always shown with `(est.)` |

Every enum/id is validated against its closed set and capped at 64 bytes before storage. Paths, bodies,
headers, cookies, tokens, prompts, IPs and user agents are **not** fields; they stay in the separately
retained hit log and are never duplicated here.

Producer stage mapping: labyrinth bare entry (page 1, no shard) = `discover`; any deeper page, shard or
record = `enumerate`; every polluter export = `collect`. Neither makes an LLM call, so their LLM usage is
an observed zero. Later stages are reserved for future issued-lure seams.

## Identity is evidence, not attribution

An episode is a local, pseudonymous observational grouping. It is never a claim that one IP, cookie or
handle is one person, account or campaign. The resolver (`EpisodeResolver`) keys on the strongest
**valid** evidence, in this order:

1. **`episode_handle` — high.** A Funnypot-issued `SignedHandle`: version, issue time, expiry, 128 bits
   of randomness and a domain-separated HMAC-SHA256. Verification is side-effect-free, rejects oversized
   input before parsing, compares MACs in constant time, and treats a future-issued handle as invalid.
2. **`cookie` — medium.** Reserved in the vocabulary for an integrity-protected, versioned, expiring
   first-party decoy cookie. No cookie meets that bar yet, so this tier is never produced today.
3. **`network_fallback` — low.** A keyed digest of peer address + a *coarse* user-agent class
   (`browser` / `library` / `empty` / `other`) + the resolver version.

A forged, expired, wrong-domain or wrong-key handle is simply ignored: the request lands on exactly the
key it would have had with no handle at all (no allocation keyed by attacker bytes, no confidence gain),
so junk can never switch metrics off. An artifact handle yields only an `artifact_id` — presenting it as
an episode handle promotes nothing.

**Stated limitations** (also shown on the dashboard): a network-basis episode can merge unrelated
clients behind NAT or a shared proxy, and one client that rotates address or user agent splits across
several episodes; a copied artifact links events without saying who holds it. The dashboard therefore
shows basis × confidence on every aggregate and never renders an "actor".

### Stored identifiers and the install-local key

All stored ids (`episode_id`, `evidence_digest`, `artifact_id`) are `substr(HMAC-SHA256(key, "v1|<domain>|<value>"), 0, 32)`
— versioned, domain-separated, 128 bits. The key (`AnalyticsKey`) is:

- `FUNNYPOT_ANALYTICS_KEY` when set and at least 16 bytes (shorter = placeholder = **no key**); else
- a sub-key derived from the install identity's private `engagement-analytics/v1` key
  (`HttpIdentity::engagementAnalyticsKey()`, its own HKDF domain — not the fake-filesystem key), so
  every install has a distinct id space by default. See `docs/IDENTITY.md`.

If neither yields usable material (a placeholder explicit key), the app wires `NoopEngagementStore`
and the dashboard reports `key-unavailable`. There is no fleet-constant fallback; the public persona
seed is never used.

## Episodes and boundaries

`SqliteEngagementStore::resolveAndRecord()` is one `BEGIN IMMEDIATE` transaction (the `TarpitBudget`
model): read the global gauges and the current episode for the digest under the write lock, decide
new-vs-continue, check caps, insert, `COMMIT` — or `ROLLBACK` to a no-op on any fault. A new episode
starts when none exists, when `now - last_seen` exceeds the idle gap, when `now - started_at` reaches
the absolute lifetime, or when the clock went backwards (`now < last_seen`; never lengthens an episode;
counted once in `clock_rollback`). Past episodes for the same digest are kept, which is what
"continuation" counts. `active_span_s` accumulates inter-event gaps (each ≤ the idle gap by
construction).

Timestamps are integer UTC epoch from one injected clock shared by recorder and store.

## Bounded storage

All caps are clamped in `AppConfig` and again in `EngagementCaps`; a registry knob cannot unbound the
store.

| knob | default | range | scope |
|---|---|---|---|
| `FUNNYPOT_ENGAGEMENT_IDLE_GAP_S` | 600 | 60–1800 | episode boundary |
| `FUNNYPOT_ENGAGEMENT_LIFETIME_S` | 7200 | 600–21600 | episode boundary |
| `FUNNYPOT_ENGAGEMENT_MAX_EVENTS` | 2000 | 1–100000 | per episode, inline |
| `FUNNYPOT_ENGAGEMENT_MAX_ARTIFACTS` | 256 | 1–10000 | per episode, inline |
| `FUNNYPOT_ENGAGEMENT_BYTES_PER_EP_MB` | 2 | 1–64 | per episode retained bytes, inline |
| `FUNNYPOT_ENGAGEMENT_GLOBAL_ROWS` | 250000 | 1000–5000000 | global event rows, inline |
| `FUNNYPOT_ENGAGEMENT_GLOBAL_BYTES_MB` | 256 | 1–4096 | global retained bytes, inline + retention |
| `FUNNYPOT_ENGAGEMENT_RETAIN_DAYS` | 30 | 1–30 | age; further capped by `FUNNYPOT_RETAIN_DAYS` when set |

Inline caps read O(1) gauges (`engagement_state.event_rows` / `bytes_total`; retained bytes are a fixed
logical per-row accounting, 256 B per event and 192 B per episode) so a write never counts a table. At
a cap the new metric is **dropped** and one fixed-name saturating counter is incremented
(`shed_episode_cap`, `shed_global_rows`, `shed_global_bytes`); fresh data is never deleted on the request
path. `demo/retention.php` runs the bulk reclaim on its timer — `retainDays(min(engagement, hits>0 ?
min(hits,30) : 30))`, `retainBytes(global bytes)`, checkpoint + `incremental_vacuum` — and recounts the
gauges. The identifier/enum field length is a class constant (64 bytes).

The store is its own file, `engagement.sqlite`, beside the hit db (one file per concern): the hit
writers queue up to 3 s on their WAL lock and this store must never queue at all.

## Observer performance and failure behaviour

The recorder runs only after the response decision exists, does no sleep, retry, DNS or network I/O,
and never throws. `PRAGMA busy_timeout` is re-issued at **5 ms** after the shared `Sqlite::open()`
(which sets 3000 ms), so lock contention sheds the metric instead of holding a request worker. Any
lock, I/O, schema, cap or serialization fault returns a no-op status and increments `fault` when the
db allows it. `ProducerWiringTest` asserts a producer's status, headers and body are byte-identical
with metrics off, on, and faulting.

### Benchmark record

`php scripts/engagement-bench.php [events] [keys]` times `EngagementRecorder::record()` from outside
the store over N warm events and exits non-zero if p95 exceeds the 5 ms budget.

| date | platform | PHP | mode | events / keys | p50 | p95 | p99 | max | drops |
|---|---|---|---|---|---|---|---|---|---|
| 2026-09-04 | Darwin 25.5.0 arm64, local SSD temp dir | 8.4.10 | WAL, synchronous=NORMAL, busy 5 ms | 2000 / 50 | 0.080 ms | 0.125 ms | 0.279 ms | 3.045 ms | 0 |

This is an engineering budget on the documented platform, not a claim of zero latency or a guarantee
against arbitrary host I/O stalls. `EngagementBenchmarkTest` keeps a deliberately loose regression
tripwire (p95 ≤ 25 ms over 1,000 events) so a loaded CI box cannot flake it while a real regression
(a per-write `COUNT(*)`, a lost prepared statement, `synchronous=FULL`) still trips.

## Operator analytics

`?admin=analytics` (session-gated like every admin read) carries `engagement` (the summary over
episodes started in the window) and `engagement_recent` (≤ 20 per-episode rows, a detail view — episode
ids appear only as a 12-char label and are never a rollup dimension). Rules:

- **Zero denominator ⇒ `null`**, rendered as a dash: `events_per_episode`, `continuation_ratio`,
  `avg_active_span_s`, `estimated.context_tokens_per_server_ms`.
- **Unknown LLM usage stays unknown**: an episode with any unavailable event is `episodes_unknown`, and
  `llm.calls` / `llm.tokens` are `null` when no episode is fully known. The UI never uses `||0` on
  these fields.
- **Estimates are labelled**: everything under `estimated` is derived from served bytes and shown with
  `(est.)`; nothing claims exact money burned or exact attacker token usage.
- A null wiring, a `NoopEngagementStore` (off / key-unavailable) and a read fault all degrade to
  `{"enabled": false, "reason": …}` with HTTP 200 — never a 500.

## Test-support seam (for the local replay / experiment work)

`tests/App/Engagement/Support/EngagementTestSnapshot.php` creates one isolated synthetic namespace (its
own temp SQLite file, its own random key, a controllable clock) and exposes `record()`, `advance()`,
`snapshot()` and `reset()`. `snapshot()` returns only the closed `FIELDS` list — counts, stages, bytes,
usage-availability, labelled estimates and separately labelled **measured** timing (p50/p95/p99 of
`record()` wall time) — never raw hits, episode/evidence ids, paths, bodies, headers, tokens, cookies or
prompts. It is autoloaded by `autoload-dev` only, and a test asserts nothing under `src/`, `demo/`,
`scripts/` or `bin/` references it: production cannot construct or expose it.
