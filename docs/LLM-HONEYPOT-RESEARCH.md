# LLM-Generated Honeypot Response Layer — Getting-Started Plan

Status: research complete, build not started. Feature is opt-in and purely
additive: it can only ever turn a request that today returns a plain 404 into a
*more convincing* fake, and it must never turn one into an error or a tell.

---

## 1. The idea in one paragraph

Today, when the deception engine cannot match an HTTP request, funnypot returns a
believable static nginx-style 404 (`HoneypotController::handle()` /
`notFound()`). The idea: for requests we currently 404, hand the request to a
**tiny local LLM running on CPU** that writes a plausible fake page for that URL
(for example `GET /super-rare-app/login.asp` gets a plausible fake login page),
then **cache that response permanently** so the same path never re-invokes the
model. The output is served to every future visitor byte-for-byte.

**The key risk — and the whole reason this needs a gate.** Content-discovery
tools (ffuf `-ac`, feroxbuster, gobuster `--wildcard`, dirsearch) deliberately
fire **random garbage paths** (for example `/intentional_404_page.php`,
`/random9271.php`, UUID-shaped tokens) *before and during* a scan to learn what
"nothing here" looks like — a baseline they then diff every real result against.
If those random probes get unique, rich, fabricated pages, the honeypot unmasks
itself instantly: a real server 404s random strings *consistently*, so N random
strings returning N distinct fabricated pages is a statistical tell that does not
even require reading the content. Galah (an LLM web honeypot that answers *every*
request) demonstrates the failure: its own published test log shows
`GET /are-you-a-honeypot` returning `"No, I am a server."` — answering at all is
the giveaway. **Conclusion, load-bearing for the whole design: the model can
never be trusted to recognise a fingerprinting probe by prompt instruction. The
decision must happen in cheap deterministic code, before the model is ever
called, and anything that is not positively a plausible app path keeps getting
the current consistent plain 404.**

---

## 2. Recommended stack

### Model: Qwen2.5-1.5B-Instruct (GGUF, Q4_K_M, ~1.1 GB)

Two independent reports converge on this pick, and one of them is directly on
point: **LLMHoney** (arXiv 2509.01463) benchmarked 13 models from 0.36B–3.8B for
exactly this "plausible fake response" job and found sub-1B models "often produce
incorrect or out-of-character outputs," while **Qwen2.5-1.5B was among the models
giving the most reliable and accurate responses.**

- **License: Apache 2.0** — the cleanest option, no attribution or use-policy
  strings. This matters because funnypot is a public repo.
- Footprint: ~1.1 GB weights at Q4_K_M, ~1.5–2 GB for the model process with KV
  cache at a modest context. 25–40 tok/s on a modest CPU box.
- Qwen2.5's instruction tuning is specifically strong at coherent structured
  output (HTML/JSON on request) — exactly the fake-page use case.

Because the model only ever fires on a cache-miss for a path that already passed
the plausibility gate, a worst-case few-second generation is a non-issue: the
result is cached forever after.

**Runner-up models:**
- **SmolLM2-1.7B-Instruct** (Apache 2.0, near-identical footprint/speed).
  HuggingFace's own IFEval numbers put it slightly ahead of Qwen2.5-1.5B on
  instruction-following. Practically interchangeable in a llama.cpp pipeline —
  worth an A/B test, keep whichever reads more convincing.
- **Qwen2.5-0.5B-Instruct** (~0.4 GB) — the lighter fallback if 1.5B is too slow
  under load, at the cost of thinner output that needs a tighter prompt.
- **Phi-3-mini-4k** (MIT, 3.8B, ~2.4 GB) — noticeably more elaborate pages, but
  ~2x the RAM and slower (~10–20 tok/s). Only if 1.5B output reads too thin.

**Rejected:** SmolLM2-135M/360M (too weak — a broken fake page is a worse tell
than a plain 404); TinyLlama-1.1B (a generation behind); Qwen2.5-3B (Research
License blocks commercial use — disqualifying for a public repo); Gemma-2-2B
(custom terms with a Prohibited-Use Policy, no quality edge). Also note:
parameter count alone does not predict CPU latency — DeepSeek-1.5B (a
reasoning/chain-of-thought model) measured ~13s in LLMHoney. **Stay with small,
non-reasoning instruct models.**

### Runtime: llama.cpp `llama-server` (localhost sidecar)

Purpose-built for CPU, MIT-licensed, 13–80% faster than Ollama on the same
hardware. Ollama and llamafile add a model registry, single-file packaging, and
GPU auto-detect — all solving problems funnypot does not have (one fixed model,
CPU-only, already containerised). Bare `llama-server` is the leanest option and
gives us **GBNF grammar-constrained decoding** (see §4 safety) that the wrappers
add nothing on top of.

Deploy it as a **sidecar container** next to funnypot in `demo/docker-compose.yml`,
bound to a container-internal address (for example `127.0.0.1:8081` or a
docker-network hostname), **never exposed publicly**, with the GGUF baked into the
image (matching funnypot's existing baked-image philosophy).

### PHP integration: HTTP to the long-lived server (not FFI, not subprocess)

Decisive, because of PHP-FPM's process model:
- **FFI is a dead end** — PHP-FPM runs many independent worker *processes*, so
  loading the model via FFI means either every worker loads its own 1–2 GB copy,
  or you reinvent a server badly.
- **Subprocess-per-request** (`llama-cli`) pays model-load + context-init on every
  call, has no KV/prompt cache, and lets a burst of concurrent probes spawn N
  model-loading processes — a self-inflicted OOM on a small box.
- **HTTP to a persistent `llama-server`** loads the model once, keeps it resident,
  supports a cached system-prompt prefix, and is trivial from PHP with cURL /
  `stream_context_create` (the same pattern `AbuseIpdb::httpPost()` already uses).

### EC2 sizing: `t4g` (Graviton/ARM)

llama.cpp has first-class Arm NEON/SVE kernels; Arm/AWS benchmarking shows up to
~4x over x86 for llama.cpp on Graviton, and Graviton is cheaper per vCPU/GB.
- **`t4g.medium` (2 vCPU / 4 GB)** — workable for 1.5B alongside the rest of
  funnypot (nginx + php-fpm + TCP listeners + SQLite) if traffic is bursty
  (honeypot profile fits; burst credits absorb spikes).
- **`t4g.large` (2 vCPU / 8 GB)** — the comfortable choice with headroom for
  concurrent generations and no burst-credit babysitting.
- Avoid `t3.small` (2 GB) — too tight once the model process is added.

---

## 3. The decision gate (probe detection)

**One-line policy: default-deny — invoke the LLM only when the source IP is NOT
bulk-scanning AND the path is positively a plausible app path AND there is no
cache entry yet; every other case gets the existing byte-identical plain 404.**

The critical research finding: **path content alone cannot separate a calibration
probe from a wordlist-sweep entry**, because real wordlists (SecLists `common.txt`,
`raft-*`) are full of legitimate-looking dictionary words (`admin`, `wp-login.php`,
`.env`) mixed in with the random calibration tokens. The thing that reliably
distinguishes bulk enumeration from a genuine one-off targeted probe is
**behaviour and volume, not the string**. So the gate is **two orthogonal checks,
AND'd together** — either failing sends the request to the plain 404.

### Gate A — IP behaviour (kills bulk dirbuster sweeps outright)

This is the load-bearing defence. Track per-IP over a sliding window in a cheap
in-process / SQLite-backed store:
- distinct not-found paths in the last 60s and last 10min,
- whether the *same* high-entropy token was probed against ≥2 base directories
  (the feroxbuster wildcard-recursion signature),
- request inter-arrival uniformity (dirbusters fire at near-constant intervals).

Trip thresholds (starting points, tune from logs): **≥5 distinct 404 paths/60s,
or ≥15/10min, or repeated-token-across-multiple-directories** → flag the IP
`BULK-SCAN` and pin it to plain-404-only for a cooldown (for example 24h),
**regardless of how plausible any individual path looks.** A full ffuf/gobuster
run then sees ~0 rich responses even though its wordlist contains real words,
because the IP flags within the first handful of requests. A genuine single
targeted probe (Bob's `/super-rare-app/login.asp`) never accumulates enough
volume to trip this.

### Gate B — lexical plausibility (kills the calibration token itself)

Catches single-shot IPs that Gate A cannot see. **Reject → plain 404** if the leaf
segment / filename stem:
- has Shannon entropy above the natural-language range (random hex/alnum sits
  ~4.0–4.7 bits/char; English/tech tokens ~2.5–3.3), or matches `^[a-f0-9]{8,}$`,
  a UUID shape, or a long pure-numeric string,
- contains explicit calibration tells as substrings (`random`, `test\d+`,
  `nonexist`, `intentional`, `404`, `notfound`),
- hits no token in a small bundled dictionary (SecLists `common.txt` /
  `raft-small-words.txt`: admin, login, api, config, backup, wp-*, phpmyadmin,
  .git, .env, vendor, cgi-bin, actuator, swagger, graphql, .well-known…) and has
  no plausible pronounceable/product-name shape,
- has an extension outside a web/app allowlist when an extension is present
  (`.php .asp .aspx .jsp .cgi .do .action .json .xml .yml .conf .bak .sql .zip
  .env .pem .key .log .html`).

**Accept-leaning** only when a path has a recognised app extension or directory
convention (`/admin/`, `/login`, `/api/`, `/portal/`, `/cms/`) AND real
dictionary/vendor words. Everything already advertised in funnypot's robots.txt
bait list (`.git/`, `.env`, `backup/`, `wp-admin/`, `phpmyadmin/`, `admin/`,
`credentials.txt`, `backup.sql`, `.aws/`) should be **hard-allowlisted** — we
deliberately advertised those.

**Express the gate as a declarative config** (a YAML file next to the existing
`templates/` corpus) rather than hardcoded PHP, so it can be tuned without a
deploy — consistent with the rest of the data-driven engine.

Bias every uncertain case toward the plain 404: a missed interesting probe costs
only a slightly-less-rich fake; a leaked rich response on garbage costs the whole
honeypot's cover.

---

## 4. Architecture

### Hook point

The controller already has the exact shape needed. `HoneypotController::handle()`
runs `if ($response !== null) { emit } elseif (!serveDecoyArchive(...)) { plain
404 }`. The LLM step is a **new `elseif` branch slotted between decoy-archive and
the literal 404 echo** (decoy-archive stays first — it is a narrow,
extension-keyed, already-correct feature, so the two can never fight over one
request):

```php
if ($response !== null) {
    ResponseEmitter::emit($response);
} elseif (!$this->serveDecoyArchive($context, $clientIp)) {
    $llmResponse = $this->llmFakes?->respond($context, $clientIp); // null if off/declined/failed
    if ($llmResponse !== null) {
        ResponseEmitter::emit($llmResponse);
    } else {
        // existing plain nginx-style 404, unchanged
    }
}
```

`LlmFakeResponder::respond()` returns a `SynthesizedResponse` (the value type
`ResponseEmitter::emit()` already serves — no new emission path) or `null`, and
`null` at any stage falls straight through to the existing 404. Wire it into the
constructor as a **nullable, opt-in** dependency exactly like the existing
`?Blocklist` / `?AbuseIpdb`, constructed in `demo/index.php` only when a new
`FUNNYPOT_LLM` env flag is on.

Internal flow of `respond()`: kill-switch/enabled → **gate (§3)** → cache lookup →
(miss) single-flight lock → generate with timeout → **sanitize (below)** → cache
write → build `SynthesizedResponse`.

### Cache

- **Key:** `PathNormalizer::key($method, $path)` — the engine's existing
  byte-stable `"METHOD /normalized/path"` builder (deliberately not
  decoded/lowercased, matching how scanners probe exact bytes). **No header or
  body component** — this is a safety property, not an oversight: keying on
  `User-Agent` would let an attacker force unlimited distinct generations against
  one path (an amplification/DoS vector). Include method (galah's omission of it
  is a real bug — a POST reusing a cached GET body).
- **Store:** a new `llm_cache.sqlite`, same idiom as the existing
  `SqliteHitStore`/`Blocklist` (WAL, `busy_timeout=3000`, `0666` chmod so
  www-data and any root listener share it, fail-open). Columns: `cache_key`
  (PK), `status`, `content_type`, `body`, `prompt_version`, `created_at`,
  `last_served_at`, `served_count`.
- **TTL:** none by freshness — a stable fake is *desirable*. The real
  invalidation trigger is a `prompt_version` bump (on any prompt or safety-rule
  change). Bound growth with an LRU `retainBytes()` (oldest-by-`last_served_at`,
  `FUNNYPOT_LLM_CACHE_MAX_BYTES`) run from the existing retention runner — bots
  enumerate large wordlists, so an unbounded cache is a disk-growth vector.
- **Concurrency / stampede:** a second `llm_inflight(cache_key, started_at)`
  table used as an atomic `INSERT OR IGNORE` mutex. Winner generates; losers poll
  briefly (for example 300ms in ~50ms steps) for the row, then fall back to the
  plain 404 for *this* request (the path is warming either way). Reclaim an
  inflight row older than ~15s (crashed worker).
- **Determinism is the point:** one cached fake per path, served to every visitor
  forever. Per-visitor variation on the same path would itself be a fingerprinting
  tell.
- **A generation failure is never cached** (so the path retries once the model is
  healthy) and must NOT produce a distinct error shape — it degrades to the same
  plain 404 as a gate rejection.

### Prompt

Only method, normalized path, and extension hint are attacker-influenced (strip
control bytes and cap length before interpolation). Everything else is fixed
instruction. Reuse two cheap tricks from prior art: a **hardcoded one-shot
exemplar turn** baked in before the real request (beelzebub — stabilises output
format far better than instructions alone), and **inject real facts** (Date/Server
header values) programmatically rather than trusting the model.

```
You are generating a fake web page for a security-research honeypot. Produce a
short, plausible response for the request below, as if this exact software existed.
Method: {method}
Path: {normalized_path}
Rules (must follow exactly):
- Output ONLY the raw HTML body (or plain text) — no explanation, no markdown fences.
- Under {max_chars} characters.
- No <script>, <iframe>, <object>, <embed>, or <link> tags.
- No absolute URLs (no http:// or https://) anywhere.
- No real or realistic credentials, API keys, tokens, private keys, or secrets.
- No working exploit code, shell commands, or SQL.
- If unsure what this app is, produce a generic login / "not authorized" /
  "under construction" page consistent with the product name in the path.
```

Use **GBNF grammar / JSON-schema constrained decoding** so the model structurally
cannot emit `<script>`, external URLs, or runaway length — a far stronger
guarantee than prompt wording.

### Safety guards (enforced in code — model output is never trusted)

A pure, unit-testable `LlmOutputSanitizer::sanitize(string $raw, int $maxBytes):
?string` returning `null` on any violation (treated identically to a failure):

1. Hard byte cap (small, for example 8KB) — **reject over-cap, don't truncate**
   (truncated HTML is malformed). Also bound to a *realistic* byte range for the
   content-type — an oddly tiny or huge "login page" is its own tell.
2. Strip dangerous tags: `<script` `<iframe` `<object` `<embed` `<link`.
3. Strip event-handler attributes: any `on\w+=`.
4. Deny absolute external URLs in `href`/`src`/`action`/CSS `url()` — prevents the
   page becoming an SSRF/beacon or off-site link.
5. Deny-list scan for exploit-shaped content: `<?php`, `#!/bin/`, `eval(`,
   `base64_decode(`, `-----BEGIN...PRIVATE KEY-----`, `../../../`.
6. UTF-8 / non-printable-byte safety (same idea as `SqliteHitStore::clean()`).
7. **Status and Content-Type are app-chosen from a small allowlist (200/401/403/
   404), never model-chosen. Redirects (3xx) are disallowed outright** — an
   LLM-chosen `Location:` would make the honeypot an open redirect.
8. **Never executed** — the sanitized string only ever reaches `header()`/`echo`
   via `SynthesizedResponse`/`ResponseEmitter::emit()`; never `eval`'d,
   `include`'d, or handed to a template engine.

Also sanitize LLM-authored **headers** against the real HTTP stack (galah's
lesson: the model hallucinates protocol-structural headers like `content-length`
and even a fake `"http/1.1"` status line as a header). Let the model supply body
values; never let it own protocol-structural headers.

### Transport and fallback

- `LlmClient::generate()` — bounded-timeout HTTP to `127.0.0.1` via
  `stream_context_create` (the `AbuseIpdb::httpPost()` pattern), with an
  **injectable transport callable** so tests never touch the network. Hard cURL
  timeout (for example 800ms–1.5s) plus an `n_predict` cap so generation cannot
  run long even if the timeout does not fire.
- **Uniform fallback:** timeout, connection refused, non-2xx, malformed response,
  or sanitizer rejection all return `null` → the existing plain-404 branch runs
  unchanged.
- **In-process circuit breaker:** N consecutive failures in a window → skip the
  LLM entirely for a cooldown, so a stalled/OOM'd server does not add
  timeout-latency to every unmatched request during an outage.
- **Resource guards:** `FUNNYPOT_LLM_MAX_CONCURRENT` (COUNT on `llm_inflight`,
  over cap → straight to 404, no queueing) and a global generations/hour ledger
  (`FUNNYPOT_LLM_GENS_PER_HOUR`, SQLite hour buckets, fail-closed) — the backstop
  for a rotating-IP flood the per-IP velocity gate cannot see.

### Timing indistinguishability

`Funnypot\Config` already has `latencyMs` + `latencyJitterMs` applied via
`serveDelayMicros()` (jitter deliberately unseeded so repeat scans see no uniform
delay). Route cache-hit LLM responses through the **same delay path** as matched
template fakes so their timing distribution is identical.

**Pre-existing gap worth fixing as a prerequisite:** the plain-404 branch today
writes directly with `echo`/`http_response_code(404)` and never calls
`serveDelayMicros()`, so a matched fake and a generic 404 *already* have different
timing profiles. Unify the delay envelope across the 404 branch too, so an
attacker sees two timing buckets (fast-nothing vs delayed-something), not three.

---

## 5. Prior-art lessons worth copying

- **Galah (the cautionary tale):** answers every request via prompt instruction
  alone, and it visibly fails on its own `are-you-a-honeypot` test. **No credible
  project solves probe-detection with a runtime model classifier** — every good
  design routes around it structurally. This is the entire justification for §3.
- **Galah caching:** SQLite, key = `port + path` (no headers/body). Coarse keying
  is a *feature* against noisy bots. Copy it, but **add method** (galah's real
  gap). Log the event asynchronously *after* the response is sent so LLM latency
  is not compounded by logging I/O.
- **Galah header hygiene:** it strips a blocklist of LLM-authored headers
  (`content-length`, `date`, hallucinated `"http/1.1"`) before writing. Always
  sanitize model headers against a real HTTP stack.
- **Beelzebub:** the LLM is one *config-routed* handler, never the default. Its
  HTTP maze uses a cheap deterministic `fallbackCommand` for "matched nothing" —
  exactly the shape of Bob's problem, solved by *not* making the LLM the fallback.
  Also copy its **one-shot exemplar prompt turn** and its **input/output
  LLM-judge + per-IP token-bucket** guardrail idea (adapt lightly for a tiny
  model).
- **AdvancedShelLM / shelLM (what actually gives these away at scale):** human
  studies found content realism *saturates fast* — the residual detection budget
  is spent on **uniform latency and non-determinism** (identical/duplicated output
  where a real server would be deterministic). Both point at the same mitigation:
  cache aggressively so any repeat gets byte-identical output, and keep timing
  uniform. At internet-scan scale, the overwhelming majority of traffic is
  shallow noise — most hits are exactly the cheap-probe traffic to keep cheap.
- **LLMHoney / ShellGames (latency):** a dictionary/cache-first binary gate with
  the LLM only as last resort; sub-2B non-reasoning models stay under a second on
  CPU. ShellGames' speculative pre-warming (kick off generation for likely-next
  paths) is a reusable v3 idea, not needed early.

---

## 6. Phased build plan

Each phase is independently shippable and defaults to the current behaviour when
off.

**Phase 0 — timing prerequisite.** Unify `serveDelayMicros()` across the plain-404
branch so the 404 and matched-fake timing buckets already match *before* the LLM
path exists. Small, independently valuable, removes an existing tell.

**Phase 1 — deterministic gate + plain 404 only (no LLM yet).** Ship
`ProbeClassifier` (Gate B, lexical) and the Gate A per-IP behaviour tracker,
config-driven YAML, fully tested (pure host tests). Wire it so it *classifies and
logs* verdicts but still always serves the plain 404. This lets Bob validate the
gate against real traffic logs with zero risk before any generation happens.

**Phase 2 — synchronous LLM behind the gate + cache.** Stand up the
`llama-server` sidecar with Qwen2.5-1.5B. Add `LlmClient`, `LlmOutputSanitizer`,
`LlmFakeCache`, `LlmFakeResponder`, the `elseif` hook, GBNF grammar, single-flight
lock, circuit breaker, and resource caps. Opt-in via `FUNNYPOT_LLM`. Smallest
useful end-to-end honeypot. Generation is inline (bounded timeout); first hit to a
new plausible path may fall back to 404 if generation is slow, cache serves every
hit after.

**Phase 3 — hardening.** Prompt-version invalidation, `retainBytes` LRU eviction
in the retention runner, dashboard `event => 'llm-fake'` log rows (free UI reuse
via the existing feed), A/B SmolLM2-1.7B vs Qwen2.5-1.5B, tune Gate A thresholds
from Phase 1 data.

**Phase 4 (optional) — async generation.** If p99 latency or timing analysis says
the inline path queues badly or is a distinguishable timing signal, split into
enqueue/drain like `AbuseIpdb`: first hit always serves the plain 404 instantly
and enqueues a background job; the second hit onward serves the cached fake. This
also removes LLM latency from the request path entirely and defuses
wordlist-burst concurrency for free. Codebase already has the exact precedent.

---

## 7. Open questions / decisions for Bob

1. **Qwen2.5-1.5B or SmolLM2-1.7B?** Both Apache 2.0, same weight class. Reports
   split narrowly (LLMHoney reliability favours Qwen; IFEval favours SmolLM2).
   Recommend shipping Qwen2.5-1.5B and A/B testing SmolLM2 in Phase 3.
2. **Instance size — `t4g.medium` (4 GB, cheaper) or `t4g.large` (8 GB, headroom)?**
   Depends on whether the box also runs the full protocol-listener stack and how
   bursty traffic is. Recommend `t4g.large` unless cost-sensitive.
3. **Gate A thresholds** (5/60s, 15/10min, 24h cooldown) are starting points —
   need tuning against real funnypot traffic logs (Phase 1 exists to gather this).
4. **Synchronous (Phase 2) or straight to async (Phase 4)?** Sync is simpler and
   probably fine given probes repeat heavily across bots; async removes all
   request-path latency but is more moving parts. Recommend sync first, measure,
   escalate only if data demands it.
5. **Prompt strategy: prompt-engineer the general instruct model, or fine-tune a
   honeypot-specialised tiny model?** (LLM Honeypot, arXiv 2409.08234, fine-tuned
   in 14 minutes on 617 curated commands.) Recommend prompt-only for v1; revisit
   fine-tuning only if generic output reads thin.
6. **Cache eviction policy — pure LRU by `last_served_at`, or add a hard age cap?**
   LRU alone lets a rarely-hit-but-real fake survive; an age cap bounds staleness.
   Recommend LRU-only given fakes are meant to be stable.

### Future idea (Bob) — LLM-classified AbuseIPDB reports

A second, separate LLM pass could classify a probe (what is it after, severity, is it report-worthy)
and enrich the AbuseIPDB report comment. It must run OFF the request path — on the existing
enqueue/drain queue (like `abuse-drain.php`), never inline — so it never adds latency to the honeypot
response. Reuse the same sidecar; a different prompt + grammar (JSON verdict instead of HTML). Deferred
until the generation layer ships.

### Rough cost / latency expectations (CPU)

- **Generation (cache miss, warm prefix):** low hundreds of ms to a few seconds
  for Qwen2.5-1.5B Q4_K_M at ~25–40 tok/s with `n_predict` capped ~300 and
  `cache_prompt: true` (TTFT drops from ~400ms to <50ms once the system prompt is
  warm). Only ever paid once per unique plausible path.
- **Cache hit (the common case):** a single SQLite read plus the normal delay
  envelope — indistinguishable from a matched template fake.
- **Gate rejection (the overwhelming majority of unmatched traffic):** pure
  deterministic PHP, no model call, same fast plain 404 as today.
- **Extra RAM:** ~1.5–2 GB resident for the model process, on top of funnypot's
  existing footprint — the main reason for `t4g.medium`-or-larger.
