# LLM Honeypot Layer - Build Spec (Phase 2)

Status: implementation spec + gate-code review. Grounds the next build phase on the
code that exists today. Companion to `LLM-HONEYPOT-RESEARCH.md` (the design) and
`LLM-MODEL-EVAL.md` (the model pick). Read those first for the "why".

The gate (Phase 1) is built: `src/App/Llm/ProbeClassifier.php`,
`VelocityTracker.php`, `ProbeGate.php`, `SqliteHitStore::probeVelocity()`. It is
not yet wired into the request path. This doc reviews that code, then specs the
sidecar, the Phase 2 PHP classes, the grammar, and the safety work.

---

## 1. Review of the gate code

Overall: the shape is right (two orthogonal checks, default-deny, pure and
testable, no I/O in the gate itself). The problems below are real and several are
load-bearing for the "no fingerprint tell" promise. Ordered by severity.

### 1.1 CRITICAL - Gate B accepts random tokens that carry an allowed extension

`ProbeClassifier::classify()` returns `plausible` for **any** path whose leaf ends
in an allowlisted extension, even when the stem is random garbage, because the
extension-allow branch (`ProbeClassifier.php:114`) fires with no positive stem
signal required:

```php
if ($ext !== '' && in_array($ext, self::EXT_ALLOW, true)) {
    return 'plausible';   // ProbeClassifier.php:114
}
```

Verified by tracing the real code:

```
/asdf1234.php   => plausible
/6qaz2wsx.php   => plausible     # ffuf/-ac calibration token shape + appended ext
/qwertyui.asp   => plausible
```

This is the exact failure the whole design exists to prevent. Content-discovery
tools fire random calibration tokens with the extension they are fuzzing (`ffuf`
appends `.php`/`.asp`; `feroxbuster`/`dirsearch` do the same). Those tokens sail
through Gate B. The only thing left standing between them and a unique fabricated
page is Gate A's volume threshold, and Gate A needs **5 distinct paths in 60s**
before it trips (`VelocityTracker.php:24`). So the **first four** calibration
probes each generate and cache a distinct rich page for a random string before the
IP is ever flagged. N random strings returning N distinct pages is precisely the
statistical tell described in `LLM-HONEYPOT-RESEARCH.md` section 1, and it can leak
in the opening handful of requests of a scan.

The `looksRandom()` check does not save this: it only catches all-hex stems of 8+
chars (`^[a-f0-9]{8,}$`) or entropy >= 3.85 over 8+ chars
(`ProbeClassifier.php:176-186`). A mixed alnum 8-char token like `6qaz2wsx` scores
~3.0 bits/char (8 distinct chars, `log2(8) = 3.0`), well under 3.85, so it is not
"random" to the classifier. The hex-only test in the suite
(`/a8f3c2b1d4e5.php` -> probe, `ProbeClassifierTest.php:71`) passes and hides this,
because it never tries a non-hex calibration token.

Fix: **an allowed extension must not be sufficient on its own.** Require a positive
stem signal (app word, pronounceable, or dotfile) in addition to the extension.
Drop the bare-extension accept at `:114` and let those paths fall to the
`pronounceable()` / app-word checks. Verified this keeps all 18 existing
`plausiblePaths` green (every one has an app word, a hard-allow hit, or a
pronounceable stem; none rely solely on the extension) while turning
`/asdf1234.php` and `/6qaz2wsx.php` into `probe`. Add those two as regression
cases. Separately, lower `looksRandom()`'s entropy floor and length floor (for
example >= 3.4 bits/char over >= 6 chars) so mixed-alnum calibration tokens are
caught even when an extension is present, and add a "mostly digits+letters with no
vowel-consonant structure" heuristic.

### 1.2 HIGH - Gate B only inspects the leaf; random directories slip through

`looksRandom()` and the `PROBE_TOKENS` / `404` checks run only against the leaf
stem (`ProbeClassifier.php:72-95`). The positive app-word scan iterates all
segments (`:99`), but the probe-rejection signals do not. So a plausible leaf
inside a random directory is accepted:

```
/aG7xK9pQ2/login.php => plausible     # verified
```

An attacker wraps a real filename in a random directory and defeats the lexical
gate on a single shot. Fix: run the entropy / probe-token / long-numeric checks
against **every** segment, not just the leaf. If any segment looks random or
carries a calibration tell, return `probe`.

### 1.3 HIGH - The 24h bulk-scan pin from the plan is not implemented

`LLM-HONEYPOT-RESEARCH.md` section 3 Gate A specifies: once an IP trips, "pin it to
plain-404-only for a cooldown (for example 24h)". `VelocityTracker` has no state
and no cooldown (`VelocityTracker.php` is a pure threshold check over a live
sliding window). An IP that bursts, trips the 60s window, then goes silent for 10
minutes has its window drain to zero and is un-flagged, free to slow-probe for
fakes at a low rate. The persistent pin the plan calls for does not exist. Add a
`llm_scan_flag(ip, flagged_at)` table (or reuse the store) and treat a flagged IP
as bulk-scan for the cooldown window regardless of current velocity.

### 1.4 MEDIUM - Two of the three Gate A signals from the plan are missing

The plan's Gate A lists three signals: distinct-path volume, "same high-entropy
token probed against >= 2 base directories" (the feroxbuster wildcard-recursion
signature), and inter-arrival uniformity. Only distinct-path volume is built
(`SqliteHitStore::probeVelocity()`). The other two are absent. Not blockers for
Phase 2, but note them as known gaps so Phase 3 tuning does not assume they exist.

### 1.5 MEDIUM - `probeVelocity()` counts all paths, and counts the current request

> **Resolved.** `probeVelocity()` now counts only rows with `served = 0 AND matched = 0`, and the
> controller appends the main hit row *after* the serve branch with `served` reflecting the actual
> outcome (engine fake, decoy archive or LLM fake — the decoy-archive event row is served+matched too),
> so neither served follows nor the current request are in the count: a human following decoy links
> is never pinned. The compensating bound for a plausible-wordlist scanner that accrues no velocity is
> the global `FUNNYPOT_LLM_GENS_PER_HOUR` budget. The text below describes the original state.

`SqliteHitStore::probeVelocity()` (`SqliteHitStore.php:283-296`) does
`COUNT(DISTINCT path) ... WHERE ip = :ip AND ts >= :cutoff`. Two divergences from
the plan text ("distinct not-found paths"):

- It counts **all** distinct paths for the IP, including matched-template hits and
  served pages, not just 404s. Arguably fine for a honeypot (any enumeration
  should trip it), but it is not what the doc says, so document the actual
  behaviour or add `AND matched = 0`.
- The current request is appended in `HoneypotController::handle()`
  (`HoneypotController.php:113-130`) **before** the null->404 branch where the gate
  will run, so the just-logged request is included in the count. The effective
  threshold is therefore "4 prior + this one" for 5/60s. Off-by-one that matters
  for tuning. Either subtract 1, exclude the current row, or bake the inclusive
  count into the documented threshold.

### 1.6 MEDIUM - `probeVelocity()` efficiency on the hot path

This runs on **every unmatched request** (the majority of scanner traffic) and
issues **two** `COUNT(DISTINCT path)` queries (`SqliteHitStore.php:288-293`).

- `idx_hits_ip` on `hits(ip)` exists (`SqliteHitStore.php:336`), so the IP equality
  seeks fine. But `COUNT(DISTINCT path)` still has to read the `path` column from
  every matching row and dedupe it in memory; the single-column index does not
  cover it. For a heavy talker with thousands of rows in the 10-minute window this
  reads all of them, twice.
- Add a composite `idx_hits_ip_ts ON hits(ip, ts)` so the `ts` range is satisfied
  from the index; a covering `hits(ip, ts, path)` is even better if disk allows.
- Collapse the two round-trips into one query with conditional aggregation:
  `SELECT COUNT(DISTINCT CASE WHEN ts >= :c60 THEN path END) recent,
  COUNT(DISTINCT path) extended FROM hits WHERE ip = :ip AND ts >= :c600`.
- Under a WAL write burst these reads queue behind the append; `busy_timeout=3000`
  makes that a stall, not an error, but it is latency on the hot path. The circuit
  breaker (section 3) should also short-circuit the velocity query when the LLM is
  disabled or tripped, so we never pay it when we would not generate anyway.

Note: `ts >= :cutoff` string compare is safe because every `ts` is
`gmdate('c')` with a fixed `+00:00` offset, so lexical order equals chronological
order. Keep it that way (any writer using a different offset would silently break
the window).

### 1.7 LOW - Correctness and cleanliness nits

- `ProbeClassifier::classify()` ignores its `$method` argument entirely. Either use
  it (a `TRACE`/`CONNECT` is less plausible than `GET`/`POST`) or drop the param to
  avoid implying it matters. The gate and cache key both include method elsewhere,
  so leaving it unused here is a mild inconsistency.
- The `leaf === ''` -> `plausible` branch (`ProbeClassifier.php:73-75`) and its
  comment are misleading. `leaf()` returns `''` only for `/` (root), never for
  `/portal/` (that yields leaf `portal`). So this branch classifies bare root as
  plausible and the comment about "a bare directory like /portal/" is wrong.
  Harmless in practice (root is handled upstream) but fix the comment.
- App-word substring matching for words of length >= 4 (`ProbeClassifier.php:108`)
  causes false-allows: `test` matches inside `greatest`/`contest`/`latest`
  (`/greatest.php => plausible`, verified), `user` inside `chooser`, and so on.
  Low risk (biases toward generate on odd-but-wordlike tokens) but worth tightening
  to word-boundary or known-suffix awareness if false-allows show up in logs.
- `HARD_ALLOW` uses `strpos` anywhere in the lowered full path
  (`ProbeClassifier.php:66-69`), so `/foo.github/x` matches `.git` and
  `/development` does not (needs the dot) but `/x/.gitfoo` does. Intended bias is
  allow, so acceptable, but note the substring breadth.

### 1.8 Gaps vs the plan, and one thing the gate does NOT defend

- Distributed enumeration (one IP per path, botnet or cloud rotation) defeats Gate
  A entirely, leaving only Gate B. Gate B correctly accepts real dictionary words
  (`/admin`, `/login`), and that is fine: those get **one** cached fake served
  identically to everyone, which is not a tell (a real server also differs between
  `/admin` and `/login`). The residual tell is different: under distributed
  probing of many *plausible-but-nonexistent* paths, the honeypot answers **too
  many** of them with 200s, when a real server would 404 most. "Every plausible
  path exists" is itself a fingerprint. Mitigation belongs in the responder, not
  the gate: bias generated fakes heavily toward app-styled `401`/`403`/`404` status
  (still convincing, still cached, but keeps the 200 hit-rate realistic). Call this
  out for Phase 3; it does not block Phase 2.
- The gate is not yet called anywhere. `probeVelocity` has no production caller
  (only tests). Wiring is Phase 2, section 3 below.

---

## 2. The funnypot-llm sidecar contract

A second container, `funnypot-llm`, running llama.cpp `llama-server` with
Qwen2.5-Coder-0.5B (per `LLM-MODEL-EVAL.md`; the 0.5B-class pick, grammar does the
format heavy lifting). Bound to the internal docker network only, never published.
The PHP app is the only client.

### 2.1 Endpoint

`llama-server` exposes an OpenAI-compatible API and a native `/completion`. Use the
**native `POST /completion`**: it takes a raw GBNF `grammar` field directly and an
`n_predict` cap, which is exactly what we need and avoids chat-template overhead for
a single-turn generation.

```
POST http://funnypot-llm:8080/completion
Content-Type: application/json
```

Request JSON (only `prompt` carries attacker-influenced bytes, already sanitized
and length-capped by the PHP prompt builder):

```json
{
  "prompt": "<full prompt string, system instructions + one-shot exemplar + the request>",
  "grammar": "<GBNF grammar string, see section 4>",
  "n_predict": 320,
  "temperature": 0.4,
  "top_p": 0.9,
  "repeat_penalty": 1.1,
  "cache_prompt": true,
  "stop": ["</html>"],
  "seed": "<derived per install + path: persona seed mixed with the cache key>"
}
```

Notes:
- `cache_prompt: true` keeps the fixed system+exemplar prefix warm across calls, so
  time-to-first-token drops after the first generation (the research doc's warm-prefix
  assumption).
- `seed` is derived by the responder from the install's persona seed and the normalised
  cache key: reproducible for one path on one install (reinforcing the "one deterministic
  fake per path" property even before the SQLite cache is consulted), different across
  paths, and different across installs — a fixed fleet-wide seed made every persona-less
  kind byte-identical on every deployment. The client's bare default is inert; the
  responder always overrides it.
- The `grammar` field is the structural safety control. `llama-server` compiles the
  GBNF and constrains every sampled token to it, so `<script`, a leading `Sure!`,
  or an unterminated document are unreachable.

Assistant prefill: llama.cpp `/completion` has no separate assistant-turn field, so
prefill is done by **ending the prompt string with the opening bytes of the answer**
(`<!doctype html>\n<html`). The model continues an HTML document already in
progress rather than deciding whether to answer, which blunts refusals. The grammar
must permit that exact prefix as a legal start.

Response JSON (llama-server shape, relevant fields):

```json
{
  "content": "<title>Sign in</title>...</html>",
  "stop": true,
  "stopped_eos": true,
  "stopped_limit": false,
  "tokens_predicted": 214,
  "timings": { "predicted_ms": 640.2 }
}
```

The PHP client reads `content` and treats everything else as diagnostics. `content`
is the raw model body; it is still passed through `LlmOutputSanitizer` because the
grammar constrains structure, not semantics (it cannot stop the model writing a real
looking password into visible text).

### 2.2 Healthcheck

`GET http://funnypot-llm:8080/health` returns `{"status":"ok"}` when the model is
loaded. Used by:
- the compose `healthcheck` so the app container can `depends_on` a healthy model,
- the `LlmClient` circuit breaker as a cheap liveness probe before the first
  generate after a cooldown.

### 2.3 Example round trip

Request (`GET /super-rare-app/login.asp`, prompt abbreviated):

```json
{
  "prompt": "You are generating a fake web page for a security-research honeypot...\nMethod: GET\nPath: /super-rare-app/login.asp\n<one-shot exemplar>\n<!doctype html>\n<html",
  "grammar": "root ::= \"<!doctype html>\" ...",
  "n_predict": 320,
  "cache_prompt": true,
  "stop": ["</html>"]
}
```

Response:

```json
{
  "content": ">\n<head><title>Super Rare App - Sign in</title></head>\n<body>\n<h1>Sign in</h1>\n<form method=\"post\" action=\"/super-rare-app/login.asp\">\n<label>User</label><input name=\"user\">\n<label>Password</label><input name=\"pass\" type=\"password\">\n<button>Log in</button>\n</form>\n</body>\n</html>",
  "stop": true,
  "stopped_eos": true,
  "tokens_predicted": 96
}
```

The PHP client concatenates the prefill (`<!doctype html>\n<html`) with `content`,
sanitizes, and caches. Served status is app-chosen (200 for a login page), never
model-chosen.

### 2.4 Dockerfile approach (no committed model)

New `demo/Dockerfile.llm`, added as a service in `demo/docker-compose.yml`. Base
image must build llama.cpp `llama-server` for both `linux/arm64` (the t4g target)
and `linux/amd64` (local dev). Two clean options:

- Use the official upstream image `ghcr.io/ggml-org/llama.cpp:server` (multi-arch,
  ships `llama-server` as entrypoint). Simplest; pin a digest so the build is
  reproducible.
- Or a two-stage build: `FROM` a build image that clones and `cmake`-builds
  llama.cpp with `-DGGML_NATIVE=OFF` (portable) plus the arch NEON/AVX flags, then
  copy `llama-server` into a slim runtime. Only needed if the upstream image is
  unacceptable.

Model is **downloaded at build**, never committed (matches the baked-image
philosophy but keeps a ~400MB GGUF out of git):

```dockerfile
# Dockerfile.llm  (sketch)
FROM ghcr.io/ggml-org/llama.cpp:server@sha256:<pin>
ARG MODEL_URL=https://huggingface.co/Qwen/Qwen2.5-Coder-0.5B-Instruct-GGUF/resolve/main/qwen2.5-coder-0.5b-instruct-q4_k_m.gguf
ARG MODEL_SHA256=<pin>
RUN mkdir -p /models \
 && wget -qO /models/model.gguf "$MODEL_URL" \
 && echo "$MODEL_SHA256  /models/model.gguf" | sha256sum -c -
EXPOSE 8080
ENTRYPOINT ["/llama-server", \
  "--model", "/models/model.gguf", \
  "--host", "0.0.0.0", "--port", "8080", \
  "--ctx-size", "2048", \
  "--parallel", "2", \
  "--threads", "2", \
  "--cont-batching", \
  "--no-webui"]
```

Pin both the image digest and the model SHA256 so a supply-chain swap fails the
build. Compose wiring:

```yaml
  funnypot-llm:
    build: { context: .., dockerfile: demo/Dockerfile.llm }
    expose: ["8080"]          # internal only, never in `ports:`
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8080/health"]
      interval: 10s
      timeout: 3s
      retries: 12
    restart: unless-stopped
  funnypot:
    depends_on:
      funnypot-llm: { condition: service_healthy }
    environment:
      FUNNYPOT_LLM: "1"
      FUNNYPOT_LLM_URL: "http://funnypot-llm:8080/completion"
```

The sidecar is opt-in: without `FUNNYPOT_LLM=1` the app never calls it and the
service can be left out of compose entirely.

---

## 3. Phase 2 PHP class design (`src/App/Llm/`)

All new classes join the existing gate classes in `src/App/Llm/`. The store lives in
`src/App/Storage/`. Everything is nullable/opt-in and every failure path returns
`null` so the request falls through to the unchanged plain 404.

### 3.1 `LlmClient` - HTTP transport, timeout, circuit breaker

Mirrors `AbuseIpdb::httpPost()` (`stream_context_create`, `ignore_errors`, timeout),
with an injectable transport so tests never touch the network.

```php
final class LlmClient
{
    /** @param callable(string,string):array{status:int,body:string}|null $transport */
    public function __construct(
        private string $url,
        private int $timeoutMs = 1500,
        private int $nPredict = 320,
        private ?CircuitBreaker $breaker = null,
        private $transport = null,
    ) {}

    /** Raw generation. Returns the model body, or null on any failure / open breaker. */
    public function generate(string $prompt, string $grammar): ?string;

    public function healthy(): bool;   // GET /health, used by the breaker
}
```

- Hard timeout (`timeoutMs`, default 1500) plus `n_predict` cap so a slow model
  cannot hold a php-fpm worker.
- Uniform failure: connection refused, non-2xx, timeout, malformed JSON, missing
  `content` all return `null`.
- Circuit breaker is a tiny in-process/SQLite-backed counter: N consecutive
  failures in a window opens it for a cooldown; while open, `generate()` returns
  `null` immediately without a socket call, so a dead sidecar does not add
  timeout-latency to every unmatched request. Model the counter on
  `AbuseIpdb`'s daily-counter table idiom.

```php
final class CircuitBreaker
{
    public function __construct(private string $dbPath, private int $threshold = 5, private int $cooldownSecs = 30) {}
    public function allow(): bool;      // false while open
    public function recordSuccess(): void;
    public function recordFailure(): void;
}
```

### 3.2 `LlmOutputSanitizer` - pure, model output is hostile (section 4 safety rules)

```php
final class LlmOutputSanitizer
{
    /** @return string|null null on ANY violation (treated identically to a generation failure) */
    public function sanitize(string $raw, int $maxBytes = 8192): ?string;
}
```

Enforces, in order, returning `null` on any hit (never truncating: a truncated body
is malformed and a tell):
1. Byte cap `<= maxBytes`, and a **minimum** realistic size (reject a 12-byte "login
   page").
2. Reject if it contains `<script`, `<iframe`, `<object`, `<embed`, `<link`
   (case-insensitive).
3. Reject any `on\w+\s*=` event-handler attribute.
4. Reject absolute external URLs in `href`/`src`/`action`/CSS `url()`
   (`https?://`, `//host`).
5. Reject exploit-shaped content: `<?php`, `#!/bin/`, `eval(`, `base64_decode(`,
   `-----BEGIN ... PRIVATE KEY-----`, `../../`.
6. UTF-8 / non-printable-byte safety (reuse the `SqliteHitStore::clean()` idea; here
   reject rather than escape, since a real HTML page has no control bytes).
7. Status and Content-Type are NOT taken from the model. The sanitizer returns only
   a validated body; status/content-type are chosen by `LlmFakeResponder` from a
   fixed allowlist (`200/401/403/404`, no 3xx).

Pure and host-testable (no framework). This is where most Phase 2 test coverage goes.

### 3.3 `LlmFakeCache` - sqlite, single-flight, LRU

New store `src/App/Storage/LlmFakeCache.php`, same PDO idiom as `SqliteHitStore`
(WAL, `busy_timeout=3000`, `0666` chmod before WAL, fail-open). Separate file
`llm_cache.sqlite` so it never contends with the hot `hits` writes.

```php
final class LlmFakeCache
{
    public function __construct(string $dbPath) {}

    /** Cached fake for this key, or null. */
    public function get(string $key): ?array;   // ['status'=>int,'content_type'=>string,'body'=>string]

    /** Store a generated fake. Never called for a failure. */
    public function put(string $key, int $status, string $contentType, string $body, string $promptVersion): void;

    /** Single-flight: true if THIS caller won the lock and should generate. */
    public function acquire(string $key): bool;   // INSERT OR IGNORE into llm_inflight
    public function release(string $key): void;
    public function awaitOther(string $key, int $waitMs = 300): ?array;   // poll get() briefly

    /** LRU eviction to a byte budget, run from the retention runner. Returns rows removed. */
    public function retainBytes(int $maxBytes): int;

    /** Reclaim inflight rows older than $secs (crashed winner). */
    public function reapInflight(int $secs = 15): void;
}
```

Schema:
```sql
CREATE TABLE llm_cache (
  cache_key TEXT PRIMARY KEY, status INTEGER, content_type TEXT, body TEXT,
  prompt_version TEXT, created_at TEXT, last_served_at TEXT, served_count INTEGER DEFAULT 0
);
CREATE TABLE llm_inflight (cache_key TEXT PRIMARY KEY, started_at TEXT);
CREATE INDEX idx_llm_cache_lru ON llm_cache(last_served_at);
```

- **Key = `PathNormalizer::key($method, $path)`** (`"GET /normalized/path"`,
  `vendor/.../Support/PathNormalizer.php:49`). Method included (galah's gap), no
  header/body component (keying on User-Agent would let one path be forced into
  unlimited distinct generations - an amplification vector, and per-visitor
  variation is itself a tell).
- **No freshness TTL.** A stable fake is desirable. Invalidation is a
  `prompt_version` bump (compare on read; a stale-version row is a miss and
  regenerates).
- **Single-flight:** `acquire()` is `INSERT OR IGNORE INTO llm_inflight`. Winner
  generates; losers `awaitOther()` for ~300ms in ~50ms steps, then fall back to the
  plain 404 for this request (the path is warming either way). `reapInflight()` runs
  from the retention timer.
- **LRU** by `last_served_at`, budget `FUNNYPOT_LLM_CACHE_MAX_BYTES`, evicted from
  `demo/retention.php` alongside the existing `retainBytes` call.

### 3.4 `LlmFakeResponder` - orchestrator

```php
final class LlmFakeResponder
{
    public function __construct(
        private ProbeGate $gate,
        private LlmFakeCache $cache,
        private LlmClient $client,
        private LlmOutputSanitizer $sanitizer,
        private HitStore $store,
        private LlmPromptBuilder $prompt,
        private string $grammar,
        private string $promptVersion,
        private int $maxConcurrent = 4,
    ) {}

    /** Returns a SynthesizedResponse to emit, or null for every decline / failure. */
    public function respond(RequestContext $context, string $clientIp): ?SynthesizedResponse;
}
```

Flow of `respond()` (any step returning null falls straight to the plain 404):
1. `$key = PathNormalizer::key($context->method, $context->path)`.
2. Cache hit? -> build `SynthesizedResponse` (bump `served_count`/`last_served_at`),
   return it. This is the common, cheap case.
3. Gate: `$velocity = $store->probeVelocity($clientIp);
   $d = $gate->decide($context->method, $context->path, $velocity);` If
   `!$d['generate']` -> return null. (The gate query runs only on a cache miss, so a
   warm path never pays it.)
4. Concurrency guard: if inflight COUNT >= `maxConcurrent` -> return null (no
   queueing).
5. `acquire($key)`? If lost -> `awaitOther()`, return its result or null.
6. `$raw = $client->generate($prompt->build($context), $grammar)`; on null ->
   `release()`, return null (failure never cached).
7. `$body = $sanitizer->sanitize($raw)`; on null -> `release()`, return null.
8. Choose status/content-type from the allowlist (bias toward `401`/`403`/`404`
   app-chrome for most paths per section 1.8), `cache->put()`, `release()`.
9. Append a `event => 'llm-fake'` hit row (mirroring `serveDecoyArchive`, which
   appends its own row, `HoneypotController.php:207-216`) so the dashboard shows it.
10. Return `new SynthesizedResponse($status, $headers, $body, Detection::none())`.

`Detection::none()` (`vendor/.../Detection.php:35`) fills the `satisfies` slot;
there is no template match behind an LLM fake.

### 3.5 The controller hook

`HoneypotController` gains a nullable `?LlmFakeResponder $llmFakes = null`
constructor arg (exactly like `?Blocklist`/`?AbuseIpdb`,
`HoneypotController.php:31-33`), constructed in `demo/index.php` only when
`FUNNYPOT_LLM` is on. The new branch slots between decoy-archive and the literal
404 (`HoneypotController.php:132-141`):

```php
if ($response !== null) {
    ResponseEmitter::emit($response);
} elseif (!$this->serveDecoyArchive($context, $clientIp)) {
    $llm = $this->llmFakes?->respond($context, $clientIp);   // null if off / declined / failed
    if ($llm !== null) {
        usleep($this->serveDelayMicrosForFake());            // same delay envelope as a matched fake
        ResponseEmitter::emit($llm);
    } else {
        // existing plain nginx-style 404, unchanged
        http_response_code(404);
        header('Content-Type: text/html');
        echo "<html>\r\n<head><title>404 Not Found</title></head>\r\n..."; // as today
    }
}
```

Two things to get right here:
- **Timing.** Route the LLM response (and, per Phase 0, the plain 404 too) through
  the same `serveDelayMicros()` envelope as a matched template fake, or an attacker
  sees distinct timing buckets. The plain-404 branch does not delay today
  (`HoneypotController.php:136-140`); fix that in Phase 0 as the plan says.
- **Logging.** `handle()` already appended the main hit row with `served => false`
  before this branch (`HoneypotController.php:113`). The responder appends its own
  `event => 'llm-fake'` row (step 9), matching how decoy-archive double-logs. Accept
  the same double-row quirk decoy-archive already has, or, better, refactor so
  `served`/`event` is decided once before the append. Note the double-count in
  `stats()` either way.

### 3.6 Config surface (`FUNNYPOT_LLM_*`)

Add to `AppConfig` (`src/App/Config/AppConfig.php`), resolved once like every other
var:

| Env var | Default | Meaning |
|---|---|---|
| `FUNNYPOT_LLM` | off (`0`) | Master opt-in. Off = responder never constructed. |
| `FUNNYPOT_LLM_URL` | `http://funnypot-llm:8080/completion` | Sidecar completion endpoint. |
| `FUNNYPOT_LLM_TIMEOUT_MS` | `9000` | Hard per-request generation timeout. |
| `FUNNYPOT_LLM_N_PREDICT` | `320` | Token cap. |
| `FUNNYPOT_LLM_CACHE_DB` | `<store>/llm_cache.sqlite` | Cache file. |
| `FUNNYPOT_LLM_CACHE_MAX_BYTES` | `0` (unbounded) | LRU budget for the retention runner. |
| `FUNNYPOT_LLM_MAX_CONCURRENT` | `4` | In-flight generation cap; over -> plain 404. |
| `FUNNYPOT_LLM_GENS_PER_HOUR` | `60` | Global fresh-generation budget per hour across ALL IPs (the rotating-IP backstop the per-IP gate cannot be); over it, cache-only. Fail-closed on a ledger fault. |
| `FUNNYPOT_LLM_PROMPT_VERSION` | `v3` | Cache invalidation key. |
| `FUNNYPOT_LLM_BREAKER_THRESHOLD` | `5` | Consecutive failures to open the breaker. |
| `FUNNYPOT_LLM_BREAKER_COOLDOWN_S` | `30` | Breaker open duration. |

### 3.7 How every failure returns null -> plain 404

Confirmed against the code: `respond()` returns `?SynthesizedResponse`, and the hook
treats `null` as "do nothing, run the existing 404". Every internal decline returns
null - gate reject, cache miss with lost single-flight and no peer result,
concurrency cap, spent hourly budget, open breaker, transport failure, malformed
response, sanitizer rejection, and the responder-not-constructed case
(`$this->llmFakes?->` short-circuits to null). None of these produce a distinct
error shape; all collapse to the same byte-identical plain 404 the honeypot serves
today. A generation failure is never written to the cache, so the path retries once
the model is healthy.

---

## 4. GBNF grammar sketch (HTML only, first token `<`, no `<script>`, bounded)

Goal: make refusal preambles, markdown fences, `<script>`, and runaway length
structurally unreachable. The grammar forces a document that begins `<!doctype
html>` and is a bounded sequence of safe inline text and a closed tag set. Length is
bounded by the grammar's repetition limits plus `n_predict` and the `</html>` stop.

```gbnf
root      ::= "<!doctype html>" ws "<html" htmlbody "</html>"
htmlbody  ::= (safechar | tag){1,4000}
tag       ::= "<" tagname attrs ">" | "</" tagname ">" | "<" tagname attrs "/>"
tagname   ::= "html" | "head" | "title" | "meta" | "body" | "div" | "span" | "p"
            | "h1" | "h2" | "h3" | "ul" | "li" | "a" | "form" | "label" | "input"
            | "button" | "table" | "tr" | "td" | "th" | "br" | "hr" | "b" | "i" | "center"
attrs     ::= (ws attr){0,6}
attr      ::= attrname "=\"" attrval "\""
attrname  ::= "class" | "id" | "name" | "type" | "value" | "method" | "action"
            | "placeholder" | "for" | "href" | "colspan" | "rowspan"
attrval   ::= relval
relval    ::= ([a-zA-Z0-9 _\-./?=&:#]){0,120}     # no scheme:// producible below
safechar  ::= [^<>] 
ws        ::= [ \t\n]*
```

Grammar-level guarantees (why this is stronger than prompt wording):
- The only legal first bytes are `<!doctype html>`, so `Sure!`, a markdown fence,
  and any refusal sentence are unreachable.
- `tagname` has no `script`/`iframe`/`object`/`embed`/`link` alternative, so those
  tags cannot be emitted at all.
- `attrname` has no `on*` handler alternative; event handlers are unreachable.
- `href`/`action` values come from `relval`, whose character class permits `/ . ? =
  & : #` but the grammar never lets the model assemble a `//` authority as an
  attribute start in a way that forms an absolute URL prefix; belt-and-braces, the
  sanitizer (section 3.2 rule 4) still rejects any `https?://` or `//host`, since
  grammars are awkward at "no substring" constraints.
- Length is bounded by `{1,4000}` on the body plus `n_predict` plus the `</html>`
  stop token.

The grammar constrains structure; `LlmOutputSanitizer` still runs, because the
grammar cannot enforce semantics (it cannot stop the model typing a realistic
password or an `eval(` inside visible text). Grammar > prefill > exemplar > wording,
all four shipped, per `LLM-MODEL-EVAL.md` section 3.

The grammar string is stored as a file (for example
`resources/llm/html.gbnf`), read once at construction, and its content is part of
what a `FUNNYPOT_LLM_PROMPT_VERSION` bump should account for (a grammar change can
change output, so cached fakes from an old grammar should be invalidated with it).

---

## 5. Safety gaps to close, and the phased checklist

### 5.1 Safety gaps (close before Phase 2 ships)

1. **Close the Gate B extension hole (section 1.1)** and the random-directory hole
   (section 1.2). These are the difference between the design working and leaking
   the exact tell it exists to prevent. Highest priority; they are gate bugs, not
   new features.
2. **Implement the persistent bulk-scan pin (section 1.3)** so a burst-then-slow
   scanner stays flagged.
3. **Model output is never executed.** The sanitized body reaches output only via
   `SynthesizedResponse` -> `ResponseEmitter::emit()` (`echo`), never `eval`,
   `include`, or a template engine. Keep it that way; add a test asserting the
   responder never interpolates model output into anything but the body field.
4. **App owns protocol-structural headers.** The model supplies body only. Status,
   Content-Type, Server, X-Powered-By are app-chosen. `ResponseEmitter` already
   strips CR/LF/NUL from header names and values (`ResponseEmitter.php:22-24`), so
   even a hallucinated header string cannot split the response; do not pass
   model-authored headers in at all.
5. **No redirects.** Status allowlist is `200/401/403/404`; no `3xx`, so an
   LLM-chosen `Location` can never make the honeypot an open redirect.
6. **Amplification / DoS guards.** Cache key excludes headers/body (no per-UA
   generation), `FUNNYPOT_LLM_MAX_CONCURRENT` caps in-flight generations,
   `FUNNYPOT_LLM_GENS_PER_HOUR` caps the global rate, the circuit breaker sheds load
   when the model is down (half-open: one probe per cooldown, so a dead sidecar never
   produces an open/stampede/open latency sawtooth), and the LRU budget bounds disk.
   Verify all four are wired, not just present.
7. **Sanitizer rejects, never truncates**, and enforces a realistic min/max size
   band per content-type (an oddly tiny or huge page is its own tell).
8. **Timing parity (Phase 0).** Unify `serveDelayMicros()` across the plain-404
   branch and the LLM branch so there are two timing buckets at most (nothing vs
   something), not three.

### 5.2 Phased checklist

Phase 0 - timing prerequisite
- [ ] Apply `serveDelayMicros()` to the plain-404 branch in
      `HoneypotController::handle()`. Independently valuable, removes an existing tell.

Phase 1 - gate hardening (the gate exists; harden it before it gates anything real)
- [ ] Fix Gate B extension-alone accept (1.1); add `/asdf1234.php`, `/6qaz2wsx.php`
      regression cases.
- [ ] Run probe/entropy checks over all segments, not just the leaf (1.2); add
      `/aG7xK9pQ2/login.php` case.
- [ ] Lower `looksRandom` entropy/length floors to catch mixed-alnum calibration
      tokens (1.1).
- [ ] Add the persistent bulk-scan pin table + cooldown (1.3).
- [ ] Add composite `idx_hits_ip_ts`; collapse `probeVelocity` to one query;
      decide current-row inclusion (1.5, 1.6).
- [ ] Optionally wire the gate in log-only mode (classify + log verdict, still serve
      the plain 404) to validate thresholds on real traffic before any generation.

Phase 2 - synchronous LLM behind the gate + cache
- [ ] `Dockerfile.llm` + compose service, model downloaded at build with pinned
      SHA256, internal-only, healthcheck, `depends_on: service_healthy`.
- [ ] `resources/llm/html.gbnf`, `LlmPromptBuilder` (system + one-shot exemplar +
      prefill, attacker bytes stripped and length-capped).
- [ ] `LlmClient` (injectable transport, timeout, `n_predict`) + `CircuitBreaker`.
- [ ] `LlmOutputSanitizer` (pure, all section-3.2 rules) with heavy host tests.
- [ ] `LlmFakeCache` (WAL/0666 fail-open, single-flight, prompt-version, LRU,
      inflight reap).
- [ ] `LlmFakeResponder` orchestration; `?LlmFakeResponder` wired into
      `HoneypotController` and constructed in `demo/index.php` under `FUNNYPOT_LLM`.
- [ ] `FUNNYPOT_LLM_*` config in `AppConfig`.
- [ ] Cache LRU + inflight reap called from `demo/retention.php`.
- [ ] `event => 'llm-fake'` hit row; confirm null -> plain 404 for every failure.

Phase 3 - hardening / tuning
- [ ] Bias generated fakes toward app-styled `401`/`403`/`404` to keep the 200
      hit-rate realistic under distributed probing (1.8).
- [ ] Dashboard `llm-fake` feed rows; prompt-version invalidation flow.
- [ ] Add the two missing Gate A signals (repeated-token-across-dirs, inter-arrival
      uniformity) (1.4); tune thresholds from Phase 1 log data.
- [ ] A/B a second model (SmolLM2 / Qwen3-0.6B) per the eval doc.

Phase 4 (optional) - async generation
- [ ] Only if p99 or timing analysis demands it: split into enqueue/drain like
      `AbuseIpdb`, first hit serves the plain 404 and enqueues, second hit onward
      serves the cached fake. Removes all LLM latency from the request path.
