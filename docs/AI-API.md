# Fake AI-inference API

funnypot impersonates three AI-inference HTTP APIs so a scanner hunting exposed LLM servers (to
steal GPU / free inference) believes it found a fat multi-model rig. The recon surface is
byte-identical to the real APIs. When an attacker chats, the reply is deliberately wrong on purpose —
so the box is worthless as free compute — with one exception: the cheap identity/capability probes a
scanner opens with ("what model are you", "who made you") are answered *plainly and believably*, since
a coherent "I'm &lt;model&gt; by &lt;vendor&gt;" is what reads as a live box and keeps the scanner
engaged. Those answers are hardcoded (no sidecar call), so believability never costs a real generation
or hands the attacker a working model.

| Dialect | Endpoints |
|---|---|
| Ollama | `GET /api/tags`, `GET /api/version`, `GET /api/ps`, `POST /api/show`, `POST /api/chat`, `POST /api/generate` |
| OpenAI-compatible | `GET /v1/models`, `POST /v1/chat/completions` |
| Anthropic Messages | `GET /v1/models` (header-branched — same path as OpenAI, keyed on `anthropic-version`), `POST /v1/messages` |

The GET endpoints and `/api/show` are **always compiled into `funnypot-core`** and serve regardless
of app config — they're the recon bait. The four `POST` chat endpoints (`/api/chat`, `/api/generate`,
`/v1/chat/completions`, `/v1/messages`) are a two-tier fallback:

- With `FUNNYPOT_AI_API=1` and a reachable sidecar, the app streams a live, per-dialect nonsense
  answer.
- With the flag off, or the sidecar unreachable/timed out/gated, core's buffered static-nonsense
  floor answers instead (Tier 2 falls back to Tier 1's shape, not to a 404 — see "How the nonsense
  works" below).

## Enable

```
FUNNYPOT_AI_API=1
```

Off by default. Turning it on wires the app's chat handler in front of the core engine for the four
POST paths and requires a reachable `FUNNYPOT_LLM_URL` sidecar (same one the LLM fake-page layer
uses) to generate live nonsense — if the sidecar is down, unreachable, or times out, the handler
falls back to a static nonsense answer, correctly framed and still streamed (never a bare error, never
a 500).

## Config

| Env var | Default | Meaning |
|---|---|---|
| `FUNNYPOT_AI_API` | off | Enables the Tier-2 streaming chat handler. Off = core's buffered floor answers every chat path. |
| `FUNNYPOT_AI_STRICT_AUTH` | off | Require an `Authorization`/`x-api-key` header on OpenAI/Anthropic paths (401 otherwise). Off impersonates an open LLM box — the more engaging default. Ollama never needs auth either way. |
| `FUNNYPOT_AI_STRICT_MODEL` | off | Require the requested model to exist in the catalog (404 otherwise). Off echoes any model name back, for max engagement. |
| `FUNNYPOT_AI_TEMP` | `0.8` | Sampling temperature for the chat sidecar call. |
| `FUNNYPOT_AI_MIN_P` | `0.0` | Sampling `min_p` for the chat sidecar call. |
| `FUNNYPOT_AI_TOP_P` | `1.0` | Sampling `top_p` for the chat sidecar call. |
| `FUNNYPOT_AI_REAL_FIRST` | `5` | A fresh IP's first N chat answers in the window are answered **straight** (real, correct) before the box degrades to the troll persona. `0` = always troll (the pre-escalation behavior). |
| `FUNNYPOT_AI_REAL_WINDOW_S` | `600` | The sliding window (seconds) the first-N budget is counted over. A quiet gap longer than this refreshes the budget, so a returning scanner gets believable answers again — like a real session. |

These four sampling/gating vars are read directly by `AppConfig::fromEnv()` — see
`src/App/Config/AppConfig.php` for the exact parsing (the `_STRICT_` flags use the same
`in_array(strtolower(...), ['1','on','true','yes'])` truthy-string parsing as `FUNNYPOT_LLM`).

**Chat sampling is separate from HTML page-gen.** `FUNNYPOT_AI_TEMP`/`_MIN_P`/`_TOP_P` apply only to
the chat path. The LLM fake-page layer keeps its own low-temperature sampling with a per-install,
per-path derived seed for HTML/JSON bodies — a helpful model answers correctly at low temperature, but
a believable *wrong* chat answer needs a high temperature and `min_p` 0, so the two paths must not
share settings.

**Sidecar reuse.** The chat handler builds its own `LlmClient` + circuit breaker but points at the
same sidecar as the page-realism layer and shares its concurrency slot cache, so the two features
can't oversubscribe the sidecar between them: `FUNNYPOT_LLM_URL` (default
`http://funnypot-llm:8080/completion`), `FUNNYPOT_LLM_TIMEOUT_MS` (default `9000`),
`FUNNYPOT_LLM_N_PREDICT` (default `320`), `FUNNYPOT_LLM_MAX_CONCURRENT` (default `4`),
`FUNNYPOT_LLM_VELOCITY_PER_60S` / `_PER_10M` (defaults `5` / `15`, the same probe-velocity gate used
elsewhere), `FUNNYPOT_LLM_GENS_PER_HOUR` (default `60`, the global fresh-generation budget shared with
the page layer — once the hour is spent the chat gate falls back to the static nonsense, no sidecar
call). None of these are AI-API-specific — tune them once for the sidecar as a whole.

## How the nonsense works

The box is believable first, troll after: a fresh IP's opening chats are answered for real, then it
degrades. When it does troll, it never asks the model to "be wrong" — live testing showed it just
ignores that and answers correctly — so instead it corrupts the *question* and has the model answer the
corrupted question straight:

0. **Identity/capability probes are answered for real** (checked first, so they never reach the troll
   path). A message that reads as "what model are you / who made you / what can you do" gets a
   deterministic hardcoded persona line (house identity: **Mythos**, by **Anthropic** — cosmetic,
   swap it in `IdentityResponder`), with a correct answer to a bundled trivial sum appended when the
   probe carries one ("what model are you, and what is 1+1" → "…And 1 + 1 = 2."). No sidecar call, no
   gate: the answer is cheap and canned, so it convinces without becoming usable compute. The detector
   is deliberately narrower than a bare "model" so it doesn't misfire on requests like "download the
   model file".
1. **Believable-first budget (per IP).** A fresh IP's first `FUNNYPOT_AI_REAL_FIRST` chat answers
   within `FUNNYPOT_AI_REAL_WINDOW_S` are answered **straight** — the raw question goes to the sidecar
   and the real (correct) reply is served — so the box behaves like a live model on the opening probes.
   The count is this IP's prior `ai-api` hits in the window (`HitStore::recentEventCount`), so the
   *current* request is not yet counted; past the budget the box degrades to the word-swap troll below.
   The window slides, so a quiet gap refreshes the budget like a real session. Code requests are the
   one exception — never answered for real, even inside the budget (see 3).
2. **Word-swap (troll mode, past the budget).** Content words in the attacker's message are swapped for
   absurd nouns (pineapple, walrus, trombone, ...) while function words and sentence shape are kept, so
   "what is the capital of France" becomes a still-grammatical "what is the trombone of pineapple" — and
   the model answers *that* faithfully. If nothing in the message is swappable (short/trivial input, so
   a real answer would come back correct), it falls straight to the static fallback instead.
3. **Code requests get a static wrong-language snippet**, not a model call — a message that reads as
   a code/script/function request is detected up front and answered with a curated, deliberately
   wrong-language or gibberish sample (BASIC, x86 asm, brainfuck, ...), so the honeypot never risks
   the sidecar emitting real working code back to the attacker who asked for it.
4. **Degrade ladder, always resolve-before-stream.** The full answer text is resolved before any byte
   is emitted, so a fault never produces a half-finished stream:
   - Sidecar reachable, gate open, concurrency slot free → live LLM answer (straight within the
     believable-first budget, word-swapped once past it).
   - Probe gate declines (bulk-scan pin, velocity, plausibility), no concurrency slot, sidecar
     timeout/error/empty output → static curated nonsense answer (deterministic per question, so a
     retried question gets the same wrong answer).
   - `FUNNYPOT_AI_API` unset → core's Tier-1 buffered floor answers instead, in the same dialect
     shape, `stream:false`.

Every path streams (or buffers) real per-dialect framing: NDJSON for Ollama, SSE with a trailing
`data: [DONE]` for OpenAI, named SSE events ending `message_stop` (no `[DONE]`) for Anthropic. Status
codes are always app-chosen — 401/404/400 for genuinely-believable auth/model/malformed errors, 200
for every generated answer, never a model-driven redirect and never a 500.

## Threat intel

Every chat-path hit is logged (path, method, IP, requested model, whether a key was sent) and
classified `ai_api_recon` (medium severity). The row is tagged with event `ai-api`, so the dashboard's
**AI API** quick-view filter narrows the feed to this surface (distinct from the LLM-generated fake
pages, which carry event `llm-fake` behind the **LLM pages** filter). It is then reported to AbuseIPDB
the same way any other attack class is — through the existing self-guarded reporter, so `FUNNYPOT_SELF_IPS` still protects the
operator's own test traffic from being reported. Confirm your test egress IP is in
`FUNNYPOT_SELF_IPS` before probing this surface against prod.
