# Fake AI-inference API

funnypot impersonates three AI-inference HTTP APIs so a scanner hunting exposed LLM servers (to
steal GPU / free inference) believes it found a fat multi-model rig. The recon surface is
byte-identical to the real APIs; when an attacker actually chats with a model, they get a
deliberately wrong answer.

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

These four sampling/gating vars are read directly by `AppConfig::fromEnv()` — see
`src/App/Config/AppConfig.php` for the exact parsing (the `_STRICT_` flags use the same
`in_array(strtolower(...), ['1','on','true','yes'])` truthy-string parsing as `FUNNYPOT_LLM`).

**Chat sampling is separate from HTML page-gen.** `FUNNYPOT_AI_TEMP`/`_MIN_P`/`_TOP_P` apply only to
the chat path. The LLM fake-page layer keeps its own low, fixed-seed sampling for HTML/JSON bodies —
a helpful model answers correctly at low temperature, but a believable *wrong* chat answer needs a
high temperature and `min_p` 0, so the two paths must not share settings.

**Sidecar reuse.** The chat handler builds its own `LlmClient` + circuit breaker but points at the
same sidecar as the page-realism layer and shares its concurrency slot cache, so the two features
can't oversubscribe the sidecar between them: `FUNNYPOT_LLM_URL` (default
`http://funnypot-llm:8080/completion`), `FUNNYPOT_LLM_TIMEOUT_MS` (default `9000`),
`FUNNYPOT_LLM_N_PREDICT` (default `320`), `FUNNYPOT_LLM_MAX_CONCURRENT` (default `4`),
`FUNNYPOT_LLM_VELOCITY_PER_60S` / `_PER_10M` (defaults `5` / `15`, the same probe-velocity gate used
elsewhere). None of these are AI-API-specific — tune them once for the sidecar as a whole.

## How the nonsense works

The chat handler never asks the model to "be wrong" — live testing showed it just ignores that and
answers correctly. Instead it corrupts the *question* and has the model answer the corrupted question
straight:

1. **Word-swap.** Content words in the attacker's message are swapped for absurd nouns (pineapple,
   walrus, trombone, ...) while function words and sentence shape are kept, so "what is the capital of
   France" becomes a still-grammatical "what is the trombone of pineapple" — and the model answers
   *that* faithfully. If nothing in the message is swappable (short/trivial input, so a real answer
   would come back correct), it falls straight to the static fallback instead.
2. **Code requests get a static wrong-language snippet**, not a model call — a message that reads as
   a code/script/function request is detected up front and answered with a curated, deliberately
   wrong-language or gibberish sample (BASIC, x86 asm, brainfuck, ...), so the honeypot never risks
   the sidecar emitting real working code back to the attacker who asked for it.
3. **Degrade ladder, always resolve-before-stream.** The full answer text is resolved before any byte
   is emitted, so a fault never produces a half-finished stream:
   - Sidecar reachable, gate open, concurrency slot free → live word-swapped LLM answer.
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
classified `ai_api_recon` (medium severity), then reported to AbuseIPDB the same way any other attack
class is — through the existing self-guarded reporter, so `FUNNYPOT_SELF_IPS` still protects the
operator's own test traffic from being reported. Confirm your test egress IP is in
`FUNNYPOT_SELF_IPS` before probing this surface against prod.
