# LLM training brainstorm — should we train, and on what?

*Thinking doc, not a plan. Question on the table: can we **train** the tiny model
(instead of only prompting it) so it "learns how to respond to HTTP requests" more
authentically — and if so, on what data?*

---

## TL;DR (read this, skip the rest if busy)

1. **Yes, there's real training signal here** — but the highest-value asset isn't "nuclei
   templates" as text. It's the fact that `funnypot-core` already **inverts** a nuclei
   matcher into a satisfying response. That's a free, correct **(request → response) pair
   generator** over the whole corpus. We can mint thousands of labelled pairs with a loop,
   no annotation.
2. **Do retrieval before you do training.** We already have 5,107 path-keyed inverted
   exemplars indexed on disk. Retrieving the nearest one into the prompt at generation time
   (RAG) is nearly free, needs no GPU, and fits the inversion philosophy exactly. That is
   the highest short-term ROI and it's my recommended first move.
3. **When you do train, distil — don't fine-tune on raw inversions.** Training the 0.5B
   directly on `ResponseSynthesizer` output bakes the *canonical nuclei matcher strings*
   into the model. That is the single worst thing you can do in a honeypot: it makes the
   model reproduce the exact substrings a nuclei-aware scanner fingerprints on. Distillation
   from a big model (or Claude) sidesteps that by construction and is the best quality/cost
   play long-term.
4. **The grammar + sanitizer stay in place no matter what.** Training reduces refusals and
   drift; it never eliminates them. They are cheap deterministic guardrails; keep them.
5. **The cache browser's keep/delete is already a labelling UI.** Over a few months of live
   traffic it becomes a curated fine-tuning set for free. Close that loop deliberately.

**Recommended path:** RAG now (weeks) → persona conditioning (days, orthogonal, do it
anyway) → distillation-to-LoRA once the flywheel has data (months). Skip standalone
"LoRA on nuclei inversions" — it's the fingerprinting trap.

---

## 1. Where we are today (one paragraph of grounding)

The unknown-404 path is **prompt-only**: `LlmPromptBuilder` sends Qwen2.5-Coder-0.5B a fixed
system instruction + **one** hand-written exemplar (`/acme-portal/signin.aspx` → a bare
sign-in page) + the real request, constrained by `html.gbnf`, validated by
`LlmOutputSanitizer`, gated by `ProbeGate`, cached byte-identical in `LlmFakeCache`. Status is
app-chosen, never model-chosen. It works, but the model is flying on a single generic exemplar
and a lot of instruction text. Everything below is about giving it *better context* or *better
weights* — and the corpus to do either is already sitting in the repo.

---

## 2. Data sources & how to build a corpus

Three sources, in descending order of leverage.

### 2a. Nuclei inversions — the free pair generator (the killer insight)

A nuclei template encodes **both** the request (path/method) **and** a matcher describing what
a vulnerable target's response looks like (status, body substrings, headers, size, regex).
`funnypot-core` already turns that matcher into a concrete satisfying response — that's the
whole engine. So a matcher isn't just a detector; run backwards it is a **label**.

Concrete numbers from the shipped corpus (`nuclei-index.full.php` manifest,
upstream `2ec9141`):

| field | value |
|---|---|
| templates indexed | **6,343** |
| distinct route keys (`METHOD /path`) | **5,107** |
| multi-bundle keys | 276 |
| largest bundle (`GET /`) | 1,325 |
| persona cap (bundles kept/path) | 40 |

**Pipeline:** iterate the compiled route keys; for each bundle call
`ResponseSynthesizer::synthesize($bundle, $satisfies, $seed)` at **RICH** style (so endpoint
emulators render believable `.env` / `.git/config` / `xmlrpc` bodies, not just minimal
substring stuffing). Emit `{method, path} → {status, headers, body}`. Dedup to one
representative bundle per route. That's **~5–8k clean, correct pairs from a `for` loop** — the
labels are guaranteed to satisfy the matcher because that's exactly what the synthesizer
proves before returning.

> **Caveat, load-bearing:** these bodies *contain the canonical matcher substrings by
> construction* (e.g. `[core]` for git-config). That's correct for a template path — you must
> include the string to convince the scanner the vuln is real — but it is **poison as training
> data** if the model memorises those strings and emits them on unknown paths. Use this corpus
> for **shape/register** (what a config-exposure page *looks like*), not verbatim content. See
> §4 (fingerprinting).

### 2b. funnypot's own decoys — the hand-authored gold

The endpoint emulators in `EmulatorRegistry` (git-config, `.env`, xmlrpc, phpmyadmin, wp-admin,
server-status, actuator, `backup.sql`, `credentials.txt`) are **human-authored, high-quality**
request→response pairs. Small in number (~dozen-plus) but each is worth more than a hundred
auto-inversions because a person tuned it to be convincing. These are your few-shot exemplars
and your eval gold set.

The 18 `templates/protocol/*.yaml` (ssh, redis, mysql, mongodb, …) are TCP banner emulations,
**not HTTP** — out of scope for the HTML model, but note them: if the protocol honeypot ever
grows a generative path, the same inversion trick applies to banners.

### 2c. Captured traffic — the perfect input distribution

`SqliteHitStore` logs every real request. Scanner traffic **is** the exact input distribution
the model will face in production — no synthetic path list matches it. And `llm_cache`
(`body`, `served_count`, `last_served_at`, plus the operator's keep/delete) is the **labelled
output** side. This is the flywheel (§4). One discipline point: train only on paths the
**gate admitted** — never feed probe-shaped paths into the input distribution, or the model
learns to answer the calibration garbage the gate exists to shed.

**Format:** JSONL, one object per line —
`{"method","path","persona","body","status"}` — trivial to produce from either the synthesizer
loop or the cache table, and directly consumable by both a retrieval index and a PEFT trainer.

---

## 3. Approaches, ranked by effort ÷ payoff

| # | Approach | Effort | Payoff | Verdict |
|---|---|---|---|---|
| a | Prompt + fixed few-shot (**today**) | — | baseline | keep as fallback |
| b | **RAG** — retrieve nearest inverted/decoy exemplar into the prompt | **low** | **high** | **do first** |
| c | LoRA on raw nuclei inversions | med | med *(risky)* | **skip** — fingerprint trap |
| d | **Distillation → LoRA** (big model writes fakes, tiny model learns) | high | highest | **do eventually** |

### (b) RAG / retrieval — highest short-term ROI, no training

At generation time, retrieve the most similar known exemplar (by path — token overlap on
path segments and the product/app word is plenty; you do **not** need embeddings for v1) and
inject it as the one-shot in place of the fixed ACME page. Suddenly a request for
`/grafana/login` is primed with a real Grafana-shaped exemplar instead of a generic portal.

Why this first: the retrieval corpus **already exists and is already path-indexed** — it's the
compiled route index. This is inversion philosophy applied to the LLM path: the engine already
answers "what does the response for *this* look like" for known paths; RAG borrows the nearest
known answer to shape an unknown one. No GPU, no training loop, ships in the existing PHP.

Two rules that make RAG safe here:
- Retrieve for **shape, not copy** — the exemplar teaches register (a login page, a config
  dump, a 401), and the grammar/sanitizer already stop verbatim regurgitation of dangerous
  bits. Strip/paraphrase canonical matcher substrings out of retrieved exemplars so §4's
  fingerprinting poison doesn't leak into the prompt.
- Only ever retrieve from **gate-admitted** exemplars, so calibration junk can't become a
  template.

### (c) LoRA/QLoRA on the raw inversions — the trap, stated plainly

Tempting because it's cheap: a 0.5B LoRA (QLoRA isn't even necessary at this size — full LoRA
on an fp16 base fits a single consumer GPU in minutes) specialises the model to
"vulnerable-app response shape", cuts refusals, and lets you **drop the exemplar and shorten
the system prompt** — a real latency win on t3.micro, where prompt-eval dominates CPU cost.
llama.cpp deploys the result as a few-MB GGUF adapter (`convert_lora_to_gguf.py`, loaded via
`--lora` / hot-swapped through llama-server's `/lora-adapters`), so inference stays the same
tiny base + adapter.

**But** if the LoRA is trained on `ResponseSynthesizer` output, you have taught the model to
emit canonical nuclei matcher strings — the exact fingerprint. Don't. If you ever do a
LoRA on inversions, it must be on **paraphrase-augmented** inversions with matcher strings
perturbed, which is most of the work of §3d anyway. So collapse c into d.

### (d) Distillation → LoRA — best quality/cost, long-term

Use a big model (or Claude) offline to generate **diverse, high-quality** fakes for a large
sample of *real captured* scanner requests, with explicit instructions to vary wording and
**not** reproduce nuclei's canonical strings. Then LoRA the 0.5B on that teacher set. This
gives you the specialisation and latency wins of (c) **without** the fingerprint, because the
teacher never emitted canonical matcher strings in the first place. The captured-traffic input
distribution (§2c) makes the teacher set match production. This is where authenticity actually
comes from.

**Phased path:** (b) RAG now → persona conditioning (§4, orthogonal) → collect flywheel data
(§5) → (d) distil-to-LoRA once you have a few thousand keep-labelled real pairs.

---

## 4. Honeypot-specific risks & mitigations

*(These are the reasons a naive "just fine-tune it" fails. Treat them as constraints, not
footnotes.)*

### Fingerprinting — the dominant risk

A scanner that knows nuclei can flag the honeypot if our responses reproduce nuclei's
**canonical matcher strings verbatim** — the deterministic engine already has this property on
template paths (unavoidable: satisfying the matcher *requires* the string). The LLM path is
our chance to *not* have it, because an unknown 404 has no matcher to satisfy — the model is
free to be plausible without being canonical. Protect that freedom:
- Never train/retrieve on unparaphrased inversions (§2a, §3c).
- Augment: paraphrase, vary casing/whitespace, mix in **real** (scraped, sanitised) app
  responses so the distribution isn't "nuclei's idea of the app".
- Add a fingerprint check to the eval: *fraction of outputs containing any canonical matcher
  substring from the corpus* — target ~0.

### Identity consistency — one host, one stack

A real host presents **one** coherent server identity — same `Server` header family, same
error-page style, same 404 chrome — across every path. A per-path generative model happily
drifts: PHP login here, ASP.NET portal there, nginx error next door. `funnypot-core` already
solves this for the deterministic path via `personaSeed` (coherent breadth: one product
persona per attacker+host) and injects a coherent `Server`/`X-Powered-By`. **The LLM path does
not yet see the persona** — `LlmPromptBuilder` gets only method+path. Fix: thread the resolved
persona (server family, product, era) into the prompt and condition generation on it, so all of
one attacker's fakes agree. This is a days-not-months change and pays off regardless of whether
we ever train. Do it early.

### Guardrails are non-negotiable

Grammar + sanitizer stay **whatever** we do to the weights. Training lowers refusal/leak rates;
it never zeroes them, and a 0.5B under adversarial paths will always occasionally emit junk.
The grammar makes a markdown fence / refusal sentence / `<script>` structurally unreachable;
the sanitizer catches semantic nasties. Cheap, deterministic, keep them as the floor.

### Don't answer calibration probes

The gate sheds probe paths before the model runs — keep it that way, and additionally make
sure no probe-shaped path enters any **training** input distribution. If the model learns to
confidently answer `/intentional_404_page.php`, it has defeated the gate's whole purpose.

---

## 5. The data flywheel

The cache browser's **keep/delete already is a human-labelling interface** — deleting a bad
fake is a negative label, leaving one that's been served *N* times is an implicit positive.
`llm_cache` even carries `served_count` and `last_served_at` for weak supervision. The loop:

1. **Serve** (prompt/RAG) and log every fake with its body (already done —
   `LlmFakeResponder::logServed`).
2. **Curate** — operator deletes the unconvincing ones in the dashboard (already done).
   *Enhancement:* add an explicit "keep/good" thumbs-up so positives aren't just "not deleted".
3. **Export** survivors (+ served_count weighting) to JSONL — the labelled real-traffic set.
4. **Distil/augment** and **LoRA** (§3d), version the adapter, ship as GGUF.
5. **Invalidate** via `prompt_version` bump so the new model regenerates from scratch and the
   next curation round grades *it*.

Safety on the loop: never auto-train on un-curated cache (poisoning — a scanner could farm the
honeypot to shape our model); keep a human in step 2; hold out the hand-authored decoys (§2b)
as a **fixed** eval set the model never trains on, so quality is measured on gold, not on its
own past output.

---

## 6. Concrete next step — the one experiment to run first

**Build the RAG retrieval path and A/B it against today's fixed-exemplar prompt.**

Steps (roughly a day or two of PHP, no GPU):
1. **Mint the exemplar corpus.** Loop the compiled route keys → `ResponseSynthesizer` at RICH
   → JSONL of `{path, body}`. Strip canonical matcher substrings on the way out. Add the
   hand-authored decoys (§2b) with priority weight.
2. **Retriever.** Given the incoming path, score exemplars by path-segment token overlap +
   app-word match (the same lexical features `ProbeClassifier` already computes — reuse them).
   Return the top-1. No embeddings for v1.
3. **Swap the exemplar.** In `LlmPromptBuilder`, replace the fixed ACME one-shot with the
   retrieved exemplar (fall back to ACME when retrieval is empty). Everything downstream —
   grammar, sanitizer, cache, gate — is unchanged.
4. **Measure** with `scripts/llm-eval/eval.php` extended:

| metric | how | target |
|---|---|---|
| refusal rate | existing `refused?` column | ~0 |
| preamble/fence | existing column | ~0 (grammar floor) |
| valid HTML | existing column | ~100% |
| **authenticity** | big-model judge: "plausible page for the product in this path?" 1–5 | ↑ vs baseline |
| **non-fingerprintability** | % outputs containing any canonical matcher substring | ~0, no worse than baseline |
| **persona coherence** | do N paths for one seed share a server family? | ↑ (after §4 persona fix) |
| latency | p50/p95 `/completion` wall-time on t3.micro | no regression |

"Better" = **higher authenticity at equal-or-lower fingerprintability, no refusal/latency
regression.** If RAG wins the authenticity/judge metric with flat fingerprintability, that's
the green light — and it *also* produces the exemplar corpus and the eval harness you'll need
later for distillation, so nothing is wasted if you go on to §3d.

If you only do one thing this month: steps 1–3 above, plus threading persona into the LLM
prompt (§4 identity). Those two are cheap, independent, and each moves authenticity on its own.

---

## Appendix — exact entry points (so this is actionable, not hand-wavy)

- Inversion engine (the pair generator): `ResponseSynthesizer::synthesize()` in
  `vendor/bobbymaher/funnypot-core/src/Synthesis/ResponseSynthesizer.php`. RICH style +
  `EmulatorRegistry` for believable bodies.
- Compiled corpus + counts: `vendor/bobbymaher/funnypot-core/resources/compiled/nuclei-index.full.php`
  (manifest at top: `route_keys`, `templates_indexed`, `persona_cap`).
- Prompt to change for RAG: `src/App/Llm/LlmPromptBuilder.php` (the fixed `EXEMPLAR_*`).
- Guardrails to keep: `resources/llm/html.gbnf`, `src/App/Llm/LlmOutputSanitizer.php`.
- Gate (reuse its lexical features for the retriever): `src/App/Llm/ProbeClassifier.php`.
- Persona plumbing to thread in: `personaSeed` / `persona_breadth: coherent` in
  `vendor/bobbymaher/funnypot-core/config/funnypot.php`; wired at
  `src/App/Http/HoneypotController.php` (`personaSeed: fn(r) => $clientIp`).
- Flywheel data + labels: `llm_cache` table and `all()`/`delete()` in
  `src/App/Storage/LlmFakeCache.php`; served-fake log in `LlmFakeResponder::logServed`.
- Eval harness to extend: `scripts/llm-eval/eval.php` (+ `docs/LLM-MODEL-EVAL.md`).
- llama.cpp LoRA (for §3d): train with PEFT offline → `convert_lora_to_gguf.py` → GGUF
  adapter → llama-server `--lora` / `/lora-adapters`. Base model unchanged, adapter is a few MB.
