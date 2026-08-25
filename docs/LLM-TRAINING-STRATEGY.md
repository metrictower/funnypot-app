# LLM training strategy — opinionated advice

*Audience: you (Bob) — strong engineer, first time near ML training. This is the
"what should I actually do, and what should I not waste a weekend on" doc. It
answers three questions you asked and gives a phased plan. Data sources and the
honeypot-specific risks live in `LLM-TRAINING-BRAINSTORM.md`; this doc is about
**which model** and **which training approach**, decided.*

---

## Bottom line up front

- **Don't train from scratch.** Not "it's hard" — it's the wrong tool. You'd
  spend weeks and money to rebuild capabilities you get for free in the base
  model. Beginners who say "from scratch" almost always want fine-tuning.
- **Don't go smaller than 0.5B yet.** 0.5B is already near the coherence floor
  for varied HTML. Shrinking is a fix for a *measured* latency/RAM problem you
  don't have yet. Measure first.
- **Don't fine-tune at all as your first move.** Do RAG/prompting first (see the
  brainstorm doc) — it's cheaper, faster to ship, and often good enough. Reach
  for fine-tuning only when you can point at a specific thing prompting can't fix.
- When you *do* train: **LoRA on your Mac with `mlx-lm`**, on a *distilled*
  teacher set — never on the raw nuclei inversions (that's the fingerprint trap).

If you internalize one mental model: **the base model is a dependency you're
importing, not code you're writing.** You pick a good one and adapt it. You don't
reimplement `libc` because your app only prints HTML.

---

## Q1: Should I start from an even smaller base model?

**No — not now, and probably not ever for this job.** Here's the honest reasoning.

### What you actually give up as you shrink

Model size buys *coherence over distance* and *breadth of memorized patterns*.
As you go down the ladder:

- **1.5B → 0.5B**: noticeably thinner output. Still emits valid HTML, but pages
  get generic and repetitive; it leans harder on your prompt's fallback shapes.
  This is the incumbent trade-off you already accepted.
- **0.5B → ~350M**: coherence starts breaking on *structure*. Unclosed tags,
  attributes that don't parse, English microcopy that reads like a bad
  translation. A real HTML/CSS parser (which some scanners run) starts noticing.
- **0.5B → ~135M (SmolLM-135M and friends)**: these are impressive *for their
  size* and genuinely useful for classification, extraction, or heavily
  constrained generation. But "write a varied, plausible, self-consistent web
  page nobody prompted the exact shape of" is close to their ceiling. You'll be
  fighting the model, not using it.

**The practical floor for "coherent, varied HTML that fools a scanner" is right
about where you are: 0.5B.** Qwen2.5-Coder-0.5B is a *code*-tuned model, which is
exactly why it holds HTML structure better than a general 0.5B — it has seen a
lot of markup. Going below that trades away the one thing you can't easily add
back (structural coherence) to save RAM you may not need to save.

### When shrinking is actually the right call

Only when you have a **measured** problem the smaller model fixes:

- p95 generation latency blows your budget on the target box, *and*
- profiling shows token generation (not prompt eval, not cold start) is the cost, *and*
- a grammar-constrained smaller model measurably closes the gap without
  wrecking output quality on your eval set.

Notice all three are numbers, not vibes. Today you have a working 0.5B on a
t3.micro. "Could I go smaller?" is a premature optimization until a graph says so.
And note the counterintuitive bit from your own eval doc: **params don't predict
CPU latency** — a "small" reasoning model can be *slower* than a larger instruct
model because it generates a wall of thinking tokens first. Fewer parameters is
not automatically faster.

---

## Q2: Should I train from scratch?

**No. Bluntly: training a language model from scratch is a bad idea here — for a
beginner, and honestly for anyone, for this use case.** Not because you're not
capable; because the cost/benefit is upside-down.

### What "from scratch" actually costs

"From scratch" (pretraining) means starting from random weights and teaching the
model language itself — grammar, HTML, English, the concept that a `<div>` closes.
Even for a *tiny* model that means:

- **Data**: billions of tokens of clean, deduplicated text, curated and
  tokenized. Not your ~5–8k inversion pairs — those are a rounding error. Your
  whole corpus wouldn't get a from-scratch model past baby-talk.
- **Compute**: real GPU-days to GPU-weeks. Rentable, but you're paying to
  recreate what Qwen already did and gave away under Apache 2.0.
- **Expertise**: this is the part people underestimate. From-scratch training is
  a research skill — learning-rate schedules, loss curves that lie to you,
  instability, tokenizer design, eval harnesses. It's the ML equivalent of
  writing your own database engine to store three rows. As a first ML project
  it's a near-guaranteed way to burn a month and ship nothing.
- **Result**: even done perfectly, a from-scratch tiny model *underperforms* a
  fine-tuned pretrained one of the same size, because the pretrained one already
  absorbed patterns from far more data than you'll ever assemble.

### What people mean when they say "from scratch"

Almost always, "I want to train it from scratch" decodes to **"I want a model
that's *mine* and does exactly *my* thing."** That desire is 100% legitimate. The
technique that delivers it is **fine-tuning** (specifically LoRA/QLoRA): you take
the pretrained model and nudge its behavior toward your task with a small amount
of your data. You get a model specialized to your job, in hours not weeks, on
hardware you own, and it's *better* than the from-scratch version. That's the win
you actually wanted.

**Verdict: skip from-scratch entirely. Fine-tune.**

---

## Q3: "A model that only outputs web responses" — narrow = from-scratch?

The intuition is reasonable: *the job is narrow, so why carry a whole general
model?* It feels like a from-scratch / tiny-model argument. **It isn't. Narrow
specialization is an argument for fine-tuning a small pretrained model, not for
starting from zero.** Here's the why, because the why is the whole point.

### Pretraining is *reusable prior knowledge*, and your narrow task needs it

Your "narrow" output — an HTTP/HTML response — is not narrow in *what it draws
on*. To emit one convincing fake page the model has to already know:

- **HTML/CSS structure** — nesting, closing tags, valid attributes, a plausible
  `<head>`.
- **HTTP conventions** — what headers look like, what a 401 body says, realistic
  `Server:` strings.
- **English microcopy** — "Sign in", "Invalid credentials", "You do not have
  permission to access this resource" — phrased like a real product, not a robot.
- **App-world conventions** — that Grafana has a login, that `.git/config` has a
  `[core]` section, that phpMyAdmin looks a certain way.

A pretrained model **already learned all of that** from general text and code.
Fine-tuning doesn't teach it HTML from nothing — it *focuses* knowledge the model
already has onto your specific output contract (only HTML, no refusals, right
register). From-scratch would force you to reteach every one of those bullets
using data you don't have. **General pretraining is exactly why a narrow task is
cheap to hit — you're renting a huge prior and pointing it at one job.**

Think of it like TypeScript's standard lib. Your app is "narrow" — it only serves
fake pages — but you don't ship a from-scratch stdlib. You import the platform's
and use 2% of it. Same here: import Qwen's "knows the web" prior, use the slice
you need.

### So does narrow ever justify tiny/from-scratch?

Narrow justifies a **small** base (you're already there) and a **specialized
fine-tune** (do this later). It does **not** justify from-scratch. The narrowness
is served by *constraint at output time* (your GBNF grammar + sanitizer + probe
gate — keep all of them) plus a light fine-tune, not by a bespoke tiny model
trained from nothing.

---

## Quantization vs model size: 0.5B @ Q4 or 1.5B @ Q2?

Short answer: **for a fixed RAM budget, prefer the smaller model at a healthier
quant.** A 0.5B at Q4_K_M is the smarter CPU pick than a 1.5B crushed to Q2.

Why: quantization below ~Q4 falls off a cliff. Q4_K_M is the well-known
sweet spot — near-full quality at a quarter the size. Q3 is noticeably degraded;
**Q2 is often incoherent**, and incoherence is the one failure your honeypot
can't tolerate (garbled HTML is a tell). A bigger model quantized into the mud
doesn't buy back the quality it lost. So the ranking for CPU deployment is:

1. Right-sized model at **Q4_K_M** (where you are). Best default.
2. Bigger model at Q4/Q5 **if** RAM allows and quality demands it (t4g.medium).
3. Bigger model at **Q2** — avoid. You paid for parameters and then broke them.

Rule of thumb: **choose the model size first for the quality floor you need, then
quantize to Q4_K_M, then size the box to that.** Don't pick a big model and quantize
down to make it fit — pick the model that fits *at Q4*.

---

## Is distillation the real unlock?

**Yes — eventually — and it's the only fine-tuning path I'd endorse for this
honeypot.** But it's a Phase 3 move, not your first weekend.

Distillation here = a big smart model (a local 14B/32B, or Claude) writes many
diverse, high-quality fake pages for *real captured* scanner paths, explicitly
told to vary wording and **not** reproduce nuclei's canonical matcher strings.
Then you LoRA the 0.5B on that teacher set. You get the specialization and the
latency win (shorter prompt, fewer refusals) **without** baking in the exact
substrings a scanner fingerprints on — because the teacher never wrote them.

The tempting shortcut — LoRA directly on the `ResponseSynthesizer` inversions —
is the trap: those bodies contain the canonical matcher strings *by construction*,
so you'd train the model to emit its own fingerprint on unknown paths. The
brainstorm doc calls this out at length; believe it. **Distillation is how you get
"trained" without stepping on the landmine.** But it only pays off once the data
flywheel (kept/deleted cache entries + captured traffic) has given you real pairs
to distill against. Do it after RAG, not before.

---

## Recommended path (phased, beginner-friendly)

### Phase 0 — the very first thing to try (this week, no training)
**RAG + prompt work.** Retrieve the nearest known exemplar into the prompt at
generation time (details in the brainstorm doc). No GPU, no training loop, ships
in the PHP you already have. Most of your quality gap closes here. **Do not train
anything until you've done this and measured what's still wrong.**

### Phase 1 — learn the tools on a throwaway LoRA (a weekend, low stakes)
Goal is *learning the mechanics*, not shipping. On your Apple-Silicon Mac,
`mlx-lm` is the low-friction path — it runs LoRA natively on Metal, no CUDA, no
rented GPU. High-level workflow:

```
pip install mlx-lm

# 1. Get the base in MLX format (convert once, optionally quantized)
mlx_lm.convert --hf-path Qwen/Qwen2.5-Coder-0.5B-Instruct -q

# 2. LoRA fine-tune on a JSONL dataset (train/valid/test split)
#    data = {"prompt": "<request>", "completion": "<fake html>"} per line
mlx_lm.lora --model <converted-path> --train \
    --data ./data --iters 400 --batch-size 4 --num-layers 8

# 3. Try it interactively with the adapter attached
mlx_lm.generate --model <converted-path> --adapter-path ./adapters \
    --prompt "GET /grafana/login"

# 4. Fuse adapter into weights, then convert to GGUF for the llama.cpp sidecar
mlx_lm.fuse --model <converted-path> --adapter-path ./adapters
# (then llama.cpp's convert_hf_to_gguf.py + quantize to Q4_K_M)
```

Use a tiny, *safe* dataset for this run (a handful of your hand-authored decoys)
— you're checking that the pipeline runs end to end and you can read a loss curve,
not producing the real adapter. **Resist the urge to train on the nuclei
inversions here** even as a test; build the muscle memory of never touching them.

### Phase 2 — the real adapter, via distillation (later, once flywheel has data)
When captured traffic + cache keep/delete have given you real pairs, distill a
teacher set (big model writes varied fakes for real paths, no canonical strings)
and LoRA on *that*. Same `mlx-lm` workflow, real data. This is where authentic,
specialized behavior actually comes from.

### What "good" looks like (define it before you train, not after)
- **Format discipline**: ~100% of outputs are HTML-only, no refusals, no
  markdown fences, no `<think>` blocks. Measure it as a pass rate on a held-out
  set of gate-admitted paths.
- **Variety**: two different unknown paths produce structurally different pages;
  the same path is consistent. Check for near-duplicate output across paths.
- **No fingerprints**: canonical nuclei matcher substrings appear **only** when
  the deterministic engine intended them, never volunteered by the model on an
  unknown path. Grep the outputs for known strings.
- **Latency/RAM within budget on the target box** — the numbers, from the real box.
- **Beats the baseline**: A/B the adapter against today's prompt-only 0.5B on the
  same eval set. If it doesn't clearly win, don't ship it.

---

## Traps a beginner falls into (all avoidable)

- **Overfitting to nuclei's exact strings → fingerprintable.** The big one. Train
  on paraphrase-augmented / distilled data, never raw inversions. A honeypot that
  reliably emits `[core]` on every unknown path is *worse* than no LLM.
- **Catastrophic forgetting.** Over-train (too many iters, learning rate too high)
  and the model forgets general HTML and only knows your ~dozen shapes — output
  collapses to repetition. Keep LoRA light: few layers, modest iters, watch the
  validation loss stop improving and stop there.
- **Tokenizer / chat-format mistakes.** Train with a prompt format that doesn't
  match what the llama.cpp sidecar sends at inference and the model behaves
  randomly in production while looking fine in your test harness. Use the base
  model's exact chat template on both sides; verify by feeding a real
  sidecar-shaped request to your fine-tune.
- **Evaluating by vibes.** "Looks good to me" on five examples is not evaluation.
  Build a held-out eval set (your hand-authored decoys are gold) and a script
  that scores format-pass-rate, variety, and fingerprint-leak *before* you start,
  so you can prove the adapter beats the baseline instead of hoping it does.
- **Training before RAG.** Reaching for a GPU when a retrieval tweak in PHP would
  have fixed it cheaper and shipped sooner.
- **Keeping the grammar/sanitizer "until the model is good enough."** Never remove
  them. Training reduces refusals and drift; it never eliminates them. They're
  cheap deterministic guardrails — permanent, not scaffolding.

---

## If you only do one thing

**Ship RAG on the 0.5B first and measure it — don't train anything yet.** Retrieval
plus prompt work closes most of the quality gap with no GPU, no training, and no
fingerprint risk, and it tells you what (if anything) is actually still broken. If
after that a *measured* problem remains, the answer is a light LoRA on your Mac
with `mlx-lm` against a **distilled** teacher set — never from scratch, never
smaller than 0.5B, and never on the raw nuclei inversions.
