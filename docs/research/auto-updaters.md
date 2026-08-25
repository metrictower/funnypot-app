# Auto-updater workflows — research + design

How to keep funnypot's external sources (nuclei-templates, OWASP CoreRuleSet, adopted
training datasets) fresh via GitHub Actions, without ever auto-merging unreviewed upstream
content into a deception engine. Part (a) documents the one auto-updater that already
exists — the template to mirror. Part (b) designs the three new workflows the maintainer
asked for, reusing that template's shape and adding the two safety gates that don't exist
yet anywhere in the repo: fingerprint-safety and license-compatibility.

Repos: `funnypot-app` (app, `github.com/metrictower/funnypot-app`) and `funnypot-core` (HTTP
deception engine, `github.com/metrictower/funnypot-core`), the latter vendored read-only
into `funnypot/vendor/metrictower/funnypot-core` via composer (`dev-main`) — confirmed
byte-identical to the source repo's copy (`diff` of both `update-templates.yml` files is
empty). All file:line citations below point at the source repo,
`/Users/bobmaher/myrepos/funnypot-core`, unless marked `[funnypot]`.

---

## a) The existing pattern: `update-templates.yml`

**File:** `funnypot-core/.github/workflows/update-templates.yml` (96 lines). One job,
`recompile`, on `ubuntu-latest`.

### Trigger / cadence
- `schedule: cron '0 6 * * 1'` — every Monday 06:00 UTC (line 12).
- `workflow_dispatch` with one optional input, `tag` (nuclei-templates tag; blank =
  resolve latest) — lines 13-18.

### Fetch source (pin by tag, not `latest`/`HEAD`)
Step `Resolve nuclei-templates tag` (lines 40-50): if the dispatch input is blank, it
shells out to
```
git ls-remote --tags --sort=-v:refname https://github.com/projectdiscovery/nuclei-templates.git \
  | grep -oE 'refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 | sed 's#refs/tags/##'
```
i.e. list remote tags sorted by version descending, regex-filter to `vX.Y.Z`, take the
top one. No API token, no GitHub Releases API — pure `git ls-remote` against the public
repo. The resolved tag is written to `$GITHUB_OUTPUT` and echoed to the log.

Step `Fetch nuclei-templates` (lines 52-55) does a pinned shallow clone:
`git clone --depth 1 --branch "$TAG" https://github.com/projectdiscovery/nuclei-templates.git /tmp/nuclei-templates`.
Reproducibility comes from cloning an exact tag, never a branch HEAD.

A second, code-level pinning layer stamps provenance into the compiled artifact itself:
`bin/funnypot`'s `resolveUpstream()` (lines 221-238, called at line 186) runs
`git rev-parse HEAD` and `git describe --tags --always` **inside the cloned templates
dir** and folds `{tag, sha, built_at}` into the compiler's `$meta`, which
`ArtifactWriter::write()` persists into `manifest.json` (`ArtifactWriter.php`, the
`$manifest` array). So every compiled index carries which upstream tag+commit produced
it, independent of the workflow's own log.

### Parse
Runs the package's own CLI, `bin/funnypot`, three times (lines 57-68):
1. `php -d memory_limit=2G bin/funnypot compile /tmp/nuclei-templates/http --out=resources/compiled/nuclei-index.full.php`
   — the real parse step, delegating to `Funnypot\Compiler\Compiler` (`src/Compiler/Compiler.php`).
2. `bin/funnypot compile-emulators` / `compile-routes` — recompiles funnypot's own
   attack/route templates against the fresh index (a fresh index has no funnypot-specific
   routes yet).
3. `bin/funnypot merge-routes` — idempotently folds funnypot's new-page route bundles
   back into the freshly compiled index (dedup by `pid`, see `bin/funnypot` lines ~140-160).

### Validate before anything can be proposed
Two gates run **before** the PR step, in order (lines 70-74):
- `vendor/bin/phpunit` — unit + compiler tests.
- `bash tests/acceptance/run.sh` — golden acceptance against **real nuclei** (Docker):
  serves the compiled index over `php -S`, runs the official `projectdiscovery/nuclei`
  image against it, and fails (exit 1) if any golden template id in
  `tests/acceptance/golden.txt` doesn't fire (`tests/acceptance/run.sh`, `MISSING` check
  near the end). Both are plain job steps — if either fails, the job stops and no PR step
  ever runs (GitHub Actions default `continue-on-error: false`).

### Diff / commit / PR
No explicit `git diff` step. The final step, `Open PR with refreshed index` (lines
76-95), uses `peter-evans/create-pull-request@v6` scoped to an explicit `add-paths` list
(the five generated artifacts only — index, manifest, skipped list, and the two
funnypot-generated template files). That action's own no-op detection means: if none of
those paths changed byte-for-byte, no branch/PR is created; if they did, it force-pushes
branch `auto/update-templates` (`delete-branch: true` — the branch is deleted after
merge/close) and opens/updates a PR with a fixed title/body template. **It never commits
to `main`/`master` directly** — `contents: write` + `pull-requests: write` (lines 20-22)
are exactly the permissions `create-pull-request` needs to push a branch and open a PR,
nothing more. No auto-merge is configured anywhere in the file.

### What this workflow does *not* yet have (gaps, confirmed by grep — nothing found)
- **No fingerprint-safety gate.** `grep -rniE "fingerprint|canonical.*signature"` across
  `src/` and `docs/` turns up only unrelated hits (anti-fingerprint *runtime* behavior in
  `Config.php`/`Honeypot.php`, and `PersonaCap.php`'s "obscure info fingerprint" tier
  name). `DynamicLiteralScreen.php` (compiler Screen A2) is adjacent in spirit — it
  rejects a template literal from becoming a synthesized response if it contains an
  unresolvable `{{var}}` (only `{{Hostname}}`/`{{Host}}` are treated as resolvable,
  `DynamicLiteralScreen.php:20`) — but that's a *correctness* screen (predictability of
  the value), not a check that the value, once resolved, doesn't literally match a known
  scanner/matcher signature string. No such check exists.
- **No automated license check.** The nuclei-templates MIT grant is recorded once,
  statically, in `resources/UPSTREAM-LICENSE.md` and referenced from a docblock in
  `ArtifactWriter.php:69-70` ("Derived from projectdiscovery/nuclei-templates (MIT, (c)
  2025 ProjectDiscovery, Inc.). See resources/UPSTREAM-LICENSE.md."). Nothing in CI
  re-verifies that text against what's actually fetched at update time — if upstream ever
  relicensed, the workflow would silently keep recompiling under a stale assumption.

Both gaps are real design work, not omissions to route around — they're exactly what the
maintainer asked for on the new workflows, and they should probably be *backfilled* onto
`update-templates.yml` too (see recommendations at the end).

---

## b) New workflow designs

Shared conventions across all three (mirroring the existing workflow so they read as one
family):
- `workflow_dispatch` + `schedule`, staggered off Monday 06:00 UTC so heavy Docker
  acceptance jobs don't collide on the same runner pool.
- Pin by tag/commit-sha, never `latest`/branch-HEAD; resolve via `git ls-remote`
  (uniform across GitHub *and* HuggingFace, since HF dataset repos are git repos over
  HTTPS — `git ls-remote https://huggingface.co/datasets/<org>/<name>` works exactly like
  `git ls-remote` against GitHub).
- Stamp `{source, ref, sha, fetched_at}` into whatever manifest the artifact carries,
  matching the `resolveUpstream()` convention.
- `peter-evans/create-pull-request@v6`, `contents: write` + `pull-requests: write` only,
  scoped `add-paths`, `delete-branch: true`, **no automerge input anywhere**.
- Two new required steps, always placed *after* correctness tests and *before* the PR
  step, so a failure blocks the PR the same way `phpunit`/acceptance already do:
  `fingerprint-safety-check` and `license-compatibility-check`.

### Shared safety gates (design once, call from all three workflows)

**Fingerprint-safety gate.** The risk: a regenerated template/rule/response literally
echoes back a string a scanner or matcher uses to *positively identify* something —
nuclei's own `matchers.words`/`matchers.regex` literals, a CRS rule's `msg`/`id`/`tag`
text, or a published honeypot-fingerprinting probe signature (e.g. the
Julius-style expected-response strings catalogued in
`funnypot/docs/research/honeypot-projects.md:110`) — appearing verbatim in what funnypot
serves to an attacker. That would let an automated classifier conclude "this is a
templated/canned reply" (or worse, "this is funnypot specifically") instead of a
plausible unique real response, which is the one thing the nuclei-inversion design exists
to prevent.

Design as one small, dependency-free PHP script,
`funnypot-core/scripts/ci/check-fingerprint-safety.php` (new), called identically by the
nuclei and CRS workflows:
1. Loads a tracked denylist, `resources/fingerprint-denylist.php` (new, hand-curated +
   append-only) — three lists: (a) funnypot's own internal markers that must never leak
   ("GENERATED by", `Funnypot\Compiler`, `DO NOT EDIT`, raw template ids like
   `CVE-2023-...` used un-synthesized); (b) canonical nuclei/CRS matcher literals pulled
   straight from the source templates being compiled (fed in at CI time, not hand
   maintained — see step 2); (c) published third-party honeypot-fingerprint probe strings
   (seeded from the honeypot-projects.md survey, growable over time).
2. For list (b), CI extracts it fresh from the very corpus it's compiling that run — e.g.
   for nuclei, every `matchers[].words`/`matchers[].regex` literal in
   `/tmp/nuclei-templates/http/**/*.yaml`; for CRS, every rule's literal `msg`/`tag`
   strings from the fetched ruleset. This is what keeps the gate meaningful release over
   release without hand-updating a list every time upstream adds templates.
3. Boots the compiled artifact the same way `tests/acceptance/server.php` already does
   (reuse that harness), replays a representative request corpus, captures every response
   (headers + body), and greps for any denylist string appearing verbatim.
4. Any hit: **fail the job** (exit non-zero) by default — per the "never auto-merge"
   requirement, a fingerprint leak should block the PR from opening, not just warn on it.
   Also emit a `::error file=...::` annotation naming the offending route/template id so a
   human can find it without re-running locally. (A `--flag-only` mode that instead posts
   a PR comment and adds a `needs-fingerprint-review` label is reasonable as an escape
   hatch for expected/reviewed exceptions, but should not be the default.)

**License-compatibility gate.** Design as
`funnypot-core/scripts/ci/check-license.sh` (new): given the fetched source dir, look for
a `LICENSE`/`LICENSE.md`/`COPYING` file (GitHub sources) or the dataset card's YAML
front-matter `license:` field (HuggingFace `README.md`), compute/extract an SPDX id, and
compare against a tracked allow-list, `resources/ALLOWED-LICENSES.txt` (new — seed with
`MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `CC0-1.0`; funnypot itself is MIT
(`funnypot-core/LICENSE`), and Apache-2.0/BSD/CC0 are all one-way compatible with
redistributing under MIT-licensed derived artifacts). Two behaviors:
- SPDX id resolves and is on the allow-list → pass, and **commit the fetched license text
  itself** into the PR diff (e.g. `resources/upstream-licenses/<source>.LICENSE.md`,
  mirroring the existing hand-written `resources/UPSTREAM-LICENSE.md`) so a human reviewer
  sees the actual license text in the diff, not just a boolean — catches wording/clause
  changes a bare SPDX match would miss.
- SPDX id missing, ambiguous, or off the allow-list → **fail the job**, no PR opens. This
  is the same posture the maintainer's own dataset survey already takes by hand (e.g.
  flagging CSIC 2010 as "research"-licensed, or several Cowrie-derived corpora as
  "license unclear/unstated, treat as unclear" — `funnypot/docs/LLM-TRAINING-DATA.md:82`,
  `funnypot/docs/research/honeypot-projects.md:141`); this gate just automates that
  judgment call as a hard stop instead of relying on someone remembering to check.

### 1. OWASP CoreRuleSet updater

New file: `funnypot-core/.github/workflows/update-crs.yml` (lives in `funnypot-core`,
alongside `update-templates.yml`, since — like nuclei-templates — CRS parsing produces a
compiled artifact consumed by the engine, not app-level data). The CRS parser itself is
being designed separately; the CLI hook name below (`compile-crs`) is a placeholder in the
same family as the existing `compile` / `compile-emulators` / `compile-routes` /
`merge-routes` subcommands in `bin/funnypot` — swap it for whatever that agent lands on.

CoreRuleSet tags as `vX.Y.Z` (confirmed via GitHub: `v4.16.0`, `v4.19.0`, etc. at
`github.com/coreruleset/coreruleset/releases`) and is Apache-2.0 licensed — on the
allow-list above, so the license gate should pass cleanly under normal operation and only
fire if that ever changes.

```yaml
name: update-crs

# Keep funnypot's CRS-derived deception rules in lock-step with upstream CoreRuleSet.
# Weekly (and on demand): pulls the latest coreruleset tag, recompiles the CRS-derived
# rule set, proves correctness + fingerprint-safety + license, and opens a PR — only if
# everything is green. Never commits directly, never auto-merges.

on:
  schedule:
    - cron: '0 6 * * 2'   # Tuesdays 06:00 UTC — offset from update-templates.yml (Monday)
  workflow_dispatch:
    inputs:
      tag:
        description: 'coreruleset tag (blank = latest release)'
        required: false
        default: ''

permissions:
  contents: write
  pull-requests: write

jobs:
  recompile:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.3'
          extensions: mbstring, ctype
          coverage: none

      - name: Install dependencies
        run: composer install --no-interaction --prefer-dist --no-progress

      - name: Resolve coreruleset tag
        id: crs
        run: |
          TAG="${{ github.event.inputs.tag }}"
          if [ -z "$TAG" ]; then
            TAG=$(git ls-remote --tags --sort=-v:refname \
              https://github.com/coreruleset/coreruleset.git \
              | grep -oE 'refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 | sed 's#refs/tags/##')
          fi
          echo "tag=$TAG" >> "$GITHUB_OUTPUT"

      - name: Fetch coreruleset
        run: |
          git clone --depth 1 --branch "${{ steps.crs.outputs.tag }}" \
            https://github.com/coreruleset/coreruleset.git /tmp/coreruleset

      - name: License check (upstream must be on the allow-list)
        run: bash scripts/ci/check-license.sh /tmp/coreruleset resources/upstream-licenses/coreruleset.LICENSE.md

      # Placeholder — swap for the real CRS parser's CLI once it lands.
      - name: Recompile CRS-derived rules
        run: php -d memory_limit=2G bin/funnypot compile-crs /tmp/coreruleset/rules --out=resources/compiled/crs-index.php

      - name: Unit + compiler tests
        run: vendor/bin/phpunit

      - name: Golden acceptance
        run: bash tests/acceptance/run.sh   # extend golden.txt/golden-templates with CRS-triggering cases

      - name: Fingerprint-safety check
        run: php scripts/ci/check-fingerprint-safety.php --source=/tmp/coreruleset/rules --index=resources/compiled/crs-index.php

      - name: Open PR with refreshed CRS rules
        uses: peter-evans/create-pull-request@v6
        with:
          commit-message: "chore: recompile CRS rules from coreruleset ${{ steps.crs.outputs.tag }}"
          branch: auto/update-crs
          delete-branch: true
          title: "Update CRS-derived rules — coreruleset ${{ steps.crs.outputs.tag }}"
          body: |
            Automated recompile from coreruleset `${{ steps.crs.outputs.tag }}`.
            Unit suite, golden acceptance, fingerprint-safety, and license checks all passed.
          add-paths: |
            resources/compiled/crs-index.php
            resources/compiled/crs-manifest.json
            resources/upstream-licenses/coreruleset.LICENSE.md
```

### 2. Nuclei templates updater — recommended improvements to the existing workflow

The existing `update-templates.yml` is otherwise solid and shouldn't be restructured —
just have two steps inserted between "Golden acceptance" (line 74) and "Open PR" (line
76):

```yaml
      - name: License check (upstream must be on the allow-list)
        run: bash scripts/ci/check-license.sh /tmp/nuclei-templates resources/upstream-licenses/nuclei-templates.LICENSE.md

      - name: Fingerprint-safety check
        run: php scripts/ci/check-fingerprint-safety.php --source=/tmp/nuclei-templates/http --index=resources/compiled/nuclei-index.full.php
```

and add the license artifact to `add-paths` (line 88-95) alongside the existing five
paths, so the fetched-and-verified `nuclei-templates` LICENSE text ships in the PR diff
too, not just referenced from the static doc.

### 3. Adopted datasets updater

New file: `funnypot/.github/workflows/update-datasets.yml` `[funnypot repo]` — datasets
feed the app-level LLM training/synthetic-content pipeline (`docs/LLM-TRAINING-DATA.md`,
`scripts/llm-eval/`), not the engine's compiled index, so this belongs in `funnypot`, not
`funnypot-core`. Today there is no adoption/ingestion automation at all — the survey docs
(`docs/LLM-TRAINING-DATA.md`, `docs/research/honeypot-projects.md`) are a manual literature
review, not a pipeline — so this workflow is deliberately conservative: it never runs an
adoption/derivation step unattended, it only detects upstream movement and hands a human
a reviewable PR with the license and a diff summary attached.

New tracked manifest, `funnypot/datasets/MANIFEST.json`:
```json
{
  "datasets": [
    {
      "name": "web-application-attack-datasets",
      "source": "https://github.com/msudol/Web-Application-Attack-Datasets.git",
      "ref": "main",
      "pinned_sha": "REPLACE_ME",
      "license": "unstated"
    }
  ]
}
```

```yaml
name: update-datasets

# Detect upstream movement on adopted training-data sources (GitHub or HuggingFace — both
# are plain git remotes) and open a PR bumping the pin. Never fetches full content and
# never re-runs adoption/derivation unattended: a human reviews the diff and the license,
# then re-runs whatever local ingestion step turns it into funnypot data by hand.

on:
  schedule:
    - cron: '0 6 * * 3'   # Wednesdays 06:00 UTC — cheap sha-only poll, no compile/Docker
  workflow_dispatch: {}

permissions:
  contents: write
  pull-requests: write

jobs:
  check-datasets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Poll each pinned dataset for a new commit
        id: poll
        run: |
          set -e
          CHANGED=0
          python3 - <<'PY'
          import json
          m = json.load(open("datasets/MANIFEST.json"))
          for d in m["datasets"]:
              print(d["name"], d["source"], d["ref"], d["pinned_sha"])
          PY
          for row in $(jq -c '.datasets[]' datasets/MANIFEST.json); do
            name=$(echo "$row" | jq -r .name)
            source=$(echo "$row" | jq -r .source)
            ref=$(echo "$row" | jq -r .ref)
            pinned=$(echo "$row" | jq -r .pinned_sha)
            latest=$(git ls-remote "$source" "refs/heads/$ref" | cut -f1)
            if [ -n "$latest" ] && [ "$latest" != "$pinned" ]; then
              echo "changed: $name $pinned -> $latest"
              CHANGED=1
              # Fetch just the dataset card / LICENSE for the PR body, not the full corpus.
              git clone --depth 1 --branch "$ref" "$source" "/tmp/$name"
              cp "/tmp/$name/LICENSE" "resources/upstream-licenses/$name.LICENSE.md" 2>/dev/null || true
              jq --arg n "$name" --arg s "$latest" \
                '(.datasets[] | select(.name==$n) | .pinned_sha) = $s' \
                datasets/MANIFEST.json > /tmp/manifest.json && mv /tmp/manifest.json datasets/MANIFEST.json
            fi
          done
          echo "changed=$CHANGED" >> "$GITHUB_OUTPUT"

      - name: License check on any dataset with resolved license text
        if: steps.poll.outputs.changed == '1'
        run: |
          for f in resources/upstream-licenses/*.LICENSE.md; do
            [ -f "$f" ] && bash scripts/ci/check-license.sh "$(dirname "$f")" "$f"
          done
          # A dataset whose license is unresolved/off-allowlist should FAIL here, not
          # silently open a PR — matches the "unstated license" caution already applied
          # by hand in docs/research/honeypot-projects.md.

      - name: Open PR bumping pinned dataset revisions
        if: steps.poll.outputs.changed == '1'
        uses: peter-evans/create-pull-request@v6
        with:
          commit-message: "chore: bump pinned dataset revision(s)"
          branch: auto/update-datasets
          delete-branch: true
          title: "Upstream dataset revision(s) changed — review before re-adopting"
          body: |
            One or more datasets in `datasets/MANIFEST.json` moved upstream. This PR only
            bumps the pinned sha and attaches the current license text — it does NOT
            re-run any ingestion/derivation step. Review the license and the upstream diff,
            then manually re-run adoption if you want the new revision's content.
          add-paths: |
            datasets/MANIFEST.json
            resources/upstream-licenses/*.LICENSE.md
```

---

## Summary of gates, per workflow

| Workflow | Fetch/pin | Correctness gate | Fingerprint-safety gate | License gate | PR only? |
|---|---|---|---|---|---|
| `update-templates.yml` (exists) | tag via `git ls-remote`, shallow clone | phpunit + real-nuclei Docker acceptance | **missing — add** | **missing — add** (static doc only) | yes, `create-pull-request` |
| `update-crs.yml` (new) | same pattern | phpunit + acceptance (extend golden set) | new script, required | new script, required | yes |
| nuclei updater (improved) | unchanged | unchanged | new script, required | new script, required | yes |
| `update-datasets.yml` (new) | sha via `git ls-remote`, no full clone unless changed | none (no auto-derivation) | N/A at pin time; apply when derived artifacts are generated | new script, required, hard-fail on unresolved license | yes |

None of the four ever push to `main`/`master` or set an automerge label — all four rely
solely on `peter-evans/create-pull-request`'s branch+PR flow with `contents: write` +
`pull-requests: write`, the same minimal permission pair the existing workflow already
uses.
