# FakeFilesystem + Fleet Console + Streaming Web Terminal — Design Spec

**Status:** design (FP-0036 + web-terminal follow-on) — rev 2 (incorporates fable review)
**Date:** 2026-08-24
**Area:** funnypot (app), PHP 8.0, framework-free
**Related:** `backlog/todo/FP-0036-reusable-fakefilesystem-web-ssh-telnet.md`, memory
`fake-web-shell-idea`, `procedural-endless-download-idea`, `persona-poly-stack-decision`,
`emulator-tier-coordination`, `mockauth-flagship-build`. Research synthesis:
`funnypot-project/scratchpad/fakefs-research-synthesis.md` (workflow wxifw857k). Interface map + fable
spec review folded in (rev 2).

## Goal

Build ONE deterministic, inert, procedurally-generated fake Unix filesystem (`FakeFilesystem`) and ONE
shared command interpreter (`ShellInterpreter`), reused by three front-ends — the existing SSH fake shell,
the telnet fake shell, and a new streaming web terminal fronted by a server "fleet console" in the deep
admin panel. Every command (and every write/exec *attempt*) is generated server-side and logged as threat
intel. Nothing executes attacker input; nothing is fingerprint-unsafe; output is deterministic per deploy.

## Decisions changed by review (read first)

- **Web-terminal command endpoint is a Router-level POST route** (sibling of `AiApiRouter`), NOT a panel
  path — the panel/`SynthesizedResponse`/`ResponseEmitter` tier is single-buffered and cannot stream. Only
  `AiApi\StreamEmitter` streams. The fleet console *UI* is a GET panel section; the *command endpoint* is
  the Router route. (fable B2 + interface map.)
- **Overlay is server-side, per-session, keyed by an opaque session cookie** — NOT a client localStorage
  blob. This reverses the earlier "client localStorage" decision on a security finding: no real web
  terminal stores filesystem state in the browser, so a localStorage FS-diff blob is itself a
  devtools-visible tell; a session cookie is what every real web app has (zero fingerprint) and still
  survives reload. Server-side keeps the mechanism hidden and the state private. **Operator: veto if you
  still want client-side.** (fable M5.)
- **Streaming resolves the full output first, then paced-emits** — never generate mid-stream (once a byte
  is flushed, status is locked; a mid-stream fault would be a truncated 200). Mirrors `AiChatHandler`.
  (fable B3.)
- **The private secret auto-generates + persists** to the mounted data volume on first boot; the shell
  never goes dark if the env var is unset. (fable B4.)

## Architecture (one line each)

- **`FakeFilesystem`** (`Funnypot\Shell\Fs`) — pure/stateless generator: `(hostSeed, role, path[, overlay])`
  → listings / file bytes / stat, by hashing the path. No materialized tree; any node computed from its
  address.
- **`ShellInterpreter`** (`Funnypot\Shell`) — shared, never-execute dispatcher over a `ShellSession`;
  reads/writes go through `FakeFilesystem`; writes mutate the session overlay; unknown input fails like
  real Linux. Returns plain `\n` output + metadata (exit code, pacing); adapters format transport.
- **`HostFacts`** (`Funnypot\Shell\Host`) — per-host coherence source: wraps `ServerProfile` and adds the
  process table (**reusing `MinerRig` + `FakeCron`**), `/proc/*`, `df` mounts, `netstat` sockets, and the
  `passwd`/uid map — all from one host seed, so fleet + shell + panel agree.
- **Front-ends** are thin: SSH (`SshConnection`), telnet (`ProtocolEmulator`), web terminal (Router POST
  endpoint). Fleet console (`FleetSection`, GET panel) is the web terminal's front door.

## Tech Stack

Framework-free PHP 8.0 (`Funnypot\` → `src/`). No new composer deps. Client terminal = scoped inline JS in
the panel (no framework, no external script). Streaming via `AiApi\StreamEmitter` (chunked flush +
`X-Accel-Buffering: no`), reused from a new Router POST handler.

## Global Constraints (bind every task)

- **PHP 8.0**, framework-free, PSR-4 `Funnypot\` → `src/`. No new composer deps.
- **Inert:** never `exec`/`eval`/`proc_open`/`shell_exec`, no real FS access, no outbound socket. Emulate
  output; the requested URL/command is intel only.
- **Determinism:** identical output per deploy for identical `(hostSeed, role, path)`. On hash-derived ints
  use only `& | ^ << >> %` (never `+ - * /` — silent float promotion breaks determinism); always mask
  `& PHP_INT_MAX` before `%`; never `hexdec()` a 64-bit hex string. `pack('N',$i)` requires `$i < 2^32` —
  the per-node draw counter stays well under this (newcount cap). Assert `PHP_INT_SIZE === 8` at bootstrap,
  but on the web path route the assertion through the endpoint's try/catch so it degrades, never 500s.
  **Do NOT "fix" `ServerProfile` to these rules** — it uses `hexdec(substr(sha256,0,15))` at ≤60-bit
  magnitudes (safe); it lives in a different seed space (hexdec-int) from the engine (raw-bytes).
- **Secret handling:** the private per-install secret is never committed, never logged, never echoed. Read
  from env `FUNNYPOT_FS_SECRET`; if unset, auto-generate 32 random bytes and persist to
  `<dataDir>/fs_secret` (the mounted `funnypot-data` volume that survives container recreate — same
  persistence story as the LE certs / rules key), then reuse it. Never go dark for a missing secret.
- **Fingerprint-safe:** generated shell/FS/fleet strings are factual/plausible, never scanner signatures.
  NOTE the CI gate (`check-fingerprint-safety.php`) scans only compiled template artifacts and does NOT see
  runtime panel/shell/FS output — so safety here is enforced by (a) escape-by-construction helpers, (b)
  `LlmOutputSanitizer::pageBodyOk` on any HTML surface, and (c) **new `FingerprintSafetyTest` provider rows**
  that render representative FS/shell/fleet output and `assertClean()` against
  `resources/app-fingerprint-denylist.php`. Adding those rows is a phase deliverable, not an afterthought.
- **Response invariant:** the web terminal only ever *upgrades* a 404; any interpreter fault degrades to a
  plain error line, never an HTTP 500. Because streaming locks the status on first flush, the endpoint
  **resolves the full (bounded) output inside `try/catch(\Throwable)` BEFORE emitting any byte.**

## Threat model & security invariants

Treat the generation algorithm and all wordlists as **public knowledge** (funnypot-core is public by
mandate; the app generator is reverse-engineerable). Security cannot come from obscurity.

1. **Private per-install secret (load-bearing).** `hostSeed = fold64(fnv1a64(secret ‖ hostName ‖ role))`
   → int for `ServerProfile::fromSeed()`. `secret` is per-install, never committed, persisted on the data
   volume (above). Defeats the *oracle-replay* attack (clone repo → run generator with guessed seeds →
   diff byte-for-byte → 100% detection + loot shortcut). **Secret persistence across redeploys is
   required** — if it changed each deploy the whole host identity + loot would reshuffle (a returning
   scanner sees a different box). Persisted-once satisfies this.
2. **Two-seed model.** *Host-identity seed* = secret-folded, per-host, **stable across attackers** — drives
   `HostFacts`/`ServerProfile`/the FS/loot (what fleet + shell + panel must agree on). *Per-attacker
   ephemeral seed* = the existing `crc32($ip)` on `ProtocolSession` — drives only `{{fake.*}}` session
   flavor / troll frame, never host identity. `FakeShell` carries no seed today; threading the host-identity
   seed in is new plumbing.
3. **Server-side overlay integrity.** The overlay is server-held, keyed by an opaque session cookie token
   (HMAC'd/signed so a forged cookie is rejected). Bounded: sparse diff, capped entry count + byte size per
   session, TTL expiry, LRU cap on live sessions (a honeypot surface must not be memory-exhaustible). A
   write beyond the cap → plausible "No space left on device".
4. **Per-host coherence, not per-attacker variance.** Host facts (hostname/cpu/mem/disk/process table/
   `/proc`/passwd) AND loot file contents are **per-host-frozen** (host-identity seed + path) so every
   surface agrees and a returning attacker sees the same box. The ONLY thing that varies per attacker is
   their own session overlay (their mutations). No two *installs* are byte-identical (different secret); no
   two *user homes* within an install are identical (different path) — both deterministic, both coherent.
5. **Large pools.** Every enumerable pool (hostnames, CPU/disk/vendor models, user/db names, filename
   wordlists) is hundreds deep from real published hardware/OS catalogs (factual public data —
   fingerprint-safe). An exact-string match against the repo must not be proof of fakeness.
6. **No shared constants across installs.** Every fabricated secret (wallet bytes, keys, reserved IPs) is
   seeded on host-identity seed + path; never a shared literal. Drop `AKIAIOSFODNN7EXAMPLE` (on known-fake
   blocklists — a stronger canary than a random-looking fake).
7. **Inert + fail-loud** (Global Constraints + §Interpreter).

## Component 1 — `FakeFilesystem` (the engine)

Namespace `Funnypot\Shell\Fs` (app-side, PHP 8.0). Pure/stateless: no time/randomness/IO beyond the
injected `FrozenClock`, `HostFacts`, and the `Fake\*` generators.

### Seeding & draw primitive

```
key(role, path)      = secret . "\0" . GEN_VERSION . "\0" . role . "\0" . canonical(path)
nodeSeed(role, path) = hash('fnv1a64', hostSeedBytes . key(role, path), true)   // 8 raw bytes
draw(seedBytes, i)   = unpack('J', hash('fnv1a64', seedBytes . pack('N', i), true))[1] & PHP_INT_MAX
```

- `GEN_VERSION` is a frozen int schema version folded into every seed; bumping it is the ONLY sanctioned
  way to change the draw schema (prevents silent reshuffles of already-observed content).
- One shared `Draw` helper: `intBelow($seed,$i,$n)` (mask-then-`%`, never negative), `pick($seed,$i,$pool)`,
  `chance($seed,$i,$num,$den)`, `heavyTailedSize($seed,$i)` (log-normal-ish via bit-slicing). Every
  generation site uses it — no hand-rolled modulo anywhere.
- `fnv1a64` because xxh3/murmur3 are PHP 8.1+. `crc32b` ONLY for internal bucketing/dedup pre-checks, never
  for scanner-observable attributes (32-bit birthday ceiling).
- **One shared `canonical()`** feeds `key()` on BOTH the `list()` and `isValidChild()` sides (leading slash,
  no trailing slash, no `.`/`..`), or the list==validate invariant silently breaks.

### Node schema

`name, type(dir|file|symlink), uid, gid, size, mode, mtime, target?` + a content handle. For a file, `size`
and the `cat` bytes derive from the SAME `nodeSeed` (metadata and content never diverge). `mtime` off
`FrozenClock`, from an install-time cluster + a thin recent tail tied to `HostFacts` uptime; never future.

### Three-layer resolution (single entry point)

Precedence — every consumer calls one resolver:

1. **Session overlay** — sparse diff (full-path → mutated node | tombstone), applied first. Never a
   whole-tree clone (base is procedurally infinite). Strictly additive/override; **never feeds back into
   any other path's seed** (tested: `mkdir foo` cannot change sibling `bar`).
2. **Pinned/curated nodes** — static override map for paths attackers reach for: `/etc/passwd`,
   `/etc/shadow`, `~/.ssh/id_rsa`, `~/.bash_history`, crypto/cloud loot, `/proc/*` (from `HostFacts`),
   per-user `/home/<dept>/<user>` roots from the `Org` roster, OS-standard symlinks (merged-/usr,
   `/etc/localtime`). Pinned content still seeded per host-identity seed (no shared constants).
3. **Procedural fill** — everything else.

### Consistency & termination (tested invariants)

- **`children(D)` and `isValidChild(D,x)` are the same code path** (membership on the generated list). Path
  valid iff each ancestor generates the next segment; validation walks root→leaf, O(depth); `cwd` memoized.
- **Hard `MAX_DEPTH`** independent of probabilistic dir-decay. **Global per-session newcount cap**
  (defense-in-depth) + per-directory bounded child counts.
- **Deterministic stream-based dedup** on name collision (draw again) — never PHP hash-set iteration order.
- **Heavy-tailed** child counts/sizes (mostly small, occasional large); depth-decay role/subtree-aware.
- **Single `PathNotFound`** type; every consumer renders its bash-standard text from it.
- **Role/persona/stack lineage** threaded parent→child through the seed (poly-stack subtree coherence).

### Public surface

`list(path): Node[]`, `read(path): string`, `stat(path): Node`, `isDir/isFile/exists(path): bool`, bound to
`(hostSeed, role, overlay)` at construction. Overlay mutation returns a new overlay (immutable-style).

## Component 2 — `HostFacts` (coherence source)

Namespace `Funnypot\Shell\Host`. Wraps `ServerProfile::fromSeed(hostIdentityInt)` and EXTENDS it with what
the shell needs and ServerProfile lacks (fable M1):

- **Process table** — reuse `MinerRig::fromSeed()` + `FakeCron::fromSeed()->processes()` (the SAME
  generators the panel's `ProcessesSection` uses) so terminal `ps`, panel `ps`, and fleet detail show one
  process set — including the miner (the "already-compromised, mining" narrative is coherent with the loot
  and appears in the shell). **Read-only reuse — do NOT edit `MinerRig`/`FakeCron`/`ProcessesSection`
  (Agent B has uncommitted WIP there); consume their public API only.**
- **`/proc/*`** — hand-modeled `cpuinfo/meminfo/loadavg/uptime/version/self/` + numeric PID dirs matching
  the process table, computed from the same `ServerProfile` numbers (never generic procedural fill, never
  absent). `meminfo`/`free` need MemFree/Buffers/Cached/Swap derived from `memory()`.
- **`df` mount table**, **`netstat`/socket list** (ports consistent with the services/loot story, e.g.
  80/443/3306/6379 given the web-app `.env`), **`passwd`/uid map** (per-user incremental uids matching the
  homes). All derived from the host-identity seed.

`HostFacts` is the one call site the fleet console, `/proc`, and the shell stat/ps/df/free/netstat all read.

## Component 3 — `ShellInterpreter`

Namespace `Funnypot\Shell`. Operates on a `ShellSession` interface (cwd, user, uid/gid, host, overlay, env,
lastExit, close) implemented by `ProtocolSession` (SSH/telnet) and a web session built from the cookie's
server-side state. Returns plain `\n` output + metadata (exit code, pacing hint); adapters convert line
endings and drive streaming/output.

- **Two-tier dispatch:** real VFS handlers (`ls cd pwd cat mkdir touch rm mv cp stat find grep head tail wc
  du df ps free top uname id whoami netstat ss ifconfig ip uptime w who last env export history echo chmod`)
  vs a flat canned lookup for cheap recon (`lsb_release arch nproc lscpu`).
- **Broad set from v1.** Writes mutate the overlay; nothing executes. `wget`/`curl` log the URL + return
  canned progress, never fetch.
- **Fail loud & specific:** unknown command → `command not found`; unknown flag → real `invalid option`;
  bad path → the single `PathNotFound` text. Never generative output for garbage (over-helpfulness is the
  tell). This does NOT collide with the LLM 404-upgrade tier (different surface: shell context vs HTTP
  path-miss).
- **Coherence:** `top/free/df/uname/uptime/ps//proc/*` render from `HostFacts` (one source). `du`/`df`
  aggregate real generated sizes.
- **Real POSIX arithmetic:** `.`/`..` in every `-a`/`-A` listing (incl empty dirs); hardlink = 2+child-dirs;
  `ls -l total` = block-rounded child-size sum; inodes clustered by parent+sibling order; per-user
  incremental uids matching `/etc/passwd`.
- **Permission enforcement** vs session uid/gid (non-root gets `Permission denied` on `cat /root/...`), not
  decorative `-l`. Deny writes under `/proc /sys /dev/pts` with kernel-like text.
- **`$?` tracking**; `history` reflects this session's typed commands (appended to overlay), reconciled with
  the pre-baked `~/.bash_history` bait. Pipe filters (`grep/wc/head/tail/sort`) transform producer output.
- **Pacing metadata (v1):** the interpreter tags slow commands (`find /`, `du -sh /`, `sleep N`, `ping`)
  with a simulated duration + chunk boundaries in the returned metadata. It still resolves output fully
  (bounded); the web endpoint paced-streams it, SSH/telnet byte-stream it. Ctrl-C = client fetch-abort
  (web) / interrupt (ssh/telnet).

## Component 4 — SSH / telnet refactor

`FakeShell` becomes a thin adapter over `ShellInterpreter`, constructed with the deploy host-identity seed
(new plumbing; today `HOST` is a `const` and `new FakeShell()` takes no args — the call sites at
`ProtocolEmulator.php:287/301` and `SshConnection.php:565/579/681` pass the seed). Behavior
preserved/improved; **no SSH/telnet test regressions.** One host per listener; many per-user
`/home/<dept>/<user>` homes from the `Org` roster (usernames/departments match). Overlay = the
connection-lifetime `ProtocolSession` (in-memory, discarded at disconnect). Closes the concrete
`FakeShell` tells (research §6): `ls -a`, hardcoded mtime/hardlink/`total`, missing `du`, empty `/proc`,
arg-blind `ps`, uid=1000-for-all, single-host `uname`, static loot.

## Component 5 — Fleet console + streaming web terminal

### Fleet console (GET panel section)
`Funnypot\App\Render\Panel\FleetSection` (+ `Fake\Fleet`). Registered in `PanelRegistry` with a nav slug
(the skin nav asserts every slug resolves — `AdminLteSkin.php:36`). Breadcrumbs use the persona company,
NOT `AbstractPanelSection::baseCrumbs()`'s hardcoded literal. Config knob: server count (default ~20–40)
with some `offline`/`degraded`. Each fleet host `h_i` seed = `fold64(fnv1a64(secret ‖ 'fleet' ‖ i))`; **one
designated fleet host IS "this box"** (same host-identity seed as the SSH/telnet/panel single host) so the
narratives line up. One `ServerProfile`/`HostFacts` per host → fleet row, detail, and that host's terminal
agree.
- **Fleet view:** hostname/role/status/CPU%/mem/disk/net/uptime/OS/RFC1918 IP/datacenter; filter/group;
  aggregate header. **Detail:** gauges + services + `ps` (from `HostFacts`) + ports/packages/users/cron/
  logs + a **Console button**. Offline hosts → "unreachable", no shell.
- **Actions** (reboot/stop/snapshot/…) → INERT "queued". The Console button is a POST launcher (a departure
  from the GET-only nav model — state it), opening the terminal against the host's endpoint.

### Streaming command endpoint (Router POST route)
A new `ConsoleRouter` wired as a **Router-level POST handler, sibling of `AiApiRouter`** (`Router::public()`
and `Router::stealth()`), ahead of the honeypot catch-all — NOT a `PanelSection`, NOT through
`LlmFakeResponder`/`ResponseEmitter` (that tier can't stream). Reuses `AiApi\StreamEmitter`
(`begin()` drains OB + `X-Accel-Buffering: no`; `chunk()` = print/flush/usleep pacing).
- **Flow:** verify session cookie (HMAC) → load/create server-side overlay → build `ShellSession(host,
  role, uid, cwd, overlay)` → `ShellInterpreter.run(command)` **resolving full bounded output inside
  try/catch** → log → `StreamEmitter.begin(200)` then paced `chunk()` the materialized bytes → persist
  overlay + updated cwd server-side.
- **Gate exemption:** interactive typing is many POSTs; the route is exempt from the per-IP velocity/
  bulk-scan gate (like `AiApiRouter`), with its own per-session rate cap, or the terminal self-destructs
  into a 24h `bulk_scan` 404 pin (CLAUDE.md gotcha).
- **Never-500:** any fault caught pre-stream → a plain error line at 200; the `PHP_INT_SIZE` assert and all
  interpreter faults route through this try/catch.
- **Logging (intel — the point):** every command → `HitStore::append(['event'=>'shell', ...])` with host in
  `path`, the raw command + write/exec-attempt flag in `body`, method/ts/ip/geo as usual (reusing the
  existing `logServed` event shape). A dashboard `shell` quick-filter (whitelist `event` already filterable)
  surfaces it beside `panel`/`ssh`.

### Web terminal UI
Scoped inline-JS terminal in the `FleetSection` detail page (prompt `user@host:cwd$`, MOTD, seeded history,
up-arrow recall, resize). POSTs each command to the `ConsoleRouter` endpoint; renders the streamed chunks;
holds NO filesystem state client-side (only the session cookie the browser sends automatically).

## Data flow (web terminal)

```
browser: command → POST {command} (+ session cookie)  → ConsoleRouter (Router POST route)
server:  verify cookie HMAC → load server-side session overlay + cwd
         ShellSession(host, role, uid, cwd, overlay)
         try { output = ShellInterpreter.run(command) }  // FULLY resolved, bounded, overlay ▸ pinned ∪ procedural
         catch(\Throwable) { output = "<plausible bash error>" }
         HitStore.append(event:'shell', host, cwd, command, isWriteAttempt)
         StreamEmitter.begin(200); paced chunk(output); persist overlay+cwd server-side
browser: render streamed chunks
```

## Testing

- **Invariant unit tests:** list==validate same path; overlay purity (`mkdir foo` doesn't perturb `bar`);
  determinism (re-list a dir twice byte-identical; two sessions identical); `MAX_DEPTH`; negative-modulo &
  int-overflow guards; `.`-`..`/hardlink/`total` arithmetic; permission enforcement; du/df consistency;
  cross-surface coherence (fleet number == shell `free`/`df`/`ps` for the same host, incl. the miner in
  both panel and shell `ps`).
- **New `FingerprintSafetyTest` provider rows** (fable B1): render `ls -la /root`, `cat /proc/cpuinfo`,
  `ps aux`, a directory listing at depth, and a fleet detail page; `assertClean()` each against
  `resources/app-fingerprint-denylist.php`. Phase-1 rows for the engine, Phase-2/3 rows for shell/fleet.
- **No regressions** in the existing SSH/telnet suites after the refactor.
- **Scanner-in-the-loop** (funnypot-ingest bench) vs Cowrie/Kippo-detectors + linpeas/linEnum + the three
  named probes: ELF-header byte-read on a claimed executable; write-then-read round-trip in a writable dir;
  bogus command/flag expecting a specific failure.
- **Existing CI fingerprint gate stays green** (don't break the compiled-artifact gate), understanding it
  does not itself cover the new runtime strings.

## Phasing (each phase = an independently testable ticket)

1. **`FakeFilesystem` engine** — `Draw`, seeding (persisted secret + `GEN_VERSION`), shared `canonical()`,
   node schema, 3-layer resolve, walk-validate, depth/newcount caps, heavy-tailed distributions, POSIX
   arithmetic helpers, single `PathNotFound`; grow pools to hundreds; invariant unit tests + engine
   fingerprint provider rows. No front-end. (Buildable now — the reworks all land in Phases 2–5.)
2. **`HostFacts`** — wrap `ServerProfile`, add process table (reuse MinerRig+FakeCron, read-only), `/proc`,
   `df`, `netstat`, passwd/uid map; coherence tests.
3. **`ShellInterpreter` + SSH/telnet refactor** — two-tier dispatch, broad commands, writes→overlay,
   du/df/`$?`/history/pipes/perms/`/proc`/fail-loud, pacing metadata; re-base `FakeShell`+telnet with the
   host-identity seed; per-user homes; no SSH-test regressions + shell fingerprint rows + scanner-in-loop.
4. **Fleet console** (`FleetSection` + `Fake\Fleet`) — fleet+detail views, INERT actions, Console button,
   per-host seeds, "this box" designation, coherence with the shell; fleet fingerprint rows.
5. **Streaming web terminal** — `ConsoleRouter` Router POST route + `StreamEmitter` reuse, server-side
   session-cookie overlay (bounded/TTL/LRU), resolve-then-paced-stream, gate exemption, terminal UI,
   `event:'shell'` logging + dashboard `shell` filter.
6. *(separate later ticket)* procedural endless download reusing the engine.

## Out of scope / noted

- Transport-layer tells (SSH HASSH handshake fingerprint) + auth-oracle plausibility — separate from this
  subsystem; cross-ref the WP-Phase-2b login-oracle guard work.
- SipHash (adversarial-input-resistant hash) — future hardening if min PHP rises past 8.0; the private
  secret makes fnv1a64 adequate now.
- Per-host (vs per-session) mutation persistence: v1 is session-scoped (a NEW session sees a clean box).
  Documented tradeoff; per-host durable mutation state is out of scope.
```
