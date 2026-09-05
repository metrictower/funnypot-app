# Protocol Honeypot Plan: a multi-protocol (L4/TCP) engine alongside the HTTP engine

Status: design and build plan. Not built.

funnypot today is an HTTP honeypot: nginx/php-fpm answers scanner probes with
fake-vulnerable responses built from data-driven templates. This document
plans a second engine that listens on raw TCP and speaks **wire protocols**
(redis, telnet, ftp, smtp, memcached, and ssh, which is the hard one), reusing
funnypot's "everything is a bounded template" approach and its
detect/respond/log spine.

The design goal is the same as the HTTP side: an attacker probing the port
gets the plausible fake they expect, their time is wasted, and every byte is
logged. The honeypot never executes attacker input and never becomes a real
service.

---

## 0. What we are mirroring from the HTTP engine

Read this before proposing anything new. The protocol engine must feel like the
same project.

- **Template = data, runtime = PHP.** `EmulatorCompiler` turns YAML
  (`templates/attack/*.yaml`) into a frozen PHP array
  (`resources/compiled/funnypot-attack.php`); the runtime
  (`TemplateAttackEmulator`) only interprets that array. symfony/yaml is a
  *build-time* dep; the runtime needs PHP alone.
- **First-match-wins rule list.** A rule has `match` conditions (regex/contains
  on a named surface) and a `response` (status/headers/body). `priority`
  orders them.
- **Bounded dynamic vocabulary.** `DirectiveRenderer` fills `{{...}}` markers
  from a *closed* set: `{{canned.passwd}}`, `{{fake.NAME:hex:N}}` (seeded,
  per-attacker, deterministic), `{{match.N}}` (bounded reflection of captured
  attacker bytes), `{{pick:a,b,c}}`, `{{canary.KEY}}`. An unknown directive fails
  the build. Reflected values are inserted once and never re-scanned, so an
  attacker-supplied `{{...}}` stays inert literal text. This is the safety
  core, so reuse it verbatim.
- **Compile-time safety lint.** The compiler rejects unknown directives, CR/LF
  in static headers, duplicate ids, invalid regex, and (via `expect:`) markers
  that only survive by reflection. The protocol compiler needs the same kind of
  lints for wire bytes.
- **Inert by default, opt-in to respond.** `Config` defaults to `detect` mode
  with the respond gate closed. `Honeypot::respond()` only serves a fake after
  kill-switch / mode / trusted-bypass / severity-ceiling / body-cap gates pass.
- **Side-effect-free core + Observer seam.** The engine does no I/O; the host
  app's `Observer` (or the demo's `demo_log`) does all logging/scoring. Every
  hit is one JSON line in `hits.log`, rendered live by the demo dashboard.
- **Seeded fakes are inert.** `{{fake.*}}` values are seeded from the persona
  (host/client) so one attacker sees stable-but-distinct fabricated secrets;
  canned data uses example.com / RFC-5737 addresses / dummy secrets. Nothing
  real is ever disclosed.

The protocol engine is a new listener front-end, a wire-template format, and a
shared shell layer bolted onto that same spine (compiled artifact to
interpreter to Observer to hit log to dashboard).

---

## 1. Runtime / event loop

The HTTP engine gets its concurrency for free from php-fpm behind nginx. A TCP
protocol engine has to own its own accept loop and hold many long-lived, mostly
idle connections. Options, honestly compared:

| Option | Deps | Concurrency model | Packaging | Verdict |
|---|---|---|---|---|
| **openswoole** | PECL C extension (large build) | coroutine per connection, true async, very high concurrency | must compile/install the extension into the image; changes the whole runtime model | Strong, but exactly the heavyweight dep Bob wants to avoid. **Reject.** |
| **ReactPHP** (`react/socket`, `react/event-loop`) | composer libs, pure PHP, zero C ext | single-process non-blocking event loop | `composer require`; runs under plain php-cli | Viable fallback. Adds runtime composer deps (breaks "runtime = PHP alone") but no build step. |
| **amphp** v3 (`amphp/socket`) | composer libs, pure PHP, needs PHP 8.1+ (fibers) | fiber-based async/await, one process | as ReactPHP | Cleaner code than React, but PHP 8.1 floor (funnypot targets ≥8.0) and same "adds runtime deps" cost. |
| **raw `stream_socket_server` + `stream_select` loop** | none | single-process, non-blocking, many idle conns per process | plain `php bin/funnypot-listen`; nothing to install | Matches funnypot's zero-runtime-dep ethos. More code to write (buffering, per-conn state machine), but honeypot protocols are simple. |
| **fork-per-connection** (`pcntl_fork`) | `pcntl` ext (absent in most fpm images) | blocking code per child | needs pcntl; fork-bomb risk under a connection flood | Reject: dep + DoS surface. |
| **process-per-protocol** (one small listener process per port, under a supervisor) | none beyond the loop it runs | isolation between protocols | each is just another process in the container | **Combine with the select loop.** |

### Recommendation

A generic zero-dependency listener binary (`stream_socket_server` plus a
`stream_select` non-blocking loop), run as one process per protocol/port under
the container's process supervisor.

```
bin/funnypot-listen <protocol-id> <bind-addr:port>
```

Each invocation:
- `stream_socket_server` on its port, sockets set non-blocking.
- One `stream_select` loop multiplexes the listen socket and all live connections.
- Per-connection state: an inbound byte buffer, the protocol state machine
  (banner sent? auth phase? shell session?), bytes-sent counter, deadlines.
- Everything non-blocking: never a blocking `fread`/`fwrite` that one slow
  or hostile client could use to freeze every other connection.

Why this over ReactPHP/amphp:
- **Keeps the runtime PHP-only.** This is the same invariant that lets the HTTP
  runtime ship without composer. The listener is `php` plus the standard
  `sockets`/stream functions, nothing to `composer require` or compile.
- Honeypot traffic is low-rate and I/O-bound (scanners, slow brute-forcers,
  the occasional interactive session). A select loop in one PHP process
  comfortably holds hundreds of idle/slow connections; we do not need coroutine
  throughput.
- **Process-per-protocol isolation is a security win**: a wedged or memory-hungry
  handler takes down one protocol's listener, not the whole honeypot, and the
  supervisor restarts it. Blast radius is capped by construction.

Keep ReactPHP documented as the escape hatch: if we ever want thousands of
concurrent sessions without hand-maintaining the loop, `react/socket` is a
drop-in for the transport layer and the protocol/template code above it is
unchanged. We just don't take the dependency now.

Hard caps the loop enforces (see §6): max concurrent connections per listener,
max connections per source IP, max inbound buffer per connection (drop and close
on overflow), idle timeout, total session timeout.

---

## 2. Protocol-template format

A **protocol template** is YAML, compiled (like attack templates) into a frozen
PHP array. It describes one wire protocol as data: an optional opening banner,
how to slice the inbound byte stream into logical requests, and a first-match-wins
list of request-to-response rules. Plaintext protocols become pure data; binary
ones additionally name a `codec` (§4).

### Schema

```yaml
protocol: redis            # id (unique)
listen: [6379]             # default port(s); docker/compose can override
severity: medium
tags: [protocol, redis, cache]

banner: null               # bytes sent on connect, before any input.
                           # null for redis (silent); set for ftp/smtp/ssh-banner.

framing: resp              # how to split the inbound stream into requests:
                           #   line   -> CRLF-delimited (telnet/ftp/smtp/memcached/redis-inline)
                           #   resp   -> RESP length-prefixed (redis), needs the resp codec
                           #   raw    -> hand the whole current buffer to rules
                           #   codec:<name> -> a binary codec owns framing both ways (§4)

auth: null                 # optional accept-all auth phase machine (see ftp below)

rules:                     # first-match-wins, on the decoded request bytes
  - match: { equals: "PING" }
    send: "+PONG\r\n"
  - match: { prefix: "INFO" }
    send: { bulk: |            # 'bulk' = RESP codec wraps this body as a bulk string,
        # Server                # so the author writes semantic content, not framing
        redis_version:7.2.4
        os:Linux 5.15.0 x86_64
        run_id:{{fake.redis_runid:hex:40}}
        tcp_port:6379
        # Keyspace
        db0:keys=3,expires=0 }
  - match: { prefix: "AUTH" }
    send: "+OK\r\n"            # accept-all: any password "works"
  - match: { prefix: "CONFIG GET" }
    send: { bulk_array: ["dir", "/var/lib/redis"] }

default:                   # unmatched request → generic plausible reply
  send: "-ERR unknown command\r\n"

close_after: null          # optional: close the connection after this rule id fires
```

Match predicates operate on bytes, mirroring the attack matcher's shape:
`equals`, `prefix`, `contains`, `regex` (with the same catastrophic-backtrack
cap and `capture:` for `{{match.N}}`). Responses are byte strings run through the
same `DirectiveRenderer`: `{{fake.*}}`, `{{canned.*}}`, `{{match.N}}`,
`{{pick}}` all work identically, so per-attacker seeded fakes and bounded
reflection come for free. Byte literals in YAML use `\xNN` escapes or a
`base64:` field for wholly binary blobs.

### Example: telnet / generic banner-grab

```yaml
protocol: telnet
listen: [23]
severity: medium
tags: [protocol, telnet]

banner: "\r\nUbuntu 22.04.3 LTS\r\nlogin: "

auth:                      # accept-all login, then hand off to the shell layer (§5)
  sequence:
    - expect: line         # username line
      capture: username
      send: "Password: "
    - expect: line         # password line (any value accepted)
      capture: password
      send: "\r\nWelcome to Ubuntu 22.04.3 LTS\r\n"
  on_success: shell        # -> shared shell-emulation layer

rules: []                  # telnet has no pre-auth request grammar; it's banner+auth+shell
```

### Example: redis is the proof that protocols are "addable as data"

The redis template above is entirely data, with no PHP written per-protocol. The
generic `resp` codec (shipped once) handles RESP framing both directions; the
`bulk`/`bulk_array` helpers let the author write the fake `INFO` block as plain
text. Adding memcached, POP3, or a bespoke TCP banner service is the same
exercise: one YAML file, no code. That is the bar: new plaintext protocol =
new template, zero new PHP.

### Compile-time lints (mirror the HTTP compiler)

- Closed directive vocabulary (reuse `DirectiveRenderer::KNOWN_PREFIXES`).
- Unique `protocol` id; valid regex; bounded response byte-size per rule.
- `framing`/`codec` names must resolve to a shipped codec.
- `expect:` markers rendered with empty captures must survive (catches
  directive typos that would emit dead literal bytes).
- No unbounded response and no response that repeats/expands input (anti-amp).

---

## 3. SSH: the hard one (do not pretend it is templatable)

> **STATUS 2026-08 (SUPERSEDED): a pure-PHP SSH server shipped.** This section
> recommended a Go/Python sidecar and rejected hand-rolling SSH in PHP. That call
> was reversed for one decisive reason: a compiled sidecar is not portable. A
> Go binary has to be built and shipped per OS *and* per CPU arch (linux/amd64,
> linux/arm64, and so on); the composer package can't know where it runs. A
> pure-PHP server runs wherever PHP, `ext-sodium`, and `ext-openssl` do, the same
> "PHP alone" promise as the rest of the engine. It was built in `src/Protocol/Ssh/`
> (curve25519-sha256 kex, ssh-ed25519 host key, aes256-ctr and hmac-sha2-256),
> completes the handshake against real OpenSSH, accepts all auth (capturing
> credentials and offered keys), and drops the attacker into the same
> `FakeShell` telnet uses, with every command logged. The crypto surface is
> deliberately narrow (server-only, one algorithm per role, no client-signature
> verification) and never executes attacker input. The Tier-1 banner analysis
> below stands as history; Tier 2 is now pure PHP, not a sidecar.

**SSH is an encrypted transport.** Before any shell bytes exist, both sides run
a version-string exchange, then `SSH_MSG_KEXINIT` negotiation, a key exchange
(curve25519 / diffie-hellman-group14), host-key auth, cipher/MAC selection, and
every packet after that is encrypted and MAC'd. You cannot template plaintext
request-to-response bytes for SSH the way you can for redis or telnet. There are
no plaintext request bytes to match on until a real crypto handshake has run.

What actually exists in PHP:
- **phpseclib is client-only.** It implements SSHv2 to *connect out* to a server;
  it has no server side (no code path that accepts an inbound handshake, presents
  a host key, and negotiates as the server). Confirmed against its docs/source.
- There is no maintained pure-PHP SSH *server* library. Hand-rolling one
  means writing kex, cipher suites, MACs, and packet handling from scratch in
  PHP. That is weeks of security-sensitive crypto code, exactly the kind of thing
  that becomes a real vulnerability if you get it wrong. **Reject.**
- For comparison, the reference honeypots don't hand-roll it either: Cowrie
  rides Twisted Conch (a real, tested SSH implementation) and only emulates the
  *shell above it*; OpenCanary's "SSH" doesn't complete a handshake at all; it
  presents a version banner and logs connection/auth attempts.

That comparison gives a clean tiered answer:

### Tier 1: SSH banner and connection logging (pure PHP, in-model, ship first)

The SSH version-identification line (`SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n`) is
sent in *plaintext before* any key exchange. A large fraction of internet SSH
"scanning" is exactly this: connect, grab the banner, log, disconnect (shodan-
style recon, version-vuln sweeps). So the cheapest tier is fully templatable
today:
- Send a seeded, realistic SSH banner on connect.
- Read the client's banner and first `KEXINIT` bytes, log them as intel (client
  version fingerprints the scanner), then close.
- No handshake completed, no crypto, no shell. Pure PHP, zero deps, sits in
  the exact `banner:` slot the template format already has.

This catches banner-grabbers and connection loggers (meaningful coverage) at
almost no cost.

### Tier 2: interactive fake shell over real SSH (Go/Python sidecar)

To fool an attacker who actually *authenticates and types commands*, you need a
real SSH transport. Recommendation: a tiny sidecar process that terminates the
SSH crypto using a proven library, does accept-all auth, and forwards the
decrypted command stream to funnypot's PHP shell-emulation layer (§5) over a
local unix socket.

- **Go + `gliderlabs/ssh`** (thin wrapper over `golang.org/x/crypto/ssh`) is the
  recommended sidecar: ~150-250 lines to accept connections, present a host key,
  accept any credentials (logging them), and pipe the session's PTY line stream
  to/from a unix socket. Single static binary, trivial to drop in the container.
- Python with Paramiko/AsyncSSH is an equivalent option if a Python runtime is
  preferred.
- **The sidecar owns transport only. It contains zero emulation logic.** It does
  not know what `ls` returns; it forwards `"ls -la\n"` to PHP over the socket and
  writes back whatever PHP renders. All the "template" content (fake filesystem,
  canned command outputs, accept-all policy nuance, seeded fakes, logging) stays
  in funnypot's PHP shell layer, shared with telnet. The wire protocol between
  sidecar and PHP is line-oriented: `{session-id}\t{command}` to `{output-bytes}`.

**Effort:** sidecar ~1-2 days (crypto is the library's job). The shell layer
(§5) is the bigger piece and is shared with telnet, so its cost is not
SSH-specific.

**Honest statement of the exception:** the SSH sidecar is the one place the
protocol engine is not pure PHP. That is a deliberate trade: correct, safe SSH
crypto from a proven library beats hand-rolled PHP crypto that could become a
real vulnerability. The sidecar is isolated, does no emulation, and is an
*optional* component. Tiers 1 (banner) and the telnet-hosted shell ship without
it.

### Recommendation summary for SSH

1. Ship **Tier 1 (banner and logging)** now: pure PHP, in the template model.
2. Build the shared shell layer over Telnet first (§5): pure PHP, fully
   in-model, no sidecar.
3. Add **Tier 2 (interactive SSH)** by pointing the Go `gliderlabs/ssh` sidecar
   at that same shell layer. Do **not** hand-roll SSH in PHP; do **not** market
   SSH as "just another template."

---

## 4. Cleanly-templatable vs codec-needed protocols

**Cleanly plaintext-templatable** (text/line framing, zero new PHP, just a
template):

- telnet, FTP control channel, SMTP, POP3, IMAP, memcached (text protocol),
  redis *inline* commands, HTTP-alt, generic TCP banner-grab, SSH banner-only
  (Tier 1).

**Need a codec** (binary / length-prefixed / stateful framing, which also needs
a small shipped PHP class alongside the template):

- **redis RESP.** Length-prefixed (`*N\r\n$len\r\n…`) but simple and *generic*:
  one `resp` codec serves every redis template. The template stays pure data.
- **MySQL / MSSQL.** Binary handshake packets with sequence numbers, capability
  flags, and an auth-plugin challenge. Needs a codec *and* a per-protocol
  template. Fiddly and fingerprintable; scope carefully (§7).
- **SSH, TLS.** Full crypto, not a codec problem. SSH goes to the sidecar (§3).
  TLS is out: nginx already terminates TLS for the HTTP engine; we do not build a
  second TLS stack.
- **RDP / SMB / VNC.** Complex binary negotiation. Out of initial scope; if ever
  wanted, do negotiate-banner-only, never full emulation.

### How the format handles length-prefixed / binary protocols

A `codec:` (or `framing: codec:<name>`) field names a small PHP class with two
jobs:

1. **Inbound framing.** Consume the connection's byte buffer and yield complete
   logical requests (e.g. RESP: read `*N`, then N bulk strings; MySQL: read the
   3-byte length and seq header, then that many payload bytes). Partial data stays
   buffered until a full frame arrives.
2. **Outbound framing.** Take the semantic response the template author wrote
   (a bulk string body, a result set, an error) and emit correct wire bytes
   (prepend lengths, sequence numbers, type markers).

This is the key separation: the template author writes the *meaning* of the
fake reply; the codec owns the *wire framing*. It is what lets redis be pure
data while MySQL needs one shared codec plus a template. Byte-exact literals in
templates use `\xNN` escapes or `base64:` fields. Codecs are shipped code,
lint-covered, and like everything else they never execute input, only frame it.

---

## 5. Shared shell / command-emulation layer

One PHP component, shared by telnet (`on_success: shell`) and the SSH sidecar. It
is funnypot's answer to Cowrie's medium-interaction shell, but a lookup table,
never an interpreter.

Components:

- **Fake filesystem.** A static, seeded, read-only tree loaded from a data file
  (`templates/shell/filesystem.yaml`, compiled), mapping paths to fake contents
  built from the same directives (`/etc/passwd` to `{{canned.passwd}}`,
  `~/.aws/credentials` to a seeded `{{fake.*}}` blob). Cowrie-style content, but
  plain data, not pickled code. Nothing in the tree is ever deserialized into
  executable state.
- **Command table.** Maps a command (plus optional arg pattern) to canned output:
  `whoami` returns `root`, `id` returns a fake uid line, `uname -a` returns a
  seeded kernel string, `ls`/`ls -la` return a listing derived from the fake fs,
  `cat <path>` returns fake file content, `ps`/`netstat` return canned tables. An
  unknown command returns `bash: <cmd>: command not found`. `wget`/`curl`/`nc`/`pip install`
  are emulated as canned text. The requested URL is logged as intel and NEVER
  dereferenced.
- **Accept-all auth.** Any username/password is accepted and logged. Optionally
  reject the first attempt to force ≥2 tries (matches real brute-forcer
  expectations and harvests more credentials).
- **Session state.** cwd, env, fake hostname, prompt string, per-attacker seed.
  Bounded: max output bytes per command, max commands per session, idle timeout,
  total session timeout.
- **Logging into the same spine.** Each session and command is an event line in
  the same `hits.log` JSON shape the HTTP demo uses, via the same `Observer`
  seam, so the existing dashboard shows HTTP probes and shell sessions together.
  New fields: `proto` (ssh/telnet), `session`, `event: shell-command`, `cmd`,
  `username`, `password`, `client_version`.

**Non-negotiable invariant:** commands are matched against the table and canned
output is returned. There is no `proc_open`/`shell_exec`/`exec`/`system`/
`eval`, no real filesystem access, no outbound socket from the handler. The fake
`cat`, fake `ls`, and fake `wget` are string lookups. The DirectiveRenderer
guarantees any reflected attacker bytes (e.g. an echoed filename) stay inert.

---

## 6. Packaging in the demo docker and safety invariants

### Packaging

The demo container already runs php-fpm and nginx via `demo/entrypoint.sh`. Add:

- **Listener processes.** One `php bin/funnypot-listen <proto> <port>` per
  protocol, plus the optional Go `ssh-sidecar` binary, run under a small process
  supervisor (`s6-overlay` or `supervisord`, or an entrypoint that backgrounds
  each and `wait`s and restarts). Process-per-protocol gives isolation and
  independent restart.
- **Ports.** Publish the protocol ports in `demo/docker-compose.yml` alongside
  the existing web ports: e.g. `6379` (redis), `23` (telnet), `21` (ftp), `25`
  (smtp), `11211` (memcached), `3306` (mysql), and `2222` for SSH mapped to
  the sidecar (avoid `22`, which collides with the host's real sshd; map
  `2222:2222` or `22:2222`). Compose, the Dockerfile `EXPOSE`, `scripts/deploy.sh`
  PORTS, the entrypoint spawns and the nginx listens are all views of one inventory,
  `demo/ports.json`; `php scripts/check-ports.php` fails on any drift or on a port
  claimed by both nginx and a listener.
- **Shared artifacts.** Listeners load the compiled protocol-template artifact
  (`resources/compiled/funnypot-protocols.php`, built by the new compiler from
  `templates/protocol/*.yaml`) and write to the same `FUNNYPOT_LOG`, so one
  dashboard covers both engines.

### Safety invariants the plan MUST respect (restated at the wire layer)

- **Emulate output, never execute input.** Command table and template lookups
  only. No `eval`/`shell_exec`/`proc_open`/`system`, no real fs, no outbound
  fetch. This holds in the listeners, the shell layer, and every codec. Reuse the
  closed `DirectiveRenderer` vocabulary so reflected attacker bytes stay inert
  literal text (insert-once, never re-scanned).
- **Reflect-never-harm.** No decompression/RESP/amplification bombs; every
  response byte-size-capped; no response that repeats or expands the input; no
  retaliation, no scan-back, no outbound connection ever. Per-message and
  per-session output caps; idle and total timeouts; caps on concurrent connections
  per listener and per source IP; inbound buffer cap (drop and close on overflow)
  so a flood can't exhaust memory. Process-per-protocol caps blast radius.
- **Runtime is PHP.** Listeners, codecs, and the shell layer are pure PHP with
  no C extension and no runtime composer dep (symfony/yaml stays build-time). The
  only non-PHP piece is the optional SSH crypto sidecar: isolated, does no
  emulation, documented as the single exception.
- **Never a real vulnerable service.** Accept-all-auth grants access to a fake
  shell over a fake filesystem, not a real system. The fake redis/mysql never
  store or execute anything; the fake SMTP never actually sends mail (no open
  relay); the fake `wget` never fetches. Fakes are inert: example.com / RFC-2606
  domains, RFC-5737 (`192.0.2.0/24`) addresses, seeded dummy secrets.
- **Inert by default.** Like the HTTP `Config`, default to detect/log only
  (e.g. SSH Tier-1 banner and auth logging, connection logging) and require an
  explicit opt-in to serve interactive fakes (full shell, fake result sets).
- **Bounded everything.** No response, session, buffer, or connection count is
  unbounded. A bound that is easy to author-around is a compiler lint, not a
  runtime hope.

---

## 7. Phased build order

- **Phase 0: listener runtime and compiler.** Generic `bin/funnypot-listen`
  (select loop, connection/buffer/timeout caps, protocol dispatch); the
  `templates/protocol/*.yaml` to `resources/compiled/funnypot-protocols.php`
  compiler with the safety lints; wire into `hits.log`/`Observer`. Ship with one
  trivial protocol (generic TCP banner) end-to-end.
- **Phase 1: plaintext protocols as pure data.** redis (with the shared `resp`
  codec), telnet banner, FTP, SMTP, memcached. Proves "new protocol = new
  template, zero new PHP." Add SSH Tier-1 banner and logging here (it's just a
  `banner:` template).
- **Phase 2: shared shell layer.** Fake filesystem, command table, accept-all
  auth, session logging, driven over Telnet (pure PHP, fully in-model). This
  is the big content phase.
- **Phase 3: interactive SSH.** Go `gliderlabs/ssh` sidecar terminating the
  crypto and forwarding the command stream to the Phase-2 shell layer over a unix
  socket. No PHP crypto.
- **Phase 4: binary codec protocols.** MySQL handshake/auth (codec and template),
  optionally MSSQL. TLS/RDP/SMB explicitly out.
- **Phase 5: packaging and dashboard.** Process supervisor, docker ports,
  dashboard columns for `proto`/session/credentials, docs, `scripts/deploy.sh`
  port sync.

---

## 8. Hardest parts / risks

- **SSH transport is the genuine hard part.** No PHP server lib exists; hand-
  rolling crypto is rejected. The plan's answer (banner-only in PHP plus a sidecar
  for the shell) is sound, but the sidecar is a real dependency and the one break
  in the PHP-only invariant. Risk: the sidecar becomes the weakest link; keep it
  thin (transport only) and pin the library.
- **Select-loop correctness.** Partial reads, per-connection state machines,
  backpressure, and above all never blocking the whole loop on one slow or
  hostile client (a slowloris against the event loop). Everything must be
  non-blocking with per-connection read caps and deadlines. This risk is the
  strongest argument for process-per-protocol (a wedged handler kills one
  process, not all).
- **Binary framing (MySQL).** Sequence numbers, capability flags, and auth-plugin
  handshakes are easy to get subtly wrong and are highly fingerprintable. Scope
  it tightly; a wrong flag is a honeypot tell.
- **Anti-fingerprinting has a ceiling.** Honeypots are detectable via tiny
  protocol deviations, wrong error text, and timing. Templating narrows the gap
  and the seeded per-attacker fakes and latency jitter (already in `Config`) help,
  but be honest: this fools scanners and automated brute-forcers, not a
  determined human auditing the service.
- **Resource exhaustion / self-DoS.** Long-lived TCP connections are a DoS
  surface the stateless HTTP engine never had. Connection caps, per-IP caps,
  buffer caps, and session timeouts are mandatory, not optional.
- **Privileged / colliding ports.** Real service ports (`22/21/23/25`) need
  privilege or mapping; `22` collides with host sshd. Use high ports mapped in
  docker; never bind the container to the host's own service ports.
- **Accidentally becoming useful to the attacker.** The sharpest safety risk: a
  fake SMTP that actually relays mail, a fake redis usable as a real SSRF/cache
  pivot, a fake `wget` that fetches. Every emulation must be provably inert:
  store nothing, forward nothing, fetch nothing, execute nothing. This is the
  invariant the whole design defends.

---

## 9. Open decisions for Bob

1. **Runtime composer deps: acceptable or not?** The recommendation keeps the
   listener zero-dep (raw select loop). If you'd rather buy concurrency and
   cleaner code with a *pure-PHP* dep, ReactPHP is the drop-in. Trade: code you
   maintain vs a runtime dep on the honeypot's own binary.
2. **The SSH sidecar (Go/Python): in or out?** It's the only non-PHP piece.
   Options: (a) accept it for interactive SSH, (b) ship SSH as banner-only
   forever and never do the interactive shell over SSH (telnet-only shell), or
   (c) defer the decision, since Phases 0-2 don't need it.
3. **How far into binary protocols?** MySQL is doable but fiddly and
   fingerprintable. Worth Phase 4, or stop at plaintext and shell?
4. **Process supervisor choice** for the container: `s6-overlay`, `supervisord`,
   or a hand-rolled entrypoint `wait` loop.
5. **New composer package vs folded into funnypot core.** The listener/codecs/
   shell could live in `src/Protocol/*` in the same package, or split into a
   companion package so HTTP-only consumers don't carry the TCP engine.
   **Decided: same package** (`src/Protocol/*`), ReactPHP in `suggest` (listener-only).

---

## 10. Future inputs

- **nuclei `network/` templates.** Once we own TCP listeners, invert nuclei's *network*
  templates the same way the HTTP engine inverts `http/`. They carry per-service
  banner/response signatures (redis, mysql, ftp, telnet, memcached, mongodb, and so on)
  and read matched inbound bytes to the expected reply. A large ready-made corpus for the
  protocol-template compiler; wire it into the same invert pipeline (matcher to witness to
  canned response).
- **greenbone/openvas-scanner (GVM).** Mine its NASL service-detection VTs for protocol probes,
  banners, and default-cred/version fingerprints to seed protocol templates and the shell layer's
  command outputs. Licensing: GPL. Take ideas/signatures, re-author, don't ingest code verbatim.
