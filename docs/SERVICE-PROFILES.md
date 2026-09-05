# Service personas (FP-0310)

The operator chooses a believable, stable service persona at deployment startup and from the
authenticated admin panel. Canonical HTTP/HTTPS (80/443) always stay enabled; every non-web service
and extra web alias is profile-controlled and budgeted. A private per-deploy seed makes optional
choices stable for that deployment — never keyed by client IP, day, request order or scan order.

## Modes and bundles

`ServiceProfileInput` (a typed, closed vocabulary — no port number, bind, command or path) has three
modes:

- **named** — a coherent bundle (`bundle_id`). The bundle fixes the base family; its required members
  are always present and each optional slot picks at most one candidate by a stable deploy-seed HMAC
  ranking.
- **manual** — an exact `manual_service_ids` set plus an explicit `base_family`. Manual never silently
  opens a companion: a missing required companion is reported and apply is rejected until the operator
  adds it. An unusual mix outside the base family is a coherence *warning*, not a rejection.
- **all** — an explicit high-fingerprint lab escape hatch: every implemented safety-compatible service,
  with a required `conflict_variants` choice per declared conflict group and the complete exposure
  budget. It waives only soft family-coherence membership; it never waives capability, dependency,
  collision, process-ceiling, UDP or publication rules, and rejects a `max_exposure` below the resolved
  count rather than quietly becoming a subset.

Initial bundles (`resources/service-profiles.php`): `web-only` (canonical only, a fail-safe/migration
choice), `linux-web`, `windows-business` (SMB+RDP, no AD implied), `voip-pbx` (SIP + bounded RTP +
optional STUN), the OT sub-profiles `ot-modbus-plc` / `ot-siemens-plc` / `ot-building-controller` /
`ot-ethernet-ip` (each web + its PLC, optional compatible SNMP), and `devops-container` (SSH + the
Docker web surface, eligible only when the Docker feature is enabled). The semantic file carries no raw
ports: it joins to `demo/ports.json` (FP-0255's one port inventory) by stable endpoint ids, and
`ServiceCatalog` fails closed on any orphan.

The exposure budget counts externally observable non-canonical `(transport, host_port)` tuples after
forward closure — TCP+UDP on one number count twice, and each forwarded alias counts separately.
Inactive RTP is reported as a reserved media tuple and one media capability, not a permanent service.

## The three states

The feature never collapses these in UI copy or audit:

- **desired** — one validated `ServiceProfileInput` and its canonical resolved set (the PHP-writable
  `service-profile.sqlite`, `0660 root:www-data`, with `BEGIN IMMEDIATE` compare-and-set).
- **published** — the Docker/host `(transport, host_port, container_port)` mappings for the target.
  `published` never means a firewall/security group was verified (`external_reachability: unverified`).
- **effective** — the accepted set whose owning child is alive and whose probe passed, plus canonical
  web. Held root-only in `runtime.sqlite` (`0600 root:root`); PHP sees only a read-only status snapshot.

A runtime admin change writes only the desired profile. HTTP alias changes and any unpublished port are
`restart`/`redeploy`-required — PHP never hot-reloads nginx or opens a host port.

## First boot (B1)

`services:prepare` on an **empty** runtime store commits a bootstrap-accepted **effective revision 1 ==
desired revision 1** at preflight (before any listener runs) and writes the persistent exposure
manifest. The acceptance mode (`bootstrap` vs `health`) lives in the runtime store and heartbeat, never
in the hashed artifact, so the supervisor's first healthy convergence flips only the mode and rotates
nothing downstream. A first-boot probe failure stays `degraded` and retries under backoff — it never
appends a rollback revision (the loop guard compares sets, not revision numbers).

## Artifacts

- **`ServiceExposureManifest`** (`ServicePaths::PERSISTENT_MANIFEST`,
  `/app/demo/storage/.funnypot/services/exposure-manifest.json`, `0600 root:root`) — the **only**
  downstream binding source. It embeds the byte-exact nested `funnypot-effective-service-exposure/v1`
  artifact with a content-derived `generation` (32 hex) and `hash` (64 hex). Read it with
  `ServiceExposureManifest::fromPersistentFile()`, which applies the trusted-input reader rule
  (lstat regular / nlink 1 / owner ∈ {0, euid} / no group-or-other access → fopen → fstat equality →
  read → fstat) and self-verifies the plan and nested hashes.
- **`/run/funnypot-service-status/effective.json`** — the runtime health heartbeat
  (`funnypot-effective-service-status/v1`), rewritten at least every 5 s. It is health only and is
  **never** a binding source. The web role serves the last verified snapshot (APCu, else an in-process
  memo, else the family-neutral profile) and never varies an attacker-facing byte on its availability
  (a 5xx would be a tell). "Unhealthy" is surfaced only via the Docker `HEALTHCHECK` and the
  session-gated admin status.

`CanonicalJson::encode()/digest()` is the one hashed-artifact writer (sorted ASCII keys, no floats, one
trailing LF, domain-separated SHA-256); the golden bytes are authoritative.

## Identity

The resolver's optional-slot ranking uses `ServiceProfileIdentity::rankingKey()` — the scoped
`service-profile/v1` output published by FP-0313 as a `0640 root:www-data` runtime bundle. It is only
ever an HMAC key and is never stored in the desired database, audit or exposure manifest.

## Supervisor

`ServiceReconciler` computes the stop/start/keep plan (restarting common processes on a base-family
change); `ServiceSupervisor` drives first-boot convergence and live cutover through
`PcntlServiceProcessControl` (`pcntl_fork` / `posix_kill` / `pcntl_waitpid` — never exec/proc_open/shell;
PHP-FPM denies all of these in `demo/fpm-pool.conf`). It publishes the first `reconciling` heartbeat
before its first fork/probe, stops and reaps every removal before starting any addition (no simultaneous
old+new superset), and commits effective/LKG → rewrites the persistent manifest → publishes the
heartbeat, in that order, or restores LKG on failure. Between cutovers heartbeat health is child
liveness (`pcntl_waitpid` WNOHANG); real socket probes run only at cutover/first-boot/crash-recovery and
their loopback source is dropped at the listener log seam so they never reach the hit store.

## CLI

```bash
bin/funnypot bootstrap:prepare --target=deploy|compose --publish=flex|exact   # identity then service preflight (no network)
bin/funnypot services:prepare  --target=deploy|compose --publish=flex|exact   # service preflight only (--json prints the secret-free manifest)
bin/funnypot services:status   [--healthcheck | --wait-ready=<seconds> | --json]
```

## Status: implemented vs. remaining physical integration

Implemented and tested (host `composer test`): the whole resolution/manifest/identity/store/status/
admin/CLI/supervisor engine, the B1 fresh-install golden gate, and the B2 heartbeat-invariance gate.

The container/deploy **physical cutover** is the remaining operator-gated integration and is not yet
wired: replacing the entrypoint's unconditional spawn loop with `services:supervise` + the supervisor
watchdog, the manifest-driven `scripts/deploy.sh` / compose publication, the `nginx` alias-fragment
install, and the `HEALTHCHECK`. Those steps run only in the built container and are validated at deploy
time; the exposure-manifest contract above is stable for downstream tickets (FP-0319/FP-0317/FP-0107)
regardless.
