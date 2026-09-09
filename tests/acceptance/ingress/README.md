# HTTP input ceilings — real-image acceptance (FP-0132 Stage A)

CI/operator only: `bash tests/acceptance/ingress/run.sh` in a fresh Linux checkout with Docker and
GNU timeout. The manually dispatched `input-ceilings.yml` job runs exactly this command. Local
agents run only `InputCeilingConfigTest`, `EarlyIngressGuardTest`, `EarlyIngressBootstrapTest` and
the pure `IngressWireTest`, individually; they do **not** run this directory's entry scripts.

The job builds the production `demo/Dockerfile` (online dependency resolution), then runs that exact
image in one isolated container with network **none**, no published ports, a read-only root, bounded
tmpfs data, 2 CPUs / 1 GiB / 64 PIDs / 240 seconds, and only the capabilities needed by nginx/FPM's
root supervisors to bind and manage their own differently-owned children. The acceptance client
has an independent 180-second / 200-request / 8-MiB traffic budget and 8-second / 64-KiB per-response
limits. No deployment environment, host socket or real credential is mounted. Only identity
preparation, nginx, FPM and the fixed-loopback client run; protocol listeners, fetchers and report
drain workers never start. Cleanup addresses only this job's unique container/image names.

Production nginx config and its common server include are used unchanged. Identity preparation
renders the actual admin TLS vhost from a fixture-only certificate. A separate loopback-only
test vhost exercises a one-second **body** timeout to verify the static generic 408 mapping; it
does not alter production locations, and is not mislabeled as the partial-header timeout path.
FPM-only configuration adds fixed begin/end/class/body counters and target-free access logging;
the actual `demo/index.php` is not replaced. The direct FastCGI request exercises its early guard
in FPM, separately from nginx's authoritative raw-target rejection.

The matrix covers public/admin Host on HTTP/TLS, origin/authority-heavy absolute form, 4095/4096/4097
bytes, one/two/sixteen method spaces, real ACME token success/reject, encoded/double-encoded/NUL
octets, multibyte/invalid bytes in query, repeated separators, gross 12-KiB line/header rejections,
and partial line/header deadlines. Partial requests keep the client write side open: a zero-byte
server close after approximately five seconds is valid, not a missing 408 failure. An immediate
close or timeout beyond the finite 7.5-second tolerance fails.

Each live sink has its own accepted positive assertion before negative scans: hit row, raw row,
JSON-lines export, both local report queue rows, PHP stderr, PHP's configured error_log, FPM access
and the fixed instrumentation. The accepted request's test-only shutdown observer emits a fixed
error_log control; this is separate from the hit writer's php://stderr/FPM capture control.
All DB/WAL/SHM/export/log files are scanned under bounded directories. The queue controls use only
RFC-5737 fixture source addresses and synthetic placeholder strings, and can never be drained.
nginx request logs are deliberately disabled by production policy and are not falsely claimed to
have positive request controls; its `nginx -t` diagnostic has a separate positive assertion.

Evidence under `ingress-evidence/` records build/config/version logs and a receipt with every case's
status, body size, FPM delta and elapsed time. `receipt.json` only attests `container-checks-passed`:
after that container exits, a pure host-side checker requires separate stdout/stderr positive markers
and no reject marker in the captured `container.log`, rejecting missing/symlink/empty/oversized files.
Capture is file-size-limited while written; the checker is bounded to1MiB/five seconds. Only successful
post-exit verification writes `completion.json` with `status: passed`; both receipts and a successful
job are needed for acceptance. The actual installed nginx version is recorded, not
assumed from the floating production base. Any missing control, malformed/truncated reply, timeout,
overflow or sentinel leak fails the job. A failed receipt is never a green acceptance. Private test
identity files and SQLite contents are not copied into uploaded artifacts.

The server rewrite uses an internal-only 418, converted to the fixed 414 named response. Gross
parser 414s remain bounded nginx errors: they can occur with an empty parsed URI, which
[`ngx_http_named_location`](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_core_module.c)
explicitly rejects as a 500. Do not replace this with a blanket `error_page 414 = @...` redirect.
nginx's documented [`error_page`](https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page)
and [`keepalive_timeout`](https://nginx.org/en/docs/http/ngx_http_core_module.html#keepalive_timeout)
contracts underpin the mapping and single Connection header; the actual image matrix remains the
required verification, not source reading alone.

Stage A is not the whole FP-0132 delivery: core v0.7.0 publication, FP-0298 installed adoption,
Stage D classifier migration, full CI and operator app-main/deployment approval remain separate.
