#!/usr/bin/env bash
#
# Deploy funnypot to your test server by building the image locally and shipping it over
# SSH — the server needs only the docker engine (from its distro repos), no buildx,
# compose plugin, or GitHub. Repeatable: re-run to rebuild + redeploy.
#
#   scripts/deploy.sh
#
# Server details live in scripts/deploy.env (gitignored — copy deploy.env.example).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# FUNNYPOT_PRINT_PORTS=1 (scripts/check-ports.php): print the publish flags a bare deploy would use
# and exit before anything is sourced, validated, built or shipped. deploy.env is deliberately NOT
# read in this mode — the port manifest is checked against the script's own defaults; operator
# opt-ins are checked through their env var (e.g. FUNNYPOT_SSH_ON_22=1) by the same tool.
PRINT_PORTS="${FUNNYPOT_PRINT_PORTS:-0}"
if [ "$PRINT_PORTS" != "1" ] && [ -f "$SCRIPT_DIR/deploy.env" ]; then
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/deploy.env"
fi

HOST="${FUNNYPOT_HOST:-}"
USER="${FUNNYPOT_USER:-ec2-user}"
KEY="${FUNNYPOT_KEY:-}"
# EC2 is x86_64; build for that even on an Apple-Silicon Mac. Override if your box differs.
PLATFORM="${FUNNYPOT_PLATFORM:-linux/amd64}"
# Optional: hostname that gets a real Let's Encrypt cert (issued by scripts/letsencrypt.sh).
# When set, the container mounts the host cert store + ACME webroot and serves real HTTPS
# for this host once a cert exists. Empty = the per-install decoy cert everywhere.
LE_DOMAIN="${LE_DOMAIN:-}"
# Every hostname that will be interpolated into the remote command is validated HERE, before any
# ssh process exists: an injection-shaped value never reaches the server.
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib/dns-name.sh"
funnypot_require_dns_name_or_empty LE_DOMAIN "$LE_DOMAIN"
funnypot_require_dns_name_or_empty FUNNYPOT_CN "${FUNNYPOT_CN:-}"
funnypot_require_dns_name_or_empty FUNNYPOT_PUBLIC_DNS "${FUNNYPOT_PUBLIC_DNS:-}"
# Optional: a deploy-managed explicit install master. FUNNYPOT_INSTALL_SECRET_FILE is a path ON THE
# SERVER to a root-owned 0600 file holding the canonical one-line master (docs/IDENTITY.md); it is
# bind-mounted read-only into the preflight and the public container and named to the app by env.
# The master itself is never placed in the local, SSH or docker argv. Empty = the app creates and
# persists its own master on the data volume (the default).
INSTALL_SECRET_FILE="${FUNNYPOT_INSTALL_SECRET_FILE:-}"
if [ -n "$INSTALL_SECRET_FILE" ] && ! printf '%s' "$INSTALL_SECRET_FILE" | grep -Eq '^/[A-Za-z0-9._/-]+$'; then
    echo "error: FUNNYPOT_INSTALL_SECRET_FILE must be an absolute path of [A-Za-z0-9._/-] characters (it is placed in a remote command)." >&2
    exit 1
fi
IDENTITY_FLAGS=""
if [ -n "$INSTALL_SECRET_FILE" ]; then
    IDENTITY_FLAGS="-v $INSTALL_SECRET_FILE:/run/secrets/funnypot-install-secret:ro -e FUNNYPOT_INSTALL_SECRET_FILE=/run/secrets/funnypot-install-secret"
fi
IDENTITY_FLAGS="$IDENTITY_FLAGS -e FUNNYPOT_CN=${FUNNYPOT_CN:-} -e FUNNYPOT_PUBLIC_DNS=${FUNNYPOT_PUBLIC_DNS:-}"
# Dashboard admin password (Emulations toggles / prune / clear / geoip). Default empty under
# `set -u` so an unset value is not a fatal unbound-variable error; empty keeps admin disabled.
ADMIN_PASSWORD="${FUNNYPOT_ADMIN_PASSWORD:-}"

# LLM fake-response sidecar (funnypot-llm). ON by default, with the prod tuning baked in below — so a
# bare `bash scripts/deploy.sh` ships + wires the sidecar with no flags to remember. The model is
# memory/CPU-heavy, so it runs with a hard memory cap + a limited thread count, and funnypot degrades
# to a plain 404 whenever it is slow or down — the honeypot is never blocked on it. Set
# FUNNYPOT_LLM_ON=0 to skip the sidecar entirely; every value below is still overridable via its
# FUNNYPOT_LLM_* env var.
# FUNNYPOT_APP_ONLY=1: quick deploy of an app-code change — build + ship ONLY the ~40 MB app image
# and reuse the LLM sidecar image already on the host (its container is recreated from that on-box
# image, so the ~1 GB model is never rebuilt or re-sent). LLM stays enabled.
APP_ONLY="${FUNNYPOT_APP_ONLY:-0}"
LLM_ON="${FUNNYPOT_LLM_ON:-1}"
LLM_REPO="${FUNNYPOT_LLM_REPO:-$REPO_ROOT/../funnypot-llm}"
LLM_MEM="${FUNNYPOT_LLM_MEM:-1500m}"
LLM_MEM_SWAP="${FUNNYPOT_LLM_MEM_SWAP:-1800m}"
LLM_THREADS="${FUNNYPOT_LLM_THREADS:-2}"
LLM_PARALLEL="${FUNNYPOT_LLM_PARALLEL:-2}"
LLM_MAX_CONCURRENT="${FUNNYPOT_LLM_MAX_CONCURRENT:-1}"
LLM_TIMEOUT_MS="${FUNNYPOT_LLM_TIMEOUT_MS:-13000}"
LLM_NET="funnypot-net"

# Every host port docker publishes: the HTTP + alt-HTTP + app/panel ports (nginx) plus the TCP
# protocol-honeypot ports (mail/cache/shell + databases + SCADA — see demo/entrypoint.sh), then the
# UDP services and the alt-port forwards below. This is a VIEW of demo/ports.json — the one port
# inventory; `php scripts/check-ports.php` runs this script in print mode and fails on any drift
# between the two (and against nginx, the entrypoint, the Dockerfile and compose). The EC2 security
# group is what actually gates reachability: `php scripts/check-ports.php --print sg` lists what it
# must admit.
PORTS="21 23 25 79 80 81 88 102 110 143 389 443 445 502 554 591 873 1433 1521 1883 20000 2082 2083 2086 2087 2095 2096 2181 2222 2375 3000 3128 3306 3310 3389 4243 4433 4443 5000 5060 5432 5555 5601 5900 5984 5985 6379 7001 7070 7080 7474 7547 7548 8000 8001 8008 8009 8065 8069 8080 8081 8082 8083 8086 8088 8090 8161 8180 8181 8200 8443 8500 8834 8843 8880 8888 8983 9000 9042 9080 9090 9100 9200 9443 10000 10443 11211 15672 27017 44818"
PFLAGS=""
for p in $PORTS; do PFLAGS="$PFLAGS -p $p:$p"; done
PFLAGS="$PFLAGS -p 5060:5060/udp"
# SIP media (RTP) is UDP on the fixed port; publish it so inbound caller audio + DTMF reach the box.
PFLAGS="$PFLAGS -p ${FUNNYPOT_SIP_RTP_PORT:-10000}:${FUNNYPOT_SIP_RTP_PORT:-10000}/udp"
# SNMP agent is UDP on 161.
PFLAGS="$PFLAGS -p 161:161/udp"
# BACnet/IP is UDP on 47808.
PFLAGS="$PFLAGS -p 47808:47808/udp"
# STUN is UDP on 3478 (NAT-discovery decoy rounding out the VoIP footprint).
PFLAGS="$PFLAGS -p 3478:3478/udp"
# IPMI (BMC) is UDP on 623; CoAP (IoT) is UDP on 5683.
PFLAGS="$PFLAGS -p 623:623/udp -p 5683:5683/udp"
# NTP is UDP on 123 (TCP 1521 Oracle / 5985 WinRM / 9042 Cassandra ride the TCP PORTS list above).
PFLAGS="$PFLAGS -p 123:123/udp"
# Extra SIP discovery ports: publish common alt SIP ports to the single 5060 listener (wide-net
# decoy; plain SIP, not TLS). Mirrors the VNC alt-ports forwarding.
for sp in ${FUNNYPOT_SIP_ALT_PORTS:-5061 5080}; do PFLAGS="$PFLAGS -p $sp:5060 -p $sp:5060/udp"; done
# Serve the SSH honeypot on the real port 22 (host 22 -> container's ssh listener on 2222).
# Requires the host's own sshd to have vacated 22 first (scripts/move-sshd-port.sh) and
# FUNNYPOT_SSH_PORT set to the moved sshd port below.
if [ "${FUNNYPOT_SSH_ON_22:-0}" = "1" ]; then PFLAGS="$PFLAGS -p 22:2222"; fi
# Extra VNC scan ports all forward to the ONE container VNC listener on 5900 (a single process
# serves them — no per-port listener). DNAT rewrites the dest to 5900, so alt-port hits log as
# 5900. Open these in the security group too, or they are unreachable. Empty to disable.
for vp in ${FUNNYPOT_VNC_ALT_PORTS:-5901 5902 5800}; do PFLAGS="$PFLAGS -p $vp:5900"; done
if [ "$PRINT_PORTS" = "1" ]; then
    echo "$PFLAGS"
    exit 0
fi

# Bounded container logs on the host: stdout/stderr (hit JSON lines, listener respawn notices, PHP
# errors) rotate at 5 x 10 MiB instead of one json-file growing forever. The persisted hit store on
# the data volume is the record; this log is diagnostics. Applied to both containers.
LOG_FLAGS="--log-driver json-file --log-opt max-size=10m --log-opt max-file=5"

if [ -z "$HOST" ] || [ -z "$KEY" ]; then
    echo "error: FUNNYPOT_HOST and FUNNYPOT_KEY are not set." >&2
    echo "  cp scripts/deploy.env.example scripts/deploy.env  then edit it (it is gitignored)." >&2
    exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "error: local docker is required (this builds the image on your machine)." >&2
    echo "  install Docker Desktop, or wait for GitHub and use a server-side build." >&2
    exit 1
fi

# Port the host's real sshd listens on. Set FUNNYPOT_SSH_PORT once you've moved sshd off 22
# (scripts/move-sshd-port.sh) so the honeypot can take port 22 — otherwise deploy locks out.
SSH_PORT="${FUNNYPOT_SSH_PORT:-22}"
SSH_OPTS=(-i "$KEY" -p "$SSH_PORT" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20)

# --- deploy only a clean, committed state ------------------------------------------------------
# The build below packages the working tree, so ANY uncommitted change silently ships to prod. A
# shared checkout worked by several sessions makes stray edits the norm, not the exception, and one
# such uncommitted change (an engine Config opt-in the live core did not support) once dark-404'd the
# whole HTTP deception. Refuse a dirty tree: when the tree is clean the built image IS the committed
# ref (HEAD), so the deployed bytes are always something in git history. Override with
# FUNNYPOT_ALLOW_DIRTY=1 for a deliberate throwaway/debug build.
#
# Fail CLOSED: this app repo is a checkout nested inside the umbrella funnypot-project repo, so a
# `rev-parse` that walks up (e.g. if this repo's .git is missing) would find the ENCLOSING repo —
# which gitignores the app dir — and wrongly report a clean tree. Only trust the check when the git
# toplevel is physically THIS repo; otherwise we cannot verify, so require the explicit override.
ALLOW_DIRTY="${FUNNYPOT_ALLOW_DIRTY:-0}"
REPO_CANON="$(cd "$REPO_ROOT" && pwd -P)"
GIT_TOP="$(git -C "$REPO_ROOT" rev-parse --show-toplevel 2>/dev/null || true)"
GIT_TOP_CANON="$([ -n "$GIT_TOP" ] && cd "$GIT_TOP" 2>/dev/null && pwd -P || true)"
if command -v git >/dev/null 2>&1 && [ -n "$GIT_TOP_CANON" ] && [ "$GIT_TOP_CANON" = "$REPO_CANON" ]; then
    DIRTY="$(git -C "$REPO_ROOT" status --porcelain)"
    if [ -n "$DIRTY" ]; then
        if [ "$ALLOW_DIRTY" = "1" ]; then
            echo "==> WARNING: working tree is dirty but FUNNYPOT_ALLOW_DIRTY=1 — shipping uncommitted changes:" >&2
            printf '%s\n' "$DIRTY" | sed 's/^/      /' >&2
        else
            echo "error: refusing to deploy a dirty working tree — uncommitted changes would silently ship to prod." >&2
            echo "       commit or stash these first, or set FUNNYPOT_ALLOW_DIRTY=1 to override:" >&2
            printf '%s\n' "$DIRTY" | sed 's/^/      /' >&2
            exit 1
        fi
    else
        REF="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo '?')"
        echo "==> deploy source: clean tree at $REF (image == committed ref)"
    fi
elif [ "$ALLOW_DIRTY" = "1" ]; then
    echo "==> WARNING: cannot verify $REPO_ROOT is its own clean git checkout — proceeding on FUNNYPOT_ALLOW_DIRTY=1." >&2
else
    echo "error: $REPO_ROOT is not its own git checkout (no .git here, or git found an enclosing repo)." >&2
    echo "       cannot verify a clean deploy state — set FUNNYPOT_ALLOW_DIRTY=1 to deploy anyway." >&2
    exit 1
fi

echo "==> [1/4] build image locally ($PLATFORM)"
docker build --platform "$PLATFORM" -f "$REPO_ROOT/demo/Dockerfile" -t funnypot "$REPO_ROOT"

if [ "$LLM_ON" = "1" ] && [ "$APP_ONLY" != "1" ]; then
    echo "==> [1b/4] build funnypot-llm sidecar image ($PLATFORM) from $LLM_REPO"
    if [ ! -f "$LLM_REPO/Dockerfile" ]; then
        echo "error: funnypot-llm repo not found at $LLM_REPO (set FUNNYPOT_LLM_REPO)." >&2
        exit 1
    fi
    docker build --platform "$PLATFORM" -t funnypot-llm "$LLM_REPO"
elif [ "$APP_ONLY" = "1" ]; then
    echo "==> [1b/4] app-only deploy — skipping sidecar build (reusing the on-host image)"
fi

echo "==> [2/4] ensure docker engine on $USER@$HOST"
ssh "${SSH_OPTS[@]}" "$USER@$HOST" 'bash -s' <<'REMOTE'
set -e
if ! command -v docker >/dev/null 2>&1; then
    echo "  installing docker..."
    if command -v dnf >/dev/null 2>&1; then sudo dnf install -y docker; else sudo yum install -y docker; fi
    sudo systemctl enable --now docker
fi
sudo systemctl start docker 2>/dev/null || true
REMOTE

# FUNNYPOT_SKIP_SHIP=1 reuses images already loaded on the host (e.g. after a load that succeeded but
# a later step failed) — it re-runs only the container (re)start, without the slow image transfer.
if [ "${FUNNYPOT_SKIP_SHIP:-0}" = "1" ]; then
    echo "==> [3/4] skip ship (FUNNYPOT_SKIP_SHIP=1) — using images already on the host"
else
    echo "==> [3/4] ship image (~40 MB gzipped) + load on server"
    docker save funnypot | gzip | ssh "${SSH_OPTS[@]}" "$USER@$HOST" 'gunzip | sudo docker load'

    if [ "$LLM_ON" = "1" ] && [ "$APP_ONLY" != "1" ]; then
        echo "==> [3b/4] ship funnypot-llm image (model baked in — larger; only re-sent when it changes)"
        docker save funnypot-llm | gzip | ssh "${SSH_OPTS[@]}" "$USER@$HOST" 'gunzip | sudo docker load'
    elif [ "$APP_ONLY" = "1" ]; then
        echo "==> [3b/4] app-only deploy — skipping sidecar ship (~1 GB not re-sent)"
    fi
fi

echo "==> [4/4] (re)start container (logs persisted to ~/funnypot-data on the host)"
# LLM sidecar: network + run commands (single line, ';'-separated to keep the remote quoting simple).
# All three vars are empty when LLM_ON=0, so the funnypot run below is byte-identical to before. The
# memory cap means the kernel OOM-kills the SIDECAR, never the honeypot, if the model overruns.
LLM_SETUP=""
FUNNYPOT_NET_FLAG=""
FUNNYPOT_LLM_FLAGS=""
if [ "$LLM_ON" = "1" ]; then
    FUNNYPOT_NET_FLAG="--network $LLM_NET"
    FUNNYPOT_LLM_FLAGS="-e FUNNYPOT_LLM=1 -e FUNNYPOT_LLM_URL=http://funnypot-llm:8080/completion -e FUNNYPOT_LLM_MAX_CONCURRENT=$LLM_MAX_CONCURRENT -e FUNNYPOT_LLM_TIMEOUT_MS=$LLM_TIMEOUT_MS"
    # Operator testing knobs (empty = app defaults 5/15, no allowlist): raise the per-IP velocity gate
    # or exempt a test IP/CIDR so it can generate unlimited fakes without self-pinning to plain-404.
    # The global generations/hour budget is the rotating-IP backstop behind that per-IP gate.
    FUNNYPOT_LLM_FLAGS="$FUNNYPOT_LLM_FLAGS -e FUNNYPOT_LLM_GATE_ALLOW=${FUNNYPOT_LLM_GATE_ALLOW:-} -e FUNNYPOT_LLM_VELOCITY_PER_60S=${FUNNYPOT_LLM_VELOCITY_PER_60S:-30} -e FUNNYPOT_LLM_VELOCITY_PER_10M=${FUNNYPOT_LLM_VELOCITY_PER_10M:-100} -e FUNNYPOT_LLM_GENS_PER_HOUR=${FUNNYPOT_LLM_GENS_PER_HOUR:-60}"
    LLM_SETUP="sudo docker network inspect $LLM_NET >/dev/null 2>&1 || sudo docker network create $LLM_NET ; sudo docker rm -f funnypot-llm 2>/dev/null || true ; sudo docker run -d --name funnypot-llm --restart unless-stopped $LOG_FLAGS --network $LLM_NET -m $LLM_MEM --memory-swap $LLM_MEM_SWAP -e THREADS=$LLM_THREADS -e PARALLEL=$LLM_PARALLEL -e CTX_SIZE=2048 funnypot-llm"
fi

# Fake AI-API chat tier (Ollama/OpenAI/Anthropic). On by default; reuses the sidecar via
# FUNNYPOT_LLM_URL when LLM_ON=1, else streams the static nonsense fallback. Chat sampling is
# independent of the HTML page-gen LLM temperature; strict auth/model are opt-in (default: serve
# every request to maximise engagement).
FUNNYPOT_AI_FLAGS="-e FUNNYPOT_AI_API=${FUNNYPOT_AI_API:-1} -e FUNNYPOT_AI_TEMP=${FUNNYPOT_AI_TEMP:-0.8} -e FUNNYPOT_AI_MIN_P=${FUNNYPOT_AI_MIN_P:-0.0} -e FUNNYPOT_AI_TOP_P=${FUNNYPOT_AI_TOP_P:-1.0} -e FUNNYPOT_AI_STRICT_AUTH=${FUNNYPOT_AI_STRICT_AUTH:-} -e FUNNYPOT_AI_STRICT_MODEL=${FUNNYPOT_AI_STRICT_MODEL:-}"
# \$HOME etc. expand on the REMOTE; \$PFLAGS / \$LLM_SETUP / the LLM flags expand locally.
# `set -e` on the remote: the identity preflight below is the gate — if it fails, the public
# container is neither removed nor replaced, and no later line runs.
# shellcheck disable=SC2029
ssh "${SSH_OPTS[@]}" "$USER@$HOST" "
    set -e
    DATA_DIR=\"\$HOME/funnypot-data\"
    ACME_DIR=\"\$HOME/funnypot-acme\"
    mkdir -p \"\$DATA_DIR\" && chmod 0777 \"\$DATA_DIR\"
    mkdir -p \"\$ACME_DIR/.well-known/acme-challenge\"
    sudo mkdir -p /etc/letsencrypt
    $LLM_SETUP
    echo '==> identity preflight (built image, real data volume, no network, no ports)'
    sudo docker run --rm --network none $IDENTITY_FLAGS \
        -e FUNNYPOT_LE_DOMAIN='$LE_DOMAIN' \
        -v \"\$DATA_DIR\":/app/demo/storage \
        -v /etc/letsencrypt:/etc/letsencrypt:ro \
        --entrypoint php funnypot /app/bin/funnypot identity:prepare
    sudo docker rm -f funnypot 2>/dev/null || true
    sudo docker run -d --name funnypot --restart unless-stopped $LOG_FLAGS $FUNNYPOT_NET_FLAG $FUNNYPOT_LLM_FLAGS $FUNNYPOT_AI_FLAGS $IDENTITY_FLAGS \
        -e FUNNYPOT_EPOCH=$(date +%s) \
        -e FUNNYPOT_STYLE=${FUNNYPOT_STYLE:-realistic} \
        -e FUNNYPOT_VNC_STYLE='${FUNNYPOT_VNC_STYLE:-}' \
        -e FUNNYPOT_VNC_IMAGE='${FUNNYPOT_VNC_IMAGE:-}' \
        -e FUNNYPOT_VNC_CLIPBOARD='${FUNNYPOT_VNC_CLIPBOARD:-}' \
        -e FUNNYPOT_VNC_IDLE_TIMEOUT='${FUNNYPOT_VNC_IDLE_TIMEOUT:-}' \
        -e FUNNYPOT_SIP_STYLE='${FUNNYPOT_SIP_STYLE:-}' \
        -e FUNNYPOT_SIP_AUDIO_MODE='${FUNNYPOT_SIP_AUDIO_MODE:-auto}' \
        -e FUNNYPOT_SIP_AUTH_MODE='${FUNNYPOT_SIP_AUTH_MODE:-permissive}' \
        -e FUNNYPOT_SIP_RTP_PORT='${FUNNYPOT_SIP_RTP_PORT:-10000}' \
        -e FUNNYPOT_SIP_EXTENSION_MODE='${FUNNYPOT_SIP_EXTENSION_MODE:-org}' \
        -e FUNNYPOT_SIP_CALLS_BURST='${FUNNYPOT_SIP_CALLS_BURST:-30}' \
        -e FUNNYPOT_SIP_CALLS_PER_SEC='${FUNNYPOT_SIP_CALLS_PER_SEC:-0.1}' \
        -e FUNNYPOT_LE_DOMAIN='$LE_DOMAIN' \
        -e FUNNYPOT_ADMIN_PASSWORD='$ADMIN_PASSWORD' \
        -e FUNNYPOT_MODE='${FUNNYPOT_MODE:-}' \
        -e FUNNYPOT_PUBLIC_IP='${FUNNYPOT_PUBLIC_IP:-}' \
        -e FUNNYPOT_CAPTURE_RAW='${FUNNYPOT_CAPTURE_RAW:-}' \
        -e FUNNYPOT_BLOCKLIST='${FUNNYPOT_BLOCKLIST:-}' \
        -e FUNNYPOT_ABUSEIPDB_KEY='${FUNNYPOT_ABUSEIPDB_KEY:-}' \
        -e FUNNYPOT_ABUSEIPDB_REPORT='${FUNNYPOT_ABUSEIPDB_REPORT:-}' \
        -e FUNNYPOT_THREATINTEL_REPORT='${FUNNYPOT_THREATINTEL_REPORT:-}' \
        -e FUNNYPOT_THREATINTEL_URL='${FUNNYPOT_THREATINTEL_URL:-}' \
        -e FUNNYPOT_THREATINTEL_KEY='${FUNNYPOT_THREATINTEL_KEY:-}' \
        -e FUNNYPOT_SELF_IPS='${FUNNYPOT_SELF_IPS:-}' \
        -e FUNNYPOT_RETAIN_DAYS='${FUNNYPOT_RETAIN_DAYS:-}' \
        -e FUNNYPOT_RETAIN_GB='${FUNNYPOT_RETAIN_GB:-}' \
        -v \"\$DATA_DIR\":/app/demo/storage \
        -v \"\$ACME_DIR\":/var/acme:ro \
        -v /etc/letsencrypt:/etc/letsencrypt:ro \
        $PFLAGS funnypot
    sudo docker ps --filter name=funnypot --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | head -3
    echo \"  logs on host: \$DATA_DIR/hits.log\"
"

# Post-deploy availability canary: hit a representative slice of the HTTP deception on the live box
# (real Host header) and confirm nothing dark-404'd. WARN-by-default so a canary miss never wedges a
# deploy; set FUNNYPOT_CANARY_STRICT=1 to abort on failure instead. Reuses the host/name already
# sourced above; canary.sh re-sources deploy.env itself, so no secrets are passed on the command line.
if [ "${FUNNYPOT_CANARY:-1}" != "0" ]; then
    echo "==> [canary] post-deploy deception availability check"
    if bash "$SCRIPT_DIR/canary.sh"; then
        :
    else
        if [ "${FUNNYPOT_CANARY_STRICT:-0}" = "1" ]; then
            echo "!!! canary FAILED and FUNNYPOT_CANARY_STRICT=1 — the deception is not fully serving. Aborting." >&2
            exit 1
        fi
        echo "!!! WARNING: post-deploy canary FAILED — the deception may be dark-404'ing. Investigate now." >&2
        echo "    (set FUNNYPOT_CANARY_STRICT=1 to make this abort the deploy.)" >&2
    fi
fi

echo "==> done. Test:  curl -I http://$HOST/   and   curl -Ik https://$HOST/"
echo "    Open the security group for the ports you want reachable (at least 80 + 443)."
