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

if [ -f "$SCRIPT_DIR/deploy.env" ]; then
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
# for this host once a cert exists. Empty = self-signed everywhere (unchanged behaviour).
LE_DOMAIN="${LE_DOMAIN:-}"
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
# Known HTTP + alt-HTTP + app/panel ports (nginx) plus the TCP protocol-honeypot ports (mail/cache/
# shell + databases + SCADA — see demo/entrypoint.sh). Keep in sync with demo/entrypoint.sh +
# demo/Dockerfile and open the matching inbound rules in the EC2 security group (the SG gates reachability).
PORTS="21 23 25 79 80 81 88 110 143 443 445 502 591 873 2082 2083 2086 2087 2095 2096 2181 2222 2375 3000 3128 3306 3310 3389 4243 4433 4443 5000 5060 5432 5555 5601 5900 5984 6379 7001 7070 7080 7474 8000 8001 8008 8009 8065 8069 8080 8081 8082 8083 8086 8088 8090 8161 8180 8181 8200 8443 8500 8834 8843 8880 8888 8983 9000 9080 9090 9100 9200 9443 10000 10443 11211 15672 27017 44818"

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
PFLAGS=""
for p in $PORTS; do PFLAGS="$PFLAGS -p $p:$p"; done
PFLAGS="$PFLAGS -p 5060:5060/udp"
# SIP media (RTP) is UDP on the fixed port; publish it so inbound caller audio + DTMF reach the box.
PFLAGS="$PFLAGS -p ${FUNNYPOT_SIP_RTP_PORT:-10000}:${FUNNYPOT_SIP_RTP_PORT:-10000}/udp"
# Serve the SSH honeypot on the real port 22 (host 22 -> container's ssh listener on 2222).
# Requires the host's own sshd to have vacated 22 first (scripts/move-sshd-port.sh) and
# FUNNYPOT_SSH_PORT set to the moved sshd port above.
if [ "${FUNNYPOT_SSH_ON_22:-0}" = "1" ]; then PFLAGS="$PFLAGS -p 22:2222"; fi
# Extra VNC scan ports all forward to the ONE container VNC listener on 5900 (a single process
# serves them — no per-port listener). DNAT rewrites the dest to 5900, so alt-port hits log as
# 5900. Open these in the security group too, or they are unreachable. Empty to disable.
for vp in ${FUNNYPOT_VNC_ALT_PORTS:-5901 5902 5800}; do PFLAGS="$PFLAGS -p $vp:5900"; done
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
    FUNNYPOT_LLM_FLAGS="$FUNNYPOT_LLM_FLAGS -e FUNNYPOT_LLM_GATE_ALLOW=${FUNNYPOT_LLM_GATE_ALLOW:-} -e FUNNYPOT_LLM_VELOCITY_PER_60S=${FUNNYPOT_LLM_VELOCITY_PER_60S:-30} -e FUNNYPOT_LLM_VELOCITY_PER_10M=${FUNNYPOT_LLM_VELOCITY_PER_10M:-100}"
    LLM_SETUP="sudo docker network inspect $LLM_NET >/dev/null 2>&1 || sudo docker network create $LLM_NET ; sudo docker rm -f funnypot-llm 2>/dev/null || true ; sudo docker run -d --name funnypot-llm --restart unless-stopped --network $LLM_NET -m $LLM_MEM --memory-swap $LLM_MEM_SWAP -e THREADS=$LLM_THREADS -e PARALLEL=$LLM_PARALLEL -e CTX_SIZE=2048 funnypot-llm"
fi

# Fake AI-API chat tier (Ollama/OpenAI/Anthropic). On by default; reuses the sidecar via
# FUNNYPOT_LLM_URL when LLM_ON=1, else streams the static nonsense fallback. Chat sampling is
# independent of the HTML page-gen LLM temperature; strict auth/model are opt-in (default: serve
# every request to maximise engagement).
FUNNYPOT_AI_FLAGS="-e FUNNYPOT_AI_API=${FUNNYPOT_AI_API:-1} -e FUNNYPOT_AI_TEMP=${FUNNYPOT_AI_TEMP:-0.8} -e FUNNYPOT_AI_MIN_P=${FUNNYPOT_AI_MIN_P:-0.0} -e FUNNYPOT_AI_TOP_P=${FUNNYPOT_AI_TOP_P:-1.0} -e FUNNYPOT_AI_STRICT_AUTH=${FUNNYPOT_AI_STRICT_AUTH:-} -e FUNNYPOT_AI_STRICT_MODEL=${FUNNYPOT_AI_STRICT_MODEL:-}"
# \$HOME etc. expand on the REMOTE; \$PFLAGS / \$LLM_SETUP / the LLM flags expand locally.
# shellcheck disable=SC2029
ssh "${SSH_OPTS[@]}" "$USER@$HOST" "
    DATA_DIR=\"\$HOME/funnypot-data\"
    ACME_DIR=\"\$HOME/funnypot-acme\"
    mkdir -p \"\$DATA_DIR\" && chmod 0777 \"\$DATA_DIR\"
    mkdir -p \"\$ACME_DIR/.well-known/acme-challenge\"
    sudo mkdir -p /etc/letsencrypt
    $LLM_SETUP
    sudo docker rm -f funnypot 2>/dev/null || true
    sudo docker run -d --name funnypot --restart unless-stopped $FUNNYPOT_NET_FLAG $FUNNYPOT_LLM_FLAGS $FUNNYPOT_AI_FLAGS \
        -e FUNNYPOT_EPOCH=$(date +%s) \
        -e FUNNYPOT_STYLE=${FUNNYPOT_STYLE:-realistic} \
        -e FUNNYPOT_VNC_STYLE='${FUNNYPOT_VNC_STYLE:-}' \
        -e FUNNYPOT_VNC_IMAGE='${FUNNYPOT_VNC_IMAGE:-}' \
        -e FUNNYPOT_VNC_CLIPBOARD='${FUNNYPOT_VNC_CLIPBOARD:-}' \
        -e FUNNYPOT_VNC_IDLE_TIMEOUT='${FUNNYPOT_VNC_IDLE_TIMEOUT:-}' \
        -e FUNNYPOT_SIP_STYLE='${FUNNYPOT_SIP_STYLE:-}' \
        -e FUNNYPOT_SIP_AUDIO_MODE='${FUNNYPOT_SIP_AUDIO_MODE:-auto}' \
        -e FUNNYPOT_SIP_AUTH_MODE='${FUNNYPOT_SIP_AUTH_MODE:-weak}' \
        -e FUNNYPOT_SIP_RTP_PORT='${FUNNYPOT_SIP_RTP_PORT:-10000}' \
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

echo "==> done. Test:  curl -I http://$HOST/   and   curl -Ik https://$HOST/"
echo "    Open the security group for the ports you want reachable (at least 80 + 443)."
