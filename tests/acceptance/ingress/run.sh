#!/usr/bin/env bash
# CI/operator only. No published ports, deployment secrets, Docker socket mount or network at runtime.
set -euo pipefail
cd "$(dirname "$0")/../../.."
command -v timeout >/dev/null
command -v docker >/dev/null
task_id="fp-ingress-${GITHUB_RUN_ID:-local}-$$"
image="$task_id"
out="$PWD/ingress-evidence"
if [[ -e "$out" ]]; then
    echo 'ingress-evidence already exists; preserve it and use a fresh checkout.' >&2
    exit 2
fi
mkdir -m 0700 "$out"
cleanup() {
    timeout 15 docker rm -f "$task_id" >/dev/null 2>&1 || true
    timeout 15 docker image rm "$image" >/dev/null 2>&1 || true
}
trap cleanup EXIT
timeout 900 docker build -f demo/Dockerfile -t "$image" . >"$out/build.log" 2>&1
timeout --signal=TERM --kill-after=10 240 docker run --name "$task_id" \
    --network none --read-only --cpus 2 --memory 1g --pids-limit 64 \
    --security-opt no-new-privileges --cap-drop ALL \
    --cap-add CHOWN --cap-add SETUID --cap-add SETGID --cap-add KILL --cap-add NET_BIND_SERVICE \
    --tmpfs /tmp:rw,nosuid,nodev,size=64m \
    --tmpfs /run:rw,nosuid,nodev,size=16m \
    --tmpfs /var/lib/nginx:rw,nosuid,nodev,size=16m \
    --tmpfs /var/log/nginx:rw,nosuid,nodev,size=16m \
    --tmpfs /var/acme:rw,nosuid,nodev,size=8m \
    --tmpfs /etc/nginx/http.d:rw,nosuid,nodev,size=1m \
    --tmpfs /etc/letsencrypt:rw,nosuid,nodev,size=1m \
    --tmpfs /app/demo/storage:rw,nosuid,nodev,size=64m \
    --mount "type=bind,src=$PWD/tests/acceptance/ingress,dst=/acceptance,readonly" \
    --mount "type=bind,src=$out,dst=/evidence" \
    --entrypoint /bin/sh "$image" /acceptance/container.sh >"$out/container.log" 2>&1
test -s "$out/receipt.json"
