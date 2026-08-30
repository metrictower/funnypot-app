#!/usr/bin/env bash
#
# Post-deploy availability canary for the HTTP deception surface.
#
# The whole deception can silently dark-404 (a Config/wiring fatal → every decoy/panel/attack path
# 404s while only static routes survive), and a quiet honeypot looks identical to a healthy one. This
# script curls a representative slice of that surface on the LIVE box, with the real Host header, and
# EXITS NON-ZERO (naming the paths) if any comes back 404, 5xx, or unreachable — turning a dark engine
# into a loud, immediate signal. The in-suite regression test (tests/App/PanelDecoyAvailabilityTest)
# is the same check at build time; this is the same check against the deployed container.
#
# Standalone:   bash scripts/canary.sh [--host ADDR] [--name HOSTNAME] [--scheme http|https] [--port N]
# From deploy:  scripts/deploy.sh runs it after the container (re)start (warn-by-default; gate with
#               FUNNYPOT_CANARY_STRICT=1).
#
# Connection details come from scripts/deploy.env (gitignored) — sourced the same way deploy.sh does,
# so no secrets are duplicated or echoed here. Only the non-secret host/name are read.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -f "$SCRIPT_DIR/deploy.env" ]; then
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/deploy.env"
fi

# --- resolve target from flags → env → deploy.env, in that order ---------------------------------
# TARGET_HOST: the address curl connects to (the deploy box).       Default: FUNNYPOT_HOST.
# NAME:        the Host: header + SNI (the real hostname the app sees). Default: LE_DOMAIN else host.
# SCHEME/PORT: transport.                                            Default: https / 443.
TARGET_HOST="${FUNNYPOT_CANARY_HOST:-${FUNNYPOT_HOST:-}}"
NAME="${FUNNYPOT_CANARY_NAME:-${LE_DOMAIN:-}}"
SCHEME="${FUNNYPOT_CANARY_SCHEME:-https}"
PORT="${FUNNYPOT_CANARY_PORT:-}"

# This script always exits non-zero when any path dark-404s; whether that ABORTS a deploy is the
# caller's call (deploy.sh warns by default and gates only under FUNNYPOT_CANARY_STRICT=1).
while [ "$#" -gt 0 ]; do
    case "$1" in
        --host) TARGET_HOST="$2"; shift 2 ;;
        --name) NAME="$2"; shift 2 ;;
        --scheme) SCHEME="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        -h|--help)
            grep '^# ' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "canary: unknown argument '$1'" >&2; exit 2 ;;
    esac
done

if [ -z "$TARGET_HOST" ]; then
    echo "canary: no target host — set FUNNYPOT_HOST in scripts/deploy.env or pass --host ADDR." >&2
    exit 3
fi
# Host header falls back to the connect address when no distinct public hostname is configured.
[ -n "$NAME" ] || NAME="$TARGET_HOST"
if [ -z "$PORT" ]; then
    case "$SCHEME" in https) PORT=443 ;; *) PORT=80 ;; esac
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "canary: curl is required." >&2
    exit 3
fi

# Representative decoy / panel / attack paths — MUST mirror tests/App/PanelDecoyAvailabilityTest so
# the build-time and post-deploy checks cover the same surface. Both slash variants where relevant.
PATHS="
/.env
/.git/config
/phpinfo.php
/phpmyadmin
/phpmyadmin/
/admin
/admin/
/grafana/login
/wp-login.php
/index.php?page=../../../../etc/passwd
"

echo "==> canary: probing $SCHEME://$NAME (via $TARGET_HOST:$PORT) — deception must serve non-404"

# Readiness wait: a just-recreated container needs a moment for nginx/php-fpm to accept connections.
# Poll the base URL until it answers with any HTTP status (not a 000 connection error) before probing,
# so a slow start is not mistaken for a dark engine. Bounded; if it never comes up the probes below
# report the failure honestly.
tries="${FUNNYPOT_CANARY_WAIT_TRIES:-10}"
i=0
while [ "$i" -lt "$tries" ]; do
    ready="$(curl -sS -k --max-time 5 \
        --connect-to "$NAME:$PORT:$TARGET_HOST:$PORT" \
        -o /dev/null -w '%{http_code}' \
        "$SCHEME://$NAME:$PORT/" 2>/dev/null || true)"
    [ -n "$ready" ] && [ "$ready" != "000" ] && break
    i=$((i + 1))
    sleep 2
done

failed=""
n=0
set -f  # no pathname expansion — PATHS are literal request paths (esp. the LFI's ../ and ?)
for path in $PATHS; do
    [ -n "$path" ] || continue
    n=$((n + 1))
    # -k: the box serves a self-signed cert for non-LE hosts (SNI split); we assert availability, not
    #     the cert. --path-as-is: keep the LFI probe's ../ sequences intact (curl would squash them).
    # --connect-to: connect to the deploy box while presenting Host+SNI = the real hostname; works
    #     whether TARGET_HOST is an IP or a name (unlike --resolve).
    code="$(curl -sS -k --path-as-is --max-time 15 \
        --connect-to "$NAME:$PORT:$TARGET_HOST:$PORT" \
        -o /dev/null -w '%{http_code}' \
        "$SCHEME://$NAME:$PORT$path" 2>/dev/null || true)"
    [ -n "$code" ] || code="000"

    # Served == any real response that is not a 404 and not a 5xx tell. 000 == connection error.
    if [ "$code" = "000" ] || [ "$code" = "404" ] || [ "$code" -ge 500 ] 2>/dev/null; then
        printf '  FAIL  %-40s -> %s\n' "$path" "$code"
        failed="$failed $path($code)"
    else
        printf '  ok    %-40s -> %s\n' "$path" "$code"
    fi
done
set +f

if [ -n "$failed" ]; then
    echo "==> CANARY FAIL: the deception dark-404'd (or was unreachable) on:$failed"
    echo "    The HTTP engine may be down (a Config/wiring fatal degrades every path to 404)."
    exit 1
fi

echo "==> CANARY PASS: all $n deception paths served non-404 on $NAME"
exit 0
