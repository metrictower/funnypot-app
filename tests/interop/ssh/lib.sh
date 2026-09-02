#!/usr/bin/env bash
# FP-0291 §2.7 — shared helpers for the SSH real-client interop harness. Sourced by run.sh.
# No app image is built: the listener runs on the runner's PHP; clients run in containers with
# --network host. Every helper is fail-loud (set -euo pipefail is expected in the caller).

# Per-run scratch: host key, hit log, SQLite store — all under $TMP so CI leaves no state behind.
TMP="${TMP:-$(mktemp -d)}"
LISTEN_HOST="127.0.0.1"
LISTEN_PORT="${LISTEN_PORT:-2222}"
LISTEN_ADDR="${LISTEN_HOST}:${LISTEN_PORT}"
LISTENER_PID=""

# start_listener: boot `php demo/listen.php ssh 127.0.0.1:2222` with an isolated store, and block until
# the banner is readable (which also asserts banner-only-before-the-client-reads).
start_listener() {
  local repo_root="$1"
  export FUNNYPOT_SSH_HOSTKEY="${TMP}/ssh_host_ed25519"
  export FUNNYPOT_APP_PATH="${TMP}"        # store dir → funnypot.sqlite / hits.log live under $TMP
  export FUNNYPOT_LOG="${TMP}/hits.log"
  export FUNNYPOT_DB="${TMP}/funnypot.sqlite"
  # No FUNNYPOT_VULNS file → EmulationPolicy default (service-ssh enabled). Belt: point it at a
  # nonexistent path so a stray repo vulns file can never disable the service in CI.
  export FUNNYPOT_VULNS="${TMP}/funnypot-vulns.json"

  php "${repo_root}/demo/listen.php" ssh "${LISTEN_ADDR}" &
  LISTENER_PID=$!

  local banner=""
  for _ in $(seq 1 50); do
    if ! kill -0 "${LISTENER_PID}" 2>/dev/null; then
      echo "listener exited during startup" >&2
      return 1
    fi
    banner="$(printf '' | nc -w1 "${LISTEN_HOST}" "${LISTEN_PORT}" 2>/dev/null | head -c 8 || true)"
    if [ "${banner}" = "SSH-2.0-" ]; then
      echo "listener up on ${LISTEN_ADDR} (banner: ${banner})"
      return 0
    fi
    sleep 0.2
  done
  echo "listener never presented an SSH-2.0- banner" >&2
  return 1
}

stop_listener() {
  if [ -n "${LISTENER_PID}" ] && kill -0 "${LISTENER_PID}" 2>/dev/null; then
    kill "${LISTENER_PID}" 2>/dev/null || true
    wait "${LISTENER_PID}" 2>/dev/null || true
  fi
}

# assert_uid: the given stdout must contain uid=0(root) — the fake shell's answer to `id`.
assert_uid() {
  local out="$1" label="$2"
  if printf '%s' "${out}" | grep -q 'uid=0(root)'; then
    echo "  ok: ${label} → uid=0(root)"
  else
    echo "  FAIL: ${label} did not yield uid=0(root); got: ${out}" >&2
    return 1
  fi
}

# assert_log: the hit log must contain a line matching the given extended-regex (a login / command event).
assert_log() {
  local pattern="$1" label="$2"
  if grep -Eq "${pattern}" "${TMP}/hits.log" 2>/dev/null; then
    echo "  ok: ${label} logged (/${pattern}/)"
  else
    echo "  FAIL: ${label} not found in hit log (/${pattern}/)" >&2
    return 1
  fi
}
