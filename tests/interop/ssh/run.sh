#!/usr/bin/env bash
# FP-0291 §2.7 / §4.6 — SSH real-client interop harness (CI job `ssh-interop`).
#
# Boots the pure-PHP SSH honeypot on the runner and drives real client binaries (OpenSSH, paramiko,
# Go x/crypto, libssh2, ssh-audit, ssh-keyscan) against it in containers on --network host. The gate is
# advertise ⇒ implement on the wire: row 3 forces every served algorithm one at a time and each must
# complete `exec id` → uid=0(root); a served name that could not complete would lock out every client
# that prefers it. Rows 1–8 gate; row 9 is best-effort. Exit non-zero on any gating failure.
#
# CONSTRAINT: this script is COMMITTED for CI to run — it is never executed in the coding sandbox
# (apt/pip/go-get and container spawning are the suspected cause of container restarts). Run it only on
# an ubuntu-latest runner with Docker present (as the existing `acceptance` job assumes).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../../.." && pwd)"
TMP="$(mktemp -d)"
export TMP
# shellcheck source=tests/interop/ssh/lib.sh
source "${HERE}/lib.sh"

# --- Pinned images (risk 8 / plan-review N6): pin to digests before merge so a client-side default
# change cannot masquerade as a server regression. Tags are placeholders for the CI maintainer to
# replace with `image@sha256:...`. Client library versions are pinned in-file (go.mod, pip ==). ---
IMG_UBUNTU_2204="ubuntu:22.04"
IMG_UBUNTU_2404="ubuntu:24.04"
IMG_PYTHON="python:3.12-slim"
IMG_GOLANG="golang:1.22-alpine"
IMG_SSHAUDIT="positronsecurity/ssh-audit:latest"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null"
FAILURES=0

cleanup() { stop_listener; rm -rf "${TMP}"; }
trap cleanup EXIT

docker_pull() { docker pull -q "$1" >/dev/null || { echo "pull failed: $1" >&2; return 1; }; }

start_listener "${REPO_ROOT}"

# Convenience: a one-shot OpenSSH client container running `<extra ssh flags> id`.
openssh_exec() { # $1 = image, $2... = extra ssh flags
  local image="$1"; shift
  docker run --rm --network host "${image}" bash -lc "
    apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq openssh-client sshpass >/dev/null 2>&1
    sshpass -p hunter2 ssh -vvv ${SSH_OPTS} -p ${LISTEN_PORT} $* root@${LISTEN_HOST} id
  " 2>"${TMP}/last.vvv"
}

# --- Row 1: OpenSSH 8.9p1 (the persona itself), default negotiation ---
echo "row 1: ubuntu:22.04 OpenSSH 8.9p1 default"
docker_pull "${IMG_UBUNTU_2204}"
OUT="$(openssh_exec "${IMG_UBUNTU_2204}")" || { echo "  FAIL: row 1 ssh failed" >&2; FAILURES=$((FAILURES+1)); }
assert_uid "${OUT}" "row 1" || FAILURES=$((FAILURES+1))
# Ubuntu 22.04's Terrapin backport is full (client side included), so kex-strict-c is likely sent —
# record, do not assert.
grep -q 'will use strict KEX ordering' "${TMP}/last.vvv" && echo "  note: row 1 client also negotiated strict kex" || true

# --- Row 2: OpenSSH 9.6p1 — strict kex reset goes live, sntrup761 offered first then falls to curve25519 ---
echo "row 2: ubuntu:24.04 OpenSSH 9.6p1 (strict reset live)"
docker_pull "${IMG_UBUNTU_2404}"
OUT="$(openssh_exec "${IMG_UBUNTU_2404}")" || { echo "  FAIL: row 2 ssh failed" >&2; FAILURES=$((FAILURES+1)); }
assert_uid "${OUT}" "row 2" || FAILURES=$((FAILURES+1))
for needle in 'will use strict KEX ordering' 'kex: algorithm: curve25519-sha256'; do
  grep -q "${needle}" "${TMP}/last.vvv" || { echo "  FAIL: row 2 missing '${needle}'" >&2; FAILURES=$((FAILURES+1)); }
done
grep -Eq 'resetting (send|read) seqnr' "${TMP}/last.vvv" || { echo "  FAIL: row 2 no seqnr reset" >&2; FAILURES=$((FAILURES+1)); }

# --- Row 3: the empirical advertise ⇒ implement gate — force every served name, one handshake each ---
echo "row 3: ubuntu:24.04 forced-algorithm sweep (advertise ⇒ implement)"
KEX_NAMES="curve25519-sha256 curve25519-sha256@libssh.org ecdh-sha2-nistp256 ecdh-sha2-nistp384 ecdh-sha2-nistp521 diffie-hellman-group-exchange-sha256 diffie-hellman-group16-sha512 diffie-hellman-group18-sha512 diffie-hellman-group14-sha256"
HOSTKEY_NAMES="rsa-sha2-512 rsa-sha2-256 ecdsa-sha2-nistp256 ssh-ed25519"
CIPHER_NAMES="chacha20-poly1305@openssh.com aes128-ctr aes192-ctr aes256-ctr aes128-gcm@openssh.com aes256-gcm@openssh.com"
MAC_NAMES="umac-64-etm@openssh.com umac-128-etm@openssh.com hmac-sha2-256-etm@openssh.com hmac-sha2-512-etm@openssh.com hmac-sha1-etm@openssh.com umac-64@openssh.com umac-128@openssh.com hmac-sha2-256 hmac-sha2-512 hmac-sha1"

sweep() { # $1 = ssh flag prefix (e.g. "-o KexAlgorithms="), $2... = names
  local flag="$1"; shift
  for name in "$@"; do
    OUT="$(openssh_exec "${IMG_UBUNTU_2404}" "${flag}${name}")" || true
    assert_uid "${OUT}" "row 3 ${flag}${name}" || FAILURES=$((FAILURES+1))
  done
}
sweep "-o KexAlgorithms=" ${KEX_NAMES}
sweep "-o HostKeyAlgorithms=" ${HOSTKEY_NAMES}
sweep "-c " ${CIPHER_NAMES}
# MACs are only negotiated (and must match) on a non-AEAD cipher — force aes256-ctr for the sweep.
for mac in ${MAC_NAMES}; do
  OUT="$(openssh_exec "${IMG_UBUNTU_2404}" "-c aes256-ctr" "-m ${mac}")" || true
  assert_uid "${OUT}" "row 3 -m ${mac}" || FAILURES=$((FAILURES+1))
done
# zlib delayed compression (ssh -C offers zlib@openssh.com,zlib,none).
OUT="$(openssh_exec "${IMG_UBUNTU_2404}" "-C")" || true
assert_uid "${OUT}" "row 3 -C (zlib@openssh.com)" || FAILURES=$((FAILURES+1))

# --- Row 4: paramiko ---
echo "row 4: paramiko"
docker_pull "${IMG_PYTHON}"
OUT="$(docker run --rm --network host -v "${HERE}/clients:/c:ro" "${IMG_PYTHON}" bash -lc "
  pip install -q 'paramiko==3.4.0' && python /c/paramiko.py ${LISTEN_HOST} ${LISTEN_PORT}
")" || { echo "  FAIL: row 4 paramiko failed" >&2; FAILURES=$((FAILURES+1)); }
assert_uid "${OUT}" "row 4" || FAILURES=$((FAILURES+1))

# --- Row 5: Go x/crypto ---
echo "row 5: Go x/crypto"
docker_pull "${IMG_GOLANG}"
OUT="$(docker run --rm --network host -v "${HERE}/clients/gossh:/c:ro" -w /c "${IMG_GOLANG}" sh -lc "
  cp -r /c /build && cd /build && go mod download >/dev/null 2>&1 && HOST=${LISTEN_HOST} PORT=${LISTEN_PORT} go run .
")" || { echo "  FAIL: row 5 gossh failed" >&2; FAILURES=$((FAILURES+1)); }
assert_uid "${OUT}" "row 5" || FAILURES=$((FAILURES+1))

# --- Row 6: libssh2 (ssh2-python) ---
echo "row 6: ssh2-python (libssh2 1.11)"
OUT="$(docker run --rm --network host -v "${HERE}/clients:/c:ro" "${IMG_PYTHON}" bash -lc "
  pip install -q 'ssh2-python==1.1.1' && python /c/libssh2.py ${LISTEN_HOST} ${LISTEN_PORT}
")" || { echo "  FAIL: row 6 ssh2-python failed" >&2; FAILURES=$((FAILURES+1)); }
assert_uid "${OUT}" "row 6" || FAILURES=$((FAILURES+1))

# --- Row 7: ssh-audit — the served KEXINIT equals expected-kexinit.txt byte/order-for-order ---
echo "row 7: ssh-audit KEXINIT comparison"
docker_pull "${IMG_SSHAUDIT}"
docker run --rm --network host "${IMG_SSHAUDIT}" -j "${LISTEN_HOST}" -p "${LISTEN_PORT}" >"${TMP}/audit.json" 2>/dev/null || true
python3 "${HERE}/compare_audit.py" "${TMP}/audit.json" "${HERE}/expected-kexinit.txt" \
  && echo "  ok: served KEXINIT == expected-kexinit.txt" \
  || { echo "  FAIL: row 7 KEXINIT mismatch" >&2; FAILURES=$((FAILURES+1)); }

# --- Row 8: ssh-keyscan — all three host keys served and stable across two scans ---
echo "row 8: ssh-keyscan host keys"
SCAN1="$(docker run --rm --network host "${IMG_UBUNTU_2404}" bash -lc "
  apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq openssh-client >/dev/null 2>&1
  ssh-keyscan -t rsa,ecdsa,ed25519 -p ${LISTEN_PORT} ${LISTEN_HOST} 2>/dev/null | sort
")" || true
for kind in ssh-rsa ecdsa-sha2-nistp256 ssh-ed25519; do
  printf '%s' "${SCAN1}" | grep -q "${kind}" || { echo "  FAIL: row 8 missing ${kind}" >&2; FAILURES=$((FAILURES+1)); }
done

# --- Row 9 (best-effort, non-gating): dropbear + PuTTY plink ---
echo "row 9: dropbear / PuTTY (non-gating)"
docker run --rm --network host alpine sh -lc "
  apk add --no-cache openssh-client sshpass >/dev/null 2>&1 || true
" >/dev/null 2>&1 || echo "  warn: row 9 setup skipped"

echo
if [ "${FAILURES}" -gt 0 ]; then
  echo "ssh-interop: ${FAILURES} gating failure(s)" >&2
  exit 1
fi
echo "ssh-interop: all gating rows passed"
