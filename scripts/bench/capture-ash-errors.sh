#!/usr/bin/env bash
# Golden capture for the webshell console's error wording: runs every probe through busybox ash on
# Alpine 3.19 and writes the fixtures the golden test compares against. Operator/CI only (needs
# Docker); nothing here runs in the agent sandbox.
#
#   bash scripts/bench/capture-ash-errors.sh
#
# Then review the diff of tests/Fixtures/cmdi/*.golden.txt, fix any wording or lexer verdict the
# golden test reports, and set AshVocabulary::GOLDEN_VERIFIED = true.
#
# Error probes run in a read-only container (so a write fails the way the console says it does).
# Parse probes run `sh -n -c` only: the shell parses the line and never executes it.
set -euo pipefail

cd "$(dirname "$0")/../.."
IMAGE="${ASH_IMAGE:-alpine:3.19}"
OUT=tests/Fixtures/cmdi
mkdir -p "$OUT"
errors="$OUT/ash-errors.golden.txt"
parse="$OUT/ash-parse.golden.txt"
: > "$errors.tmp"
: > "$parse.tmp"

docker pull -q "$IMAGE" >/dev/null

php scripts/bench/ash-probes.php | while IFS=$'\t' read -r kind key b64; do
    payload="$(printf '%s' "$b64" | base64 -d)"
    if [ "$kind" = error ]; then
        line="$(docker run --rm --read-only --network none -e P="$payload" "$IMAGE" sh -c 'sh -c "$P" 2>&1 >/dev/null | head -n 1' || true)"
        printf '%s\t%s\n' "$key" "$line" >> "$errors.tmp"
    else
        res="$(docker run --rm --network none -e P="$payload" "$IMAGE" sh -c 'out="$(sh -n -c "$P" 2>&1)"; rc=$?; printf "%s\t%s" "$rc" "$(printf "%s" "$out" | head -n 1)"' || true)"
        printf '%s\t%s\n' "$key" "$res" >> "$parse.tmp"
    fi
done

mv "$errors.tmp" "$errors"
mv "$parse.tmp" "$parse"
echo "wrote $errors and $parse"
