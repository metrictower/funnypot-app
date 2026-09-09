#!/usr/bin/env bash
# Pure post-exit log proof. No Docker, sockets, server, environment overrides or writes.
set -euo pipefail
[[ $# == 1 && -f "$1" && ! -L "$1" ]] || exit 2
bytes=$(wc -c < "$1")
[[ "$bytes" =~ ^[[:space:]]*[0-9]+[[:space:]]*$ ]] || exit 2
(( bytes > 0 && bytes <= 1048576 )) || exit 1
grep -Fq -- 'ingress-positive-container-stdout' "$1" || exit 1
grep -Fq -- 'ingress-positive-container-stderr' "$1" || exit 1
if grep -Fq -- 'ingress-reject-7b6e4d' "$1"; then
    exit 1
else
    result=$?
    [[ $result == 1 ]] || exit 2
fi
printf '%s\n' '{"status":"passed","sink_controls":["container stdout","container stderr"],"negative_marker_absent":true,"max_log_bytes":1048576}'
