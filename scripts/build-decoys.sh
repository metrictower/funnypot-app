#!/usr/bin/env bash
#
# Build the decoy archives the demo honeypot serves for archive probes (.zip / .tar.gz /
# .tar / .tar.bz2) on paths that would otherwise 404. Each is a DEEP nested archive: peel a
# layer, find another same-type archive, repeat — hundreds of levels down to a fake .env /
# credentials core. It wastes an attacker's *time* (manual re-extraction), never their RAM/disk.
#
# Grown to ~TARGET_BYTES so a downloaded "backup" looks fat and real. Size is driven by a small
# incompressible blob added at every layer (empty-file tar headers compress to nothing under
# gzip/bzip2, so they cannot carry the size — the blob does). Depth falls out of TARGET/BLOB.
#
# Bounded and safe, NOT a decompression bomb:
#   - the loop stops at TARGET_BYTES (and a hard MAX_LAYERS backstop), so recursion terminates;
#   - each layer wraps ONE inner archive plus small junk, so fully-recursive extraction is linear
#     in depth — a few hundred MB total, never exponential;
#   - the script asserts the outer file lands in [TARGET, MAX_BYTES] before writing it.
#
# Tunables (env): DECOY_TARGET_BYTES, DECOY_BLOB_BYTES (smaller => deeper), DECOY_EMPTIES,
# DECOY_MAX_BYTES, DECOY_MAX_LAYERS.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$SCRIPT_DIR/../demo/decoys"
TARGET_BYTES="${DECOY_TARGET_BYTES:-1000000}"   # ~1 MB served file
BLOB_BYTES="${DECOY_BLOB_BYTES:-2048}"          # incompressible bytes per layer (size driver)
EMPTIES="${DECOY_EMPTIES:-5}"                   # empty junk files per layer (flavor, not size)
MAX_BYTES="${DECOY_MAX_BYTES:-1400000}"         # refuse to write anything larger
MAX_LAYERS="${DECOY_MAX_LAYERS:-8000}"          # runaway backstop

mkdir -p "$OUT_DIR"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Enticing per-layer archive names so a human keeps digging.
NAMES=(backup_full db_backup_final website_backup account_dump prod_snapshot \
       config_archive vault_export secrets_bundle db_prod home_backup wp_backup etc_backup \
       mail_spool billing_export uploads_bak archive)
# Plausible empty-file names scattered through the tree.
EMPTY_POOL=(access.log error.log debug.log php_errors.log .lock index.php .htaccess \
            session.tmp cache.dat thumbs.db .gitkeep queue.lock)

# --- innermost payload: fabricated, obviously-inert secrets + a plain-English notice. ---
seed_payload() {
    local dir="$1"
    cat > "$dir/.env" <<'ENV'
APP_ENV=production
APP_KEY=base64:0000000000000000000000000000000000000000000=
DB_HOST=127.0.0.1
DB_USERNAME=admin
DB_PASSWORD=0000000000000000000000000000
ENV
    cat > "$dir/credentials.txt" <<'CREDS'
AWS_ACCESS_KEY_ID=AKIA0000000000000000
AWS_SECRET_ACCESS_KEY=0000000000000000000000000000000000000000
CREDS
    cat > "$dir/NOTICE.txt" <<'NOTE'
This archive was served by a honeypot. Every value inside it is fabricated
and useless. There was never any real data here. Your request has been logged.
NOTE
}

# README + empty junk files + one incompressible blob (the per-layer size driver).
layer_fill() {
    local dir="$1" i
    printf 'Full backup split across the enclosed archive. Continue unpacking.\n' > "$dir/README.txt"
    for (( i = 0; i < EMPTIES; i++ )); do
        : > "$dir/${EMPTY_POOL[$(( i % ${#EMPTY_POOL[@]} ))]}.$i"
    done
    head -c "$BLOB_BYTES" /dev/urandom > "$dir/page_data.bin"
}

pack_zip()    { ( cd "$1" && zip -q -0 -rX "$2" . ); }   # -0 store: don't re-deflate nested archives
pack_targz()  { tar czf "$2" -C "$1" .; }
pack_tar()    { tar cf  "$2" -C "$1" .; }   # uncompressed: reaches ~1MB shallower than the others
pack_tarbz2() { tar cjf "$2" -C "$1" .; }

filesize() { wc -c < "$1" | tr -d ' '; }

build_nest() {
    local kind="$1" pack="$2" ext="$3"

    local inner="$WORK/${kind}-core"
    mkdir -p "$inner"
    seed_payload "$inner"
    local cur="$WORK/${kind}-l0.$ext"
    "$pack" "$inner" "$cur"

    local i=0 name layerdir next size
    size="$(filesize "$cur")"
    while [ "$size" -lt "$TARGET_BYTES" ] && [ "$i" -lt "$MAX_LAYERS" ]; do
        i=$(( i + 1 ))
        name="${NAMES[$(( (i - 1) % ${#NAMES[@]} ))]}"
        layerdir="$WORK/${kind}-layer$i"
        mkdir -p "$layerdir"
        mv "$cur" "$layerdir/${name}.$ext"
        layer_fill "$layerdir"
        next="$WORK/${kind}-l$i.$ext"
        "$pack" "$layerdir" "$next"
        cur="$next"
        size="$(filesize "$cur")"
    done

    if [ "$size" -lt "$TARGET_BYTES" ]; then
        echo "ERROR: $kind decoy only reached ${size} bytes in ${i} layers (< ${TARGET_BYTES})." >&2
        exit 1
    fi
    if [ "$size" -gt "$MAX_BYTES" ]; then
        echo "ERROR: $kind decoy is ${size} bytes (> ${MAX_BYTES}). Refusing." >&2
        exit 1
    fi
    cp "$cur" "$OUT_DIR/backup.$ext"
    echo "  backup.$ext: ${size} bytes, $(( i + 1 )) nested layers"
}

echo "==> building deep nested decoys (target=${TARGET_BYTES}B, blob=${BLOB_BYTES}B) -> $OUT_DIR"
build_nest zip    pack_zip    zip
build_nest targz  pack_targz  tar.gz
build_nest tar    pack_tar    tar
build_nest tarbz2 pack_tarbz2 tar.bz2
echo "==> done."
