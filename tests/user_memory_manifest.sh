#!/bin/sh
# solo5-elftool's USER_MEMORY manifest entries: a size (and an optional
# address) that are multiples of 64 KiB, refused everywhere else; and device
# types other than the three it knows refused (the check used to accept any).
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
elftool=${ELFTOOL:-$root/elftool/solo5-elftool}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/user-memory-mft.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

manifest() {
    printf '{ "type": "solo5.manifest", "version": 1, "devices": [ %s ] }\n' "$1" \
        > "$tmp/manifest.json"
}

# accepted DEVICES PATTERN: the generated manifest has PATTERN
accepted() {
    manifest "$1"
    "$elftool" gen-manifest "$tmp/manifest.json" "$tmp/manifest.c"
    grep -q "$2" "$tmp/manifest.c" || { echo "FAIL: $1: no $2" >&2; exit 1; }
}

# refused DEVICES MESSAGE
refused() {
    manifest "$1"
    if "$elftool" gen-manifest "$tmp/manifest.json" "$tmp/manifest.c" \
        > "$tmp/out" 2>&1; then
        echo "FAIL: accepted $1" >&2; exit 1
    fi
    grep -q "$2" "$tmp/out" || { echo "FAIL: $1: no \"$2\"" >&2; cat "$tmp/out" >&2; exit 1; }
}

accepted '{ "name": "guest", "type": "USER_MEMORY", "size": 65536 }' \
    '.address = 0x0, .size = 0x10000'
accepted '{ "name": "guest", "type": "USER_MEMORY", "size": 3218079744, "address": 2097152 }' \
    '.address = 0x200000, .size = 0xbfd00000'
refused '{ "name": "guest", "type": "USER_MEMORY" }' 'USER_MEMORY needs a .size'
refused '{ "name": "guest", "type": "USER_MEMORY", "size": 0 }' '.size may not be 0'
refused '{ "name": "guest", "type": "USER_MEMORY", "size": 4096 }' \
    '.size must be a multiple of 65536 bytes'
refused '{ "name": "guest", "type": "USER_MEMORY", "size": 65536, "address": 4096 }' \
    '.address must be a multiple of 65536 bytes'
refused '{ "name": "guest", "type": "USER_MEMORY", "size": -65536 }' \
    '.size must be a multiple of 65536 bytes'
refused '{ "name": "guest", "type": "USER_MEMORY", "size": "1M" }' 'expected INTEGER'
refused '{ "name": "disk", "type": "BLOCK_BASIC", "size": 65536 }' \
    'only USER_MEMORY has a .size or .address'
refused '{ "name": "disk", "type": "FLOPPY" }' \
    'type FLOPPY is not NET_BASIC, BLOCK_BASIC or USER_MEMORY'
echo 'PASS: USER_MEMORY entries are checked, other types refused'
