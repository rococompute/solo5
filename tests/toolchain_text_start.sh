#!/bin/sh
# The toolchain's -z solo5-text-start=ADDR: an hvt-only hexadecimal address,
# refused otherwise by both the cc and the ld wrappers. (Linking at ADDR is
# checked by test_user_memory_high.)
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
bin=$root/toolchain/bin
cc=$(ls "$bin"/*-solo5-none-static-cc)
ld=$(ls "$bin"/*-solo5-none-static-ld)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/text-start.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

# refused TOOL MESSAGE ARGS...
refused() {
    tool=$1 message=$2; shift 2
    if "$tool" "$@" -o "$tmp/out" > "$tmp/log" 2>&1; then
        echo "FAIL: $tool $* was accepted" >&2; exit 1
    fi
    grep -q -- "$message" "$tmp/log" || { echo "FAIL: $tool $*: no \"$message\"" >&2; cat "$tmp/log" >&2; exit 1; }
}

for tool in "$cc" "$ld"; do
    refused "$tool" 'not a hexadecimal address' -z solo5-abi=hvt -z solo5-text-start=3221225472 x.o
    refused "$tool" 'not a hexadecimal address' -z solo5-abi=hvt -z solo5-text-start=0xC000000g x.o
    refused "$tool" 'not a hexadecimal address' -z solo5-abi=hvt -z solo5-text-start=0x x.o
    refused "$tool" 'needs -z solo5-abi=hvt' -z solo5-abi=spt -z solo5-text-start=0xC0000000 x.o
done
refused "$cc" 'needs -z solo5-abi=hvt' -z solo5-text-start=0xC0000000 x.o
echo 'PASS: -z solo5-text-start is checked'
