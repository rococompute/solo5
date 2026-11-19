#!/bin/sh
# Build and run the HVT guest-address range regression test on any POSIX host.
# It compiles tenders/hvt/hvt.h with the production include layout; no
# hypervisor, KVM/HVF or macOS SDK is needed.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
: "${CC:=cc}"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/hvt-gpa-bounds.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

# CFLAGS is intentionally word-split so callers can pass several options.
# shellcheck disable=SC2086
"$CC" -std=c11 -O2 -Wall -Wextra -Werror ${CFLAGS:-} \
    -I "$root/include" -I "$root/tenders/hvt" -I "$root/tenders/common" \
    -o "$tmp/hvt_gpa_bounds" "$here/hvt_gpa_bounds.c"
"$tmp/hvt_gpa_bounds"
