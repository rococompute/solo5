#!/bin/sh
# Build and run the macOS sandbox descriptor-limit regression on any POSIX
# host. Only tenders/hvt/hvt_sandbox_macos.h is used; sandbox.h and macOS
# frameworks are not needed.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
: "${CC:=cc}"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/hvt-sandbox-rlimit.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

# CFLAGS is intentionally word-split so callers can pass several options.
# shellcheck disable=SC2086
"$CC" -std=c11 -O2 -Wall -Wextra -Werror ${CFLAGS:-} \
    -I "$root/tenders/hvt" -o "$tmp/hvt_sandbox_rlimit" \
    "$here/hvt_sandbox_rlimit.c"
"$tmp/hvt_sandbox_rlimit"
