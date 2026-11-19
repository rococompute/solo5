#!/bin/sh
# Exercise the complete production GDB protocol over a socketpair. Only the
# hypervisor-specific register/breakpoint backend is replaced by test stubs;
# macOS has no native debug tender, so this also runs there without a VM.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
: "${CC:=cc}"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/hvt-gdb-protocol.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
python3 - "${HVT_GDB_SOURCE:-$root/tenders/hvt/hvt_module_gdb.c}" "$tmp/gdb-module.c" <<'PY'
import pathlib, sys
source = pathlib.Path(sys.argv[1]).read_text()
start = source.index('#if defined(__linux__) && defined(__x86_64__)')
end = source.index('\n#endif', start) + len('\n#endif')
backend = source[start:end]
assert '#include "hvt_gdb_kvm_x86_64.c"' in backend
assert '#error Unsupported target' in backend
pathlib.Path(sys.argv[2]).write_text(source[:start] + source[end:])
PY
# CFLAGS deliberately accepts several compiler options, e.g. sanitizers.
# shellcheck disable=SC2086
"$CC" -std=gnu11 -O1 -g -Wall -Wextra -Werror -Wno-unused-parameter \
    ${CFLAGS:-} -I "$tmp" -I "$root/include" -I "$root/tenders/hvt" \
    -I "$root/tenders/common" -o "$tmp/check" "$here/hvt_gdb_protocol.c"
"$tmp/check"
