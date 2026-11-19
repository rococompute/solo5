#!/bin/sh
# Exercise the production report/err stream on the host libc, without a VM.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/hvt-exit-report.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
python3 - "${HVT_MAIN_SOURCE:-$root/tenders/hvt/hvt_main.c}" "$tmp/report.c" <<'PY'
import pathlib,sys
source = pathlib.Path(sys.argv[1]).read_text()
signal = source[source.index('static void sig_handler('):source.index('\n/*\n * --exit-report=FD')]
report = source[source.index('static int exit_report_fd'):source.index('\n/*\n * --cpu-limit=SECONDS')]
pathlib.Path(sys.argv[2]).write_text(signal + report)
PY
cat > "$tmp/test.c" <<'C'
#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "report.c"
#ifdef HVT_REPORT_SECCOMP
void hvt_seccomp_apply(void);
#endif
int main(int argc, char **argv)
{
    assert(argc == 3);
    char option[64];
    snprintf(option, sizeof option, "--exit-report=%d", atoi(argv[1]));
    handle_exit_report(option);
#ifdef HVT_REPORT_SECCOMP
    hvt_seccomp_apply();
#endif
    if (!strcmp(argv[2], "fault"))
        errx(1, "host/guest translation fault");
    if (!strcmp(argv[2], "signal")) {
#ifdef HVT_REPORT_SECCOMP
        /* The real signal is delivered externally, not by a filtered
         * getpid/tgkill pair. Exercise its actual handler directly here. */
        sig_handler(SIGTERM);
#else
        assert(signal(SIGTERM, sig_handler) != SIG_ERR);
        raise(SIGTERM);
#endif
    }
    if (!strcmp(argv[2], "cpu"))
        errx(1, "CPU time limit of 1 seconds exceeded");
    if (!strcmp(argv[2], "guest")) {
        exit_report_guest_status = 7;
        return 7;
    }
    errx(1, "ordinary tender error");
}
C
if [ "${HVT_REPORT_SECCOMP:-0}" = 1 ]; then
    "${CC:-cc}" -std=gnu11 -O2 -Wall -Wextra -Werror -Wno-unused-variable \
        -DHVT_REPORT_SECCOMP -I "$root/include" \
        -iquote "$root/tenders/common" -iquote "$root/tenders/hvt" \
        "$tmp/test.c" "$root/tenders/hvt/hvt_seccomp_linux.c" \
        -lseccomp -o "$tmp/check"
else
    "${CC:-cc}" -std=gnu11 -O2 -Wall -Wextra -Werror -Wno-unused-variable \
        "$tmp/test.c" -o "$tmp/check"
fi
python3 - "$tmp/check" <<'PY'
import json,subprocess,sys,tempfile
for mode,kind,reason in [('fault','fault','translation_fault'),('signal','signal',None),('cpu','fault','cpu_limit'),('guest','guest_exit',None),('error','tender_error',None)]:
    with tempfile.TemporaryFile() as output:
        p = subprocess.run([sys.argv[1],str(output.fileno()),mode],pass_fds=(output.fileno(),),capture_output=True,timeout=5)
        output.seek(0)
        raw = output.read()
    data=json.loads(raw)
    assert data['kind']==kind,(mode,data,p.stderr)
    if reason:
        assert data['reason']==reason,(mode,data)
    if mode=='guest':
        assert data['status']==7 and p.returncode==7,(mode,data,p.returncode)
    else:
        assert data['message'] and p.returncode==1,(mode,data,p.returncode)
print('PASS: exit reports preserve guest, fault, signal, CPU-limit and tender-error classifications')
PY
