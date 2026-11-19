#!/bin/sh
# Linux-only: install the production TSYNC policy while a thread is alive,
# then exercise both watchdog sleep syscall variants and thread teardown.
set -eu
case $(uname -s) in Linux) ;; *) echo 'SKIP: Linux seccomp required'; exit 77 ;; esac
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/hvt-seccomp-watchdog.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
cat > "$tmp/test.c" <<'C'
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
static atomic_int ready, start, finished;
void hvt_seccomp_apply(void);
static void *worker(void *unused)
{
    (void)unused;
    atomic_store_explicit(&ready, 1, memory_order_release);
    while (!atomic_load_explicit(&start, memory_order_acquire)) {}
    struct timespec delay = {.tv_nsec = 1000000};
    assert(syscall(SYS_nanosleep, &delay, NULL) == 0);
    assert(syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &delay, NULL) == 0);
    assert(nanosleep(&delay, NULL) == 0);
    assert(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &delay) == 0);
    atomic_store_explicit(&finished, 1, memory_order_release);
    return NULL;
}
int main(void)
{
    pthread_t thread;
    assert(pthread_create(&thread, NULL, worker, NULL) == 0);
    while (!atomic_load_explicit(&ready, memory_order_acquire)) {}
    hvt_seccomp_apply();
    atomic_store_explicit(&start, 1, memory_order_release);
    assert(pthread_join(thread, NULL) == 0);
    /* KILL_THREAD can let join succeed even though the worker never finished. */
    if (!atomic_load_explicit(&finished, memory_order_acquire))
        _exit(42);
    const char message[] = "PASS: production TSYNC policy permits watchdog sleep and thread teardown\n";
    assert(write(STDOUT_FILENO, message, sizeof message - 1) == sizeof message - 1);
    return 0;
}
C
"${CC:-cc}" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -I "$root/include" -iquote "$root/tenders/common" -iquote "$root/tenders/hvt" \
    "$tmp/test.c" "${HVT_SECCOMP_SOURCE:-$root/tenders/hvt/hvt_seccomp_linux.c}" \
    -lseccomp -pthread -o "$tmp/check"
"$tmp/check"
