/*
 * Regression test for HVT_CHECKED_GPA_P / hvt_checked_gpa_p.
 *
 * The guest-address range is half-open: [gpa, gpa + sz) must lie inside
 * guest memory. This test includes the real tenders/hvt/hvt.h and calls the
 * actual inline function. Each case runs in a forked child so that the errx()
 * abort path can be observed without terminating the harness.
 */
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "hvt.h"

#define GUEST_SIZE 65536

static unsigned char guest_mem[GUEST_SIZE];
static int checks;
static int failures;

static void check_range(struct hvt *hvt, hvt_gpa_t gpa, size_t sz,
                        int expect_ok, const char *what)
{
    fflush(NULL);
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(2);
    }
    if (pid == 0) {
        /* errx() reports on stderr; keep the harness output readable. */
        int fd = open("/dev/null", O_WRONLY);
        if (fd != -1) {
            (void)dup2(fd, STDERR_FILENO);
            (void)close(fd);
        }
        void *p = hvt_checked_gpa_p(hvt, gpa, sz, __FILE__, __LINE__);
        if (!expect_ok)
            _exit(3); /* the call should have aborted */
        _exit(p == (void *)(hvt->mem + gpa) ? 0 : 4);
    }

    int status;
    if (waitpid(pid, &status, 0) != pid) {
        perror("waitpid");
        exit(2);
    }
    int ok = WIFEXITED(status) &&
             WEXITSTATUS(status) == (expect_ok ? 0 : 1);
    checks++;
    if (!ok) {
        failures++;
        printf("FAIL: %s (gpa=0x%" PRIx64 ", sz=%zu): ", what,
               (uint64_t)gpa, sz);
        if (WIFSIGNALED(status))
            printf("killed by signal %d\n", WTERMSIG(status));
        else if (WIFEXITED(status))
            printf("exit status %d\n", WEXITSTATUS(status));
        else
            printf("unknown child status\n");
    }
}

int main(void)
{
    struct hvt hvt = {0};
    struct hvt empty = {0};

    hvt.mem = guest_mem;
    hvt.guest_mem_size = GUEST_SIZE;
    empty.mem = guest_mem;
    empty.guest_mem_size = 0;

    /* Normal accesses inside the range. */
    check_range(&hvt, 0, 16, 1, "in-range at start");
    check_range(&hvt, 0x1000, 0x1000, 1, "in-range in middle");
    check_range(&hvt, GUEST_SIZE - 1, 0, 1, "zero length before end");
    check_range(&hvt, 0, GUEST_SIZE, 1, "whole guest range");

    /* The half-open end is valid: gpa + sz == guest_mem_size. */
    check_range(&hvt, GUEST_SIZE - 1, 1, 1, "exact end, last byte");
    check_range(&hvt, GUEST_SIZE - 16, 16, 1, "exact end, sz > 0");

    /* gpa itself must still be inside guest memory. */
    check_range(&hvt, GUEST_SIZE, 0, 0, "gpa at end, zero length");
    check_range(&hvt, GUEST_SIZE, 1, 0, "gpa at end with length");
    check_range(&hvt, GUEST_SIZE + 1, 0, 0, "gpa past end");
    check_range(&hvt, UINT64_MAX, 0, 0, "gpa at maximum");
    check_range(&empty, 0, 0, 0, "zero-size guest");

    /* An end strictly beyond guest_mem_size is invalid. */
    check_range(&hvt, GUEST_SIZE - 1, 2, 0, "end one past");
    check_range(&hvt, GUEST_SIZE - 16, 17, 0, "end past by one");
    check_range(&hvt, 0, GUEST_SIZE + 1, 0, "length past end");
    check_range(&hvt, GUEST_SIZE - 1, GUEST_SIZE, 0, "length wraps range");

    /* gpa + sz overflow must abort even when gpa is in range. */
    check_range(&hvt, 16, UINT64_MAX, 0, "addition overflow");
    check_range(&hvt, 0, UINT64_MAX, 0, "addition overflow from zero");

    if (failures) {
        printf("FAILED: %d of %d checks\n", failures, checks);
        return 1;
    }
    printf("PASS: %d checks\n", checks);
    return 0;
}
