/*
 * Regression test for the macOS sandbox descriptor limit.
 *
 * hvt_sandbox_macos_enter() lowers RLIMIT_NOFILE to highest_open_fd() + 1.
 * RLIMIT_NOFILE bounds the descriptor *number*, not the number of open
 * descriptors, so a closed gap below the limit (hvt_main closes the ELF fd
 * just before dropping privileges) can be reused by socket()/pipe().
 *
 * The descriptor logic lives in tenders/hvt/hvt_sandbox_macos.h, which has no
 * sandbox.h or macOS dependency, so this test compiles and runs on Linux and
 * exercises the real functions rather than a copied model. Every scenario
 * runs in a forked child because it lowers RLIMIT_NOFILE.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "hvt_sandbox_macos.h"

static int checks;
static int failures;

#define FAIL(...)                                                              \
    do {                                                                       \
        fprintf(stderr, __VA_ARGS__);                                          \
        fputc('\n', stderr);                                                   \
        return 1;                                                              \
    } while (0)

static int open_nulls(int *fds, int count)
{
    for (int i = 0; i < count; i++) {
        fds[i] = open("/dev/null", O_RDONLY);
        if (fds[i] == -1) {
            fprintf(stderr, "open(/dev/null): %s\n", strerror(errno));
            return -1;
        }
    }
    return 0;
}

/* The production step: apply the returned highest + 1 as RLIMIT_NOFILE. */
static int apply_limit(int limit)
{
    struct rlimit rl = {.rlim_cur = (rlim_t)limit,
                        .rlim_max = (rlim_t)limit};
    if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
        fprintf(stderr, "setrlimit(%d): %s\n", limit, strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * The old logic, kept as a counterexample: lower the limit to highest + 1
 * without filling the gap. A new descriptor must land in the gap, below the
 * limit. This scenario succeeds only if the old logic is demonstrably leaky.
 */
static int scenario_old_limit_gap(void)
{
    int fds[5];
    if (open_nulls(fds, 5) == -1)
        return 1;
    int gap = fds[2];
    close(gap);

    int limit = hvt_sandbox_highest_fd() + 1;
    if (limit <= gap)
        FAIL("old limit %d does not cover the closed gap %d", limit, gap);
    if (apply_limit(limit) == -1)
        return 1;

    int fd = open("/dev/null", O_RDONLY);
    if (fd == -1)
        FAIL("old highest+1 limit unexpectedly denied open: %s",
             strerror(errno));
    if (fd >= limit)
        FAIL("new descriptor %d is at or above the limit %d", fd, limit);
    if (fd != gap)
        FAIL("new descriptor %d is not the closed gap %d", fd, gap);
    close(fd);
    return 0;
}

/* Closed gap below the limit: it must be filled, and no new fd may appear. */
static int scenario_fixed_gap(void)
{
    int fds[5];
    if (open_nulls(fds, 5) == -1)
        return 1;
    int gap = fds[2];
    close(gap);

    int expected = hvt_sandbox_highest_fd() + 1;
    int limit = hvt_sandbox_fill_fd_gaps();
    if (limit == -1)
        FAIL("hvt_sandbox_fill_fd_gaps(): %s", strerror(errno));
    if (limit != expected)
        FAIL("fill returned %d, expected highest+1 %d", limit, expected);
    if (apply_limit(limit) == -1)
        return 1;

    if (fcntl(gap, F_GETFD) == -1)
        FAIL("closed gap %d was not filled", gap);
    for (int i = 0; i < 5; i++) {
        if (fcntl(fds[i], F_GETFD) == -1)
            FAIL("pre-existing descriptor %d was lost", fds[i]);
    }

    errno = 0;
    int fd = open("/dev/null", O_RDONLY);
    if (fd != -1) {
        close(fd);
        FAIL("open() succeeded with descriptor %d below limit %d", fd, limit);
    }
    if (errno != EMFILE)
        FAIL("open() failed with %s, expected EMFILE", strerror(errno));

    int p[2];
    errno = 0;
    if (pipe(p) != -1) {
        close(p[0]);
        close(p[1]);
        FAIL("pipe() succeeded below limit %d", limit);
    }
    if (errno != EMFILE)
        FAIL("pipe() failed with %s, expected EMFILE", strerror(errno));

    errno = 0;
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s != -1) {
        close(s);
        FAIL("socket() succeeded below limit %d", limit);
    }
    if (errno != EMFILE)
        FAIL("socket() failed with %s, expected EMFILE", strerror(errno));
    return 0;
}

/* Normal case: descriptors are already contiguous, nothing to fill. */
static int scenario_fixed_no_gap(void)
{
    int fds[5];
    if (open_nulls(fds, 5) == -1)
        return 1;

    int expected = hvt_sandbox_highest_fd() + 1;
    int limit = hvt_sandbox_fill_fd_gaps();
    if (limit == -1)
        FAIL("hvt_sandbox_fill_fd_gaps(): %s", strerror(errno));
    if (limit != expected)
        FAIL("fill returned %d, expected highest+1 %d", limit, expected);
    if (apply_limit(limit) == -1)
        return 1;

    errno = 0;
    int fd = open("/dev/null", O_RDONLY);
    if (fd != -1) {
        close(fd);
        FAIL("open() succeeded with descriptor %d below limit %d", fd, limit);
    }
    if (errno != EMFILE)
        FAIL("open() failed with %s, expected EMFILE", strerror(errno));
    return 0;
}

/* Every descriptor number below the limit must be open after filling. */
static int scenario_fixed_all_open(void)
{
    int fds[5];
    if (open_nulls(fds, 5) == -1)
        return 1;

    int limit = hvt_sandbox_fill_fd_gaps();
    if (limit == -1)
        FAIL("hvt_sandbox_fill_fd_gaps(): %s", strerror(errno));
    if (apply_limit(limit) == -1)
        return 1;

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == -1)
        FAIL("getrlimit(): %s", strerror(errno));
    if (rl.rlim_cur != (rlim_t)limit)
        FAIL("RLIMIT_NOFILE is %llu, expected %d",
             (unsigned long long)rl.rlim_cur, limit);
    for (int fd = 0; fd < (int)rl.rlim_cur; fd++) {
        if (fcntl(fd, F_GETFD) == -1)
            FAIL("descriptor %d is free below limit %d", fd, limit);
    }
    errno = 0;
    int fd = open("/dev/null", O_RDONLY);
    if (fd != -1) {
        close(fd);
        FAIL("open() succeeded with descriptor %d below limit %d", fd, limit);
    }
    if (errno != EMFILE)
        FAIL("open() failed with %s, expected EMFILE", strerror(errno));
    return 0;
}

/* A gap at descriptor 0 must be filled like any other. */
static int scenario_fixed_gap_zero(void)
{
    int fds[3];
    if (open_nulls(fds, 3) == -1)
        return 1;
    close(STDIN_FILENO);

    int limit = hvt_sandbox_fill_fd_gaps();
    if (limit == -1)
        FAIL("hvt_sandbox_fill_fd_gaps(): %s", strerror(errno));
    if (apply_limit(limit) == -1)
        return 1;
    if (fcntl(STDIN_FILENO, F_GETFD) == -1)
        FAIL("descriptor 0 was not filled");

    errno = 0;
    int fd = open("/dev/null", O_RDONLY);
    if (fd != -1) {
        close(fd);
        FAIL("open() succeeded with descriptor %d below limit %d", fd, limit);
    }
    if (errno != EMFILE)
        FAIL("open() failed with %s, expected EMFILE", strerror(errno));
    return 0;
}

/* No open descriptor at all is an error, as before. */
static int scenario_no_open_fds(void)
{
    for (int fd = 0; fd < HVT_SANDBOX_FD_SCAN_MAX; fd++) {
        if (fcntl(fd, F_GETFD) != -1)
            close(fd);
    }
    return hvt_sandbox_fill_fd_gaps() == -1 ? 0 : 1;
}

static void run(const char *name, int (*scenario)(void))
{
    fflush(NULL);
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(2);
    }
    if (pid == 0)
        _exit(scenario());

    int status;
    if (waitpid(pid, &status, 0) != pid) {
        perror("waitpid");
        exit(2);
    }
    checks++;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("ok: %s\n", name);
    } else {
        failures++;
        printf("FAIL: %s\n", name);
    }
}

int main(void)
{
    run("old highest+1 leaves the closed gap reusable",
        scenario_old_limit_gap);
    run("fixed: closed gap filled, open/pipe/socket denied",
        scenario_fixed_gap);
    run("fixed: no gap, open denied", scenario_fixed_no_gap);
    run("fixed: every slot below the limit is open",
        scenario_fixed_all_open);
    run("fixed: gap at descriptor zero is filled", scenario_fixed_gap_zero);
    run("fixed: no open descriptors is an error", scenario_no_open_fds);

    if (failures) {
        printf("FAILED: %d of %d scenarios\n", failures, checks);
        return 1;
    }
    printf("PASS: %d scenarios\n", checks);
    return 0;
}
