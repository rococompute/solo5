/*
 * Copyright (c) 2015-2019 Contributors as noted in the AUTHORS file
 *
 * This file is part of Solo5, a sandboxed execution environment.
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * hvt_sandbox_macos.h: privilege drop for the macOS (HVF) tender. Kept free
 * of tender dependencies so that tests/test_sandbox_macos can link it alone.
 */

#ifndef HVT_SANDBOX_MACOS_H
#define HVT_SANDBOX_MACOS_H

#include <fcntl.h>
#include <sys/resource.h>
#include <unistd.h>

/*
 * Upper bound on the descriptor numbers scanned when looking for open
 * descriptors. RLIMIT_NOFILE is normally much smaller; the bound keeps the
 * scan finite when it is RLIM_INFINITY.
 */
#define HVT_SANDBOX_FD_SCAN_MAX 65536

extern const char hvt_sandbox_profile[];

/*
 * Highest open descriptor below the current RLIMIT_NOFILE (capped at
 * HVT_SANDBOX_FD_SCAN_MAX), or -1 if there is none or the limit cannot be
 * read.
 */
static inline int hvt_sandbox_highest_fd(void)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == -1)
        return -1;
    int max = (rl.rlim_cur == RLIM_INFINITY ||
               rl.rlim_cur > HVT_SANDBOX_FD_SCAN_MAX)
                  ? HVT_SANDBOX_FD_SCAN_MAX
                  : (int)rl.rlim_cur;
    int highest = -1;
    for (int fd = 0; fd < max; fd++) {
        if (fcntl(fd, F_GETFD) != -1)
            highest = fd;
    }
    return highest;
}

/*
 * Fill every closed descriptor slot below the highest open descriptor with a
 * duplicate of the lowest open descriptor. Returns highest + 1, which is the
 * RLIMIT_NOFILE value that leaves no descriptor number below the limit free:
 * after it is applied, open(), socket() and pipe() cannot create descriptors.
 * Existing descriptors keep their numbers and stay open. Returns -1 on error,
 * including when no descriptor is open.
 *
 * This is portable POSIX code, deliberately kept out of the macOS-only
 * source file so that tests can exercise it without sandbox.h.
 */
static inline int hvt_sandbox_fill_fd_gaps(void)
{
    int highest = hvt_sandbox_highest_fd();
    if (highest < 0)
        return -1;
    int lowest = -1;
    for (int fd = 0; fd <= highest; fd++) {
        if (fcntl(fd, F_GETFD) != -1) {
            lowest = fd;
            break;
        }
    }
    if (lowest < 0)
        return -1;
    for (int fd = 0; fd < highest; fd++) {
        if (fcntl(fd, F_GETFD) == -1 && dup2(lowest, fd) == -1)
            return -1;
    }
    return highest + 1;
}

/*
 * Confine the calling process for good. Descriptors that are already open
 * keep working; no new ones can be opened or created. Returns 0 on success,
 * -1 (with a warning printed) on failure.
 */
int hvt_sandbox_macos_enter(void);

#endif /* HVT_SANDBOX_MACOS_H */
