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
 * hvt_sandbox_macos.c: privilege drop for the macOS (HVF) tender.
 *
 * macOS has no seccomp(2), pledge(2) or capsicum(4). The closest equivalent
 * is a sandbox(7) ("seatbelt") profile applied to the running process with
 * sandbox_init(3). The API is deprecated but remains the only public way to
 * confine a process after it has started.
 *
 * By the time hvt_drop_privileges() runs, the tender holds everything it
 * needs: the VM and vCPU, guest memory, the block and network fds, the kick
 * pipe, the kqueue and the net I/O thread. None of what remains to be done
 * needs any of the operations a seatbelt profile mediates, so the profile is
 * the strictest one possible: deny everything. This was established by
 * running hv_vcpu_run(), I/O on pre-opened vnodes, sockets and pipes, and
 * kevent() under it (see docs/hvf-spikes.md).
 *
 * In particular this denies opening or creating any file, exec, fork, any
 * outbound or inbound network operation (connect, bind, sendto), Mach
 * service lookups, IOKit, and sysctl writes.
 *
 * socket(2) itself is not mediated by seatbelt. To keep the tender from
 * creating new descriptors of any kind, RLIMIT_NOFILE is also lowered to just
 * above the highest descriptor currently open, after filling every closed
 * descriptor slot below it. Filling the gaps matters: RLIMIT_NOFILE bounds
 * the descriptor *number*, not the number of open descriptors, so a slot
 * freed by hvt_main (for example the ELF fd) would otherwise be reused by
 * socket() or pipe() under the deny-all profile.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <sandbox.h>

#include "hvt_sandbox_macos.h"

const char hvt_sandbox_profile[] = "(version 1)\n"
                                   "(deny default)\n";

int hvt_sandbox_macos_enter(void)
{
    /*
     * Lower RLIMIT_NOFILE first: setrlimit() is itself not something the
     * profile needs to allow, but do it while nothing is restricted.
     */
    int limit = hvt_sandbox_fill_fd_gaps();
    if (limit < 0) {
        warnx("sandbox: could not determine open file descriptors");
        return -1;
    }
    struct rlimit rl = {.rlim_cur = (rlim_t)limit,
                        .rlim_max = (rlim_t)limit};
    if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
        warn("sandbox: setrlimit(RLIMIT_NOFILE)");
        return -1;
    }

    char *sberr = NULL;
    if (sandbox_init(hvt_sandbox_profile, 0, &sberr) != 0) {
        warnx("sandbox: sandbox_init() failed: %s",
              sberr ? sberr : "unknown error");
        if (sberr)
            sandbox_free_error(sberr);
        return -1;
    }
    return 0;
}

#pragma clang diagnostic pop
