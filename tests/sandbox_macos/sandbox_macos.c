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
 * sandbox_macos: checks that hvt_sandbox_macos_enter(), as used by the
 * macOS tender's hvt_drop_privileges(), leaves the descriptors the tender
 * already holds working and denies everything else.
 *
 * That hv_vcpu_run() itself keeps working under the profile is covered by
 * running the rest of the test suite with the sandboxed tender.
 *
 * Usage: sandbox_macos BLOCKFILE
 */

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../../tenders/hvt/hvt_sandbox_macos.h"

extern char **environ;
static int failures;

static void expect(const char *what, int ok)
{
    printf("%-52s %s\n", what, ok ? "ok" : "FAILED");
    if (!ok)
        failures++;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        errx(2, "usage: sandbox_macos BLOCKFILE");

    /* What a tender holds when it calls hvt_drop_privileges(). */
    int blk = open(argv[1], O_RDWR);
    if (blk == -1)
        err(2, "open %s", argv[1]);
    int sp[2], kick[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) == -1 || pipe(kick) == -1)
        err(2, "socketpair/pipe");
    int kq = kqueue();
    if (kq == -1)
        err(2, "kqueue");

    if (hvt_sandbox_macos_enter() == -1)
        errx(1, "hvt_sandbox_macos_enter() failed");

    /*
     * Must keep working. The random hypercall is served with arc4random_buf(),
     * and this is its first use in this process, as in the tender.
     */
    unsigned char r1[16] = {0}, r2[16] = {0}, zero[16] = {0};
    arc4random_buf(r1, sizeof r1);
    arc4random_buf(r2, sizeof r2);
    expect("arc4random_buf",
           memcmp(r1, zero, sizeof r1) != 0 && memcmp(r1, r2, sizeof r1) != 0);
    expect("getentropy", getentropy(r1, sizeof r1) == 0);
    char buf[512];
    memset(buf, 0xa5, sizeof buf);
    expect("pwrite on pre-opened block fd", pwrite(blk, buf, 512, 512) == 512);
    expect("pread on pre-opened block fd", pread(blk, buf, 512, 512) == 512);
    expect("fsync on pre-opened block fd", fsync(blk) == 0);
    expect("send on pre-opened socketpair", send(sp[0], buf, 64, 0) == 64);
    expect("recv on pre-opened socketpair", recv(sp[1], buf, 64, 0) == 64);
    expect("write on pre-opened pipe", write(kick[1], buf, 1) == 1);
    struct kevent kev[2];
    EV_SET(&kev[0], kick[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
    expect("kevent on pre-opened kqueue",
           kevent(kq, kev, 1, &kev[1], 1, &(struct timespec){0, 0}) == 1);
    struct timespec ts;
    expect("clock_gettime", clock_gettime(CLOCK_MONOTONIC, &ts) == 0);

    /* Must be denied. */
    expect("open(/etc/passwd) denied", open("/etc/passwd", O_RDONLY) == -1);
    expect("re-open of the block file denied",
           open(argv[1], O_RDONLY) == -1);
    char tmp[] = "/tmp/solo5-sandbox-XXXXXX";
    expect("file creation denied", mkstemp(tmp) == -1);
    expect("kqueue() denied", kqueue() == -1);
    expect("pipe() denied", pipe(kick) == -1);
    expect("socket(AF_INET) denied", socket(AF_INET, SOCK_STREAM, 0) == -1);
    expect("socket(AF_UNIX) denied", socket(AF_UNIX, SOCK_STREAM, 0) == -1);
    /*
     * Even with a socket in hand, nothing can be done with it. Close one of
     * our own descriptors to make room for one.
     */
    close(kick[0]);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sin = {.sin_len = sizeof sin,
                              .sin_family = AF_INET,
                              .sin_port = htons(53)};
    sin.sin_addr.s_addr = htonl(0x01010101);
    expect("sendto(1.1.1.1:53) denied",
           s == -1 ||
               sendto(s, buf, 1, 0, (struct sockaddr *)&sin, sizeof sin) == -1);
    expect("connect(1.1.1.1:53) denied",
           s == -1 ||
               connect(s, (struct sockaddr *)&sin, sizeof sin) == -1);
    if (s != -1)
        close(s);
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sun = {.sun_family = AF_UNIX};
    strcpy(sun.sun_path, "/var/run/mDNSResponder");
    expect("connect(/var/run/mDNSResponder) denied",
           s == -1 || connect(s, (struct sockaddr *)&sun, sizeof sun) == -1);
    if (s != -1)
        close(s);

    pid_t pid;
    char *av[] = {"/usr/bin/true", NULL};
    int rc = posix_spawn(&pid, "/usr/bin/true", NULL, NULL, av, environ);
    if (rc == 0) {
        int st;
        waitpid(pid, &st, 0);
        rc = !(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }
    expect("posix_spawn(/usr/bin/true) denied", rc != 0);
    pid = fork();
    if (pid == 0)
        _exit(0);
    if (pid > 0)
        waitpid(pid, NULL, 0);
    expect("fork() denied", pid == -1);

    if (failures) {
        printf("FAILURE (%d)\n", failures);
        return 1;
    }
    printf("SUCCESS\n");
    return 0;
}
