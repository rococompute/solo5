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
 * netpeer: a host-side ping peer for the net tests, for hosts without a tap
 * device (macOS) or for running the tests unprivileged.
 *
 * netpeer creates one AF_UNIX/SOCK_DGRAM socketpair per interface, passes
 * one end of interface i to the command as fd 3+i (so the tender is run with
 * --net:NAME=@3, @4, ...), and plays the role of the host on the other end:
 * it is 10.i.0.1 and floods ICMP echo requests to 10.i.0.2 with a 32-bit
 * payload pattern, checking every reply, until the command exits.
 *
 * Usage: netpeer [-n NIF] [-c COUNT] [-k] [-p PATTERN] -- command [args...]
 *
 *   -n NIF      number of interfaces (default 1, max 8)
 *   -c COUNT    stop after COUNT echo requests per interface (default:
 *               unlimited; 0 sends none and only keeps the fds open)
 *   -k          once COUNT good replies have arrived on every interface,
 *               stop the command with SIGTERM and exit 0 (for guests that
 *               never exit by themselves, such as servers)
 *   -p PATTERN  32-bit payload pattern in hex (default deadbeef)
 *
 * Exits with the command's exit status, or 1 if any reply was corrupted.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_NIF      8
#define WINDOW       32
#define PAYLOAD_LEN  56
#define SOCKBUF_SIZE (1 << 20)
#define FRAME_MAX    65536

struct __attribute__((packed)) ether {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

struct __attribute__((packed)) arp {
    uint16_t htype, ptype;
    uint8_t hlen, plen;
    uint16_t op;
    uint8_t sha[6], spa[4], tha[6], tpa[4];
};

struct __attribute__((packed)) ip {
    uint8_t version_ihl, type;
    uint16_t length, id, flags_offset;
    uint8_t ttl, proto;
    uint16_t checksum;
    uint8_t src[4], dst[4];
};

struct __attribute__((packed)) icmp_echo {
    uint8_t type, code;
    uint16_t checksum, id, seq;
    uint8_t data[PAYLOAD_LEN];
};

struct iface {
    int fd;
    uint8_t mac[6], ip[4];
    uint8_t guest_mac[6], guest_ip[4];
    bool guest_mac_known;
    unsigned long sent, replies, corrupted;
    unsigned outstanding;
    double last_progress;
};

static const uint8_t mac_brd[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static uint8_t pattern[4];

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static uint16_t checksum(const void *buf, size_t len)
{
    const uint8_t *p = buf;
    uint32_t sum = 0;
    for (; len > 1; len -= 2, p += 2)
        sum += (p[0] << 8) | p[1];
    if (len)
        sum += p[0] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return htons(~sum);
}

static void send_frame(struct iface *ifc, const void *buf, size_t len)
{
    /* The socketpair does not drop frames; a full buffer just waits. */
    while (send(ifc->fd, buf, len, 0) == -1) {
        if (errno != ENOBUFS && errno != EAGAIN && errno != EINTR)
            return;
        usleep(100);
    }
}

static void send_arp_request(struct iface *ifc)
{
    struct __attribute__((packed)) {
        struct ether e;
        struct arp a;
    } f;
    memcpy(f.e.dst, mac_brd, 6);
    memcpy(f.e.src, ifc->mac, 6);
    f.e.type = htons(0x0806);
    f.a.htype = htons(1);
    f.a.ptype = htons(0x0800);
    f.a.hlen = 6;
    f.a.plen = 4;
    f.a.op = htons(1);
    memcpy(f.a.sha, ifc->mac, 6);
    memcpy(f.a.spa, ifc->ip, 4);
    memset(f.a.tha, 0, 6);
    memcpy(f.a.tpa, ifc->guest_ip, 4);
    send_frame(ifc, &f, sizeof f);
}

static void send_arp_reply(struct iface *ifc, const struct arp *req)
{
    struct __attribute__((packed)) {
        struct ether e;
        struct arp a;
    } f;
    memcpy(f.e.dst, req->sha, 6);
    memcpy(f.e.src, ifc->mac, 6);
    f.e.type = htons(0x0806);
    f.a.htype = htons(1);
    f.a.ptype = htons(0x0800);
    f.a.hlen = 6;
    f.a.plen = 4;
    f.a.op = htons(2);
    memcpy(f.a.sha, ifc->mac, 6);
    memcpy(f.a.spa, ifc->ip, 4);
    memcpy(f.a.tha, req->sha, 6);
    memcpy(f.a.tpa, req->spa, 4);
    send_frame(ifc, &f, sizeof f);
}

static void send_echo(struct iface *ifc)
{
    struct __attribute__((packed)) {
        struct ether e;
        struct ip i;
        struct icmp_echo c;
    } f;
    memcpy(f.e.dst, ifc->guest_mac, 6);
    memcpy(f.e.src, ifc->mac, 6);
    f.e.type = htons(0x0800);
    memset(&f.i, 0, sizeof f.i);
    f.i.version_ihl = 0x45;
    f.i.length = htons(sizeof f.i + sizeof f.c);
    f.i.id = htons((uint16_t)ifc->sent);
    f.i.ttl = 64;
    f.i.proto = 1;
    memcpy(f.i.src, ifc->ip, 4);
    memcpy(f.i.dst, ifc->guest_ip, 4);
    f.i.checksum = checksum(&f.i, sizeof f.i);
    f.c.type = 8;
    f.c.code = 0;
    f.c.checksum = 0;
    f.c.id = htons(0x5050);
    f.c.seq = htons((uint16_t)ifc->sent);
    for (size_t i = 0; i < PAYLOAD_LEN; i++)
        f.c.data[i] = pattern[i % 4];
    f.c.checksum = checksum(&f.c, sizeof f.c);
    send_frame(ifc, &f, sizeof f);
    ifc->sent++;
    ifc->outstanding++;
}

static void handle_frame(struct iface *ifc, const uint8_t *buf, size_t len)
{
    if (len < sizeof(struct ether))
        return;
    const struct ether *e = (const void *)buf;
    if (memcmp(e->dst, ifc->mac, 6) && memcmp(e->dst, mac_brd, 6))
        return;

    if (ntohs(e->type) == 0x0806 && len >= sizeof *e + sizeof(struct arp)) {
        const struct arp *a = (const void *)(buf + sizeof *e);
        /* Any ARP packet from the guest tells us its MAC address. */
        if (memcmp(a->spa, ifc->guest_ip, 4) == 0) {
            memcpy(ifc->guest_mac, a->sha, 6);
            ifc->guest_mac_known = true;
        }
        /* Answer ARP requests for our own address (e.g. a TCP/IP stack
         * resolving its gateway before replying to us). */
        if (ntohs(a->op) == 1 && memcmp(a->tpa, ifc->ip, 4) == 0)
            send_arp_reply(ifc, a);
        return;
    }

    if (ntohs(e->type) != 0x0800 ||
        len < sizeof *e + sizeof(struct ip) + sizeof(struct icmp_echo))
        return;
    const struct ip *i = (const void *)(buf + sizeof *e);
    const struct icmp_echo *c = (const void *)(buf + sizeof *e + sizeof *i);
    if (i->proto != 1 || memcmp(i->dst, ifc->ip, 4) || c->type != 0)
        return;

    bool ok = ntohs(c->id) == 0x5050 &&
              checksum(c, sizeof *c) == 0 &&
              checksum(i, sizeof *i) == 0;
    for (size_t k = 0; ok && k < PAYLOAD_LEN; k++)
        ok = c->data[k] == pattern[k % 4];
    if (ok)
        ifc->replies++;
    else
        ifc->corrupted++;
    if (ifc->outstanding)
        ifc->outstanding--;
    ifc->last_progress = now();
}

static void usage(void)
{
    fprintf(stderr, "usage: netpeer [-n NIF] [-c COUNT] [-k] [-p PATTERN] -- "
                    "command [args...]\n");
    exit(2);
}

int main(int argc, char **argv)
{
    int nif = 1;
    long count = -1;
    uint32_t pat = 0xdeadbeef;
    bool kill_when_done = false;
    int opt;

    while ((opt = getopt(argc, argv, "n:c:kp:")) != -1) {
        switch (opt) {
        case 'n':
            nif = atoi(optarg);
            break;
        case 'c':
            count = atol(optarg);
            break;
        case 'k':
            kill_when_done = true;
            break;
        case 'p':
            pat = (uint32_t)strtoul(optarg, NULL, 16);
            break;
        default:
            usage();
        }
    }
    if (nif < 1 || nif > MAX_NIF || optind >= argc ||
        (kill_when_done && count <= 0))
        usage();
    pattern[0] = pat >> 24;
    pattern[1] = pat >> 16;
    pattern[2] = pat >> 8;
    pattern[3] = pat;

    struct iface ifs[MAX_NIF];
    int child_fds[MAX_NIF];
    memset(ifs, 0, sizeof ifs);
    for (int n = 0; n < nif; n++) {
        int sp[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) == -1) {
            perror("netpeer: socketpair");
            return 1;
        }
        /*
         * On macOS the maximum datagram size on an AF_UNIX socket is bounded
         * by its send buffer (2 KiB by default), which is less than a jumbo
         * frame. Raise both buffers on both ends.
         */
        int sz = SOCKBUF_SIZE;
        for (int k = 0; k < 2; k++) {
            setsockopt(sp[k], SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
            setsockopt(sp[k], SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
        }
        ifs[n].fd = sp[0];
        child_fds[n] = sp[1];
        uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, (uint8_t)n, 0x01};
        memcpy(ifs[n].mac, mac, 6);
        uint8_t ip[4] = {10, (uint8_t)n, 0, 1};
        uint8_t gip[4] = {10, (uint8_t)n, 0, 2};
        memcpy(ifs[n].ip, ip, 4);
        memcpy(ifs[n].guest_ip, gip, 4);
        ifs[n].last_progress = now();
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("netpeer: fork");
        return 1;
    }
    if (pid == 0) {
        /* Move the child ends to 3, 4, ... without clobbering each other. */
        int tmp[MAX_NIF];
        for (int n = 0; n < nif; n++)
            tmp[n] = fcntl(child_fds[n], F_DUPFD, 3 + MAX_NIF + 1);
        for (int n = 0; n < nif; n++) {
            close(ifs[n].fd);
            dup2(tmp[n], 3 + n);
            close(tmp[n]);
        }
        execvp(argv[optind], &argv[optind]);
        perror("netpeer: exec");
        _exit(127);
    }
    for (int n = 0; n < nif; n++)
        close(child_fds[n]);

    int status = 0;
    bool killed = false;
    double last_arp = 0;
    static uint8_t buf[FRAME_MAX];
    for (;;) {
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid)
            break;

        if (kill_when_done && !killed) {
            bool done = true;
            for (int n = 0; n < nif; n++)
                done = done && (long)ifs[n].replies >= count;
            if (done) {
                kill(pid, SIGTERM);
                killed = true;
            }
        }

        double t = now();
        for (int n = 0; n < nif; n++) {
            struct iface *ifc = &ifs[n];
            if (!ifc->guest_mac_known) {
                if (t - last_arp > 0.1)
                    send_arp_request(ifc);
                continue;
            }
            /* The guest may have reset; do not stall forever on a window. */
            if (ifc->outstanding && t - ifc->last_progress > 1.0) {
                ifc->outstanding = 0;
                ifc->last_progress = t;
            }
            while (ifc->outstanding < WINDOW &&
                   (count < 0 || (long)ifc->sent < count))
                send_echo(ifc);
        }
        if (t - last_arp > 0.1)
            last_arp = t;

        struct pollfd pfd[MAX_NIF];
        for (int n = 0; n < nif; n++) {
            pfd[n].fd = ifs[n].fd;
            pfd[n].events = POLLIN;
        }
        if (poll(pfd, nif, 10) > 0) {
            for (int n = 0; n < nif; n++) {
                if (!(pfd[n].revents & POLLIN))
                    continue;
                ssize_t len;
                while ((len = recv(ifs[n].fd, buf, sizeof buf,
                                   MSG_DONTWAIT)) > 0)
                    handle_frame(&ifs[n], buf, (size_t)len);
            }
        }
    }

    int rc;
    if (killed)
        rc = 0;
    else if (WIFEXITED(status))
        rc = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        rc = 128 + WTERMSIG(status);
    else
        rc = 1;

    bool corrupted = false;
    for (int n = 0; n < nif; n++) {
        fprintf(stderr,
                "netpeer: if%d: sent %lu, good replies %lu, corrupted %lu\n",
                n, ifs[n].sent, ifs[n].replies, ifs[n].corrupted);
        if (ifs[n].corrupted)
            corrupted = true;
    }
    if (corrupted) {
        fprintf(stderr, "netpeer: FAILURE: corrupted replies\n");
        return 1;
    }
    return rc;
}
