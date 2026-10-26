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
 * solo5-vmnet: give a solo5-hvt unikernel a network on macOS.
 *
 * macOS has no tap device. solo5-vmnet starts a vmnet(3) interface, which
 * needs only the com.apple.security.virtualization entitlement (no root) on
 * macOS 26, and bridges its frames to one end of an AF_UNIX datagram
 * socketpair. It then runs the tender with the other end as fd 3, adding
 *
 *     --net:NAME=@3 --net-mac:NAME=<MAC assigned by vmnet>
 *
 * to its command line. The tender itself never touches the network and stays
 * fully sandboxed; every frame the guest sends passes through here, which is
 * where the egress policy is enforced.
 *
 * Usage:
 *   solo5-vmnet [OPTIONS] -- solo5-hvt [TENDER OPTIONS] [--] KERNEL [ARGS]
 *
 * Options:
 *   --net=NAME          manifest name of the network device (default:
 *                       service)
 *   --mode=shared|host  shared: NAT to the outside world with DHCP and DNS
 *                       from macOS (default); host: host-only network
 *   --isolate           do not let this guest talk to other vmnet guests
 *   --allow=CIDR[:PORT] egress policy: only let the guest send IPv4 packets
 *                       to CIDR (and PORT, for TCP/UDP), plus ARP, DHCP and
 *                       DNS to the vmnet gateway. May be repeated. Without
 *                       any --allow, all egress is allowed.
 *   --verbose           log dropped packets to stderr
 *
 * Exits with the tender's exit status.
 */

#include <arpa/inet.h>
#include <dispatch/dispatch.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vmnet/vmnet.h>

#define SOCKBUF_SIZE (1 << 20)
#define MAX_RULES    64
#define BATCH        32
#define CHILD_FD     3

struct rule {
    uint32_t net, mask; /* host byte order */
    uint16_t port;      /* 0: any */
};

static struct rule rules[MAX_RULES];
static int nrules;
static bool verbose;
static uint32_t gateway_ip; /* host byte order, 0 if unknown */
static int sock = -1;
static interface_ref iface;
static size_t max_packet_size = 1514;
static char mac[32];

static void usage(void)
{
    fprintf(stderr,
            "usage: solo5-vmnet [--net=NAME] [--mode=shared|host] [--isolate]\n"
            "                   [--allow=CIDR[:PORT]]... [--verbose]\n"
            "                   -- solo5-hvt [TENDER OPTIONS] [--] KERNEL "
            "[ARGS]\n");
    exit(2);
}

static void parse_rule(const char *arg)
{
    char buf[64];
    if (nrules == MAX_RULES)
        errx(2, "too many --allow rules");
    if (strlen(arg) >= sizeof buf)
        errx(2, "--allow=%s: too long", arg);
    strcpy(buf, arg);

    struct rule *r = &rules[nrules];
    char *port = strchr(buf, ':');
    if (port) {
        *port++ = 0;
        long p = strtol(port, NULL, 10);
        if (p <= 0 || p > 65535)
            errx(2, "--allow=%s: bad port", arg);
        r->port = (uint16_t)p;
    }
    int bits = 32;
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash++ = 0;
        bits = atoi(slash);
        if (bits < 0 || bits > 32)
            errx(2, "--allow=%s: bad prefix length", arg);
    }
    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1)
        errx(2, "--allow=%s: bad IPv4 address", arg);
    r->mask = bits ? htonl(~0U << (32 - bits)) : 0;
    r->mask = ntohl(r->mask);
    r->net = ntohl(a.s_addr) & r->mask;
    nrules++;
}

/*
 * Egress policy. Returns true if the frame the guest sent may go out.
 */
static bool egress_allowed(const uint8_t *f, size_t len)
{
    if (nrules == 0)
        return true;
    if (len < 14)
        return false;
    uint16_t type = (uint16_t)(f[12] << 8 | f[13]);
    if (type == 0x0806) /* ARP */
        return true;
    if (type != 0x0800) /* IPv6 and anything else: denied */
        return false;
    if (len < 14 + 20)
        return false;
    const uint8_t *ip = f + 14;
    size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
    if ((ip[0] >> 4) != 4 || ihl < 20 || len < 14 + ihl)
        return false;
    uint8_t proto = ip[9];
    uint32_t dst = (uint32_t)ip[16] << 24 | (uint32_t)ip[17] << 16 |
                   (uint32_t)ip[18] << 8 | ip[19];
    uint16_t dport = 0;
    bool first_fragment = ((ip[6] & 0x1f) | ip[7]) == 0;
    if ((proto == 6 || proto == 17) && len >= 14 + ihl + 4 && first_fragment)
        dport = (uint16_t)(ip[ihl + 2] << 8 | ip[ihl + 3]);

    /* DHCP, and DNS to the gateway's resolver. */
    if (proto == 17 && (dport == 67 || dst == 0xffffffff))
        return true;
    if (gateway_ip && dst == gateway_ip && proto == 17 && dport == 53)
        return true;

    for (int i = 0; i < nrules; i++) {
        if ((dst & rules[i].mask) != rules[i].net)
            continue;
        if (rules[i].port == 0)
            return true;
        if ((proto == 6 || proto == 17) && dport == rules[i].port)
            return true;
    }
    return false;
}

static void log_drop(const uint8_t *f, size_t len)
{
    if (!verbose)
        return;
    if (len >= 34 && f[12] == 0x08 && f[13] == 0x00)
        fprintf(stderr, "solo5-vmnet: dropped IPv4 packet to %u.%u.%u.%u "
                        "(proto %u)\n",
                f[30], f[31], f[32], f[33], f[23]);
    else
        fprintf(stderr, "solo5-vmnet: dropped frame (ethertype 0x%02x%02x)\n",
                len >= 14 ? f[12] : 0, len >= 14 ? f[13] : 0);
}

/* vmnet -> guest */
static void pump_from_vmnet(void)
{
    static uint8_t bufs[BATCH][65536];
    struct iovec iov[BATCH];
    struct vmpktdesc pkts[BATCH];

    for (;;) {
        for (int i = 0; i < BATCH; i++) {
            iov[i].iov_base = bufs[i];
            iov[i].iov_len = max_packet_size;
            pkts[i].vm_pkt_size = max_packet_size;
            pkts[i].vm_pkt_iov = &iov[i];
            pkts[i].vm_pkt_iovcnt = 1;
            pkts[i].vm_flags = 0;
        }
        int n = BATCH;
        if (vmnet_read(iface, pkts, &n) != VMNET_SUCCESS || n == 0)
            return;
        for (int i = 0; i < n; i++) {
            /* A full socket buffer means the guest is not keeping up: drop,
             * as a NIC would. */
            (void)send(sock, bufs[i], pkts[i].vm_pkt_size, MSG_DONTWAIT);
        }
        if (n < BATCH)
            return;
    }
}

/* guest -> vmnet */
static void pump_to_vmnet(void)
{
    static uint8_t buf[65536];
    for (;;) {
        ssize_t len = recv(sock, buf, sizeof buf, MSG_DONTWAIT);
        if (len <= 0)
            return;
        if (!egress_allowed(buf, (size_t)len)) {
            log_drop(buf, (size_t)len);
            continue;
        }
        struct iovec iov = {.iov_base = buf, .iov_len = (size_t)len};
        struct vmpktdesc pkt = {.vm_pkt_size = (size_t)len,
                                .vm_pkt_iov = &iov,
                                .vm_pkt_iovcnt = 1,
                                .vm_flags = 0};
        int n = 1;
        (void)vmnet_write(iface, &pkt, &n);
    }
}

int main(int argc, char **argv)
{
    const char *net_name = "service";
    uint64_t mode = VMNET_SHARED_MODE;
    bool isolate = false;
    int i;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--") == 0) {
            i++;
            break;
        } else if (strncmp(a, "--net=", 6) == 0) {
            net_name = a + 6;
        } else if (strcmp(a, "--mode=shared") == 0) {
            mode = VMNET_SHARED_MODE;
        } else if (strcmp(a, "--mode=host") == 0) {
            mode = VMNET_HOST_MODE;
        } else if (strcmp(a, "--isolate") == 0) {
            isolate = true;
        } else if (strncmp(a, "--allow=", 8) == 0) {
            parse_rule(a + 8);
        } else if (strcmp(a, "--verbose") == 0) {
            verbose = true;
        } else {
            usage();
        }
    }
    if (i >= argc)
        usage();
    char **cmd = &argv[i];

    /* Start the vmnet interface and wait for its parameters. */
    dispatch_queue_t q =
        dispatch_queue_create("solo5-vmnet", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t started = dispatch_semaphore_create(0);
    xpc_object_t desc = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(desc, vmnet_operation_mode_key, mode);
    if (isolate)
        xpc_dictionary_set_bool(desc, vmnet_enable_isolation_key, true);

    __block vmnet_return_t start_status = VMNET_FAILURE;
    __block uint64_t mtu = 1500;
    iface = vmnet_start_interface(
        desc, q, ^(vmnet_return_t status, xpc_object_t params) {
            start_status = status;
            if (status == VMNET_SUCCESS) {
                const char *m =
                    xpc_dictionary_get_string(params, vmnet_mac_address_key);
                if (m)
                    snprintf(mac, sizeof mac, "%s", m);
                mtu = xpc_dictionary_get_uint64(params, vmnet_mtu_key);
                max_packet_size = xpc_dictionary_get_uint64(
                    params, vmnet_max_packet_size_key);
                const char *gw =
                    xpc_dictionary_get_string(params, vmnet_start_address_key);
                struct in_addr a;
                if (gw && inet_pton(AF_INET, gw, &a) == 1)
                    gateway_ip = ntohl(a.s_addr);
            }
            dispatch_semaphore_signal(started);
        });
    if (iface == NULL)
        errx(1, "vmnet_start_interface() failed");
    dispatch_semaphore_wait(started, DISPATCH_TIME_FOREVER);
    if (start_status != VMNET_SUCCESS)
        errx(1,
             "vmnet_start_interface() failed: status %u. solo5-vmnet must be "
             "code signed with the com.apple.security.virtualization "
             "entitlement (macOS 26 or newer)",
             start_status);
    if (mac[0] == 0)
        errx(1, "vmnet did not assign a MAC address");
    if (max_packet_size == 0 || max_packet_size > 65536)
        max_packet_size = 1514;

    int sp[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) == -1)
        err(1, "socketpair");
    int sz = SOCKBUF_SIZE;
    for (int k = 0; k < 2; k++) {
        setsockopt(sp[k], SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
        setsockopt(sp[k], SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
    }
    sock = sp[0];

    /*
     * Build the tender's command line: insert the network options right
     * after the tender's own name, before any of its other arguments.
     */
    int cmdc = 0;
    while (cmd[cmdc])
        cmdc++;
    char **nargv = calloc((size_t)cmdc + 4, sizeof(char *));
    if (nargv == NULL)
        err(1, "calloc");
    char netopt[128], macopt[128], mtuopt[128];
    snprintf(netopt, sizeof netopt, "--net:%s=@%d", net_name, CHILD_FD);
    snprintf(macopt, sizeof macopt, "--net-mac:%s=%s", net_name, mac);
    snprintf(mtuopt, sizeof mtuopt, "--net-mtu:%s=%llu", net_name,
             (unsigned long long)mtu);
    nargv[0] = cmd[0];
    nargv[1] = netopt;
    nargv[2] = macopt;
    nargv[3] = mtuopt;
    for (int k = 1; k < cmdc; k++)
        nargv[k + 3] = cmd[k];

    if (verbose)
        fprintf(stderr, "solo5-vmnet: %s mode, mac %s, mtu %llu, %d egress "
                        "rule(s)\n",
                mode == VMNET_SHARED_MODE ? "shared" : "host", mac,
                (unsigned long long)mtu, nrules);

    pid_t pid = fork();
    if (pid == -1)
        err(1, "fork");
    if (pid == 0) {
        if (sp[1] != CHILD_FD) {
            if (dup2(sp[1], CHILD_FD) == -1)
                err(1, "dup2");
            close(sp[1]);
        }
        close(sp[0]);
        execvp(nargv[0], nargv);
        err(127, "exec %s", nargv[0]);
    }
    close(sp[1]);

    /* Frames from vmnet. */
    vmnet_interface_set_event_callback(
        iface, VMNET_INTERFACE_PACKETS_AVAILABLE, q,
        ^(interface_event_t ev, xpc_object_t params) {
            (void)ev;
            (void)params;
            pump_from_vmnet();
        });
    /* Frames from the guest. */
    dispatch_source_t rd =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)sock, 0, q);
    dispatch_source_set_event_handler(rd, ^{
        pump_to_vmnet();
    });
    dispatch_resume(rd);

    /* Forward termination signals to the tender. */
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    for (int s = 0; s < 2; s++) {
        int signo = s ? SIGTERM : SIGINT;
        dispatch_source_t ss =
            dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, (uintptr_t)signo,
                                   0, q);
        dispatch_source_set_event_handler(ss, ^{
            kill(pid, signo);
        });
        dispatch_resume(ss);
    }

    /* When the tender exits, tear down and exit with its status. */
    dispatch_source_t ps = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_PROC, (uintptr_t)pid, DISPATCH_PROC_EXIT, q);
    dispatch_source_set_event_handler(ps, ^{
        int status;
        int rc = 1;
        if (waitpid(pid, &status, 0) == pid) {
            if (WIFEXITED(status))
                rc = WEXITSTATUS(status);
            else if (WIFSIGNALED(status))
                rc = 128 + WTERMSIG(status);
        }
        /* vmnet releases the interface when this process exits. */
        exit(rc);
    });
    dispatch_resume(ps);

    dispatch_main();
}
