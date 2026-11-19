#!/bin/sh
# Exercise production hypercall and ring handlers against real backpressure.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/hvt-net-pressure.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
python3 - "${HVT_NET_SOURCE:-$root/tenders/hvt/hvt_module_net.c}" "$tmp/handlers.c" <<'PY'
import pathlib, sys
source = pathlib.Path(sys.argv[1]).read_text()
start = source.index('static void hypercall_net_write(')
end = source.index('\nstatic void *io_thread_net_fn(', start)
pathlib.Path(sys.argv[2]).write_text(source[start:end])
PY
cat > "$tmp/test.c" <<'C'
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "hvt.h"
#include "hvt_ring.h"
#include "solo5.h"
static struct mft *host_mft;
#include "handlers.c"
static void check_backpressure(bool datagram)
{
    int fd[2];
    if (datagram) {
        assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, fd) == 0);
    } else {
        int ends[2];
        assert(pipe(ends) == 0);
        fd[0] = ends[1];
        fd[1] = ends[0];
    }
    assert(fcntl(fd[0], F_SETFL, O_NONBLOCK) == 0);
    assert(fcntl(fd[1], F_SETFL, O_NONBLOCK) == 0);
    host_mft = calloc(1, sizeof(*host_mft) + 2 * sizeof(struct mft_entry));
    assert(host_mft);
    host_mft->entries = 2;
    host_mft->e[0].type = MFT_RESERVED_FIRST;
    host_mft->e[1].type = MFT_DEV_NET_BASIC;
    host_mft->e[1].b.hostfd = fd[0];
    uint8_t memory[256] = {0};
    struct hvt hvt = {.mem = memory, .guest_mem_size = sizeof(memory)};
    struct hvt_hc_net_write *wr = (void *)memory;
    wr->handle = 1;
    wr->data = 128;
    wr->len = 1;
    wr->ret = SOLO5_R_EINVAL;
    hypercall_net_write(&hvt, 0);
    assert(wr->ret == SOLO5_R_OK);
    unsigned filled = 0;
    while (write(fd[0], memory + 128, 1) == 1)
        assert(++filled < 1000000);
    assert(errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS);
    wr->ret = SOLO5_R_EINVAL;
    hypercall_net_write(&hvt, 0);
    assert(wr->ret == SOLO5_R_OK);
    struct hvt_ring *ring = calloc(1, sizeof(*ring));
    assert(ring);
    for (unsigned i = 0; i < 3; ++i) {
        ring->entries[i].operation = HVT_RING_NET_WRITE;
        ring->entries[i].handle = 1;
        ring->entries[i].data = 128;
        ring->entries[i].len = 1;
    }
    ring->ent_tail = 3;
    process_ring_commits(&hvt, ring);
    assert(ring->ent_head == 3 && ring->com_tail == 0);
    while (read(fd[1], memory + 129, 1) == 1) {}
    assert(errno == EAGAIN || errno == EWOULDBLOCK);
    hypercall_net_write(&hvt, 0);
    assert(read(fd[1], memory + 129, 1) == 1);
    assert(memory[129] == memory[128]);
    close(fd[0]);
    close(fd[1]);
    free(host_mft);
    free(ring);
}
int main(void)
{
    check_backpressure(false);
    check_backpressure(true);
    puts("PASS: hypercall and ring writes tolerate transient backpressure");
    return 0;
}
C
"${CC:-cc}" -std=gnu11 -O1 -Wall -Wextra -Werror -Wno-unused-function \
    -I "$tmp" -I "$root/include" -I "$root/tenders/common" \
    -I "$root/tenders/hvt" "$tmp/test.c" "$root/tenders/common/mft.c" \
    -o "$tmp/check"
"$tmp/check"
