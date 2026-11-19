#!/bin/sh
# Run the actual ring handlers with bounded synthetic submissions, without
# attaching a network device or launching a guest.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/hvt-ring-bounds.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
python3 - "${HVT_NET_SOURCE:-$root/tenders/hvt/hvt_module_net.c}" "$tmp/handlers.c" <<'PY'
import pathlib,sys
source=pathlib.Path(sys.argv[1]).read_text()
start=source.index('static void hypercall_net_write(')
end=source.index('\nstatic void *io_thread_net_fn(',start)
pathlib.Path(sys.argv[2]).write_text(source[start:end])
PY
cat > "$tmp/test.c" <<'C'
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "hvt.h"
#include "hvt_ring.h"
#include "solo5.h"
static struct mft *host_mft;
static struct hvt_ring *changing_ring;
static unsigned writes;
static ssize_t test_write(int fd, const void *data, size_t size)
{
    (void)fd;
    (void)data;
    writes++;
    if (changing_ring && writes == 1)
        changing_ring->ent_head = 2; /* untrusted shared-memory change */
    return (ssize_t)size;
}
#define write test_write
#include "handlers.c"
#undef write
int main(int argc, char **argv)
{
    assert(argc == 2);
    struct hvt_ring *ring = calloc(1, sizeof(*ring));
    host_mft = calloc(1, sizeof(*host_mft) + 2 * sizeof(struct mft_entry));
    assert(ring && host_mft);
    host_mft->entries = 2;
    host_mft->e[0].type = MFT_RESERVED_FIRST;
    host_mft->e[1].type = MFT_DEV_NET_BASIC;
    unsigned char memory[256] = {0};
    struct hvt hvt = {.mem = memory, .guest_mem_size = sizeof(memory)};
    if (!strcmp(argv[1], "bad-submission")) {
        ring->ent_tail = HVT_RING_SIZE + 1;
        process_ring_commits(&hvt, ring);
        return 0; /* must be rejected, even for unknown operation entries */
    }
    ring->ent_tail = 1;
    ring->entries[0].operation = HVT_RING_NET_READ;
    ring->entries[0].handle = 63; /* invalid device => bounded EINVAL completion */
    ring->entries[0].id = 42;
    if (!strcmp(argv[1], "bad-completion")) {
        ring->com_tail = HVT_RING_SIZE + 1;
        process_ring_commits(&hvt, ring);
        return 0;
    }
    if (!strcmp(argv[1], "full")) {
        ring->com_tail = HVT_RING_SIZE;
        ring->commits[0].id = 123;
        process_ring_commits(&hvt, ring);
        assert(ring->ent_head == 0 && ring->com_tail == HVT_RING_SIZE);
        assert(ring->commits[0].id == 123);
        ring->com_head = 1;
        process_ring_commits(&hvt, ring);
        assert(ring->ent_head == 1 && ring->com_tail == HVT_RING_SIZE + 1);
        assert(ring->commits[0].id == 42);
    } else if (!strcmp(argv[1], "wrap")) {
        uint32_t start = UINT32_MAX - 1;
        ring->ent_head = ring->com_head = ring->com_tail = start;
        ring->ent_tail = start + 3;
        for (uint32_t i = 0; i < 3; i++) {
            ring->entries[(start + i) & HVT_RING_MASK].operation = HVT_RING_NET_READ;
            ring->entries[(start + i) & HVT_RING_MASK].handle = 63;
            ring->entries[(start + i) & HVT_RING_MASK].id = i + 10;
        }
        process_ring_commits(&hvt, ring);
        assert(ring->ent_head == start + 3 && ring->com_tail == start + 3);
        for (uint32_t i = 0; i < 3; i++)
            assert(ring->commits[(start + i) & HVT_RING_MASK].id == i + 10);
    } else {
        assert(!strcmp(argv[1], "changed-head"));
        changing_ring = ring;
        ring->ent_tail = 3;
        for (unsigned i = 0; i < 3; i++) {
            ring->entries[i].operation = HVT_RING_NET_WRITE;
            ring->entries[i].handle = 1;
            ring->entries[i].data = 128;
            ring->entries[i].len = 1;
        }
        process_ring_commits(&hvt, ring);
        assert(writes == 3 && ring->ent_head == 3);
    }
    free(host_mft);
    free(ring);
    return 0;
}
C
"${CC:-cc}" -std=gnu11 -O2 -Wall -Wextra -Werror -Wno-unused-function \
    -I "$tmp" -I "$root/include" -iquote "$root/tenders/common" \
    -iquote "$root/tenders/hvt" "$tmp/test.c" "$root/tenders/common/mft.c" \
    -o "$tmp/check"
python3 - "$tmp/check" <<'PY'
import subprocess,sys
for mode,expected in [('bad-submission',1),('bad-completion',1),('full',0),('wrap',0),('changed-head',0)]:
    p=subprocess.run([sys.argv[1],mode],capture_output=True,timeout=5)
    assert p.returncode==expected,(mode,p.returncode,p.stderr)
print('PASS: bounded ring submissions, completion backpressure, wraparound and local host indices')
PY
