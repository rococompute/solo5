#!/bin/sh
# Compile the real reader: malformed resources must fail before header reads.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/muen-reader.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
cat > "$tmp/test.c" <<'C'
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "reader.h"
int main(void)
{
    struct muchannel_reader reader;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    void *unmapped = mmap(NULL, page, PROT_NONE, MAP_ANON | MAP_PRIVATE, -1, 0);
    assert(unmapped != MAP_FAILED);
    uint64_t value = 0;
    for (size_t size = 0; size < sizeof(struct muchannel_header); size++) {
        muen_channel_init_reader(&reader, 42, sizeof(value), size);
        assert(muen_channel_read(unmapped, &reader, &value) == MUCHANNEL_INCOMPATIBLE_INTERFACE);
        assert(!muen_channel_has_pending_data(unmapped, &reader));
        muen_channel_drain(unmapped, &reader);
    }
    assert(munmap(unmapped, page) == 0);
    size_t bytes = sizeof(struct muchannel_header) + 2 * sizeof(value);
    struct muchannel *channel = calloc(1, bytes);
    assert(channel);
    channel->hdr.epoch = 1;
    channel->hdr.protocol = 42;
    channel->hdr.transport = SHMSTREAM20;
    channel->hdr.size = sizeof(value);
    channel->hdr.elements = 3; /* exceeds the mapped payload */
    muen_channel_init_reader(&reader, 42, sizeof(value), bytes);
    assert(muen_channel_read(channel, &reader, &value) == MUCHANNEL_INCOMPATIBLE_INTERFACE);
    channel->hdr.elements = 2;
    assert(muen_channel_read(channel, &reader, &value) == MUCHANNEL_EPOCH_CHANGED);
    uint64_t expected = 99;
    memcpy(channel->data, &expected, sizeof(expected));
    channel->hdr.wc = channel->hdr.wsc = 1;
    assert(muen_channel_has_pending_data(channel, &reader));
    assert(muen_channel_read(channel, &reader, &value) == MUCHANNEL_SUCCESS);
    assert(value == expected);
    assert(!muen_channel_has_pending_data(channel, &reader));
    channel->hdr.wc = 4;
    assert(muen_channel_read(channel, &reader, &value) == MUCHANNEL_OVERRUN_DETECTED);
    free(channel);
    puts("PASS: Muen reader bounds precede all mapped-header accesses");
    return 0;
}
C
"${CC:-cc}" -std=gnu11 -fgnu89-inline -ffreestanding -O2 -Wall -Wextra -Werror \
    -I "$root/include" -I "$root/bindings" -I "$root/bindings/muen" \
    "$tmp/test.c" "${MUEN_READER_SOURCE:-$root/bindings/muen/reader.c}" \
    "$root/bindings/muen/channel.c" -o "$tmp/check"
"$tmp/check"
