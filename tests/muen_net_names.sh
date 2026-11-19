#!/bin/sh
# Run the actual Muen network acquire/init path with monitor-resource stubs.
# Real MFT lookup and channel code stay linked; no Muen VM is required.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/muen-net-names.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
cat > "$tmp/test.c" <<'C'
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "solo5.h"
#include "mft.h"
#include "sinfo.h"
struct hvt_boot_info;
void net_init(const struct hvt_boot_info *);
const struct mft *muen_manifest;
static struct muen_resource_type input, output;
static char queried[2][MAX_NAME_LENGTH + 1];
static unsigned lookups;
uint64_t muen_get_sched_start(void) { return 1; }
uint64_t muen_get_sched_end(void) { return 2; }
uint64_t tscclock_epochoffset(void) { return 0; }
const char *muen_get_subject_name(void) { return "test-subject"; }
const struct muen_resource_type *muen_get_resource(const char *const name,
                                                  enum muen_resource_kind kind)
{
    assert(kind == MUEN_RES_MEMORY && lookups < 2);
    assert(strlen(name) <= MAX_NAME_LENGTH);
    strcpy(queried[lookups], name);
    return lookups++ == 0 ? &output : &input;
}
int log(int level, const char *format, ...)
{
    (void)level;
    (void)format;
    return 0;
}
void _assert_fail(const char *file, const char *line, const char *condition)
{
    fprintf(stderr, "unexpected Muen assertion: %s:%s %s\n", file, line, condition);
    _exit(70);
}
int main(void)
{
    struct mft *mft = calloc(1, sizeof(*mft) + 2 * sizeof(struct mft_entry));
    assert(mft);
    mft->entries = 2;
    mft->e[1].type = MFT_DEV_NET_BASIC;
    muen_manifest = mft;
    void *in = calloc(1, 4096), *out = calloc(1, 4096);
    assert(in && out);
    input.data.mem.kind = output.data.mem.kind = MUEN_MEM_SUBJ_CHANNEL;
    input.data.mem.address = (uintptr_t)in;
    output.data.mem.address = (uintptr_t)out;
    input.data.mem.size = output.data.mem.size = 4096;
    output.data.mem.flags = MEM_WRITABLE_FLAG;
    const size_t lengths[] = {1, MAX_NAME_LENGTH - 4, MAX_NAME_LENGTH - 3, MFT_NAME_MAX};
    for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; i++) {
        size_t length = lengths[i];
        char name[MFT_NAME_SIZE];
        memset(name, 'n', length);
        name[length] = 0;
        strcpy(mft->e[1].name, name);
        net_init(NULL);
        lookups = 0;
        solo5_handle_t handle = UINT64_MAX;
        struct solo5_net_info info;
        solo5_result_t result = solo5_net_acquire(name, &handle, &info);
        if (length <= MAX_NAME_LENGTH - 4) {
            assert(result == SOLO5_R_OK && handle == 1 && info.mtu == 1500);
            assert(lookups == 2);
            char expected[MAX_NAME_LENGTH + 1];
            memcpy(expected, name, length);
            memcpy(expected + length, "|out", sizeof "|out");
            assert(!strcmp(queried[0], expected));
            memcpy(expected + length, "|in", sizeof "|in");
            assert(!strcmp(queried[1], expected));
        } else {
            assert(result == SOLO5_R_EINVAL && lookups == 0);
            assert(handle == UINT64_MAX);
        }
    }
    free(in); free(out); free(mft);
    puts("PASS: Muen accepts 59-character device names and refuses longer names without truncation or abort");
    return 0;
}
C
"${CC:-cc}" -std=gnu11 -fgnu89-inline -ffreestanding -O2 -Wall -Wextra -Werror \
    -I "$root/include" -I "$root/bindings" -I "$root/bindings/muen" \
    -iquote "$root/tenders/common" "$tmp/test.c" \
    "${MUEN_NET_SOURCE:-$root/bindings/muen/muen-net.c}" \
    "$root/tenders/common/mft.c" "$root/bindings/muen/reader.c" \
    "$root/bindings/muen/writer.c" "$root/bindings/muen/channel.c" -o "$tmp/check"
"$tmp/check"
