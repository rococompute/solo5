#!/bin/sh
# Run the production option handler and manifest lookup without attaching a NIC.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/hvt-net-names.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
python3 - "${HVT_NET_SOURCE:-$root/tenders/hvt/hvt_module_net.c}" "$tmp/cmdarg.c" <<'PY'
import pathlib, sys
source = pathlib.Path(sys.argv[1]).read_text()
start = source.index('static int requested_mtu[')
end = source.index('\nstatic int setup(', start)
pathlib.Path(sys.argv[2]).write_text(source[start:end])
PY
cat > "$tmp/test.c" <<'C'
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mft.h"
#define STR(x) #x
#define XSTR(x) STR(x)
static bool module_in_use;
static int tap_attach(const char *name, int *mtu)
{
    assert(!strcmp(name, "@7"));
    *mtu = 1500;
    return 7;
}
#include "cmdarg.c"
int main(void)
{
    char longest[MFT_NAME_SIZE];
    memset(longest, 'n', MFT_NAME_MAX);
    longest[MFT_NAME_MAX - 1] = '_';
    longest[MFT_NAME_MAX] = 0;
    const char *names[] = {"net0", "net-0", "net_0", "_-", longest};
    unsigned checks = 0;
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        struct mft *mft = calloc(1, sizeof(*mft) + 2 * sizeof(struct mft_entry));
        assert(mft);
        mft->entries = 2;
        mft->e[0].type = MFT_RESERVED_FIRST;
        mft->e[1].type = MFT_DEV_NET_BASIC;
        strcpy(mft->e[1].name, names[i]);
        memset(requested_mtu, 0, sizeof(requested_mtu));
        memset(attached_fd, 0, sizeof(attached_fd));
        char arg[256];
        snprintf(arg, sizeof(arg), "--net-mtu:%s=1400", names[i]);
        assert(handle_cmdarg(arg, mft) == 0);
        snprintf(arg, sizeof(arg), "--net-mac:%s=02:11:22:33:44:55", names[i]);
        assert(handle_cmdarg(arg, mft) == 0);
        snprintf(arg, sizeof(arg), "--net:%s=@7", names[i]);
        assert(handle_cmdarg(arg, mft) == 0);
        assert(mft->e[1].attached && mft->e[1].b.hostfd == 7);
        assert(mft->e[1].u.net_basic.mtu == 1400);
        const uint8_t mac[] = {2, 17, 34, 51, 68, 85};
        assert(!memcmp(mft->e[1].u.net_basic.mac, mac, sizeof(mac)));
        checks += 3;
        assert(handle_cmdarg("--net-mtu:missing=1400", mft) == -1);
        assert(handle_cmdarg("--net-mtu:net.0=1400", mft) == -1);
        checks += 2;
        free(mft);
    }
    printf("PASS: %u production network-name checks\n", checks);
    return 0;
}
C
"${CC:-cc}" -std=gnu11 -Wall -Wextra -Werror -I "$tmp" \
    -I "$root/include" -I "$root/tenders/common" \
    "$tmp/test.c" "$root/tenders/common/mft.c" -o "$tmp/check"
"$tmp/check"
