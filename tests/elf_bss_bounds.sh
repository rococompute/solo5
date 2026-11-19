#!/bin/sh
# Exercise zero-filesz LOADs in the real platform-independent ELF loader.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/elf-bss.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
cat > "$tmp/test.c" <<'C'
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "elf.h"
static unsigned calls;
#if defined(__powerpc64__)
#define PAGE 0x10000
#else
#define PAGE 0x1000
#endif
static int protect_guest(void *unused, uint64_t start, uint64_t end, int prot)
{
    (void)unused;
    if (calls++ == 0) {
        assert(start == 0x100000 && end == 0x100000 + PAGE && prot == PROT_EXEC);
    } else {
        assert(start == 0x100000 + PAGE && end == 0x100000 + 3 * PAGE);
        assert(prot == (PROT_READ | PROT_WRITE));
    }
    return 0;
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    uint8_t *memory = malloc(0x400000);
    assert(memory);
    memset(memory, 0x55, 0x400000);
    int fd = open(argv[1], O_RDONLY);
    assert(fd >= 0);
    uint64_t entry, end;
    elf_load(fd, argv[1], memory, 0x400000, 0x100000, protect_guest, NULL, &entry, &end);
    assert(entry == 0x100000 && end == 0x100000 + 3 * PAGE && calls == 2);
    for (size_t i = 0x100000 + PAGE; i < 0x100000 + 3 * PAGE; i++) assert(memory[i] == 0);
    close(fd);
    free(memory);
    return 0;
}
C
"${CC:-cc}" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -iquote "$root/tenders/common" "$tmp/test.c" \
    "${HVT_ELF_SOURCE:-$root/tenders/common/elf.c}" -o "$tmp/check"
python3 - "$tmp" <<'PY'
import pathlib,platform,struct,subprocess,sys
root=pathlib.Path(sys.argv[1])
machine={'aarch64':183,'arm64':183,'x86_64':62,'AMD64':62,'ppc64':21,'ppc64le':21,'riscv64':243}[platform.machine()]
page=0x10000 if machine==21 else 0x1000
endian='<' if sys.byteorder=='little' else '>'
ident=b'\x7fELF\x02'+bytes([1 if sys.byteorder=='little' else 2,1])+bytes(9)
header=struct.pack(endian+'16sHHIQQQIHHHHHH',ident,2,machine,1,0x100000,64,0,0,64,56,2,0,0,0)
text=struct.pack(endian+'IIQQQQQQ',1,1,page,0x100000,0,4,page,page)
for label,address,size,flags,ok in [('valid',0x100000+page,2*page,6,True),('outside',0x400000,2*page,6,False),('overflow',2**64-page,2*page,6,False),('writable-executable',0x100000+page,2*page,7,False)]:
    bss=struct.pack(endian+'IIQQQQQQ',1,flags,2*page,address,0,0,size,page)
    path=root/(label+'.elf')
    path.write_bytes((header+text+bss).ljust(page,b'\0')+b'\0'*4)
    p=subprocess.run([str(root/'check'),str(path)],capture_output=True,timeout=5)
    assert (p.returncode==0)==ok,(label,p.returncode,p.stderr)
print('PASS: pure BSS is zeroed, range-checked, protected and included in kernel_end')
PY
