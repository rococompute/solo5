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
 * hvt_hvf.c: Architecture-independent part of the macOS Hypervisor.framework
 * (HVF) backend implementation.
 */

#include <assert.h>
#include <err.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "hvt.h"
#include "hvt_hvf.h"

struct hvt *hvt_init(size_t mem_size)
{
    hv_return_t ret;

    struct hvt *hvt = malloc(sizeof(struct hvt));
    if (hvt == NULL)
        err(1, "malloc");
    memset(hvt, 0, sizeof(struct hvt));
    struct hvt_b *hvb = malloc(sizeof(struct hvt_b));
    if (hvb == NULL)
        err(1, "malloc");
    memset(hvb, 0, sizeof(struct hvt_b));

    /*
     * Creating a VM requires the com.apple.security.hypervisor entitlement;
     * the tender is ad-hoc code signed with it at build time. A tender that
     * lost its signature (e.g. after strip(1)) fails here rather than anywhere
     * more subtle, so say so.
     */
    ret = hv_vm_create(NULL);
    if (ret != HV_SUCCESS)
        errx(1, "HVF: hv_vm_create() failed: 0x%x. Is the tender code signed "
                "with the com.apple.security.hypervisor entitlement?",
             ret);

    /*
     * (dinosaure, 2026-05-20): The unikernel's memory zone is set to 0, see
     * the corresponding comment in hvt_kvm.c. MAP_ANON memory is zero filled,
     * and is returned aligned to the host page size, which hv_vm_map()
     * requires.
     */
    hvt->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANON, -1, 0);
    if (hvt->mem == MAP_FAILED)
        err(1, "Error allocating guest memory");
    hvt->guest_mem_size = mem_size;
    hvt->mem_alloc_size = mem_size;

    /*
     * Guest memory is mapped at IPA 0, matching the address space layout in
     * hvt_cpu_aarch64.h. Everything above it (in particular the hypercall
     * MMIO region at AARCH64_MMIO_BASE) is deliberately left unmapped so that
     * guest accesses to it trap out as stage 2 data aborts.
     */
    ret = hv_vm_map(hvt->mem, 0, mem_size,
                    HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);
    if (ret != HV_SUCCESS)
        errx(1, "HVF: hv_vm_map() failed: 0x%x", ret);

    hvb->kick_net_pipe[0] = -1;
    hvb->kick_net_pipe[1] = -1;

    hvt->b = hvb;
    return hvt;
}

#if defined(HVT_DROP_PRIVILEGES) && HVT_DROP_PRIVILEGES == 1
void hvt_drop_privileges()
{
    /*
     * TODO: macOS offers no equivalent of seccomp(2), pledge(2) or
     * capsicum(4). The nearest fit is a sandbox(7) profile applied via the
     * deprecated sandbox_init(3), which would have to be written so as not to
     * cut off the Mach traps that hv_vcpu_run() depends on. Until that exists,
     * be loud about it rather than silently pretending to sandbox anything.
     */
    warnx("WARNING: The HVF tender does not yet drop any privileges on macOS.");
    warnx("WARNING: This is not recommended for production use.");
}
#endif

int hvt_guest_mprotect(void *t_arg, uint64_t addr_start, uint64_t addr_end,
                       int prot)
{
    struct hvt *hvt = t_arg;

    assert(addr_start <= hvt->guest_mem_size);
    assert(addr_end <= hvt->guest_mem_size);
    assert(addr_start < addr_end);

    size_t size = addr_end - addr_start;
    assert(size > 0 && size <= hvt->guest_mem_size);

    /*
     * Both mprotect() and hv_vm_protect() operate at host page granularity,
     * which is 16k on Apple silicon, whereas ELF segments are only guaranteed
     * to be aligned to the 4k architectural page size. Rounding the range
     * outward would let one segment's protections spill onto its neighbour's
     * page -- taking execute permission away from the tail of .text when
     * .rodata follows it, for instance -- so refuse to guess instead.
     *
     * Unikernels linked on macOS get -z max-page-size=0x4000 (see
     * configure.sh) and land here fully aligned; ones built elsewhere run
     * unhardened.
     */
    static bool warned_unaligned = false;
    size_t page_size = (size_t)getpagesize();
    if ((addr_start & (page_size - 1)) || (addr_end & (page_size - 1))) {
        if (!warned_unaligned) {
            warnx("Executable segments are not aligned to the host page size "
                  "(%zu bytes); page protections will not be applied",
                  page_size);
            warned_unaligned = true;
        }
        return 0;
    }

    uint8_t *vaddr_start = hvt->mem + addr_start;
    assert(vaddr_start >= hvt->mem);

    /*
     * Host-side page protections:
     *
     * Ensure that guest-executable pages are not also executable but are
     * readable in the host.
     */
    int host_prot = prot;
    if (host_prot & PROT_EXEC) {
        host_prot &= ~(PROT_EXEC);
        host_prot |= PROT_READ;
    }
    if (mprotect(vaddr_start, size, host_prot) == -1)
        return -1;

    /*
     * Guest-side page protections:
     *
     * Unlike KVM, HVF keeps stage 2 permissions independent of the host
     * mapping, so apply them explicitly. Note that guest-side X/NX is honoured
     * here, in contrast to the other backends.
     */
    hv_memory_flags_t flags = 0;
    if (prot & PROT_READ)
        flags |= HV_MEMORY_READ;
    if (prot & PROT_WRITE)
        flags |= HV_MEMORY_WRITE;
    if (prot & PROT_EXEC)
        flags |= HV_MEMORY_EXEC;
    hv_return_t ret = hv_vm_protect(addr_start, size, flags);
    if (ret != HV_SUCCESS) {
        warnx("HVF: hv_vm_protect() failed: 0x%x", ret);
        return -1;
    }

    return 0;
}
