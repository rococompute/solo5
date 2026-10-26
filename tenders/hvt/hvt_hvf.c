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
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "hvt.h"
#include "hvt_hvf.h"

/* Stage 2 granule requested in hvt_init(); see there. */
#define HVF_IPA_GRANULE_SIZE 0x1000UL

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
     * Solo5 aarch64 guests are linked with 4 KiB aligned segments, but HVF
     * defaults to the 16 KiB host page size for stage 2. Ask for a 4 KiB IPA
     * granule so that hvt_guest_mprotect() can protect each segment exactly.
     * The public API for this first appeared in macOS 26.
     */
    hv_vm_config_t config = NULL;
    if (__builtin_available(macOS 26.0, *)) {
        config = hv_vm_config_create();
        if (config == NULL)
            errx(1, "HVF: hv_vm_config_create() failed");
        ret = hv_vm_config_set_ipa_granule(config, HV_IPA_GRANULE_4KB);
        if (ret != HV_SUCCESS)
            errx(1, "HVF: hv_vm_config_set_ipa_granule(4KB) failed: 0x%x",
                 ret);
    } else {
        errx(1, "HVF: macOS 26 or newer is required (for a 4 KiB IPA "
                "granule)");
    }

    /*
     * Creating a VM requires the com.apple.security.hypervisor entitlement;
     * the tender is ad-hoc code signed with it at build time. A tender that
     * lost its signature (e.g. after strip(1)) fails here rather than anywhere
     * more subtle, so say so.
     */
    ret = hv_vm_create(config);
    os_release(config);
    if (ret == HV_DENIED)
        errx(1, "HVF: hv_vm_create() was denied. The tender must be code "
                "signed with the com.apple.security.hypervisor entitlement; "
                "re-sign it with: codesign --force --sign - --entitlements "
                "solo5-hvt.entitlements <path to solo5-hvt>");
    if (ret != HV_SUCCESS)
        errx(1, "HVF: hv_vm_create() failed: 0x%x", ret);

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
     * Host-side page protections:
     *
     * None. Guest memory stays PROT_READ | PROT_WRITE (never PROT_EXEC) in
     * the host for the lifetime of the tender. Host pages are 16 KiB, so
     * mprotect() could not follow 4 KiB segment boundaries anyway, and HVF
     * stage 2 permissions do not depend on the host mapping.
     *
     * Guest-side page protections:
     *
     * Applied at stage 2 with the 4 KiB IPA granule set up in hvt_init(), so
     * every segment gets exactly its own permissions. Unlike on KVM, guest
     * X/NX is enforced too, as is execute-only.
     */
    if ((addr_start & (HVF_IPA_GRANULE_SIZE - 1)) ||
        (addr_end & (HVF_IPA_GRANULE_SIZE - 1))) {
        warnx("HVF: segment [0x%" PRIx64 ", 0x%" PRIx64 ") is not 4 KiB "
              "aligned",
              addr_start, addr_end);
        errno = EINVAL;
        return -1;
    }
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
