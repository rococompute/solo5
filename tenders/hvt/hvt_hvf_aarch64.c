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
 * hvt_hvf_aarch64.c: aarch64 architecture-dependent part of the macOS
 * Hypervisor.framework (HVF) backend implementation.
 */

#include <assert.h>
#include <err.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hvt.h"
#include "hvt_hvf.h"
#include "hvt_cpu_aarch64.h"
#include "hvt_hvf_aarch64_decode.h"

/*
 * PSTATE bits. These come from the Linux uapi headers on the KVM backend;
 * macOS provides no equivalent, so spell out the architectural values.
 */
#define PSR_MODE_EL1h _AC(0x00000005, UL)
#define PSR_F_BIT     _AC(0x00000040, UL)
#define PSR_I_BIT     _AC(0x00000080, UL)
#define PSR_A_BIT     _AC(0x00000100, UL)
#define PSR_D_BIT     _AC(0x00000200, UL)

/*
 * Default PSTATE flags:
 * Mask Debug, Abort, IRQ and FIQ. Switch to EL1h mode
 */
#define AARCH64_PSTATE_INIT                                                    \
    (PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL1h)

/* Architectural Feature Access Control Register EL1 */
#define _FPEN_NOTRAP 0x3
#define _FPEN_SHIFT  20
#define _FPEN_MASK   GENMASK32(21, 20)

/* Memory Attribute Indirection Register EL1 */
#define MAIR(attr, mt) (_AC(attr, UL) << ((mt) * 8))

#define MAIR_EL1_INIT                                                          \
    MAIR(0x00, MT_DEVICE_nGnRnE) | MAIR(0x04, MT_DEVICE_nGnRE) |               \
        MAIR(0x0C, MT_DEVICE_GRE) | MAIR(0x44, MT_NORMAL_NC) |                 \
        MAIR(0xFF, MT_NORMAL) | MAIR(0xBB, MT_NORMAL_WT)

/*
 * TCR flags.
 */
#define TCR_T0SZ_OFFSET 0
#define TCR_T1SZ_OFFSET 16
#define TCR_T0SZ(x)     ((_AC(64, UL) - (x)) << TCR_T0SZ_OFFSET)
#define TCR_T1SZ(x)     ((_AC(64, UL) - (x)) << TCR_T1SZ_OFFSET)
#define TCR_TxSZ(x)     (TCR_T0SZ(x) | TCR_T1SZ(x))

#define TCR_IRGN0_SHIFT 8
#define TCR_IRGN0_WBWA  (_AC(1, UL) << TCR_IRGN0_SHIFT)
#define TCR_IRGN1_SHIFT 24
#define TCR_IRGN1_WBWA  (_AC(1, UL) << TCR_IRGN1_SHIFT)
#define TCR_IRGN_WBWA   (TCR_IRGN0_WBWA | TCR_IRGN1_WBWA)

#define TCR_ORGN0_SHIFT 10
#define TCR_ORGN0_WBWA  (_AC(1, UL) << TCR_ORGN0_SHIFT)
#define TCR_ORGN1_SHIFT 26
#define TCR_ORGN1_WBWA  (_AC(1, UL) << TCR_ORGN1_SHIFT)
#define TCR_ORGN_WBWA   (TCR_ORGN0_WBWA | TCR_ORGN1_WBWA)

#define TCR_SH0_SHIFT 12
#define TCR_SH0_INNER (_AC(3, UL) << TCR_SH0_SHIFT)
#define TCR_SH1_SHIFT 28
#define TCR_SH1_INNER (_AC(3, UL) << TCR_SH1_SHIFT)
#define TCR_SHARED    (TCR_SH0_INNER | TCR_SH1_INNER)

#define TCR_TG0_SHIFT 14
#define TCR_TG0_4K    (_AC(0, UL) << TCR_TG0_SHIFT)
#define TCR_TG1_SHIFT 30
#define TCR_TG1_4K    (_AC(2, UL) << TCR_TG1_SHIFT)

#define TCR_ASID16  (_AC(1, UL) << 36)
#define TCR_TBI0    (_AC(1, UL) << 37)
#define TCR_IPS_1TB (_AC(2, UL) << 32)

#define TCR_TG_FLAGS    TCR_TG0_4K | TCR_TG1_4K
#define TCR_CACHE_FLAGS TCR_IRGN_WBWA | TCR_ORGN_WBWA

/*
 * We will do 1:1 VA to PA Mapping, so we define the same address size
 * for VA and PA. 1TB size for Virtual and Physical Address Space.
 */
#define VA_BITS 40

#define TCR_EL1_INIT                                                           \
    TCR_TxSZ(VA_BITS) | TCR_CACHE_FLAGS | TCR_SHARED | TCR_TG_FLAGS |          \
        TCR_ASID16 | TCR_TBI0 | TCR_IPS_1TB

/* System Control Register EL1 */
#define _SCTLR_M  _BITUL(0)
#define _SCTLR_A  _BITUL(1)
#define _SCTLR_C  _BITUL(2)
#define _SCTLR_SA _BITUL(3)
#define _SCTLR_I  _BITUL(12)

/* A64 instructions are always 4 bytes wide. */
#define AARCH64_INSN_SIZE 4

static uint64_t aarch64_get_reg(hv_vcpu_t vcpu, hv_reg_t reg)
{
    uint64_t data;

    if (hv_vcpu_get_reg(vcpu, reg, &data) != HV_SUCCESS)
        errx(1, "HVF: hv_vcpu_get_reg(%d) failed", (int)reg);

    return data;
}

static void aarch64_set_reg(hv_vcpu_t vcpu, hv_reg_t reg, uint64_t data)
{
    if (hv_vcpu_set_reg(vcpu, reg, data) != HV_SUCCESS)
        errx(1, "HVF: hv_vcpu_set_reg(%d) failed", (int)reg);
}

static uint64_t aarch64_get_sys_reg(hv_vcpu_t vcpu, hv_sys_reg_t reg)
{
    uint64_t data;

    if (hv_vcpu_get_sys_reg(vcpu, reg, &data) != HV_SUCCESS)
        errx(1, "HVF: hv_vcpu_get_sys_reg(0x%x) failed", (unsigned)reg);

    return data;
}

static void aarch64_set_sys_reg(hv_vcpu_t vcpu, hv_sys_reg_t reg, uint64_t data)
{
    if (hv_vcpu_set_sys_reg(vcpu, reg, data) != HV_SUCCESS)
        errx(1, "HVF: hv_vcpu_set_sys_reg(0x%x) failed", (unsigned)reg);
}

static void aarch64_enable_guest_float(hv_vcpu_t vcpu)
{
    uint64_t data;

    /* Enable the floating-point and Advanced SIMD registers for Guest */
    data = aarch64_get_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1);
    data &= ~(_FPEN_MASK);
    data |= (_FPEN_NOTRAP << _FPEN_SHIFT);
    aarch64_set_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1, data);
}

static uint64_t aarch64_get_counter_frequency(void)
{
    uint64_t frq;

    __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(frq)::"memory");

    return frq;
}

static void aarch64_enable_guest_mmu(hv_vcpu_t vcpu)
{
    uint64_t data;

    /*
     * Setup Memory Attribute Indirection Register EL1, this register
     * must be set before setup page tables.
     */
    aarch64_set_sys_reg(vcpu, HV_SYS_REG_MAIR_EL1, MAIR_EL1_INIT);

    /* Setup Translation Control Register EL1 */
    aarch64_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, TCR_EL1_INIT);

    /*
     * Setup Translation Table Base Register 0 EL1. The translation range
     * doesn't exceed the 0 ~ 1^64. So the TTBR0_EL1 is enough.
     */
    aarch64_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, AARCH64_PGD_PGT_BASE);

    /*
     * Enable MMU and I/D Cache for EL1, and switch alignment checking off to
     * match the other backends. Unlike KVM, which resets SCTLR_EL1 to zero,
     * HVF hands us the architectural reset value, so preserve its RES1 bits
     * rather than assigning a bare M|C|I.
     */
    data = aarch64_get_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1);
    data |= (_SCTLR_M | _SCTLR_C | _SCTLR_I);
    data &= ~(_SCTLR_A | _SCTLR_SA);
    aarch64_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, data);
}

/*
 * Initialize registers: instruction pointer for our code, addends,
 * and PSTATE flags required by ARM64 architecture.
 * Arguments to the kernel main are passed using the ARM64 calling
 * convention: x0 ~ x7
 */
static void aarch64_setup_core_registers(struct hvt *hvt, hvt_gpa_t gpa_ep)
{
    struct hvt_b *hvb = hvt->b;

    /*
     * Set default PSTATE flags. HVF exposes the initial PSTATE of a vcpu that
     * has not run yet as CPSR, not as SPSR_EL1.
     */
    aarch64_set_reg(hvb->vcpu, HV_REG_CPSR, AARCH64_PSTATE_INIT);

    /*
     * Set Stack Poniter for Guest. ARM64 require stack be 16-bytes
     * alignment by default.
     */
    aarch64_set_sys_reg(hvb->vcpu, HV_SYS_REG_SP_EL1, hvt->guest_mem_size - 16);

    /*
     * HVF gives the guest the host's counter frequency, so read cntfrq_el0
     * directly, as the KVM backend does.
     */
    hvt->cpu_cycle_freq = aarch64_get_counter_frequency();

    /* Passing hvt_boot_info through x0 */
    aarch64_set_reg(hvb->vcpu, HV_REG_X0, AARCH64_BOOT_INFO);
    hvt->cpu_boot_info_base = AARCH64_BOOT_INFO;

    /* Set guest reset PC entry here */
    aarch64_set_reg(hvb->vcpu, HV_REG_PC, gpa_ep);
}

void hvt_vcpu_init(struct hvt *hvt, hvt_gpa_t gpa_ep)
{
    struct hvt_b *hvb = hvt->b;
    hv_return_t ret;

    /*
     * Setup aarch64 phys to virt mapping. Currently we only map 4GB for
     * RAM space and 1GB for MMIO space. Although the guest can use up
     * to 1TB address space which we configured in TCR_EL1.
     */
    aarch64_setup_memory_mapping(hvt->mem, hvt->mem_alloc_size);

    /*
     * HVF binds a vcpu to the thread that created it, and only that thread may
     * call hv_vcpu_run(). This runs on the same thread as hvt_vcpu_loop().
     */
    ret = hv_vcpu_create(&hvb->vcpu, &hvb->vcpu_exit, NULL);
    if (ret != HV_SUCCESS)
        errx(1, "HVF: hv_vcpu_create() failed: 0x%x", ret);

    /* Enable float for guest */
    aarch64_enable_guest_float(hvb->vcpu);
    /* Enable MMU for guest*/
    aarch64_enable_guest_mmu(hvb->vcpu);

    /* Initialize core registers for guest */
    aarch64_setup_core_registers(hvt, gpa_ep);

    /*
     * The guest reads time from cntvct_el0 but never arms the virtual timer,
     * and has no interrupt controller to deliver it to. Keep the timer masked
     * so that a stray CNTV_CTL_EL0 write cannot spin us on
     * HV_EXIT_REASON_VTIMER_ACTIVATED.
     */
    ret = hv_vcpu_set_vtimer_mask(hvb->vcpu, true);
    if (ret != HV_SUCCESS)
        errx(1, "HVF: hv_vcpu_set_vtimer_mask() failed: 0x%x", ret);
}

int hvt_vcpu_loop(struct hvt *hvt)
{
    struct hvt_b *hvb = hvt->b;
    hv_return_t ret;

    while (1) {
        ret = hv_vcpu_run(hvb->vcpu);
        if (ret != HV_SUCCESS)
            errx(1, "HVF: hv_vcpu_run() failed: 0x%x", ret);

        int handled = 0;
        for (hvt_vmexit_fn_t *fn = hvt_core_vmexits; *fn && !handled; fn++)
            handled = ((*fn)(hvt) == 0);
        if (handled)
            continue;

        switch (hvb->vcpu_exit->reason) {
        case HV_EXIT_REASON_EXCEPTION:
            break;

        case HV_EXIT_REASON_CANCELED:
            continue;

        case HV_EXIT_REASON_VTIMER_ACTIVATED:
            /* Masked at init; re-mask and carry on if it fires anyway. */
            hv_vcpu_set_vtimer_mask(hvb->vcpu, true);
            continue;

        default:
            errx(1, "HVF: unhandled exit: reason=0x%x, pc=0x%" PRIx64,
                 hvb->vcpu_exit->reason,
                 aarch64_get_reg(hvb->vcpu, HV_REG_PC));
        }

        uint64_t esr = hvb->vcpu_exit->exception.syndrome;
        uint64_t ipa = hvb->vcpu_exit->exception.physical_address;
        uint64_t va = hvb->vcpu_exit->exception.virtual_address;
        struct hvf_exit_decision d = hvf_decode_exit(
            esr, ipa, AARCH64_MMIO_BASE, HVT_HYPERCALL_MMIO_BASE,
            HVT_HYPERCALL_MAX, HVT_RING_KICK_MMIO_BASE);

        switch (d.action) {
        case HVF_EXIT_TRANSLATION_FAULT:
            /*
             * Reported the way the other backends report the equivalent
             * failure: a write to a page the ELF loader marked read-only,
             * say, or a branch into a non-executable one.
             */
            errx(1,
                 "HVF: host/guest translation fault: pc=0x%" PRIx64
                 ", va=0x%" PRIx64 ", pa=0x%" PRIx64,
                 aarch64_get_reg(hvb->vcpu, HV_REG_PC), va, ipa);

        case HVF_EXIT_INVALID_MMIO:
            errx(1,
                 "Invalid guest mmio access: mmio=0x%" PRIx64 ", esr=0x%" PRIx64
                 ", pc=0x%" PRIx64,
                 ipa, esr, aarch64_get_reg(hvb->vcpu, HV_REG_PC));

        case HVF_EXIT_UNHANDLED:
            errx(1,
                 "HVF: unhandled exception: ec=0x%x, esr=0x%" PRIx64
                 ", va=0x%" PRIx64 ", pa=0x%" PRIx64 ", pc=0x%" PRIx64,
                 (unsigned)ESR_EC(esr), esr, va, ipa,
                 aarch64_get_reg(hvb->vcpu, HV_REG_PC));

        case HVF_EXIT_STEP:
            aarch64_set_reg(hvb->vcpu, HV_REG_PC,
                            aarch64_get_reg(hvb->vcpu, HV_REG_PC) +
                                AARCH64_INSN_SIZE);
            break;

        case HVF_EXIT_RING_KICK:
        case HVF_EXIT_HYPERCALL: {
            /*
             * Unlike KVM, HVF neither decodes the access for us nor steps
             * over the faulting store. SRT == 31 is the zero register.
             */
            uint64_t data =
                (d.srt == 31) ? 0
                              : aarch64_get_reg(hvb->vcpu, HV_REG_X0 + d.srt);
            aarch64_set_reg(hvb->vcpu, HV_REG_PC,
                            aarch64_get_reg(hvb->vcpu, HV_REG_PC) +
                                AARCH64_INSN_SIZE);

            if (d.action == HVF_EXIT_RING_KICK) {
                /*
                 * HVF has no ioeventfd equivalent, so wake the I/O thread by
                 * hand as the BSD backends do. The pipe is non-blocking: a
                 * full pipe already means a kick is pending.
                 */
                if (hvb->kick_net_pipe[1] != -1) {
                    uint8_t byte = 1;
                    (void)!write(hvb->kick_net_pipe[1], &byte, 1);
                }
                break;
            }

            hvt_gpa_t gpa = (uint32_t)data;

            /* Guest has halted the CPU. */
            if (d.nr == HVT_HYPERCALL_HALT)
                return hvt_core_hypercall_halt(hvt, gpa);

            hvt_hypercall_fn_t fn = hvt_core_hypercalls[d.nr];
            if (fn == NULL)
                errx(1, "Invalid guest hypercall: num=%u", d.nr);

            fn(hvt, gpa);
            break;
        }
        }
    }
}

void hvt_mem_size(size_t *mem_size)
{
    aarch64_mem_size(mem_size);
}

void hvt_mem_size_roundup(size_t *mem_size)
{
    size_t mem = ((*mem_size + AARCH64_GUEST_BLOCK_SIZE - 1) /
                  AARCH64_GUEST_BLOCK_SIZE) *
                 AARCH64_GUEST_BLOCK_SIZE;
    if (mem > AARCH64_MMIO_BASE)
        mem = AARCH64_MMIO_BASE;
    *mem_size = mem;
}
