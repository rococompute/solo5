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
 * hvt_hvf_aarch64_decode.h: decide what to do about a guest exception exit.
 *
 * This is the part of the HVF backend a hostile guest controls most
 * directly: the syndrome (ESR_EL2) and faulting IPA of every exception exit.
 * It is kept free of Hypervisor.framework so that it can be fuzzed on its
 * own (tests/fuzz_hvf_decode).
 */

#ifndef HVT_HVF_AARCH64_DECODE_H
#define HVT_HVF_AARCH64_DECODE_H

#include <stdint.h>

/*
 * Exception class, ESR_EL2[31:26].
 */
#define ESR_EC(esr)     (((esr) >> 26) & 0x3f)
#define ESR_EC_WFX      0x01
#define ESR_EC_HVC64    0x16
#define ESR_EC_SMC64    0x17
#define ESR_EC_SYSREG   0x18
#define ESR_EC_IABT_LOW 0x20
#define ESR_EC_DABT_LOW 0x24
#define ESR_EC_BRK64    0x3c

/*
 * Data abort ISS, ESR_EL2[24:0].
 */
#define ESR_DABT_ISV(esr) (((esr) >> 24) & 0x1)
#define ESR_DABT_SAS(esr) (((esr) >> 22) & 0x3)
#define ESR_DABT_SRT(esr) (((esr) >> 16) & 0x1f)
#define ESR_DABT_WNR(esr) (((esr) >> 6) & 0x1)

enum hvf_exit_action {
    /* A hypercall: dispatch hypercall nr with the value of register srt. */
    HVF_EXIT_HYPERCALL,
    /* A net ring kick. */
    HVF_EXIT_RING_KICK,
    /* WFI/WFE: step over the instruction. */
    HVF_EXIT_STEP,
    /* Access violating stage 2 permissions (guest W^X, or beyond RAM). */
    HVF_EXIT_TRANSLATION_FAULT,
    /* An MMIO access that is not a well-formed hypercall or kick. */
    HVF_EXIT_INVALID_MMIO,
    /* Anything else (HVC, SMC, sysreg traps, BRK, ...). */
    HVF_EXIT_UNHANDLED,
};

struct hvf_exit_decision {
    enum hvf_exit_action action;
    /* For HVF_EXIT_HYPERCALL: hypercall number, < hypercall_max. */
    unsigned nr;
    /*
     * For HVF_EXIT_HYPERCALL and HVF_EXIT_RING_KICK: the source register of
     * the store, 0..31, where 31 is the zero register.
     */
    unsigned srt;
};

/*
 * Decide what to do about an exception exit with syndrome esr at IPA ipa.
 *
 *   mmio_base:       lowest IPA that is not guest RAM (AARCH64_MMIO_BASE)
 *   hypercall_base:  HVT_HYPERCALL_MMIO_BASE
 *   hypercall_max:   HVT_HYPERCALL_MAX
 *   kick:            HVT_RING_KICK_MMIO_BASE
 *
 * The ABI only ever issues "str Wt, [Xn]" to exactly
 * hypercall_base + (nr << 3), or to kick. Anything else is rejected,
 * including an access with no valid syndrome (ISS.ISV == 0): no instruction
 * is ever decoded from guest memory.
 */
static inline struct hvf_exit_decision
hvf_decode_exit(uint64_t esr, uint64_t ipa, uint64_t mmio_base,
                uint64_t hypercall_base, unsigned hypercall_max, uint64_t kick)
{
    struct hvf_exit_decision d = {HVF_EXIT_UNHANDLED, 0, 0};

    switch (ESR_EC(esr)) {
    case ESR_EC_DABT_LOW:
        if (ipa < mmio_base) {
            d.action = HVF_EXIT_TRANSLATION_FAULT;
            break;
        }
        /* A 32-bit store with a valid syndrome. */
        if (!ESR_DABT_ISV(esr) || !ESR_DABT_WNR(esr) ||
            ESR_DABT_SAS(esr) != 2) {
            d.action = HVF_EXIT_INVALID_MMIO;
            break;
        }
        d.srt = (unsigned)ESR_DABT_SRT(esr);
        if (ipa == kick) {
            d.action = HVF_EXIT_RING_KICK;
            break;
        }
        if (ipa < hypercall_base || (ipa - hypercall_base) & 7 ||
            (ipa - hypercall_base) >> 3 >= hypercall_max) {
            d.action = HVF_EXIT_INVALID_MMIO;
            d.srt = 0;
            break;
        }
        d.action = HVF_EXIT_HYPERCALL;
        d.nr = (unsigned)((ipa - hypercall_base) >> 3);
        break;

    case ESR_EC_IABT_LOW:
        /*
         * Only reachable when the guest branches into a page the ELF loader
         * marked non-executable, or beyond guest RAM; stage 1 faults are the
         * guest's own business and never exit to us.
         */
        d.action = HVF_EXIT_TRANSLATION_FAULT;
        break;

    case ESR_EC_WFX:
        /*
         * The guest has nothing to wake it but a hypercall return, so treat
         * WFI/WFE as a no-op rather than letting it wait forever.
         */
        d.action = HVF_EXIT_STEP;
        break;

    default:
        break;
    }
    return d;
}

#endif /* HVT_HVF_AARCH64_DECODE_H */
