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
 * test_hostile: a guest that misbehaves on purpose, one way per run, chosen
 * by its command line. Each case must end with the tender stopping the guest
 * and reporting why, never with the tender crashing or the guest getting
 * further than it should. The expected outcome of each case is in
 * tests.bats.
 *
 * The cases poke at the hvt ABI directly (MMIO hypercalls), so they are
 * aarch64-only.
 */

#include "solo5.h"
#include "../../bindings/lib.c"

static void puts(const char *s)
{
    solo5_console_write(s, strlen(s));
}

#if defined(__aarch64__)

/* See include/hvt_abi.h. */
#define HYPERCALL_BASE    0x100000000UL
#define HYPERCALL(n)      (HYPERCALL_BASE + ((n) << 3))
#define HYPERCALL_WALLTIME 1
#define HYPERCALL_NET_READ 7

static void store32(uint64_t addr, uint32_t v)
{
    __asm__ __volatile__("str %w0, [%1]" : : "rZ"(v), "r"(addr) : "memory");
}

static void store64(uint64_t addr, uint64_t v)
{
    __asm__ __volatile__("str %0, [%1]" : : "rZ"(v), "r"(addr) : "memory");
}

static uint32_t load32(uint64_t addr)
{
    uint32_t v;
    __asm__ __volatile__("ldr %w0, [%1]" : "=r"(v) : "r"(addr) : "memory");
    return v;
}

static bool run_case(const char *c)
{
    if (!strcmp(c, "spin")) {
        /* Never yields to the tender. Stopped by --cpu-limit. */
        for (;;)
            __asm__ __volatile__("" ::: "memory");
    } else if (!strcmp(c, "wfi")) {
        /* Waits for an interrupt that cannot come. Stopped by --cpu-limit. */
        for (;;)
            __asm__ __volatile__("wfi" ::: "memory");
    } else if (!strcmp(c, "hvc")) {
        __asm__ __volatile__("hvc #0" ::: "memory");
    } else if (!strcmp(c, "smc")) {
        __asm__ __volatile__("smc #0" ::: "memory");
    } else if (!strcmp(c, "hypercall_reserved")) {
        /* Hypercall 0 is reserved and has no handler. */
        store32(HYPERCALL(0), 0x10000);
    } else if (!strcmp(c, "hypercall_unregistered")) {
        /* No network is attached, so NET_READ has no handler. */
        store32(HYPERCALL(HYPERCALL_NET_READ), 0x10000);
    } else if (!strcmp(c, "hypercall_bad_gpa")) {
        /* WALLTIME writes 8 bytes at a guest address beyond guest memory. */
        store32(HYPERCALL(HYPERCALL_WALLTIME), 0xfffffff8);
    } else if (!strcmp(c, "hypercall_wide_store")) {
        /* The ABI only ever issues 32-bit stores. */
        store64(HYPERCALL(HYPERCALL_WALLTIME), 0x10000);
    } else if (!strcmp(c, "hypercall_load")) {
        (void)load32(HYPERCALL(HYPERCALL_WALLTIME));
    } else if (!strcmp(c, "mmio_unassigned")) {
        /* Above the hypercall range, not the ring kick. */
        store32(HYPERCALL_BASE + 0x800, 0);
    } else if (!strcmp(c, "beyond_ram")) {
        /* Below the MMIO base but beyond guest memory (--mem=32). */
        store32(0x40000000UL, 0);
    } else if (!strcmp(c, "console_overflow")) {
        /* A length that runs off the end of guest memory. */
        solo5_console_write("x", 0x7ffffff0);
    } else if (!strcmp(c, "hypercall_wzr")) {
        /*
         * A legitimate hypercall whose argument register is the zero
         * register (ISS.SRT == 31): WALLTIME writes to guest address 0. The
         * guest must carry on normally afterwards.
         */
        store32(HYPERCALL(HYPERCALL_WALLTIME), 0);
        return true;
    } else {
        puts("Unknown case\n");
        return false;
    }
    /* Every other case must have been stopped by the tender by now. */
    puts("Tender let the guest continue\n");
    return false;
}

#else

static bool run_case(const char *c)
{
    (void)c;
    puts("test_hostile is aarch64-only\n");
    return false;
}

#endif

int solo5_app_main(const struct solo5_start_info *si)
{
    puts("\n**** Solo5 standalone test_hostile ****\n\n");
    if (run_case(si->cmdline)) {
        puts("SUCCESS\n");
        return SOLO5_EXIT_SUCCESS;
    }
    puts("FAILURE\n");
    return SOLO5_EXIT_FAILURE;
}
