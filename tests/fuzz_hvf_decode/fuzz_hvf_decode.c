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
 * fuzz_hvf_decode: check hvf_decode_exit(), which turns the syndrome and
 * IPA of a guest exception exit (both under the guest's control) into an
 * action for the macOS tender, against the hvt ABI's rules.
 *
 * Built two ways:
 *
 *   - as a libFuzzer target (with -DFUZZ_LIBFUZZER and
 *     -fsanitize=fuzzer,address,undefined), for open-ended fuzzing:
 *       make -C tests fuzz-hvf-decode && tests/fuzz_hvf_decode/fuzz -max_total_time=600
 *   - as a plain program checking a fixed number of pseudo-random inputs,
 *     biased towards the interesting ranges, which tests.bats runs.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../tenders/hvt/hvt_hvf_aarch64_decode.h"

/* The values the tender uses (include/hvt_abi.h, hvt_cpu_aarch64.h). */
#define MMIO_BASE      0x100000000ULL
#define HYPERCALL_BASE 0x100000000ULL
#define HYPERCALL_MAX  9U
#define KICK           (HYPERCALL_BASE + 0x100)

static void fail(const char *what, uint64_t esr, uint64_t ipa)
{
    fprintf(stderr,
            "fuzz_hvf_decode: %s (esr=0x%016llx ipa=0x%016llx)\n", what,
            (unsigned long long)esr, (unsigned long long)ipa);
    abort();
}

static void check(uint64_t esr, uint64_t ipa)
{
    struct hvf_exit_decision d = hvf_decode_exit(
        esr, ipa, MMIO_BASE, HYPERCALL_BASE, HYPERCALL_MAX, KICK);
    unsigned ec = (unsigned)ESR_EC(esr);
    int good_store = ESR_DABT_ISV(esr) && ESR_DABT_WNR(esr) &&
                     ESR_DABT_SAS(esr) == 2;

    switch (d.action) {
    case HVF_EXIT_HYPERCALL:
        if (ec != ESR_EC_DABT_LOW || !good_store)
            fail("hypercall from something other than a 32-bit store", esr,
                 ipa);
        if (d.nr >= HYPERCALL_MAX)
            fail("hypercall number out of range", esr, ipa);
        if (ipa != HYPERCALL_BASE + ((uint64_t)d.nr << 3))
            fail("hypercall from an address that is not its own", esr, ipa);
        if (d.srt > 31 || d.srt != ESR_DABT_SRT(esr))
            fail("bad source register", esr, ipa);
        break;
    case HVF_EXIT_RING_KICK:
        if (ec != ESR_EC_DABT_LOW || !good_store || ipa != KICK)
            fail("kick that is not a 32-bit store to the kick address", esr,
                 ipa);
        if (d.srt > 31)
            fail("bad source register", esr, ipa);
        break;
    case HVF_EXIT_STEP:
        if (ec != ESR_EC_WFX)
            fail("stepping over something other than WFI/WFE", esr, ipa);
        break;
    case HVF_EXIT_TRANSLATION_FAULT:
        if (!(ec == ESR_EC_IABT_LOW ||
              (ec == ESR_EC_DABT_LOW && ipa < MMIO_BASE)))
            fail("translation fault for the wrong exit", esr, ipa);
        break;
    case HVF_EXIT_INVALID_MMIO:
        if (ec != ESR_EC_DABT_LOW || ipa < MMIO_BASE)
            fail("invalid MMIO for the wrong exit", esr, ipa);
        break;
    case HVF_EXIT_UNHANDLED:
        if (ec == ESR_EC_DABT_LOW || ec == ESR_EC_IABT_LOW || ec == ESR_EC_WFX)
            fail("data/instruction abort or WFx left unhandled", esr, ipa);
        break;
    default:
        fail("unknown action", esr, ipa);
    }
}

/* Inputs: 8 bytes of ESR, 8 bytes of IPA, 1 byte choosing an IPA bias. */
static void run(const uint8_t *data, size_t size)
{
    uint64_t esr = 0, ipa = 0;
    uint8_t bias = 0;
    memcpy(&esr, data, size < 8 ? size : 8);
    if (size > 8)
        memcpy(&ipa, data + 8, size - 8 < 8 ? size - 8 : 8);
    if (size > 16)
        bias = data[16];
    switch (bias % 4) {
    case 1: /* near the hypercall page */
        ipa = HYPERCALL_BASE + (ipa & 0x1ff);
        break;
    case 2: /* make it a data abort */
        esr = (esr & ~(0x3fULL << 26)) | ((uint64_t)ESR_EC_DABT_LOW << 26);
        ipa = HYPERCALL_BASE + (ipa & 0x1ff);
        break;
    case 3: /* a well-formed 32-bit store, anywhere near MMIO */
        esr = ((uint64_t)ESR_EC_DABT_LOW << 26) | (1ULL << 24) | (2ULL << 22) |
              (esr & (0x1fULL << 16)) | (1ULL << 6);
        ipa = MMIO_BASE - 0x1000 + (ipa & 0x1fff);
        break;
    default:
        break;
    }
    check(esr, ipa);
}

#if defined(FUZZ_LIBFUZZER)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    run(data, size);
    return 0;
}

#else

int main(int argc, char **argv)
{
    unsigned long iterations = argc > 1 ? strtoul(argv[1], NULL, 10) : 20000000;
    uint64_t x = 0x9e3779b97f4a7c15ULL; /* fixed seed: reproducible */

    for (unsigned long i = 0; i < iterations; i++) {
        uint8_t buf[17];
        for (size_t k = 0; k < sizeof buf; k++) {
            /* xorshift64* */
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            buf[k] = (uint8_t)((x * 0x2545f4914f6cdd1dULL) >> 56);
        }
        run(buf, sizeof buf);
    }
    /* And every hypercall address, kick and boundary exactly. */
    for (uint64_t a = MMIO_BASE - 16; a < KICK + 16; a++)
        for (unsigned sas = 0; sas < 4; sas++)
            check(((uint64_t)ESR_EC_DABT_LOW << 26) | (1ULL << 24) |
                      ((uint64_t)sas << 22) | (1ULL << 6),
                  a);
    printf("SUCCESS: %lu inputs checked\n", iterations);
    return 0;
}

#endif
