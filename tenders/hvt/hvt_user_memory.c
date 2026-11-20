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
 * hvt_user_memory.c: user memory regions (MFT_USER_MEMORY).
 *
 * Guest memory is mapped readable and writable but not executable, and the
 * ELF loader grants execution only to the image's executable segments. A
 * unikernel that runs other programs on top of itself (loading their code
 * into its memory and branching to it) declares user memory in its manifest
 * instead: a region its own allocator never uses, mapped readable, writable
 * and executable, inside which it enforces its programs' protections with its
 * own page tables. Everything else keeps its W^X protection.
 *
 * A region either asks for a fixed guest-physical address (a personality
 * that runs fixed-address programs on the identity map needs that), or
 * leaves the address to the tender, which places it above the image. The
 * bindings start the heap above any region above the image (bindings/mem.c),
 * and the stack stays at the top of guest memory.
 */

#include <err.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>

#include "hvt.h"

/*
 * Where the tender places a region: on a 2 MB boundary, so that the unikernel
 * can map it with 2 MB blocks.
 */
#define USER_MEMORY_PLACE_ALIGN 0x200000UL

static uint64_t align_up(uint64_t x, uint64_t a)
{
    return (x + a - 1) & ~(a - 1);
}

static bool overlaps(uint64_t a_start, uint64_t a_end, uint64_t b_start,
                     uint64_t b_end)
{
    return a_start < b_end && b_start < a_end;
}

/*
 * Grant [start, start + size) to (e), or exit saying why it cannot be
 * granted. (granted) holds the (n_granted) entries granted so far.
 */
static void grant(struct hvt *hvt, struct mft_entry *e, uint64_t start,
                  uint64_t size, hvt_gpa_t image_start, hvt_gpa_t image_end,
                  struct mft_entry **granted, unsigned n_granted)
{
    uint64_t end;

    if (add_overflow(start, size, end))
        errx(1, "User memory '%s': address 0x%" PRIx64 " + size 0x%" PRIx64
                " overflows",
             e->name, start, size);
    if (start < HVT_GUEST_MIN_BASE)
        errx(1, "User memory '%s' at 0x%" PRIx64 " is below 0x%x, where the "
                "boot information and page tables are",
             e->name, start, HVT_GUEST_MIN_BASE);
    if (end > hvt->guest_mem_size)
        errx(1, "User memory '%s' [0x%" PRIx64 ", 0x%" PRIx64 ") ends past "
                "guest memory (0x%zx bytes); give the tender more memory "
                "with --mem",
             e->name, start, end, hvt->guest_mem_size);
    if (overlaps(start, end, image_start, image_end))
        errx(1, "User memory '%s' [0x%" PRIx64 ", 0x%" PRIx64 ") overlaps "
                "the unikernel's image [0x%" PRIx64 ", 0x%" PRIx64 ")",
             e->name, start, end, image_start, image_end);
    for (unsigned i = 0; i != n_granted; i++) {
        uint64_t g_start = granted[i]->u.user_memory.address;
        uint64_t g_end = g_start + granted[i]->u.user_memory.size;
        if (overlaps(start, end, g_start, g_end))
            errx(1, "User memory '%s' [0x%" PRIx64 ", 0x%" PRIx64 ") overlaps "
                    "user memory '%s' [0x%" PRIx64 ", 0x%" PRIx64 ")",
                 e->name, start, end, granted[i]->name, g_start, g_end);
    }
    if (hvt_guest_mprotect(hvt, start, end,
                           PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
        errx(1, "User memory '%s' [0x%" PRIx64 ", 0x%" PRIx64 "): could not "
                "map it executable",
             e->name, start, end);

    e->u.user_memory.address = start;
    e->u.user_memory.size = size;
    e->attached = true;
}

void hvt_user_memory_attach(struct hvt *hvt, struct mft *mft,
                            hvt_gpa_t image_start, hvt_gpa_t image_end)
{
    struct mft_entry *granted[MFT_MAX_ENTRIES];
    unsigned n_granted = 0;
    /* The lowest address the heap may start at: above the image and above
     * every region above the image. */
    uint64_t heap_start = image_end;

    /*
     * The manifest is untrusted: check each request before using it. Fixed
     * regions first, so that the tender places the others above them.
     */
    for (int fixed = 1; fixed >= 0; fixed--) {
        for (unsigned i = 0; i != mft->entries; i++) {
            struct mft_entry *e = &mft->e[i];
            if (e->type != MFT_USER_MEMORY)
                continue;
            uint64_t address = e->u.user_memory.address;
            uint64_t size = e->u.user_memory.size;
            if ((address != 0) != fixed)
                continue;
            if (size == 0 || (size & (MFT_USER_MEMORY_ALIGN - 1)) ||
                (address & (MFT_USER_MEMORY_ALIGN - 1)))
                errx(1, "User memory '%s': address 0x%" PRIx64 " and size "
                        "0x%" PRIx64 " must be non-zero multiples of 0x%x "
                        "(address 0: placed by the tender)",
                     e->name, address, size, MFT_USER_MEMORY_ALIGN);
            if (!fixed)
                address = align_up(heap_start, USER_MEMORY_PLACE_ALIGN);
            grant(hvt, e, address, size, image_start, image_end, granted,
                  n_granted);
            granted[n_granted++] = e;
            if (address >= image_end && address + size > heap_start)
                heap_start = address + size;
        }
    }

    if (n_granted > 0 &&
        (heap_start > hvt->guest_mem_size ||
         hvt->guest_mem_size - heap_start < HVT_GUEST_MIN_FREE))
        errx(1, "User memory leaves less than %d KB above 0x%" PRIx64
                " for the unikernel's heap and stack; give the tender more "
                "memory with --mem",
             HVT_GUEST_MIN_FREE >> 10, heap_start);
}
