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
 * test_user_memory_high: linked at 256 MB (-z solo5-text-start=0x10000000),
 * with user memory at a fixed address below the image, [2 MB, 255 MB): the
 * layout of a personality that runs fixed-address programs (linked at
 * 0x400000, say) on the identity map. The image must be where it was linked,
 * the region where the manifest says, code must run in it, and the heap must
 * be above the image.
 */

#include "solo5.h"
#include "../../bindings/lib.c"

static void puts(const char *s)
{
    solo5_console_write(s, strlen(s));
}

#if defined(__aarch64__)
/* mov w0, #42; ret */
static const uint32_t code[] = {0x52800540, 0xd65f03c0};
static void sync_code(void *p)
{
    __asm__ __volatile__("dc cvau, %0; dsb ish; ic ivau, %0; dsb ish; isb"
                         : : "r"(p) : "memory");
}
#elif defined(__x86_64__)
/* mov eax, 42; ret */
static const uint8_t code[] = {0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3};
static void sync_code(void *p __attribute__((unused)))
{
}
#else
#error Unsupported architecture
#endif

static bool runs(uintptr_t p)
{
    memcpy((void *)p, code, sizeof code);
    sync_code((void *)p);
    return ((int (*)(void))p)() == 42;
}

int solo5_app_main(const struct solo5_start_info *si)
{
    extern char _stext[];

    puts("\n**** Solo5 standalone test_user_memory_high ****\n\n");

    if ((uintptr_t)_stext != 0x10000000UL) {
        puts("the image is not linked at 0x10000000\n");
        return 1;
    }
    struct solo5_user_memory_info guest;
    if (solo5_user_memory_acquire("guest", &guest) != SOLO5_R_OK ||
        guest.address != 0x200000UL || guest.size != 0xfd00000UL) {
        puts("user memory is not where the manifest put it\n");
        return 1;
    }
    if (si->heap_start < (uintptr_t)_stext) {
        puts("the heap is below the image\n");
        return 1;
    }
    /* 0x400000: where a non-PIE Linux/aarch64 program is linked. */
    if (!runs(guest.address) || !runs(0x400000) ||
        !runs(guest.address + guest.size - 0x1000)) {
        puts("code in user memory did not run\n");
        return 1;
    }

    puts("SUCCESS\n");
    return SOLO5_EXIT_SUCCESS;
}
