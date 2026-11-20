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
 * test_user_memory: the manifest declares a fixed user memory region at
 * 16 MB (4 MB) and one the tender places (8 MB). Both must be granted where
 * the manifest says, hold code that runs, and lie below the heap. With
 * "exec_heap" on its command line, it runs code from the heap instead, which
 * must still fault: user memory leaves the rest of guest memory W^X.
 */

#include "solo5.h"
#include "../../bindings/lib.c"

static void puts(const char *s)
{
    solo5_console_write(s, strlen(s));
}

#define FIXED_ADDRESS 0x1000000UL
#define FIXED_SIZE    0x400000UL
#define PLACED_SIZE   0x800000UL

#if defined(__aarch64__)
/* mov w0, #42; ret */
static const uint32_t code[] = {0x52800540, 0xd65f03c0};
static void sync_code(void *p)
{
    __asm__ __volatile__("dc cvau, %0; dsb ish; ic ivau, %0; dsb ish; isb"
                         :
                         : "r"(p)
                         : "memory");
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

/* Copy code returning 42 to (p), run it, and say whether it returned 42. */
static bool runs(uintptr_t p)
{
    memcpy((void *)p, code, sizeof code);
    sync_code((void *)p);
    return ((int (*)(void))p)() == 42;
}

int solo5_app_main(const struct solo5_start_info *si)
{
    puts("\n**** Solo5 standalone test_user_memory ****\n\n");

    if (strcmp(si->cmdline, "exec_heap") == 0) {
        runs(si->heap_start);
        puts("code ran from the heap\n");
        return 1;
    }

    struct solo5_user_memory_info fixed, placed, none;
    if (solo5_user_memory_acquire("fixed", &fixed) != SOLO5_R_OK ||
        solo5_user_memory_acquire("placed", &placed) != SOLO5_R_OK) {
        puts("could not acquire user memory\n");
        return 1;
    }
    if (solo5_user_memory_acquire("missing", &none) != SOLO5_R_EINVAL) {
        puts("acquired undeclared user memory\n");
        return 1;
    }
    if (fixed.address != FIXED_ADDRESS || fixed.size != FIXED_SIZE) {
        puts("fixed user memory is not where the manifest put it\n");
        return 1;
    }
    /* The tender places a region on a 2 MB boundary above the image and
     * above every fixed region there. */
    if (placed.size != PLACED_SIZE || (placed.address & 0x1fffff) != 0 ||
        placed.address < fixed.address + fixed.size) {
        puts("placed user memory is not above the fixed region\n");
        return 1;
    }
    if (si->heap_start < placed.address + placed.size) {
        puts("the heap overlaps user memory\n");
        return 1;
    }
    /* Code runs anywhere in each region. */
    if (!runs(fixed.address) || !runs(fixed.address + fixed.size - 0x1000) ||
        !runs(placed.address) || !runs(placed.address + placed.size - 0x1000)) {
        puts("code in user memory did not run\n");
        return 1;
    }

    puts("SUCCESS\n");
    return SOLO5_EXIT_SUCCESS;
}
