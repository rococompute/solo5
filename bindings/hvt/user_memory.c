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
 * user_memory.c: user memory regions, as the tender granted them
 * (tenders/hvt/hvt_user_memory.c).
 */

#include "bindings.h"

static const struct mft *mft;

void user_memory_init(const struct hvt_boot_info *bi)
{
    mft = bi->mft;
}

solo5_result_t solo5_user_memory_acquire(const char *name,
                                         struct solo5_user_memory_info *info)
{
    const struct mft_entry *e =
        mft_get_by_name(mft, name, MFT_USER_MEMORY, NULL);
    if (e == NULL)
        return SOLO5_R_EINVAL;
    assert(e->attached);

    info->address = e->u.user_memory.address;
    info->size = e->u.user_memory.size;
    return SOLO5_R_OK;
}

uint64_t user_memory_heap_start(uint64_t heap_start, uint64_t mem_size)
{
    extern char _stext[];
    uint64_t image_start = (uint64_t)&_stext;
    uint64_t image_end = heap_start;

    for (unsigned i = 0; i != mft->entries; i++) {
        const struct mft_entry *e = &mft->e[i];
        if (e->type != MFT_USER_MEMORY)
            continue;
        assert(e->attached);
        uint64_t start = e->u.user_memory.address;
        uint64_t end = start + e->u.user_memory.size;
        if (start < image_end && image_start < end)
            PANIC("User memory overlaps the image", NULL);
        if (end > mem_size)
            PANIC("User memory ends past guest memory", NULL);
        if (start >= image_end && end > heap_start)
            heap_start = end;
        log(INFO, "Solo5: user memory '%s' @ (0x%llx - 0x%llx)\n", e->name,
            (unsigned long long)start, (unsigned long long)end - 1);
    }
    return heap_start;
}
