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
 * user_memory_none.c: targets without user memory (all but hvt). Their
 * tenders attach no USER_MEMORY entry, so a manifest declaring one does not
 * run there.
 */

#include "bindings.h"

solo5_result_t solo5_user_memory_acquire(const char *name
                                         __attribute__((unused)),
                                         struct solo5_user_memory_info *info
                                         __attribute__((unused)))
{
    return SOLO5_R_EUNSPEC;
}

uint64_t user_memory_heap_start(uint64_t heap_start,
                                uint64_t mem_size __attribute__((unused)))
{
    return heap_start;
}
