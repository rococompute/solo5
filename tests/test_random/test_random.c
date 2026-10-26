/*
 * Copyright (c) 2026 Contributors as noted in the AUTHORS file
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
 * test_random: solo5_random() returns host random bytes, and rejects what it
 * should. Run with "fallback" under a tender that does not offer random
 * bytes (solo5-hvt --no-random, or another target), where solo5_random()
 * must return SOLO5_R_EUNSPEC without the guest being stopped.
 */

#include <stdarg.h>
#include <stddef.h>

#include "solo5.h"
#include "../../bindings/lib.c"
#include "../../bindings/printf.c"

static void printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void printf(const char *fmt, ...)
{
    char buffer[1024];
    va_list args;
    size_t size;

    va_start(args, fmt);
    size = vsnprintf(buffer, sizeof buffer, fmt, args);
    va_end(args);

    if (size >= sizeof buffer)
        size = sizeof buffer - 1;
    solo5_console_write(buffer, size);
}

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

static bool all_zero(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (buf[i] != 0)
            return false;
    return true;
}

static bool all_equal(const uint8_t *buf, size_t len, uint8_t v)
{
    for (size_t i = 0; i < len; i++)
        if (buf[i] != v)
            return false;
    return true;
}

static uint8_t big[8192];

static bool test_random(void)
{
    uint8_t a[32] = {0}, b[32] = {0};

    if (solo5_random(a, sizeof a) != SOLO5_R_OK ||
        solo5_random(b, sizeof b) != SOLO5_R_OK) {
        printf("ERROR: solo5_random() failed\n");
        return false;
    }
    print_hex("first", a, sizeof a);
    print_hex("second", b, sizeof b);
    if (all_zero(a, sizeof a) || all_zero(b, sizeof b)) {
        printf("ERROR: all-zero output\n");
        return false;
    }
    if (memcmp(a, b, sizeof a) == 0) {
        printf("ERROR: two calls returned the same bytes\n");
        return false;
    }

    /* An empty request succeeds and does nothing. */
    if (solo5_random(a, 0) != SOLO5_R_OK) {
        printf("ERROR: zero-length request failed\n");
        return false;
    }

    /* Too large: refused, buffer untouched, guest carries on. */
    memset(big, 0xa5, sizeof big);
    if (solo5_random(big, sizeof big) != SOLO5_R_EINVAL) {
        printf("ERROR: oversized request was not refused\n");
        return false;
    }
    if (!all_equal(big, sizeof big, 0xa5)) {
        printf("ERROR: oversized request changed the buffer\n");
        return false;
    }

    /* The largest allowed request fills all of it. */
    memset(big, 0, sizeof big);
    if (solo5_random(big, 4096) != SOLO5_R_OK) {
        printf("ERROR: 4096-byte request failed\n");
        return false;
    }
    if (all_zero(big + 4064, 32) || !all_zero(big + 4096, 32)) {
        printf("ERROR: 4096-byte request filled the wrong range\n");
        return false;
    }
    return true;
}

static bool test_fallback(void)
{
    uint8_t a[32] = {0};

    if (solo5_random(a, sizeof a) != SOLO5_R_EUNSPEC) {
        printf("ERROR: expected SOLO5_R_EUNSPEC\n");
        return false;
    }
    if (!all_zero(a, sizeof a)) {
        printf("ERROR: buffer changed\n");
        return false;
    }
    printf("fallback\n");
    return true;
}

int solo5_app_main(const struct solo5_start_info *si)
{
    printf("\n**** Solo5 standalone test_random ****\n\n");

    bool ok = strcmp(si->cmdline, "fallback") == 0 ? test_fallback()
                                                   : test_random();
    if (!ok)
        return SOLO5_EXIT_FAILURE;
    printf("SUCCESS\n");
    return SOLO5_EXIT_SUCCESS;
}
