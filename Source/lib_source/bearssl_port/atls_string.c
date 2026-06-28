/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * Minimal string helpers for VBCC -nostdlib library links (_memcmp, _memmove).
 */

#include <stddef.h>

int
_memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *a;
    const unsigned char *b;
    size_t i;

    a = (const unsigned char *)s1;
    b = (const unsigned char *)s2;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return (int)a[i] - (int)b[i];
        }
    }
    return 0;
}

void *
_memmove(void *dst, const void *src, size_t n)
{
    unsigned char *d;
    const unsigned char *s;
    size_t i;

    d = (unsigned char *)dst;
    s = (const unsigned char *)src;
    if (d == s || n == 0) {
        return dst;
    }
    if (d < s) {
        for (i = 0; i < n; i++) {
            d[i] = s[i];
        }
    } else {
        for (i = n; i > 0; i--) {
            d[i - 1] = s[i - 1];
        }
    }
    return dst;
}
