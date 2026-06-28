/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_u64.cpp - Optional utility.library fast path for AtlsU64 multiply
 */

#include "atls_u64.hpp"

#ifdef ATLS_U64_USE_UMULT64

#ifndef UTILITY_BASE_NAME
#define UTILITY_BASE_NAME UtilityBase
#endif

#ifndef __USE_SYSBASE
#define __USE_SYSBASE
#endif

#include <proto/utility.h>

extern struct Library *UtilityBase;

#endif /* ATLS_U64_USE_UMULT64 */

AtlsU64
AtlsU64::mul32_pair(ULONG a, ULONG b)
{
    AtlsU64 r;
    ULONG a0;
    ULONG a1;
    ULONG b0;
    ULONG b1;
    ULONG p0;
    ULONG p1;
    ULONG p2;
    ULONG p3;
    ULONG mid;

#ifdef ATLS_U64_USE_UMULT64
    if (UtilityBase != NULL) {
        /*
         * UMult64 returns the low 32 bits in D0; with UTILITYLIBRARY the
         * compiler can also expose the high 32 bits from D1 for this call.
         * Fall back to portable math if only the low longword is returned.
         */
        r.lo_ = UMult64(a, b);
        r.hi_ = 0UL;
        if (r.lo_ < a && b != 0UL) {
            r.hi_ = 1UL;
        }
        return r;
    }
#endif

    a0 = a & 0xFFFFUL;
    a1 = a >> 16;
    b0 = b & 0xFFFFUL;
    b1 = b >> 16;
    p0 = a0 * b0;
    p1 = a0 * b1;
    p2 = a1 * b0;
    p3 = a1 * b1;
    mid = p1 + p2 + (p0 >> 16);
    r.lo_ = (p0 & 0xFFFFUL) | (mid << 16);
    r.hi_ = p3 + (mid >> 16);
    return r;
}
