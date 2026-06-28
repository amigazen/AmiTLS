/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * VBCC 68000 runtime helpers __lmodu / __lmods for 32-bit modulo when the
 * CPU has no div.l (68000/68010).  Implemented with utility.library
 * UDivMod32 / SDivMod32 (V36): quotient in D0, remainder in D1.
 *
 * C prototypes only return D0, so remainder is reconstructed as
 * dividend - quotient * divisor (see clib/utility_protos.h).
 *
 * https://developer.amigaos3.net/autodocs/utility.library/UDivMod32.html
 */

#include <exec/types.h>

#include <proto/utility.h>

extern struct Library *UtilityBase;

unsigned long
_lmodu(unsigned long dividend, unsigned long divisor)
{
    ULONG quotient;

    if (divisor == 0UL) {
        return 0UL;
    }
    quotient = UDivMod32((ULONG)dividend, (ULONG)divisor);
    return (ULONG)dividend - UMult32(quotient, (ULONG)divisor);
}

long
_lmods(long dividend, long divisor)
{
    LONG quotient;

    if (divisor == 0L) {
        return 0L;
    }
    quotient = SDivMod32(dividend, divisor);
    return dividend - SMult32(quotient, divisor);
}
