/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * compiler.h - Cross-compiler attributes for amitls.library
 *
 * Use NDK-style macros from clib/compiler-specific.h:
 *   __ASM__, __REG__(r,p), __SAVE_DS__, __STDARGS__, __FAR__, etc.
 *
 * VBCC: compile with -DVBCC -sc -c (see makefile.vbcc).  vc defines __VBCC__;
 * -DVBCC selects Amiga-library conventions (SEGLISTPTR) only.
 */

#ifndef ATLS_COMPILER_H
#define ATLS_COMPILER_H

#if defined(VBCC) && !defined(__VBCC__)
#define __VBCC__
#endif

#include <exec/types.h>
#include <clib/compiler-specific.h>
#include <proto/exec.h>

#ifndef ATLS_INITTABLE_DEFINED
#define ATLS_INITTABLE_DEFINED 1
struct InitTable
{
    ULONG it_LibSize;
    APTR *it_FuncTable;
    APTR  it_DataTable;
    APTR  it_InitFunc;
};
#endif

struct MyDataInit
{
    ULONG md_Init[19];
};

/* CLib37x / VBCC: seglist from InitLib is APTR, not BPTR */
#ifdef VBCC
#ifndef SEGLISTPTR
#define SEGLISTPTR APTR
#endif

/*
 * VBCC LVO syntax (SDK/CLib37x/ReadMe.VBCC, StartUp.c):
 *   struct Foo * __saveds ASM InitLib(register __a6 ...);
 * Preprocess __saveds and ASM away; use register __aN parameters.
 */
#undef __SAVE_DS__
#define __SAVE_DS__
#undef __ASM__
#define __ASM__
#define __d0 __reg("d0")
#define __d1 __reg("d1")
#define __d2 __reg("d2")
#define __d3 __reg("d3")
#define __d4 __reg("d4")
#define __d5 __reg("d5")
#define __d6 __reg("d6")
#define __d7 __reg("d7")
#define __a0 __reg("a0")
#define __a1 __reg("a1")
#define __a2 __reg("a2")
#define __a3 __reg("a3")
#define __a4 __reg("a4")
#define __a5 __reg("a5")
#define __a6 __reg("a6")
#define __a7 __reg("a7")
#undef __REG__
#define __REG__(r, p) register __ ## r p
#endif

#endif /* ATLS_COMPILER_H */
