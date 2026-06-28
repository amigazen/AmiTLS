/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * bearssl_types.h - Fixed-width types for BearSSL on Amiga compilers
 *
 * C99 (VBCC -c99): native unsigned long long / long long for uint64_t.
 * C++ (SAS/C CXXSRC): AtlsU64 class in atls_u64.hpp.
 * C89 SAS/C: 8/32-bit Amiga typedef macros only; uint64_t needs C99 or C++.
 */

#ifndef ATLS_BEARSSL_TYPES_H
#define ATLS_BEARSSL_TYPES_H

#ifdef __cplusplus

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif

#include "atls_u64.hpp"

#ifndef uint64_t
#define uint64_t AtlsU64
#endif

#ifndef int64_t
#define int64_t AtlsS64
#endif

#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)

typedef unsigned char      uint8_t;
typedef signed char        int8_t;
typedef unsigned short     uint16_t;
typedef signed short       int16_t;
typedef unsigned long      uint32_t;
typedef signed long        int32_t;
typedef unsigned long long uint64_t;
typedef signed long long   int64_t;
typedef unsigned long      uintptr_t;
typedef signed long        intptr_t;

#define UINT8_MAX   255U
#define UINT16_MAX  65535U
#define UINT32_MAX  0xFFFFFFFFUL
#define UINT64_MAX  0xFFFFFFFFFFFFFFFFULL

#else /* C89 */

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif

#ifndef ATLS_BR_WIDTH_TYPES
#define ATLS_BR_WIDTH_TYPES 1

#define uint8_t  UBYTE
#define int8_t   BYTE
#define uint16_t UWORD
#define int16_t  WORD
#define uint32_t ULONG
#define int32_t  LONG

#define UINT8_MAX   255U
#define UINT16_MAX  65535U
#define UINT32_MAX  0xFFFFFFFFUL

#endif /* ATLS_BR_WIDTH_TYPES */

#error "amitls BearSSL needs C99 (-c99) or SAS/C C++ (CXXSRC) for uint64_t"

#endif /* compiler mode */

#endif /* ATLS_BEARSSL_TYPES_H */
