/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * stddef.h shim - shadows system stddef when bearssl_port is first on -I.
 */

#ifndef ATLS_BEARSSL_STDDEF_H
#define ATLS_BEARSSL_STDDEF_H

#ifndef _STDDEF_H
#define _STDDEF_H
#endif

#if (defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)) \
    || defined(__VBCC__)

#ifndef size_t
typedef unsigned long size_t;
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef offsetof
#if defined(__VBCC__)
#define offsetof(type, member) __offsetof(type, member)
#else
#define offsetof(type, member) ((size_t)&(((type *)0)->member))
#endif
#endif

#else

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif

#include "bearssl_types.h"

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef ATLS_BR_SIZE_T
#define ATLS_BR_SIZE_T 1
#define size_t ULONG
#endif

#define ptrdiff_t LONG

#ifndef offsetof
#if defined(__VBCC__)
#define offsetof(type, member) __offsetof(type, member)
#else
#define offsetof(type, member) ((size_t)&(((type *)0)->member))
#endif
#endif

#endif /* __STDC_VERSION__ */

#endif /* ATLS_BEARSSL_STDDEF_H */
