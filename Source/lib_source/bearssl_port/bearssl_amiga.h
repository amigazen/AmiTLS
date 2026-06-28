/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * bearssl_amiga.h - Single BearSSL include point for amitls.library
 */

#ifndef ATLS_BEARSSL_AMIGA_H
#define ATLS_BEARSSL_AMIGA_H

#ifndef BR_LOMUL
#define BR_LOMUL 1
#endif

/*
 * Amiga has no POSIX time() or Win32 file time; x509_minimal must use
 * br_x509_minimal_set_time() from atls_x509_engine.c (DateStamp).
 */
#ifndef BR_USE_UNIX_TIME
#define BR_USE_UNIX_TIME 0
#endif
#ifndef BR_USE_WIN32_TIME
#define BR_USE_WIN32_TIME 0
#endif

#include <stddef.h>
#include <stdint.h>
#include <bearssl.h>

#endif /* ATLS_BEARSSL_AMIGA_H */
