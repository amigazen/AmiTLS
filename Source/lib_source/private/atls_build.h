/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_build.h - amitls.library build identity
 */

#ifndef ATLS_PRIVATE_ATLS_BUILD_H
#define ATLS_PRIVATE_ATLS_BUILD_H

#define ATLS_LIB_VERSION   1
#define ATLS_LIB_REVISION  2
#define ATLS_BUILD_ID      20260628L
#define ATLS_BUILD_ID_STR  "20260628"

/*
 * BearSSL X.509 dates use days since 1978-01-01 via Amiga DateStamp, mapped
 * with the Unix-epoch day count from bearssl_x509.h (year 0 AD calendar).
 * Do NOT use 722084: that value assumes year 1 = day 0 and makes live certs
 * look not-yet-valid (BearSSL brerr 54 / ERROR_TLS_VERIFY).
 */
#define ATLS_BR_UNIX_EPOCH_DAYS   719528UL
#define ATLS_AMIGA_EPOCH_UNIX_DAYS 2922UL
#define ATLS_BR_EPOCH_DAYS  (ATLS_BR_UNIX_EPOCH_DAYS + ATLS_AMIGA_EPOCH_UNIX_DAYS)
#define ATLS_BR_EPOCH_STR  "722450"
#define ATLS_SUITE_COUNT   3

#endif /* ATLS_PRIVATE_ATLS_BUILD_H */
