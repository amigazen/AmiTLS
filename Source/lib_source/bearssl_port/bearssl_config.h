/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * bearssl_config.h - Build-time switches for vendored BearSSL trim profile
 *
 * Client TLS 1.2 ECDHE-RSA AES-128-GCM profile (from amitls13 allow-list).
 * BearSSL sources are imported in a later phase; this header documents the
 * intended configuration for atls_bearssl.c.
 */

#ifndef ATLS_BEARSSL_CONFIG_H
#define ATLS_BEARSSL_CONFIG_H

#define ATLS_BR_LOMUL             1
#define ATLS_BR_TLS12_ONLY        1
#define ATLS_BR_IOBUF_SIZE        32768

#endif /* ATLS_BEARSSL_CONFIG_H */
