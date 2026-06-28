/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_x509_engine.h - BearSSL X.509 validator selection (insecure vs minimal)
 */

#ifndef ATLS_X509_ENGINE_H
#define ATLS_X509_ENGINE_H

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif

#include "atls_x509_insecure.h"
#include "bearssl_amiga.h"

#define ATLS_X509_INSECURE  0
#define ATLS_X509_MINIMAL   1

struct TlsContext;
struct br_ssl_engine_context;

typedef struct AtlsX509Engine
{
    ULONG                     xe_Mode;
    union {
        AtlsInsecureX509Context insecure;
        br_x509_minimal_context minimal;
    } xe_u;
    const br_x509_class      *xe_Vtable;
} AtlsX509Engine;

LONG atls_x509_engine_init(AtlsX509Engine *eng, struct TlsContext *ctx,
    ULONG verify_mode, struct br_ssl_engine_context *ssl_eng);
VOID atls_x509_engine_clear(AtlsX509Engine *eng);
VOID atls_x509_engine_refresh_time(AtlsX509Engine *eng);
BOOL atls_x509_engine_have_pkey(const AtlsX509Engine *eng);
const br_x509_class **atls_x509_engine_vtable_ref(AtlsX509Engine *eng);

#endif /* ATLS_X509_ENGINE_H */
