/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_x509_insecure.h - Accept-any-chain X.509 handler for BearSSL client
 */

#ifndef ATLS_X509_INSECURE_H
#define ATLS_X509_INSECURE_H

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif

#include "bearssl_amiga.h"

typedef struct AtlsInsecureX509Context
{
    const br_x509_class      *ix_vtable;
    br_x509_decoder_context   ix_decoder;
    br_x509_pkey              ix_pkey;
    UBYTE                     ix_key_data[BR_X509_BUFSIZE_KEY];
    size_t                    ix_key_data_len;
    UBYTE                     ix_leaf_key_sha256[32];
    UWORD                     ix_cert_index;
    UBYTE                     ix_have_pkey;
    UBYTE                     ix_failed;
} AtlsInsecureX509Context;

VOID atls_x509_insecure_init(AtlsInsecureX509Context *ctx);

#endif /* ATLS_X509_INSECURE_H */
