/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_bearssl.h - BearSSL per-connection engine state (library private)
 */

#ifndef ATLS_PRIVATE_ATLS_BEARSSL_H
#define ATLS_PRIVATE_ATLS_BEARSSL_H

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif

#include "bearssl_amiga.h"
#include "atls_x509_engine.h"

struct AtlsBearSslState
{
    br_ssl_client_context     br_sc;
    br_sslio_context          br_ioc;
    AtlsX509Engine            br_x509;
    UBYTE                    *br_iobuf;
    UBYTE                     br_active;
    UBYTE                     br_broken;
    UBYTE                     br_suppress_alerts;
};

#endif /* ATLS_PRIVATE_ATLS_BEARSSL_H */
