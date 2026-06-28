/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_trust.h - Per-context CA trust store (PEM bundle loading)
 */

#ifndef ATLS_TRUST_H
#define ATLS_TRUST_H

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif

struct TlsContext;

VOID atls_trust_clear(struct TlsContext *ctx);
VOID atls_trust_global_clear(struct AmiTlsBase *base);
LONG atls_trust_ensure(struct TlsContext *ctx);
ULONG atls_trust_anchor_count(struct TlsContext *ctx);
/*
 * Trust anchor array; layout is br_x509_trust_anchor (bearssl_x509.h).
 * Callers that use BearSSL types must cast the result.
 */
APTR atls_trust_anchors(struct TlsContext *ctx);

#endif /* ATLS_TRUST_H */
