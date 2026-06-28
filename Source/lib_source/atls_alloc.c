/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_alloc.c - AllocMem helpers for amitls.library
 */


#include <exec/types.h>
#include <exec/memory.h>

#include <proto/exec.h>

#include "private/atls_internal.h"

STRPTR
atls_strdup(STRPTR s)
{
    STRPTR d;
    ULONG n;
    ULONG i;

    if (s == NULL) {
        return NULL;
    }
    n = 0;
    while (s[n] != 0) {
        n++;
    }
    n++;
    d = (STRPTR)AllocMem(n, MEMF_CLEAR);
    if (d == NULL) {
        return NULL;
    }
    for (i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return d;
}

VOID
atls_free_str(STRPTR s)
{
    if (s != NULL) {
        FreeMem(s, 0);
    }
}

VOID
atls_peer_cert_clear(struct TlsConnection *conn)
{
    if (conn == NULL) {
        return;
    }
    atls_free_str(conn->tc_CertSubject);
    atls_free_str(conn->tc_CertIssuer);
    atls_free_str(conn->tc_CertCommonName);
    atls_free_str(conn->tc_CertNotBefore);
    atls_free_str(conn->tc_CertNotAfter);
    atls_free_str(conn->tc_CertSerial);
    conn->tc_CertSubject = NULL;
    conn->tc_CertIssuer = NULL;
    conn->tc_CertCommonName = NULL;
    conn->tc_CertNotBefore = NULL;
    conn->tc_CertNotAfter = NULL;
    conn->tc_CertSerial = NULL;
    conn->tc_CertPresent = FALSE;
    conn->tc_CertVerifyResult = 0;
}

VOID
atls_peer_cert_copy(struct TlsPeerCert *dst, struct TlsConnection *conn)
{
    if (dst == NULL || conn == NULL) {
        return;
    }
    dst->tpc_Subject = atls_strdup(conn->tc_CertSubject);
    dst->tpc_Issuer = atls_strdup(conn->tc_CertIssuer);
    dst->tpc_CommonName = atls_strdup(conn->tc_CertCommonName);
    dst->tpc_NotBefore = atls_strdup(conn->tc_CertNotBefore);
    dst->tpc_NotAfter = atls_strdup(conn->tc_CertNotAfter);
    dst->tpc_Serial = atls_strdup(conn->tc_CertSerial);
    dst->tpc_VerifyResult = conn->tc_CertVerifyResult;
}
