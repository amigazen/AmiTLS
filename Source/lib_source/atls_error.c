/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_error.c - Error strings for amitls.library
 */


#include <exec/types.h>

#include <libraries/amitls.h>

#include "private/atls_internal.h"

VOID
atls_set_error(struct AmiTlsBase *base, LONG code)
{
    if (base != NULL) {
        base->atb_LastError = code;
    }
}

static STRPTR
atls_error_text(LONG code)
{
    switch (code) {
    case 0:
        return (STRPTR)"No error";
    case ERROR_TLS_NOT_IMPLEMENTED:
        return (STRPTR)"TLS not implemented";
    case ERROR_TLS_DNS_FAILED:
        return (STRPTR)"DNS lookup failed";
    case ERROR_TLS_CONNECT_FAILED:
        return (STRPTR)"TCP connect failed";
    case ERROR_TLS_CONNECT_TIMEOUT:
        return (STRPTR)"TCP connect timed out";
    case ERROR_TLS_HANDSHAKE:
        return (STRPTR)"TLS handshake failed";
    case ERROR_TLS_VERIFY:
        return (STRPTR)"TLS certificate verification failed";
    case ERROR_TLS_READ_TIMEOUT:
        return (STRPTR)"TLS read timed out";
    case ERROR_TLS_WRITE_FAILED:
        return (STRPTR)"TLS write failed";
    case ERROR_TLS_READ_FAILED:
        return (STRPTR)"TLS read failed";
    case ERROR_TLS_ABORTED:
        return (STRPTR)"TLS operation aborted";
    case ERROR_TLS_PROTOCOL:
        return (STRPTR)"TLS protocol error";
    case ERROR_TLS_OUT_OF_MEMORY:
        return (STRPTR)"Out of memory";
    case ERROR_TLS_INVALID_URL:
        return (STRPTR)"Invalid URL";
    case ERROR_TLS_INVALID_HANDLE:
        return (STRPTR)"Invalid handle";
    case ERROR_TLS_IO:
        return (STRPTR)"TLS I/O error";
    case ERROR_TLS_WANT_READ:
        return (STRPTR)"TLS needs socket read (retry after WaitSelect)";
    case ERROR_TLS_WANT_WRITE:
        return (STRPTR)"TLS needs socket write (retry after WaitSelect)";
    default:
        return (STRPTR)"Unknown TLS error";
    }
}

STRPTR
atls_get_error_string(LONG code)
{
    return atls_error_text(code);
}
