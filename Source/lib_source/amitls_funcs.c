/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * amitls_funcs.c - LVO implementations for amitls.library
 */


#include <exec/types.h>
#include <exec/memory.h>
#include <exec/lists.h>
#include <exec/semaphores.h>

#include <utility/tagitem.h>

#include <proto/exec.h>

#include "private/amitlsbase.h"
#include <libraries/amitls.h>

#include "private/atls_internal.h"
#include "atls_trust.h"
#include "compiler.h"
#include "amitls_funcs.h"

extern struct AmiTlsBase *TlsBase;

VOID
atls_lvo_bind(struct AmiTlsBase *base)
{
    TlsBase = base;
    atls_sync_proto_bases(base);
}

static ULONG
atls_resolve_verify(struct TlsContext *ctx, struct TagItem *tags)
{
    struct TagItem *t;
    ULONG verify;

    verify = ATSSL_VERIFY_PEER;
    if (TlsBase != NULL) {
        verify = TlsBase->atb_SslVerify;
    }
    if (ctx != NULL) {
        verify = ctx->tx_SslVerify;
    }
    if (tags != NULL) {
        t = tags;
        while (t->ti_Tag != TAG_DONE) {
            if (t->ti_Tag == ATTA_SSL_VERIFY) {
                verify = (ULONG)t->ti_Data;
            }
            t++;
        }
    }
    return verify;
}

static VOID
atls_apply_attach_tags(struct TlsConnection *conn, struct TagItem *tags)
{
    struct TagItem *t;

    if (conn == NULL || tags == NULL) {
        return;
    }
    t = tags;
    while (t->ti_Tag != TAG_DONE) {
        if (t->ti_Tag == ATTA_NON_BLOCKING) {
            conn->tc_NonBlocking = (t->ti_Data != 0) ? TRUE : FALSE;
        } else if (t->ti_Tag == ATTA_EXTERNAL_WAIT) {
            conn->tc_ExternalWait = (t->ti_Data != 0) ? TRUE : FALSE;
        }
        t++;
    }
}

static VOID
atls_apply_base_tags(struct AmiTlsBase *base, struct TagItem *tags)
{
    struct TagItem *t;
    STRPTR path;

    if (base == NULL || tags == NULL) {
        return;
    }
    t = tags;
    while (t->ti_Tag != TAG_DONE) {
        switch (t->ti_Tag) {
        case ATBT_ERRNOPTR:
            base->atb_ErrnoPtr = (APTR)t->ti_Data;
            break;
        case ATBT_SSL_VERIFY:
            base->atb_SslVerify = (ULONG)t->ti_Data;
            break;
        case ATBT_CA_BUNDLE_PATH:
            path = (STRPTR)t->ti_Data;
            atls_free_str(base->atb_CABundlePath);
            if (path != NULL && path[0] != '\0') {
                base->atb_CABundlePath = atls_strdup(path);
            } else {
                base->atb_CABundlePath = NULL;
            }
            break;
        case ATBT_BREAKMASK:
            base->atb_BreakMask = (ULONG)t->ti_Data;
            break;
        default:
            break;
        }
        t++;
    }
}

static VOID
atls_apply_context_tags(struct TlsContext *ctx, struct TagItem *tags)
{
    struct TagItem *t;
    STRPTR alpn;
    STRPTR path;

    if (ctx == NULL || tags == NULL) {
        return;
    }
    t = tags;
    while (t->ti_Tag != TAG_DONE) {
        switch (t->ti_Tag) {
        case ATSA_SSL_VERIFY:
            ctx->tx_SslVerify = (ULONG)t->ti_Data;
            break;
        case ATSA_CIPHER_POLICY:
            ctx->tx_CipherPolicy = (ULONG)t->ti_Data;
            break;
        case ATSA_ALPN:
            alpn = (STRPTR)t->ti_Data;
            atls_free_str(ctx->tx_Alpn);
            ctx->tx_Alpn = atls_strdup(alpn);
            break;
        case ATSA_CA_BUNDLE_PATH:
            atls_trust_clear(ctx);
            path = (STRPTR)t->ti_Data;
            atls_free_str(ctx->tx_CABundlePath);
            if (path != NULL && path[0] != '\0') {
                ctx->tx_CABundlePath = atls_strdup(path);
            } else {
                ctx->tx_CABundlePath = NULL;
            }
            break;
        case ATSA_CERT_HOOK:
            ctx->tx_CertHook = (struct Hook *)t->ti_Data;
            break;
        default:
            break;
        }
        t++;
    }
}

static struct TlsContext *
atls_new_context(struct AmiTlsBase *base, struct TagItem *tags)
{
    struct TlsContext *ctx;

    if (base == NULL) {
        return NULL;
    }
    ctx = (struct TlsContext *)AllocMem(sizeof(*ctx), MEMF_CLEAR);
    if (ctx == NULL) {
        atls_set_error(base, ERROR_TLS_OUT_OF_MEMORY);
        return NULL;
    }
    ctx->tx_Parent = base;
    ctx->tx_SslVerify = base->atb_SslVerify;
    ctx->tx_CipherPolicy = ATCP_DEFAULT;
    atls_apply_context_tags(ctx, tags);
    return ctx;
}

LONG __ASM__ __SAVE_DS__ TlsBaseTagsA(__REG__(a0, struct TagItem *tags),
    __REG__(a6, struct AmiTlsBase *libbase))
{
    atls_lvo_bind(libbase);
    if (TlsBase == NULL) {
        return ERROR_TLS_INVALID_HANDLE;
    }
    atls_apply_base_tags(TlsBase, tags);
    atls_set_error(TlsBase, 0);
    return 0;
}

LONG __ASM__ __SAVE_DS__ TlsError(__REG__(a6, struct AmiTlsBase *libbase))
{
    atls_lvo_bind(libbase);
    if (TlsBase == NULL) {
        return ERROR_TLS_INVALID_HANDLE;
    }
    return TlsBase->atb_LastError;
}

STRPTR __ASM__ __SAVE_DS__ TlsGetErrorString(__REG__(d0, LONG code))
{
    return atls_get_error_string(code);
}

LONG __ASM__ __SAVE_DS__ TlsTaskAttach(__REG__(a0, struct Library *sock_base),
    __REG__(a1, APTR errno_ptr), __REG__(a6, struct AmiTlsBase *libbase))
{
    LONG rc;

    atls_lvo_bind(libbase);
    if (TlsBase == NULL) {
        return ERROR_TLS_INVALID_HANDLE;
    }
    rc = atls_task_attach(TlsBase, sock_base, errno_ptr);
    if (rc == 0) {
        atls_set_error(TlsBase, 0);
    }
    return rc;
}

VOID __ASM__ __SAVE_DS__ TlsTaskDetach(__REG__(a6, struct AmiTlsBase *libbase))
{
    atls_lvo_bind(libbase);
    if (TlsBase != NULL) {
        atls_task_detach(TlsBase);
    }
}

struct TlsContext * __ASM__ __SAVE_DS__ NewTlsContextA(__REG__(a0, struct TagItem *tags),
    __REG__(a6, struct AmiTlsBase *libbase))
{
    atls_lvo_bind(libbase);
    if (TlsBase == NULL) {
        return NULL;
    }
    return atls_new_context(TlsBase, tags);
}

VOID __ASM__ __SAVE_DS__ DisposeTlsContext(__REG__(a0, struct TlsContext *ctx))
{
    if (ctx == NULL) {
        return;
    }
    atls_free_str(ctx->tx_Alpn);
    atls_free_str(ctx->tx_CABundlePath);
    atls_trust_clear(ctx);
    FreeMem(ctx, sizeof(*ctx));
}

LONG __ASM__ __SAVE_DS__ SetTlsContextAttrsA(__REG__(a0, struct TlsContext *ctx),
    __REG__(a1, struct TagItem *tags), __REG__(a6, struct AmiTlsBase *libbase))
{
    atls_lvo_bind(libbase);
    if (ctx == NULL) {
        if (TlsBase != NULL) {
            atls_set_error(TlsBase, ERROR_TLS_INVALID_HANDLE);
        }
        return ERROR_TLS_INVALID_HANDLE;
    }
    atls_apply_context_tags(ctx, tags);
    atls_set_error(TlsBase, 0);
    return 0;
}

struct TlsConnection * __ASM__ __SAVE_DS__ NewTlsConnection(
    __REG__(a0, struct TlsContext *ctx), __REG__(a6, struct AmiTlsBase *libbase))
{
    struct TlsConnection *conn;

    atls_lvo_bind(libbase);
    if (TlsBase == NULL) {
        return NULL;
    }
    conn = (struct TlsConnection *)AllocMem(sizeof(*conn), MEMF_CLEAR);
    if (conn == NULL) {
        atls_set_error(TlsBase, ERROR_TLS_OUT_OF_MEMORY);
        return NULL;
    }
    conn->tc_Context = ctx;
    conn->tc_OwnsContext = FALSE;
    if (ctx == NULL) {
        conn->tc_Context = atls_new_context(TlsBase, NULL);
        if (conn->tc_Context == NULL) {
            FreeMem(conn, sizeof(*conn));
            return NULL;
        }
        conn->tc_OwnsContext = TRUE;
    }
    return conn;
}

VOID __ASM__ __SAVE_DS__ DisposeTlsConnection(__REG__(a0, struct TlsConnection *conn))
{
    struct TlsContext *ctx;
    BOOL owns;

    if (conn == NULL) {
        return;
    }
    atls_bearssl_dispose(conn);
    atls_peer_cert_clear(conn);
    atls_free_str(conn->tc_Hostname);
    ctx = conn->tc_Context;
    owns = conn->tc_OwnsContext;
    FreeMem(conn, sizeof(*conn));
    if (ctx != NULL && owns) {
        DisposeTlsContext(ctx);
    }
}

LONG __ASM__ __SAVE_DS__ TlsAttachSocketA(__REG__(a0, struct TlsConnection *conn),
    __REG__(d0, LONG sock), __REG__(a1, STRPTR hostname),
    __REG__(a2, struct TagItem *tags), __REG__(a6, struct AmiTlsBase *libbase))
{
    struct TlsTaskState *tts;
    ULONG verify;
    LONG rc;

    atls_lvo_bind(libbase);
    if (conn == NULL || sock < 0) {
        if (TlsBase != NULL) {
            atls_set_error(TlsBase, ERROR_TLS_INVALID_HANDLE);
        }
        return ERROR_TLS_INVALID_HANDLE;
    }

    rc = atls_bind_current_task(TlsBase);
    if (rc != 0) {
        if (TlsBase != NULL) {
            atls_set_error(TlsBase, rc);
        }
        conn->tc_LastError = rc;
        return rc;
    }

    tts = NULL;
    if (TlsBase != NULL) {
        tts = atls_task_current(TlsBase);
    }
    if (tts != NULL) {
        atls_conn_snapshot_io(conn, tts);
    }

    atls_apply_attach_tags(conn, tags);
    atls_free_str(conn->tc_Hostname);
    conn->tc_Hostname = atls_strdup(hostname);
    conn->tc_Sock = sock;
    verify = atls_resolve_verify(conn->tc_Context, tags);
    rc = atls_bearssl_attach(conn, sock, hostname, verify);
    if (rc == 0) {
        if (TlsBase != NULL) {
            atls_set_error(TlsBase, 0);
        }
        conn->tc_LastError = 0;
    } else {
        conn->tc_LastError = rc;
        if (TlsBase != NULL) {
            atls_set_error(TlsBase, rc);
        }
    }
    return rc;
}

LONG __ASM__ __SAVE_DS__ TlsRead(__REG__(a0, struct TlsConnection *conn),
    __REG__(a1, APTR buffer), __REG__(d0, ULONG buflen),
    __REG__(d1, ULONG timeout_secs), __REG__(a6, struct AmiTlsBase *libbase))
{
    struct TlsTaskState *tts;
    LONG rc;

    atls_lvo_bind(libbase);
    if (conn == NULL || buffer == NULL || buflen == 0) {
        if (TlsBase != NULL) {
            atls_set_error(TlsBase, ERROR_TLS_INVALID_HANDLE);
        }
        return ERROR_TLS_INVALID_HANDLE;
    }
    rc = atls_bind_current_task(TlsBase);
    if (rc != 0) {
        conn->tc_LastError = rc;
        return rc;
    }
    tts = atls_task_current(TlsBase);
    if (tts != NULL) {
        atls_conn_snapshot_io(conn, tts);
    }
    if (!conn->tc_HandshakeDone) {
        conn->tc_LastError = ERROR_TLS_HANDSHAKE;
        return ERROR_TLS_HANDSHAKE;
    }
    rc = atls_bearssl_read(conn, buffer, buflen, timeout_secs);
    if (atls_rc_is_error(rc)) {
        conn->tc_LastError = rc;
    } else if (rc > 0) {
        conn->tc_LastError = 0;
    }
    return rc;
}

LONG __ASM__ __SAVE_DS__ TlsWrite(__REG__(a0, struct TlsConnection *conn),
    __REG__(a1, APTR buffer), __REG__(d0, ULONG len),
    __REG__(a6, struct AmiTlsBase *libbase))
{
    struct TlsTaskState *tts;
    LONG rc;

    atls_lvo_bind(libbase);
    if (conn == NULL || buffer == NULL || len == 0) {
        if (TlsBase != NULL) {
            atls_set_error(TlsBase, ERROR_TLS_INVALID_HANDLE);
        }
        return ERROR_TLS_INVALID_HANDLE;
    }
    rc = atls_bind_current_task(TlsBase);
    if (rc != 0) {
        conn->tc_LastError = rc;
        return rc;
    }
    tts = atls_task_current(TlsBase);
    if (tts != NULL) {
        atls_conn_snapshot_io(conn, tts);
    }
    rc = atls_bearssl_write(conn, buffer, len);
    if (atls_rc_is_error(rc)) {
        conn->tc_LastError = rc;
    } else if (rc > 0) {
        conn->tc_LastError = 0;
    }
    return rc;
}

ULONG __ASM__ __SAVE_DS__ TlsPending(__REG__(a0, struct TlsConnection *conn))
{
    if (conn == NULL) {
        return 0;
    }
    atls_conn_bind_io(conn);
    return atls_bearssl_pending(conn);
}

LONG __ASM__ __SAVE_DS__ TlsShutdown(__REG__(a0, struct TlsConnection *conn),
    __REG__(a6, struct AmiTlsBase *libbase))
{
    LONG rc;

    atls_lvo_bind(libbase);
    if (conn == NULL) {
        if (TlsBase != NULL) {
            atls_set_error(TlsBase, ERROR_TLS_INVALID_HANDLE);
        }
        return ERROR_TLS_INVALID_HANDLE;
    }
    rc = atls_bind_current_task(TlsBase);
    if (rc != 0) {
        conn->tc_LastError = rc;
        return rc;
    }
    rc = atls_bearssl_shutdown(conn);
    if (rc != 0) {
        conn->tc_LastError = rc;
    }
    return rc;
}

LONG __ASM__ __SAVE_DS__ TlsGetLastError(__REG__(a0, struct TlsConnection *conn))
{
    if (conn == NULL) {
        return ERROR_TLS_INVALID_HANDLE;
    }
    return conn->tc_LastError;
}

LONG __ASM__ __SAVE_DS__ TlsGetCertVerifyDetail(
    __REG__(a0, struct TlsConnection *conn))
{
    if (conn == NULL) {
        return 0;
    }
    return conn->tc_LastBrErr;
}

LONG __ASM__ __SAVE_DS__ TlsGetPeerCert(__REG__(a0, struct TlsConnection *conn),
    __REG__(a1, struct TlsPeerCert *cert), __REG__(a6, struct AmiTlsBase *libbase))
{
    atls_lvo_bind(libbase);
    if (conn == NULL || cert == NULL) {
        if (TlsBase != NULL) {
            atls_set_error(TlsBase, ERROR_TLS_INVALID_HANDLE);
        }
        return ERROR_TLS_INVALID_HANDLE;
    }
    if (!conn->tc_CertPresent) {
        return ERROR_TLS_PROTOCOL;
    }
    atls_peer_cert_copy(cert, conn);
    return 0;
}

VOID __ASM__ __SAVE_DS__ TlsPeerCertFree(__REG__(a0, struct TlsPeerCert *cert))
{
    if (cert == NULL) {
        return;
    }
    atls_free_str(cert->tpc_Subject);
    atls_free_str(cert->tpc_Issuer);
    atls_free_str(cert->tpc_CommonName);
    atls_free_str(cert->tpc_NotBefore);
    atls_free_str(cert->tpc_NotAfter);
    atls_free_str(cert->tpc_Serial);
    cert->tpc_Subject = NULL;
    cert->tpc_Issuer = NULL;
    cert->tpc_CommonName = NULL;
    cert->tpc_NotBefore = NULL;
    cert->tpc_NotAfter = NULL;
    cert->tpc_Serial = NULL;
    cert->tpc_VerifyResult = 0;
}

LONG __ASM__ __SAVE_DS__ TlsLoadCABundle(__REG__(a0, STRPTR path),
    __REG__(a6, struct AmiTlsBase *libbase))
{
    /*
     * Sets the process-wide PEM bundle path (same field as ATBT_CA_BUNDLE_PATH).
     * Prefer TlsBaseTagsA / TlsBaseTags(ATBT_CA_BUNDLE_PATH); this LVO is a convenience for
     * callers that configure trust via a function call instead of tags.
     */
    atls_lvo_bind(libbase);
    if (TlsBase == NULL) {
        return ERROR_TLS_INVALID_HANDLE;
    }
    if (path == NULL) {
        atls_set_error(TlsBase, ERROR_TLS_INVALID_HANDLE);
        return ERROR_TLS_INVALID_HANDLE;
    }
    atls_free_str(TlsBase->atb_CABundlePath);
    TlsBase->atb_CABundlePath = atls_strdup(path);
    if (TlsBase->atb_CABundlePath == NULL) {
        atls_set_error(TlsBase, ERROR_TLS_OUT_OF_MEMORY);
        return ERROR_TLS_OUT_OF_MEMORY;
    }
    atls_set_error(TlsBase, 0);
    return 0;
}

LONG __ASM__ __SAVE_DS__ TlsAddTrustedCert(__REG__(a0, APTR data),
    __REG__(d0, ULONG len), __REG__(d1, ULONG format),
    __REG__(a6, struct AmiTlsBase *libbase))
{
    (void)data;
    (void)len;
    (void)format;

    /*
     * Not implemented: use ATSA_CA_BUNDLE_PATH / ATBT_CA_BUNDLE_PATH with a
     * PEM file.  Future Tier 3 work may add in-memory roots on TlsContext.
     */
    atls_lvo_bind(libbase);
    if (TlsBase != NULL) {
        atls_set_error(TlsBase, ERROR_TLS_NOT_IMPLEMENTED);
    }
    return ERROR_TLS_NOT_IMPLEMENTED;
}

LONG __ASM__ __SAVE_DS__ TlsHandshake(__REG__(a0, struct TlsConnection *conn),
    __REG__(d0, ULONG timeout_secs), __REG__(a6, struct AmiTlsBase *libbase))
{
    struct TlsTaskState *tts;
    LONG rc;

    atls_lvo_bind(libbase);
    if (conn == NULL) {
        if (TlsBase != NULL) {
            atls_set_error(TlsBase, ERROR_TLS_INVALID_HANDLE);
        }
        return ERROR_TLS_INVALID_HANDLE;
    }
    rc = atls_bind_current_task(TlsBase);
    if (rc != 0) {
        conn->tc_LastError = rc;
        return rc;
    }
    tts = atls_task_current(TlsBase);
    if (tts != NULL) {
        atls_conn_snapshot_io(conn, tts);
    }
    rc = atls_bearssl_handshake(conn, timeout_secs);
    if (atls_rc_is_error(rc)) {
        conn->tc_LastError = rc;
    } else {
        conn->tc_LastError = 0;
    }
    return rc;
}

VOID __ASM__ __SAVE_DS__ TlsClearTrustedCerts(__REG__(a6, struct AmiTlsBase *libbase))
{
    atls_lvo_bind(libbase);
    if (TlsBase != NULL) {
        atls_trust_global_clear(TlsBase);
        atls_free_str(TlsBase->atb_CABundlePath);
        TlsBase->atb_CABundlePath = NULL;
        atls_set_error(TlsBase, 0);
    }
}
