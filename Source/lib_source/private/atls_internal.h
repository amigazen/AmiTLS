/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_internal.h - Private structures and helpers for amitls.library
 */

#ifndef ATLS_PRIVATE_ATLS_INTERNAL_H
#define ATLS_PRIVATE_ATLS_INTERNAL_H

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif
#ifndef EXEC_LISTS_H
#include <exec/lists.h>
#endif
#ifndef UTILITY_TAGITEM_H
#include <utility/tagitem.h>
#endif
#ifndef UTILITY_HOOKS_H
#include <utility/hooks.h>
#endif

#include "private/amitlsbase.h"
#include <libraries/amitls.h>

struct TlsTaskState
{
    struct Node     tts_Node;
    struct Task    *tts_Task;
    ULONG           tts_RefCount;
    struct Library *tts_SocketBase;
    APTR            tts_ErrnoPtr;
};

struct TlsContext
{
    struct AmiTlsBase  *tx_Parent;
    ULONG               tx_SslVerify;
    ULONG               tx_CipherPolicy;
    STRPTR              tx_Alpn;
    STRPTR              tx_CABundlePath;
    struct Hook        *tx_CertHook;
    APTR                tx_Trust;
    BOOL                tx_TrustShared;
};

struct TlsConnection
{
    struct TlsContext  *tc_Context;
    STRPTR              tc_Hostname;
    LONG                tc_Sock;
    struct Library     *tc_SocketBase;
    APTR                tc_ErrnoPtr;
    BOOL                tc_NonBlocking;
    BOOL                tc_ExternalWait;
    BOOL                tc_HandshakeDone;
    BOOL                tc_ShutdownDone;
    LONG                tc_LastError;
    BOOL                tc_CertPresent;
    STRPTR              tc_CertSubject;
    STRPTR              tc_CertIssuer;
    STRPTR              tc_CertCommonName;
    STRPTR              tc_CertNotBefore;
    STRPTR              tc_CertNotAfter;
    STRPTR              tc_CertSerial;
    LONG                tc_CertVerifyResult;
    LONG                tc_LastBrErr;
    BOOL                tc_OwnsContext;
    struct AtlsBearSslState *tc_Br;
};

extern struct AmiTlsBase *TlsBase;

VOID atls_sync_proto_bases(struct AmiTlsBase *base);
BOOL atls_rc_is_error(LONG rc);
BOOL atls_rc_is_want(LONG rc);
VOID atls_lvo_bind(struct AmiTlsBase *base);
VOID atls_set_error(struct AmiTlsBase *base, LONG code);
STRPTR atls_get_error_string(LONG code);
STRPTR atls_strdup(STRPTR s);
VOID atls_free_str(STRPTR s);
STRPTR atls_context_ca_path(struct TlsContext *ctx);
VOID atls_trust_clear(struct TlsContext *ctx);
VOID atls_peer_cert_clear(struct TlsConnection *conn);
VOID atls_peer_cert_copy(struct TlsPeerCert *dst, struct TlsConnection *conn);

struct TlsTaskState *atls_task_current(struct AmiTlsBase *base);
LONG atls_bind_current_task(struct AmiTlsBase *base);
VOID atls_conn_snapshot_io(struct TlsConnection *conn, struct TlsTaskState *tts);
LONG atls_task_attach(struct AmiTlsBase *base, struct Library *socket_base,
    APTR errno_ptr);
VOID atls_task_detach(struct AmiTlsBase *base);

LONG atls_bearssl_attach(struct TlsConnection *conn, LONG sock, STRPTR hostname,
    ULONG verify_mode);
LONG atls_bearssl_handshake(struct TlsConnection *conn, ULONG timeout_secs);
LONG atls_bearssl_read(struct TlsConnection *conn, APTR buf, ULONG len,
    ULONG timeout_secs);
LONG atls_bearssl_write(struct TlsConnection *conn, APTR buf, ULONG len);
ULONG atls_bearssl_pending(struct TlsConnection *conn);
LONG atls_bearssl_shutdown(struct TlsConnection *conn);
VOID atls_bearssl_dispose(struct TlsConnection *conn);

#endif /* ATLS_PRIVATE_ATLS_INTERNAL_H */
