/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * libbases.c - Global bases required by proto/ pragmas at link time
 *
 * Roadshow #pragma libcall send()/recv() expand to SocketBase in THIS module.
 * The .library must therefore define SocketBase, errno and h_errno so VBCC
 * can link.  That is a separate copy from the host program's globals.
 *
 * Runtime socket I/O uses per-task TlsTaskState and per-connection snapshots
 * (see atls_task.c / atls_socket.c), not AmiTlsBase->atb_SocketBase.
 */

#include <exec/types.h>

#include <proto/exec.h>

#include <libraries/amitls.h>

#include "private/atls_internal.h"
#include "atls_socket.h"

extern struct DosLibrary *DOSBase;

struct Library *SocketBase;
struct Library *UtilityBase;
int errno;
int h_errno;

BOOL
atls_rc_is_error(LONG rc)
{
    if (rc >= ERROR_TLS_NOT_IMPLEMENTED && rc <= ERROR_TLS_WANT_WRITE) {
        return TRUE;
    }
    return FALSE;
}

BOOL
atls_rc_is_want(LONG rc)
{
    if (rc == ERROR_TLS_WANT_READ || rc == ERROR_TLS_WANT_WRITE) {
        return TRUE;
    }
    return FALSE;
}

VOID
atls_sync_proto_bases(struct AmiTlsBase *base)
{
    if (base == NULL) {
        return;
    }
    DOSBase = (struct DosLibrary *)base->atb_DOSBase;
    UtilityBase = base->atb_UtilityBase;
}

STRPTR
atls_context_ca_path(struct TlsContext *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    if (ctx->tx_CABundlePath != NULL) {
        return ctx->tx_CABundlePath;
    }
    if (ctx->tx_Parent != NULL) {
        return ctx->tx_Parent->atb_CABundlePath;
    }
    return NULL;
}
