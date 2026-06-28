/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_protos.h - Plain C prototypes for amitls.library LVO functions
 */

#ifndef CLIB_ATLS_PROTOS_H
#define CLIB_ATLS_PROTOS_H

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif
#ifndef LIBRARIES_AMITLS_H
#include <libraries/amitls.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

LONG TlsBaseTagList( struct TagItem *tags );
LONG TlsError( VOID );
STRPTR TlsGetErrorString( LONG code );

LONG TlsTaskAttach( struct Library *SocketBase, APTR errno_ptr );
VOID TlsTaskDetach( VOID );

struct TlsContext *NewTlsContext( struct TagItem *tags );
VOID DisposeTlsContext( struct TlsContext *ctx );
LONG SetTlsContextAttrsA( struct TlsContext *ctx, struct TagItem *tags );

struct TlsConnection *NewTlsConnection( struct TlsContext *ctx );
VOID DisposeTlsConnection( struct TlsConnection *conn );
LONG TlsAttachSocket( struct TlsConnection *conn, LONG sock, STRPTR hostname, struct TagItem *tags );
LONG TlsRead( struct TlsConnection *conn, APTR buffer, ULONG buflen, ULONG timeout_secs );
LONG TlsWrite( struct TlsConnection *conn, APTR buffer, ULONG len );
ULONG TlsPending( struct TlsConnection *conn );
LONG TlsShutdown( struct TlsConnection *conn );
LONG TlsGetLastError( struct TlsConnection *conn );
LONG TlsGetCertVerifyDetail( struct TlsConnection *conn );
LONG TlsGetPeerCert( struct TlsConnection *conn, struct TlsPeerCert *cert );
VOID TlsPeerCertFree( struct TlsPeerCert *cert );

LONG TlsLoadCABundle( STRPTR path );
LONG TlsAddTrustedCert( APTR data, ULONG len, ULONG format );
VOID TlsClearTrustedCerts( VOID );
LONG TlsHandshake( struct TlsConnection *conn, ULONG timeout_secs );

#ifdef __cplusplus
}
#endif

#endif /* CLIB_ATLS_PROTOS_H */
