/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * amitls.h - Public constants, tags, hooks, and opaque types for amitls.library
 *
 * Amiga-native TLS client API wrapping BearSSL.  Callers never include BearSSL
 * headers or touch engine context structures.
 */

#ifndef LIBRARIES_AMITLS_H
#define LIBRARIES_AMITLS_H

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif
#ifndef EXEC_LISTS_H
#include <exec/lists.h>
#endif
#ifndef UTILITY_HOOKS_H
#include <utility/hooks.h>
#endif
#ifndef UTILITY_TAGITEM_H
#include <utility/tagitem.h>
#endif

/****************************************************************************/
/* Library identity                                                         */
/****************************************************************************/

#define AMITLSNAME      "amitls.library"
#define AMITLSVERSION   1

/****************************************************************************/
/* Opaque handles - internal layout is private to the library               */
/****************************************************************************/

struct TlsContext;
struct TlsConnection;

/****************************************************************************/
/* Error model                                                              */
/*   TlsError() - library bootstrap, task attach, context, trust stubs.     */
/*   TlsGetLastError(conn) - authoritative for TlsRead/TlsWrite/shutdown.   */
/*   TlsGetCertVerifyDetail(conn) - BearSSL brerr after ERROR_TLS_VERIFY.   */
/****************************************************************************/

/****************************************************************************/
/* TlsRead / TlsWrite semantics                                               */
/*   Success: >0 byte count (always below ERROR_TLS_NOT_IMPLEMENTED).         */
/*   Failure: ERROR_TLS_* (8800..8816).                                       */
/*   Non-blocking (ATTA_NON_BLOCKING): ERROR_TLS_WANT_READ / WANT_WRITE;      */
/*     WaitSelect on the raw TCP fd, then retry the same call.                */
/*   TlsRead:  >0 bytes read, 0 at clean EOF, <0 failure.                   */
/*   TlsPending: decrypted bytes available without blocking read.             */
/****************************************************************************/

#define ERROR_TLS_NOT_IMPLEMENTED       8800
#define ERROR_TLS_DNS_FAILED            8801
#define ERROR_TLS_CONNECT_FAILED        8802
#define ERROR_TLS_CONNECT_TIMEOUT       8803
#define ERROR_TLS_HANDSHAKE             8804
#define ERROR_TLS_VERIFY                8805
#define ERROR_TLS_READ_TIMEOUT          8806
#define ERROR_TLS_WRITE_FAILED          8807
#define ERROR_TLS_READ_FAILED           8808
#define ERROR_TLS_ABORTED               8809
#define ERROR_TLS_PROTOCOL              8810
#define ERROR_TLS_OUT_OF_MEMORY         8811
#define ERROR_TLS_INVALID_URL           8812
#define ERROR_TLS_INVALID_HANDLE        8813
#define ERROR_TLS_IO                    8814
#define ERROR_TLS_WANT_READ             8815
#define ERROR_TLS_WANT_WRITE            8816

/****************************************************************************/
/* TlsBaseTagsA / TlsBaseTags tags (Tier 0 - per-process defaults)          */
/****************************************************************************/

#define ATBT_ERRNOPTR               (TAG_USER + 0x01)
#define ATBT_SSL_VERIFY             (TAG_USER + 0x02)
/* PEM CA bundle for VERIFY_PEER; no implicit default — caller must set path. */
#define ATBT_CA_BUNDLE_PATH         (TAG_USER + 0x03)
#define ATBT_BREAKMASK              (TAG_USER + 0x04)
#define ATBT_LOG_HOOK               (TAG_USER + 0x05)

/****************************************************************************/
/* NewTlsContextA / SetTlsContextAttrsA tags (Tier 1)                       */
/****************************************************************************/

#define ATSA_SSL_VERIFY             (TAG_USER + 0x100)
#define ATSA_CIPHER_POLICY          (TAG_USER + 0x101)
#define ATSA_ALPN                   (TAG_USER + 0x102)
#define ATSA_CERT_HOOK              (TAG_USER + 0x103)
/* Per-context PEM CA bundle override (inherits ATBT when unset). */
#define ATSA_CA_BUNDLE_PATH         (TAG_USER + 0x104)

/****************************************************************************/
/* TlsAttachSocketA / TlsAttachSocket one-shot tags (Tier 2)                */
/****************************************************************************/

#define ATTA_SSL_VERIFY             (TAG_USER + 0x200)
#define ATTA_NON_BLOCKING           (TAG_USER + 0x201)
/*
 * ATTA_EXTERNAL_WAIT (ABI v1.1): when TRUE, TlsRead/TlsHandshake do not call
 * WaitSelect internally; they return ERROR_TLS_WANT_READ/WRITE and the caller
 * must wait on the raw TCP fd (e.g. amihttp ht_wait_socket_io) then retry.
 * Required for layered timeout/abort polling without double-blocking.
 */
#define ATTA_EXTERNAL_WAIT          (TAG_USER + 0x202)

/****************************************************************************/
/* ABI v1.1 additions (library revision 2+)                                   */
/*   TlsHandshake(conn, timeout_secs) — run TLS handshake after attach.     */
/*   ATTA_EXTERNAL_WAIT — caller-owned socket wait before TlsRead retry.      */
/****************************************************************************/
/* Hook types for SetTlsContextAttrsA ATSA_CERT_HOOK                        */
/****************************************************************************/

#define ATHK_CERT_VERIFY            1

/****************************************************************************/
/* SSL verify policy (ATBT_SSL_VERIFY / ATSA_SSL_VERIFY / ATTA_SSL_VERIFY)  */
/****************************************************************************/

#define ATSSL_VERIFY_NONE           0
#define ATSSL_VERIFY_PEER           1
#define ATSSL_VERIFY_PEER_STRICT    2

/****************************************************************************/
/* Tier 3 - Trust store (function-call entry points; prefer tag configuration)  */
/* ATBT_CA_BUNDLE_PATH / ATSA_CA_BUNDLE_PATH are primary. TlsLoadCABundle()    */
/* sets the same process-wide path as ATBT. No default bundle path is implicit. */
/****************************************************************************/

#define ATCF_DER                    0
#define ATCF_PEM                    1

/****************************************************************************/
/* Cipher policy values (ATSA_CIPHER_POLICY) - reserved for v2               */
/****************************************************************************/

#define ATCP_DEFAULT                0
#define ATCP_MODERN                 1
#define ATCP_COMPAT                 2

/****************************************************************************/
/* TlsPeerCert - filled by TlsGetPeerCert(); free with TlsPeerCertFree()     */
/****************************************************************************/

struct TlsPeerCert
{
    STRPTR  tpc_Subject;
    STRPTR  tpc_Issuer;
    STRPTR  tpc_CommonName;
    STRPTR  tpc_NotBefore;
    STRPTR  tpc_NotAfter;
    STRPTR  tpc_Serial;
    LONG    tpc_VerifyResult;
};

/****************************************************************************/
/* Tier 1 - Per-task TLS runtime (TlsTaskAttach / TlsTaskDetach)            */
/* Tier 0 - process bootstrap                                               */
/*   Caller OpenLibrary("bsdsocket.library") then TlsTaskAttach(base, ptr).  */
/*   Copies the bsdsocket base into the library and SocketBaseTagList().      */
/****************************************************************************/

/****************************************************************************/
/* Tier 2 - TlsConnection (caller-owned TCP socket + TLS handshake)           */
/*   TlsAttachSocketA(conn, sock, hostname, tags) expects sock from connect().*/
/*   TlsHandshake(conn, timeout_secs) completes handshake after attach (v1.1).  */
/****************************************************************************/

#endif /* LIBRARIES_AMITLS_H */
