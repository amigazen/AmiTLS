/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * amitls_funcs.h - LVO function declarations for FuncTab (__ASM__ / __REG__)
 *
 * Every LVO takes a6 = library base (Amiga library convention); atls_lvo_bind() copies
 * it into the library-global TlsBase for VBCC/SAS segment safety.
 */

#ifndef AMITLS_FUNCS_H
#define AMITLS_FUNCS_H

#include <exec/types.h>
#include <libraries/amitls.h>
#include "compiler.h"

struct AmiTlsBase;

LONG __ASM__ __SAVE_DS__ TlsBaseTagsA(__REG__(a0, struct TagItem *tags),
    __REG__(a6, struct AmiTlsBase *libbase));
LONG __ASM__ __SAVE_DS__ TlsError(__REG__(a6, struct AmiTlsBase *libbase));
STRPTR __ASM__ __SAVE_DS__ TlsGetErrorString(__REG__(d0, LONG code));

LONG __ASM__ __SAVE_DS__ TlsTaskAttach(__REG__(a0, struct Library *sock_base),
    __REG__(a1, APTR errno_ptr), __REG__(a6, struct AmiTlsBase *libbase));
VOID __ASM__ __SAVE_DS__ TlsTaskDetach(__REG__(a6, struct AmiTlsBase *libbase));

struct TlsContext * __ASM__ __SAVE_DS__ NewTlsContextA(__REG__(a0, struct TagItem *tags),
    __REG__(a6, struct AmiTlsBase *libbase));
VOID __ASM__ __SAVE_DS__ DisposeTlsContext(__REG__(a0, struct TlsContext *ctx));
LONG __ASM__ __SAVE_DS__ SetTlsContextAttrsA(__REG__(a0, struct TlsContext *ctx),
    __REG__(a1, struct TagItem *tags), __REG__(a6, struct AmiTlsBase *libbase));

struct TlsConnection * __ASM__ __SAVE_DS__ NewTlsConnection(
    __REG__(a0, struct TlsContext *ctx), __REG__(a6, struct AmiTlsBase *libbase));
VOID __ASM__ __SAVE_DS__ DisposeTlsConnection(__REG__(a0, struct TlsConnection *conn));
LONG __ASM__ __SAVE_DS__ TlsAttachSocketA(__REG__(a0, struct TlsConnection *conn),
    __REG__(d0, LONG sock), __REG__(a1, STRPTR hostname),
    __REG__(a2, struct TagItem *tags), __REG__(a6, struct AmiTlsBase *libbase));
LONG __ASM__ __SAVE_DS__ TlsRead(__REG__(a0, struct TlsConnection *conn),
    __REG__(a1, APTR buffer), __REG__(d0, ULONG buflen),
    __REG__(d1, ULONG timeout_secs), __REG__(a6, struct AmiTlsBase *libbase));
LONG __ASM__ __SAVE_DS__ TlsWrite(__REG__(a0, struct TlsConnection *conn),
    __REG__(a1, APTR buffer), __REG__(d0, ULONG len),
    __REG__(a6, struct AmiTlsBase *libbase));
ULONG __ASM__ __SAVE_DS__ TlsPending(__REG__(a0, struct TlsConnection *conn));
LONG __ASM__ __SAVE_DS__ TlsShutdown(__REG__(a0, struct TlsConnection *conn),
    __REG__(a6, struct AmiTlsBase *libbase));
LONG __ASM__ __SAVE_DS__ TlsGetLastError(__REG__(a0, struct TlsConnection *conn));
LONG __ASM__ __SAVE_DS__ TlsGetCertVerifyDetail(
    __REG__(a0, struct TlsConnection *conn));
LONG __ASM__ __SAVE_DS__ TlsGetPeerCert(__REG__(a0, struct TlsConnection *conn),
    __REG__(a1, struct TlsPeerCert *cert), __REG__(a6, struct AmiTlsBase *libbase));
VOID __ASM__ __SAVE_DS__ TlsPeerCertFree(__REG__(a0, struct TlsPeerCert *cert));

LONG __ASM__ __SAVE_DS__ TlsLoadCABundle(__REG__(a0, STRPTR path),
    __REG__(a6, struct AmiTlsBase *libbase));
LONG __ASM__ __SAVE_DS__ TlsAddTrustedCert(__REG__(a0, APTR data),
    __REG__(d0, ULONG len), __REG__(d1, ULONG format),
    __REG__(a6, struct AmiTlsBase *libbase));
VOID __ASM__ __SAVE_DS__ TlsClearTrustedCerts(__REG__(a6, struct AmiTlsBase *libbase));

LONG __ASM__ __SAVE_DS__ TlsHandshake(__REG__(a0, struct TlsConnection *conn),
    __REG__(d0, ULONG timeout_secs), __REG__(a6, struct AmiTlsBase *libbase));

#endif /* AMITLS_FUNCS_H */
