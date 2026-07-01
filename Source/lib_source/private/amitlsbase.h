/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * amitlsbase.h - amitls.library base structure (library-private only)
 *
 * Applications use struct Library * from OpenLibrary(); never include this.
 */

#ifndef ATLS_PRIVATE_AMITLSBASE_H
#define ATLS_PRIVATE_AMITLSBASE_H

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif
#ifndef DOS_DOS_H
#include <dos/dos.h>
#endif
#ifndef EXEC_LIBRARIES_H
#include <exec/libraries.h>
#endif
#ifndef EXEC_LISTS_H
#include <exec/lists.h>
#endif
#ifndef EXEC_SEMAPHORES_H
#include <exec/semaphores.h>
#endif

#ifdef __VBCC__
#ifndef SEGLISTPTR
#define SEGLISTPTR APTR
#endif
#else
#ifndef SEGLISTPTR
#define SEGLISTPTR BPTR
#endif
#endif

struct AmiTlsBase
{
    struct Library          atb_LibNode;
    SEGLISTPTR              atb_SegList;
    struct ExecBase        *atb_SysBase;

    /* Defaults for TlsTaskAttach(NULL socket) and ATBT_* tags only. */
    struct Library         *atb_SocketBase;
    struct Library         *atb_DOSBase;
    struct Library         *atb_UtilityBase;
    ULONG                   atb_SocketOpenCount;

    struct List             atb_TaskList;
    struct SignalSemaphore  atb_GlobalSema;
    struct SignalSemaphore  atb_TaskSema;

    ULONG                   atb_BreakMask;
    APTR                    atb_ErrnoPtr;
    ULONG                   atb_SslVerify;
    STRPTR                  atb_CABundlePath;

    /* Parsed PEM trust anchors shared by all TlsContext (same bundle path). */
    APTR                    atb_SharedTrust;
    STRPTR                  atb_SharedTrustPath;

    LONG                    atb_LastError;
    UBYTE                   atb_ErrorString[256];
};

#define AMITLS_LIBNAME "amitls.library"

#endif /* ATLS_PRIVATE_AMITLSBASE_H */
