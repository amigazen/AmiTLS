/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * StartUp.c - LVO trap and function vector table for amitls.library
 */


#include <exec/types.h>
#include <exec/memory.h>
#include <exec/libraries.h>
#include <exec/execbase.h>
#include <exec/resident.h>
#include <exec/initializers.h>
#include <exec/lists.h>
#include <exec/semaphores.h>

#include <proto/exec.h>
#include <proto/alib.h>

#include "private/amitlsbase.h"
#include <libraries/amitls.h>
#include "private/atls_build.h"
#include "compiler.h"
#include "amitls_funcs.h"

extern ULONG L_OpenLibs(struct AmiTlsBase *base);
extern VOID L_CloseLibs(VOID);

extern struct Resident ROMTag;
extern const char ATLS_LibName[];
extern const char ATLS_LibID[];
extern struct MyDataInit DataTab;

struct AmiTlsBase *TlsBase = NULL;

struct ExecBase *SysBase = NULL;
struct DosLibrary *DOSBase = NULL;

LONG __ASM__ LibStart(void);
struct AmiTlsBase * __ASM__ __SAVE_DS__ InitLib(
    __REG__(a6, struct ExecBase *sysbase),
    __REG__(a0, SEGLISTPTR seglist),
    __REG__(d0, struct AmiTlsBase *base));
struct AmiTlsBase * __ASM__ __SAVE_DS__ OpenLib(
    __REG__(a6, struct AmiTlsBase *base));
#ifdef __VBCC__
SEGLISTPTR __ASM__ __SAVE_DS__ CloseLib(
    __REG__(a6, struct AmiTlsBase *base));
SEGLISTPTR __ASM__ __SAVE_DS__ ExpungeLib(
    __REG__(a6, struct AmiTlsBase *base));
#else
BPTR __ASM__ __SAVE_DS__ CloseLib(
    __REG__(a6, struct AmiTlsBase *base));
BPTR __ASM__ __SAVE_DS__ ExpungeLib(
    __REG__(a6, struct AmiTlsBase *base));
#endif
ULONG __ASM__ ExtFuncLib(void);

APTR FuncTab[];

/*
 * FuncTab[] order MUST match SDK/SFD/amitls_lib.sfd and pragmas/amitls_pragmas.h.
 */
struct InitTable InitTab = {
    (ULONG)sizeof(struct AmiTlsBase),
    (APTR *)FuncTab,
    (APTR)&DataTab,
    (APTR)InitLib
};

APTR FuncTab[] = {
    (APTR)OpenLib,
    (APTR)CloseLib,
    (APTR)ExpungeLib,
    (APTR)ExtFuncLib,
    /* Tier 0 */
    (APTR)TlsBaseTagsA,
    (APTR)TlsError,
    (APTR)TlsGetErrorString,
    /* Tier 1 task */
    (APTR)TlsTaskAttach,
    (APTR)TlsTaskDetach,
    /* Tier 1 context */
    (APTR)NewTlsContextA,
    (APTR)DisposeTlsContext,
    (APTR)SetTlsContextAttrsA,
    /* Tier 2 connection */
    (APTR)NewTlsConnection,
    (APTR)DisposeTlsConnection,
    (APTR)TlsAttachSocketA,
    (APTR)TlsRead,
    (APTR)TlsWrite,
    (APTR)TlsPending,
    (APTR)TlsShutdown,
    (APTR)TlsGetLastError,
    (APTR)TlsGetCertVerifyDetail,
    (APTR)TlsGetPeerCert,
    (APTR)TlsPeerCertFree,
    /* Tier 3 trust store */
    (APTR)TlsLoadCABundle,
    (APTR)TlsAddTrustedCert,
    (APTR)TlsClearTrustedCerts,
    (APTR)TlsHandshake,
    (APTR)((LONG)-1)
};

LONG __ASM__ LibStart(void)
{
    return -1;
}

struct AmiTlsBase * __ASM__ __SAVE_DS__ InitLib(
    __REG__(a6, struct ExecBase *sysbase),
    __REG__(a0, SEGLISTPTR seglist),
    __REG__(d0, struct AmiTlsBase *base))
{
    TlsBase = base;

    base->atb_LibNode.lib_Node.ln_Type = NT_LIBRARY;
    base->atb_LibNode.lib_Flags = LIBF_SUMUSED | LIBF_CHANGED;
    base->atb_LibNode.lib_Version = ATLS_LIB_VERSION;
    base->atb_LibNode.lib_Revision = ATLS_LIB_REVISION;
    base->atb_LibNode.lib_IdString = (STRPTR)ATLS_LibID;

    base->atb_SysBase = sysbase;
    base->atb_SegList = seglist;
    base->atb_LastError = 0;
    base->atb_SslVerify = ATSSL_VERIFY_PEER;
    base->atb_SocketOpenCount = 0;

    if (L_OpenLibs(base) != 0) {
        return (struct AmiTlsBase *)NULL;
    }

    NewList(&base->atb_TaskList);
    InitSemaphore(&base->atb_GlobalSema);
    InitSemaphore(&base->atb_TaskSema);

    return base;
}

struct AmiTlsBase * __ASM__ __SAVE_DS__ OpenLib(__REG__(a6, struct AmiTlsBase *base))
{
    TlsBase = base;
    base->atb_LibNode.lib_OpenCnt++;
    base->atb_LibNode.lib_Flags &= ~LIBF_DELEXP;
    base->atb_LastError = 0;
    return base;
}

#ifdef __VBCC__
SEGLISTPTR __ASM__ __SAVE_DS__ CloseLib(__REG__(a6, struct AmiTlsBase *base))
#else
BPTR __ASM__ __SAVE_DS__ CloseLib(__REG__(a6, struct AmiTlsBase *base))
#endif
{
    base->atb_LibNode.lib_OpenCnt--;

    if (base->atb_LibNode.lib_OpenCnt == 0) {
        if (base->atb_LibNode.lib_Flags & LIBF_DELEXP) {
            return ExpungeLib(base);
        }
    }

    return 0;
}

#ifdef __VBCC__
SEGLISTPTR __ASM__ __SAVE_DS__ ExpungeLib(__REG__(a6, struct AmiTlsBase *base))
#else
BPTR __ASM__ __SAVE_DS__ ExpungeLib(__REG__(a6, struct AmiTlsBase *base))
#endif
{
    SEGLISTPTR seg;

    if (base->atb_LibNode.lib_OpenCnt != 0) {
        base->atb_LibNode.lib_Flags |= LIBF_DELEXP;
        return 0;
    }

    seg = base->atb_SegList;

    L_CloseLibs();

    Remove(&base->atb_LibNode.lib_Node);
    FreeMem((APTR)((BYTE *)base - base->atb_LibNode.lib_NegSize),
        base->atb_LibNode.lib_NegSize + base->atb_LibNode.lib_PosSize);

    TlsBase = NULL;

    return seg;
}

ULONG __ASM__ ExtFuncLib(void)
{
    return 0;
}
