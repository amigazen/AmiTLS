/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * LibInit.c - ROMTag, DataTab, and dependency open/close for amitls.library
 *
 * Opens dos.library and utility.library only.  bsdsocket.library is opened by
 * the caller and passed to TlsTaskAttach() (AmiSSL AmiSSL_SocketBase model).
 */


#include <exec/types.h>
#include <exec/memory.h>
#include <exec/libraries.h>
#include <exec/execbase.h>
#include <exec/resident.h>
#include <exec/initializers.h>

#include <proto/exec.h>
#include <proto/dos.h>

#include "private/amitlsbase.h"
#include "private/atls_build.h"
#include "private/atls_internal.h"
#include "compiler.h"

#define ATLSLIBNAME "amitls"

#if (ATLS_BUILD_OPT_LVL) == 3
#define ATLS_OPT_TAG "O3"
#elif (ATLS_BUILD_OPT_LVL) == 1
#define ATLS_OPT_TAG "O1"
#else
#define ATLS_OPT_TAG "O2"
#endif

#if (ATLS_BUILD_BR_OPT_LVL) == 3
#define ATLS_BR_OPT_TAG "O3"
#elif (ATLS_BUILD_BR_OPT_LVL) == 1
#define ATLS_BR_OPT_TAG "O1"
#else
#define ATLS_BR_OPT_TAG "O2"
#endif

#if (ATLS_BUILD_BR_X509_OPT_LVL) == 3
#define ATLS_BR_X509_OPT_TAG "O3"
#elif (ATLS_BUILD_BR_X509_OPT_LVL) == 1
#define ATLS_BR_X509_OPT_TAG "O1"
#else
#define ATLS_BR_X509_OPT_TAG "O2"
#endif

#define ATLS_XSTR(x) ATLS_STR(x)
#define ATLS_STR(x) #x
#define ATLS_CPU_TAG_STR ATLS_XSTR(ATLS_BUILD_CPU)

#define ATLS_BUILD_PROFILE " [" ATLS_CPU_TAG_STR "/" ATLS_OPT_TAG \
    " br-" ATLS_BR_OPT_TAG "/x509-" ATLS_BR_X509_OPT_TAG "]"

#define ATLSLIBVER  " 1.0 (23.6.2026)" ATLS_BUILD_PROFILE

const char ATLS_LibName[] = ATLSLIBNAME ".library";
const char ATLS_LibID[]   = ATLSLIBNAME ATLSLIBVER;
const char ATLS_VerString[] = "\0$VER: " ATLSLIBNAME ATLSLIBVER;

extern struct ExecBase *SysBase;
extern struct AmiTlsBase *TlsBase;
extern struct DosLibrary *DOSBase;
extern struct Library *UtilityBase;

ULONG __SAVE_DS__
L_OpenLibs(struct AmiTlsBase *base)
{
    SysBase = *((struct ExecBase **)4);

    if (base != NULL) {
        base->atb_SocketBase = NULL;
        base->atb_DOSBase = NULL;
        base->atb_UtilityBase = NULL;
        base->atb_SocketOpenCount = 0;
    }

    DOSBase = (struct DosLibrary *)OpenLibrary((STRPTR)"dos.library", 37);
    if (DOSBase == NULL) {
        return 1;
    }
    if (base != NULL) {
        base->atb_DOSBase = (struct Library *)DOSBase;
    }

    if (base != NULL) {
        base->atb_UtilityBase = OpenLibrary((STRPTR)"utility.library", 36);
        if (base->atb_UtilityBase == NULL) {
            CloseLibrary((struct Library *)DOSBase);
            DOSBase = NULL;
            base->atb_DOSBase = NULL;
            return 1;
        }
    }

    atls_sync_proto_bases(base);
    return 0;
}

VOID __SAVE_DS__
L_CloseLibs(VOID)
{
    if (TlsBase == NULL) {
        return;
    }

    if (TlsBase->atb_SocketBase != NULL) {
        TlsBase->atb_SocketBase = NULL;
    }
    TlsBase->atb_SocketOpenCount = 0;

    if (TlsBase->atb_DOSBase != NULL) {
        CloseLibrary(TlsBase->atb_DOSBase);
        TlsBase->atb_DOSBase = NULL;
        DOSBase = NULL;
    }

    if (TlsBase->atb_UtilityBase != NULL) {
        CloseLibrary(TlsBase->atb_UtilityBase);
        TlsBase->atb_UtilityBase = NULL;
        UtilityBase = NULL;
    }

    atls_free_str(TlsBase->atb_CABundlePath);
    TlsBase->atb_CABundlePath = NULL;

    atls_sync_proto_bases(TlsBase);
}

extern struct InitTable InitTab;
extern APTR EndResident;

struct Resident ROMTag = {
    RTC_MATCHWORD,
    &ROMTag,
    &EndResident,
    RTF_AUTOINIT,
    ATLS_LIB_VERSION,
    NT_LIBRARY,
    0,
    (APTR)ATLS_LibName,
    (APTR)ATLS_LibID,
    (APTR)&InitTab
};

APTR EndResident;

struct MyDataInit DataTab = {
    0xE000, 8,  NT_LIBRARY,
    0x80,   10, (ULONG)ATLS_LibName,
    0xE000, 14, LIBF_SUMUSED | LIBF_CHANGED,
    0xE000, 20, ATLS_LIB_VERSION,
    0xE000, 22, ATLS_LIB_REVISION,
    0x80,   24, (ULONG)ATLS_LibID,
    (ULONG)0
};

#ifdef __SASC
void __regargs __chkabort(void) { }
void __regargs _CXBRK(void)     { }
#endif
