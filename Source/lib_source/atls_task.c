/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_task.c - Per-task TLS runtime attach/detach
 *
 * Each Exec task that performs TLS I/O must call TlsTaskAttach() once with
 * its bsdsocket.library base and errno pointer.  Socket/errno state lives on
 * TlsTaskState, not on the singleton AmiTlsBase (last-attach-wins safe).
 *
 * Never AllocMem while holding a semaphore.
 */

#define __USE_SYSBASE

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/lists.h>
#include <exec/tasks.h>
#include <exec/semaphores.h>

#include <utility/tagitem.h>

#include <proto/exec.h>

#include <libraries/bsdsocket.h>
#include <proto/bsdsocket.h>

#include "private/atls_internal.h"
#include "atls_socket.h"

extern struct ExecBase *SysBase;
extern struct Library *SocketBase;
extern int errno;
extern int h_errno;

static struct TlsTaskState *
atls_task_find(struct AmiTlsBase *base, struct Task *task)
{
    struct Node *node;
    struct TlsTaskState *tts;

    if (base == NULL || task == NULL) {
        return NULL;
    }
    for (node = (struct Node *)base->atb_TaskList.lh_Head;
         node != NULL && node->ln_Succ != NULL;
         node = node->ln_Succ) {
        tts = (struct TlsTaskState *)node;
        if (tts->tts_Task == task) {
            return tts;
        }
    }
    return NULL;
}

struct TlsTaskState *
atls_task_current(struct AmiTlsBase *base)
{
    return atls_task_find(base, (struct Task *)FindTask(NULL));
}

static VOID
atls_task_apply_io(struct TlsTaskState *tts)
{
    if (tts == NULL || tts->tts_SocketBase == NULL) {
        return;
    }
    SocketBase = tts->tts_SocketBase;
    atls_sock_set_errno_ptr(tts->tts_ErrnoPtr);
    atls_sock_configure_errno(tts->tts_ErrnoPtr);
}

LONG
atls_bind_current_task(struct AmiTlsBase *base)
{
    struct TlsTaskState *tts;

    if (base == NULL) {
        return ERROR_TLS_INVALID_HANDLE;
    }
    tts = atls_task_current(base);
    if (tts == NULL || tts->tts_SocketBase == NULL) {
        return ERROR_TLS_IO;
    }
    atls_task_apply_io(tts);
    return 0;
}

VOID
atls_conn_snapshot_io(struct TlsConnection *conn, struct TlsTaskState *tts)
{
    if (conn == NULL || tts == NULL) {
        return;
    }
    conn->tc_SocketBase = tts->tts_SocketBase;
    conn->tc_ErrnoPtr = tts->tts_ErrnoPtr;
}

static LONG
atls_task_resolve_attach(struct AmiTlsBase *base, struct Library *socket_base,
    APTR errno_ptr, struct Library **out_socket, APTR *out_errno)
{
    struct Library *sock;
    APTR errp;

    if (base == NULL || out_socket == NULL || out_errno == NULL) {
        return ERROR_TLS_INVALID_HANDLE;
    }

    sock = socket_base;
    if (sock == NULL) {
        sock = base->atb_SocketBase;
    }
    if (sock == NULL) {
        return ERROR_TLS_IO;
    }

    if (errno_ptr != NULL) {
        errp = errno_ptr;
    } else if (base->atb_ErrnoPtr != NULL) {
        errp = base->atb_ErrnoPtr;
    } else {
        errp = (APTR)&errno;
    }

    *out_socket = sock;
    *out_errno = errp;
    return 0;
}

LONG
atls_task_attach(struct AmiTlsBase *base, struct Library *socket_base,
    APTR errno_ptr)
{
    struct TlsTaskState *tts;
    struct Task *task;
    struct Library *sock;
    APTR errp;
    LONG rc;

    if (base == NULL) {
        return ERROR_TLS_INVALID_HANDLE;
    }

    rc = atls_task_resolve_attach(base, socket_base, errno_ptr, &sock, &errp);
    if (rc != 0) {
        atls_set_error(base, rc);
        return rc;
    }

    if (socket_base != NULL) {
        base->atb_SocketBase = socket_base;
    }
    if (errno_ptr != NULL) {
        base->atb_ErrnoPtr = errno_ptr;
    }

    task = (struct Task *)FindTask(NULL);

    ObtainSemaphore(&base->atb_TaskSema);
    tts = atls_task_find(base, task);
    if (tts != NULL) {
        tts->tts_SocketBase = sock;
        tts->tts_ErrnoPtr = errp;
        tts->tts_RefCount++;
        atls_task_apply_io(tts);
        ReleaseSemaphore(&base->atb_TaskSema);
        return 0;
    }
    ReleaseSemaphore(&base->atb_TaskSema);

    tts = (struct TlsTaskState *)AllocMem(sizeof(*tts), MEMF_CLEAR);
    if (tts == NULL) {
        atls_set_error(base, ERROR_TLS_OUT_OF_MEMORY);
        return ERROR_TLS_OUT_OF_MEMORY;
    }
    tts->tts_Task = task;
    tts->tts_RefCount = 1;
    tts->tts_SocketBase = sock;
    tts->tts_ErrnoPtr = errp;

    ObtainSemaphore(&base->atb_TaskSema);
    if (atls_task_find(base, task) != NULL) {
        ReleaseSemaphore(&base->atb_TaskSema);
        FreeMem(tts, sizeof(*tts));
        ObtainSemaphore(&base->atb_TaskSema);
        tts = atls_task_find(base, task);
        if (tts != NULL) {
            tts->tts_SocketBase = sock;
            tts->tts_ErrnoPtr = errp;
            tts->tts_RefCount++;
            atls_task_apply_io(tts);
        }
        ReleaseSemaphore(&base->atb_TaskSema);
        return 0;
    }
    AddTail(&base->atb_TaskList, &tts->tts_Node);
    atls_task_apply_io(tts);
    ReleaseSemaphore(&base->atb_TaskSema);
    return 0;
}

VOID
atls_task_detach(struct AmiTlsBase *base)
{
    struct TlsTaskState *tts;
    struct TlsTaskState *dead;
    struct Task *task;

    if (base == NULL) {
        return;
    }

    dead = NULL;
    task = (struct Task *)FindTask(NULL);

    ObtainSemaphore(&base->atb_TaskSema);
    tts = atls_task_find(base, task);
    if (tts == NULL) {
        ReleaseSemaphore(&base->atb_TaskSema);
        return;
    }
    if (tts->tts_RefCount > 0) {
        tts->tts_RefCount--;
    }
    if (tts->tts_RefCount == 0) {
        Remove(&tts->tts_Node);
        dead = tts;
    }
    ReleaseSemaphore(&base->atb_TaskSema);

    if (dead != NULL) {
        FreeMem(dead, sizeof(*dead));
    }
}
