/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_socket.c - bsdsocket I/O on caller-provided TCP file descriptors
 *
 * Each TlsConnection snapshots the attaching task's SocketBase and errno
 * pointer so interleaved multi-connection I/O stays on the correct bases.
 */

#include <exec/types.h>

#include <sys/socket.h>
#include <sys/errno.h>
#include <proto/bsdsocket.h>

#include <utility/tagitem.h>

#include <libraries/bsdsocket.h>

#include <string.h>

#include "private/atls_internal.h"
#include "atls_socket.h"

extern struct Library *SocketBase;
extern int errno;
extern int h_errno;

#ifndef ATLS_TLS_SEND_CHUNK
#define ATLS_TLS_SEND_CHUNK 512UL
#endif
#ifndef ATLS_TLS_WAIT_US
#define ATLS_TLS_WAIT_US 50000UL
#endif
#ifndef ATLS_TLS_IO_TRIES
#define ATLS_TLS_IO_TRIES 400
#endif

static LONG g_atls_sock_errno = 0;
static APTR g_atls_sock_errno_ptr = NULL;

VOID
atls_sock_set_errno_ptr(APTR errno_ptr)
{
    g_atls_sock_errno_ptr = errno_ptr;
}

VOID
atls_sock_configure_errno(APTR errno_ptr)
{
    struct TagItem tags[3];
    APTR errp;

    if (SocketBase == NULL) {
        return;
    }
    if (errno_ptr != NULL) {
        errp = errno_ptr;
    } else if (g_atls_sock_errno_ptr != NULL) {
        errp = g_atls_sock_errno_ptr;
    } else {
        errp = (APTR)&errno;
    }
    tags[0].ti_Tag = SBTM_SETVAL(SBTC_ERRNOPTR(sizeof(int)));
    tags[0].ti_Data = (ULONG)errp;
    tags[1].ti_Tag = SBTM_SETVAL(SBTC_HERRNOLONGPTR);
    tags[1].ti_Data = (ULONG)&h_errno;
    tags[2].ti_Tag = TAG_END;
    SocketBaseTagList(tags);
}

VOID
atls_conn_bind_io(struct TlsConnection *conn)
{
    if (conn == NULL) {
        return;
    }
    if (conn->tc_SocketBase != NULL) {
        SocketBase = conn->tc_SocketBase;
    }
    atls_sock_set_errno_ptr(conn->tc_ErrnoPtr);
    atls_sock_configure_errno(conn->tc_ErrnoPtr);
}

static LONG
atls_sock_fetch_errno(void)
{
    if (g_atls_sock_errno_ptr != NULL) {
        return (LONG)(*(int *)g_atls_sock_errno_ptr);
    }
    return (LONG)errno;
}

static VOID
atls_sock_store_errno(LONG err)
{
    g_atls_sock_errno = err;
}

BOOL
atls_sock_is_wouldblock(LONG err)
{
    if (err == EWOULDBLOCK || err == EAGAIN) {
        return TRUE;
    }
    return FALSE;
}

LONG
atls_sock_last_errno(void)
{
    return g_atls_sock_errno;
}

LONG
atls_sock_send(LONG fd, const UBYTE *buf, ULONG len)
{
    LONG r;

    atls_sock_store_errno(0);
    if (SocketBase == NULL || fd < 0 || buf == NULL || len == 0) {
        return -1;
    }
    r = send(fd, (const char *)buf, (int)len, 0);
    if (r < 0) {
        atls_sock_store_errno(atls_sock_fetch_errno());
    }
    return r;
}

LONG
atls_sock_recv(LONG fd, UBYTE *buf, ULONG maxlen)
{
    LONG r;

    atls_sock_store_errno(0);
    if (SocketBase == NULL || fd < 0 || buf == NULL || maxlen == 0) {
        return -1;
    }
    r = recv(fd, (char *)buf, (int)maxlen, 0);
    if (r < 0) {
        atls_sock_store_errno(atls_sock_fetch_errno());
    }
    return r;
}

LONG
atls_sock_wait_read(LONG fd, ULONG micros)
{
    fd_set rfds;
    struct timeval tv;
    LONG r;
    LONG nfds;

    if (SocketBase == NULL || fd < 0) {
        return -1;
    }
    FD_ZERO(&rfds);
    FD_SET((int)fd, &rfds);
    nfds = fd + 1;
    tv.tv_sec = (long)(micros / 1000000UL);
    tv.tv_usec = (long)(micros % 1000000UL);
    atls_sock_store_errno(0);
    r = WaitSelect((int)nfds, &rfds, NULL, NULL, &tv, NULL);
    if (r < 0) {
        atls_sock_store_errno(atls_sock_fetch_errno());
    }
    return r;
}

LONG
atls_sock_wait_write(LONG fd, ULONG micros)
{
    fd_set wfds;
    struct timeval tv;
    LONG r;
    LONG nfds;

    if (SocketBase == NULL || fd < 0) {
        return -1;
    }
    FD_ZERO(&wfds);
    FD_SET((int)fd, &wfds);
    nfds = fd + 1;
    tv.tv_sec = (long)(micros / 1000000UL);
    tv.tv_usec = (long)(micros % 1000000UL);
    atls_sock_store_errno(0);
    r = WaitSelect((int)nfds, NULL, &wfds, NULL, &tv, NULL);
    if (r < 0) {
        atls_sock_store_errno(atls_sock_fetch_errno());
    }
    return r;
}

LONG
atls_sock_send_all(LONG fd, const UBYTE *buf, ULONG len, UBYTE suppress_alerts,
    BOOL nonblocking)
{
    ULONG done;
    ULONG chunk;
    LONG r;
    LONG err;
    UWORD tries;

    done = 0;
    if (fd < 0 || buf == NULL || len == 0) {
        return -1;
    }
    if (suppress_alerts && len >= 1 && buf[0] == 0x15) {
        return (LONG)len;
    }
    while (done < len) {
        r = 0;
        chunk = len - done;
        if (chunk > ATLS_TLS_SEND_CHUNK) {
            chunk = ATLS_TLS_SEND_CHUNK;
        }
        for (tries = 0; tries < ATLS_TLS_IO_TRIES; tries++) {
            r = atls_sock_send(fd, buf + done, chunk);
            if (r > 0) {
                break;
            }
            err = atls_sock_last_errno();
            if (r < 0 && err != 0 && !atls_sock_is_wouldblock(err)) {
                return -1;
            }
            if (nonblocking && atls_sock_is_wouldblock(err)) {
                return -1;
            }
            if (atls_sock_wait_write(fd, ATLS_TLS_WAIT_US) < 0) {
                return -1;
            }
        }
        if (r <= 0) {
            return -1;
        }
        done += (ULONG)r;
    }
    return (LONG)done;
}

LONG
atls_sock_recv_some(LONG fd, UBYTE *buf, ULONG len, BOOL nonblocking)
{
    LONG r;
    LONG err;
    UWORD tries;

    if (fd < 0 || buf == NULL || len == 0) {
        return -1;
    }
    for (tries = 0; tries < ATLS_TLS_IO_TRIES; tries++) {
        r = atls_sock_recv(fd, buf, len);
        if (r > 0) {
            return r;
        }
        err = atls_sock_last_errno();
        if (r < 0 && err != 0 && !atls_sock_is_wouldblock(err)) {
            return -1;
        }
        if (nonblocking && atls_sock_is_wouldblock(err)) {
            return -1;
        }
        if (atls_sock_wait_read(fd, ATLS_TLS_WAIT_US) < 0) {
            return -1;
        }
    }
    return -1;
}
