/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_socket.h - Socket I/O for BearSSL callbacks (caller-owned fd)
 */

#ifndef ATLS_SOCKET_H
#define ATLS_SOCKET_H

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif

struct TlsConnection;

VOID atls_sock_set_errno_ptr(APTR errno_ptr);
VOID atls_sock_configure_errno(APTR errno_ptr);
VOID atls_conn_bind_io(struct TlsConnection *conn);
LONG atls_sock_send(LONG fd, const UBYTE *buf, ULONG len);
LONG atls_sock_recv(LONG fd, UBYTE *buf, ULONG maxlen);
LONG atls_sock_wait_read(LONG fd, ULONG micros);
LONG atls_sock_wait_write(LONG fd, ULONG micros);
LONG atls_sock_last_errno(void);
BOOL atls_sock_is_wouldblock(LONG err);
LONG atls_sock_send_all(LONG fd, const UBYTE *buf, ULONG len, UBYTE suppress_alerts,
    BOOL nonblocking);
LONG atls_sock_recv_some(LONG fd, UBYTE *buf, ULONG len, BOOL nonblocking);

#endif /* ATLS_SOCKET_H */
