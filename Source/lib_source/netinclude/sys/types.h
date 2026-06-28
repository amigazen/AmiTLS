/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * Fallback sys/types.h when SDK netinclude: has no sys/types.h.
 * sys/socket.h and netinet/* come from the SDK netinclude assign.
 */

#ifndef ATLS_SYS_TYPES_H
#define ATLS_SYS_TYPES_H

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif

typedef LONG ssize_t;
typedef ULONG u_long;
typedef LONG gid_t;
typedef LONG pid_t;
typedef ULONG uid_t;

#endif /* ATLS_SYS_TYPES_H */
