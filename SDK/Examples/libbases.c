/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * libbases.c - TlsBase / SocketBase for SAS/C #pragma libcall dispatch.
 */

#include <exec/types.h>
#include <exec/libraries.h>

struct Library *TlsBase;
struct Library *SocketBase;
int errno;
int h_errno;
