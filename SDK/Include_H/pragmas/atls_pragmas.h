/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_pragmas.h - SAS/C pragmas for amitls.library
 *
 * FuncTab[] order MUST match SDK/SFD/amitls_lib.sfd (bias 0x1e, +6 per LVO).
 */

#ifndef PRAGMAS_ATLS_H
#define PRAGMAS_ATLS_H

#ifndef CLIB_ATLS_PROTOS_H
#include <clib/atls_protos.h>
#endif

#pragma libcall TlsBase TlsBaseTagList                 1e 801
#pragma libcall TlsBase TlsError                       24 00
#pragma libcall TlsBase TlsGetErrorString              2a 001
#pragma libcall TlsBase TlsTaskAttach                  30 9802
#pragma libcall TlsBase TlsTaskDetach                  36 00
#pragma libcall TlsBase NewTlsContext                  3c 801
#pragma libcall TlsBase DisposeTlsContext              42 801
#pragma libcall TlsBase SetTlsContextAttrsA            48 9802
#pragma libcall TlsBase NewTlsConnection               4e 801
#pragma libcall TlsBase DisposeTlsConnection           54 801
#pragma libcall TlsBase TlsAttachSocket                5a a90804
#pragma libcall TlsBase TlsRead                        60 09804
#pragma libcall TlsBase TlsWrite                       66 09803
#pragma libcall TlsBase TlsPending                     6c 801
#pragma libcall TlsBase TlsShutdown                    72 801
#pragma libcall TlsBase TlsGetLastError                78 801
#pragma libcall TlsBase TlsGetCertVerifyDetail         7e 801
#pragma libcall TlsBase TlsGetPeerCert                 84 9802
#pragma libcall TlsBase TlsPeerCertFree                8a 801
#pragma libcall TlsBase TlsLoadCABundle                90 801
#pragma libcall TlsBase TlsAddTrustedCert               96 90003
#pragma libcall TlsBase TlsClearTrustedCerts           9c 00
#pragma libcall TlsBase TlsHandshake                   a2 8002

#endif /* PRAGMAS_ATLS_H */
