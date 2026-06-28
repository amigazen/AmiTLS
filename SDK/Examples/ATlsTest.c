/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * ATlsTest.c - Standalone amitls.library smoke / regression harness (SAS/C).
 *
 * Run after "smake install" and "smake headers" in Source/lib_source.
 *
 *   ATlsTest                    offline API tests only
 *   ATlsTest example.com        offline + HTTPS GET on port 443
 *
 *   ATlsTest -q example.com
 *       Quiet mode: only FAIL lines and the final summary.
 *
 *   ATlsTest -v example.com
 *       Verbose API trace (pointers, rc, errno, response snippet).
 *
 *   ATlsTest -ca testdata/atlstest-ca.pem example.com
 *       Live HTTPS with ATSSL_VERIFY_PEER (test CA will not verify real sites).
 *
 *   ATlsTest -verify -ca RAM:mozilla.pem example.com
 *       Live verified HTTPS using a real Mozilla-style CA bundle on disk.
 *
 * Offline tests cover VERIFY_PEER without anchors, missing CA bundle I/O,
 * PEM trust load, deferred handshake (read before write), WANT_READ/WRITE
 * rc semantics, per-connection TlsGetLastError vs TlsError(), and dual
 * connection handles.  With a hostname, live tests add wrong-CA verify
 * failure and two parallel VERIFY_NONE sessions.
 *
 * Redirect on Amiga: ATlsTest >RAM:ATlsTest.out
 */

#include <exec/types.h>
#include <exec/memory.h>
#include <devices/timer.h>
#include <dos/dos.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <libraries/amitls.h>
#include <clib/compiler-specific.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/atls.h>

/* Must match private/atls_build.h ATLS_BR_EPOCH_DAYS (ATlsTest-only check). */
#ifndef ATLS_TEST_BR_EPOCH_DAYS
#define ATLS_TEST_BR_EPOCH_DAYS (719528UL + 2922UL)
#endif
#ifndef ATLS_TEST_BR_TICK_HZ
#define ATLS_TEST_BR_TICK_HZ 50UL
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <libraries/bsdsocket.h>
#include <proto/bsdsocket.h>

extern int errno;
extern int h_errno;

static const char version_tag[] = "\0$VER: ATlsTest 1.0 (23.6.2026)";

#define ATLS_TEST_HTTPS_PORT  443UL
#define ATLS_TEST_READ_MAX    4096UL

/* Live HTTPS read buffer (heap would also work; static avoids large stack frames). */
static UBYTE at_live_body[ATLS_TEST_READ_MAX];

#define ATLS_TEST_CA_REL      "testdata/atlstest-ca.pem"
#define ATLS_TEST_CA_RAM      "RAM:ATlsTest_ca.pem"
#define ATLS_TEST_CA_MISSING  "RAM:ATlsTest_no_such_ca.pem"
#define ATLS_TEST_CACERT_REL  "testdata/cacert.pem"

/* Self-signed test CA; also shipped as testdata/atlstest-ca.pem */
static const char atlstest_ca_pem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICsjCCAZoCCQCMB6bA/t5kGDANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDDBBB\n"
    "VGxzVGVzdCBUZXN0IENBMB4XDTI2MDYyNDE3NDgxNFoXDTM2MDYyMTE3NDgxNFow\n"
    "GzEZMBcGA1UEAwwQQVRsc1Rlc3QgVGVzdCBDQTCCASIwDQYJKoZIhvcNAQEBBQAD\n"
    "ggEPADCCAQoCggEBAL+BM8wEKSoRfrgr0l9yFIu+lL2omqI3O4KPLxZyFDzXuPlW\n"
    "RUi2k7Q2IcHNoAvYYbgA8Z/pbccP+42iVnponkebJXcpq6As95cvCE0qbYrvq8g1\n"
    "9bZ+n282OO2RdTX0M59sNfkgarVOu5S1gG7ZWIM83nUSuNT5hx9eeJniQO6cx0j6\n"
    "73PsLJwSnlhGuXK45qo2ZzRP8hpgE4j04vPFoIO0OgdKYuSCncNDr2hLWX0LJXYG\n"
    "wp6CnIl0mbgsT+fC9LmidQetoEqlW1BMC+ndQzVDgFi23ys3P5FFWr1OjZPDRpQe\n"
    "7go34mUaD+HPCwjZ1QNKstbyXX7h0vowQ2wErUcCAwEAATANBgkqhkiG9w0BAQsF\n"
    "AAOCAQEAAxw98W48Qd/VaRugrzQP++Ru3KUih5h9fFvMZTJ7x84wSKVM5y/bdvL4\n"
    "czcOVkPYg/mT/XHfEOT59/h4YN0SpjLm1TfTgTVqXHAwumqB606knuYvfIW0XwIu\n"
    "SS28rSvI1Y2ZOdgeAAOsqTxytJI+QkmLc2F1Ys0kSjNdvJW+yXYWgTx/0QazRqwI\n"
    "SlYWIoALR69g1QiSDP1cAV3adOI87xytBylnzRIRsncLTxzeomRuv99OvFyP+u4Z\n"
    "yj9gSb8mCMKi0zTLBt+yzLP/WEj/oK4rToCRbSUmfiA1NE0BX+404uGZrpKDnykm\n"
    "SjzKeV0MI9htQ/Idvt7qPMehFTg0Gg==\n"
    "-----END CERTIFICATE-----\n";

static BOOL
at_tls_ok(LONG rc)
{
    if (rc > 0 && rc < ERROR_TLS_NOT_IMPLEMENTED) {
        return TRUE;
    }
    return FALSE;
}

static BOOL
at_tls_want(LONG rc)
{
    if (rc == ERROR_TLS_WANT_READ || rc == ERROR_TLS_WANT_WRITE) {
        return TRUE;
    }
    return FALSE;
}

static ULONG at_pass;
static ULONG at_fail;
static ULONG at_step_id;
static int at_errno_slot;
static BOOL at_quiet;
static BOOL at_verbose;
static BOOL at_test_socket_open;
static STRPTR at_ca_path;
static BOOL at_live_verify;

static VOID
at_flush(VOID)
{
    Flush(Output());
}

static VOID
at_printf(STRPTR fmt, ...)
{
    char buf[512];
    va_list ap;

    va_start(ap, fmt);
    vsprintf(buf, (const char *)fmt, ap);
    va_end(ap);
    Printf("%s", buf);
    at_flush();
}

static VOID
at_log(STRPTR msg)
{
    if (!at_quiet) {
        at_printf("ATlsTest:     %s\n", msg);
    }
}

static VOID
at_dbg(STRPTR fmt, ...)
{
    char buf[512];
    va_list ap;

    if (!at_verbose) {
        return;
    }
    va_start(ap, fmt);
    vsprintf(buf, (const char *)fmt, ap);
    va_end(ap);
    at_printf("ATlsTest:     %s\n", buf);
}

static VOID
at_step(STRPTR step)
{
    at_step_id++;
    if (!at_quiet) {
        at_printf("ATlsTest[%04lu] %s\n", (unsigned long)at_step_id, step);
    }
}

static VOID
at_log_tls(STRPTR where)
{
    LONG code;
    STRPTR msg;
    char buf[128];

    code = TlsError();
    msg = TlsGetErrorString(code);
    if (msg == NULL) {
        msg = (STRPTR)"?";
    }
    sprintf(buf, "%s: TlsError()=%ld (%s) errno_slot=%ld",
        where, (long)code, (char *)msg, (long)at_errno_slot);
    if (at_quiet) {
        at_printf("ATlsTest:     %s\n", buf);
    } else {
        at_log((STRPTR)buf);
    }
}

static VOID
at_note(STRPTR name, BOOL ok, STRPTR detail)
{
    if (ok) {
        at_pass++;
        if (!at_quiet) {
            at_printf("ATlsTest: PASS %s", name);
            if (detail != NULL && detail[0] != '\0') {
                at_printf(" (%s)", detail);
            }
            at_printf("\n");
        }
    } else {
        at_fail++;
        at_printf("ATlsTest: FAIL %s", name);
        if (detail != NULL && detail[0] != '\0') {
            at_printf(" (%s)", detail);
        }
        at_printf("\n");
    }
}

static VOID
at_note_code(STRPTR name, LONG code)
{
    char buf[96];
    STRPTR msg;

    msg = TlsGetErrorString(code);
    if (msg == NULL) {
        msg = (STRPTR)"?";
    }
    sprintf(buf, "rc=%ld %s", (long)code, (char *)msg);
    at_log_tls(name);
    at_note(name, FALSE, (STRPTR)buf);
}

static STRPTR
at_br_x509_err_name(LONG brerr)
{
    switch (brerr) {
    case 27:
        return (STRPTR)"BAD_SIGNATURE";
    case 48:
        return (STRPTR)"X509_BAD_TIME";
    case 52:
        return (STRPTR)"X509_BAD_SIGNATURE";
    case 54:
        return (STRPTR)"X509_EXPIRED";
    case 56:
        return (STRPTR)"X509_BAD_SERVER_NAME";
    case 62:
        return (STRPTR)"X509_NOT_TRUSTED";
    default:
        return NULL;
    }
}

static VOID
at_log_system_date(VOID)
{
    struct DateStamp ds;
    char buf[128];
    ULONG year;
    ULONG bear_day;
    ULONG bear_sec;

    DateStamp(&ds);
    year = 1978UL + (ds.ds_Days / 365UL);
    bear_day = ATLS_TEST_BR_EPOCH_DAYS + (ULONG)ds.ds_Days;
    bear_sec = (ULONG)ds.ds_Minute * 60UL
        + (ULONG)ds.ds_Tick / ATLS_TEST_BR_TICK_HZ;
    sprintf(buf,
        "DateStamp ds_Days=%lu ds_Minute=%lu ds_Tick=%lu (~year %lu)",
        (unsigned long)ds.ds_Days, (unsigned long)ds.ds_Minute,
        (unsigned long)ds.ds_Tick, (unsigned long)year);
    at_log((STRPTR)buf);
    sprintf(buf,
        "BearSSL validation day=%lu sec=%lu (ep %lu; want ep722450 day~740159 Jun26)",
        (unsigned long)bear_day, (unsigned long)bear_sec,
        (unsigned long)ATLS_TEST_BR_EPOCH_DAYS);
    at_log((STRPTR)buf);
    if (bear_day < 740000UL && ds.ds_Days > 17000UL) {
        at_log((STRPTR)"WARN: validation day too low -> wrong epoch (722084?)");
    }
}

static VOID
at_note_verify_fail(struct TlsConnection *conn, STRPTR name, LONG rc)
{
    char buf[128];
    LONG brerr;
    STRPTR brname;
    STRPTR msg;

    brerr = TlsGetCertVerifyDetail(conn);
    brname = at_br_x509_err_name(brerr);
    msg = TlsGetErrorString(rc);
    if (msg == NULL) {
        msg = (STRPTR)"?";
    }
    at_log_system_date();
    if (brname != NULL) {
        sprintf(buf, "rc=%ld %s BearSSL brerr=%ld (%s)",
            (long)rc, (char *)msg, (long)brerr, (char *)brname);
    } else if (brerr != 0) {
        sprintf(buf, "rc=%ld %s BearSSL brerr=%ld",
            (long)rc, (char *)msg, (long)brerr);
    } else {
        sprintf(buf, "rc=%ld %s (no BearSSL brerr recorded)",
            (long)rc, (char *)msg);
    }
    at_log_tls(name);
    at_note(name, FALSE, (STRPTR)buf);
}

static BOOL
at_open_libs(VOID)
{
    at_step("OpenLibrary(amitls.library)");
    TlsBase = OpenLibrary((STRPTR)AMITLSNAME, AMITLSVERSION);
    at_dbg("TlsBase=%08lx", (unsigned long)TlsBase);
    if (TlsBase == NULL) {
        at_note("OpenLibrary(amitls.library)", FALSE, (STRPTR)"not found");
        return FALSE;
    }
    if (TlsBase->lib_IdString != NULL) {
        at_log(TlsBase->lib_IdString);
    }
    at_note("OpenLibrary(amitls.library)", TRUE, NULL);
    return TRUE;
}

static VOID
at_socket_configure_errno(VOID)
{
    struct TagItem tags[3];

    if (SocketBase == NULL) {
        return;
    }
    tags[0].ti_Tag = SBTM_SETVAL(SBTC_ERRNOPTR(sizeof(int)));
    tags[0].ti_Data = (ULONG)&at_errno_slot;
    tags[1].ti_Tag = SBTM_SETVAL(SBTC_HERRNOLONGPTR);
    tags[1].ti_Data = (ULONG)&h_errno;
    tags[2].ti_Tag = TAG_END;
    SocketBaseTagList(tags);
}

static BOOL
at_ensure_test_socket(VOID)
{
    if (SocketBase != NULL) {
        at_dbg("SocketBase already %08lx", (unsigned long)SocketBase);
        return TRUE;
    }

    at_step("OpenLibrary(bsdsocket.library)");
    SocketBase = OpenLibrary((STRPTR)"bsdsocket.library", 4);
    at_dbg("SocketBase=%08lx", (unsigned long)SocketBase);
    if (SocketBase == NULL) {
        at_note("OpenLibrary(bsdsocket.library)", FALSE, (STRPTR)"not found");
        return FALSE;
    }
    at_test_socket_open = TRUE;
    at_socket_configure_errno();
    at_note("OpenLibrary(bsdsocket.library)", TRUE, NULL);
    return TRUE;
}

static VOID
at_close_libs(VOID)
{
    if (SocketBase != NULL && at_test_socket_open) {
        CloseLibrary(SocketBase);
        SocketBase = NULL;
        at_test_socket_open = FALSE;
    }
    if (TlsBase != NULL) {
        CloseLibrary(TlsBase);
        TlsBase = NULL;
    }
}

static BOOL
at_ensure_task_attached(VOID)
{
    LONG rc;

    if (!at_ensure_test_socket()) {
        return FALSE;
    }
    at_errno_slot = 0;
    rc = TlsTaskAttach(SocketBase, (APTR)&at_errno_slot);
    if (rc != 0) {
        at_note_code("TlsTaskAttach", rc);
        return FALSE;
    }
    return TRUE;
}

static struct TlsContext *
at_new_context_verify_ca(ULONG verify, STRPTR ca_path)
{
    struct TlsContext *ctx;
    struct TagItem tags[3];
    ULONG n;

    n = 0;
    tags[n].ti_Tag = ATSA_SSL_VERIFY;
    tags[n].ti_Data = (ULONG)verify;
    n++;
    if (ca_path != NULL && ca_path[0] != '\0') {
        tags[n].ti_Tag = ATSA_CA_BUNDLE_PATH;
        tags[n].ti_Data = (ULONG)ca_path;
        n++;
    }
    tags[n].ti_Tag = TAG_DONE;
    tags[n].ti_Data = 0;
    ctx = NewTlsContext(tags);
    return ctx;
}

static LONG
at_attach_socket(struct TlsConnection *conn, LONG sock, STRPTR hostname,
    ULONG verify, BOOL nonblocking)
{
    struct TagItem tags[3];
    ULONG n;

    n = 0;
    tags[n].ti_Tag = ATTA_SSL_VERIFY;
    tags[n].ti_Data = (ULONG)verify;
    n++;
    if (nonblocking) {
        tags[n].ti_Tag = ATTA_NON_BLOCKING;
        tags[n].ti_Data = (ULONG)TRUE;
        n++;
    }
    tags[n].ti_Tag = TAG_DONE;
    tags[n].ti_Data = 0;
    return TlsAttachSocket(conn, sock, hostname, tags);
}

static BOOL
at_file_exists(STRPTR path)
{
    BPTR lock;

    if (path == NULL || path[0] == '\0') {
        return FALSE;
    }
    lock = Lock((STRPTR)path, ACCESS_READ);
    if (lock == (BPTR)0) {
        return FALSE;
    }
    UnLock(lock);
    return TRUE;
}

static BOOL
at_install_test_ca(VOID)
{
    BPTR fh;
    LONG len;
    LONG total;
    LONG n;

    DeleteFile((STRPTR)ATLS_TEST_CA_RAM);
    len = (LONG)strlen(atlstest_ca_pem);
    fh = Open((STRPTR)ATLS_TEST_CA_RAM, MODE_NEWFILE);
    if (fh == (BPTR)0) {
        return FALSE;
    }
    total = 0;
    while (total < len) {
        n = Write(fh, (APTR)(atlstest_ca_pem + total), len - total);
        if (n <= 0) {
            Close(fh);
            DeleteFile((STRPTR)ATLS_TEST_CA_RAM);
            return FALSE;
        }
        total += n;
    }
    Close(fh);
    return TRUE;
}

static VOID
at_clear_base_ca_path(VOID)
{
    struct TagItem tags[2];

    tags[0].ti_Tag = ATBT_CA_BUNDLE_PATH;
    tags[0].ti_Data = (ULONG)"";
    tags[1].ti_Tag = TAG_DONE;
    tags[1].ti_Data = 0;
    TlsBaseTagList(tags);
    TlsClearTrustedCerts();
}

static STRPTR
at_test_ca_path(VOID)
{
    if (at_file_exists((STRPTR)ATLS_TEST_CA_RAM)) {
        return (STRPTR)ATLS_TEST_CA_RAM;
    }
    if (at_file_exists((STRPTR)ATLS_TEST_CA_REL)) {
        return (STRPTR)ATLS_TEST_CA_REL;
    }
    return NULL;
}

static VOID
at_test_error_strings(VOID)
{
    STRPTR s;

    at_step("TlsGetErrorString samples");
    s = TlsGetErrorString(0);
    at_dbg("TlsGetErrorString(0) -> \"%s\"", s ? (char *)s : "(null)");
    if (s != NULL && strcmp((char *)s, "No error") == 0) {
        at_note("TlsGetErrorString(0)", TRUE, NULL);
    } else {
        at_note("TlsGetErrorString(0)", FALSE, s);
    }

    s = TlsGetErrorString(ERROR_TLS_INVALID_HANDLE);
    at_dbg("TlsGetErrorString(%ld) -> \"%s\"",
        (long)ERROR_TLS_INVALID_HANDLE, s ? (char *)s : "(null)");
    if (s != NULL && strcmp((char *)s, "Invalid handle") == 0) {
        at_note("TlsGetErrorString(INVALID_HANDLE)", TRUE, NULL);
    } else {
        at_note("TlsGetErrorString(INVALID_HANDLE)", FALSE, s);
    }

    s = TlsGetErrorString(ERROR_TLS_WANT_READ);
    if (s != NULL && strstr((char *)s, "read") != NULL) {
        at_note("TlsGetErrorString(WANT_READ)", TRUE, NULL);
    } else {
        at_note("TlsGetErrorString(WANT_READ)", FALSE, s);
    }

    s = TlsGetErrorString(ERROR_TLS_WANT_WRITE);
    if (s != NULL && strstr((char *)s, "write") != NULL) {
        at_note("TlsGetErrorString(WANT_WRITE)", TRUE, NULL);
    } else {
        at_note("TlsGetErrorString(WANT_WRITE)", FALSE, s);
    }
}

static VOID
at_test_base_tags(VOID)
{
    struct TagItem tags[2];
    LONG rc;

    at_step("TlsBaseTagList / TlsError");
    tags[0].ti_Tag = ATBT_SSL_VERIFY;
    tags[0].ti_Data = (ULONG)ATSSL_VERIFY_NONE;
    tags[1].ti_Tag = TAG_DONE;
    tags[1].ti_Data = 0;

    at_log((STRPTR)"TlsBaseTagList(ATBT_SSL_VERIFY, ATSSL_VERIFY_NONE)");
    rc = TlsBaseTagList(tags);
    at_dbg("TlsBaseTagList -> %ld", (long)rc);
    at_log_tls("after TlsBaseTagList");
    if (rc != 0) {
        at_note_code("TlsBaseTagList", rc);
        return;
    }
    if (TlsError() != 0) {
        at_note_code("TlsError after TlsBaseTagList", TlsError());
        return;
    }
    at_note("TlsBaseTagList", TRUE, (STRPTR)"ATSSL_VERIFY_NONE");
}

static VOID
at_test_task_attach(VOID)
{
    LONG rc;

    at_step("TlsTaskAttach / TlsTaskDetach");
    if (!at_ensure_test_socket()) {
        at_note_code("TlsTaskAttach", ERROR_TLS_IO);
        return;
    }
    at_errno_slot = 0;
    at_log((STRPTR)"TlsTaskAttach(SocketBase, &errno_slot)");
    rc = TlsTaskAttach(SocketBase, (APTR)&at_errno_slot);
    at_dbg("TlsTaskAttach -> %ld errno_slot=%ld", (long)rc, (long)at_errno_slot);
    at_log_tls("after TlsTaskAttach");
    if (rc != 0) {
        at_note_code("TlsTaskAttach", rc);
        return;
    }
    at_log((STRPTR)"TlsTaskDetach()");
    TlsTaskDetach();
    at_log_tls("after TlsTaskDetach");
    at_note("TlsTaskAttach/TlsTaskDetach", TRUE, (STRPTR)"caller SocketBase");
}

static VOID
at_test_context(VOID)
{
    struct TlsContext *ctx;
    struct TagItem tags[2];
    LONG rc;

    at_step("NewTlsContext / SetTlsContextAttrsA");
    ctx = NewTlsContext(NULL);
    at_dbg("NewTlsContext -> %08lx", (unsigned long)ctx);
    if (ctx == NULL) {
        at_log_tls("NewTlsContext failed");
        at_note("NewTlsContext", FALSE, (STRPTR)"NULL");
        return;
    }

    tags[0].ti_Tag = ATSA_SSL_VERIFY;
    tags[0].ti_Data = (ULONG)ATSSL_VERIFY_NONE;
    tags[1].ti_Tag = TAG_DONE;
    tags[1].ti_Data = 0;
    at_log((STRPTR)"SetTlsContextAttrsA(ATSA_SSL_VERIFY, ATSSL_VERIFY_NONE)");
    rc = SetTlsContextAttrsA(ctx, tags);
    at_dbg("SetTlsContextAttrsA -> %ld", (long)rc);
    at_log_tls("after SetTlsContextAttrsA");
    if (rc != 0) {
        DisposeTlsContext(ctx);
        at_note_code("SetTlsContextAttrsA", rc);
        return;
    }

    DisposeTlsContext(ctx);
    at_note("TlsContext lifecycle", TRUE, NULL);
}

static VOID
at_test_context_ca_path(VOID)
{
    struct TlsContext *ctx;
    struct TagItem tags[2];
    LONG rc;

    at_step("SetTlsContextAttrsA ATSA_CA_BUNDLE_PATH");
    ctx = NewTlsContext(NULL);
    if (ctx == NULL) {
        at_note("NewTlsContext (CA path)", FALSE, (STRPTR)"NULL");
        return;
    }
    tags[0].ti_Tag = ATSA_CA_BUNDLE_PATH;
    tags[0].ti_Data = (ULONG)"RAM:TestCABundle.pem";
    tags[1].ti_Tag = TAG_DONE;
    tags[1].ti_Data = 0;
    rc = SetTlsContextAttrsA(ctx, tags);
    if (rc != 0) {
        DisposeTlsContext(ctx);
        at_note_code("SetTlsContextAttrsA CA path", rc);
        return;
    }
    DisposeTlsContext(ctx);
    at_note("TlsContext ATSA_CA_BUNDLE_PATH", TRUE, NULL);
}

static VOID
at_test_attach_requires_task(VOID)
{
    struct TlsConnection *conn;
    LONG rc;

    at_step("TlsAttachSocket without TlsTaskAttach");
    conn = NewTlsConnection(NULL);
    if (conn == NULL) {
        at_note("NewTlsConnection (no task)", FALSE, (STRPTR)"NULL");
        return;
    }
    rc = TlsAttachSocket(conn, 1, (STRPTR)"localhost", NULL);
    at_dbg("TlsAttachSocket -> %ld TlsGetLastError=%ld",
        (long)rc, (long)TlsGetLastError(conn));
    if (rc == ERROR_TLS_IO) {
        at_note("TlsAttachSocket needs TlsTaskAttach", TRUE, (STRPTR)"IO expected");
    } else {
        at_note_code("TlsAttachSocket without task", rc);
    }
    DisposeTlsConnection(conn);
}

static VOID
at_test_dual_connections(VOID)
{
    struct TlsConnection *conn_a;
    struct TlsConnection *conn_b;
    UBYTE buf[8];
    LONG rc_a;
    LONG rc_b;

    at_step("Dual TlsConnection per-connection errors");
    if (!at_ensure_test_socket()) {
        return;
    }
    at_errno_slot = 0;
    rc_a = TlsTaskAttach(SocketBase, (APTR)&at_errno_slot);
    if (rc_a != 0) {
        at_note_code("TlsTaskAttach (dual)", rc_a);
        return;
    }

    conn_a = NewTlsConnection(NULL);
    conn_b = NewTlsConnection(NULL);
    if (conn_a == NULL || conn_b == NULL) {
        if (conn_a != NULL) {
            DisposeTlsConnection(conn_a);
        }
        if (conn_b != NULL) {
            DisposeTlsConnection(conn_b);
        }
        TlsTaskDetach();
        at_note("NewTlsConnection x2", FALSE, (STRPTR)"NULL");
        return;
    }

    rc_a = TlsRead(conn_a, buf, sizeof(buf), 1);
    rc_b = TlsRead(conn_b, buf, sizeof(buf), 1);
    at_dbg("TlsRead A -> %ld last=%ld  B -> %ld last=%ld",
        (long)rc_a, (long)TlsGetLastError(conn_a),
        (long)rc_b, (long)TlsGetLastError(conn_b));
    if (rc_a == ERROR_TLS_HANDSHAKE && rc_b == ERROR_TLS_HANDSHAKE
        && TlsGetLastError(conn_a) == ERROR_TLS_HANDSHAKE
        && TlsGetLastError(conn_b) == ERROR_TLS_HANDSHAKE) {
        at_note("Dual connection TlsGetLastError", TRUE, (STRPTR)"independent");
    } else {
        at_note("Dual connection TlsGetLastError", FALSE, (STRPTR)"mismatch");
    }

    DisposeTlsConnection(conn_a);
    DisposeTlsConnection(conn_b);
    TlsTaskDetach();
}

static VOID
at_test_task_refcount(VOID)
{
    LONG rc;

    at_step("TlsTaskAttach refcount");
    if (!at_ensure_test_socket()) {
        return;
    }
    at_errno_slot = 0;
    rc = TlsTaskAttach(SocketBase, (APTR)&at_errno_slot);
    if (rc != 0) {
        at_note_code("TlsTaskAttach (ref 1)", rc);
        return;
    }
    rc = TlsTaskAttach(SocketBase, (APTR)&at_errno_slot);
    if (rc != 0) {
        TlsTaskDetach();
        at_note_code("TlsTaskAttach (ref 2)", rc);
        return;
    }
    TlsTaskDetach();
    rc = TlsTaskAttach(SocketBase, (APTR)&at_errno_slot);
    if (rc != 0) {
        TlsTaskDetach();
        at_note_code("TlsTaskAttach after partial detach", rc);
        return;
    }
    TlsTaskDetach();
    TlsTaskDetach();
    at_note("TlsTaskAttach refcount", TRUE, (STRPTR)"nested attach/detach");
}

static VOID
at_test_connection_handles(VOID)
{
    struct TlsConnection *conn;
    UBYTE buf[16];
    LONG rc;

    at_step("TlsConnection handle validation");
    conn = NewTlsConnection(NULL);
    at_dbg("NewTlsConnection -> %08lx", (unsigned long)conn);
    if (conn == NULL) {
        at_log_tls("NewTlsConnection failed");
        at_note("NewTlsConnection", FALSE, (STRPTR)"NULL");
        return;
    }

    if (!at_ensure_test_socket()) {
        DisposeTlsConnection(conn);
        return;
    }
    at_errno_slot = 0;
    rc = TlsTaskAttach(SocketBase, (APTR)&at_errno_slot);
    if (rc != 0) {
        DisposeTlsConnection(conn);
        at_note_code("TlsTaskAttach (handles)", rc);
        return;
    }

    at_log((STRPTR)"TlsRead before attach (expect ERROR_TLS_HANDSHAKE)");
    rc = TlsRead(conn, buf, sizeof(buf), 5);
    at_dbg("TlsRead -> %ld TlsGetLastError=%ld", (long)rc, (long)TlsGetLastError(conn));
    if (rc != ERROR_TLS_HANDSHAKE) {
        at_note_code("TlsRead before attach", rc);
    } else {
        at_note("TlsRead before attach", TRUE, (STRPTR)"HANDSHAKE expected");
    }

    at_log((STRPTR)"TlsAttachSocket(sock=-1) (expect ERROR_TLS_INVALID_HANDLE)");
    rc = TlsAttachSocket(conn, -1, (STRPTR)"localhost", NULL);
    at_dbg("TlsAttachSocket -> %ld", (long)rc);
    if (rc != ERROR_TLS_INVALID_HANDLE) {
        at_note_code("TlsAttachSocket bad sock", rc);
    } else {
        at_note("TlsAttachSocket bad sock", TRUE, NULL);
    }

    DisposeTlsConnection(conn);
    TlsTaskDetach();
    at_note("DisposeTlsConnection (no attach)", TRUE, NULL);
}

static VOID
at_test_trust_store_stubs(VOID)
{
    LONG rc;

    at_step("Trust store stubs (Tier 3)");
    at_log((STRPTR)"TlsLoadCABundle(RAM:CABundle.pem)");
    rc = TlsLoadCABundle((STRPTR)"RAM:CABundle.pem");
    at_dbg("TlsLoadCABundle -> %ld", (long)rc);
    at_log_tls("after TlsLoadCABundle");
    if (rc != 0) {
        at_note_code("TlsLoadCABundle", rc);
    } else {
        at_note("TlsLoadCABundle", TRUE, (STRPTR)"path stored");
    }

    at_log((STRPTR)"TlsAddTrustedCert(dummy, 5, ATCF_PEM)");
    rc = TlsAddTrustedCert((APTR)"dummy", 5, ATCF_PEM);
    at_dbg("TlsAddTrustedCert -> %ld", (long)rc);
    if (rc != ERROR_TLS_NOT_IMPLEMENTED) {
        at_note_code("TlsAddTrustedCert", rc);
    } else {
        at_note("TlsAddTrustedCert", TRUE, (STRPTR)"NOT_IMPLEMENTED");
    }

    TlsClearTrustedCerts();
    at_note("TlsClearTrustedCerts", TRUE, NULL);
}

static VOID
at_test_tls_ok_semantics(VOID)
{
    at_step("at_tls_ok / at_tls_want semantics");
    if (!at_tls_ok(ERROR_TLS_WANT_READ) && !at_tls_ok(ERROR_TLS_WANT_WRITE)
        && !at_tls_ok(ERROR_TLS_VERIFY) && at_tls_ok(128)) {
        at_note("at_tls_ok rejects errors", TRUE, NULL);
    } else {
        at_note("at_tls_ok rejects errors", FALSE, NULL);
    }
    if (at_tls_want(ERROR_TLS_WANT_READ) && at_tls_want(ERROR_TLS_WANT_WRITE)
        && !at_tls_want(ERROR_TLS_HANDSHAKE)) {
        at_note("at_tls_want WANT codes", TRUE, NULL);
    } else {
        at_note("at_tls_want WANT codes", FALSE, NULL);
    }
}

static VOID
at_test_verify_peer_no_ca(VOID)
{
    struct TlsContext *ctx;
    struct TlsConnection *conn;
    LONG rc;

    at_step("VERIFY_PEER without CA anchors");
    at_clear_base_ca_path();
    if (!at_ensure_task_attached()) {
        return;
    }
    ctx = at_new_context_verify_ca(ATSSL_VERIFY_PEER, NULL);
    if (ctx == NULL) {
        TlsTaskDetach();
        at_note("NewTlsContext (verify no ca)", FALSE, (STRPTR)"NULL");
        return;
    }
    conn = NewTlsConnection(ctx);
    if (conn == NULL) {
        DisposeTlsContext(ctx);
        TlsTaskDetach();
        at_note("NewTlsConnection (verify no ca)", FALSE, (STRPTR)"NULL");
        return;
    }
    rc = at_attach_socket(conn, 1, (STRPTR)"localhost", ATSSL_VERIFY_PEER, FALSE);
    at_dbg("TlsAttachSocket VERIFY_PEER no CA -> %ld last=%ld",
        (long)rc, (long)TlsGetLastError(conn));
    if (rc == ERROR_TLS_VERIFY && TlsGetLastError(conn) == ERROR_TLS_VERIFY) {
        at_note("VERIFY_PEER no CA", TRUE, (STRPTR)"VERIFY at attach");
    } else {
        at_note_code("VERIFY_PEER no CA", rc);
    }
    DisposeTlsConnection(conn);
    DisposeTlsContext(ctx);
    TlsTaskDetach();
}

static VOID
at_test_verify_peer_missing_ca(VOID)
{
    struct TlsContext *ctx;
    struct TlsConnection *conn;
    LONG rc;

    at_step("VERIFY_PEER missing CA bundle file");
    if (!at_ensure_task_attached()) {
        return;
    }
    ctx = at_new_context_verify_ca(ATSSL_VERIFY_PEER,
        (STRPTR)ATLS_TEST_CA_MISSING);
    if (ctx == NULL) {
        TlsTaskDetach();
        at_note("NewTlsContext (missing CA)", FALSE, (STRPTR)"NULL");
        return;
    }
    conn = NewTlsConnection(ctx);
    if (conn == NULL) {
        DisposeTlsContext(ctx);
        TlsTaskDetach();
        at_note("NewTlsConnection (missing CA)", FALSE, (STRPTR)"NULL");
        return;
    }
    rc = at_attach_socket(conn, 1, (STRPTR)"localhost", ATSSL_VERIFY_PEER, FALSE);
    at_dbg("TlsAttachSocket missing bundle -> %ld last=%ld",
        (long)rc, (long)TlsGetLastError(conn));
    if (rc == ERROR_TLS_IO && TlsGetLastError(conn) == ERROR_TLS_IO) {
        at_note("VERIFY_PEER missing CA file", TRUE, (STRPTR)"IO at attach");
    } else {
        at_note_code("VERIFY_PEER missing CA file", rc);
    }
    DisposeTlsConnection(conn);
    DisposeTlsContext(ctx);
    TlsTaskDetach();
}

static VOID
at_test_trust_pem_bundle_attach(VOID)
{
    struct TlsContext *ctx;
    struct TlsConnection *conn;
    STRPTR ca_path;
    LONG rc;

    at_step("PEM CA bundle load + VERIFY_PEER attach");
    ca_path = at_test_ca_path();
    if (ca_path == NULL) {
        at_note("PEM CA bundle attach", FALSE,
            (STRPTR)"no test CA (RAM: or testdata/)");
        return;
    }
    if (!at_ensure_task_attached()) {
        return;
    }
    ctx = at_new_context_verify_ca(ATSSL_VERIFY_PEER, ca_path);
    if (ctx == NULL) {
        TlsTaskDetach();
        at_note("NewTlsContext (PEM CA)", FALSE, (STRPTR)"NULL");
        return;
    }
    conn = NewTlsConnection(ctx);
    if (conn == NULL) {
        DisposeTlsContext(ctx);
        TlsTaskDetach();
        at_note("NewTlsConnection (PEM CA)", FALSE, (STRPTR)"NULL");
        return;
    }
    rc = at_attach_socket(conn, 1, (STRPTR)"localhost", ATSSL_VERIFY_PEER, FALSE);
    at_dbg("TlsAttachSocket with PEM anchors -> %ld", (long)rc);
    if (rc == 0) {
        at_note("PEM CA bundle attach", TRUE, (STRPTR)"engine OK");
    } else {
        at_note_code("PEM CA bundle attach", rc);
    }
    DisposeTlsConnection(conn);
    DisposeTlsContext(ctx);
    TlsTaskDetach();
}

static VOID
at_test_cacert_bundle_load(VOID)
{
    struct TlsContext *ctx;
    struct TlsConnection *conn;
    LONG rc;

    at_step("Mozilla cacert.pem bundle load + VERIFY_PEER attach");
    if (!at_file_exists((STRPTR)ATLS_TEST_CACERT_REL)) {
        at_log((STRPTR)"(skip cacert.pem; copy testdata/cacert.pem to Examples)");
        return;
    }
    if (!at_ensure_task_attached()) {
        return;
    }
    ctx = at_new_context_verify_ca(ATSSL_VERIFY_PEER, (STRPTR)ATLS_TEST_CACERT_REL);
    if (ctx == NULL) {
        TlsTaskDetach();
        at_note("NewTlsContext (cacert)", FALSE, (STRPTR)"NULL");
        return;
    }
    conn = NewTlsConnection(ctx);
    if (conn == NULL) {
        DisposeTlsContext(ctx);
        TlsTaskDetach();
        at_note("NewTlsConnection (cacert)", FALSE, (STRPTR)"NULL");
        return;
    }
    rc = at_attach_socket(conn, 1, (STRPTR)"localhost", ATSSL_VERIFY_PEER, FALSE);
    at_dbg("TlsAttachSocket cacert bundle -> %ld", (long)rc);
    if (rc == 0) {
        at_note("cacert.pem bundle attach", TRUE, (STRPTR)"engine OK");
    } else {
        at_note_code("cacert.pem bundle attach", rc);
    }
    DisposeTlsConnection(conn);
    DisposeTlsContext(ctx);
    TlsTaskDetach();
}

static VOID
at_test_atbt_ca_bundle_attach(VOID)
{
    struct TlsConnection *conn;
    struct TagItem tags[2];
    STRPTR ca_path;
    LONG rc;

    at_step("ATBT_CA_BUNDLE_PATH default + VERIFY_PEER attach");
    ca_path = at_test_ca_path();
    if (ca_path == NULL) {
        at_note("ATBT_CA_BUNDLE_PATH attach", FALSE,
            (STRPTR)"no test CA (RAM: or testdata/)");
        return;
    }
    tags[0].ti_Tag = ATBT_CA_BUNDLE_PATH;
    tags[0].ti_Data = (ULONG)ca_path;
    tags[1].ti_Tag = TAG_DONE;
    tags[1].ti_Data = 0;
    rc = TlsBaseTagList(tags);
    if (rc != 0) {
        at_note_code("TlsBaseTagList CA path", rc);
        return;
    }
    if (!at_ensure_task_attached()) {
        return;
    }
    conn = NewTlsConnection(NULL);
    if (conn == NULL) {
        TlsTaskDetach();
        at_note("NewTlsConnection (ATBT CA)", FALSE, (STRPTR)"NULL");
        return;
    }
    rc = at_attach_socket(conn, 1, (STRPTR)"localhost", ATSSL_VERIFY_PEER, FALSE);
    at_dbg("TlsAttachSocket ATBT CA -> %ld", (long)rc);
    if (rc == 0) {
        at_note("ATBT_CA_BUNDLE_PATH attach", TRUE, (STRPTR)"inherited path");
    } else {
        at_note_code("ATBT_CA_BUNDLE_PATH attach", rc);
    }
    DisposeTlsConnection(conn);
    TlsTaskDetach();
}

static VOID
at_test_deferred_handshake_offline(VOID)
{
    struct TlsConnection *conn;
    UBYTE buf[4];
    LONG rc_read;
    LONG rc_write;

    at_step("Deferred handshake (read before write, offline)");
    if (!at_ensure_task_attached()) {
        return;
    }
    conn = NewTlsConnection(NULL);
    if (conn == NULL) {
        TlsTaskDetach();
        at_note("NewTlsConnection (deferred)", FALSE, (STRPTR)"NULL");
        return;
    }
    rc_read = 0;
    rc_write = 0;
    if (at_attach_socket(conn, 1, (STRPTR)"localhost", ATSSL_VERIFY_NONE, FALSE) != 0) {
        DisposeTlsConnection(conn);
        TlsTaskDetach();
        at_note("Deferred handshake attach", FALSE, NULL);
        return;
    }
    rc_read = TlsRead(conn, buf, sizeof(buf), 1);
    at_dbg("TlsRead before handshake -> %ld last=%ld",
        (long)rc_read, (long)TlsGetLastError(conn));
    if (rc_read != ERROR_TLS_HANDSHAKE) {
        DisposeTlsConnection(conn);
        TlsTaskDetach();
        at_note_code("TlsRead before handshake", rc_read);
        return;
    }
    rc_write = TlsWrite(conn, (APTR)"x", 1);
    at_dbg("TlsWrite drives handshake -> %ld last=%ld",
        (long)rc_write, (long)TlsGetLastError(conn));
  /* I/O may fail on dummy sock=1; HANDSHAKE or socket error is acceptable. */
    if (rc_write == ERROR_TLS_HANDSHAKE || rc_write == ERROR_TLS_IO
        || rc_write == ERROR_TLS_WRITE_FAILED || at_tls_ok(rc_write)
        || at_tls_want(rc_write)) {
        at_note("Deferred handshake offline", TRUE, (STRPTR)"read blocked");
    } else {
        at_note_code("Deferred handshake offline write", rc_write);
    }
    DisposeTlsConnection(conn);
    TlsTaskDetach();
}

static VOID
at_test_conn_vs_bootstrap_error(VOID)
{
    struct TlsConnection *conn;
    struct TagItem tags[2];
    UBYTE buf[4];
    LONG rc;
    LONG boot_err;
    LONG conn_err;

    at_step("TlsGetLastError vs TlsError()");
    tags[0].ti_Tag = ATBT_SSL_VERIFY;
    tags[0].ti_Data = (ULONG)ATSSL_VERIFY_NONE;
    tags[1].ti_Tag = TAG_DONE;
    tags[1].ti_Data = 0;
    rc = TlsBaseTagList(tags);
    if (rc != 0) {
        at_note_code("TlsBaseTagList (error split)", rc);
        return;
    }
    if (!at_ensure_task_attached()) {
        return;
    }
    conn = NewTlsConnection(NULL);
    if (conn == NULL) {
        TlsTaskDetach();
        at_note("NewTlsConnection (error split)", FALSE, (STRPTR)"NULL");
        return;
    }
    boot_err = TlsError();
    rc = TlsRead(conn, buf, sizeof(buf), 1);
    conn_err = TlsGetLastError(conn);
    at_dbg("TlsRead -> %ld boot=%ld conn=%ld", (long)rc, (long)boot_err,
        (long)conn_err);
    if (rc == ERROR_TLS_HANDSHAKE && conn_err == ERROR_TLS_HANDSHAKE) {
        at_note("TlsGetLastError per conn", TRUE, (STRPTR)"HANDSHAKE");
    } else {
        at_note("TlsGetLastError per conn", FALSE, NULL);
    }
    DisposeTlsConnection(conn);
    TlsTaskDetach();
}

static VOID
at_test_nonblocking_attach_tag(VOID)
{
    struct TlsConnection *conn;
    LONG rc;

    at_step("ATTA_NON_BLOCKING attach tag");
    if (!at_ensure_task_attached()) {
        return;
    }
    conn = NewTlsConnection(NULL);
    if (conn == NULL) {
        TlsTaskDetach();
        at_note("NewTlsConnection (nonblock)", FALSE, (STRPTR)"NULL");
        return;
    }
    rc = at_attach_socket(conn, 1, (STRPTR)"localhost", ATSSL_VERIFY_NONE, TRUE);
    at_dbg("TlsAttachSocket NON_BLOCKING -> %ld", (long)rc);
    if (rc == 0) {
        at_note("ATTA_NON_BLOCKING attach", TRUE, NULL);
    } else {
        at_note_code("ATTA_NON_BLOCKING attach", rc);
    }
    DisposeTlsConnection(conn);
    TlsTaskDetach();
}

static VOID
at_test_get_peer_cert_no_handshake(VOID)
{
    struct TlsConnection *conn;
    struct TlsPeerCert cert;
    LONG rc;

    at_step("TlsGetPeerCert before handshake");
    if (!at_ensure_task_attached()) {
        return;
    }
    conn = NewTlsConnection(NULL);
    if (conn == NULL) {
        TlsTaskDetach();
        at_note("NewTlsConnection (peer cert)", FALSE, (STRPTR)"NULL");
        return;
    }
    memset(&cert, 0, sizeof(cert));
    rc = TlsGetPeerCert(conn, &cert);
    at_dbg("TlsGetPeerCert pre-handshake -> %ld", (long)rc);
    if (rc == ERROR_TLS_PROTOCOL) {
        at_note("TlsGetPeerCert pre-handshake", TRUE, (STRPTR)"PROTOCOL");
    } else {
        at_note_code("TlsGetPeerCert pre-handshake", rc);
    }
    TlsPeerCertFree(&cert);
    DisposeTlsConnection(conn);
    TlsTaskDetach();
}

/*
 * Accept bare hostnames or URLs (https://host/path).  gethostbyname() needs
 * the host part only.
 */
static STRPTR
at_normalize_host(STRPTR in, char *buf, ULONG buflen)
{
    STRPTR host;
    STRPTR p;
    ULONG i;

    host = in;
    if (host == NULL) {
        buf[0] = '\0';
        return (STRPTR)buf;
    }
    if (strncmp((char *)host, "https://", 8) == 0) {
        host += 8;
    } else if (strncmp((char *)host, "http://", 7) == 0) {
        host += 7;
    }
    i = 0;
    p = host;
    while (*p != '\0' && *p != '/' && *p != ':' && i < (buflen - 1)) {
        buf[i++] = *p++;
    }
    buf[i] = '\0';
    return (STRPTR)buf;
}

static BOOL
at_tcp_connect(STRPTR host, ULONG port, LONG *out_sock)
{
    struct hostent *he;
    struct sockaddr_in sa;
    LONG sock;
    LONG fd;
    char addrbuf[32];

    at_log((STRPTR)"gethostbyname()");
    he = gethostbyname((char *)host);
    if (he == NULL || he->h_addr_list == NULL || he->h_addr_list[0] == NULL) {
        at_dbg("gethostbyname failed errno=%ld h_errno=%ld",
            (long)errno, (long)h_errno);
        return FALSE;
    }
    sprintf(addrbuf, "%lu.%lu.%lu.%lu",
        (unsigned long)((UBYTE)he->h_addr_list[0][0]),
        (unsigned long)((UBYTE)he->h_addr_list[0][1]),
        (unsigned long)((UBYTE)he->h_addr_list[0][2]),
        (unsigned long)((UBYTE)he->h_addr_list[0][3]));
    at_dbg("resolved %s -> %s port %lu", (char *)host, addrbuf,
        (unsigned long)port);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    at_dbg("socket() -> %ld", (long)sock);
    if (sock < 0) {
        return FALSE;
    }
    if (sock == 0) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) {
            CloseSocket(sock);
            sock = fd;
        }
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((UWORD)port);
    memcpy(&sa.sin_addr, he->h_addr_list[0], (size_t)he->h_length);

    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        at_dbg("connect failed errno=%ld", (long)errno);
        CloseSocket(sock);
        return FALSE;
    }
    at_dbg("connect OK sock=%ld", (long)sock);

    *out_sock = sock;
    return TRUE;
}

static LONG
at_https_tls_write_get(struct TlsConnection *conn, STRPTR host)
{
    char req[256];
    LONG rc;

    sprintf(req, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", (char *)host);
    at_dbg("request %lu bytes", (unsigned long)strlen(req));
    rc = TlsWrite(conn, (APTR)req, (ULONG)strlen(req));
    at_dbg("TlsWrite -> %ld last=%ld", (long)rc, (long)TlsGetLastError(conn));
    return rc;
}

static BOOL
at_https_exchange(STRPTR host_arg, ULONG verify, STRPTR ca_path, STRPTR label,
    BOOL probe_deferred, BOOL probe_peer_cert)
{
    struct TlsContext *ctx;
    struct TlsConnection *conn;
    char hostbuf[256];
    STRPTR host;
    LONG sock;
    LONG rc;
    LONG n;
    ULONG got;
    STRPTR p;

    at_step(label);
    host = at_normalize_host(host_arg, hostbuf, (ULONG)sizeof(hostbuf));
    at_dbg("host_arg=\"%s\" normalized=\"%s\" verify=%lu ca=%s",
        host_arg ? (char *)host_arg : "", (char *)host,
        (unsigned long)verify, ca_path ? (char *)ca_path : "(none)");
    if (host[0] == '\0') {
        at_note(label, FALSE, (STRPTR)"no host");
        return FALSE;
    }
    if (verify != ATSSL_VERIFY_NONE && (ca_path == NULL || ca_path[0] == '\0')) {
        at_note(label, FALSE, (STRPTR)"VERIFY_PEER needs -ca path");
        return FALSE;
    }
    if (verify != ATSSL_VERIFY_NONE && !at_file_exists(ca_path)) {
        at_note(label, FALSE, ca_path);
        return FALSE;
    }

    if (!at_ensure_test_socket()) {
        return FALSE;
    }
    if (!at_tcp_connect(host, ATLS_TEST_HTTPS_PORT, &sock)) {
        at_note("TCP connect", FALSE, host);
        return FALSE;
    }
    at_note("TCP connect", TRUE, host);

    if (!at_ensure_task_attached()) {
        CloseSocket(sock);
        return FALSE;
    }

    ctx = NULL;
    if (ca_path != NULL && ca_path[0] != '\0') {
        ctx = at_new_context_verify_ca(verify, ca_path);
        if (ctx == NULL) {
            CloseSocket(sock);
            TlsTaskDetach();
            at_note("NewTlsContext (live)", FALSE, (STRPTR)"NULL");
            return FALSE;
        }
        conn = NewTlsConnection(ctx);
    } else {
        conn = NewTlsConnection(NULL);
    }
    at_dbg("NewTlsConnection -> %08lx sock=%ld",
        (unsigned long)conn, (long)sock);
    if (conn == NULL) {
        if (ctx != NULL) {
            DisposeTlsContext(ctx);
        }
        CloseSocket(sock);
        TlsTaskDetach();
        at_note("NewTlsConnection (live)", FALSE, (STRPTR)"NULL");
        return FALSE;
    }

    rc = at_attach_socket(conn, sock, host, verify, FALSE);
    at_dbg("TlsAttachSocket -> %ld TlsGetLastError=%ld",
        (long)rc, (long)TlsGetLastError(conn));
    if (rc != 0) {
        CloseSocket(sock);
        DisposeTlsConnection(conn);
        if (ctx != NULL) {
            DisposeTlsContext(ctx);
        }
        TlsTaskDetach();
        at_note_code("TlsAttachSocket (live)", rc);
        return FALSE;
    }
    at_note("TlsAttachSocket (live)", TRUE, NULL);

    if (probe_deferred) {
        UBYTE prebuf[4];

        rc = TlsRead(conn, prebuf, sizeof(prebuf), 2);
        at_dbg("TlsRead before write (deferred) -> %ld last=%ld",
            (long)rc, (long)TlsGetLastError(conn));
        if (rc == ERROR_TLS_HANDSHAKE) {
            at_note("Deferred handshake (live)", TRUE, (STRPTR)"read blocked");
        } else {
            at_note("Deferred handshake (live)", FALSE, (STRPTR)"unexpected rc");
        }
    }

    rc = at_https_tls_write_get(conn, host);
    if (!at_tls_ok(rc)) {
        TlsShutdown(conn);
        CloseSocket(sock);
        if (rc == ERROR_TLS_VERIFY) {
            at_note_verify_fail(conn, (STRPTR)"TlsWrite GET", rc);
        } else {
            at_note_code("TlsWrite GET", rc);
        }
        DisposeTlsConnection(conn);
        if (ctx != NULL) {
            DisposeTlsContext(ctx);
        }
        TlsTaskDetach();
        return FALSE;
    }

    got = 0;
    at_live_body[0] = '\0';
    for (n = 0; n < 8; n++) {
        at_dbg("TlsRead attempt %ld pending=%lu",
            (long)(n + 1), (unsigned long)TlsPending(conn));
        rc = TlsRead(conn, at_live_body + got,
            (ULONG)(sizeof(at_live_body) - got - 1), 30);
        at_dbg("TlsRead -> %ld (total got %lu)", (long)rc, (unsigned long)got);
        if (at_tls_ok(rc)) {
            got += (ULONG)rc;
            at_live_body[got] = '\0';
            if (got >= 12) {
                break;
            }
        } else if (rc == 0) {
            break;
        } else if (at_tls_want(rc)) {
            continue;
        } else {
            TlsShutdown(conn);
            CloseSocket(sock);
            DisposeTlsConnection(conn);
            if (ctx != NULL) {
                DisposeTlsContext(ctx);
            }
            TlsTaskDetach();
            at_note_code("TlsRead response", rc);
            return FALSE;
        }
    }

    if (probe_peer_cert) {
        struct TlsPeerCert cert;

        memset(&cert, 0, sizeof(cert));
        rc = TlsGetPeerCert(conn, &cert);
        at_dbg("TlsGetPeerCert after handshake -> %ld", (long)rc);
        if (rc == 0) {
            at_note("TlsGetPeerCert (live)", TRUE,
                cert.tpc_CommonName ? cert.tpc_CommonName : (STRPTR)"(no CN)");
        } else {
            at_note_code("TlsGetPeerCert (live)", rc);
        }
        TlsPeerCertFree(&cert);
    }

    TlsShutdown(conn);
    CloseSocket(sock);
    DisposeTlsConnection(conn);
    if (ctx != NULL) {
        DisposeTlsContext(ctx);
    }
    TlsTaskDetach();

    p = (STRPTR)at_live_body;
    at_dbg("response %lu bytes", (unsigned long)got);
    if (at_verbose && got > 0) {
        ULONG show;
        char snippet[128];
        ULONG si;

        show = got;
        if (show > 80) {
            show = 80;
        }
        si = 0;
        while (si < show && p[si] != '\0') {
            if (p[si] == '\r' || p[si] == '\n') {
                snippet[si] = ' ';
            } else {
                snippet[si] = (char)p[si];
            }
            si++;
        }
        snippet[si] = '\0';
        at_dbg("body head: \"%s\"", snippet);
    }
    if (got >= 4 && p[0] == 'H' && p[1] == 'T' && p[2] == 'T' && p[3] == 'P') {
        at_note(label, TRUE, (STRPTR)"HTTP prefix");
        return TRUE;
    }
    at_note(label, FALSE, (STRPTR)"no HTTP prefix");
    return FALSE;
}

static VOID
at_test_https_wrong_ca(STRPTR host_arg)
{
    struct TlsContext *ctx;
    struct TlsConnection *conn;
    char hostbuf[256];
    STRPTR host;
    STRPTR ca_path;
    char req[256];
    LONG sock;
    LONG rc;

    at_step("HTTPS wrong CA verify failure (live)");
    ca_path = at_test_ca_path();
    if (ca_path == NULL) {
        at_note("HTTPS wrong CA", FALSE, (STRPTR)"no test CA file");
        return;
    }
    host = at_normalize_host(host_arg, hostbuf, (ULONG)sizeof(hostbuf));
    if (host[0] == '\0') {
        return;
    }
    if (!at_ensure_test_socket()) {
        return;
    }
    if (!at_tcp_connect(host, ATLS_TEST_HTTPS_PORT, &sock)) {
        at_note("TCP connect (wrong CA)", FALSE, host);
        return;
    }
    if (!at_ensure_task_attached()) {
        CloseSocket(sock);
        return;
    }
    ctx = at_new_context_verify_ca(ATSSL_VERIFY_PEER, ca_path);
    if (ctx == NULL) {
        CloseSocket(sock);
        TlsTaskDetach();
        at_note("NewTlsContext (wrong CA)", FALSE, (STRPTR)"NULL");
        return;
    }
    conn = NewTlsConnection(ctx);
    if (conn == NULL) {
        DisposeTlsContext(ctx);
        CloseSocket(sock);
        TlsTaskDetach();
        at_note("NewTlsConnection (wrong CA)", FALSE, (STRPTR)"NULL");
        return;
    }
    rc = at_attach_socket(conn, sock, host, ATSSL_VERIFY_PEER, FALSE);
    if (rc != 0) {
        CloseSocket(sock);
        DisposeTlsConnection(conn);
        DisposeTlsContext(ctx);
        TlsTaskDetach();
        at_note_code("TlsAttachSocket (wrong CA)", rc);
        return;
    }
    sprintf(req, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", (char *)host);
    rc = TlsWrite(conn, (APTR)req, (ULONG)strlen(req));
    at_dbg("TlsWrite wrong CA -> %ld last=%ld",
        (long)rc, (long)TlsGetLastError(conn));
    if (!at_tls_ok(rc) && (TlsGetLastError(conn) == ERROR_TLS_VERIFY
        || TlsGetLastError(conn) == ERROR_TLS_HANDSHAKE
        || rc == ERROR_TLS_VERIFY || rc == ERROR_TLS_HANDSHAKE)) {
        at_note("HTTPS wrong CA verify", TRUE, (STRPTR)"expected failure");
    } else {
        at_note("HTTPS wrong CA verify", FALSE, (STRPTR)"handshake succeeded?");
    }
    TlsShutdown(conn);
    CloseSocket(sock);
    DisposeTlsConnection(conn);
    DisposeTlsContext(ctx);
    TlsTaskDetach();
}

static VOID
at_test_https_dual(STRPTR host_arg)
{
    struct TlsConnection *conn_a;
    struct TlsConnection *conn_b;
    char hostbuf[256];
    STRPTR host;
    char req[256];
    UBYTE body_a[512];
    UBYTE body_b[512];
    LONG sock_a;
    LONG sock_b;
    LONG rc;
    ULONG got_a;
    ULONG got_b;

    at_step("Dual live HTTPS connections");
    host = at_normalize_host(host_arg, hostbuf, (ULONG)sizeof(hostbuf));
    if (host[0] == '\0') {
        return;
    }
    if (!at_ensure_test_socket()) {
        return;
    }
    if (!at_tcp_connect(host, ATLS_TEST_HTTPS_PORT, &sock_a)) {
        at_note("Dual TCP connect A", FALSE, host);
        return;
    }
    if (!at_tcp_connect(host, ATLS_TEST_HTTPS_PORT, &sock_b)) {
        CloseSocket(sock_a);
        at_note("Dual TCP connect B", FALSE, host);
        return;
    }
    if (!at_ensure_task_attached()) {
        CloseSocket(sock_a);
        CloseSocket(sock_b);
        return;
    }
    conn_a = NewTlsConnection(NULL);
    conn_b = NewTlsConnection(NULL);
    if (conn_a == NULL || conn_b == NULL) {
        if (conn_a != NULL) {
            DisposeTlsConnection(conn_a);
        }
        if (conn_b != NULL) {
            DisposeTlsConnection(conn_b);
        }
        CloseSocket(sock_a);
        CloseSocket(sock_b);
        TlsTaskDetach();
        at_note("Dual NewTlsConnection", FALSE, (STRPTR)"NULL");
        return;
    }
    rc = at_attach_socket(conn_a, sock_a, host, ATSSL_VERIFY_NONE, FALSE);
    if (rc != 0 || at_attach_socket(conn_b, sock_b, host, ATSSL_VERIFY_NONE, FALSE) != 0) {
        CloseSocket(sock_a);
        CloseSocket(sock_b);
        DisposeTlsConnection(conn_a);
        DisposeTlsConnection(conn_b);
        TlsTaskDetach();
        at_note("Dual TlsAttachSocket", FALSE, NULL);
        return;
    }
    sprintf(req, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", (char *)host);
    rc = TlsWrite(conn_a, (APTR)req, (ULONG)strlen(req));
    if (!at_tls_ok(rc)) {
        TlsShutdown(conn_a);
        TlsShutdown(conn_b);
        CloseSocket(sock_a);
        CloseSocket(sock_b);
        DisposeTlsConnection(conn_a);
        DisposeTlsConnection(conn_b);
        TlsTaskDetach();
        at_note_code("Dual TlsWrite A", rc);
        return;
    }
    rc = TlsWrite(conn_b, (APTR)req, (ULONG)strlen(req));
    if (!at_tls_ok(rc)) {
        TlsShutdown(conn_a);
        TlsShutdown(conn_b);
        CloseSocket(sock_a);
        CloseSocket(sock_b);
        DisposeTlsConnection(conn_a);
        DisposeTlsConnection(conn_b);
        TlsTaskDetach();
        at_note_code("Dual TlsWrite B", rc);
        return;
    }
    got_a = 0;
    got_b = 0;
    body_a[0] = '\0';
    body_b[0] = '\0';
    rc = TlsRead(conn_a, body_a, sizeof(body_a) - 1, 30);
    if (at_tls_ok(rc)) {
        got_a = (ULONG)rc;
        body_a[got_a] = '\0';
    }
    rc = TlsRead(conn_b, body_b, sizeof(body_b) - 1, 30);
    if (at_tls_ok(rc)) {
        got_b = (ULONG)rc;
        body_b[got_b] = '\0';
    }
    at_dbg("dual got A=%lu B=%lu last A=%ld B=%ld",
        (unsigned long)got_a, (unsigned long)got_b,
        (long)TlsGetLastError(conn_a), (long)TlsGetLastError(conn_b));
    TlsShutdown(conn_a);
    TlsShutdown(conn_b);
    CloseSocket(sock_a);
    CloseSocket(sock_b);
    DisposeTlsConnection(conn_a);
    DisposeTlsConnection(conn_b);
    TlsTaskDetach();
    if (got_a >= 4 && got_b >= 4
        && body_a[0] == 'H' && body_b[0] == 'H') {
        at_note("Dual live HTTPS", TRUE, (STRPTR)"both HTTP");
    } else {
        at_note("Dual live HTTPS", FALSE, NULL);
    }
}

static VOID
at_run_offline(VOID)
{
    at_clear_base_ca_path();
    if (!at_install_test_ca()) {
        at_log((STRPTR)"(test CA install to RAM: failed; try testdata/)");
    }
    at_test_error_strings();
    at_test_base_tags();
    at_test_task_attach();
    at_test_task_refcount();
    at_test_context();
    at_test_context_ca_path();
    at_test_attach_requires_task();
    at_test_dual_connections();
    at_test_connection_handles();
    at_test_tls_ok_semantics();
    at_test_verify_peer_no_ca();
    at_test_verify_peer_missing_ca();
    at_test_trust_pem_bundle_attach();
    at_test_cacert_bundle_load();
    at_test_deferred_handshake_offline();
    at_test_conn_vs_bootstrap_error();
    at_test_nonblocking_attach_tag();
    at_test_get_peer_cert_no_handshake();
    at_test_trust_store_stubs();
    at_test_atbt_ca_bundle_attach();
}

int
main(int argc, char **argv)
{
    STRPTR live_host;
    int i;

    at_pass = 0;
    at_fail = 0;
    at_step_id = 0;
    at_quiet = FALSE;
    at_verbose = FALSE;
    at_ca_path = NULL;
    at_live_verify = FALSE;
    live_host = NULL;

    for (i = 1; i < argc; i++) {
        if (argv[i] != NULL && strcmp(argv[i], "-q") == 0) {
            at_quiet = TRUE;
            at_verbose = FALSE;
        } else if (argv[i] != NULL && strcmp(argv[i], "-v") == 0) {
            at_verbose = TRUE;
            at_quiet = FALSE;
        } else if (argv[i] != NULL && strcmp(argv[i], "-verify") == 0) {
            at_live_verify = TRUE;
        } else if (argv[i] != NULL && strcmp(argv[i], "-ca") == 0) {
            if (i + 1 < argc && argv[i + 1] != NULL) {
                i++;
                at_ca_path = (STRPTR)argv[i];
                at_live_verify = TRUE;
            }
        } else if (argv[i] != NULL && strcmp(argv[i], "TEST") == 0) {
            /* offline only (AGet-style alias) */
        } else if (live_host == NULL && argv[i] != NULL && argv[i][0] != '\0'
            && argv[i][0] != '-') {
            live_host = (STRPTR)argv[i];
        }
    }

    if (!at_quiet) {
        at_printf("ATlsTest: amitls.library smoke harness%s\n",
            at_verbose ? (STRPTR)" (verbose)" : (STRPTR)"");
    }

    if (!at_open_libs()) {
        at_printf("ATlsTest: %lu passed, %lu failed (library missing)\n",
            at_pass, at_fail);
        return 20;
    }

    at_run_offline();

    if (live_host != NULL) {
        BOOL live_ok;

        live_ok = FALSE;
        if (at_live_verify && at_ca_path != NULL) {
            live_ok = at_https_exchange(live_host, ATSSL_VERIFY_PEER, at_ca_path,
                (STRPTR)"HTTPS GET verified", TRUE, TRUE);
        } else {
            live_ok = at_https_exchange(live_host, ATSSL_VERIFY_NONE, NULL,
                (STRPTR)"HTTPS GET", TRUE, TRUE);
        }
        if (!at_live_verify || live_ok) {
            at_test_https_wrong_ca(live_host);
            at_test_https_dual(live_host);
        } else if (!at_quiet) {
            at_log((STRPTR)"(skip wrong-CA/dual live after verify failure)");
        }
    } else if (!at_quiet) {
        at_printf("ATlsTest: (skip live HTTPS; pass hostname as argv)\n");
    }

    at_close_libs();

    at_printf("ATlsTest: %lu passed, %lu failed\n", at_pass, at_fail);

    if (at_fail > 0) {
        return 10;
    }
    return 0;
}
