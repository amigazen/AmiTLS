/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_bearssl.c - BearSSL TLS client engine (caller-owned socket fd)
 *
 * TlsAttachSocket() installs BearSSL on an existing TCP connection; the TLS
 * handshake completes on the first TlsWrite().
 * amitls.library does not perform DNS lookup, connect(), or close() on sockets.
 */


#include <exec/types.h>
#include <exec/memory.h>
#include <exec/execbase.h>
#include <exec/tasks.h>
#include <devices/timer.h>

#include <proto/exec.h>
#include <proto/dos.h>

#include <sys/socket.h>
#include <proto/bsdsocket.h>

#include <string.h>

#include <libraries/amitls.h>

#include "private/atls_internal.h"
#include "private/atls_bearssl.h"
#include "atls_x509_engine.h"
#include "atls_socket.h"

#ifndef ATLS_HOST_COPY_MAX
#define ATLS_HOST_COPY_MAX 256
#endif

#ifndef ATLS_TLS_SEND_CHUNK
#define ATLS_TLS_SEND_CHUNK 512UL
#endif
#ifndef ATLS_TLS_WAIT_US
#define ATLS_TLS_WAIT_US 50000UL
#endif
#ifndef ATLS_TLS_IO_TRIES
#define ATLS_TLS_IO_TRIES 200
#endif

extern struct ExecBase *SysBase;
extern struct Library *SocketBase;

static LONG
atls_br_map_want(struct TlsConnection *conn, BOOL writing)
{
    LONG err;

    if (conn == NULL || !conn->tc_NonBlocking) {
        return 0;
    }
    err = atls_sock_last_errno();
    if (!atls_sock_is_wouldblock(err)) {
        return 0;
    }
    if (writing) {
        return ERROR_TLS_WANT_WRITE;
    }
    return ERROR_TLS_WANT_READ;
}

static VOID
atls_fill_entropy(ULONG *seed)
{
    struct DateStamp ds;
    ULONG i;

    DateStamp(&ds);
    seed[0] = (ULONG)ds.ds_Days;
    seed[1] = (ULONG)ds.ds_Minute;
    seed[2] = (ULONG)ds.ds_Tick;
    seed[3] = (ULONG)FindTask(NULL);
    seed[4] = (ULONG)SysBase;
    seed[5] = (ULONG)SysBase->VBlankFrequency;
    seed[6] = (ULONG)SysBase->ex_EClockFrequency;
    seed[7] = (ULONG)SysBase->DispCount;
    seed[8] = (ULONG)AvailMem(MEMF_ANY);
    seed[9] = (ULONG)AvailMem(MEMF_CHIP);
    seed[10] = (ULONG)seed;
    seed[11] = (ULONG)&ds;
    for (i = 0; i < 12; i++) {
        seed[i] ^= (seed[(i + 5) % 12] << 5) ^ (seed[(i + 7) % 12] >> 3) ^ (0x9e3779b9UL + i);
    }
}

static int
atls_br_sock_read(void *opaque, unsigned char *buf, size_t len)
{
    struct TlsConnection *conn;
    LONG fd;
    LONG r;
    UWORD tries;

    conn = (struct TlsConnection *)opaque;
    if (conn == NULL || conn->tc_Sock < 0) {
        return -1;
    }
    atls_conn_bind_io(conn);
    fd = conn->tc_Sock;
    if (conn->tc_NonBlocking) {
        r = atls_sock_recv(fd, (UBYTE *)buf, (ULONG)len);
        if (r > 0) {
            return (int)r;
        }
        return -1;
    }
    for (tries = 0; tries < ATLS_TLS_IO_TRIES; tries++) {
        r = atls_sock_recv(fd, (UBYTE *)buf, (ULONG)len);
        if (r > 0) {
            return (int)r;
        }
        if (r < 0) {
            break;
        }
        if (atls_sock_last_errno() != 0) {
            break;
        }
        if (atls_sock_wait_read(fd, ATLS_TLS_WAIT_US) < 0) {
            break;
        }
    }
    return -1;
}

static int
atls_br_sock_write(void *opaque, const unsigned char *buf, size_t len)
{
    struct TlsConnection *conn;
    LONG fd;
    ULONG done;
    ULONG chunk;
    LONG r;
    UWORD tries;

    conn = (struct TlsConnection *)opaque;
    if (conn == NULL || conn->tc_Sock < 0) {
        return -1;
    }
    atls_conn_bind_io(conn);
    fd = conn->tc_Sock;
    if (conn->tc_Br != NULL && conn->tc_Br->br_suppress_alerts
        && len >= 1 && buf[0] == 0x15) {
        return (int)len;
    }
    done = 0;
    while (done < len) {
        r = 0;
        for (tries = 0; tries < ATLS_TLS_IO_TRIES; tries++) {
            chunk = (ULONG)(len - done);
            if (chunk > ATLS_TLS_SEND_CHUNK) {
                chunk = ATLS_TLS_SEND_CHUNK;
            }
            r = atls_sock_send(fd, (const UBYTE *)(buf + done), chunk);
            if (r > 0) {
                break;
            }
            if (conn->tc_NonBlocking && atls_sock_is_wouldblock(atls_sock_last_errno())) {
                break;
            }
            if (atls_sock_wait_write(fd, ATLS_TLS_WAIT_US) < 0) {
                break;
            }
        }
        if (r <= 0) {
            if (conn->tc_Br != NULL) {
                conn->tc_Br->br_broken = 1;
            }
            return -1;
        }
        done += (ULONG)r;
    }
    return (int)done;
}

static LONG
atls_br_engine_init(struct TlsConnection *conn, STRPTR hostname, ULONG verify_mode)
{
    /*
     * Let's Encrypt hosts (amigaworld.net) prefer ECDHE-ECDSA-ChaCha20;
     * Sectigo/Azure hosts (amiga.com) use ECDHE-RSA-AES128-GCM.
     */
    static const uint16_t suites[] = {
        BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    };
    struct AtlsBearSslState *br;
    ULONG seed[12];
    char host_copy[ATLS_HOST_COPY_MAX];
    ULONG hi;
    STRPTR h;
    LONG rc;

    br = conn->tc_Br;
    if (br == NULL) {
        return ERROR_TLS_INVALID_HANDLE;
    }

    h = hostname;
    if (h == NULL) {
        h = conn->tc_Hostname;
    }
    if (h == NULL) {
        return ERROR_TLS_INVALID_HANDLE;
    }

    hi = 0;
    while (h[hi] != 0 && hi < (ATLS_HOST_COPY_MAX - 1)) {
        host_copy[hi] = h[hi];
        hi++;
    }
    host_copy[hi] = 0;
    if (h[hi] != 0) {
        return ERROR_TLS_INVALID_HANDLE;
    }

    br_ssl_client_zero(&br->br_sc);
    br_ssl_engine_set_versions(&br->br_sc.eng, BR_TLS12, BR_TLS12);
    br_ssl_engine_set_suites(&br->br_sc.eng, suites,
        (sizeof(suites) / sizeof(suites[0])));
    br_ssl_client_set_rsapub(&br->br_sc, br_rsa_i15_public);
    br_ssl_engine_set_rsavrfy(&br->br_sc.eng, br_rsa_i15_pkcs1_vrfy);
    br_ssl_engine_set_ec(&br->br_sc.eng, &br_ec_all_m15);
    br_ssl_engine_set_ecdsa(&br->br_sc.eng, br_ecdsa_i15_vrfy_asn1);
    br_ssl_engine_set_hash(&br->br_sc.eng, br_sha1_ID, &br_sha1_vtable);
    br_ssl_engine_set_hash(&br->br_sc.eng, br_sha256_ID, &br_sha256_vtable);
    br_ssl_engine_set_hash(&br->br_sc.eng, br_sha384_ID, &br_sha384_vtable);
    br_ssl_engine_set_hash(&br->br_sc.eng, br_sha512_ID, &br_sha512_vtable);
    br_ssl_engine_set_prf_sha256(&br->br_sc.eng, &br_tls12_sha256_prf);
    br_ssl_engine_set_prf_sha384(&br->br_sc.eng, &br_tls12_sha384_prf);
    br_ssl_engine_set_gcm(&br->br_sc.eng, &br_sslrec_in_gcm_vtable,
        &br_sslrec_out_gcm_vtable);
    br_ssl_engine_set_aes_ctr(&br->br_sc.eng, &br_aes_ct_ctr_vtable);
    br_ssl_engine_set_ghash(&br->br_sc.eng, &br_ghash_ctmul32);
    br_ssl_engine_set_chapol(&br->br_sc.eng,
        &br_sslrec_in_chapol_vtable, &br_sslrec_out_chapol_vtable);
    br_ssl_engine_set_chacha20(&br->br_sc.eng, &br_chacha20_ct_run);
    br_ssl_engine_set_poly1305(&br->br_sc.eng, &br_poly1305_ctmul32_run);

    rc = atls_x509_engine_init(&br->br_x509, conn->tc_Context, verify_mode,
        &br->br_sc.eng);
    if (rc != 0) {
        return rc;
    }
    if (atls_x509_engine_vtable_ref(&br->br_x509) == NULL) {
        return ERROR_TLS_PROTOCOL;
    }
    br_ssl_engine_set_x509(&br->br_sc.eng,
        atls_x509_engine_vtable_ref(&br->br_x509));

    atls_fill_entropy(seed);
    br_ssl_engine_inject_entropy(&br->br_sc.eng, seed, sizeof(seed));
    memset(seed, 0, sizeof(seed));

    if (br->br_iobuf == NULL) {
        return ERROR_TLS_OUT_OF_MEMORY;
    }
    br_ssl_engine_set_buffer(&br->br_sc.eng, br->br_iobuf,
        BR_SSL_BUFSIZE_BIDI, 1);

    if (!br_ssl_client_reset(&br->br_sc, host_copy, 0)) {
        return ERROR_TLS_HANDSHAKE;
    }

    br_sslio_init(&br->br_ioc, &br->br_sc.eng,
        atls_br_sock_read, conn, atls_br_sock_write, conn);
    br->br_active = 1;
    return 0;
}

LONG
atls_bearssl_attach(struct TlsConnection *conn, LONG sock, STRPTR hostname,
    ULONG verify_mode)
{
    struct AtlsBearSslState *br;
    LONG rc;

    if (conn == NULL || sock < 0) {
        return ERROR_TLS_INVALID_HANDLE;
    }

    if (conn->tc_Br != NULL) {
        atls_bearssl_dispose(conn);
    }

    br = (struct AtlsBearSslState *)AllocMem(sizeof(*br), MEMF_CLEAR);
    if (br == NULL) {
        return ERROR_TLS_OUT_OF_MEMORY;
    }
    br->br_iobuf = (UBYTE *)AllocMem(BR_SSL_BUFSIZE_BIDI, MEMF_CLEAR);
    if (br->br_iobuf == NULL) {
        FreeMem(br, sizeof(*br));
        return ERROR_TLS_OUT_OF_MEMORY;
    }
    conn->tc_Br = br;
    conn->tc_Sock = sock;

    rc = atls_br_engine_init(conn, hostname, verify_mode);
    if (rc != 0) {
        atls_bearssl_dispose(conn);
        return rc;
    }

    atls_conn_bind_io(conn);

    conn->tc_HandshakeDone = FALSE;
    conn->tc_LastError = 0;
    return 0;
}

static LONG
atls_br_engine_want(struct TlsConnection *conn)
{
    struct AtlsBearSslState *br;
    unsigned state;

    if (conn == NULL) {
        return ERROR_TLS_WANT_READ;
    }
    br = conn->tc_Br;
    if (br == NULL) {
        return ERROR_TLS_WANT_READ;
    }
    state = br_ssl_engine_current_state(&br->br_sc.eng);
    if (state & BR_SSL_SENDREC) {
        return ERROR_TLS_WANT_WRITE;
    }
    if (state & BR_SSL_RECVREC) {
        return ERROR_TLS_WANT_READ;
    }
    return ERROR_TLS_WANT_READ;
}

static LONG
atls_br_want_from_engine(struct TlsConnection *conn)
{
    struct AtlsBearSslState *br;
    unsigned state;

    if (conn == NULL || !conn->tc_NonBlocking) {
        return 0;
    }
    br = conn->tc_Br;
    if (br == NULL) {
        return 0;
    }
    state = br_ssl_engine_current_state(&br->br_sc.eng);
    if (state & BR_SSL_SENDREC) {
        return ERROR_TLS_WANT_WRITE;
    }
    if (state & BR_SSL_RECVREC) {
        return ERROR_TLS_WANT_READ;
    }
    return 0;
}

static LONG
atls_br_map_write_error(struct TlsConnection *conn, int r, unsigned brerr)
{
    LONG want;
    struct TlsContext *ctx;

    if (r == 0) {
        return 0;
    }
    want = atls_br_want_from_engine(conn);
    if (want == 0) {
        want = atls_br_map_want(conn, TRUE);
    }
    if (want != 0) {
        return want;
    }
    if (brerr >= BR_ERR_X509_INVALID_VALUE && brerr <= BR_ERR_X509_NOT_TRUSTED) {
        if (conn != NULL) {
            conn->tc_LastBrErr = (LONG)brerr;
            conn->tc_CertVerifyResult = (LONG)brerr;
        }
        return ERROR_TLS_VERIFY;
    }
    /*
     * br_x509_minimal may surface BR_ERR_BAD_SIGNATURE (27) during chain
     * validation before the x509-specific codes; map it to VERIFY when peer
     * checking is enabled so callers see ERROR_TLS_VERIFY not HANDSHAKE.
     */
    ctx = (conn != NULL) ? conn->tc_Context : NULL;
    if (ctx != NULL && ctx->tx_SslVerify != ATSSL_VERIFY_NONE &&
        conn != NULL && !conn->tc_HandshakeDone &&
        brerr == BR_ERR_BAD_SIGNATURE) {
        if (conn != NULL) {
            conn->tc_LastBrErr = (LONG)brerr;
            conn->tc_CertVerifyResult = (LONG)brerr;
        }
        return ERROR_TLS_VERIFY;
    }
    if (conn != NULL && conn->tc_Br != NULL) {
        conn->tc_Br->br_broken = 1;
    }
    if (atls_sock_last_errno() != 0) {
        if (conn != NULL && !conn->tc_HandshakeDone) {
            return ERROR_TLS_IO;
        }
        return ERROR_TLS_WRITE_FAILED;
    }
    if (conn != NULL && !conn->tc_HandshakeDone) {
        return ERROR_TLS_HANDSHAKE;
    }
    return ERROR_TLS_WRITE_FAILED;
}

static LONG
atls_br_map_read_error(struct TlsConnection *conn)
{
    LONG want;

    want = atls_br_map_want(conn, FALSE);
    if (want != 0) {
        return want;
    }
    return ERROR_TLS_READ_FAILED;
}

LONG
atls_bearssl_write(struct TlsConnection *conn, APTR buf, ULONG len)
{
    struct AtlsBearSslState *br;
    int r;
    unsigned brerr;
    LONG err;

    if (conn == NULL || buf == NULL || len == 0) {
        return ERROR_TLS_INVALID_HANDLE;
    }
    br = conn->tc_Br;
    if (br == NULL || !br->br_active) {
        return ERROR_TLS_HANDSHAKE;
    }

    if (!conn->tc_HandshakeDone) {
        atls_x509_engine_refresh_time(&br->br_x509);
    }

    atls_conn_bind_io(conn);

    r = br_sslio_write_all(&br->br_ioc, (const unsigned char *)buf, (size_t)len);
    brerr = br_ssl_engine_last_error(&br->br_sc.eng);
    err = atls_br_map_write_error(conn, r, brerr);
    if (err != 0) {
        return err;
    }
    r = br_sslio_flush(&br->br_ioc);
    brerr = br_ssl_engine_last_error(&br->br_sc.eng);
    err = atls_br_map_write_error(conn, r, brerr);
    if (err != 0) {
        return err;
    }

    if (!conn->tc_HandshakeDone) {
        conn->tc_HandshakeDone = TRUE;
        if (atls_x509_engine_have_pkey(&br->br_x509)) {
            conn->tc_CertPresent = TRUE;
            conn->tc_CertVerifyResult = 0;
        }
    }
    return (LONG)len;
}

LONG
atls_bearssl_handshake(struct TlsConnection *conn, ULONG timeout_secs)
{
    struct AtlsBearSslState *br;
    unsigned state;
    int r;
    unsigned brerr;
    LONG err;
    ULONG attempts;
    UBYTE discard[256];

    if (conn == NULL) {
        return ERROR_TLS_INVALID_HANDLE;
    }
    br = conn->tc_Br;
    if (br == NULL || !br->br_active) {
        return ERROR_TLS_HANDSHAKE;
    }
    if (conn->tc_HandshakeDone) {
        return 0;
    }

    atls_conn_bind_io(conn);
    attempts = 0;
    for (;;) {
        attempts++;
        if (attempts > ATLS_TLS_IO_TRIES) {
            return ERROR_TLS_CONNECT_TIMEOUT;
        }
        state = br_ssl_engine_current_state(&br->br_sc.eng);
        if (state & BR_SSL_SENDAPP) {
            conn->tc_HandshakeDone = TRUE;
            if (atls_x509_engine_have_pkey(&br->br_x509)) {
                conn->tc_CertPresent = TRUE;
                conn->tc_CertVerifyResult = 0;
            }
            conn->tc_LastError = 0;
            return 0;
        }
        if (state & BR_SSL_RECVREC) {
            r = br_sslio_read(&br->br_ioc, discard,
                (size_t)sizeof(discard));
        } else {
            r = br_sslio_flush(&br->br_ioc);
        }
        brerr = br_ssl_engine_last_error(&br->br_sc.eng);
        if (r > 0) {
            continue;
        }
        if (r < 0) {
            err = atls_br_map_write_error(conn, r, brerr);
            if (atls_rc_is_want(err) && conn->tc_ExternalWait) {
                return err;
            }
            if (err != 0) {
                return err;
            }
            continue;
        }
        /* r == 0: need more wire I/O */
        if (conn->tc_ExternalWait) {
            return atls_br_engine_want(conn);
        }
        /*
         * Blocking callers: wait for socket readiness.  Without this, r==0 spins
         * forever at 100% CPU (client lockup when ATTA_EXTERNAL_WAIT unset).
         */
        if (conn->tc_Sock >= 0) {
            state = br_ssl_engine_current_state(&br->br_sc.eng);
            if (state & BR_SSL_SENDREC) {
                if (atls_sock_wait_write(conn->tc_Sock, ATLS_TLS_WAIT_US) < 0) {
                    return ERROR_TLS_IO;
                }
            } else {
                if (atls_sock_wait_read(conn->tc_Sock, ATLS_TLS_WAIT_US) < 0) {
                    return ERROR_TLS_IO;
                }
            }
            continue;
        }
        return ERROR_TLS_IO;
    }
}

LONG
atls_bearssl_read(struct TlsConnection *conn, APTR buf, ULONG len,
    ULONG timeout_secs)
{
    struct AtlsBearSslState *br;
    unsigned char *pending;
    size_t avail;
    int r;
    ULONG attempts;
    fd_set rfds;
    struct timeval tv;
    LONG nfds;
    LONG sel;
    LONG err;

    if (conn == NULL || buf == NULL || len == 0) {
        return ERROR_TLS_INVALID_HANDLE;
    }
    br = conn->tc_Br;
    if (br == NULL || !br->br_active) {
        return ERROR_TLS_HANDSHAKE;
    }

    atls_conn_bind_io(conn);

    attempts = 0;
    for (;;) {
        avail = 0;
        pending = br_ssl_engine_recvapp_buf(&br->br_sc.eng, &avail);
        if (pending != NULL && avail > 0) {
            if (avail > (size_t)len) {
                avail = (size_t)len;
            }
            memcpy(buf, pending, avail);
            br_ssl_engine_recvapp_ack(&br->br_sc.eng, avail);
            return (LONG)avail;
        }

        r = br_sslio_read(&br->br_ioc, (unsigned char *)buf, (size_t)len);
        if (r > 0) {
            return (LONG)r;
        }
        if (r < 0) {
            err = atls_br_map_read_error(conn);
            if (!atls_rc_is_want(err)) {
                br->br_broken = 1;
            }
            return err;
        }

        attempts++;
        if (timeout_secs == 0UL || attempts > ATLS_TLS_IO_TRIES) {
            return ERROR_TLS_READ_TIMEOUT;
        }

        if (conn->tc_ExternalWait) {
            return atls_br_engine_want(conn);
        }

        if (conn->tc_Sock >= 0) {
            FD_ZERO(&rfds);
            FD_SET((int)conn->tc_Sock, &rfds);
            nfds = conn->tc_Sock + 1;
            tv.tv_sec = (long)timeout_secs;
            tv.tv_usec = 0;
            sel = WaitSelect((int)nfds, &rfds, NULL, NULL, &tv, NULL);
            if (sel <= 0) {
                return ERROR_TLS_READ_TIMEOUT;
            }
        }
    }
}

ULONG
atls_bearssl_pending(struct TlsConnection *conn)
{
    struct AtlsBearSslState *br;
    unsigned char *data;
    size_t n;

    if (conn == NULL) {
        return 0;
    }
    br = conn->tc_Br;
    if (br == NULL || !br->br_active) {
        return 0;
    }
    n = 0;
    data = br_ssl_engine_recvapp_buf(&br->br_sc.eng, &n);
    if (data == NULL) {
        return 0;
    }
    return (ULONG)n;
}

LONG
atls_bearssl_shutdown(struct TlsConnection *conn)
{
    struct AtlsBearSslState *br;

    if (conn == NULL) {
        return ERROR_TLS_INVALID_HANDLE;
    }
    br = conn->tc_Br;
    if (br != NULL && br->br_active) {
        br->br_suppress_alerts = 1;
        (void)br_sslio_close(&br->br_ioc);
        br->br_active = 0;
    }
    conn->tc_ShutdownDone = TRUE;
    return 0;
}

VOID
atls_bearssl_dispose(struct TlsConnection *conn)
{
    struct AtlsBearSslState *br;

    if (conn == NULL) {
        return;
    }
    br = conn->tc_Br;
    if (br != NULL) {
        atls_x509_engine_clear(&br->br_x509);
        if (br->br_iobuf != NULL) {
            memset(br->br_iobuf, 0, BR_SSL_BUFSIZE_BIDI);
            FreeMem(br->br_iobuf, BR_SSL_BUFSIZE_BIDI);
            br->br_iobuf = NULL;
        }
        FreeMem(br, sizeof(*br));
        conn->tc_Br = NULL;
    }
    conn->tc_HandshakeDone = FALSE;
    conn->tc_ShutdownDone = FALSE;
}
