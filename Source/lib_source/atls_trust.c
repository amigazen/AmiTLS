/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_trust.c - Load PEM CA bundles into per-context trust anchors
 *
 * Uses BearSSL br_x509_decoder to extract subject DN and public key from each
 * PEM certificate block.  Trust anchors are owned by TlsContext and freed in
 * DisposeTlsContext / atls_trust_clear().
 */

#include <exec/types.h>
#include <exec/memory.h>

#include <proto/dos.h>
#include <dos/dos.h>

#include <string.h>

#include <libraries/amitls.h>

#include <proto/exec.h>

#include "private/atls_internal.h"
#include "atls_trust.h"
#include "bearssl_amiga.h"

extern struct AmiTlsBase *TlsBase;
extern struct DosLibrary *DOSBase;

#ifndef ATLS_TRUST_MAX_FILE
#define ATLS_TRUST_MAX_FILE (512UL * 1024UL)
#endif
#ifndef ATLS_TRUST_MAX_ANCHORS
#define ATLS_TRUST_MAX_ANCHORS 512UL
#endif
#ifndef ATLS_TRUST_KEY_BUF
#define ATLS_TRUST_KEY_BUF 2048UL
#endif
#ifndef ATLS_TRUST_READ_CHUNK
#define ATLS_TRUST_READ_CHUNK 1024UL
#endif

struct AtlsTrustStore
{
    br_x509_trust_anchor  *ts_Anchors;
    ULONG                  ts_Count;
    ULONG                  ts_Capacity;
    BOOL                   ts_LoadAttempted;
    LONG                   ts_LoadError;
};

struct AtlsDnAccum
{
    UBYTE  *da_Buf;
    ULONG   da_Len;
    ULONG   da_Cap;
};

static VOID
atls_trust_free_store(struct AtlsTrustStore *store)
{
    ULONG i;

    if (store == NULL) {
        return;
    }
    if (store->ts_Anchors != NULL) {
        for (i = 0; i < store->ts_Count; i++) {
            if (store->ts_Anchors[i].dn.data != NULL) {
                FreeMem((APTR)store->ts_Anchors[i].dn.data, 0);
            }
            if (store->ts_Anchors[i].pkey.key_type == BR_KEYTYPE_RSA) {
                if (store->ts_Anchors[i].pkey.key.rsa.n != NULL) {
                    FreeMem((APTR)store->ts_Anchors[i].pkey.key.rsa.n,
                        ATLS_TRUST_KEY_BUF);
                }
            } else if (store->ts_Anchors[i].pkey.key_type == BR_KEYTYPE_EC) {
                if (store->ts_Anchors[i].pkey.key.ec.q != NULL) {
                    FreeMem((APTR)store->ts_Anchors[i].pkey.key.ec.q,
                        ATLS_TRUST_KEY_BUF);
                }
            }
        }
        FreeMem(store->ts_Anchors,
            store->ts_Capacity * sizeof(br_x509_trust_anchor));
    }
    FreeMem(store, sizeof(*store));
}

static BOOL
atls_trust_path_match(STRPTR a, STRPTR b)
{
    char ca;
    char cb;

    if (a == NULL || b == NULL) {
        return FALSE;
    }
    while (*a != '\0' && *b != '\0') {
        ca = *a++;
        cb = *b++;
        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca + ('a' - 'A'));
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb + ('a' - 'A'));
        }
        if (ca != cb) {
            return FALSE;
        }
    }
    return (BOOL)(*a == '\0' && *b == '\0');
}

VOID
atls_trust_global_clear(struct AmiTlsBase *base)
{
    struct AtlsTrustStore *store;

    if (base == NULL) {
        return;
    }
    ObtainSemaphore(&base->atb_GlobalSema);
    store = (struct AtlsTrustStore *)base->atb_SharedTrust;
    base->atb_SharedTrust = NULL;
    if (base->atb_SharedTrustPath != NULL) {
        FreeMem(base->atb_SharedTrustPath, 0);
        base->atb_SharedTrustPath = NULL;
    }
    ReleaseSemaphore(&base->atb_GlobalSema);
    atls_trust_free_store(store);
}

static VOID
atls_dn_append(void *ctx, const void *buf, size_t len)
{
    struct AtlsDnAccum *acc;
    UBYTE *nb;
    ULONG need;
    ULONG i;

    acc = (struct AtlsDnAccum *)ctx;
    if (acc == NULL || buf == NULL || len == 0) {
        return;
    }
    need = acc->da_Len + (ULONG)len;
    if (need > acc->da_Cap) {
        if (acc->da_Cap == 0) {
            acc->da_Cap = 256;
        }
        while (acc->da_Cap < need) {
            acc->da_Cap *= 2;
        }
        nb = (UBYTE *)AllocMem(acc->da_Cap, MEMF_CLEAR);
        if (nb == NULL) {
            return;
        }
        for (i = 0; i < acc->da_Len; i++) {
            nb[i] = acc->da_Buf[i];
        }
        if (acc->da_Buf != NULL) {
            FreeMem(acc->da_Buf, 0);
        }
        acc->da_Buf = nb;
    }
    memcpy(acc->da_Buf + acc->da_Len, buf, len);
    acc->da_Len = need;
}

static BOOL
atls_trust_copy_pkey(br_x509_trust_anchor *ta, UBYTE *key_buf, ULONG key_cap,
    const br_x509_pkey *pk, ULONG *out_key_len)
{
    size_t nlen;
    size_t elen;
    size_t qlen;

    if (ta == NULL || key_buf == NULL || pk == NULL || out_key_len == NULL) {
        return FALSE;
    }
    ta->pkey.key_type = pk->key_type;
    if (pk->key_type == BR_KEYTYPE_RSA) {
        nlen = pk->key.rsa.nlen;
        elen = pk->key.rsa.elen;
        if (nlen + elen > key_cap) {
            return FALSE;
        }
        memcpy(key_buf, pk->key.rsa.n, nlen);
        memcpy(key_buf + nlen, pk->key.rsa.e, elen);
        ta->pkey.key.rsa.n = key_buf;
        ta->pkey.key.rsa.nlen = nlen;
        ta->pkey.key.rsa.e = key_buf + nlen;
        ta->pkey.key.rsa.elen = elen;
        *out_key_len = (ULONG)(nlen + elen);
        return TRUE;
    }
    if (pk->key_type == BR_KEYTYPE_EC) {
        qlen = pk->key.ec.qlen;
        if (qlen > key_cap) {
            return FALSE;
        }
        memcpy(key_buf, pk->key.ec.q, qlen);
        ta->pkey.key.ec.curve = pk->key.ec.curve;
        ta->pkey.key.ec.q = key_buf;
        ta->pkey.key.ec.qlen = qlen;
        *out_key_len = (ULONG)qlen;
        return TRUE;
    }
    return FALSE;
}

static LONG
atls_trust_grow(struct AtlsTrustStore *store)
{
    br_x509_trust_anchor *nanchors;
    ULONG ncap;

    if (store == NULL) {
        return ERROR_TLS_INVALID_HANDLE;
    }
    ncap = store->ts_Capacity;
    if (ncap == 0) {
        ncap = 8;
    } else {
        ncap *= 2;
    }
    nanchors = (br_x509_trust_anchor *)AllocMem(
        ncap * sizeof(br_x509_trust_anchor), MEMF_CLEAR);
    if (nanchors == NULL) {
        return ERROR_TLS_OUT_OF_MEMORY;
    }
    if (store->ts_Anchors != NULL && store->ts_Count > 0) {
        memcpy(nanchors, store->ts_Anchors,
            store->ts_Count * sizeof(br_x509_trust_anchor));
        FreeMem(store->ts_Anchors, store->ts_Capacity * sizeof(br_x509_trust_anchor));
    }
    store->ts_Anchors = nanchors;
    store->ts_Capacity = ncap;
    return 0;
}

static LONG
atls_trust_add_der(struct AtlsTrustStore *store, const UBYTE *der, ULONG der_len)
{
    br_x509_decoder_context dec;
    struct AtlsDnAccum acc;
    br_x509_trust_anchor *ta;
    UBYTE *key_buf;
    const br_x509_pkey *pk;
    ULONG key_len;
    LONG rc;

    if (store == NULL || der == NULL || der_len == 0) {
        return ERROR_TLS_INVALID_HANDLE;
    }
    if (store->ts_Count >= ATLS_TRUST_MAX_ANCHORS) {
        return 0;
    }
    if (store->ts_Count >= store->ts_Capacity) {
        rc = atls_trust_grow(store);
        if (rc != 0) {
            return rc;
        }
    }

    acc.da_Buf = NULL;
    acc.da_Len = 0;
    acc.da_Cap = 0;
    br_x509_decoder_init(&dec, atls_dn_append, &acc);
    br_x509_decoder_push(&dec, der, (size_t)der_len);
    if (!dec.decoded) {
        if (acc.da_Buf != NULL) {
            FreeMem(acc.da_Buf, 0);
        }
        return ERROR_TLS_PROTOCOL;
    }
    pk = br_x509_decoder_get_pkey(&dec);
    if (pk == NULL || acc.da_Len == 0) {
        if (acc.da_Buf != NULL) {
            FreeMem(acc.da_Buf, 0);
        }
        return ERROR_TLS_PROTOCOL;
    }

    key_buf = (UBYTE *)AllocMem(ATLS_TRUST_KEY_BUF, MEMF_CLEAR);
    if (key_buf == NULL) {
        if (acc.da_Buf != NULL) {
            FreeMem(acc.da_Buf, 0);
        }
        return ERROR_TLS_OUT_OF_MEMORY;
    }

    ta = &store->ts_Anchors[store->ts_Count];
    memset(ta, 0, sizeof(*ta));
    key_len = 0;
    if (!atls_trust_copy_pkey(ta, key_buf, ATLS_TRUST_KEY_BUF, pk, &key_len)) {
        FreeMem(key_buf, ATLS_TRUST_KEY_BUF);
        if (acc.da_Buf != NULL) {
            FreeMem(acc.da_Buf, 0);
        }
        return ERROR_TLS_PROTOCOL;
    }
    ta->flags = BR_X509_TA_CA;
    ta->dn.data = acc.da_Buf;
    ta->dn.len = (size_t)acc.da_Len;
    store->ts_Count++;
    return 0;
}

static int
atls_b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (int)(c - 'A');
    }
    if (c >= 'a' && c <= 'z') {
        return (int)(c - 'a') + 26;
    }
    if (c >= '0' && c <= '9') {
        return (int)(c - '0') + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

static LONG
atls_b64_decode(const char *in, ULONG in_len, UBYTE **out_der, ULONG *out_len)
{
    UBYTE *der;
    ULONG cap;
    ULONG o;
    ULONG i;
    ULONG val;
    ULONG bits;
    char c;
    int v;

    if (in == NULL || out_der == NULL || out_len == NULL) {
        return ERROR_TLS_INVALID_HANDLE;
    }
    cap = (in_len / 4) * 3 + 8;
    der = (UBYTE *)AllocMem(cap, MEMF_CLEAR);
    if (der == NULL) {
        return ERROR_TLS_OUT_OF_MEMORY;
    }
    o = 0;
    val = 0;
    bits = 0;
    for (i = 0; i < in_len; i++) {
        c = in[i];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
            continue;
        }
        if (c == '=') {
            break;
        }
        v = atls_b64_val(c);
        if (v < 0) {
            FreeMem(der, 0);
            return ERROR_TLS_PROTOCOL;
        }
        val = (val << 6) | (ULONG)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            der[o++] = (UBYTE)((val >> bits) & 0xFF);
            if (o >= cap) {
                FreeMem(der, 0);
                return ERROR_TLS_OUT_OF_MEMORY;
            }
        }
    }
    if (o == 0) {
        FreeMem(der, 0);
        return ERROR_TLS_PROTOCOL;
    }
    *out_der = der;
    *out_len = o;
    return 0;
}

static LONG
atls_trust_parse_pem(struct AtlsTrustStore *store, const char *pem, ULONG pem_len)
{
    ULONG i;
    ULONG start;
    ULONG end;
    LONG rc;
    UBYTE *der;
    ULONG der_len;

    i = 0;
    while (i + 27 <= pem_len) {
        if (strncmp(pem + i, "-----BEGIN CERTIFICATE-----", 27) != 0) {
            i++;
            continue;
        }
        if (store->ts_Count >= ATLS_TRUST_MAX_ANCHORS) {
            break;
        }
        start = i + 27;
        end = start;
        while (end + 25 <= pem_len) {
            if (strncmp(pem + end, "-----END CERTIFICATE-----", 25) == 0) {
                break;
            }
            end++;
        }
        if (end + 25 > pem_len) {
            break;
        }
        der = NULL;
        der_len = 0;
        rc = atls_b64_decode(pem + start, end - start, &der, &der_len);
        if (rc == 0 && der != NULL && der_len > 0) {
            rc = atls_trust_add_der(store, der, der_len);
        }
        if (der != NULL) {
            FreeMem(der, der_len);
        }
        i = end + 25;
    }
    if (store->ts_Count == 0) {
        return ERROR_TLS_PROTOCOL;
    }
    return 0;
}

static LONG
atls_trust_load_file(struct AtlsTrustStore *store, STRPTR path)
{
    BPTR fh;
    char *buf;
    char *nbuf;
    ULONG cap;
    ULONG grow;
    ULONG total;
    LONG n;
    LONG rc;

    if (store == NULL || path == NULL || path[0] == '\0') {
        return ERROR_TLS_INVALID_HANDLE;
    }
    if (TlsBase != NULL) {
        atls_sync_proto_bases(TlsBase);
    }
    if (DOSBase == NULL) {
        return ERROR_TLS_IO;
    }
    fh = Open((STRPTR)path, MODE_OLDFILE);
    if (fh == (BPTR)0) {
        return ERROR_TLS_IO;
    }
    cap = ATLS_TRUST_READ_CHUNK;
    buf = (char *)AllocMem(cap + 1, MEMF_CLEAR);
    if (buf == NULL) {
        Close(fh);
        return ERROR_TLS_OUT_OF_MEMORY;
    }
    total = 0;
    for (;;) {
        if ((total + ATLS_TRUST_READ_CHUNK) > cap) {
            grow = cap;
            if (grow > (ATLS_TRUST_MAX_FILE / 2)) {
                grow = ATLS_TRUST_MAX_FILE / 2;
            }
            if ((cap + grow) > ATLS_TRUST_MAX_FILE) {
                Close(fh);
                FreeMem(buf, 0);
                return ERROR_TLS_IO;
            }
            nbuf = (char *)AllocMem(cap + grow + 1, MEMF_CLEAR);
            if (nbuf == NULL) {
                Close(fh);
                FreeMem(buf, 0);
                return ERROR_TLS_OUT_OF_MEMORY;
            }
            memcpy(nbuf, buf, total);
            FreeMem(buf, 0);
            buf = nbuf;
            cap += grow;
        }
        n = Read(fh, buf + total, (LONG)(cap - total));
        if (n < 0) {
            Close(fh);
            FreeMem(buf, 0);
            return ERROR_TLS_IO;
        }
        if (n == 0) {
            break;
        }
        total += (ULONG)n;
    }
    Close(fh);
    if (total == 0) {
        FreeMem(buf, 0);
        return ERROR_TLS_IO;
    }
    if (total >= 3
        && (UBYTE)buf[0] == 0xEF
        && (UBYTE)buf[1] == 0xBB
        && (UBYTE)buf[2] == 0xBF) {
        memmove(buf, buf + 3, total - 3);
        total -= 3;
        buf[total] = '\0';
    }
    rc = atls_trust_parse_pem(store, buf, total);
    FreeMem(buf, 0);
    if (store->ts_Count == 0) {
        return (rc != 0) ? rc : ERROR_TLS_PROTOCOL;
    }
    return 0;
}

static LONG
atls_trust_global_ensure(STRPTR path)
{
    struct AtlsTrustStore *store;
    LONG rc;

    if (TlsBase == NULL || path == NULL || path[0] == '\0') {
        return 0;
    }
    ObtainSemaphore(&TlsBase->atb_GlobalSema);
    store = (struct AtlsTrustStore *)TlsBase->atb_SharedTrust;
    if (store != NULL && store->ts_LoadAttempted &&
        atls_trust_path_match(TlsBase->atb_SharedTrustPath, path)) {
        rc = store->ts_LoadError;
        ReleaseSemaphore(&TlsBase->atb_GlobalSema);
        return rc;
    }
    if (store != NULL) {
        atls_trust_free_store(store);
        TlsBase->atb_SharedTrust = NULL;
    }
    if (TlsBase->atb_SharedTrustPath != NULL) {
        FreeMem(TlsBase->atb_SharedTrustPath, 0);
        TlsBase->atb_SharedTrustPath = NULL;
    }
    store = (struct AtlsTrustStore *)AllocMem(sizeof(*store), MEMF_CLEAR);
    if (store == NULL) {
        ReleaseSemaphore(&TlsBase->atb_GlobalSema);
        return ERROR_TLS_OUT_OF_MEMORY;
    }
    store->ts_LoadAttempted = TRUE;
    rc = atls_trust_load_file(store, path);
    store->ts_LoadError = rc;
    if (rc == 0) {
        TlsBase->atb_SharedTrust = (APTR)store;
        TlsBase->atb_SharedTrustPath = (STRPTR)AllocMem(
            (ULONG)(strlen((const char *)path) + 1), MEMF_CLEAR);
        if (TlsBase->atb_SharedTrustPath != NULL) {
            strcpy((char *)TlsBase->atb_SharedTrustPath, (const char *)path);
        }
    } else {
        atls_trust_free_store(store);
    }
    ReleaseSemaphore(&TlsBase->atb_GlobalSema);
    return rc;
}

static struct AtlsTrustStore *
atls_trust_get_store(struct TlsContext *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    return (struct AtlsTrustStore *)ctx->tx_Trust;
}

VOID
atls_trust_clear(struct TlsContext *ctx)
{
    struct AtlsTrustStore *store;

    if (ctx == NULL) {
        return;
    }
    if (ctx->tx_TrustShared) {
        ctx->tx_Trust = NULL;
        ctx->tx_TrustShared = FALSE;
        return;
    }
    store = atls_trust_get_store(ctx);
    if (store == NULL) {
        return;
    }
    atls_trust_free_store(store);
    ctx->tx_Trust = NULL;
}

static struct AtlsTrustStore *
atls_trust_alloc_store(struct TlsContext *ctx)
{
    struct AtlsTrustStore *store;

    store = (struct AtlsTrustStore *)AllocMem(sizeof(*store), MEMF_CLEAR);
    if (store == NULL) {
        return NULL;
    }
    ctx->tx_Trust = (APTR)store;
    return store;
}

LONG
atls_trust_ensure(struct TlsContext *ctx)
{
    struct AtlsTrustStore *store;
    STRPTR path;
    LONG rc;

    if (ctx == NULL) {
        return ERROR_TLS_INVALID_HANDLE;
    }
    if (ctx->tx_TrustShared && ctx->tx_Trust != NULL) {
        store = (struct AtlsTrustStore *)ctx->tx_Trust;
        return store->ts_LoadError;
    }
    path = atls_context_ca_path(ctx);
    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    rc = atls_trust_global_ensure(path);
    if (rc != 0) {
        return rc;
    }
    if (TlsBase != NULL && TlsBase->atb_SharedTrust != NULL) {
        if (ctx->tx_Trust != NULL && !ctx->tx_TrustShared) {
            atls_trust_clear(ctx);
        }
        ctx->tx_Trust = TlsBase->atb_SharedTrust;
        ctx->tx_TrustShared = TRUE;
    }
    return 0;
}

ULONG
atls_trust_anchor_count(struct TlsContext *ctx)
{
    struct AtlsTrustStore *store;

    store = atls_trust_get_store(ctx);
    if (store == NULL) {
        return 0;
    }
    return store->ts_Count;
}

APTR
atls_trust_anchors(struct TlsContext *ctx)
{
    struct AtlsTrustStore *store;

    store = atls_trust_get_store(ctx);
    if (store == NULL || store->ts_Count == 0 || store->ts_Anchors == NULL) {
        return NULL;
    }
    return (APTR)store->ts_Anchors;
}
