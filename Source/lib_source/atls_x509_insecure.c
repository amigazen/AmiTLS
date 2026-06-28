/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_x509_insecure.c - Insecure acceptor for BearSSL client (phase 1)
 *
 * Validates certificate chain structure and extracts the leaf public key.
 * CA trust and hostname verification are added in a later phase.
 */


#include <exec/types.h>

#include <string.h>

#include "atls_x509_insecure.h"

static VOID
ix_clear_pkey(AtlsInsecureX509Context *xc)
{
    xc->ix_have_pkey = 0;
    xc->ix_key_data_len = 0;
    memset(&xc->ix_pkey, 0, sizeof(xc->ix_pkey));
    memset(xc->ix_key_data, 0, sizeof(xc->ix_key_data));
    memset(xc->ix_leaf_key_sha256, 0, sizeof(xc->ix_leaf_key_sha256));
}

static UBYTE
ix_copy_pkey(AtlsInsecureX509Context *xc, const br_x509_pkey *pk)
{
    size_t nlen;
    size_t elen;
    size_t qlen;

    ix_clear_pkey(xc);
    if (pk == NULL) {
        return 0;
    }
    xc->ix_pkey.key_type = pk->key_type;
    if (pk->key_type == BR_KEYTYPE_RSA) {
        nlen = pk->key.rsa.nlen;
        elen = pk->key.rsa.elen;
        if (nlen + elen > sizeof(xc->ix_key_data)) {
            return 0;
        }
        memcpy(xc->ix_key_data, pk->key.rsa.n, nlen);
        memcpy(xc->ix_key_data + nlen, pk->key.rsa.e, elen);
        xc->ix_pkey.key.rsa.n = xc->ix_key_data;
        xc->ix_pkey.key.rsa.nlen = nlen;
        xc->ix_pkey.key.rsa.e = xc->ix_key_data + nlen;
        xc->ix_pkey.key.rsa.elen = elen;
        xc->ix_key_data_len = nlen + elen;
        xc->ix_have_pkey = 1;
        return 1;
    }
    if (pk->key_type == BR_KEYTYPE_EC) {
        qlen = pk->key.ec.qlen;
        if (qlen > sizeof(xc->ix_key_data)) {
            return 0;
        }
        memcpy(xc->ix_key_data, pk->key.ec.q, qlen);
        xc->ix_pkey.key.ec.curve = pk->key.ec.curve;
        xc->ix_pkey.key.ec.q = xc->ix_key_data;
        xc->ix_pkey.key.ec.qlen = qlen;
        xc->ix_key_data_len = qlen;
        xc->ix_have_pkey = 1;
        return 1;
    }
    return 0;
}

static VOID
ix_start_chain(const br_x509_class **ctx, const char *server_name)
{
    AtlsInsecureX509Context *xc;

    xc = (AtlsInsecureX509Context *)(void *)ctx;
    ix_clear_pkey(xc);
    xc->ix_cert_index = 0;
    xc->ix_failed = 0;
    (void)server_name;
}

static VOID
ix_start_cert(const br_x509_class **ctx, uint32_t length)
{
    AtlsInsecureX509Context *xc;

    xc = (AtlsInsecureX509Context *)(void *)ctx;
    if (xc->ix_cert_index == 0) {
        br_x509_decoder_init(&xc->ix_decoder, 0, 0);
    }
    (void)length;
}

static VOID
ix_append(const br_x509_class **ctx, const unsigned char *buf, size_t len)
{
    AtlsInsecureX509Context *xc;

    xc = (AtlsInsecureX509Context *)(void *)ctx;
    if (xc->ix_cert_index == 0) {
        br_x509_decoder_push(&xc->ix_decoder, buf, len);
    }
}

static VOID
ix_end_cert(const br_x509_class **ctx)
{
    AtlsInsecureX509Context *xc;
    const br_x509_pkey *pk;

    xc = (AtlsInsecureX509Context *)(void *)ctx;
    if (xc->ix_cert_index == 0) {
        pk = br_x509_decoder_get_pkey(&xc->ix_decoder);
        if (!ix_copy_pkey(xc, pk)) {
            xc->ix_failed = 1;
        }
    }
    xc->ix_cert_index++;
}

static unsigned
ix_end_chain(const br_x509_class **ctx)
{
    AtlsInsecureX509Context *xc;

    xc = (AtlsInsecureX509Context *)(void *)ctx;
    if (xc->ix_failed || !xc->ix_have_pkey) {
        return BR_ERR_X509_BAD_SERVER_NAME;
    }
    return 0;
}

static const br_x509_pkey *
ix_get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
    const AtlsInsecureX509Context *xc;

    xc = (const AtlsInsecureX509Context *)(const void *)ctx;
    if (usages != NULL) {
        *usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN;
    }
    if (xc->ix_have_pkey) {
        return &xc->ix_pkey;
    }
    return NULL;
}

static const br_x509_class ix_vtable = {
    sizeof(AtlsInsecureX509Context),
    ix_start_chain,
    ix_start_cert,
    ix_append,
    ix_end_cert,
    ix_end_chain,
    ix_get_pkey
};

VOID
atls_x509_insecure_init(AtlsInsecureX509Context *ctx)
{
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->ix_vtable = &ix_vtable;
}
