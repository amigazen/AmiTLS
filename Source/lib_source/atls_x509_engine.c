/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * atls_x509_engine.c - Select insecure or BearSSL x509_minimal validation
 */

#include <exec/types.h>

#include <devices/timer.h>

#include <string.h>

#include <libraries/amitls.h>

#include "private/atls_internal.h"
#include "private/atls_build.h"
#include "atls_trust.h"
#include "atls_x509_engine.h"

extern const br_hash_class br_sha1_vtable;
extern const br_hash_class br_sha256_vtable;
extern const br_hash_class br_sha384_vtable;
extern const br_hash_class br_sha512_vtable;
extern const br_ec_impl br_ec_all_m15;
extern const br_rsa_pkcs1_vrfy br_rsa_i15_pkcs1_vrfy;
extern uint32_t br_ecdsa_i15_vrfy_asn1(const br_ec_impl *impl,
    const br_hash_class *hf, const void *hash, size_t hash_len,
    const br_ec_public_key *pk, const unsigned char *sig, size_t sig_len);

#ifndef ATLS_BR_TICK_HZ
#define ATLS_BR_TICK_HZ 50UL
#endif

static VOID
atls_x509_register_hashes(br_x509_minimal_context *xc)
{
    /*
     * BearSSL ssl_client_full registers all hashes on the x509 engine;
     * without these, br_multihash_out() cannot compute TBS digests and
     * signature verification reads garbage.  Let's Encrypt E7 chains use
     * ecdsa-with-SHA384 on the server certificate (amigaworld.net, etc.).
     */
    br_x509_minimal_set_hash(xc, br_sha1_ID, &br_sha1_vtable);
    br_x509_minimal_set_hash(xc, br_sha256_ID, &br_sha256_vtable);
    br_x509_minimal_set_hash(xc, br_sha384_ID, &br_sha384_vtable);
    br_x509_minimal_set_hash(xc, br_sha512_ID, &br_sha512_vtable);
}

static VOID
atls_x509_set_validation_time(br_x509_minimal_context *xc)
{
    struct DateStamp ds;
    uint32_t days;
    uint32_t secs;

    /*
     * ATLS_BR_EPOCH_DAYS uses BearSSL year-0 AD day numbers (bearssl_x509.h)
     * so validation time matches read-date() output in x509_minimal.
     */
    DateStamp(&ds);
    days = ATLS_BR_EPOCH_DAYS + (uint32_t)ds.ds_Days;
    secs = (uint32_t)ds.ds_Minute * 60UL
        + (uint32_t)ds.ds_Tick / ATLS_BR_TICK_HZ;
    br_x509_minimal_set_time(xc, days, secs);
}

LONG
atls_x509_engine_init(AtlsX509Engine *eng, struct TlsContext *ctx,
    ULONG verify_mode, struct br_ssl_engine_context *ssl_eng)
{
    ULONG count;
    LONG rc;
    br_x509_trust_anchor *anchors;

    if (eng == NULL) {
        return ERROR_TLS_INVALID_HANDLE;
    }
    atls_x509_engine_clear(eng);

    if (verify_mode == ATSSL_VERIFY_NONE) {
        atls_x509_insecure_init(&eng->xe_u.insecure);
        eng->xe_Mode = ATLS_X509_INSECURE;
        eng->xe_Vtable = eng->xe_u.insecure.ix_vtable;
        return 0;
    }

    rc = atls_trust_ensure(ctx);
    if (rc != 0) {
        return rc;
    }
    count = atls_trust_anchor_count(ctx);
    if (count == 0) {
        return ERROR_TLS_VERIFY;
    }
    anchors = (br_x509_trust_anchor *)atls_trust_anchors(ctx);
    if (anchors == NULL) {
        return ERROR_TLS_VERIFY;
    }

    br_x509_minimal_init(&eng->xe_u.minimal, &br_sha256_vtable,
        anchors, (size_t)count);
    atls_x509_register_hashes(&eng->xe_u.minimal);
    atls_x509_set_validation_time(&eng->xe_u.minimal);
    br_x509_minimal_set_rsa(&eng->xe_u.minimal, &br_rsa_i15_pkcs1_vrfy);
    if (ssl_eng != NULL) {
        br_x509_minimal_set_ecdsa(&eng->xe_u.minimal,
            br_ssl_engine_get_ec(ssl_eng), &br_ecdsa_i15_vrfy_asn1);
    } else {
        br_x509_minimal_set_ecdsa(&eng->xe_u.minimal,
            &br_ec_all_m15, &br_ecdsa_i15_vrfy_asn1);
    }
    eng->xe_Mode = ATLS_X509_MINIMAL;
    eng->xe_Vtable = eng->xe_u.minimal.vtable;
    return 0;
}

const br_x509_class **
atls_x509_engine_vtable_ref(AtlsX509Engine *eng)
{
    if (eng == NULL) {
        return NULL;
    }
    if (eng->xe_Mode == ATLS_X509_MINIMAL) {
        return &eng->xe_u.minimal.vtable;
    }
    return &eng->xe_u.insecure.ix_vtable;
}

VOID
atls_x509_engine_refresh_time(AtlsX509Engine *eng)
{
    if (eng == NULL || eng->xe_Mode != ATLS_X509_MINIMAL) {
        return;
    }
    atls_x509_set_validation_time(&eng->xe_u.minimal);
}

VOID
atls_x509_engine_clear(AtlsX509Engine *eng)
{
    if (eng == NULL) {
        return;
    }
    memset(eng, 0, sizeof(*eng));
}

BOOL
atls_x509_engine_have_pkey(const AtlsX509Engine *eng)
{
    const br_x509_pkey *pk;
    unsigned usages;
    const br_x509_class **vref;

    if (eng == NULL || eng->xe_Vtable == NULL) {
        return FALSE;
    }
    if (eng->xe_Mode == ATLS_X509_INSECURE) {
        return eng->xe_u.insecure.ix_have_pkey ? TRUE : FALSE;
    }
    vref = atls_x509_engine_vtable_ref((AtlsX509Engine *)eng);
    if (vref == NULL || *vref == NULL) {
        return FALSE;
    }
    pk = (*vref)->get_pkey(vref, &usages);
    if (pk != NULL) {
        return TRUE;
    }
    return FALSE;
}
