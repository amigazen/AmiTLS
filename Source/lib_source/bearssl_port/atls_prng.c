/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2026 amigazen project
 *
 * Amiga PRNG seeder stub for BearSSL ssl_engine.c.
 *
 * atls_bearssl.c seeds the DRBG via br_ssl_engine_inject_entropy() before
 * br_ssl_client_reset(); 
 */

#include "inner.h"

/* see bearssl_rand.h */
br_prng_seeder
br_prng_seeder_system(const char **name)
{
    if (name != NULL) {
        *name = NULL;
    }
    return 0;
}
