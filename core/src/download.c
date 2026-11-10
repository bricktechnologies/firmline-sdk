/* SPDX-License-Identifier: Apache-2.0 */
#include "firmline/fl_download.h"

#include <string.h>

int fl_download_begin(fl_download *d, const uint8_t sha256[32], uint64_t size) {
    if (d == NULL || sha256 == NULL)
        return FL_ERR_ARG;
    memset(d, 0, sizeof *d);
    d->op = psa_hash_operation_init();
    memcpy(d->sha256, sha256, 32);
    d->size = size;
    if (psa_hash_setup(&d->op, PSA_ALG_SHA_256) != PSA_SUCCESS) {
        psa_hash_abort(&d->op);
        return FL_ERR_CRYPTO;
    }
    return FL_OK;
}

int fl_download_update(fl_download *d, const uint8_t *data, size_t len) {
    if (d == NULL || (data == NULL && len != 0))
        return FL_ERR_ARG;
    if (d->received > d->size || (uint64_t)len > d->size - d->received) {
        d->received = d->size + 1; /* beyond the size: finish reports size_mismatch */
        if (d->received == 0)      /* size == UINT64_MAX: cannot be represented, keep it beyond */
            d->received = UINT64_MAX;
        return FL_ERR_FORMAT;
    }
    if (len == 0)
        return FL_OK;
    if (psa_hash_update(&d->op, data, len) != PSA_SUCCESS)
        return FL_ERR_CRYPTO;
    d->received += len;
    return FL_OK;
}

int fl_download_finish(fl_download *d, const char **detail) {
    uint8_t digest[32];
    size_t digest_len = 0;
    unsigned diff = 0;
    size_t i;
    if (d == NULL)
        return FL_ERR_ARG;
    if (d->received != d->size) {
        psa_hash_abort(&d->op);
        if (detail != NULL)
            *detail = "size_mismatch";
        return FL_ERR_FORMAT;
    }
    if (psa_hash_finish(&d->op, digest, sizeof digest, &digest_len) != PSA_SUCCESS ||
        digest_len != sizeof digest) {
        psa_hash_abort(&d->op);
        return FL_ERR_CRYPTO;
    }
    for (i = 0; i < sizeof digest; i++)
        diff |= (unsigned)(digest[i] ^ d->sha256[i]);
    if (diff != 0) {
        if (detail != NULL)
            *detail = "hash_mismatch";
        return FL_ERR_FORMAT;
    }
    return FL_OK;
}

void fl_download_abort(fl_download *d) {
    if (d != NULL)
        psa_hash_abort(&d->op);
}
