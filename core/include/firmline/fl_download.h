/* SPDX-License-Identifier: Apache-2.0 */
/* Checking a downloaded file against the size and SHA-256 of the signed manifest. */
#ifndef FIRMLINE_FL_DOWNLOAD_H
#define FIRMLINE_FL_DOWNLOAD_H

#include <psa/crypto.h>
#include <stddef.h>
#include <stdint.h>

#include "fl_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    psa_hash_operation_t op;
    uint64_t received, size;
    uint8_t sha256[32];
} fl_download;

/* Starts a check of a file of `size` bytes with the expected `sha256`. Call fl_init first.
 * FL_ERR_ARG for NULL arguments, FL_ERR_CRYPTO if the hash cannot start. Any earlier state of *d
 * is overwritten: end a running check with fl_download_finish or fl_download_abort first. */
int fl_download_begin(fl_download *d, const uint8_t sha256[32], uint64_t size);

/* Adds the next bytes (data may be NULL only when len is 0). FL_ERR_FORMAT once more than `size`
 * bytes would have arrived: the extra bytes are not hashed and fl_download_finish then reports
 * size_mismatch. FL_ERR_CRYPTO if hashing fails. */
int fl_download_update(fl_download *d, const uint8_t *data, size_t len);

/* Ends the check, always releasing the hash state. FL_OK when exactly `size` bytes arrived and
 * their SHA-256 equals the expected one (compared in constant time). Otherwise FL_ERR_FORMAT with
 * *detail (if not NULL) a static string, "size_mismatch" or "hash_mismatch": the details the
 * platform expects. FL_ERR_CRYPTO if hashing fails, FL_ERR_ARG for a NULL d. */
int fl_download_finish(fl_download *d, const char **detail);

/* Abandons a check (download cancelled): releases the hash state. Harmless when none is running
 * and when called twice. */
void fl_download_abort(fl_download *d);

#ifdef __cplusplus
}
#endif

#endif
