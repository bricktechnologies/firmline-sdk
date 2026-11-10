/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FIRMLINE_FL_COMMON_H
#define FIRMLINE_FL_COMMON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FL_OK 0
#define FL_ERR_ARG (-1)    /* invalid argument */
#define FL_ERR_SPACE (-2)  /* output buffer too small */
#define FL_ERR_FORMAT (-3) /* malformed input */
#define FL_ERR_CRYPTO (-4) /* crypto library failure */
#define FL_ERR_FULL (-5)   /* fixed-size table full */

typedef int64_t fl_time; /* seconds since 1970-01-01T00:00:00Z */

typedef enum { FL_RESULT_INSTALLED, FL_RESULT_FAILED, FL_RESULT_REJECTED_SIGNATURE } fl_result;

/* Initializes the crypto library (psa_crypto_init). FL_ERR_CRYPTO on failure. */
int fl_init(void);

/* SHA-256 of data (data may be NULL only when len is 0). Call fl_init first. */
int fl_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* Parses an ISO 8601 date-time with "Z" or a "+hh:mm" / "-hh:mm" offset, for example
 * "2027-03-10T08:00:00Z" or "2027-03-10T09:00:00+01:00". FL_ERR_FORMAT if malformed or not a real
 * date. */
int fl_time_parse(const char *iso, size_t len, fl_time *out);

/* Writes t as "2027-03-10T08:00:00Z" (offset 0) or "2027-03-10T09:00:00+01:00" (offset in
 * minutes, -1439..1439), NUL-terminated. FL_ERR_ARG if the offset or the year (0..9999) is out of
 * range. */
int fl_time_format(fl_time t, int offset_minutes, char out[26]);

#ifdef __cplusplus
}
#endif

#endif
