/* SPDX-License-Identifier: Apache-2.0 */
/* Checking an OTA offer and its signed manifest: what the device does with it. */
#ifndef FIRMLINE_FL_OFFER_H
#define FIRMLINE_FL_OFFER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fl_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* What the device knows of itself. */
typedef struct {
    /* lowercase GUID */
    const char *tenant;
    /* "" when unknown (registered before T178, no `family` in the configuration) */
    const char *family;
    /* SubjectPublicKeyInfo */
    const uint8_t *update_key_der;
    size_t update_key_der_len;
    /* false for unknown and for `none` components */
    bool (*installable)(void *ctx, const char *component);
    /* NULL when unknown */
    const char *(*installed_version)(void *ctx, const char *component);
    void *ctx;
} fl_device;

typedef enum { FL_OFFER_INSTALL, FL_OFFER_WAIT, FL_OFFER_REJECT, FL_OFFER_IGNORE } fl_offer_action;

/* The decision on an offer.
 * INSTALL and WAIT: every field below is filled from the verified manifest and the offer.
 * REJECT: result, detail and release; the other fields are zero.
 * IGNORE (offer or manifest unreadable, or no readable release: no result can be sent): all zero.
 */
typedef struct {
    fl_offer_action action;
    fl_result result;
    char detail[65];    /* REJECT: one of the details advised by the guide, or family_unknown */
    fl_time wait_until; /* notBefore (WAIT: the time to check the offer again) */
    char release[37], component[65], version[65], url[1025];
    uint8_t sha256[32];
    uint64_t size;
    fl_time url_expires;
    bool rollback;
} fl_offer;

/* Checks the offer `json` (len bytes, no NUL needed) for the device `dev` at time `now`.
 * The signature is verified (ES256, 64 bytes r||s) over the exact manifest bytes decoded from
 * base64, with dev->update_key_der; nothing reaches INSTALL or WAIT without it. The offer's own
 * `kid` field is not trusted: the manifest's `kid` must be fl_key_id of the update key.
 * Order of the checks, each failure stops:
 *  1. offer JSON with `manifest`, `sig`, `url`, `urlExpires` strings; manifest base64 of at most
 *     2048 bytes, a JSON object with a GUID `release`: else IGNORE;
 *  2. manifest `kid` != fl_key_id(update key): REJECT rejected_signature kid_mismatch;
 *  3. `alg` != ES256, `sig` not 64 bytes, signature invalid: REJECT rejected_signature
 *     signature_invalid;
 *  4. any other field missing, of the wrong type or too long for its buffer, `v` != 1, `sha256`
 *     not 64 lowercase hex, `size` not 1..268435456, `url` not https://, a time not ISO 8601:
 *     REJECT failed format_unknown;
 *  5. REJECT failed tenant_mismatch, family_unknown (dev->family ""), family_mismatch,
 *     component_mismatch, older_version (fl_version_too_old and not `rollback`);
 *  6. notBefore after now: WAIT (never a refusal: the clock may not be set yet); else INSTALL.
 * GUIDs and kid are compared ignoring case. `release` is kept as written in the manifest.
 * Returns FL_OK with a decision in *out. Errors (out->action IGNORE, all zero): FL_ERR_ARG for a
 * NULL argument or callback, or an update key that is not a P-256 SubjectPublicKeyInfo;
 * FL_ERR_CRYPTO when the crypto library fails (fl_init not called, out of memory).
 * No allocation of its own (Mbed TLS allocates while verifying); about 7 KB of stack. */
int fl_offer_check(const fl_device *dev, const char *json, size_t len, fl_time now, fl_offer *out);

/* The key id: lowercase hex SHA-256 of key_der (SubjectPublicKeyInfo), NUL-terminated.
 * FL_ERR_ARG for NULL or empty arguments, FL_ERR_CRYPTO if hashing fails. */
int fl_key_id(const uint8_t *key_der, size_t len, char out[65]);

#ifdef __cplusplus
}
#endif

#endif
