/* SPDX-License-Identifier: Apache-2.0 */
/* Test helper: an update key generated at run time (never saved), manifests and offers signed with
 * it, the way the platform signs them. */
#ifndef FIRMLINE_TESTS_SIGNER_H
#define FIRMLINE_TESTS_SIGNER_H

#include <psa/crypto.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    psa_key_id_t key;
    uint8_t spki[91]; /* the public key, SubjectPublicKeyInfo DER */
    size_t spki_len;
    char kid[65];
} signer;

/* Generates a P-256 key pair in PSA (call fl_init first). 0 on success. */
int signer_init(signer *s);
void signer_free(signer *s);

/* Signs data (ES256) and writes the 64-byte r||s signature in base64, NUL-terminated. */
int signer_sign(const signer *s, const uint8_t *data, size_t len, char sig_b64[89]);

/* The fields of a manifest as raw JSON text, inserted as they are; NULL leaves a field out. */
typedef struct {
    const char *v, *release, *tenant, *family, *component, *kid, *version, *sha256, *size,
        *not_before, *rollback;
    const char *extra; /* raw `"key":value` text added after the fields, or NULL */
    char kid_json[68];
} manifest_spec;

/* The manifest of the test vector, signed by s: kid of s, version 1.4.3. */
void manifest_default(manifest_spec *m, const signer *s);

/* Writes the manifest JSON (no NUL needed by the caller, but written). Its length, or -1. */
int manifest_write(const manifest_spec *m, char *out, size_t cap);

/* Writes an offer carrying `manifest` (raw bytes, encoded here in base64); NULL leaves a field out.
 * Its length, or -1 if it does not fit. */
int offer_write(const uint8_t *manifest, size_t len, const char *alg, const char *kid,
                const char *sig_b64, const char *url, const char *url_expires, char *out,
                size_t cap);

/* The default url and urlExpires of the test offers. */
#define SIGNER_URL "https://app.example/api/v1/ota/downloads/test"
#define SIGNER_URL_EXPIRES "2027-03-25T09:00:00Z"

/* Signs the manifest with s and writes the offer (alg ES256, kid of s, url or the default). */
int signer_offer(const signer *s, const char *manifest, size_t len, const char *url, char *out,
                 size_t cap);

#endif
