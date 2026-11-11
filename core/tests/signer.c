/* SPDX-License-Identifier: Apache-2.0 */
#include "signer.h"

#include "firmline/fl_offer.h"

#include <mbedtls/base64.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* DER of a P-256 SubjectPublicKeyInfo up to the 65-byte uncompressed point. */
static const uint8_t spki_prefix[26] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
                                        0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
                                        0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00};

int signer_init(signer *s) {
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t point[65];
    size_t n = 0;
    memset(s, 0, sizeof *s);
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&a, 256);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&a, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    if (psa_generate_key(&a, &s->key) != PSA_SUCCESS)
        return -1;
    if (psa_export_public_key(s->key, point, sizeof point, &n) != PSA_SUCCESS || n != sizeof point)
        return -1;
    memcpy(s->spki, spki_prefix, sizeof spki_prefix);
    memcpy(s->spki + sizeof spki_prefix, point, sizeof point);
    s->spki_len = sizeof spki_prefix + sizeof point;
    return fl_key_id(s->spki, s->spki_len, s->kid) == FL_OK ? 0 : -1;
}

void signer_free(signer *s) { psa_destroy_key(s->key); }

int signer_sign(const signer *s, const uint8_t *data, size_t len, char sig_b64[89]) {
    uint8_t sig[64];
    size_t n = 0;
    if (psa_sign_message(s->key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), data, len, sig, sizeof sig, &n) !=
            PSA_SUCCESS ||
        n != sizeof sig)
        return -1;
    return mbedtls_base64_encode((unsigned char *)sig_b64, 89, &n, sig, sizeof sig) == 0 ? 0 : -1;
}

void manifest_default(manifest_spec *m, const signer *s) {
    memset(m, 0, sizeof *m);
    snprintf(m->kid_json, sizeof m->kid_json, "\"%s\"", s->kid);
    m->v = "1";
    m->release = "\"8c1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b\"";
    m->tenant = "\"11111111-2222-4333-8444-555555555555\"";
    m->family = "\"66666666-7777-4888-9999-aaaaaaaaaaaa\"";
    m->component = "\"firmware\"";
    m->kid = m->kid_json;
    m->version = "\"1.4.3\"";
    m->sha256 = "\"c344861c7dd2b9a3bfaa0f5f97b8155553cfe3c8d8128e43eef4511ab795372b\"";
    m->size = "1000";
    m->not_before = "\"2027-03-25T00:00:00Z\"";
    m->rollback = "false";
}

/* Appends formatted text at *len; false once it does not fit. */
static bool append(char *out, size_t cap, size_t *len, const char *fmt, ...) {
    va_list ap;
    int n;
    if (*len >= cap)
        return false;
    va_start(ap, fmt);
    n = vsnprintf(out + *len, cap - *len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= cap - *len)
        return false;
    *len += (size_t)n;
    return true;
}

/* Appends `"key":value` (value raw), with a comma before all but the first; nothing if NULL. */
static bool field(char *out, size_t cap, size_t *len, bool *first, const char *key,
                  const char *value) {
    bool ok;
    if (value == NULL)
        return true;
    ok = append(out, cap, len, "%s\"%s\":%s", *first ? "" : ",", key, value);
    *first = false;
    return ok;
}

int manifest_write(const manifest_spec *m, char *out, size_t cap) {
    size_t len = 0;
    bool first = true;
    bool ok = append(out, cap, &len, "{") && field(out, cap, &len, &first, "v", m->v) &&
              field(out, cap, &len, &first, "release", m->release) &&
              field(out, cap, &len, &first, "tenant", m->tenant) &&
              field(out, cap, &len, &first, "family", m->family) &&
              field(out, cap, &len, &first, "component", m->component) &&
              field(out, cap, &len, &first, "kid", m->kid) &&
              field(out, cap, &len, &first, "version", m->version) &&
              field(out, cap, &len, &first, "sha256", m->sha256) &&
              field(out, cap, &len, &first, "size", m->size) &&
              field(out, cap, &len, &first, "notBefore", m->not_before) &&
              field(out, cap, &len, &first, "rollback", m->rollback) &&
              (m->extra == NULL || append(out, cap, &len, "%s%s", first ? "" : ",", m->extra)) &&
              append(out, cap, &len, "}");
    return ok ? (int)len : -1;
}

/* Appends `"key":"value"`; nothing if NULL. */
static bool string_field(char *out, size_t cap, size_t *len, bool *first, const char *key,
                         const char *value) {
    bool ok;
    if (value == NULL)
        return true;
    ok = append(out, cap, len, "%s\"%s\":\"%s\"", *first ? "" : ",", key, value);
    *first = false;
    return ok;
}

int offer_write(const uint8_t *manifest, size_t len, const char *alg, const char *kid,
                const char *sig_b64, const char *url, const char *url_expires, char *out,
                size_t cap) {
    static char b64[8192];
    size_t n = 0, out_len = 0;
    bool first = true, ok;
    if (mbedtls_base64_encode((unsigned char *)b64, sizeof b64, &n, manifest, len) != 0)
        return -1;
    ok = append(out, cap, &out_len, "{") &&
         string_field(out, cap, &out_len, &first, "manifest", b64) &&
         string_field(out, cap, &out_len, &first, "alg", alg) &&
         string_field(out, cap, &out_len, &first, "kid", kid) &&
         string_field(out, cap, &out_len, &first, "sig", sig_b64) &&
         string_field(out, cap, &out_len, &first, "url", url) &&
         string_field(out, cap, &out_len, &first, "urlExpires", url_expires) &&
         append(out, cap, &out_len, "}");
    return ok ? (int)out_len : -1;
}

int signer_offer(const signer *s, const char *manifest, size_t len, const char *url, char *out,
                 size_t cap) {
    char sig[89];
    if (signer_sign(s, (const uint8_t *)manifest, len, sig) != 0)
        return -1;
    return offer_write((const uint8_t *)manifest, len, "ES256", s->kid, sig,
                       url != NULL ? url : SIGNER_URL, SIGNER_URL_EXPIRES, out, cap);
}
