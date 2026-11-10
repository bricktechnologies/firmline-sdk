/* SPDX-License-Identifier: Apache-2.0 */
#include "firmline/fl_offer.h"

#include "firmline/fl_json.h"
#include "firmline/fl_version.h"

#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <psa/crypto.h>
#include <string.h>

#define MANIFEST_MAX 2048     /* bytes of the decoded manifest */
#define MANIFEST_B64_MAX 2732 /* 4 * ceil(2048 / 3) */
#define SIG_LEN 64            /* r||s of P-256 */
#define SIG_B64_LEN 88        /* base64 of 64 bytes */
#define ALG_CAP 8
#define TIME_CAP 32
#define GUID_LEN 36
#define FIRMWARE_MAX 268435456 /* 256 MB (D43) */

static bool is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static char lower(char c) { return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c; }

static bool equal_ignore_case(const char *a, const char *b) {
    for (; *a != '\0' && *b != '\0'; a++, b++)
        if (lower(*a) != lower(*b))
            return false;
    return *a == *b;
}

/* 8-4-4-4-12 hex digits, either case. Stops at the first character that does not fit, so it
 * never reads past the NUL. */
static bool is_guid(const char *s) {
    int i;
    for (i = 0; i < GUID_LEN; i++) {
        bool dash = i == 8 || i == 13 || i == 18 || i == 23;
        if (dash ? s[i] != '-' : !is_hex(s[i]))
            return false;
    }
    return s[GUID_LEN] == '\0';
}

/* Exactly 64 lowercase hex digits into 32 bytes. */
static bool sha256_from_hex(const char *s, uint8_t out[32]) {
    int i;
    for (i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    if (s[64] != '\0')
        return false;
    for (i = 0; i < 32; i++) {
        char h = s[2 * i], l = s[2 * i + 1];
        int hv = h <= '9' ? h - '0' : h - 'a' + 10, lv = l <= '9' ? l - '0' : l - 'a' + 10;
        out[i] = (uint8_t)(hv * 16 + lv);
    }
    return true;
}

static int parse_time(const char *s, fl_time *out) { return fl_time_parse(s, strlen(s), out); }

/* A string that is present: read whole (FL_OK) or too long for the buffer (FL_ERR_SPACE). */
static bool present(int rc) { return rc == FL_OK || rc == FL_ERR_SPACE; }

/* No decision can be sent: everything zero. */
static int ignore(fl_offer *out, int rc) {
    memset(out, 0, sizeof *out);
    out->action = FL_OFFER_IGNORE;
    return rc;
}

/* A refusal: result, detail and release; everything else zero. */
static int reject(fl_offer *out, fl_result result, const char *detail) {
    char release[sizeof out->release];
    size_t n;
    memcpy(release, out->release, sizeof release);
    memset(out, 0, sizeof *out);
    memcpy(out->release, release, sizeof release);
    out->action = FL_OFFER_REJECT;
    out->result = result;
    n = strlen(detail);
    if (n >= sizeof out->detail)
        n = sizeof out->detail - 1;
    memcpy(out->detail, detail, n);
    return FL_OK;
}

/* Verifies the ES256 signature (r||s) of msg with the SubjectPublicKeyInfo key_der.
 * FL_OK valid, FL_ERR_FORMAT invalid, FL_ERR_ARG not a P-256 public key, FL_ERR_CRYPTO otherwise.
 * The PSA key exists only during the call. */
static int verify(const uint8_t *key_der, size_t key_len, const uint8_t *msg, size_t msg_len,
                  const uint8_t sig[SIG_LEN]) {
    mbedtls_pk_context pk;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t status;
    int rc;
    mbedtls_pk_init(&pk);
    if (mbedtls_pk_parse_public_key(&pk, key_der, key_len) != 0 ||
        mbedtls_pk_get_type(&pk) != MBEDTLS_PK_ECKEY ||
        mbedtls_pk_get_psa_attributes(&pk, PSA_KEY_USAGE_VERIFY_MESSAGE, &attr) != 0 ||
        psa_get_key_type(&attr) != PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1) ||
        psa_get_key_bits(&attr) != 256) {
        rc = FL_ERR_ARG;
        goto done;
    }
    /* Only the one algorithm of the contract. */
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    if (mbedtls_pk_import_into_psa(&pk, &attr, &key) != 0) {
        rc = FL_ERR_CRYPTO;
        goto done;
    }
    status = psa_verify_message(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), msg, msg_len, sig, SIG_LEN);
    if (status == PSA_SUCCESS)
        rc = FL_OK;
    else if (status == PSA_ERROR_INVALID_SIGNATURE) /* also r or s zero or not below n */
        rc = FL_ERR_FORMAT;
    else
        rc = FL_ERR_CRYPTO;
done:
    psa_destroy_key(key); /* nothing to do for the null key */
    psa_reset_key_attributes(&attr);
    mbedtls_pk_free(&pk);
    return rc;
}

int fl_key_id(const uint8_t *key_der, size_t len, char out[65]) {
    static const char hex[] = "0123456789abcdef";
    uint8_t h[32];
    int i, rc;
    if (key_der == NULL || len == 0 || out == NULL)
        return FL_ERR_ARG;
    rc = fl_sha256(key_der, len, h);
    if (rc != FL_OK)
        return rc;
    for (i = 0; i < 32; i++) {
        out[2 * i] = hex[h[i] >> 4];
        out[2 * i + 1] = hex[h[i] & 0x0f];
    }
    out[64] = '\0';
    return FL_OK;
}

int fl_offer_check(const fl_device *dev, const char *json, size_t len, fl_time now, fl_offer *out) {
    fl_json j; /* the offer, then the manifest */
    char manifest_b64[MANIFEST_B64_MAX + 1];
    uint8_t manifest[MANIFEST_MAX];
    size_t manifest_len = 0, sig_len = 0;
    char sig_b64[SIG_B64_LEN + 1], alg[ALG_CAP], url_expires[TIME_CAP], not_before[TIME_CAP];
    char key_kid[65], kid[65], tenant[GUID_LEN + 1], family[GUID_LEN + 1], sha256[65];
    uint8_t sig[SIG_LEN];
    int sig_rc, alg_rc, url_rc, expires_rc, rc;
    int64_t v = 0, size = 0;

    if (out == NULL)
        return FL_ERR_ARG;
    if (dev == NULL || json == NULL || dev->tenant == NULL || dev->family == NULL ||
        dev->update_key_der == NULL || dev->update_key_der_len == 0 || dev->installable == NULL ||
        dev->installed_version == NULL)
        return ignore(out, FL_ERR_ARG);
    (void)ignore(out, FL_OK);

    /* 1. The offer and the release of its manifest: without them no result can be sent. */
    if (fl_json_parse(&j, json, len) != FL_OK ||
        fl_json_string(&j, "manifest", manifest_b64, sizeof manifest_b64) != FL_OK)
        return ignore(out, FL_OK);
    sig_rc = fl_json_string(&j, "sig", sig_b64, sizeof sig_b64);
    url_rc = fl_json_string(&j, "url", out->url, sizeof out->url);
    expires_rc = fl_json_string(&j, "urlExpires", url_expires, sizeof url_expires);
    alg_rc = fl_json_string(&j, "alg", alg, sizeof alg);
    if (!present(sig_rc) || !present(url_rc) || !present(expires_rc))
        return ignore(out, FL_OK);
    if (mbedtls_base64_decode(manifest, sizeof manifest, &manifest_len,
                              (const unsigned char *)manifest_b64, strlen(manifest_b64)) != 0 ||
        fl_json_parse(&j, (const char *)manifest, manifest_len) != FL_OK ||
        fl_json_string(&j, "release", out->release, sizeof out->release) != FL_OK ||
        !is_guid(out->release))
        return ignore(out, FL_OK);

    /* 2. The key named by the manifest (the offer's own kid is not trusted). */
    rc = fl_key_id(dev->update_key_der, dev->update_key_der_len, key_kid);
    if (rc != FL_OK)
        return ignore(out, rc);
    if (fl_json_string(&j, "kid", kid, sizeof kid) != FL_OK || !equal_ignore_case(kid, key_kid))
        return reject(out, FL_RESULT_REJECTED_SIGNATURE, "kid_mismatch");

    /* 3. The signature over the exact decoded bytes. Nothing below runs without it. */
    if (alg_rc != FL_OK || strcmp(alg, "ES256") != 0 || sig_rc != FL_OK ||
        mbedtls_base64_decode(sig, sizeof sig, &sig_len, (const unsigned char *)sig_b64,
                              strlen(sig_b64)) != 0 ||
        sig_len != SIG_LEN)
        return reject(out, FL_RESULT_REJECTED_SIGNATURE, "signature_invalid");
    rc = verify(dev->update_key_der, dev->update_key_der_len, manifest, manifest_len, sig);
    if (rc == FL_ERR_FORMAT)
        return reject(out, FL_RESULT_REJECTED_SIGNATURE, "signature_invalid");
    if (rc != FL_OK)
        return ignore(out, rc);

    /* 4. Every other field, whole and well formed. */
    if (fl_json_int(&j, "v", &v) != FL_OK || v != 1 ||
        fl_json_string(&j, "tenant", tenant, sizeof tenant) != FL_OK ||
        fl_json_string(&j, "family", family, sizeof family) != FL_OK ||
        fl_json_string(&j, "component", out->component, sizeof out->component) != FL_OK ||
        out->component[0] == '\0' ||
        fl_json_string(&j, "version", out->version, sizeof out->version) != FL_OK ||
        out->version[0] == '\0' || fl_json_string(&j, "sha256", sha256, sizeof sha256) != FL_OK ||
        !sha256_from_hex(sha256, out->sha256) || fl_json_int(&j, "size", &size) != FL_OK ||
        size < 1 || size > FIRMWARE_MAX ||
        fl_json_string(&j, "notBefore", not_before, sizeof not_before) != FL_OK ||
        parse_time(not_before, &out->wait_until) != FL_OK ||
        fl_json_bool(&j, "rollback", &out->rollback) != FL_OK || url_rc != FL_OK ||
        strncmp(out->url, "https://", 8) != 0 || expires_rc != FL_OK ||
        parse_time(url_expires, &out->url_expires) != FL_OK)
        return reject(out, FL_RESULT_FAILED, "format_unknown");
    out->size = (uint64_t)size;

    /* 5. This device, this component, not an older version. */
    if (!equal_ignore_case(tenant, dev->tenant))
        return reject(out, FL_RESULT_FAILED, "tenant_mismatch");
    if (dev->family[0] == '\0')
        return reject(out, FL_RESULT_FAILED, "family_unknown");
    if (!equal_ignore_case(family, dev->family))
        return reject(out, FL_RESULT_FAILED, "family_mismatch");
    if (!dev->installable(dev->ctx, out->component))
        return reject(out, FL_RESULT_FAILED, "component_mismatch");
    if (!out->rollback &&
        fl_version_too_old(out->version, dev->installed_version(dev->ctx, out->component)))
        return reject(out, FL_RESULT_FAILED, "older_version");

    /* 6. Not before notBefore: wait, never refuse (the clock may not be set yet). */
    out->action = out->wait_until > now ? FL_OFFER_WAIT : FL_OFFER_INSTALL;
    return FL_OK;
}
