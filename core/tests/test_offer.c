/* SPDX-License-Identifier: Apache-2.0 */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS /* mbedtls_psa_stats_t fields, to count the PSA keys */

#include "firmline/fl_offer.h"

#include "check.h"
#include "signer.h"

#include <mbedtls/base64.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <string.h>

#define TENANT "11111111-2222-4333-8444-555555555555"
#define FAMILY "66666666-7777-4888-9999-aaaaaaaaaaaa"
#define RELEASE "8c1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b"
#define VECTOR_KID "70203f39f1a767927b55ac11efeab380e9b452dd5dff073807eb1ee82d7dc623"
#define VECTOR_URL                                                                                 \
    "https://app.example/api/v1/ota/downloads/"                                                    \
    "ERERESIiM0OERFVVVVVVVVuApcrvFDleg6jN8hc8YYar0PUaP2SJrtP4HUJnjLHW"
#define VECTOR_URL_EXPIRES "2027-03-25T09:00:00Z"
#define NOT_BEFORE "2027-03-25T00:00:00Z"

static const uint8_t vector_sha256[32] = {
    0xc3, 0x44, 0x86, 0x1c, 0x7d, 0xd2, 0xb9, 0xa3, 0xbf, 0xaa, 0x0f, 0x5f, 0x97, 0xb8, 0x15, 0x55,
    0x53, 0xcf, 0xe3, 0xc8, 0xd8, 0x12, 0x8e, 0x43, 0xee, 0xf4, 0x51, 0x1a, 0xb7, 0x95, 0x37, 0x2b};

static char vector_offer[2048];
static size_t vector_offer_len;
static char vector_manifest[1024];
static size_t vector_manifest_len;
static uint8_t vector_key[128];
static size_t vector_key_len;
static char vector_sig[128];     /* P1363, base64 */
static char vector_sig_der[128]; /* DER, base64 */
static signer test_signer;

/* ---- setup -------------------------------------------------------------------------------- */

static size_t read_file(const char *path, char *buf, size_t cap) {
    size_t n;
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return 0;
    n = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[n] = '\0';
    return n;
}

static void trim(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' '))
        s[--n] = '\0';
}

/* The DER inside the PEM file: the base64 lines between the BEGIN and END lines. */
static bool pem_to_der(const char *pem, uint8_t *der, size_t cap, size_t *len) {
    char b64[256];
    size_t n = 0;
    const char *p = strstr(pem, "-----\n");
    const char *end = strstr(pem, "\n-----END");
    if (p == NULL || end == NULL)
        return false;
    for (p += 6; p < end && n + 1 < sizeof b64; p++)
        if (*p != '\n' && *p != '\r')
            b64[n++] = *p;
    b64[n] = '\0';
    return mbedtls_base64_decode(der, cap, len, (const unsigned char *)b64, n) == 0;
}

static bool load_vector(void) {
    char pem[512];
    vector_offer_len =
        read_file(FL_VECTOR_DIR "/ota/offer.json", vector_offer, sizeof vector_offer);
    vector_manifest_len =
        read_file(FL_VECTOR_DIR "/ota/manifest.json", vector_manifest, sizeof vector_manifest);
    if (vector_offer_len == 0 || vector_manifest_len == 0 ||
        read_file(FL_VECTOR_DIR "/ota/public-key.pem", pem, sizeof pem) == 0 ||
        read_file(FL_VECTOR_DIR "/ota/signature-p1363.b64", vector_sig, sizeof vector_sig) == 0 ||
        read_file(FL_VECTOR_DIR "/ota/signature-der.b64", vector_sig_der, sizeof vector_sig_der) ==
            0)
        return false;
    trim(vector_sig);
    trim(vector_sig_der);
    return pem_to_der(pem, vector_key, sizeof vector_key, &vector_key_len);
}

/* ---- devices ------------------------------------------------------------------------------ */

typedef struct {
    const char *component;      /* the one installable component */
    const char *none_component; /* known, only reported (installation `none`) */
    const char *installed;      /* version of both */
} test_ctx;

static bool installable(void *ctx, const char *component) {
    const test_ctx *c = ctx;
    return strcmp(component, c->component) == 0;
}

static const char *installed_version(void *ctx, const char *component) {
    const test_ctx *c = ctx;
    if (strcmp(component, c->component) == 0 || strcmp(component, c->none_component) == 0)
        return c->installed;
    return NULL;
}

static fl_device make_device(test_ctx *c, const uint8_t *key, size_t key_len) {
    fl_device d;
    c->component = "firmware";
    c->none_component = "torizon-os";
    c->installed = "1.4.2";
    d.tenant = TENANT;
    d.family = FAMILY;
    d.update_key_der = key;
    d.update_key_der_len = key_len;
    d.installable = installable;
    d.installed_version = installed_version;
    d.ctx = c;
    return d;
}

static fl_device vector_device(test_ctx *c) { return make_device(c, vector_key, vector_key_len); }

static fl_device signer_device(test_ctx *c) {
    return make_device(c, test_signer.spki, test_signer.spki_len);
}

static fl_time at(const char *iso) {
    fl_time t = 0;
    CHECK_EQ_INT(fl_time_parse(iso, strlen(iso), &t), FL_OK);
    return t;
}

/* ---- helpers ------------------------------------------------------------------------------ */

static char offer_buf[16384];

/* Checks an offer carrying the given manifest bytes and base64 signature (vector url). */
static int check_raw(const fl_device *d, const uint8_t *manifest, size_t len, const char *alg,
                     const char *sig, fl_time now, fl_offer *o) {
    int n = offer_write(manifest, len, alg, VECTOR_KID, sig, VECTOR_URL, VECTOR_URL_EXPIRES,
                        offer_buf, sizeof offer_buf);
    CHECK(n > 0);
    if (n <= 0)
        return FL_ERR_ARG;
    return fl_offer_check(d, offer_buf, (size_t)n, now, o);
}

/* Writes the manifest, signs it with test_signer and checks the offer (url NULL: the default). */
static int check_signed(const manifest_spec *m, const fl_device *d, fl_time now, const char *url,
                        fl_offer *o) {
    static char manifest[8192];
    int ml = manifest_write(m, manifest, sizeof manifest), ol = -1;
    CHECK(ml > 0);
    if (ml > 0)
        ol = signer_offer(&test_signer, manifest, (size_t)ml, url, offer_buf, sizeof offer_buf);
    CHECK(ol > 0);
    if (ol <= 0)
        return FL_ERR_ARG;
    return fl_offer_check(d, offer_buf, (size_t)ol, now, o);
}

/* Fills o with garbage first, so that a field the check forgets to set or clear shows. */
static void dirty(fl_offer *o) { memset(o, 0x5a, sizeof *o); }

static bool all_zero(const void *p, size_t n) {
    const uint8_t *b = p;
    size_t i;
    for (i = 0; i < n; i++)
        if (b[i] != 0)
            return false;
    return true;
}

/* REJECT with result and detail, release filled, everything else empty. */
static void check_reject(const fl_offer *o, fl_result result, const char *detail) {
    CHECK_EQ_INT(o->action, FL_OFFER_REJECT);
    CHECK_EQ_INT(o->result, result);
    CHECK_EQ_STR(o->detail, detail);
    CHECK_EQ_STR(o->release, RELEASE);
    CHECK(o->component[0] == '\0' && o->version[0] == '\0' && o->url[0] == '\0');
    CHECK(all_zero(o->sha256, sizeof o->sha256) && o->size == 0 && o->url_expires == 0 &&
          o->wait_until == 0 && !o->rollback);
}

static void check_ignore(const fl_offer *o) {
    CHECK_EQ_INT(o->action, FL_OFFER_IGNORE);
    CHECK(o->release[0] == '\0' && o->detail[0] == '\0' && o->url[0] == '\0');
}

static void check_failed(const manifest_spec *m, const char *detail) {
    test_ctx c;
    fl_device d = signer_device(&c);
    fl_offer o;
    dirty(&o);
    CHECK_EQ_INT(check_signed(m, &d, at(NOT_BEFORE), NULL, &o), FL_OK);
    check_reject(&o, FL_RESULT_FAILED, detail);
}

static void check_installs(const manifest_spec *m, const fl_device *d, fl_offer *o) {
    dirty(o);
    CHECK_EQ_INT(check_signed(m, d, at(NOT_BEFORE), NULL, o), FL_OK);
    CHECK_EQ_INT(o->action, FL_OFFER_INSTALL);
    CHECK_EQ_STR(o->release, RELEASE);
}

/* ---- tests -------------------------------------------------------------------------------- */

static void key_id_of_the_vector(void) {
    char kid[65];
    CHECK_EQ_INT(fl_key_id(vector_key, vector_key_len, kid), FL_OK);
    CHECK_EQ_STR(kid, VECTOR_KID);
    CHECK_EQ_INT(fl_key_id(NULL, 1, kid), FL_ERR_ARG);
    CHECK_EQ_INT(fl_key_id(vector_key, 0, kid), FL_ERR_ARG);
    CHECK_EQ_INT(fl_key_id(vector_key, vector_key_len, NULL), FL_ERR_ARG);
}

static void vector_offer_is_installed(void) {
    test_ctx c;
    fl_device d = vector_device(&c);
    fl_offer o;
    dirty(&o);
    CHECK_EQ_INT(fl_offer_check(&d, vector_offer, vector_offer_len, at(NOT_BEFORE), &o), FL_OK);
    CHECK_EQ_INT(o.action, FL_OFFER_INSTALL);
    CHECK_EQ_STR(o.detail, "");
    CHECK_EQ_STR(o.release, RELEASE);
    CHECK_EQ_STR(o.component, "firmware");
    CHECK_EQ_STR(o.version, "1.4.3+build.7");
    CHECK_EQ_STR(o.url, VECTOR_URL);
    CHECK_EQ_MEM(o.sha256, vector_sha256, 32);
    CHECK(o.size == 1000);
    CHECK(o.url_expires == at(VECTOR_URL_EXPIRES));
    CHECK(o.wait_until == at(NOT_BEFORE));
    CHECK(!o.rollback);
}

static void every_byte_of_the_manifest_altered_is_rejected(void) {
    test_ctx c;
    fl_device d = vector_device(&c);
    uint8_t m[1024];
    size_t i, kid_from, kid_to, ignored = 0, kid = 0, sig = 0;
    const char *k = strstr(vector_manifest, "\"kid\":\"");
    CHECK(k != NULL);
    if (k == NULL)
        return;
    kid_from = (size_t)(k - vector_manifest);
    kid_to = kid_from + 7 + 64 + 1; /* "kid":" + 64 hex + " */
    for (i = 0; i < vector_manifest_len; i++) {
        fl_offer o;
        memcpy(m, vector_manifest, vector_manifest_len);
        m[i] ^= (uint8_t)(1u << (i % 8));
        dirty(&o);
        CHECK_EQ_INT(check_raw(&d, m, vector_manifest_len, "ES256", vector_sig, at(NOT_BEFORE), &o),
                     FL_OK);
        CHECK(o.action == FL_OFFER_REJECT || o.action == FL_OFFER_IGNORE);
        if (o.action == FL_OFFER_IGNORE) {
            ignored++;
            continue;
        }
        CHECK_EQ_INT(o.result, FL_RESULT_REJECTED_SIGNATURE);
        CHECK(o.release[0] != '\0');
        if (strcmp(o.detail, "kid_mismatch") == 0) {
            kid++;
            if (i < kid_from || i >= kid_to)
                fprintf(stderr, "kid_mismatch for byte %zu, outside kid\n", i);
            CHECK(i >= kid_from && i < kid_to);
        } else {
            sig++;
            CHECK_EQ_STR(o.detail, "signature_invalid");
        }
    }
    printf("  %zu bytes: %zu ignored, %zu kid_mismatch, %zu signature_invalid\n",
           vector_manifest_len, ignored, kid, sig);
    CHECK(kid > 0 && sig > 0 && ignored > 0);
}

static void every_byte_of_the_signature_altered_is_rejected(void) {
    test_ctx c;
    fl_device d = vector_device(&c);
    uint8_t sig[64];
    size_t n = 0, i;
    CHECK_EQ_INT(mbedtls_base64_decode(sig, sizeof sig, &n, (const unsigned char *)vector_sig,
                                       strlen(vector_sig)),
                 0);
    CHECK(n == 64);
    for (i = 0; i < 64; i++) {
        uint8_t altered[64];
        char b64[89];
        fl_offer o;
        memcpy(altered, sig, 64);
        altered[i] ^= (uint8_t)(1u << (i % 8));
        CHECK_EQ_INT(mbedtls_base64_encode((unsigned char *)b64, sizeof b64, &n, altered, 64), 0);
        dirty(&o);
        CHECK_EQ_INT(check_raw(&d, (const uint8_t *)vector_manifest, vector_manifest_len, "ES256",
                               b64, at(NOT_BEFORE), &o),
                     FL_OK);
        check_reject(&o, FL_RESULT_REJECTED_SIGNATURE, "signature_invalid");
    }
    /* the unaltered signature through the same path installs */
    {
        fl_offer o;
        CHECK_EQ_INT(check_raw(&d, (const uint8_t *)vector_manifest, vector_manifest_len, "ES256",
                               vector_sig, at(NOT_BEFORE), &o),
                     FL_OK);
        CHECK_EQ_INT(o.action, FL_OFFER_INSTALL);
    }
}

static void der_signature_is_rejected(void) {
    test_ctx c;
    fl_device d = vector_device(&c);
    fl_offer o;
    dirty(&o);
    CHECK_EQ_INT(check_raw(&d, (const uint8_t *)vector_manifest, vector_manifest_len, "ES256",
                           vector_sig_der, at(NOT_BEFORE), &o),
                 FL_OK);
    check_reject(&o, FL_RESULT_REJECTED_SIGNATURE, "signature_invalid");
}

static void bad_signature_encodings_are_rejected(void) {
    /* Not base64, 63 and 66 bytes, r = s = 0, r and s over the group order, too long to read. */
    static char sigs[7][200];
    test_ctx c;
    fl_device d = vector_device(&c);
    size_t i, n = strlen(vector_sig);
    strcpy(sigs[0], "");
    strcpy(sigs[1], "not base64!");
    memcpy(sigs[2], vector_sig, n - 4); /* the last 4 characters carry 1 byte and the padding */
    sigs[2][n - 4] = '\0';
    memcpy(sigs[3], vector_sig, n - 4);
    strcpy(sigs[3] + n - 4, "AAAA");
    memset(sigs[4], 'A', 86);
    strcpy(sigs[4] + 86, "==");
    memset(sigs[5], '/', 85);
    strcpy(sigs[5] + 85, "w==");
    memset(sigs[6], 'A', 192);
    sigs[6][192] = '\0';
    for (i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
        fl_offer o;
        dirty(&o);
        CHECK_EQ_INT(check_raw(&d, (const uint8_t *)vector_manifest, vector_manifest_len, "ES256",
                               sigs[i], at(NOT_BEFORE), &o),
                     FL_OK);
        check_reject(&o, FL_RESULT_REJECTED_SIGNATURE, "signature_invalid");
    }
}

static void other_update_key_is_kid_mismatch(void) {
    test_ctx c;
    fl_device d = signer_device(&c); /* configured with another key */
    fl_offer o;
    dirty(&o);
    CHECK_EQ_INT(fl_offer_check(&d, vector_offer, vector_offer_len, at(NOT_BEFORE), &o), FL_OK);
    check_reject(&o, FL_RESULT_REJECTED_SIGNATURE, "kid_mismatch");
}

static void kid_of_the_offer_is_not_trusted(void) {
    /* The manifest of test_signer, its signature, but the offer claims the vector kid: the
     * device has the vector key, so the manifest kid decides: kid_mismatch. */
    static char manifest[1024];
    manifest_spec m;
    test_ctx c;
    fl_device d = vector_device(&c);
    fl_offer o;
    char sig[89];
    int ml, ol;
    manifest_default(&m, &test_signer);
    ml = manifest_write(&m, manifest, sizeof manifest);
    CHECK(ml > 0 && signer_sign(&test_signer, (const uint8_t *)manifest, (size_t)ml, sig) == 0);
    ol = offer_write((const uint8_t *)manifest, (size_t)ml, "ES256", VECTOR_KID, sig, VECTOR_URL,
                     VECTOR_URL_EXPIRES, offer_buf, sizeof offer_buf);
    CHECK(ol > 0);
    dirty(&o);
    CHECK_EQ_INT(fl_offer_check(&d, offer_buf, (size_t)ol, at(NOT_BEFORE), &o), FL_OK);
    check_reject(&o, FL_RESULT_REJECTED_SIGNATURE, "kid_mismatch");
    /* A kid in upper case is the same key. */
    {
        char upper[68];
        size_t i;
        for (i = 0; test_signer.kid[i] != '\0'; i++)
            upper[i + 1] = (char)(test_signer.kid[i] >= 'a' && test_signer.kid[i] <= 'f'
                                      ? test_signer.kid[i] - 'a' + 'A'
                                      : test_signer.kid[i]);
        upper[0] = '"';
        upper[i + 1] = '"';
        upper[i + 2] = '\0';
        m.kid = upper;
        d = signer_device(&c);
        check_installs(&m, &d, &o);
    }
}

static void alg_other_than_es256_is_rejected(void) {
    static const char *const algs[] = {"ES384", "es256", "ES256 ", "", "none", NULL};
    test_ctx c;
    fl_device d = vector_device(&c);
    size_t i;
    for (i = 0; i < sizeof algs / sizeof algs[0]; i++) {
        fl_offer o;
        dirty(&o);
        CHECK_EQ_INT(check_raw(&d, (const uint8_t *)vector_manifest, vector_manifest_len, algs[i],
                               vector_sig, at(NOT_BEFORE), &o),
                     FL_OK);
        check_reject(&o, FL_RESULT_REJECTED_SIGNATURE, "signature_invalid");
    }
}

static void signed_manifest_installs(void) {
    manifest_spec m;
    test_ctx c;
    fl_device d = signer_device(&c);
    fl_offer o;
    manifest_default(&m, &test_signer);
    check_installs(&m, &d, &o);
    CHECK_EQ_STR(o.version, "1.4.3");
    CHECK_EQ_STR(o.url, SIGNER_URL);
    CHECK(o.url_expires == at(SIGNER_URL_EXPIRES));
}

static void format_v2_fails(void) {
    manifest_spec m;
    manifest_default(&m, &test_signer);
    m.v = "2";
    check_failed(&m, "format_unknown");
    m.v = "1.0";
    check_failed(&m, "format_unknown");
    m.v = "\"1\"";
    check_failed(&m, "format_unknown");
    m.v = NULL;
    check_failed(&m, "format_unknown");
}

static void other_tenant_fails(void) {
    manifest_spec m;
    manifest_default(&m, &test_signer);
    m.tenant = "\"11111111-2222-4333-8444-555555555556\"";
    check_failed(&m, "tenant_mismatch");
    m.tenant = "\"11111111-2222-4333-8444-55555555555\"";
    check_failed(&m, "tenant_mismatch");
}

static void other_family_fails(void) {
    manifest_spec m;
    manifest_default(&m, &test_signer);
    m.family = "\"66666666-7777-4888-9999-aaaaaaaaaaab\"";
    check_failed(&m, "family_mismatch");
}

static void guids_compare_ignoring_case(void) {
    manifest_spec m;
    test_ctx c;
    fl_device d = signer_device(&c);
    fl_offer o;
    manifest_default(&m, &test_signer);
    m.family = "\"66666666-7777-4888-9999-AAAAAAAAAAAA\"";
    m.release = "\"8C1F2A3B-4C5D-4E6F-8A9B-0C1D2E3F4A5B\"";
    dirty(&o);
    CHECK_EQ_INT(check_signed(&m, &d, at(NOT_BEFORE), NULL, &o), FL_OK);
    CHECK_EQ_INT(o.action, FL_OFFER_INSTALL);
    CHECK_EQ_STR(o.release, "8C1F2A3B-4C5D-4E6F-8A9B-0C1D2E3F4A5B"); /* as written */
    d.tenant = "11111111-2222-4333-8444-555555555555";
    d.family = "66666666-7777-4888-9999-AaAaAaAaAaAa";
    manifest_default(&m, &test_signer);
    check_installs(&m, &d, &o);
}

static void unknown_family_fails_family_unknown(void) {
    manifest_spec m;
    test_ctx c;
    fl_device d = signer_device(&c);
    fl_offer o;
    manifest_default(&m, &test_signer);
    d.family = "";
    dirty(&o);
    CHECK_EQ_INT(check_signed(&m, &d, at(NOT_BEFORE), NULL, &o), FL_OK);
    check_reject(&o, FL_RESULT_FAILED, "family_unknown");
    /* the tenant is checked first */
    m.tenant = "\"11111111-2222-4333-8444-555555555556\"";
    dirty(&o);
    CHECK_EQ_INT(check_signed(&m, &d, at(NOT_BEFORE), NULL, &o), FL_OK);
    check_reject(&o, FL_RESULT_FAILED, "tenant_mismatch");
}

static void none_component_fails_component_mismatch(void) {
    manifest_spec m;
    manifest_default(&m, &test_signer);
    m.component = "\"torizon-os\""; /* known to the device, installation `none` */
    check_failed(&m, "component_mismatch");
    m.component = "\"bootloader\""; /* unknown */
    check_failed(&m, "component_mismatch");
}

static void older_version_fails(void) {
    manifest_spec m;
    manifest_default(&m, &test_signer);
    m.version = "\"1.4.1\"";
    check_failed(&m, "older_version");
    m.version = "\"1.3.9+build.99\"";
    check_failed(&m, "older_version");
}

static void older_version_with_rollback_installs(void) {
    manifest_spec m;
    test_ctx c;
    fl_device d = signer_device(&c);
    fl_offer o;
    manifest_default(&m, &test_signer);
    m.version = "\"1.4.1\"";
    m.rollback = "true";
    check_installs(&m, &d, &o);
    CHECK(o.rollback);
    CHECK_EQ_STR(o.version, "1.4.1");
}

static void same_version_fails_older_version(void) {
    manifest_spec m;
    test_ctx c;
    fl_device d = signer_device(&c);
    fl_offer o;
    manifest_default(&m, &test_signer);
    m.version = "\"1.4.2\"";
    check_failed(&m, "older_version");
    /* installed version unknown: never too old */
    c.installed = NULL;
    check_installs(&m, &d, &o);
}

static void offer_waits_until_not_before(void) {
    manifest_spec m;
    test_ctx c;
    fl_device d = signer_device(&c);
    fl_device dv = vector_device(&c);
    fl_offer o;
    fl_time boot = at("1970-01-01T00:01:00Z"); /* clock not synchronized yet */
    manifest_default(&m, &test_signer);
    dirty(&o);
    CHECK_EQ_INT(check_signed(&m, &d, boot, NULL, &o), FL_OK);
    CHECK_EQ_INT(o.action, FL_OFFER_WAIT);
    CHECK(o.wait_until == at(NOT_BEFORE));
    CHECK_EQ_STR(o.release, RELEASE);
    CHECK_EQ_STR(o.detail, "");
    CHECK_EQ_STR(o.component, "firmware");
    CHECK_EQ_STR(o.url, SIGNER_URL);
    CHECK(o.size == 1000);

    dirty(&o);
    CHECK_EQ_INT(fl_offer_check(&dv, vector_offer, vector_offer_len, boot, &o), FL_OK);
    CHECK_EQ_INT(o.action, FL_OFFER_WAIT);
    CHECK(o.wait_until == at(NOT_BEFORE));

    /* one second before: WAIT; at notBefore: INSTALL */
    dirty(&o);
    CHECK_EQ_INT(check_signed(&m, &d, at(NOT_BEFORE) - 1, NULL, &o), FL_OK);
    CHECK_EQ_INT(o.action, FL_OFFER_WAIT);
    check_installs(&m, &d, &o);

    /* a notBefore with an offset */
    m.not_before = "\"2027-03-25T01:00:00+01:00\"";
    dirty(&o);
    CHECK_EQ_INT(check_signed(&m, &d, boot, NULL, &o), FL_OK);
    CHECK_EQ_INT(o.action, FL_OFFER_WAIT);
    CHECK(o.wait_until == at(NOT_BEFORE));

    /* WAIT only after every other check: an offer refused for another reason is refused */
    manifest_default(&m, &test_signer);
    m.version = "\"1.4.1\"";
    dirty(&o);
    CHECK_EQ_INT(check_signed(&m, &d, boot, NULL, &o), FL_OK);
    check_reject(&o, FL_RESULT_FAILED, "older_version");
}

/* A string of n copies of c, quoted, in buf. */
static const char *quoted(char *buf, char c, size_t n) {
    buf[0] = '"';
    memset(buf + 1, c, n);
    buf[n + 1] = '"';
    buf[n + 2] = '\0';
    return buf;
}

/* An `"pad":"xxx"` field that brings the manifest m (without extra) to exactly total bytes. */
static const char *pad_to(manifest_spec *m, char *buf, size_t total) {
    static char tmp[8192];
    int base;
    size_t n;
    m->extra = NULL;
    base = manifest_write(m, tmp, sizeof tmp);
    n = total - (size_t)base - 9; /* ,"pad":" and " */
    memcpy(buf, "\"pad\":", 6);
    quoted(buf + 6, 'x', n);
    return buf;
}

static void offer_with_oversized_fields_fails_cleanly(void) {
    static char big[4096], url[2100], extra[4096];
    manifest_spec m;
    test_ctx c;
    fl_device d = signer_device(&c);
    fl_offer o;

    /* version of 200 chars, and the longest that fits (64) */
    manifest_default(&m, &test_signer);
    m.version = quoted(big, '7', 200);
    check_failed(&m, "format_unknown");
    m.version = quoted(big, '7', 65);
    check_failed(&m, "format_unknown");
    m.version = quoted(big, '7', 64);
    check_installs(&m, &d, &o);
    CHECK(strlen(o.version) == 64);

    /* component, tenant, family too long */
    manifest_default(&m, &test_signer);
    m.component = quoted(big, 'c', 65);
    check_failed(&m, "format_unknown");
    manifest_default(&m, &test_signer);
    m.tenant = quoted(big, '1', 100);
    check_failed(&m, "format_unknown");
    manifest_default(&m, &test_signer);
    m.family = quoted(big, '6', 37);
    check_failed(&m, "format_unknown");

    /* url of 2000 chars; the longest that fits (1024) */
    manifest_default(&m, &test_signer);
    memcpy(url, "https://", 8);
    memset(url + 8, 'u', 2000 - 8);
    url[2000] = '\0';
    dirty(&o);
    CHECK_EQ_INT(check_signed(&m, &d, at(NOT_BEFORE), url, &o), FL_OK);
    check_reject(&o, FL_RESULT_FAILED, "format_unknown");
    url[1025] = '\0';
    dirty(&o);
    CHECK_EQ_INT(check_signed(&m, &d, at(NOT_BEFORE), url, &o), FL_OK);
    check_reject(&o, FL_RESULT_FAILED, "format_unknown");
    url[1024] = '\0';
    dirty(&o);
    CHECK_EQ_INT(check_signed(&m, &d, at(NOT_BEFORE), url, &o), FL_OK);
    CHECK_EQ_INT(o.action, FL_OFFER_INSTALL);
    CHECK(strlen(o.url) == 1024);

    /* kid too long: not the key's */
    manifest_default(&m, &test_signer);
    m.kid = quoted(big, 'a', 200);
    dirty(&o);
    CHECK_EQ_INT(check_signed(&m, &d, at(NOT_BEFORE), NULL, &o), FL_OK);
    check_reject(&o, FL_RESULT_REJECTED_SIGNATURE, "kid_mismatch");

    /* manifest of 3000 bytes: IGNORE; of 2048 bytes: installs; 2049: IGNORE */
    manifest_default(&m, &test_signer);
    m.extra = pad_to(&m, extra, 3000);
    dirty(&o);
    CHECK_EQ_INT(check_signed(&m, &d, at(NOT_BEFORE), NULL, &o), FL_OK);
    check_ignore(&o);
    m.extra = pad_to(&m, extra, 2049);
    dirty(&o);
    CHECK_EQ_INT(check_signed(&m, &d, at(NOT_BEFORE), NULL, &o), FL_OK);
    check_ignore(&o);
    m.extra = pad_to(&m, extra, 2048);
    check_installs(&m, &d, &o);

    /* nested 5 levels: the manifest is refused as a whole, release unreadable: IGNORE */
    manifest_default(&m, &test_signer);
    m.extra = "\"x\":{\"a\":{\"b\":{\"c\":{}}}}";
    dirty(&o);
    CHECK_EQ_INT(check_signed(&m, &d, at(NOT_BEFORE), NULL, &o), FL_OK);
    check_ignore(&o);
    /* nested 4 levels where a string is expected: release readable, format_unknown */
    manifest_default(&m, &test_signer);
    m.version = "{\"a\":{\"b\":{}}}";
    check_failed(&m, "format_unknown");
    /* nested 4 levels in an extra field: allowed */
    manifest_default(&m, &test_signer);
    m.extra = "\"x\":{\"a\":{\"b\":[1,2]}}";
    check_installs(&m, &d, &o);
}

static void bad_fields_fail_format_unknown(void) {
    static const struct {
        int field;
        const char *value;
    } cases[] = {
        {0, "\"C344861C7DD2B9A3BFAA0F5F97B8155553CFE3C8D8128E43EEF4511AB795372B\""},
        {0, "\"c344861c7dd2b9a3bfaa0f5f97b8155553cfe3c8d8128e43eef4511ab795372\""},
        {0, "\"c344861c7dd2b9a3bfaa0f5f97b8155553cfe3c8d8128e43eef4511ab795372bb\""},
        {0, "\"g344861c7dd2b9a3bfaa0f5f97b8155553cfe3c8d8128e43eef4511ab795372b\""},
        {0, "123"},
        {0, NULL},
        {1, "0"},
        {1, "-1"},
        {1, "268435457"},
        {1, "\"1000\""},
        {1, "1000.0"},
        {1, "99999999999999999999"},
        {1, NULL},
        {2, "\"2027-03-25\""},
        {2, "\"2027-02-30T00:00:00Z\""},
        {2, "1806000000"},
        {2, NULL},
        {3, "\"false\""},
        {3, "0"},
        {3, "null"},
        {3, NULL},
        {4, "\"\""},
        {4, "7"},
        {4, NULL},
        {5, "\"\""},
        {5, "[\"firmware\"]"},
        {5, NULL},
        {6, "7"},
        {6, NULL},
        {7, "null"},
        {7, NULL},
    };
    size_t i;
    for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        manifest_spec m;
        const char **f[] = {&m.sha256,  &m.size,      &m.not_before, &m.rollback,
                            &m.version, &m.component, &m.tenant,     &m.family};
        manifest_default(&m, &test_signer);
        *f[cases[i].field] = cases[i].value;
        check_failed(&m, "format_unknown");
    }
}

static void bad_offer_fields_fail_format_unknown(void) {
    static const char *const urls[] = {"http://app.example/x", "ftp://x", "HTTPS://x", "",
                                       "https:/"};
    static char manifest[1024];
    manifest_spec m;
    test_ctx c;
    fl_device d = signer_device(&c);
    fl_offer o;
    char sig[89];
    int ml, ol;
    size_t i;
    manifest_default(&m, &test_signer);
    for (i = 0; i < sizeof urls / sizeof urls[0]; i++) {
        dirty(&o);
        CHECK_EQ_INT(check_signed(&m, &d, at(NOT_BEFORE), urls[i], &o), FL_OK);
        check_reject(&o, FL_RESULT_FAILED, "format_unknown");
    }
    ml = manifest_write(&m, manifest, sizeof manifest);
    CHECK(ml > 0 && signer_sign(&test_signer, (const uint8_t *)manifest, (size_t)ml, sig) == 0);
    ol = offer_write((const uint8_t *)manifest, (size_t)ml, "ES256", test_signer.kid, sig,
                     SIGNER_URL, "2027-03-25 09:00", offer_buf, sizeof offer_buf);
    CHECK(ol > 0);
    dirty(&o);
    CHECK_EQ_INT(fl_offer_check(&d, offer_buf, (size_t)ol, at(NOT_BEFORE), &o), FL_OK);
    check_reject(&o, FL_RESULT_FAILED, "format_unknown");
    /* the boundary of size, 256 MB, is allowed */
    m.size = "268435456";
    check_installs(&m, &d, &o);
    CHECK(o.size == 268435456u);
}

static void unreadable_offers_are_ignored(void) {
    static const char *const offers[] = {
        "",
        "not json",
        "[1,2]",
        "{\"alg\":\"ES256\"}",
        "{\"manifest\":\"!!!\",\"sig\":\"\",\"url\":\"https://x\",\"urlExpires\":\"x\"}",
        /* "{}" in base64 */
        "{\"manifest\":\"e30=\",\"sig\":\"\",\"url\":\"https://x\",\"urlExpires\":\"x\"}",
        /* {"release":"x"} */
        "{\"manifest\":\"eyJyZWxlYXNlIjoieCJ9\",\"sig\":\"\",\"url\":\"https://x\","
        "\"urlExpires\":\"x\"}",
        /* not JSON: "release" */
        "{\"manifest\":\"InJlbGVhc2Ui\",\"sig\":\"\",\"url\":\"https://x\",\"urlExpires\":\"x\"}",
    };
    test_ctx c;
    fl_device d = vector_device(&c);
    size_t i;
    for (i = 0; i < sizeof offers / sizeof offers[0]; i++) {
        fl_offer o;
        dirty(&o);
        CHECK_EQ_INT(fl_offer_check(&d, offers[i], strlen(offers[i]), at(NOT_BEFORE), &o), FL_OK);
        check_ignore(&o);
    }
    /* the vector manifest with one of manifest, sig, url, urlExpires missing or not a string */
    {
        static const char *const keys[] = {"\"sig\"", "\"url\"", "\"urlExpires\""};
        for (i = 0; i < 3; i++) {
            static char text[2048];
            fl_offer o;
            char *p;
            memcpy(text, vector_offer, vector_offer_len + 1);
            p = strstr(text, keys[i]);
            CHECK(p != NULL);
            if (p == NULL)
                continue;
            p[1] = 'X'; /* renamed: missing */
            dirty(&o);
            CHECK_EQ_INT(fl_offer_check(&d, text, vector_offer_len, at(NOT_BEFORE), &o), FL_OK);
            check_ignore(&o);
        }
    }
    /* release not a GUID, release missing */
    {
        manifest_spec m;
        fl_device ds = signer_device(&c);
        fl_offer o;
        manifest_default(&m, &test_signer);
        m.release = "\"8c1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5\"";
        dirty(&o);
        CHECK_EQ_INT(check_signed(&m, &ds, at(NOT_BEFORE), NULL, &o), FL_OK);
        check_ignore(&o);
        m.release = "\"8c1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5bb\"";
        dirty(&o);
        CHECK_EQ_INT(check_signed(&m, &ds, at(NOT_BEFORE), NULL, &o), FL_OK);
        check_ignore(&o);
        m.release = "\"8c1f2a3b+4c5d-4e6f-8a9b-0c1d2e3f4a5b\"";
        dirty(&o);
        CHECK_EQ_INT(check_signed(&m, &ds, at(NOT_BEFORE), NULL, &o), FL_OK);
        check_ignore(&o);
        m.release = NULL;
        dirty(&o);
        CHECK_EQ_INT(check_signed(&m, &ds, at(NOT_BEFORE), NULL, &o), FL_OK);
        check_ignore(&o);
    }
}

static void invalid_arguments(void) {
    static char manifest[1024];
    static const uint8_t not_a_key[] = "not a key";
    manifest_spec m;
    test_ctx c;
    fl_device d = vector_device(&c), bad;
    fl_offer o;
    char kid[65];
    int ml, ol;
    CHECK_EQ_INT(fl_offer_check(NULL, vector_offer, vector_offer_len, 0, &o), FL_ERR_ARG);
    CHECK_EQ_INT(fl_offer_check(&d, vector_offer, vector_offer_len, 0, NULL), FL_ERR_ARG);
    CHECK_EQ_INT(fl_offer_check(&d, NULL, 1, 0, &o), FL_ERR_ARG);
    bad = d;
    bad.installable = NULL;
    CHECK_EQ_INT(fl_offer_check(&bad, vector_offer, vector_offer_len, 0, &o), FL_ERR_ARG);
    bad = d;
    bad.installed_version = NULL;
    CHECK_EQ_INT(fl_offer_check(&bad, vector_offer, vector_offer_len, 0, &o), FL_ERR_ARG);
    bad = d;
    bad.tenant = NULL;
    CHECK_EQ_INT(fl_offer_check(&bad, vector_offer, vector_offer_len, 0, &o), FL_ERR_ARG);
    bad = d;
    bad.family = NULL;
    CHECK_EQ_INT(fl_offer_check(&bad, vector_offer, vector_offer_len, 0, &o), FL_ERR_ARG);
    bad = d;
    bad.update_key_der = NULL;
    CHECK_EQ_INT(fl_offer_check(&bad, vector_offer, vector_offer_len, 0, &o), FL_ERR_ARG);
    bad = d;
    bad.update_key_der_len = 0;
    CHECK_EQ_INT(fl_offer_check(&bad, vector_offer, vector_offer_len, 0, &o), FL_ERR_ARG);

    /* A configured key that is not a P-256 public key, with a manifest naming its kid: an
     * error of the device, not a decision. */
    bad = d;
    bad.update_key_der = not_a_key;
    bad.update_key_der_len = sizeof not_a_key - 1;
    CHECK_EQ_INT(fl_key_id(not_a_key, sizeof not_a_key - 1, kid), FL_OK);
    manifest_default(&m, &test_signer);
    snprintf(m.kid_json, sizeof m.kid_json, "\"%s\"", kid);
    ml = manifest_write(&m, manifest, sizeof manifest);
    CHECK(ml > 0);
    ol = signer_offer(&test_signer, manifest, (size_t)ml, NULL, offer_buf, sizeof offer_buf);
    CHECK(ol > 0);
    dirty(&o);
    CHECK_EQ_INT(fl_offer_check(&bad, offer_buf, (size_t)ol, at(NOT_BEFORE), &o), FL_ERR_ARG);
    check_ignore(&o);
}

static void repeated_checks_do_not_leak_keys(void) {
    mbedtls_psa_stats_t before, after;
    test_ctx c;
    fl_device d = vector_device(&c);
    int i, installed = 0;
    mbedtls_psa_get_stats(&before);
    for (i = 0; i < 1000; i++) {
        fl_offer o;
        if (fl_offer_check(&d, vector_offer, vector_offer_len, at(NOT_BEFORE), &o) == FL_OK &&
            o.action == FL_OFFER_INSTALL)
            installed++;
    }
    mbedtls_psa_get_stats(&after);
    CHECK_EQ_INT(installed, 1000);
    CHECK_EQ_INT(after.volatile_slots, before.volatile_slots);
    CHECK_EQ_INT(after.locked_slots, 0);
}

int main(void) {
    if (fl_init() != FL_OK || !load_vector() || signer_init(&test_signer) != 0) {
        fprintf(stderr, "setup failed\n");
        return 1;
    }
    RUN(key_id_of_the_vector);
    RUN(vector_offer_is_installed);
    RUN(every_byte_of_the_manifest_altered_is_rejected);
    RUN(every_byte_of_the_signature_altered_is_rejected);
    RUN(der_signature_is_rejected);
    RUN(bad_signature_encodings_are_rejected);
    RUN(other_update_key_is_kid_mismatch);
    RUN(kid_of_the_offer_is_not_trusted);
    RUN(alg_other_than_es256_is_rejected);
    RUN(signed_manifest_installs);
    RUN(format_v2_fails);
    RUN(other_tenant_fails);
    RUN(other_family_fails);
    RUN(guids_compare_ignoring_case);
    RUN(unknown_family_fails_family_unknown);
    RUN(none_component_fails_component_mismatch);
    RUN(older_version_fails);
    RUN(older_version_with_rollback_installs);
    RUN(same_version_fails_older_version);
    RUN(offer_waits_until_not_before);
    RUN(offer_with_oversized_fields_fails_cleanly);
    RUN(bad_fields_fail_format_unknown);
    RUN(bad_offer_fields_fail_format_unknown);
    RUN(unreadable_offers_are_ignored);
    RUN(invalid_arguments);
    RUN(repeated_checks_do_not_leak_keys);
    signer_free(&test_signer);
    return CHECK_RESULT;
}
