/* SPDX-License-Identifier: Apache-2.0 */
#include "firmline/fl_messages.h"

#include "firmline/fl_json.h"

#include <mbedtls/base64.h>
#include <string.h>

#define PROOF_LEN 64
#define PROOF_B64_LEN 88 /* base64 of 64 bytes, with padding */
#define GUID_LEN 36

/* A required text of 1..FL_TEXT_MAX bytes. */
static bool text_ok(const char *s) {
    size_t n;
    if (s == NULL)
        return false;
    n = strlen(s);
    return n >= 1 && n <= FL_TEXT_MAX;
}

static bool is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static bool is_guid(const char *s) {
    size_t i;
    if (strlen(s) != GUID_LEN)
        return false;
    for (i = 0; i < GUID_LEN; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (s[i] != '-')
                return false;
        } else if (!is_hex(s[i])) {
            return false;
        }
    }
    return true;
}

/* Ends the message. A message that exceeds the contract limit is FL_ERR_ARG (also when the writer
 * ran out of space with a buffer that held the limit: the text is then over it); a buffer that is
 * too small for a message within the limit is FL_ERR_SPACE. Any error clears out. */
static int finish(fl_jw *w, char *out, size_t cap, size_t limit) {
    int r = fl_jw_end(w);
    if (r == FL_ERR_SPACE && cap > limit)
        r = FL_ERR_ARG;
    else if (r > 0 && (size_t)r > limit)
        r = FL_ERR_ARG;
    if (r < 0 && out != NULL && cap > 0)
        out[0] = '\0';
    return r;
}

static int fail(char *out, size_t cap, int err) {
    if (out != NULL && cap > 0)
        out[0] = '\0';
    return err;
}

int fl_status_build(char *out, size_t cap, const char *fw, const fl_component_version *components,
                    size_t n, fl_time ts, int offset_minutes, int64_t uptime) {
    fl_jw w;
    char iso[26];
    size_t i, j;
    if (out == NULL || (n > 0 && components == NULL) || n > FL_STATUS_MAX_COMPONENTS ||
        (fw == NULL && n == 0) || (fw != NULL && !text_ok(fw)))
        return fail(out, cap, FL_ERR_ARG);
    for (i = 0; i < n; i++) {
        if (!text_ok(components[i].code) || !text_ok(components[i].version))
            return fail(out, cap, FL_ERR_ARG);
        for (j = 0; j < i; j++)
            if (strcmp(components[i].code, components[j].code) == 0)
                return fail(out, cap, FL_ERR_ARG);
    }
    if (fl_time_format(ts, offset_minutes, iso) != FL_OK)
        return fail(out, cap, FL_ERR_ARG);

    fl_jw_begin(&w, out, cap);
    if (fw != NULL)
        fl_jw_string(&w, "fw", fw);
    if (n > 0) {
        fl_jw_object_begin(&w, "components");
        for (i = 0; i < n; i++)
            fl_jw_string(&w, components[i].code, components[i].version);
        fl_jw_object_end(&w);
    }
    fl_jw_string(&w, "ts", iso);
    if (uptime >= 0)
        fl_jw_int(&w, "uptime", uptime);
    return finish(&w, out, cap, FL_STATUS_MAX);
}

int fl_result_build(char *out, size_t cap, const char *release, fl_result result, const char *fw,
                    const char *detail) {
    fl_jw w;
    const char *name;
    switch (result) {
    case FL_RESULT_INSTALLED:
        name = "installed";
        break;
    case FL_RESULT_FAILED:
        name = "failed";
        break;
    case FL_RESULT_REJECTED_SIGNATURE:
        name = "rejected_signature";
        break;
    default:
        return fail(out, cap, FL_ERR_ARG);
    }
    if (out == NULL || release == NULL || release[0] == '\0' || (fw != NULL && !text_ok(fw)))
        return fail(out, cap, FL_ERR_ARG);
    if (detail != NULL && (detail[0] == '\0' || strlen(detail) > FL_TEXT_MAX))
        detail = NULL; /* dropped, the result is kept */

    fl_jw_begin(&w, out, cap);
    fl_jw_string(&w, "release", release);
    fl_jw_string(&w, "result", name);
    if (fw != NULL)
        fl_jw_string(&w, "fw", fw);
    if (detail != NULL)
        fl_jw_string(&w, "detail", detail);
    return finish(&w, out, cap, FL_RESULT_MAX);
}

int fl_registration_body(char *out, size_t cap, const char *token, const char *serial,
                         const char *csr_pem) {
    fl_jw w;
    if (out == NULL || token == NULL || token[0] == '\0' || serial == NULL || serial[0] == '\0' ||
        csr_pem == NULL || csr_pem[0] == '\0')
        return fail(out, cap, FL_ERR_ARG);
    fl_jw_begin(&w, out, cap);
    fl_jw_string(&w, "token", token);
    fl_jw_string(&w, "serialNumber", serial);
    fl_jw_string(&w, "csr", csr_pem);
    return finish(&w, out, cap, SIZE_MAX);
}

int fl_renewal_body(char *out, size_t cap, const char *certificate_pem, const char *csr_pem,
                    const uint8_t proof_p1363[64]) {
    fl_jw w;
    char proof[PROOF_B64_LEN + 1];
    size_t olen = 0;
    if (out == NULL || certificate_pem == NULL || certificate_pem[0] == '\0' || csr_pem == NULL ||
        csr_pem[0] == '\0' || proof_p1363 == NULL)
        return fail(out, cap, FL_ERR_ARG);
    if (mbedtls_base64_encode((unsigned char *)proof, sizeof proof, &olen, proof_p1363,
                              PROOF_LEN) != 0 ||
        olen != PROOF_B64_LEN)
        return fail(out, cap, FL_ERR_CRYPTO);
    fl_jw_begin(&w, out, cap);
    fl_jw_string(&w, "certificate", certificate_pem);
    fl_jw_string(&w, "csr", csr_pem);
    fl_jw_string(&w, "proof", proof);
    return finish(&w, out, cap, SIZE_MAX);
}

static bool has_root_key(const fl_json *j, const char *key) {
    size_t n = strlen(key);
    int i = 1;
    while (i + 1 < j->count) {
        const jsmntok_t *k = &j->tok[i];
        if ((size_t)(k->end - k->start) == n && memcmp(j->js + k->start, key, n) == 0)
            return true;
        i = fl_json_next(j, i + 1);
    }
    return false;
}

/* A required, non-empty string member copied into a fixed field. */
static int required_string(const fl_json *j, const char *key, char *dst, size_t cap) {
    int r = fl_json_string(j, key, dst, cap);
    if (r == FL_OK && dst[0] == '\0')
        return FL_ERR_FORMAT;
    return r;
}

/* The optional familyId: absent is "", present must be a GUID string. */
static int family_id(const fl_json *j, char out[37]) {
    int r = fl_json_string(j, "familyId", out, 37);
    if (r != FL_OK)
        out[0] = 0;
    if (r == FL_OK)
        return is_guid(out) ? FL_OK : FL_ERR_FORMAT;
    if (r == FL_ERR_SPACE)
        return FL_ERR_FORMAT;                                   /* longer than a GUID */
    return has_root_key(j, "familyId") ? FL_ERR_FORMAT : FL_OK; /* present, not a string */
}

int fl_provisioned_parse(const char *json, size_t len, char *pem_buf, size_t pem_cap,
                         fl_provisioned *out) {
    fl_json j;
    int r;
    size_t used;
    if (out == NULL)
        return FL_ERR_ARG;
    memset(out, 0, sizeof *out);
    if (pem_buf == NULL || pem_cap == 0 || json == NULL)
        return FL_ERR_ARG;
    pem_buf[0] = '\0';

    r = fl_json_parse(&j, json, len);
    if (r == FL_OK)
        r = required_string(&j, "deviceId", out->device_id, sizeof out->device_id);
    if (r == FL_OK)
        r = family_id(&j, out->family_id);
    if (r == FL_OK)
        r = required_string(&j, "clientId", out->client_id, sizeof out->client_id);
    if (r == FL_OK)
        r = required_string(&j, "topicRoot", out->topic_root, sizeof out->topic_root);
    if (r == FL_OK)
        r = required_string(&j, "otaOfferTopic", out->ota_offer_topic, sizeof out->ota_offer_topic);
    if (r == FL_OK)
        r = required_string(&j, "certificate", pem_buf, pem_cap);
    if (r == FL_OK) {
        used = strlen(pem_buf) + 1;
        out->certificate = pem_buf;
        r = required_string(&j, "chain", pem_buf + used, pem_cap - used);
        if (r == FL_OK)
            out->chain = pem_buf + used;
    }
    if (r != FL_OK) {
        memset(out, 0, sizeof *out);
        pem_buf[0] = '\0';
    }
    return r;
}

int fl_problem_code(const char *json, size_t len, char out[64]) {
    fl_json j;
    int r;
    if (out == NULL)
        return FL_ERR_ARG;
    out[0] = '\0';
    if (json == NULL)
        return FL_ERR_ARG;
    r = fl_json_parse(&j, json, len);
    if (r == FL_OK)
        r = fl_json_string(&j, "code", out, 64);
    if (r != FL_OK)
        out[0] = '\0';
    return r;
}
