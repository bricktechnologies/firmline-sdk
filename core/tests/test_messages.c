/* SPDX-License-Identifier: Apache-2.0 */
#include "check.h"
#include "firmline/fl_messages.h"

#include <stdio.h>
#include <stdlib.h>

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

static void test_status_matches_the_guide_example(void) {
    char expected[512], b[4096];
    size_t n = read_file(FL_VECTOR_DIR "/device/status.json", expected, sizeof expected);
    int r = fl_status_build(b, sizeof b, "1.4.3+build.7", NULL, 0, 1804665600, 0, 86400);
    CHECK(n > 0);
    CHECK_EQ_INT(r, (int)n);
    CHECK_EQ_STR(b, expected);
}

static void test_result_matches_the_guide_example(void) {
    char expected[512], b[1024];
    size_t n = read_file(FL_VECTOR_DIR "/device/result.json", expected, sizeof expected);
    int r = fl_result_build(b, sizeof b, "8c1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b",
                            FL_RESULT_INSTALLED, "1.4.3+build.7", NULL);
    CHECK(n > 0);
    CHECK_EQ_INT(r, (int)n);
    CHECK_EQ_STR(b, expected);
}

static void test_status_with_components_and_offset(void) {
    char b[4096];
    fl_component_version c[2] = {{"main", "1.4.3"}, {"modem", "2.0.1"}};
    int r = fl_status_build(b, sizeof b, NULL, c, 2, 1804665600, 60, -1);
    CHECK(r > 0);
    CHECK_EQ_STR(b, "{\"components\":{\"main\":\"1.4.3\",\"modem\":\"2.0.1\"},"
                    "\"ts\":\"2027-03-10T09:00:00+01:00\"}");
}

static void fill_components(fl_component_version *c, char code[][8], size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        code[i][0] = 'c';
        code[i][1] = (char)('a' + i);
        code[i][2] = 0;
        c[i].code = code[i];
        c[i].version = "1";
    }
}

static void test_status_limits(void) {
    char b[4096], code[17][8], long65[66];
    fl_component_version c[17];
    fill_components(c, code, 17);
    CHECK(fl_status_build(b, sizeof b, NULL, c, 16, 0, 0, 0) > 0);
    memset(long65, 'a', 65);
    long65[65] = '\0';
    CHECK_EQ_INT(fl_status_build(b, sizeof b, long65, NULL, 0, 0, 0, 0), FL_ERR_ARG);
    CHECK_EQ_STR(b, "");
    CHECK(fl_status_build(b, sizeof b, long65 + 1, NULL, 0, 0, 0, 0) > 0); /* 64 bytes */
    CHECK_EQ_INT(fl_status_build(b, sizeof b, "", NULL, 0, 0, 0, 0), FL_ERR_ARG);
    CHECK_EQ_INT(fl_status_build(b, sizeof b, NULL, NULL, 0, 0, 0, 0), FL_ERR_ARG);
    c[0].version = long65;
    CHECK_EQ_INT(fl_status_build(b, sizeof b, NULL, c, 1, 0, 0, 0), FL_ERR_ARG);
    c[0].version = "";
    CHECK_EQ_INT(fl_status_build(b, sizeof b, NULL, c, 1, 0, 0, 0), FL_ERR_ARG);
    c[0].version = "1";
    c[1].code = c[0].code; /* repeated code */
    CHECK_EQ_INT(fl_status_build(b, sizeof b, NULL, c, 2, 0, 0, 0), FL_ERR_ARG);
    CHECK_EQ_INT(fl_status_build(b, sizeof b, "1", NULL, 0, 0, 1440, 0), FL_ERR_ARG);
    CHECK_EQ_INT(fl_status_build(b, 10, "1", NULL, 0, 0, 0, 0), FL_ERR_SPACE);
    CHECK_EQ_STR(b, "");
}

static void test_status_refuses_17_components(void) {
    char b[4096], code[17][8];
    fl_component_version c[17];
    fill_components(c, code, 17);
    CHECK_EQ_INT(fl_status_build(b, sizeof b, "1", c, 17, 0, 0, 0), FL_ERR_ARG);
    CHECK_EQ_STR(b, "");
}

static void test_status_over_4096_bytes(void) {
    /* 16 components of 64+64 quotes: the escaping pushes the message over 4096 bytes. */
    char big[8192], codes[16][65], vers[65];
    fl_component_version c[16];
    size_t i;
    memset(vers, '"', 64);
    vers[64] = '\0';
    for (i = 0; i < 16; i++) {
        memset(codes[i], '"', 64);
        codes[i][62] = (char)('a' + i);
        codes[i][64] = '\0';
        c[i].code = codes[i];
        c[i].version = vers;
    }
    CHECK_EQ_INT(fl_status_build(big, sizeof big, "1", c, 16, 0, 0, 0), FL_ERR_ARG);
    CHECK_EQ_STR(big, "");
}

static void test_result_drops_detail_over_64(void) {
    char b[1024], d65[66], d64[65];
    memset(d65, 'x', 65);
    d65[65] = '\0';
    memcpy(d64, d65, 64);
    d64[64] = '\0';
    CHECK(fl_result_build(b, sizeof b, "r1", FL_RESULT_FAILED, NULL, d65) > 0);
    CHECK_EQ_STR(b, "{\"release\":\"r1\",\"result\":\"failed\"}");
    CHECK(fl_result_build(b, sizeof b, "r1", FL_RESULT_FAILED, NULL, d64) > 0);
    CHECK(strstr(b, "\"detail\":\"xxxxxxxx") != NULL);
    CHECK(fl_result_build(b, sizeof b, "r1", FL_RESULT_FAILED, "2.0", "no_space") > 0);
    CHECK_EQ_STR(
        b, "{\"release\":\"r1\",\"result\":\"failed\",\"fw\":\"2.0\",\"detail\":\"no_space\"}");
}

static void test_result_limits(void) {
    char b[2048], rel[1100];
    memset(rel, 'r', sizeof rel);
    rel[sizeof rel - 1] = '\0';
    CHECK_EQ_INT(fl_result_build(b, sizeof b, rel, FL_RESULT_FAILED, NULL, NULL), FL_ERR_ARG);
    CHECK_EQ_STR(b, "");
    CHECK_EQ_INT(fl_result_build(b, sizeof b, "", FL_RESULT_FAILED, NULL, NULL), FL_ERR_ARG);
    CHECK_EQ_INT(fl_result_build(b, sizeof b, NULL, FL_RESULT_FAILED, NULL, NULL), FL_ERR_ARG);
    CHECK_EQ_INT(fl_result_build(b, sizeof b, "r", (fl_result)7, NULL, NULL), FL_ERR_ARG);
    CHECK_EQ_INT(fl_result_build(b, sizeof b, "r", FL_RESULT_FAILED, "", NULL), FL_ERR_ARG);
    CHECK_EQ_INT(fl_result_build(b, 8, "r", FL_RESULT_FAILED, NULL, NULL), FL_ERR_SPACE);
    CHECK_EQ_INT(fl_result_build(NULL, 8, "r", FL_RESULT_FAILED, NULL, NULL), FL_ERR_ARG);
}

static void test_rejected_signature_is_written_as_such(void) {
    char b[1024];
    CHECK(fl_result_build(b, sizeof b, "r1", FL_RESULT_REJECTED_SIGNATURE, NULL,
                          "signature_invalid") > 0);
    CHECK_EQ_STR(b, "{\"release\":\"r1\",\"result\":\"rejected_signature\","
                    "\"detail\":\"signature_invalid\"}");
}

static void test_registration_body(void) {
    char b[512];
    int r = fl_registration_body(b, sizeof b, "tok", "SN-1", "-----BEGIN\nabc\n-----END");
    CHECK(r > 0);
    CHECK(strncmp(b, "{\"token\":\"tok\",\"serialNumber\":\"SN-1\",\"csr\":\"-----BEGIN", 52) == 0);
    CHECK(strchr(b, '\n') == NULL); /* newlines of the PEM are escaped */
    CHECK_EQ_INT(fl_registration_body(b, sizeof b, "", "SN", "csr"), FL_ERR_ARG);
    CHECK_EQ_INT(fl_registration_body(b, sizeof b, "t", NULL, "csr"), FL_ERR_ARG);
    CHECK_EQ_INT(fl_registration_body(b, 20, "t", "s", "csr"), FL_ERR_SPACE);
    CHECK_EQ_STR(b, "");
}

static void test_renewal_body_has_base64_proof(void) {
    char b[1024];
    uint8_t proof[64];
    const char *p;
    size_t i;
    for (i = 0; i < 64; i++)
        proof[i] = (uint8_t)i;
    CHECK(fl_renewal_body(b, sizeof b, "CERT", "CSR", proof) > 0);
    p = strstr(b, "\"proof\":\"");
    CHECK(p != NULL);
    if (p != NULL) {
        const char *q = p + 9;
        size_t n = 0;
        while (q[n] != '"' && q[n] != '\0')
            n++;
        CHECK_EQ_INT(n, 88);
        CHECK(strncmp(q,
                      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4"
                      "OTo7PD0+Pw==",
                      88) == 0);
    }
    CHECK(strstr(b, "\"certificate\":\"CERT\",\"csr\":\"CSR\"") != NULL);
    CHECK_EQ_INT(fl_renewal_body(b, sizeof b, "CERT", "CSR", NULL), FL_ERR_ARG);
    CHECK_EQ_STR(b, "");
}

#define PROV                                                                                       \
    "{\"deviceId\":\"d-1\",%s\"clientId\":\"brkt-c-1\",\"topicRoot\":\"t/a/d-1\","                 \
    "\"otaOfferTopic\":\"t/a/d-1/ota/offer\","                                                     \
    "\"certificate\":\"-----BEGIN CERTIFICATE-----\\nAAA\\n-----END CERTIFICATE-----\\n\","        \
    "\"chain\":\"-----BEGIN CERTIFICATE-----\\nBBB\\n-----END CERTIFICATE-----\\n\"}"

static void test_provisioned_parses_family_and_pem(void) {
    char json[1024], pem[512];
    fl_provisioned p;
    int len =
        snprintf(json, sizeof json, PROV, "\"familyId\":\"0b9d3c1e-5a7f-4c2d-9e8b-1a2b3c4d5e6f\",");
    CHECK_EQ_INT(fl_provisioned_parse(json, (size_t)len, pem, sizeof pem, &p), FL_OK);
    CHECK_EQ_STR(p.device_id, "d-1");
    CHECK_EQ_STR(p.family_id, "0b9d3c1e-5a7f-4c2d-9e8b-1a2b3c4d5e6f");
    CHECK_EQ_STR(p.client_id, "brkt-c-1");
    CHECK_EQ_STR(p.topic_root, "t/a/d-1");
    CHECK_EQ_STR(p.ota_offer_topic, "t/a/d-1/ota/offer");
    CHECK_EQ_STR(p.certificate, "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n");
    CHECK_EQ_STR(p.chain, "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n");
    CHECK(p.certificate >= pem && p.certificate < pem + sizeof pem);
    CHECK(p.chain >= pem && p.chain < pem + sizeof pem);
}

static void test_provisioned_without_family_id_leaves_it_empty(void) {
    char json[1024], pem[512];
    fl_provisioned p;
    int len = snprintf(json, sizeof json, PROV, "");
    CHECK_EQ_INT(fl_provisioned_parse(json, (size_t)len, pem, sizeof pem, &p), FL_OK);
    CHECK_EQ_STR(p.family_id, "");
    CHECK_EQ_STR(p.device_id, "d-1");
}

static void test_provisioned_rejects(void) {
    char json[1024], pem[512], small[40];
    fl_provisioned p;
    int len = snprintf(json, sizeof json, PROV, "\"familyId\":\"not-a-guid\",");
    CHECK_EQ_INT(fl_provisioned_parse(json, (size_t)len, pem, sizeof pem, &p), FL_ERR_FORMAT);
    CHECK(p.certificate == NULL && p.chain == NULL);
    CHECK_EQ_STR(pem, "");
    len =
        snprintf(json, sizeof json, PROV, "\"familyId\":\"0b9d3c1e-5a7f-4c2d-9e8b-1a2b3c4d5e6g\",");
    CHECK_EQ_INT(fl_provisioned_parse(json, (size_t)len, pem, sizeof pem, &p), FL_ERR_FORMAT);
    len = snprintf(json, sizeof json, PROV, "");
    CHECK_EQ_INT(fl_provisioned_parse(json, (size_t)len, small, sizeof small, &p), FL_ERR_SPACE);
    CHECK_EQ_INT(fl_provisioned_parse(json, (size_t)len, pem, 0, &p), FL_ERR_ARG);
    CHECK_EQ_INT(fl_provisioned_parse(json, (size_t)len, pem, sizeof pem, NULL), FL_ERR_ARG);
    CHECK_EQ_INT(fl_provisioned_parse("{\"deviceId\":\"d\"}", 16, pem, sizeof pem, &p),
                 FL_ERR_FORMAT); /* a missing field */
    CHECK_EQ_INT(fl_provisioned_parse("[]", 2, pem, sizeof pem, &p), FL_ERR_FORMAT);
    len = snprintf(json, sizeof json,
                   "{\"deviceId\":\"%0100d\",\"clientId\":\"c\",\"topicRoot\":\"t\","
                   "\"otaOfferTopic\":\"o\",\"certificate\":\"c\",\"chain\":\"c\"}",
                   1); /* a value too long for its field */
    CHECK_EQ_INT(fl_provisioned_parse(json, (size_t)len, pem, sizeof pem, &p), FL_ERR_SPACE);
    len = snprintf(json, sizeof json,
                   "{\"deviceId\":\"d\",\"clientId\":\"\",\"topicRoot\":\"t\","
                   "\"otaOfferTopic\":\"o\",\"certificate\":\"c\",\"chain\":\"c\"}");
    CHECK_EQ_INT(fl_provisioned_parse(json, (size_t)len, pem, sizeof pem, &p),
                 FL_ERR_FORMAT); /* an empty required value */
}

static void test_problem_code_reads_serial_number_taken(void) {
    char c[64];
    const char *body = "{\"type\":\"https://x/y\",\"title\":\"Conflict\",\"status\":409,"
                       "\"code\":\"serial_number_taken\",\"details\":{\"serial\":\"SN-1\","
                       "\"a\":[1,2]}}";
    CHECK_EQ_INT(fl_problem_code(body, strlen(body), c), FL_OK);
    CHECK_EQ_STR(c, "serial_number_taken");
    CHECK_EQ_INT(fl_problem_code("{\"title\":\"x\"}", 13, c), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_problem_code("{\"code\":5}", 10, c), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_problem_code("not json", 8, c), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_problem_code("[]", 2, c), FL_ERR_FORMAT);
    CHECK_EQ_STR(c, "");
    CHECK_EQ_INT(fl_problem_code(NULL, 0, c), FL_ERR_ARG);
}

static void test_problem_code_length(void) {
    char json[200], c[64];
    int len = snprintf(json, sizeof json, "{\"code\":\"%063d\"}", 7);
    CHECK_EQ_INT(fl_problem_code(json, (size_t)len, c), FL_OK);
    CHECK_EQ_INT(strlen(c), 63);
    len = snprintf(json, sizeof json, "{\"code\":\"%064d\"}", 7);
    CHECK_EQ_INT(fl_problem_code(json, (size_t)len, c), FL_ERR_SPACE);
    CHECK_EQ_STR(c, "");
}

int main(void) {
    RUN(test_status_matches_the_guide_example);
    RUN(test_result_matches_the_guide_example);
    RUN(test_status_with_components_and_offset);
    RUN(test_status_limits);
    RUN(test_status_refuses_17_components);
    RUN(test_status_over_4096_bytes);
    RUN(test_result_drops_detail_over_64);
    RUN(test_result_limits);
    RUN(test_rejected_signature_is_written_as_such);
    RUN(test_registration_body);
    RUN(test_renewal_body_has_base64_proof);
    RUN(test_provisioned_parses_family_and_pem);
    RUN(test_provisioned_without_family_id_leaves_it_empty);
    RUN(test_provisioned_rejects);
    RUN(test_problem_code_reads_serial_number_taken);
    RUN(test_problem_code_length);
    return CHECK_RESULT;
}
