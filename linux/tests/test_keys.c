/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "check.h"
#include "keys.h"
#include "store.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static void make_dir(char path[], size_t size) {
    snprintf(path, size, "/tmp/fa-keys-XXXXXX");
    if (mkdtemp(path) == NULL)
        path[0] = '\0';
}

static EVP_PKEY *read_key(const char *dir, const char *name) {
    char *pem = NULL;
    size_t len = 0;
    if (fa_store_read(dir, name, &pem, &len) != 0)
        return NULL;
    BIO *bio = BIO_new_mem_buf(pem, (int)len);
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    free(pem);
    return key;
}

static int is_p256(EVP_PKEY *key) {
    char group[64] = "";
    size_t n = 0;
    return key != NULL && EVP_PKEY_is_a(key, "EC") &&
           EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof group,
                                          &n) == 1 &&
           strcmp(group, "prime256v1") == 0;
}

static void key_is_p256_pkcs8_and_private(void) {
    umask(022);
    char dir[64];
    make_dir(dir, sizeof dir);
    CHECK_EQ_INT(fa_key_generate(dir, "device.key"), 0);

    char path[128];
    struct stat st;
    snprintf(path, sizeof path, "%s/device.key", dir);
    CHECK_EQ_INT(stat(path, &st), 0);
    CHECK_EQ_INT(st.st_mode & 0777, 0600);

    char *pem = NULL;
    size_t len = 0;
    CHECK_EQ_INT(fa_store_read(dir, "device.key", &pem, &len), 0);
    CHECK(pem != NULL && strncmp(pem, "-----BEGIN PRIVATE KEY-----\n", 28) == 0); /* PKCS#8 */
    free(pem);

    EVP_PKEY *key = read_key(dir, "device.key");
    CHECK(is_p256(key));
    EVP_PKEY_free(key);
}

static void keys_are_new_each_time(void) {
    char dir[64];
    make_dir(dir, sizeof dir);
    CHECK_EQ_INT(fa_key_generate(dir, "a.key"), 0);
    CHECK_EQ_INT(fa_key_generate(dir, "b.key"), 0);
    EVP_PKEY *a = read_key(dir, "a.key"), *b = read_key(dir, "b.key");
    CHECK(a != NULL && b != NULL && EVP_PKEY_eq(a, b) == 0);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    CHECK_EQ_INT(fa_key_generate(dir, "bad/name"), -1);
}

static void csr_is_signed_by_the_key_with_cn_device(void) {
    char dir[64], pem[4096];
    make_dir(dir, sizeof dir);
    CHECK_EQ_INT(fa_key_generate(dir, "device.key"), 0);
    CHECK_EQ_INT(fa_csr_create(dir, "device.key", pem, sizeof pem), 0);
    CHECK(strncmp(pem, "-----BEGIN CERTIFICATE REQUEST-----\n", 36) == 0);

    BIO *bio = BIO_new_mem_buf(pem, -1);
    X509_REQ *req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    BIO_free(bio);
    CHECK(req != NULL);
    if (req == NULL)
        return;
    EVP_PKEY *req_key = X509_REQ_get0_pubkey(req);
    CHECK_EQ_INT(X509_REQ_verify(req, req_key), 1);
    EVP_PKEY *key = read_key(dir, "device.key");
    CHECK_EQ_INT(EVP_PKEY_eq(req_key, key), 1);
    EVP_PKEY_free(key);

    char cn[64] = "";
    X509_NAME_get_text_by_NID(X509_REQ_get_subject_name(req), NID_commonName, cn, sizeof cn);
    CHECK_EQ_STR(cn, "device");
    CHECK_EQ_INT(X509_NAME_entry_count(X509_REQ_get_subject_name(req)), 1);
    X509_REQ_free(req);
}

static void csr_needs_room_and_a_key(void) {
    char dir[64], pem[4096];
    make_dir(dir, sizeof dir);
    CHECK_EQ_INT(fa_csr_create(dir, "missing.key", pem, sizeof pem), -1);
    CHECK_EQ_INT(pem[0], 0);
    CHECK_EQ_INT(fa_store_write(dir, "junk.key", "not a key\n", 10, 0600), 0);
    CHECK_EQ_INT(fa_csr_create(dir, "junk.key", pem, sizeof pem), -1);

    CHECK_EQ_INT(fa_key_generate(dir, "device.key"), 0);
    char small[100];
    CHECK_EQ_INT(fa_csr_create(dir, "device.key", small, sizeof small), -1);
    CHECK_EQ_INT(small[0], 0);
}

static void key_of_another_curve_is_refused(void) {
    char dir[64], pem[4096];
    make_dir(dir, sizeof dir);
    EVP_PKEY *other = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384");
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PKCS8PrivateKey(bio, other, NULL, NULL, 0, NULL, NULL);
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    CHECK_EQ_INT(fa_store_write(dir, "p384.key", data, (size_t)len, 0600), 0);
    BIO_free(bio);
    EVP_PKEY_free(other);
    CHECK_EQ_INT(fa_csr_create(dir, "p384.key", pem, sizeof pem), -1);
    uint8_t hash[32] = {0}, sig[64];
    CHECK_EQ_INT(fa_sign_sha256(dir, "p384.key", hash, sig), -1);
}

/* The public key of a new key of the curve as a SubjectPublicKeyInfo PEM file dir/name; the key is
 * returned (the caller frees it). */
static EVP_PKEY *write_public(const char *dir, const char *name, const char *curve) {
    char path[128];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", curve);
    FILE *f = fopen(path, "w");
    if (f != NULL) {
        PEM_write_PUBKEY(f, key);
        fclose(f);
    }
    return key;
}

static void update_key_is_p256_public_key_der(void) {
    char dir[64], path[128];
    make_dir(dir, sizeof dir);
    EVP_PKEY *key = write_public(dir, "update.pem", "P-256");
    unsigned char *expected = NULL;
    int expected_len = i2d_PUBKEY(key, &expected);
    uint8_t der[128];
    size_t len = 0;
    snprintf(path, sizeof path, "%s/update.pem", dir);
    CHECK_EQ_INT(fa_update_key_load(path, der, sizeof der, &len), 0);
    CHECK_EQ_INT(len, 91); /* P-256 SubjectPublicKeyInfo */
    CHECK_EQ_INT(len, expected_len);
    CHECK(expected != NULL && memcmp(der, expected, len) == 0);
    CHECK_EQ_INT(fa_update_key_load(path, der, 90, &len), -1); /* does not fit */
    OPENSSL_free(expected);
    EVP_PKEY_free(key);
}

static void update_key_of_another_kind_is_refused(void) {
    char dir[64], path[128];
    make_dir(dir, sizeof dir);
    EVP_PKEY_free(write_public(dir, "p384.pem", "P-384"));
    CHECK_EQ_INT(fa_key_generate(dir, "private.pem"), 0); /* a private key, not a public one */
    CHECK_EQ_INT(fa_store_write(dir, "junk.pem", "not a key\n", 10, 0644), 0);
    const char *names[] = {"p384.pem", "private.pem", "junk.pem", "missing.pem"};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        uint8_t der[128];
        size_t len = 7;
        snprintf(path, sizeof path, "%s/%s", dir, names[i]);
        CHECK_EQ_INT(fa_update_key_load(path, der, sizeof der, &len), -1);
        CHECK_EQ_INT(len, 0);
    }
}

/* r||s back to DER, then verified with the public key over the same SHA-256. */
static int verifies(EVP_PKEY *key, const uint8_t hash[32], const uint8_t sig[64]) {
    ECDSA_SIG *s = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(sig, 32, NULL), *ss = BN_bin2bn(sig + 32, 32, NULL);
    ECDSA_SIG_set0(s, r, ss);
    unsigned char *der = NULL;
    int der_len = i2d_ECDSA_SIG(s, &der);
    ECDSA_SIG_free(s);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    int ok = ctx != NULL && der_len > 0 && EVP_PKEY_verify_init(ctx) == 1 &&
             EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) == 1 &&
             EVP_PKEY_verify(ctx, der, (size_t)der_len, hash, 32) == 1;
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(der);
    return ok;
}

static void signature_is_r_and_s_over_the_hash(void) {
    char dir[64];
    make_dir(dir, sizeof dir);
    CHECK_EQ_INT(fa_key_generate(dir, "device.key"), 0);
    EVP_PKEY *key = read_key(dir, "device.key");

    uint8_t hash[32];
    unsigned int hash_len = 0;
    EVP_Digest("csr bytes", 9, hash, &hash_len, EVP_sha256(), NULL);
    uint8_t sig[64], again[64];
    CHECK_EQ_INT(fa_sign_sha256(dir, "device.key", hash, sig), 0);
    CHECK_EQ_INT(fa_sign_sha256(dir, "device.key", hash, again), 0);
    CHECK(verifies(key, hash, sig));
    CHECK(verifies(key, hash, again));
    CHECK(memcmp(sig, again, 64) != 0); /* a new nonce each time */

    hash[0] ^= 1;
    CHECK(!verifies(key, hash, sig));
    EVP_PKEY_free(key);

    CHECK_EQ_INT(fa_sign_sha256(dir, "missing.key", hash, sig), -1);
}

/* A signature whose r has leading zero bytes is still 32 bytes each (padded, not shortened). */
static void signature_halves_are_padded(void) {
    char dir[64];
    make_dir(dir, sizeof dir);
    CHECK_EQ_INT(fa_key_generate(dir, "device.key"), 0);
    EVP_PKEY *key = read_key(dir, "device.key");
    uint8_t hash[32] = {1, 2, 3}, sig[64];
    int short_seen = 0;
    for (int i = 0; i < 4000 && !short_seen; i++) {
        hash[31] = (uint8_t)i;
        hash[30] = (uint8_t)(i >> 8);
        if (fa_sign_sha256(dir, "device.key", hash, sig) != 0)
            break;
        CHECK(verifies(key, hash, sig));
        short_seen = sig[0] == 0 || sig[32] == 0;
    }
    CHECK(short_seen); /* about 1 in 128 signatures: 4000 tries miss it once in 10^13 runs */
    EVP_PKEY_free(key);
}

/* A self-signed certificate for the key dir/key_name, valid from `from` until `until` (ASN.1 time
 * text, YYYYMMDDHHMMSSZ), as PEM in out. 0, or -1. */
static int make_certificate(const char *dir, const char *key_name, const char *from,
                            const char *until, char *out, size_t cap) {
    EVP_PKEY *key = read_key(dir, key_name);
    X509 *cert = X509_new();
    BIO *bio = BIO_new(BIO_s_mem());
    int rc = -1;
    if (key != NULL && cert != NULL && bio != NULL &&
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 7) == 1 &&
        ASN1_TIME_set_string_X509(X509_getm_notBefore(cert), from) == 1 &&
        ASN1_TIME_set_string_X509(X509_getm_notAfter(cert), until) == 1 &&
        X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC,
                                   (const unsigned char *)"device", -1, -1, 0) == 1 &&
        X509_set_issuer_name(cert, X509_get_subject_name(cert)) == 1 &&
        X509_set_pubkey(cert, key) == 1 && X509_sign(cert, key, EVP_sha256()) > 0 &&
        PEM_write_bio_X509(bio, cert) == 1) {
        char *data = NULL;
        long len = BIO_get_mem_data(bio, &data);
        if (len > 0 && (size_t)len < cap) {
            memcpy(out, data, (size_t)len);
            out[len] = '\0';
            rc = 0;
        }
    }
    BIO_free(bio);
    X509_free(cert);
    EVP_PKEY_free(key);
    return rc;
}

/* A certificate with subject CN=cn for `key`, signed by issuer_key as issuer (NULL: self-signed),
 * a CA when `ca`, appended as PEM to out (cap bytes, NUL-terminated). The X509 is returned (the
 * caller frees it), or NULL. */
static X509 *add_certificate(EVP_PKEY *key, const char *cn, EVP_PKEY *issuer_key, X509 *issuer,
                             int ca, char *out, size_t cap) {
    X509 *cert = X509_new();
    BIO *bio = BIO_new(BIO_s_mem());
    X509_EXTENSION *ext = NULL;
    X509V3_CTX v3;
    int ok =
        cert != NULL && bio != NULL && X509_set_version(cert, 2) == 1 &&
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 9) == 1 &&
        ASN1_TIME_set_string_X509(X509_getm_notBefore(cert), "20200101000000Z") == 1 &&
        ASN1_TIME_set_string_X509(X509_getm_notAfter(cert), "20400101000000Z") == 1 &&
        X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC,
                                   (const unsigned char *)cn, -1, -1, 0) == 1 &&
        X509_set_issuer_name(cert, X509_get_subject_name(issuer != NULL ? issuer : cert)) == 1 &&
        X509_set_pubkey(cert, key) == 1;
    if (ok) {
        X509V3_set_ctx(&v3, issuer != NULL ? issuer : cert, cert, NULL, NULL, 0);
        ext = X509V3_EXT_conf_nid(NULL, &v3, NID_basic_constraints,
                                  ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
        ok = ext != NULL && X509_add_ext(cert, ext, -1) == 1 &&
             X509_sign(cert, issuer_key != NULL ? issuer_key : key, EVP_sha256()) > 0 &&
             PEM_write_bio_X509(bio, cert) == 1;
    }
    char *data = NULL;
    long len = ok ? BIO_get_mem_data(bio, &data) : 0;
    size_t used = strlen(out);
    if (ok && len > 0 && used + (size_t)len < cap) {
        memcpy(out + used, data, (size_t)len);
        out[used + (size_t)len] = '\0';
    } else {
        X509_free(cert);
        cert = NULL;
    }
    X509_EXTENSION_free(ext);
    BIO_free(bio);
    return cert;
}

static void certificate_chains_only_to_the_root_in_use(void) {
    EVP_PKEY *root_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    EVP_PKEY *mid_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    EVP_PKEY *leaf_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    EVP_PKEY *forged_root_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    EVP_PKEY *forged_mid_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    static char root[4096], chain[8192], mid_only[4096], leaf[4096];
    static char forged_root[4096], forged_chain[8192], forged_leaf[4096], scratch[16384];
    root[0] = chain[0] = mid_only[0] = leaf[0] = '\0';
    forged_root[0] = forged_chain[0] = forged_leaf[0] = scratch[0] = '\0';

    X509 *r = add_certificate(root_key, "Root", NULL, NULL, 1, root, sizeof root);
    X509 *m = add_certificate(mid_key, "Device CA", root_key, r, 1, chain, sizeof chain);
    X509_free(add_certificate(mid_key, "Device CA", root_key, r, 1, mid_only, sizeof mid_only));
    strcat(chain, root); /* the answer's chain: intermediate, then root */
    X509 *l = add_certificate(leaf_key, "device", mid_key, m, 0, leaf, sizeof leaf);
    /* A forged hierarchy with the same names. */
    X509 *fr =
        add_certificate(forged_root_key, "Root", NULL, NULL, 1, forged_root, sizeof forged_root);
    X509 *fm = add_certificate(forged_mid_key, "Device CA", forged_root_key, fr, 1, forged_chain,
                               sizeof forged_chain);
    strcat(forged_chain, forged_root);
    X509 *fl =
        add_certificate(leaf_key, "device", forged_mid_key, fm, 0, forged_leaf, sizeof forged_leaf);
    CHECK(r != NULL && m != NULL && l != NULL && fr != NULL && fm != NULL && fl != NULL);

    /* Accepted: what is written is what was checked, serialised again. */
    char *cert_out = NULL, *chain_out = NULL;
    CHECK_EQ_INT(fa_certificate_chains_to(leaf, chain, root, &cert_out, &chain_out), 1);
    CHECK_EQ_STR(cert_out, leaf);
    CHECK_EQ_STR(chain_out, chain); /* intermediate, then the root in use */
    free(cert_out);
    free(chain_out);
    /* Accepted with CRLF line ends and blank lines between blocks; written with LF. */
    static char crlf[16384];
    size_t n = 0;
    for (const char *p = chain; *p != '\0' && n + 4 < sizeof crlf; p++) {
        if (*p == '\n')
            crlf[n++] = '\r';
        crlf[n++] = *p;
    }
    crlf[n] = '\0';
    CHECK_EQ_INT(fa_certificate_chains_to(leaf, crlf, root, NULL, &chain_out), 1);
    CHECK_EQ_STR(chain_out, chain);
    free(chain_out);

    /* the answer's root is another one (same name) */
    CHECK_EQ_INT(fa_certificate_chains_to(forged_leaf, forged_chain, root, NULL, NULL), 0);
    /* our chain, a certificate from another issuer of the same name */
    CHECK_EQ_INT(fa_certificate_chains_to(forged_leaf, chain, root, NULL, NULL), 0);
    /* a chain that does not end with the root in use */
    CHECK_EQ_INT(fa_certificate_chains_to(leaf, mid_only, root, NULL, NULL), 0);
    /* the root in use is the only anchor: a chain ending with it, the root itself forged */
    snprintf(scratch, sizeof scratch, "%s%s", mid_only, root);
    CHECK_EQ_INT(fa_certificate_chains_to(leaf, scratch, forged_root, NULL, NULL), 0);

    /* Anything but whitespace and whole certificate blocks, each starting a line: refused. */
    const char *const bad_chains[] = {
        "%sx%s", /* a block hidden mid-line after the root */
        "%s%s-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n", /* not base64 */
        "text\n%s%s",                                                         /* text before */
        "%s%stext\n",                                                         /* text after */
        "%s  %s",                                 /* a BEGIN line that starts with spaces */
        "%s%s-----BEGIN CERTIFICATE-----\nMII\n", /* a block without its END */
        "%s%s%s%s%s",                             /* more than 4 certificates (5) */
    };
    for (size_t i = 0; i < sizeof bad_chains / sizeof bad_chains[0]; i++) {
        snprintf(scratch, sizeof scratch, bad_chains[i], mid_only, root, mid_only, mid_only, root);
        CHECK_EQ_INT(fa_certificate_chains_to(leaf, scratch, root, NULL, NULL), 0);
    }
    /* 4 certificates are still a chain (the intermediate repeated, the root last); what is
     * written is the verified path: intermediate, root. */
    snprintf(scratch, sizeof scratch, "%s%s%s%s", mid_only, mid_only, mid_only, root);
    CHECK_EQ_INT(fa_certificate_chains_to(leaf, scratch, root, NULL, &chain_out), 1);
    static char path[8192];
    snprintf(path, sizeof path, "%s%s", mid_only, root);
    CHECK_EQ_STR(chain_out, path);
    free(chain_out);

    /* A certificate off the verified path (verification ignores it, found by name elsewhere):
     * refused, never written in front of the intermediate. */
    EVP_PKEY *unrelated_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    static char unrelated[4096];
    unrelated[0] = '\0';
    X509 *u =
        add_certificate(unrelated_key, "Unrelated CA", NULL, NULL, 1, unrelated, sizeof unrelated);
    CHECK(u != NULL);
    snprintf(scratch, sizeof scratch, "%s%s", unrelated, chain);
    chain_out = NULL;
    CHECK_EQ_INT(fa_certificate_chains_to(leaf, scratch, root, NULL, &chain_out), 0);
    CHECK(chain_out == NULL);
    snprintf(scratch, sizeof scratch, "%s%s%s", mid_only, unrelated, root);
    CHECK_EQ_INT(fa_certificate_chains_to(leaf, scratch, root, NULL, NULL), 0);
    X509_free(u);
    EVP_PKEY_free(unrelated_key);
    /* the device certificate: exactly one block */
    snprintf(scratch, sizeof scratch, "%s%s", leaf, leaf);
    CHECK_EQ_INT(fa_certificate_chains_to(scratch, chain, root, NULL, NULL), 0);
    snprintf(scratch, sizeof scratch, "x%s", leaf);
    CHECK_EQ_INT(fa_certificate_chains_to(scratch, chain, root, NULL, NULL), 0);
    CHECK_EQ_INT(fa_certificate_chains_to("junk\n", chain, root, NULL, NULL), 0);
    CHECK_EQ_INT(fa_certificate_chains_to(leaf, "junk\n", root, NULL, NULL), 0);
    CHECK_EQ_INT(fa_certificate_chains_to(leaf, "", root, NULL, NULL), 0);
    /* the root in use cannot be read: a local failure */
    CHECK_EQ_INT(fa_certificate_chains_to(leaf, chain, "junk\n", NULL, NULL), -1);

    X509_free(r);
    X509_free(m);
    X509_free(l);
    X509_free(fr);
    X509_free(fm);
    X509_free(fl);
    EVP_PKEY_free(root_key);
    EVP_PKEY_free(mid_key);
    EVP_PKEY_free(leaf_key);
    EVP_PKEY_free(forged_root_key);
    EVP_PKEY_free(forged_mid_key);
}

static fl_time utc(const char *iso) {
    fl_time t = -1;
    fl_time_parse(iso, strlen(iso), &t);
    return t;
}

static void certificate_validity_is_read_in_utc(void) {
    char dir[64], pem[4096], chain[8192];
    make_dir(dir, sizeof dir);
    CHECK_EQ_INT(fa_key_generate(dir, "device.key"), 0);
    /* UTCTime before 2050, GeneralizedTime from 2050 on */
    CHECK_EQ_INT(
        make_certificate(dir, "device.key", "20270310080000Z", "20510101000000Z", pem, sizeof pem),
        0);
    fl_time not_before = 0, not_after = 0;
    CHECK_EQ_INT(fa_certificate_validity(pem, strlen(pem), &not_before, &not_after), 0);
    CHECK_EQ_INT(not_before, utc("2027-03-10T08:00:00Z"));
    CHECK_EQ_INT(not_after, utc("2051-01-01T00:00:00Z"));

    /* The first certificate of a chain counts. */
    char second[4096];
    CHECK_EQ_INT(make_certificate(dir, "device.key", "20200101000000Z", "20210101000000Z", second,
                                  sizeof second),
                 0);
    snprintf(chain, sizeof chain, "%s%s", pem, second);
    CHECK_EQ_INT(fa_certificate_validity(chain, strlen(chain), &not_before, &not_after), 0);
    CHECK_EQ_INT(not_after, utc("2051-01-01T00:00:00Z"));

    CHECK_EQ_INT(fa_certificate_validity("junk\n", 5, &not_before, &not_after), -1);
    CHECK_EQ_INT(fa_certificate_validity(pem, 40, &not_before, &not_after), -1); /* cut */
}

static void key_matches_only_its_certificate(void) {
    char dir[64], pem[4096];
    make_dir(dir, sizeof dir);
    CHECK_EQ_INT(fa_key_generate(dir, "a.key"), 0);
    CHECK_EQ_INT(fa_key_generate(dir, "b.key"), 0);
    CHECK_EQ_INT(
        make_certificate(dir, "a.key", "20260101000000Z", "20280101000000Z", pem, sizeof pem), 0);
    CHECK_EQ_INT(fa_key_matches_certificate(dir, "a.key", pem, strlen(pem)), 1);
    CHECK_EQ_INT(fa_key_matches_certificate(dir, "b.key", pem, strlen(pem)), 0);
    CHECK_EQ_INT(fa_key_matches_certificate(dir, "missing.key", pem, strlen(pem)), -1);
    CHECK_EQ_INT(fa_key_matches_certificate(dir, "a.key", "junk\n", 5), -1);
}

int main(void) {
    RUN(key_is_p256_pkcs8_and_private);
    RUN(keys_are_new_each_time);
    RUN(csr_is_signed_by_the_key_with_cn_device);
    RUN(csr_needs_room_and_a_key);
    RUN(key_of_another_curve_is_refused);
    RUN(signature_is_r_and_s_over_the_hash);
    RUN(signature_halves_are_padded);
    RUN(update_key_is_p256_public_key_der);
    RUN(update_key_of_another_kind_is_refused);
    RUN(certificate_validity_is_read_in_utc);
    RUN(key_matches_only_its_certificate);
    RUN(certificate_chains_only_to_the_root_in_use);
    return CHECK_RESULT;
}
