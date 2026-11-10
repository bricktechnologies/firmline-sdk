/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "keys.h"

#include "store.h"

#include <limits.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* A key file is never encrypted: never ask for a pass phrase (OpenSSL would prompt on the tty). */
static int no_pass_phrase(char *buf, int size, int rwflag, void *u) {
    (void)buf;
    (void)size;
    (void)rwflag;
    (void)u;
    return -1;
}

static int is_p256(EVP_PKEY *key) {
    char group[64] = "";
    size_t n = 0;
    return EVP_PKEY_is_a(key, "EC") &&
           EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof group,
                                          &n) == 1 &&
           strcmp(group, "prime256v1") == 0;
}

/* The P-256 key of dir/name, or NULL. The PEM read from the file is wiped before it is freed. */
static EVP_PKEY *load_key(const char *dir, const char *name) {
    char *pem = NULL;
    size_t len = 0;
    if (fa_store_read(dir, name, &pem, &len) != 0)
        return NULL;
    EVP_PKEY *key = NULL;
    BIO *bio = BIO_new_mem_buf(pem, (int)len); /* len <= 1 MiB */
    if (bio != NULL)
        key = PEM_read_bio_PrivateKey(bio, NULL, no_pass_phrase, NULL);
    BIO_free(bio);
    OPENSSL_cleanse(pem, len);
    free(pem);
    if (key != NULL && !is_p256(key)) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    return key;
}

int fa_key_generate(const char *dir, const char *name) {
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    if (key == NULL)
        return -1;
    int rc = -1;
    /* A secure-memory BIO: the PEM is wiped when the BIO is freed. */
    BIO *bio = BIO_new(BIO_s_secmem());
    if (bio != NULL && PEM_write_bio_PKCS8PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) == 1) {
        char *data = NULL;
        long len = BIO_get_mem_data(bio, &data);
        if (len > 0)
            rc = fa_store_write(dir, name, data, (size_t)len, 0600);
    }
    BIO_free(bio);
    EVP_PKEY_free(key);
    return rc;
}

int fa_csr_create(const char *dir, const char *key_name, char *pem, size_t cap) {
    if (cap > 0)
        pem[0] = '\0';
    EVP_PKEY *key = load_key(dir, key_name);
    if (key == NULL)
        return -1;
    int rc = -1;
    X509_REQ *req = X509_REQ_new();
    X509_NAME *subject = req != NULL ? X509_REQ_get_subject_name(req) : NULL;
    BIO *bio = NULL;
    if (subject != NULL && X509_REQ_set_version(req, X509_REQ_VERSION_1) == 1 &&
        X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (const unsigned char *)"device", -1,
                                   -1, 0) == 1 &&
        X509_REQ_set_pubkey(req, key) == 1 && X509_REQ_sign(req, key, EVP_sha256()) > 0 &&
        (bio = BIO_new(BIO_s_mem())) != NULL && PEM_write_bio_X509_REQ(bio, req) == 1) {
        char *data = NULL;
        long len = BIO_get_mem_data(bio, &data);
        if (len > 0 && (size_t)len < cap) {
            memcpy(pem, data, (size_t)len);
            pem[len] = '\0';
            rc = 0;
        }
    }
    BIO_free(bio);
    X509_REQ_free(req);
    EVP_PKEY_free(key);
    return rc;
}

int fa_sign_sha256(const char *dir, const char *key_name, const uint8_t hash[32], uint8_t sig[64]) {
    EVP_PKEY *key = load_key(dir, key_name);
    if (key == NULL)
        return -1;
    int rc = -1;
    unsigned char der[80]; /* an ECDSA P-256 signature in DER is at most 72 bytes */
    size_t der_len = sizeof der;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (ctx != NULL && EVP_PKEY_sign_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) == 1 &&
        EVP_PKEY_sign(ctx, der, &der_len, hash, 32) == 1) {
        const unsigned char *p = der;
        ECDSA_SIG *s = d2i_ECDSA_SIG(NULL, &p, (long)der_len);
        const BIGNUM *r = NULL, *ss = NULL;
        if (s != NULL) {
            ECDSA_SIG_get0(s, &r, &ss);
            if (BN_bn2binpad(r, sig, 32) == 32 && BN_bn2binpad(ss, sig + 32, 32) == 32)
                rc = 0;
            ECDSA_SIG_free(s);
        }
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    return rc;
}

int fa_update_key_load(const char *path, uint8_t *der, size_t cap, size_t *len) {
    *len = 0;
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return -1;
    EVP_PKEY *key = PEM_read_PUBKEY(f, NULL, no_pass_phrase, NULL);
    fclose(f);
    int rc = -1;
    if (key != NULL && is_p256(key)) {
        int n = i2d_PUBKEY(key, NULL);
        unsigned char *p = der;
        if (n > 0 && (size_t)n <= cap && i2d_PUBKEY(key, &p) == n) {
            *len = (size_t)n;
            rc = 0;
        }
    }
    EVP_PKEY_free(key);
    return rc;
}

/* The first certificate of a PEM text, or NULL. */
static X509 *read_certificate(const char *pem, size_t len) {
    if (len > INT_MAX)
        return NULL;
    BIO *bio = BIO_new_mem_buf(pem, (int)len);
    X509 *cert = bio != NULL ? PEM_read_bio_X509(bio, NULL, no_pass_phrase, NULL) : NULL;
    BIO_free(bio);
    return cert;
}

int fa_key_matches_certificate(const char *dir, const char *key_name, const char *cert_pem,
                               size_t len) {
    EVP_PKEY *key = load_key(dir, key_name);
    X509 *cert = key != NULL ? read_certificate(cert_pem, len) : NULL;
    EVP_PKEY *public = cert != NULL ? X509_get0_pubkey(cert) : NULL;
    int rc = public == NULL ? -1 : EVP_PKEY_eq(key, public) == 1;
    X509_free(cert);
    EVP_PKEY_free(key);
    return rc;
}

/* An ASN1_TIME as UTC seconds, through the ISO text the core reads (no timegm, no time zone). */
static int asn1_seconds(const ASN1_TIME *t, fl_time *out) {
    struct tm tm;
    char iso[32];
    if (t == NULL || ASN1_TIME_to_tm(t, &tm) != 1)
        return -1;
    int n = snprintf(iso, sizeof iso, "%04d-%02d-%02dT%02d:%02d:%02dZ", tm.tm_year + 1900,
                     tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    return n > 0 && (size_t)n < sizeof iso && fl_time_parse(iso, (size_t)n, out) == FL_OK ? 0 : -1;
}

int fa_certificate_validity(const char *cert_pem, size_t len, fl_time *not_before,
                            fl_time *not_after) {
    X509 *cert = read_certificate(cert_pem, len);
    int rc = cert != NULL && asn1_seconds(X509_get0_notBefore(cert), not_before) == 0 &&
                     asn1_seconds(X509_get0_notAfter(cert), not_after) == 0
                 ? 0
                 : -1;
    X509_free(cert);
    return rc;
}
