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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdbool.h>
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

static const char PEM_BEGIN[] = "-----BEGIN CERTIFICATE-----";
static const char PEM_END[] = "-----END CERTIFICATE-----";

/* The certificates of a PEM text read strictly: nothing but whitespace and whole certificate
 * blocks, each BEGIN at the start of a line, each block parsing on its own; 1..max of them. Each
 * block is parsed alone, so no text can sit between blocks unseen (OpenSSL's reader would skip a
 * BEGIN that does not start a line, or anything before a BEGIN). NULL when the text has another
 * form (or memory runs out). */
static STACK_OF(X509) * read_certificates_strict(const char *pem, int max) {
    STACK_OF(X509) *all = sk_X509_new_null();
    const char *p = pem;
    while (all != NULL) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            p++;
        if (*p == '\0')
            break;
        if ((p != pem && p[-1] != '\n') || strncmp(p, PEM_BEGIN, sizeof PEM_BEGIN - 1) != 0)
            goto refuse; /* text, or a BEGIN that does not start a line */
        const char *body = p + sizeof PEM_BEGIN - 1;
        const char *end = strstr(body, PEM_END);
        const char *other = strstr(body, "-----BEGIN");
        if (end == NULL || (other != NULL && other < end) || sk_X509_num(all) >= max)
            goto refuse;
        end += sizeof PEM_END - 1;
        X509 *cert = read_certificate(p, (size_t)(end - p));
        if (cert == NULL || sk_X509_push(all, cert) <= 0) {
            X509_free(cert);
            goto refuse;
        }
        p = end;
    }
    if (all != NULL && sk_X509_num(all) > 0)
        return all;
refuse:
    ERR_clear_error();
    sk_X509_pop_free(all, X509_free);
    return NULL;
}

/* certs[0..n-1] as PEM blocks, malloc'ed and NUL-terminated, or NULL. */
static char *to_pem(X509 *const *certs, int n) {
    BIO *bio = BIO_new(BIO_s_mem());
    char *out = NULL, *data = NULL;
    int ok = bio != NULL;
    for (int i = 0; ok && i < n; i++)
        ok = PEM_write_bio_X509(bio, certs[i]) == 1;
    long len = ok ? BIO_get_mem_data(bio, &data) : -1;
    if (len > 0 && (out = malloc((size_t)len + 1)) != NULL) {
        memcpy(out, data, (size_t)len);
        out[len] = '\0';
    }
    BIO_free(bio);
    return out;
}

int fa_certificate_chains_to(const char *cert_pem, const char *chain_pem, const char *root_pem,
                             char **cert_out, char **chain_out) {
    if (cert_out != NULL)
        *cert_out = NULL;
    if (chain_out != NULL)
        *chain_out = NULL;
    X509 *root = read_certificate(root_pem, strlen(root_pem));
    STACK_OF(X509) *cert = read_certificates_strict(cert_pem, 1);
    STACK_OF(X509) *chain = read_certificates_strict(chain_pem, FA_CHAIN_MAX);
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509 *written[FA_CHAIN_MAX];
    char *new_cert = NULL, *new_chain = NULL;
    int rc = -1, n = chain != NULL ? sk_X509_num(chain) : 0;
    if (root == NULL)
        goto done;
    rc = 0;
    if (cert == NULL || chain == NULL || X509_cmp(sk_X509_value(chain, n - 1), root) != 0)
        goto done; /* not certificate blocks only, or another root */
    rc = -1;
    store = X509_STORE_new();
    ctx = X509_STORE_CTX_new();
    if (store == NULL || ctx == NULL || X509_STORE_add_cert(store, root) != 1 ||
        X509_STORE_CTX_init(ctx, store, sk_X509_value(cert, 0), chain) != 1)
        goto done;
    X509_VERIFY_PARAM_set_flags(X509_STORE_CTX_get0_param(ctx), X509_V_FLAG_NO_CHECK_TIME);
    if (X509_verify_cert(ctx) != 1) {
        rc = 0;
        goto done;
    }
    /* What is written is the verified path (certificate, intermediate(s), root), not the answer's
     * list: OpenSSL picks issuers by name and would ignore a certificate sent in front of the
     * intermediate, which chain.pem (and so device-chain.pem) would then present first. Every
     * certificate of the answer must be on that path, and the path must end with the anchor. */
    STACK_OF(X509) *path = X509_STORE_CTX_get0_chain(ctx);
    int len = path != NULL ? sk_X509_num(path) : 0;
    rc = 0;
    if (len < 2 || len - 1 > FA_CHAIN_MAX || X509_cmp(sk_X509_value(path, len - 1), root) != 0)
        goto done;
    for (int i = 0; i < n; i++) {
        bool on_path = false;
        for (int j = 1; j < len && !on_path; j++)
            on_path = X509_cmp(sk_X509_value(chain, i), sk_X509_value(path, j)) == 0;
        if (!on_path)
            goto done; /* a certificate the verification did not use */
    }
    rc = -1;
    for (int j = 1; j < len; j++)
        written[j - 1] = sk_X509_value(path, j);
    X509 *leaf = sk_X509_value(path, 0);
    new_cert = to_pem(&leaf, 1);
    new_chain = to_pem(written, len - 1);
    if (new_cert == NULL || new_chain == NULL)
        goto done;
    rc = 1;
    if (cert_out != NULL) {
        *cert_out = new_cert;
        new_cert = NULL;
    }
    if (chain_out != NULL) {
        *chain_out = new_chain;
        new_chain = NULL;
    }
done:
    ERR_clear_error();
    free(new_cert);
    free(new_chain);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_pop_free(chain, X509_free);
    sk_X509_pop_free(cert, X509_free);
    X509_free(root);
    return rc;
}
