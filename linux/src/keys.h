/* SPDX-License-Identifier: Apache-2.0 */
/* The device key, ECDSA P-256 with OpenSSL 3 (EVP only). A key lives in the data folder as an
 * unencrypted PKCS#8 PEM with mode 0600 and never leaves it; a key of another type or curve is
 * refused. Every function returns 0, or -1 on any failure, unless it says otherwise. */
#ifndef FIRMLINE_AGENT_KEYS_H
#define FIRMLINE_AGENT_KEYS_H

#include "firmline/fl_common.h"

#include <stddef.h>
#include <stdint.h>

/* A new key written atomically to dir/name (fa_store_write, mode 0600). */
int fa_key_generate(const char *dir, const char *name);

/* A CSR with subject CN=device for the key dir/key_name, signed with it (SHA-256), as a
 * NUL-terminated PEM in pem; -1 (pem[0] = '\0') when it does not fit in cap. */
int fa_csr_create(const char *dir, const char *key_name, char *pem, size_t cap);

/* The ECDSA signature with the key dir/key_name of a SHA-256 hash, as 64 bytes r||s (each half
 * padded to 32 bytes). */
int fa_sign_sha256(const char *dir, const char *key_name, const uint8_t hash[32], uint8_t sig[64]);

/* The update verification key of the file at path (a "PUBLIC KEY" PEM, SubjectPublicKeyInfo, from
 * the page "OTA releases"), which must be P-256: its DER (91 bytes) into der, the length in *len.
 * -1 (*len = 0) when the file is missing, holds no public key, a key of another type or curve, or
 * the DER does not fit in cap. */
int fa_update_key_load(const char *path, uint8_t *der, size_t cap, size_t *len);

/* Whether the key dir/key_name is the key of the first certificate of the PEM text cert_pem (len
 * bytes): 1 when it is, 0 when it is not, -1 when the key or the certificate cannot be read. */
int fa_key_matches_certificate(const char *dir, const char *key_name, const char *cert_pem,
                               size_t len);

/* notBefore and notAfter of the first certificate of the PEM text cert_pem (len bytes), as UTC
 * seconds. 0, or -1 when no certificate can be read. */
int fa_certificate_validity(const char *cert_pem, size_t len, fl_time *not_before,
                            fl_time *not_after);

#define FA_CHAIN_MAX 4 /* certificates in a chain of the platform (intermediate, root: 2) */

/* Whether the certificate and chain of a renewal answer keep the trust anchor (root_pem, the
 * root.pem in use; all three NUL-terminated PEM texts):
 *   - cert_pem is exactly one certificate block, chain_pem 1..FA_CHAIN_MAX blocks: nothing but
 *     whitespace and whole "-----BEGIN CERTIFICATE-----" ... "-----END CERTIFICATE-----" blocks,
 *     each BEGIN starting a line, each parsing as a certificate;
 *   - the last certificate of the chain is DER-equal to root_pem's certificate;
 *   - the certificate verifies through the chain against root_pem's certificate as the only
 *     trusted one (no system authority, no partial chain; the time is not checked: the clock of
 *     a device may be wrong).
 * 1 when all hold: then *cert_out (when not NULL) is the certificate and *chain_out (when not
 * NULL) the chain before the root followed by the root in use, both serialised again from the
 * checked certificates (PEM, LF line ends, malloc'ed, NUL-terminated: the caller frees them), so
 * that what is installed is what was checked. 0 when the answer is refused; -1 when root_pem
 * holds no certificate or memory runs out (outputs NULL in both cases). */
int fa_certificate_chains_to(const char *cert_pem, const char *chain_pem, const char *root_pem,
                             char **cert_out, char **chain_out);

#endif
