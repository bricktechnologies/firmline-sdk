/* SPDX-License-Identifier: Apache-2.0 */
/* The device key, ECDSA P-256 with OpenSSL 3 (EVP only). A key lives in the data folder as an
 * unencrypted PKCS#8 PEM with mode 0600 and never leaves it; a key of another type or curve is
 * refused. Every function returns 0, or -1 on any failure. */
#ifndef FIRMLINE_AGENT_KEYS_H
#define FIRMLINE_AGENT_KEYS_H

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

#endif
