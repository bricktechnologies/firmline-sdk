/* SPDX-License-Identifier: Apache-2.0 */
/* Device messages of the platform contract: status, update result, registration and renewal
 * requests, and the provisioning response. Builders write NUL-terminated JSON into a caller
 * buffer; on any error out[0] is '\0' (cap > 0), so a partial message cannot be sent by mistake.
 * Lengths of text limits are in bytes (UTF-8). */
#ifndef FIRMLINE_FL_MESSAGES_H
#define FIRMLINE_FL_MESSAGES_H

#include <stddef.h>
#include <stdint.h>

#include "fl_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FL_STATUS_MAX 4096
#define FL_STATUS_MAX_COMPONENTS 16
#define FL_RESULT_MAX 1024
#define FL_TEXT_MAX 64 /* fw, component code, version, detail */

typedef struct {
    const char *code;
    const char *version;
} fl_component_version;

/* {"fw","components","sdk","ts","uptime"}. fw (NULL to omit) and each code and version are 1..64
 * bytes; components are an object {"code":"version"} (codes distinct). At least fw or one
 * component. sdk (NULL to omit) is "name/version" of the SDK that builds the message: name 1..32 of
 * [A-Za-z0-9._-], one "/", version valid as fw without a leading or trailing space, 64 bytes at
 * most. uptime < 0 omits it. Returns the length, FL_ERR_ARG for a violated limit (more than
 * FL_STATUS_MAX bytes, more than 16 components, a NULL or empty text, a repeated code, neither fw
 * nor components, an offset or year out of range), FL_ERR_SPACE if cap is too small. */
int fl_status_build(char *out, size_t cap, const char *fw, const fl_component_version *components,
                    size_t n, const char *sdk, fl_time ts, int offset_minutes, int64_t uptime);

/* {"release","result","fw","detail"}. release is required (non-empty); fw NULL omits it (1..64
 * bytes otherwise); detail NULL or empty is omitted and one over 64 bytes is dropped, the result
 * is kept. Same returns as fl_status_build, with the limit FL_RESULT_MAX. */
int fl_result_build(char *out, size_t cap, const char *release, fl_result result, const char *fw,
                    const char *detail);

/* {"token","serialNumber","csr"}, all three required and non-empty. */
int fl_registration_body(char *out, size_t cap, const char *token, const char *serial,
                         const char *csr_pem);

/* {"certificate","csr","proof"}; proof is base64 (standard, with padding, 88 characters) of the 64
 * bytes r||s of the P-256 signature. */
int fl_renewal_body(char *out, size_t cap, const char *certificate_pem, const char *csr_pem,
                    const uint8_t proof_p1363[64]);

typedef struct {
    char device_id[37];
    char family_id[37]; /* "" when the platform does not send it (before T178) */
    char client_id[80];
    char topic_root[96];
    char ota_offer_topic[112];
    const char *certificate; /* point into pem_buf, NUL-terminated */
    const char *chain;
} fl_provisioned;

/* Reads the 200 response of registration and renewal. deviceId, clientId, topicRoot,
 * otaOfferTopic, certificate and chain are required and non-empty; familyId is optional and, when
 * present, a GUID. certificate and chain are unescaped one after the other into pem_buf.
 * FL_ERR_FORMAT: invalid JSON, a field missing, empty or not a string, a bad familyId.
 * FL_ERR_SPACE: a value does not fit its field or pem_buf (never truncated). FL_ERR_ARG: NULL
 * argument or pem_cap 0. On error out is cleared (pointers NULL) and pem_buf[0] is '\0'. */
int fl_provisioned_parse(const char *json, size_t len, char *pem_buf, size_t pem_cap,
                         fl_provisioned *out);

/* The `code` of an RFC 9457 error body; other members, nested ones included, are ignored.
 * FL_ERR_FORMAT: not a JSON object or no string code. FL_ERR_SPACE: code over 63 bytes. On error
 * out[0] is '\0'. */
int fl_problem_code(const char *json, size_t len, char out[64]);

#ifdef __cplusplus
}
#endif

#endif
