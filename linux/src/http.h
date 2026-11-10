/* SPDX-License-Identifier: Apache-2.0 */
/* HTTPS with libcurl: TLS 1.2 or later, peer and host name verified (with ca_file when it is set,
 * otherwise the system authorities), https only, no redirect followed, 15 s to connect and 60 s
 * in all. Nothing about a request (URL, body) is logged; a failure logs only libcurl's reason. */
#ifndef FIRMLINE_AGENT_HTTP_H
#define FIRMLINE_AGENT_HTTP_H

#include <stddef.h>

#define FA_HTTP_BODY_MAX (64 * 1024) /* a longer answer is a network error */

typedef struct {
    int status; /* 0 = network or TLS error */
    char *body; /* NUL-terminated, never NULL after an answer; free with fa_http_response_free */
    size_t len;
} fa_http_response;

/* Once per process, before any request, and at the end. */
int fa_http_global_init(void);
void fa_http_global_cleanup(void);

/* POST of a JSON body. 0 when the server answered, whatever the status; -1 on a network or TLS
 * error, an answer over FA_HTTP_BODY_MAX or no memory (status 0, body NULL). */
int fa_http_post_json(const char *url, const char *ca_file, const char *body,
                      fa_http_response *out);

/* Wipes and frees the body; the response can be used again. */
void fa_http_response_free(fa_http_response *r);

#endif
