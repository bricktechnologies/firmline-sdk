/* SPDX-License-Identifier: Apache-2.0 */
/* HTTPS with libcurl: TLS 1.2 or later, peer and host name verified (with ca_file when it is set,
 * otherwise the system authorities), https only, no redirect followed, 15 s to connect and 60 s
 * in all. Nothing about a request (URL, body) is logged; a failure logs only libcurl's reason. */
#ifndef FIRMLINE_AGENT_HTTP_H
#define FIRMLINE_AGENT_HTTP_H

#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

/* ---- Downloads in the background ------------------------------------------------------------
 * A GET driven from the caller's loop (libcurl multi interface), so that the MQTT connection
 * keeps turning while a large file arrives. Same TLS rules as above and 15 s to connect; no limit
 * on the whole transfer, but less than 1 byte/s for 60 s ends it as a network error. From
 * `offset` on with "Range: bytes=<offset>-" when offset > 0. Nothing about the request is
 * logged. */

typedef struct fa_http_download fa_http_download;

/* The body as it arrives, with the HTTP status and the first byte of the Content-Range of the
 * answer (-1 when there is none). Return 0 to go on, -1 to stop the transfer. */
typedef int (*fa_http_sink)(void *ctx, int status, int64_t range_start, const void *data,
                            size_t len);

typedef struct {
    int status;         /* the HTTP status, 0 when no answer came */
    bool complete;      /* the whole answer arrived (libcurl reported no error) */
    const char *reason; /* libcurl's text for how the transfer ended, never the URL */
} fa_http_outcome;

/* NULL when libcurl cannot even start the transfer. */
fa_http_download *fa_http_download_start(const char *url, const char *ca_file, uint64_t offset,
                                         fa_http_sink sink, void *ctx);

/* Waits up to timeout_ms for the transfer's sockets and for the caller's `fds` (revents filled;
 * POLLIN and POLLOUT only, at most 4). */
void fa_http_download_wait(fa_http_download *d, struct pollfd *fds, int nfds, int timeout_ms);

/* Moves the transfer on (the sink is called from here). 1 while it runs; 0 when it has ended,
 * with *out filled. */
int fa_http_download_step(fa_http_download *d, fa_http_outcome *out);

/* Stops the transfer if it still runs and frees everything. NULL is allowed. */
void fa_http_download_free(fa_http_download *d);

#endif
