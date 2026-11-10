/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "http.h"

#include "log.h"

#include <ctype.h>
#include <curl/curl.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t len;
    int too_big;
} buffer;

static size_t on_data(char *ptr, size_t size, size_t nmemb, void *userdata) {
    buffer *b = userdata;
    size_t n = size * nmemb;
    if (n > FA_HTTP_BODY_MAX - b->len) {
        b->too_big = 1;
        return 0; /* anything but n stops the transfer */
    }
    char *grown = realloc(b->data, b->len + n + 1);
    if (grown == NULL)
        return 0;
    memcpy(grown + b->len, ptr, n);
    b->len += n;
    grown[b->len] = '\0';
    b->data = grown;
    return n;
}

int fa_http_global_init(void) { return curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK ? 0 : -1; }

void fa_http_global_cleanup(void) { curl_global_cleanup(); }

/* The options of every request of the agent. */
static int secure_options(CURL *curl, const char *url, const char *ca_file) {
    int ok =
        curl_easy_setopt(curl, CURLOPT_URL, url) == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https") == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L) == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_2) == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L) == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L) == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L) == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L) == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "firmline-agent") == CURLE_OK;
    if (ok && ca_file != NULL && ca_file[0] != '\0')
        ok = curl_easy_setopt(curl, CURLOPT_CAINFO, ca_file) == CURLE_OK;
    return ok ? 0 : -1;
}

void fa_http_response_free(fa_http_response *r) {
    if (r->body != NULL) {
        OPENSSL_cleanse(r->body, r->len);
        free(r->body);
    }
    r->body = NULL;
    r->len = 0;
    r->status = 0;
}

int fa_http_post_json(const char *url, const char *ca_file, const char *body,
                      fa_http_response *out) {
    out->status = 0;
    out->body = NULL;
    out->len = 0;
    CURL *curl = curl_easy_init();
    if (curl == NULL)
        return -1;
    struct curl_slist *headers = NULL, *h;
    if ((h = curl_slist_append(headers, "Content-Type: application/json")) != NULL)
        headers = h;
    if (h != NULL && (h = curl_slist_append(headers, "Accept: application/json, "
                                                     "application/problem+json")) != NULL)
        headers = h;

    buffer b = {NULL, 0, 0};
    CURLcode rc = CURLE_FAILED_INIT;
    if (h != NULL && secure_options(curl, url, ca_file) == 0 &&
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body) == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(body)) == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_data) == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &b) == CURLE_OK)
        rc = curl_easy_perform(curl);

    long status = 0;
    if (rc == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK || status <= 0) {
        if (b.too_big)
            fa_log("error", "HTTPS answer longer than %d bytes", FA_HTTP_BODY_MAX);
        else
            fa_log("error", "HTTPS request failed: %s", curl_easy_strerror(rc));
        free(b.data);
        return -1;
    }
    if (b.data == NULL && (b.data = calloc(1, 1)) == NULL)
        return -1;
    out->status = (int)status;
    out->body = b.data;
    out->len = b.len;
    return 0;
}

/* ---- Downloads in the background ------------------------------------------------------------ */

#define DOWNLOAD_MAX_FDS 4

struct fa_http_download {
    CURLM *multi;
    CURL *easy;
    fa_http_sink sink;
    void *ctx;
    int64_t range_start; /* of the last answer's Content-Range, -1 when it has none */
    bool done;
    CURLcode result;
    char range[32];
};

/* "Content-Range: bytes <first>-<last>/<size>" of the answer; a new status line (an interim
 * answer before the real one) forgets it. */
static size_t on_download_header(char *buf, size_t size, size_t nitems, void *userdata) {
    fa_http_download *d = userdata;
    size_t n = size * nitems;
    static const char name[] = "content-range:";
    if (n >= 5 && memcmp(buf, "HTTP/", 5) == 0) {
        d->range_start = -1;
        return n;
    }
    if (n <= sizeof name - 1)
        return n;
    for (size_t i = 0; i < sizeof name - 1; i++)
        if (tolower((unsigned char)buf[i]) != name[i])
            return n;
    size_t i = sizeof name - 1;
    while (i < n && (buf[i] == ' ' || buf[i] == '\t'))
        i++;
    if (n - i < 7 || memcmp(buf + i, "bytes ", 6) != 0)
        return n;
    i += 6;
    int64_t first = 0;
    size_t digits = 0;
    while (i < n && buf[i] >= '0' && buf[i] <= '9' && digits < 18) {
        first = first * 10 + (buf[i] - '0');
        i++;
        digits++;
    }
    if (digits > 0 && i < n && buf[i] == '-')
        d->range_start = first;
    return n;
}

static size_t on_download_data(char *ptr, size_t size, size_t nmemb, void *userdata) {
    fa_http_download *d = userdata;
    size_t n = size * nmemb;
    long status = 0;
    curl_easy_getinfo(d->easy, CURLINFO_RESPONSE_CODE, &status);
    if (d->sink(d->ctx, (int)status, d->range_start, ptr, n) != 0)
        return n == 0 ? 1 : 0; /* anything but n stops the transfer */
    return n;
}

fa_http_download *fa_http_download_start(const char *url, const char *ca_file, uint64_t offset,
                                         fa_http_sink sink, void *ctx) {
    fa_http_download *d = calloc(1, sizeof *d);
    if (d == NULL)
        return NULL;
    d->sink = sink;
    d->ctx = ctx;
    d->range_start = -1;
    d->easy = curl_easy_init();
    d->multi = curl_multi_init();
    int ok = d->easy != NULL && d->multi != NULL && secure_options(d->easy, url, ca_file) == 0 &&
             curl_easy_setopt(d->easy, CURLOPT_TIMEOUT, 0L) == CURLE_OK &&
             curl_easy_setopt(d->easy, CURLOPT_LOW_SPEED_LIMIT, 1L) == CURLE_OK &&
             curl_easy_setopt(d->easy, CURLOPT_LOW_SPEED_TIME, 60L) == CURLE_OK &&
             curl_easy_setopt(d->easy, CURLOPT_HTTPGET, 1L) == CURLE_OK &&
             curl_easy_setopt(d->easy, CURLOPT_HEADERFUNCTION, on_download_header) == CURLE_OK &&
             curl_easy_setopt(d->easy, CURLOPT_HEADERDATA, d) == CURLE_OK &&
             curl_easy_setopt(d->easy, CURLOPT_WRITEFUNCTION, on_download_data) == CURLE_OK &&
             curl_easy_setopt(d->easy, CURLOPT_WRITEDATA, d) == CURLE_OK;
    if (ok && offset > 0) {
        snprintf(d->range, sizeof d->range, "%llu-", (unsigned long long)offset);
        ok = curl_easy_setopt(d->easy, CURLOPT_RANGE, d->range) == CURLE_OK;
    }
    if (!ok || curl_multi_add_handle(d->multi, d->easy) != CURLM_OK) {
        if (d->easy != NULL)
            curl_easy_cleanup(d->easy);
        if (d->multi != NULL)
            curl_multi_cleanup(d->multi);
        free(d);
        return NULL;
    }
    return d;
}

void fa_http_download_wait(fa_http_download *d, struct pollfd *fds, int nfds, int timeout_ms) {
    struct curl_waitfd extra[DOWNLOAD_MAX_FDS];
    if (nfds > DOWNLOAD_MAX_FDS)
        nfds = DOWNLOAD_MAX_FDS;
    for (int i = 0; i < nfds; i++) {
        extra[i].fd = fds[i].fd;
        extra[i].events = (short)(((fds[i].events & POLLIN) ? CURL_WAIT_POLLIN : 0) |
                                  ((fds[i].events & POLLOUT) ? CURL_WAIT_POLLOUT : 0));
        extra[i].revents = 0;
    }
    curl_multi_poll(d->multi, extra, (unsigned)nfds, timeout_ms, NULL);
    for (int i = 0; i < nfds; i++)
        fds[i].revents = (short)(((extra[i].revents & CURL_WAIT_POLLIN) ? POLLIN : 0) |
                                 ((extra[i].revents & CURL_WAIT_POLLOUT) ? POLLOUT : 0));
}

int fa_http_download_step(fa_http_download *d, fa_http_outcome *out) {
    if (!d->done) {
        int running = 0;
        CURLMcode mc = curl_multi_perform(d->multi, &running);
        CURLMsg *msg;
        int left = 0;
        while ((msg = curl_multi_info_read(d->multi, &left)) != NULL)
            if (msg->msg == CURLMSG_DONE) {
                d->done = true;
                d->result = msg->data.result;
            }
        if (mc != CURLM_OK && !d->done) {
            d->done = true;
            d->result = CURLE_FAILED_INIT;
        }
        if (!d->done)
            return 1;
    }
    long status = 0;
    curl_easy_getinfo(d->easy, CURLINFO_RESPONSE_CODE, &status);
    out->status = (int)status;
    out->complete = d->result == CURLE_OK;
    out->reason = curl_easy_strerror(d->result);
    return 0;
}

void fa_http_download_free(fa_http_download *d) {
    if (d == NULL)
        return;
    curl_multi_remove_handle(d->multi, d->easy);
    curl_easy_cleanup(d->easy);
    curl_multi_cleanup(d->multi);
    free(d);
}
