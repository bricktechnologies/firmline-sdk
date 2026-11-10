/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "http.h"

#include "log.h"

#include <curl/curl.h>
#include <openssl/crypto.h>
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
