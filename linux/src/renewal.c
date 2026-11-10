/* SPDX-License-Identifier: Apache-2.0 */
/* The certificate renewal of `run`; the order of the files is described in renewal.h. Nothing of
 * the request or the answer is logged: no key, CSR, certificate or proof; only dates, HTTP
 * statuses, the platform's code and libcurl's reason. */
#define _POSIX_C_SOURCE 200809L
#include "renewal.h"

#include "firmline/fl_json.h"
#include "firmline/fl_messages.h"
#include "firmline/fl_policy.h"
#include "http.h"
#include "keys.h"
#include "log.h"
#include "store.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

#define NEW_KEY "renewal-new.key"
#define REQUEST "renewal-request.json"
#define COMMIT "renewal-commit"
#define RENEWAL_PATH "/api/v1/provisioning/renewal"
#define CSR_MAX 4096
#define REQUEST_MAX 16384
#define ROOT_MAX 8192

static const char CERT_BEGIN[] = "-----BEGIN CERTIFICATE-----";
static const char CERT_END[] = "-----END CERTIFICATE-----";

/* Pending name -> live name, in the order of the renames. */
static const struct {
    const char *pending, *live;
} SWAP[] = {
    {"renewal-device.pem", "device.pem"},   {"renewal-chain.pem", "chain.pem"},
    {"renewal-root.pem", "root.pem"},       {NEW_KEY, "device.key"},
    {"renewal-device.json", "device.json"},
};
#define SWAP_COUNT (sizeof SWAP / sizeof SWAP[0])

struct fa_renewal {
    fa_service *svc;
    const char *dir;
    fa_http_download *http; /* the request in flight, or NULL */
    char *body;             /* its answer so far */
    size_t len;
    bool too_long;
    bool swap_pending;      /* the marker is written but a rename failed: again before connecting */
    bool expired_logged;    /* "expired, register again" said once */
    bool unreadable_logged; /* "device.pem cannot be read" said once */
};

/* ---- Files -------------------------------------------------------------------------------- */

static bool exists(const char *dir, const char *name) {
    char path[PATH_MAX];
    struct stat st;
    int n = snprintf(path, sizeof path, "%s/%s", dir, name);
    return n > 0 && (size_t)n < sizeof path && lstat(path, &st) == 0;
}

static void remove_quietly(const char *dir, const char *name) {
    if (fa_store_remove(dir, name) != 0)
        fa_log("warning", "cannot remove %s/%s: %s", dir, name, strerror(errno));
}

/* The renames of step 3, then the marker and the request. A pending file already missing was
 * renamed before (a crash in the middle). 0, or -1 (logged): the marker stays. */
static int finish_swap(const char *dir) {
    for (size_t i = 0; i < SWAP_COUNT; i++) {
        errno = 0;
        if (fa_store_rename(dir, SWAP[i].pending, SWAP[i].live) == 0 || errno == ENOENT)
            continue;
        fa_log("error", "certificate renewal: cannot rename %s/%s to %s: %s", dir, SWAP[i].pending,
               SWAP[i].live, strerror(errno));
        return -1;
    }
    if (fa_store_remove(dir, COMMIT) != 0) {
        fa_log("error", "certificate renewal: cannot remove %s/%s: %s", dir, COMMIT,
               strerror(errno));
        return -1;
    }
    remove_quietly(dir, REQUEST); /* left over, it is removed at the next start */
    return 0;
}

static void remove_pending_identity(const char *dir) {
    for (size_t i = 0; i < SWAP_COUNT; i++)
        if (strcmp(SWAP[i].pending, NEW_KEY) != 0)
            remove_quietly(dir, SWAP[i].pending);
}

int fa_renewal_recover(const char *dir) {
    if (exists(dir, COMMIT)) {
        if (finish_swap(dir) != 0) {
            fa_log("error", "run: the certificate renewal interrupted in %s cannot be finished",
                   dir);
            return -1;
        }
        fa_log("info", "finished the certificate renewal interrupted by a stop: the new "
                       "certificate is in use");
        return 0;
    }
    /* Stopped before the marker: the live files are the old pair, still valid. */
    remove_pending_identity(dir);
    bool key = exists(dir, NEW_KEY), request = exists(dir, REQUEST);
    if (key != request) { /* one written, the other not: a new request is made when due */
        remove_quietly(dir, NEW_KEY);
        remove_quietly(dir, REQUEST);
    }
    return 0;
}

/* ---- State -------------------------------------------------------------------------------- */

static fl_time load_last_attempt(const fa_renewal *r) {
    char *text = NULL, iso[32];
    size_t len = 0;
    fl_time t = 0;
    fl_json j;
    if (fa_store_read(r->dir, FA_RENEWAL_STATE, &text, &len) == 0 &&
        fl_json_parse(&j, text, len) == FL_OK &&
        fl_json_string(&j, "lastAttempt", iso, sizeof iso) == FL_OK &&
        fl_time_parse(iso, strlen(iso), &t) != FL_OK)
        t = 0;
    free(text);
    return t;
}

static void save_last_attempt(const fa_renewal *r, fl_time now) {
    char iso[26], json[64];
    fl_jw w;
    int n = -1;
    if (fl_time_format(now, 0, iso) == FL_OK) {
        fl_jw_begin(&w, json, sizeof json);
        fl_jw_string(&w, "lastAttempt", iso);
        n = fl_jw_end(&w);
    }
    if (n < 0 || fa_store_write(r->dir, FA_RENEWAL_STATE, json, (size_t)n, 0644) != 0)
        fa_log("warning", "cannot write %s/%s", r->dir, FA_RENEWAL_STATE);
}

static void drop_pending(fa_renewal *r) {
    remove_quietly(r->dir, NEW_KEY);
    remove_quietly(r->dir, REQUEST);
}

static void format_time(fl_time t, char iso[26]) {
    if (fl_time_format(t, 0, iso) != FL_OK)
        snprintf(iso, 26, "(out of range)");
}

/* notBefore and notAfter of device.pem. 0, or -1. */
static int validity(const fa_renewal *r, fl_time *not_before, fl_time *not_after) {
    char *pem = NULL;
    size_t len = 0;
    int rc = fa_store_read(r->dir, "device.pem", &pem, &len) == 0
                 ? fa_certificate_validity(pem, len, not_before, not_after)
                 : -1;
    free(pem);
    return rc;
}

/* ---- The request -------------------------------------------------------------------------- */

static int on_bytes(void *ctx, int status, int64_t range_start, const void *data, size_t len) {
    fa_renewal *r = ctx;
    (void)status;
    (void)range_start;
    if (len > FA_HTTP_BODY_MAX - r->len) {
        r->too_long = true;
        return -1;
    }
    char *grown = realloc(r->body, r->len + len + 1);
    if (grown == NULL)
        return -1;
    memcpy(grown + r->len, data, len);
    r->len += len;
    grown[r->len] = '\0';
    r->body = grown;
    return 0;
}

/* Sends renewal-request.json as it is on disk. */
static void send_saved(fa_renewal *r) {
    const fa_endpoint *e = fa_service_endpoint(r->svc);
    char url[512], *body = NULL;
    size_t len = 0, base = strlen(e->https);
    while (base > 0 && e->https[base - 1] == '/')
        base--;
    int n = snprintf(url, sizeof url, "%.*s%s", (int)base, e->https, RENEWAL_PATH);
    if (n < 0 || (size_t)n >= sizeof url || fa_store_read(r->dir, REQUEST, &body, &len) != 0) {
        fa_log("error", "certificate renewal: %s/%s cannot be read; next try in a day", r->dir,
               REQUEST);
        free(body);
        drop_pending(r);
        return;
    }
    r->len = 0;
    r->too_long = false;
    r->http = fa_http_post_start(url, e->https_ca, body, on_bytes, r);
    free(body);
    if (r->http == NULL)
        fa_log("warning", "certificate renewal: the request cannot start; the same request goes "
                          "again at the next check");
}

/* A new key, its CSR, the proof (the current key's signature of the SHA-256 of the exact CSR
 * bytes) and the body, saved before anything is sent. */
static void start_new(fa_renewal *r, fl_time now, fl_time not_after) {
    char csr[CSR_MAX], iso[26];
    char *cert = NULL, *body = malloc(REQUEST_MAX);
    size_t cert_len = 0;
    uint8_t hash[32], proof[64];
    int n = -1;
    if (body != NULL && fa_key_generate(r->dir, NEW_KEY) == 0 &&
        fa_csr_create(r->dir, NEW_KEY, csr, sizeof csr) == 0 &&
        fa_store_read(r->dir, "device.pem", &cert, &cert_len) == 0 &&
        fl_sha256((const uint8_t *)csr, strlen(csr), hash) == FL_OK &&
        fa_sign_sha256(r->dir, "device.key", hash, proof) == 0)
        n = fl_renewal_body(body, REQUEST_MAX, cert, csr, proof);
    if (n <= 0 || fa_store_write(r->dir, REQUEST, body, (size_t)n, 0600) != 0) {
        /* A local failure (no space, no entropy): tried again at the next check. */
        fa_log("error", "certificate renewal: the request cannot be prepared in %s", r->dir);
        drop_pending(r);
    } else {
        save_last_attempt(r, now); /* the daily limit counts from the request made */
        format_time(not_after, iso);
        fa_log("info", "renewing the device certificate (valid until %s)", iso);
        send_saved(r);
    }
    free(cert);
    free(body);
}

/* ---- The answer --------------------------------------------------------------------------- */

static void keep(const char *why) {
    fa_log("warning", "certificate renewal: %s; the same request goes again at the next check",
           why);
}

/* A code as the platform writes them (letters, digits, '_', '-', '.'): safe in the log. */
static bool plain_code(const char *code) {
    if (code[0] == '\0')
        return false;
    for (const char *p = code; *p != '\0'; p++)
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-' && *p != '.')
            return false;
    return true;
}

static void refused(fa_renewal *r, fl_time now, const char *code, int status) {
    fa_log("warning",
           "certificate renewal refused: %s (HTTP %d); the current certificate stays, next try "
           "in a day",
           code, status);
    drop_pending(r);
    save_last_attempt(r, now);
}

/* The last certificate of the chain (the platform root), up to its END line, plus a newline. */
static int last_certificate(const char *chain, char *out, size_t cap) {
    const char *begin = NULL;
    for (const char *p = chain; (p = strstr(p, CERT_BEGIN)) != NULL; p++)
        begin = p;
    const char *end = begin != NULL ? strstr(begin, CERT_END) : NULL;
    if (end == NULL)
        return -1;
    size_t n = (size_t)(end - begin) + strlen(CERT_END);
    if (n + 2 > cap)
        return -1;
    memcpy(out, begin, n);
    out[n] = '\n';
    out[n + 1] = '\0';
    return 0;
}

/* Step 1: the new identity under the pending names. 0, or -1. */
static int write_pending(const fa_renewal *r, const fl_provisioned *p, const char *root) {
    const fa_identity *id = fa_service_identity(r->svc);
    char json[1024];
    fl_jw w;
    fl_jw_begin(&w, json, sizeof json);
    fl_jw_string(&w, "deviceId", p->device_id);
    /* The family of the answer (T178); an answer without one keeps the one the device has. */
    fl_jw_string(&w, "familyId", p->family_id[0] != '\0' ? p->family_id : id->family_id);
    fl_jw_string(&w, "clientId", p->client_id);
    fl_jw_string(&w, "topicRoot", p->topic_root);
    fl_jw_string(&w, "otaOfferTopic", p->ota_offer_topic);
    int n = fl_jw_end(&w);
    const char *dir = r->dir;
    return n > 0 &&
                   fa_store_write(dir, SWAP[0].pending, p->certificate, strlen(p->certificate),
                                  0644) == 0 &&
                   fa_store_write(dir, SWAP[1].pending, p->chain, strlen(p->chain), 0644) == 0 &&
                   fa_store_write(dir, SWAP[2].pending, root, strlen(root), 0644) == 0 &&
                   fa_store_write(dir, SWAP[4].pending, json, (size_t)n, 0644) == 0
               ? 0
               : -1;
}

/* The swap is complete: the service reads the new identity and connects again with it. */
static void completed(fa_renewal *r, fl_time now) {
    char iso[26] = "(unknown)";
    fl_time not_before = 0, not_after = 0;
    r->swap_pending = false;
    save_last_attempt(r, now);
    if (validity(r, &not_before, &not_after) == 0)
        format_time(not_after, iso);
    fa_log("info", "device certificate renewed: valid until %s; connecting again with it", iso);
    fa_service_identity_changed(r->svc);
    fa_service_request_reconnect(r->svc);
}

static void issued(fa_renewal *r, fl_time now) {
    char *pem = malloc(FA_HTTP_BODY_MAX), *root = malloc(ROOT_MAX);
    fl_provisioned p;
    const fa_identity *id = fa_service_identity(r->svc);
    if (pem == NULL || root == NULL ||
        fl_provisioned_parse(r->body, r->len, pem, FA_HTTP_BODY_MAX, &p) != FL_OK ||
        strstr(p.certificate, CERT_BEGIN) == NULL ||
        last_certificate(p.chain, root, ROOT_MAX) != 0) {
        keep("the answer cannot be read"); /* a 200 garbled on the way: the same answer again */
        goto done;
    }
    if (strcasecmp(p.device_id, id->device_id) != 0) {
        fa_log("error", "certificate renewal: the answer is for device %s, not %s", p.device_id,
               id->device_id);
        refused(r, now, "another_device", 200);
        goto done;
    }
    int match = fa_key_matches_certificate(r->dir, NEW_KEY, p.certificate, strlen(p.certificate));
    if (match < 0) {
        keep("the certificate of the answer cannot be read");
        goto done;
    }
    if (match == 0) {
        fa_log("error",
               "certificate renewal: the certificate of the answer is not for the new key");
        refused(r, now, "certificate_key_mismatch", 200);
        goto done;
    }
    if (write_pending(r, &p, root) != 0) {
        remove_pending_identity(r->dir);
        keep("the new certificate cannot be written");
        goto done;
    }
    /* Step 2. A write reported as failed may still have renamed the marker into place (the
     * folder sync failed): the marker on disk decides. */
    if (fa_store_write(r->dir, COMMIT, "", 0, 0644) != 0 && !exists(r->dir, COMMIT)) {
        remove_pending_identity(r->dir);
        keep("the new certificate cannot be committed");
        goto done;
    }
    if (finish_swap(r->dir) != 0) {
        r->swap_pending = true; /* the old key may already be replaced: before connecting */
        fa_log("error", "certificate renewal: the new certificate is not fully in place; trying "
                        "again before the next connection");
        goto done;
    }
    completed(r, now);
done:
    free(pem);
    free(root);
}

void fa_renewal_tick(fa_renewal *r, fl_time now) {
    if (r->http == NULL)
        return;
    fa_http_outcome out;
    if (fa_http_download_step(r->http, &out) == 1)
        return;
    int status = out.status;
    char why[160];
    if (r->too_long)
        snprintf(why, sizeof why, "the answer is longer than %d bytes", FA_HTTP_BODY_MAX);
    else
        snprintf(why, sizeof why, "no answer (%s)", out.reason);
    bool complete = out.complete;
    fa_http_download_free(r->http);
    r->http = NULL;

    if (!complete || status <= 0) {
        keep(why);
    } else if (status == 200) {
        issued(r, now);
    } else if (status == 429 || status >= 500) {
        snprintf(why, sizeof why, "the platform answered HTTP %d", status);
        keep(why);
    } else {
        char code[64];
        if (fl_problem_code(r->body, r->len, code) != FL_OK || !plain_code(code))
            snprintf(code, sizeof code, "http_%d", status);
        refused(r, now, code, status);
    }
    free(r->body);
    r->body = NULL;
    r->len = 0;
}

/* ---- Life cycle --------------------------------------------------------------------------- */

fa_renewal *fa_renewal_open(fa_service *s) {
    fa_renewal *r = calloc(1, sizeof *r);
    if (r == NULL || fl_init() != FL_OK) {
        fa_log("error", "run: the certificate renewal cannot start");
        free(r);
        return NULL;
    }
    r->svc = s;
    r->dir = fa_service_config(s)->data_dir;
    return r;
}

void fa_renewal_close(fa_renewal *r) {
    if (r == NULL)
        return;
    fa_http_download_free(r->http);
    free(r->body);
    free(r);
}

void fa_renewal_check(fa_renewal *r, fl_time now) {
    if (r->http != NULL || r->swap_pending)
        return;
    fl_time not_before = 0, not_after = 0;
    if (validity(r, &not_before, &not_after) != 0) {
        if (!r->unreadable_logged)
            fa_log("error", "certificate renewal: %s/device.pem cannot be read", r->dir);
        r->unreadable_logged = true;
        return;
    }
    r->unreadable_logged = false;
    bool key = exists(r->dir, NEW_KEY), request = exists(r->dir, REQUEST);
    if (now >= not_after) {
        if (!r->expired_logged) {
            char iso[26];
            format_time(not_after, iso);
            fa_log("error",
                   "the device certificate expired on %s and cannot be renewed: register the "
                   "device again with a new token",
                   iso);
        }
        r->expired_logged = true;
        if (key || request)
            drop_pending(r);
        return;
    }
    if (now < not_before) /* the clock is not set yet (a cold boot without RTC): nothing */
        return;
    if (key && request) { /* an answer lost: the same bytes again */
        fa_log("info", "certificate renewal: sending the saved request again");
        send_saved(r);
        return;
    }
    if (key || request)
        drop_pending(r);
    fl_time last = load_last_attempt(r);
    if (last > now) /* saved with a clock that was wrong then */
        last = 0;
    if (fl_renewal_due(not_before, not_after, now, last))
        start_new(r, now, not_after);
}

void fa_renewal_before_connect(fa_renewal *r, fl_time now) {
    if (r->swap_pending && finish_swap(r->dir) == 0)
        completed(r, now);
}

bool fa_renewal_busy(const fa_renewal *r) { return r->http != NULL; }

void fa_renewal_wait(fa_renewal *r, int fd, bool want_write, int timeout_ms) {
    struct pollfd fds[1];
    int n = 0;
    if (fd >= 0)
        fds[n++] = (struct pollfd){fd, (short)(POLLIN | (want_write ? POLLOUT : 0)), 0};
    fa_http_download_wait(r->http, fds, n, timeout_ms);
}
