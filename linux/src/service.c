/* SPDX-License-Identifier: Apache-2.0 */
/* The loop of `run`. States of the broker link: DOWN (waiting for the next attempt), CONNECTING
 * (TCP, TLS and CONNACK pending), CONNECTED (SUBACK of the offer topic pending), SUBSCRIBED
 * (status and offers). Any failure closes the connection and waits fl_backoff_seconds(attempt),
 * the attempt counter starting again from 0 after a connection that stayed up 60 s. */
#define _POSIX_C_SOURCE 200809L
#include "service.h"

#include "components.h"
#include "firmline/fl_json.h"
#include "firmline/fl_messages.h"
#include "firmline/fl_policy.h"
#include "keys.h"
#include "log.h"
#include "mqtt.h"
#include "ota.h"
#include "renewal.h"
#include "store.h"
#include "version.h"

#include <errno.h>
#include <limits.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define IDENTITY "device.json"
#define TICK_MS 1000            /* the longest the loop sleeps */
#define ANSWER_TIMEOUT_MS 30000 /* for CONNACK and SUBACK */
#define STABLE_MS 60000         /* a connection up this long starts the attempts again from 0 */
#define MAX_ATTEMPT 16          /* fl_backoff_seconds is at its cap long before */
#define SHARED_WAIT_MS 100 /* a download and a renewal at once: each waits on its own sockets */

static const char CERT_BEGIN[] = "-----BEGIN CERTIFICATE-----";
static const char CERT_END[] = "-----END CERTIFICATE-----";

typedef enum { LINK_DOWN, LINK_CONNECTING, LINK_CONNECTED, LINK_SUBSCRIBED } link_state;

struct fa_service {
    const fa_config *cfg;
    fa_identity id;
    fa_endpoint endpoint;
    uint8_t update_key[128];
    size_t update_key_len;
    char ca_path[PATH_MAX], cert_path[PATH_MAX], key_path[PATH_MAX];
    char status_topic[128];

    fa_mqtt *mqtt; /* NULL while LINK_DOWN */
    link_state state;
    long long attempt_at, connected_at, next_attempt_at, next_status_at; /* monotonic ms */
    uint32_t failures;
    bool status_requested, reconnect_requested;
    bool lost; /* the connection failed: closed at the end of the loop turn */
    char lost_reason[FA_MQTT_ERROR_MAX + 96];

    uint32_t unreadable;   /* bit i: the version of component i could not be read last time */
    bool nothing_readable; /* the last status had nothing to report (logged once) */

    unsigned session;    /* grows at every subscription of the offer topic */
    fa_ota *ota;         /* the updates */
    fa_renewal *renewal; /* the certificate renewal */
};

static volatile sig_atomic_t stop_requested = 0;

static void on_stop_signal(int sig) {
    (void)sig;
    stop_requested = 1;
}

/* ---- Hook points: the updates and the certificate renewal --------------------------------- */

static fl_time wall_clock(void);

void fa_hook_before_connect(fa_service *s, fl_time now) {
    fa_renewal_before_connect(s->renewal, now);
}

void fa_hook_offer(fa_service *s, const char *payload, size_t len) {
    fa_ota_offer(s->ota, payload, len, wall_clock());
}

void fa_hook_tick(fa_service *s, fl_time now) {
    fa_ota_tick(s->ota, now);
    fa_renewal_tick(s->renewal, now);
}

void fa_hook_after_status(fa_service *s, fl_time now) { fa_renewal_check(s->renewal, now); }

/* ---- Helpers ------------------------------------------------------------------------------ */

static long long monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static fl_time wall_clock(void) { return (fl_time)time(NULL); }

static void sleep_ms(long long ms) {
    if (ms <= 0)
        return;
    struct timespec ts = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL); /* a signal ends it early: the loop then sees the stop */
}

static uint32_t random32(void) {
    uint32_t r = 0;
    if (RAND_bytes((unsigned char *)&r, sizeof r) != 1)
        r = (uint32_t)monotonic_ms();
    return r;
}

static int join_path(char *out, size_t size, const char *dir, const char *name) {
    int n = snprintf(out, size, "%s/%s", dir, name);
    return n > 0 && (size_t)n < size ? 0 : -1;
}

/* The seconds since boot from /proc/uptime (floor), or -1. */
static int64_t read_uptime(void) {
    FILE *f = fopen("/proc/uptime", "r");
    if (f == NULL)
        return -1;
    char buf[64];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = '\0';
    if (n == 0 || buf[0] < '0' || buf[0] > '9')
        return -1;
    errno = 0;
    char *end = NULL;
    long long v = strtoll(buf, &end, 10);
    if (errno != 0 || (*end != '.' && *end != ' ' && *end != '\n'))
        return -1;
    return v;
}

int fa_identity_load(const char *dir, fa_identity *out) {
    memset(out, 0, sizeof *out);
    char *text = NULL;
    size_t len = 0;
    if (fa_store_read(dir, IDENTITY, &text, &len) != 0)
        return -1;
    fl_json j;
    int ok = fl_json_parse(&j, text, len) == FL_OK &&
             fl_json_string(&j, "deviceId", out->device_id, sizeof out->device_id) == FL_OK &&
             fl_json_string(&j, "clientId", out->client_id, sizeof out->client_id) == FL_OK &&
             fl_json_string(&j, "topicRoot", out->topic_root, sizeof out->topic_root) == FL_OK &&
             fl_json_string(&j, "otaOfferTopic", out->ota_offer_topic,
                            sizeof out->ota_offer_topic) == FL_OK &&
             out->device_id[0] != '\0' && out->client_id[0] != '\0' && out->topic_root[0] != '\0' &&
             out->ota_offer_topic[0] != '\0';
    if (ok && fl_json_string(&j, "familyId", out->family_id, sizeof out->family_id) != FL_OK)
        out->family_id[0] = '\0'; /* registered before T178 */
    free(text);
    if (!ok)
        memset(out, 0, sizeof *out);
    return ok ? 0 : -1;
}

int fa_device_chain_update(const char *dir) {
    char *cert = NULL, *chain = NULL, *current = NULL, *wanted = NULL;
    size_t cert_len = 0, chain_len = 0, current_len = 0;
    int rc = FA_CHAIN_UNREADABLE, saved_errno = 0;
    if (fa_store_read(dir, "device.pem", &cert, &cert_len) != 0 ||
        fa_store_read(dir, "chain.pem", &chain, &chain_len) != 0)
        goto done;
    const char *begin = strstr(chain, CERT_BEGIN);
    const char *end = begin != NULL ? strstr(begin, CERT_END) : NULL;
    if (end == NULL || strstr(cert, CERT_BEGIN) == NULL)
        goto done;
    size_t first = (size_t)(end - begin) + strlen(CERT_END); /* the intermediate */
    bool newline = cert_len > 0 && cert[cert_len - 1] != '\n';
    size_t total = cert_len + newline + first + 1;
    wanted = malloc(total + 1);
    if (wanted == NULL) { /* not the identity's fault */
        rc = FA_CHAIN_UNWRITABLE;
        saved_errno = ENOMEM;
        goto done;
    }
    memcpy(wanted, cert, cert_len);
    if (newline)
        wanted[cert_len] = '\n';
    memcpy(wanted + cert_len + newline, begin, first);
    wanted[total - 1] = '\n';
    wanted[total] = '\0';
    if (fa_store_read(dir, FA_DEVICE_CHAIN, &current, &current_len) == 0 && current_len == total &&
        memcmp(current, wanted, total) == 0)
        rc = 0;
    else if (fa_store_write(dir, FA_DEVICE_CHAIN, wanted, total, 0644) == 0)
        rc = 0;
    else {
        rc = FA_CHAIN_UNWRITABLE;
        saved_errno = errno;
    }
done:
    free(cert);
    free(chain);
    free(current);
    free(wanted);
    if (rc == FA_CHAIN_UNWRITABLE)
        errno = saved_errno;
    return rc;
}

int fa_endpoint_load(const fa_config *cfg, fa_endpoint *out) {
    memset(out, 0, sizeof *out);
    char path[PATH_MAX];
    struct stat st;
    if (join_path(path, sizeof path, cfg->data_dir, FA_ENDPOINT) != 0)
        return -1;
    if (lstat(path, &st) != 0 && errno == ENOENT) { /* direct: the configuration */
        snprintf(out->https, sizeof out->https, "%s", cfg->platform_url);
        snprintf(out->https_ca, sizeof out->https_ca, "%s", cfg->ca_file);
        snprintf(out->broker, sizeof out->broker, "%s", cfg->broker_host);
        out->broker_port = cfg->broker_port;
        return 0;
    }
    char *text = NULL;
    size_t len = 0;
    int64_t port = 0;
    fl_json j;
    out->relay = true;
    int ok = fa_store_read(cfg->data_dir, FA_ENDPOINT, &text, &len) == 0 &&
             fl_json_parse(&j, text, len) == FL_OK &&
             fl_json_string(&j, "https", out->https, sizeof out->https) == FL_OK &&
             fl_json_string(&j, "broker", out->broker, sizeof out->broker) == FL_OK &&
             fl_json_int(&j, "brokerPort", &port) == FL_OK &&
             strncmp(out->https, "https://", 8) == 0 && out->https[8] != '\0' &&
             out->broker[0] != '\0' && port >= 1 && port <= 65535 &&
             join_path(out->https_ca, sizeof out->https_ca, cfg->data_dir, "root.pem") == 0;
    free(text);
    out->broker_port = (int)port;
    return ok ? 0 : -1;
}

/* ---- What the hooks can use ------------------------------------------------------------- */

const fa_config *fa_service_config(const fa_service *s) { return s->cfg; }

const fa_identity *fa_service_identity(const fa_service *s) { return &s->id; }

const fa_endpoint *fa_service_endpoint(const fa_service *s) { return &s->endpoint; }

void fa_service_identity_changed(fa_service *s) {
    fa_identity id;
    char topic[sizeof s->status_topic];
    if (fa_identity_load(s->cfg->data_dir, &id) != 0 ||
        join_path(topic, sizeof topic, id.topic_root, "status") != 0) {
        fa_log("error", "%s/%s cannot be read: the identity in use stays until a restart",
               s->cfg->data_dir, IDENTITY);
        return;
    }
    s->id = id; /* in place: what the hooks point to stays valid */
    memcpy(s->status_topic, topic, sizeof topic);
    fa_ota_identity_changed(s->ota);
}

const uint8_t *fa_service_update_key(const fa_service *s, size_t *len) {
    *len = s->update_key_len;
    return s->update_key;
}

int fa_service_publish(fa_service *s, const char *subtopic, const char *payload, size_t len) {
    char topic[256];
    int mid = 0;
    if (s->mqtt == NULL || s->lost || s->state != LINK_SUBSCRIBED ||
        join_path(topic, sizeof topic, s->id.topic_root, subtopic) != 0 ||
        fa_mqtt_publish(s->mqtt, topic, payload, len, &mid) != 0 || mid <= 0)
        return -1;
    return mid;
}

unsigned fa_service_session(const fa_service *s) { return s->session; }

bool fa_service_stopping(const fa_service *s) {
    (void)s;
    return stop_requested != 0;
}

void fa_service_request_status(fa_service *s) { s->status_requested = true; }

void fa_service_request_reconnect(fa_service *s) {
    if (s->state != LINK_DOWN) /* down: the next attempt reads the new files anyway */
        s->reconnect_requested = true;
}

/* ---- The connection ----------------------------------------------------------------------- */

static void lose(fa_service *s, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* The connection failed: it is closed at the end of this loop turn. The first reason counts. */
static void lose(fa_service *s, const char *fmt, ...) {
    if (s->lost)
        return;
    s->lost = true;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(s->lost_reason, sizeof s->lost_reason, fmt, ap);
    va_end(ap);
}

static void record_connection(fa_service *s) {
    char iso[26], json[64];
    fl_jw w;
    if (fl_time_format(wall_clock(), 0, iso) != FL_OK) {
        fa_log("warning", "the clock is out of range: %s not written", FA_CONNECTION);
        return;
    }
    fl_jw_begin(&w, json, sizeof json);
    fl_jw_string(&w, "lastConnection", iso);
    int n = fl_jw_end(&w);
    if (n < 0 || fa_store_write(s->cfg->data_dir, FA_CONNECTION, json, (size_t)n, 0644) != 0)
        fa_log("warning", "cannot write %s/%s", s->cfg->data_dir, FA_CONNECTION);
}

static void on_connect(void *ctx, int reason) {
    fa_service *s = ctx;
    if (s->state != LINK_CONNECTING)
        return;
    if (reason != 0) {
        lose(s, "the broker refused the connection: %s", fa_mqtt_reason(reason));
        return;
    }
    s->state = LINK_CONNECTED;
    s->connected_at = monotonic_ms();
    record_connection(s);
    fa_log("info", "connected to the broker %s:%d as %s", s->endpoint.broker,
           s->endpoint.broker_port, s->id.client_id);
    if (fa_mqtt_subscribe(s->mqtt, s->id.ota_offer_topic, 1) != 0)
        lose(s, "cannot subscribe to the offer topic");
}

static void on_subscribe(void *ctx, int granted) {
    fa_service *s = ctx;
    if (s->state != LINK_CONNECTED)
        return;
    if (granted < 1 || granted > 2) { /* QoS 0 or a refusal: no offer would be safe to miss */
        lose(s, "the broker refused the subscription to the offer topic: %s",
             granted >= 0x80 ? fa_mqtt_reason(granted) : "QoS 0 granted");
        return;
    }
    s->state = LINK_SUBSCRIBED;
    s->session++;
    s->status_requested = true;
    fa_log("info", "subscribed to %s (QoS %d)", s->id.ota_offer_topic, granted);
}

static void on_message(void *ctx, const char *topic, const void *payload, size_t len) {
    fa_service *s = ctx;
    if (s->state == LINK_SUBSCRIBED && strcmp(topic, s->id.ota_offer_topic) == 0)
        fa_hook_offer(s, payload, len);
}

static void on_published(void *ctx, int mid, int reason) {
    fa_service *s = ctx;
    fa_ota_published(s->ota, mid, reason);
}

static void log_endpoint(const fa_endpoint *e) {
    if (e->relay)
        fa_log("info", "through the relay: broker %s:%d, HTTPS %s (verified with root.pem)",
               e->broker, e->broker_port, e->https);
    else
        fa_log("info", "directly: broker %s:%d, HTTPS %s", e->broker, e->broker_port, e->https);
}

static bool same_endpoint(const fa_endpoint *a, const fa_endpoint *b) {
    return a->relay == b->relay && a->broker_port == b->broker_port &&
           strcmp(a->https, b->https) == 0 && strcmp(a->https_ca, b->https_ca) == 0 &&
           strcmp(a->broker, b->broker) == 0;
}

/* endpoint.json again (the command `endpoint` may have changed it): before every attempt. */
static void reload_endpoint(fa_service *s) {
    fa_endpoint e;
    if (fa_endpoint_load(s->cfg, &e) != 0) {
        fa_log("warning", "%s/%s cannot be read: the addresses in use stay", s->cfg->data_dir,
               FA_ENDPOINT);
        return;
    }
    if (!same_endpoint(&e, &s->endpoint)) {
        s->endpoint = e;
        log_endpoint(&e);
    }
}

static void start_attempt(fa_service *s) {
    fa_hook_before_connect(s, wall_clock());
    reload_endpoint(s);
    s->lost = false;
    s->lost_reason[0] = '\0';
    s->connected_at = 0;
    s->attempt_at = monotonic_ms();
    s->state = LINK_CONNECTING;
    int chain = fa_device_chain_update(s->cfg->data_dir);
    if (chain == FA_CHAIN_UNWRITABLE) {
        lose(s, "cannot write %s in %s (%s): free space or fix permissions", FA_DEVICE_CHAIN,
             s->cfg->data_dir, strerror(errno));
        return;
    }
    if (chain != 0) {
        lose(s, "the device certificate in %s cannot be read", s->cfg->data_dir);
        return;
    }
    const fa_mqtt_settings settings = {s->endpoint.broker, s->endpoint.broker_port,
                                       s->id.client_id,    s->ca_path,
                                       s->cert_path,       s->key_path};
    const fa_mqtt_events events = {on_connect, on_subscribe, on_message, on_published, s};
    char err[FA_MQTT_ERROR_MAX];
    fa_log("info", "connecting to the broker %s:%d", s->endpoint.broker, s->endpoint.broker_port);
    s->mqtt = fa_mqtt_connect(&settings, &events, err);
    if (s->mqtt == NULL)
        lose(s, "%s", err);
}

/* Closes the connection (DISCONNECT when it is up) and plans the next attempt. */
static void close_and_wait(fa_service *s) {
    bool was_up = s->state >= LINK_CONNECTED;
    fa_mqtt_close(s->mqtt);
    s->mqtt = NULL;
    long long now = monotonic_ms();
    if (s->connected_at != 0 && now - s->connected_at >= STABLE_MS)
        s->failures = 0;
    uint32_t wait = fl_backoff_seconds(s->failures, random32());
    if (s->failures < MAX_ATTEMPT)
        s->failures++;
    s->next_attempt_at = now + (long long)wait * 1000;
    s->state = LINK_DOWN;
    s->connected_at = 0;
    s->lost = false;
    s->reconnect_requested = false; /* the next connection is a new one anyway */
    if (!stop_requested)
        fa_log("warning", "%s: %s; next attempt in %u s",
               was_up ? "disconnected from the broker" : "cannot connect to the broker",
               s->lost_reason, (unsigned)wait);
}

/* ---- The status --------------------------------------------------------------------------- */

static void note_readability(fa_service *s, uint32_t unreadable) {
    const fa_config *cfg = s->cfg;
    for (int i = 0; i < cfg->component_count; i++) {
        uint32_t bit = 1u << i;
        if (((unreadable ^ s->unreadable) & bit) == 0)
            continue;
        if (unreadable & bit)
            fa_log("warning", "component %s: the version cannot be read", cfg->component[i].code);
        else
            fa_log("info", "component %s: the version can be read again", cfg->component[i].code);
    }
    s->unreadable = unreadable;
}

static void send_status(fa_service *s) {
    const fa_config *cfg = s->cfg;
    fl_time now = wall_clock();
    s->status_requested = false;
    s->next_status_at = monotonic_ms() + (long long)cfg->status_interval_s * 1000;

    char versions[FA_MAX_COMPONENTS][65];
    fl_component_version others[FA_MAX_COMPONENTS];
    const char *fw = NULL;
    size_t n = 0;
    uint32_t unreadable = 0;
    for (int i = 0; i < cfg->component_count; i++) {
        const fa_component *c = &cfg->component[i];
        if (fa_component_version(cfg, c, versions[i]) != 0) {
            unreadable |= 1u << i;
        } else if (c->main) {
            fw = versions[i];
        } else {
            others[n].code = c->code;
            others[n].version = versions[i];
            n++;
        }
    }
    note_readability(s, unreadable);
    if (fw == NULL && n == 0) {
        if (!s->nothing_readable)
            fa_log("warning", "no component version can be read: no status is sent until one can");
        s->nothing_readable = true;
        return;
    }
    s->nothing_readable = false;

    char payload[FL_STATUS_MAX + 1];
    int len = fl_status_build(payload, sizeof payload, fw, others, n, FA_AGENT_NAME_VERSION, now, 0,
                              read_uptime());
    if (len < 0) {
        fa_log("error", "the status cannot be built (error %d)", len);
        return;
    }
    if (fa_mqtt_publish(s->mqtt, s->status_topic, payload, (size_t)len, NULL) != 0) {
        lose(s, "the status cannot be sent");
        return;
    }
    fa_log("info", "status sent: fw %s, %zu other component(s)", fw != NULL ? fw : "unreadable", n);
    fa_hook_after_status(s, now);
}

/* ---- The loop ----------------------------------------------------------------------------- */

/* Waits up to timeout_ms for `fd` (the broker, -1 for none) and for the work in progress: a
 * download, a script, a renewal. False (nothing waited) when there is no such work. */
static bool wait_for_work(fa_service *s, int fd, bool want_write, int timeout_ms) {
    bool ota = fa_ota_busy(s->ota), renewal = fa_renewal_busy(s->renewal);
    if (ota && renewal && timeout_ms > SHARED_WAIT_MS)
        timeout_ms = SHARED_WAIT_MS; /* the renewal's sockets are not in the download's wait */
    if (ota)
        fa_ota_wait(s->ota, fd, want_write, timeout_ms);
    else if (renewal)
        fa_renewal_wait(s->renewal, fd, want_write, timeout_ms);
    return ota || renewal;
}

static void loop_turn(fa_service *s) {
    long long now = monotonic_ms();
    fa_hook_tick(s, wall_clock());
    if (stop_requested)
        return;
    if (s->mqtt == NULL && s->state == LINK_DOWN) {
        if (now < s->next_attempt_at) {
            long long left = s->next_attempt_at - now;
            left = left < TICK_MS ? left : TICK_MS;
            /* a download, a script or a renewal goes on without the broker */
            if (!wait_for_work(s, -1, false, (int)left))
                sleep_ms(left);
            return;
        }
        start_attempt(s);
    }
    if (s->reconnect_requested) {
        s->reconnect_requested = false;
        lose(s, "reconnecting");
    }
    if (s->state == LINK_CONNECTING && now - s->attempt_at >= ANSWER_TIMEOUT_MS)
        lose(s, "no answer (CONNACK) from the broker in %d s", ANSWER_TIMEOUT_MS / 1000);
    if (s->state == LINK_CONNECTED && now - s->connected_at >= ANSWER_TIMEOUT_MS)
        lose(s, "no answer (SUBACK) to the subscription in %d s", ANSWER_TIMEOUT_MS / 1000);
    if (!s->lost && s->state == LINK_SUBSCRIBED &&
        (s->status_requested || now >= s->next_status_at))
        send_status(s);
    if (!s->lost) {
        long long timeout = TICK_MS;
        if (s->state == LINK_SUBSCRIBED && s->next_status_at - now < timeout)
            timeout = s->next_status_at - now > 0 ? s->next_status_at - now : 0;
        /* One wait for the broker, the transfer and the script's output; then libmosquitto
         * handles what came without waiting again. */
        if (wait_for_work(s, fa_mqtt_socket(s->mqtt), fa_mqtt_want_write(s->mqtt) != 0,
                          (int)timeout))
            timeout = 0;
        char err[FA_MQTT_ERROR_MAX];
        if (fa_mqtt_loop(s->mqtt, (int)timeout, err) != 0)
            lose(s, "%s", err);
    }
    if (s->lost)
        close_and_wait(s);
}

/* device.key must be the key of device.pem: a renewal never leaves them apart (renewal.h), so a
 * difference means a damaged folder. 0, or -1 (logged). */
static int check_pair(const char *dir) {
    char *pem = NULL;
    size_t len = 0;
    int match = fa_store_read(dir, "device.pem", &pem, &len) == 0
                    ? fa_key_matches_certificate(dir, "device.key", pem, len)
                    : -1;
    free(pem);
    if (match == 1)
        return 0;
    if (match == 0)
        fa_log("error",
               "run: device.key does not match device.pem in %s and no interrupted renewal "
               "explains it: register the device again",
               dir);
    else
        fa_log("error",
               "run: device.key or device.pem in %s cannot be read: register the device "
               "again",
               dir);
    return -1;
}

static int prepare(fa_service *s, const fa_config *cfg) {
    const char *dir = cfg->data_dir;
    char path[PATH_MAX];
    struct stat st;
    s->cfg = cfg;
    errno = 0;
    if (join_path(path, sizeof path, dir, IDENTITY) != 0 || stat(path, &st) != 0) {
        if (errno == ENOENT)
            fa_log("error", "run: the device is not registered (%s is missing): run register first",
                   path);
        else
            fa_log("error", "run: cannot read %s/%s: %s", dir, IDENTITY, strerror(errno));
        return -1;
    }
    if (fa_renewal_recover(dir) != 0) /* before anything reads the identity */
        return -1;
    if (fa_identity_load(dir, &s->id) != 0) {
        fa_log("error", "run: %s cannot be read", path);
        return -1;
    }
    if (fa_update_key_load(cfg->update_key, s->update_key, sizeof s->update_key,
                           &s->update_key_len) != 0) {
        fa_log("error",
               "run: update_key %s is not a P-256 public key (the PUBLIC KEY PEM of the page "
               "\"OTA releases\")",
               cfg->update_key);
        return -1;
    }
    int stale = fa_store_remove_stale(dir);
    if (stale > 0)
        fa_log("info", "removed %d temporary file(s) left by an interrupted write", stale);
    int chain = 0;
    if (join_path(s->ca_path, sizeof s->ca_path, dir, "root.pem") != 0 ||
        join_path(s->cert_path, sizeof s->cert_path, dir, FA_DEVICE_CHAIN) != 0 ||
        join_path(s->key_path, sizeof s->key_path, dir, "device.key") != 0 ||
        join_path(s->status_topic, sizeof s->status_topic, s->id.topic_root, "status") != 0 ||
        access(s->ca_path, R_OK) != 0 || access(s->key_path, R_OK) != 0 ||
        (chain = fa_device_chain_update(dir)) == FA_CHAIN_UNREADABLE) {
        fa_log("error",
               "run: the identity in %s is incomplete (root.pem, device.key, device.pem, "
               "chain.pem): register the device again (see \"Registering again\" in the "
               "integration guide)",
               dir);
        return -1;
    }
    if (chain == FA_CHAIN_UNWRITABLE) {
        /* The identity is whole: only the disk is in the way (full after a renewal, read-only).
         * Registering again would throw a valid identity away. */
        fa_log("error",
               "run: cannot write %s in %s (%s): free space or fix permissions, then restart",
               FA_DEVICE_CHAIN, dir, strerror(errno));
        return -1;
    }
    if (check_pair(dir) != 0)
        return -1;
    if (fa_endpoint_load(cfg, &s->endpoint) != 0) {
        fa_log("error",
               "run: %s/%s cannot be read: run firmline-agent endpoint --relay <host> again, or "
               "endpoint --direct",
               dir, FA_ENDPOINT);
        return -1;
    }
    log_endpoint(&s->endpoint);
    return 0;
}

int fa_service_run(const fa_config *cfg) {
    fa_service *s = calloc(1, sizeof *s);
    if (s == NULL) {
        fa_log("error", "run: out of memory");
        return 1;
    }
    if (prepare(s, cfg) != 0) {
        free(s);
        return 1;
    }
    if (fa_mqtt_lib_init() != 0) {
        fa_log("error", "run: cannot start libmosquitto");
        free(s);
        return 1;
    }
    s->ota = fa_ota_open(s, wall_clock());
    s->renewal = s->ota != NULL ? fa_renewal_open(s) : NULL;
    if (s->renewal == NULL) {
        fa_ota_close(s->ota);
        fa_mqtt_lib_cleanup();
        free(s);
        return 1;
    }

    /* No SA_RESTART: a signal interrupts the waits, and the loop sees the flag at once. A broken
     * connection must be an error of the write, not the end of the process. */
    struct sigaction stop, ignore;
    memset(&stop, 0, sizeof stop);
    memset(&ignore, 0, sizeof ignore);
    stop.sa_handler = on_stop_signal;
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&stop.sa_mask);
    sigemptyset(&ignore.sa_mask);
    stop_requested = 0;
    sigaction(SIGTERM, &stop, NULL);
    sigaction(SIGINT, &stop, NULL);
    sigaction(SIGPIPE, &ignore, NULL);

    fa_log("info", "running as device %s", s->id.device_id);
    fa_renewal_check(s->renewal, wall_clock()); /* at start; then after each status */
    while (!stop_requested)
        loop_turn(s);

    if (s->mqtt != NULL) {
        fa_mqtt_close(s->mqtt); /* DISCONNECT with "normal disconnection" when connected */
        fa_log("info", "disconnected from the broker");
    }
    fa_renewal_close(s->renewal);
    fa_ota_close(s->ota);
    fa_mqtt_lib_cleanup();
    fa_log("info", "stopped");
    free(s);
    return 0;
}
