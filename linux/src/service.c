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
#include "store.h"

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

static const char CERT_BEGIN[] = "-----BEGIN CERTIFICATE-----";
static const char CERT_END[] = "-----END CERTIFICATE-----";

typedef enum { LINK_DOWN, LINK_CONNECTING, LINK_CONNECTED, LINK_SUBSCRIBED } link_state;

struct fa_service {
    const fa_config *cfg;
    fa_identity id;
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
};

static volatile sig_atomic_t stop_requested = 0;

static void on_stop_signal(int sig) {
    (void)sig;
    stop_requested = 1;
}

/* ---- Hook points: empty until Tasks 9 and 10 --------------------------------------------- */

void fa_hook_before_connect(fa_service *s, fl_time now) {
    (void)s;
    (void)now;
}

void fa_hook_offer(fa_service *s, const char *payload, size_t len) {
    (void)s;
    (void)payload;
    (void)len;
}

void fa_hook_tick(fa_service *s, fl_time now) {
    (void)s;
    (void)now;
}

void fa_hook_after_status(fa_service *s, fl_time now) {
    (void)s;
    (void)now;
}

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
    int rc = -1;
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
    if (wanted == NULL)
        goto done;
    memcpy(wanted, cert, cert_len);
    if (newline)
        wanted[cert_len] = '\n';
    memcpy(wanted + cert_len + newline, begin, first);
    wanted[total - 1] = '\n';
    wanted[total] = '\0';
    if (fa_store_read(dir, FA_DEVICE_CHAIN, &current, &current_len) == 0 && current_len == total &&
        memcmp(current, wanted, total) == 0)
        rc = 0;
    else
        rc = fa_store_write(dir, FA_DEVICE_CHAIN, wanted, total, 0644);
done:
    free(cert);
    free(chain);
    free(current);
    free(wanted);
    return rc;
}

/* ---- What the hooks can use ------------------------------------------------------------- */

const fa_config *fa_service_config(const fa_service *s) { return s->cfg; }

const fa_identity *fa_service_identity(const fa_service *s) { return &s->id; }

const uint8_t *fa_service_update_key(const fa_service *s, size_t *len) {
    *len = s->update_key_len;
    return s->update_key;
}

int fa_service_publish(fa_service *s, const char *subtopic, const char *payload, size_t len) {
    char topic[256];
    if (s->mqtt == NULL || s->lost || s->state != LINK_SUBSCRIBED ||
        join_path(topic, sizeof topic, s->id.topic_root, subtopic) != 0)
        return -1;
    return fa_mqtt_publish(s->mqtt, topic, payload, len);
}

void fa_service_request_status(fa_service *s) { s->status_requested = true; }

void fa_service_request_reconnect(fa_service *s) { s->reconnect_requested = true; }

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
    fa_log("info", "connected to the broker %s:%d as %s", s->cfg->broker_host, s->cfg->broker_port,
           s->id.client_id);
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
    s->status_requested = true;
    fa_log("info", "subscribed to %s (QoS %d)", s->id.ota_offer_topic, granted);
}

static void on_message(void *ctx, const char *topic, const void *payload, size_t len) {
    fa_service *s = ctx;
    if (s->state == LINK_SUBSCRIBED && strcmp(topic, s->id.ota_offer_topic) == 0)
        fa_hook_offer(s, payload, len);
}

static void start_attempt(fa_service *s) {
    fa_hook_before_connect(s, wall_clock());
    s->lost = false;
    s->lost_reason[0] = '\0';
    s->connected_at = 0;
    s->attempt_at = monotonic_ms();
    s->state = LINK_CONNECTING;
    if (fa_device_chain_update(s->cfg->data_dir) != 0) {
        lose(s, "the device certificate in %s cannot be read", s->cfg->data_dir);
        return;
    }
    const fa_mqtt_settings settings = {s->cfg->broker_host, s->cfg->broker_port, s->id.client_id,
                                       s->ca_path,          s->cert_path,        s->key_path};
    const fa_mqtt_events events = {on_connect, on_subscribe, on_message, s};
    char err[FA_MQTT_ERROR_MAX];
    fa_log("info", "connecting to the broker %s:%d", s->cfg->broker_host, s->cfg->broker_port);
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
    int len = fl_status_build(payload, sizeof payload, fw, others, n, now, 0, read_uptime());
    if (len < 0) {
        fa_log("error", "the status cannot be built (error %d)", len);
        return;
    }
    if (fa_mqtt_publish(s->mqtt, s->status_topic, payload, (size_t)len) != 0) {
        lose(s, "the status cannot be sent");
        return;
    }
    fa_log("info", "status sent: fw %s, %zu other component(s)", fw != NULL ? fw : "unreadable", n);
    fa_hook_after_status(s, now);
}

/* ---- The loop ----------------------------------------------------------------------------- */

static void loop_turn(fa_service *s) {
    long long now = monotonic_ms();
    fa_hook_tick(s, wall_clock());
    if (stop_requested)
        return;
    if (s->mqtt == NULL && s->state == LINK_DOWN) {
        if (now < s->next_attempt_at) {
            long long left = s->next_attempt_at - now;
            sleep_ms(left < TICK_MS ? left : TICK_MS);
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
        char err[FA_MQTT_ERROR_MAX];
        if (fa_mqtt_loop(s->mqtt, (int)timeout, err) != 0)
            lose(s, "%s", err);
    }
    if (s->lost)
        close_and_wait(s);
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
    if (join_path(s->ca_path, sizeof s->ca_path, dir, "root.pem") != 0 ||
        join_path(s->cert_path, sizeof s->cert_path, dir, FA_DEVICE_CHAIN) != 0 ||
        join_path(s->key_path, sizeof s->key_path, dir, "device.key") != 0 ||
        join_path(s->status_topic, sizeof s->status_topic, s->id.topic_root, "status") != 0 ||
        access(s->ca_path, R_OK) != 0 || access(s->key_path, R_OK) != 0 ||
        fa_device_chain_update(dir) != 0) {
        fa_log("error",
               "run: the identity in %s is incomplete (root.pem, device.key, device.pem, "
               "chain.pem): register the device again",
               dir);
        return -1;
    }
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
    while (!stop_requested)
        loop_turn(s);

    if (s->mqtt != NULL) {
        fa_mqtt_close(s->mqtt); /* DISCONNECT with "normal disconnection" when connected */
        fa_log("info", "disconnected from the broker");
    }
    fa_mqtt_lib_cleanup();
    fa_log("info", "stopped");
    free(s);
    return 0;
}
