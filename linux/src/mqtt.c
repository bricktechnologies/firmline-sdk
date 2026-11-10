/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "mqtt.h"

#include "log.h"

#include <errno.h>
#include <mosquitto.h>
#include <mqtt_protocol.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CLOSE_WAIT_MS 2000
#define CLOSE_STEP_MS 100

struct fa_mqtt {
    struct mosquitto *mosq;
    fa_mqtt_events events;
    bool connected;                /* CONNACK accepted and not yet disconnected */
    int disconnect_reason;         /* reason of a DISCONNECT from the broker (>= 0x80), or 0 */
    char error[FA_MQTT_ERROR_MAX]; /* the first error libmosquitto logged (TLS), or "" */
};

/* The key file is never encrypted: never ask for a pass phrase (OpenSSL would prompt). */
static int no_pass_phrase(char *buf, int size, int rwflag, void *userdata) {
    (void)buf;
    (void)size;
    (void)rwflag;
    (void)userdata;
    return 0;
}

static void on_connect(struct mosquitto *mosq, void *obj, int reason, int flags,
                       const mosquitto_property *props) {
    (void)mosq;
    (void)flags;
    (void)props;
    fa_mqtt *m = obj;
    m->connected = reason == 0;
    m->events.on_connect(m->events.ctx, reason);
}

static void on_disconnect(struct mosquitto *mosq, void *obj, int reason,
                          const mosquitto_property *props) {
    (void)mosq;
    (void)props;
    fa_mqtt *m = obj;
    m->connected = false;
    /* A DISCONNECT of the broker carries an MQTT 5 reason code (>= 0x80 for an error); a
     * connection lost gives a small libmosquitto error number instead. */
    if (reason >= 0x80)
        m->disconnect_reason = reason;
}

static void on_subscribe(struct mosquitto *mosq, void *obj, int mid, int count, const int *granted,
                         const mosquitto_property *props) {
    (void)mosq;
    (void)mid;
    (void)props;
    fa_mqtt *m = obj;
    m->events.on_subscribe(m->events.ctx, count > 0 ? granted[0] : MQTT_RC_UNSPECIFIED);
}

static void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg,
                       const mosquitto_property *props) {
    (void)mosq;
    (void)props;
    fa_mqtt *m = obj;
    if (msg->topic != NULL && msg->payloadlen >= 0)
        m->events.on_message(m->events.ctx, msg->topic, msg->payload, (size_t)msg->payloadlen);
}

static void on_publish(struct mosquitto *mosq, void *obj, int mid, int reason,
                       const mosquitto_property *props) {
    (void)mosq;
    (void)props;
    fa_mqtt *m = obj;
    if (reason >= 0x80)
        fa_log("warning", "the broker refused message %d: %s", mid,
               mosquitto_reason_string(reason));
    if (m->events.on_published != NULL)
        m->events.on_published(m->events.ctx, mid, reason);
}

/* libmosquitto logs the reason of a TLS failure (OpenSSL's error text, no key or certificate):
 * the first error is kept for the line that reports the failure. */
static void on_log(struct mosquitto *mosq, void *obj, int level, const char *text) {
    (void)mosq;
    fa_mqtt *m = obj;
    if (level == MOSQ_LOG_ERR && m->error[0] == '\0' && text != NULL)
        snprintf(m->error, sizeof m->error, "%s", text);
}

static void describe(char err[FA_MQTT_ERROR_MAX], int rc, int saved_errno) {
    if (rc == MOSQ_ERR_ERRNO)
        snprintf(err, FA_MQTT_ERROR_MAX, "%s", strerror(saved_errno));
    else
        snprintf(err, FA_MQTT_ERROR_MAX, "%s", mosquitto_strerror(rc));
    size_t n = strlen(err);
    if (n > 0 && err[n - 1] == '.') /* the caller's line goes on after it */
        err[n - 1] = '\0';
}

const char *fa_mqtt_reason(int reason) { return mosquitto_reason_string(reason); }

int fa_mqtt_lib_init(void) { return mosquitto_lib_init() == MOSQ_ERR_SUCCESS ? 0 : -1; }

void fa_mqtt_lib_cleanup(void) { mosquitto_lib_cleanup(); }

fa_mqtt *fa_mqtt_connect(const fa_mqtt_settings *s, const fa_mqtt_events *events,
                         char err[FA_MQTT_ERROR_MAX]) {
    err[0] = '\0';
    fa_mqtt *m = calloc(1, sizeof *m);
    if (m == NULL) {
        snprintf(err, FA_MQTT_ERROR_MAX, "out of memory");
        return NULL;
    }
    m->events = *events;
    m->mosq = mosquitto_new(s->client_id, true, m); /* clean start */
    if (m->mosq == NULL) {
        snprintf(err, FA_MQTT_ERROR_MAX, "cannot create the MQTT client");
        free(m);
        return NULL;
    }
    struct mosquitto *q = m->mosq;
    mosquitto_connect_v5_callback_set(q, on_connect);
    mosquitto_disconnect_v5_callback_set(q, on_disconnect);
    mosquitto_subscribe_v5_callback_set(q, on_subscribe);
    mosquitto_message_v5_callback_set(q, on_message);
    mosquitto_publish_v5_callback_set(q, on_publish);
    mosquitto_log_callback_set(q, on_log);

    int rc = mosquitto_int_option(q, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);
    if (rc == MOSQ_ERR_SUCCESS)
        rc = mosquitto_tls_set(q, s->ca_file, NULL, s->cert_file, s->key_file, no_pass_phrase);
    if (rc == MOSQ_ERR_SUCCESS)
        rc = mosquitto_tls_opts_set(q, 1 /* SSL_VERIFY_PEER */, "tlsv1.2", NULL);
    if (rc == MOSQ_ERR_SUCCESS)
        rc = mosquitto_tls_insecure_set(q, false); /* the broker's name is checked */
    int saved_errno = 0;
    if (rc == MOSQ_ERR_SUCCESS) {
        errno = 0;
        rc = mosquitto_connect(q, s->host, s->port, FA_MQTT_KEEPALIVE_S);
        saved_errno = errno;
    }
    if (rc != MOSQ_ERR_SUCCESS) {
        if (m->error[0] != '\0')
            snprintf(err, FA_MQTT_ERROR_MAX, "%s", m->error);
        else
            describe(err, rc, saved_errno);
        mosquitto_destroy(q);
        free(m);
        return NULL;
    }
    return m;
}

int fa_mqtt_loop(fa_mqtt *m, int timeout_ms, char err[FA_MQTT_ERROR_MAX]) {
    err[0] = '\0';
    errno = 0;
    int rc = mosquitto_loop(m->mosq, timeout_ms, 1);
    int saved_errno = errno;
    if (rc == MOSQ_ERR_SUCCESS)
        return 0;
    m->connected = false;
    if (m->disconnect_reason != 0)
        snprintf(err, FA_MQTT_ERROR_MAX, "the broker disconnected: %s",
                 mosquitto_reason_string(m->disconnect_reason));
    else if (m->error[0] != '\0')
        snprintf(err, FA_MQTT_ERROR_MAX, "%s", m->error);
    else
        describe(err, rc, saved_errno);
    return -1;
}

int fa_mqtt_subscribe(fa_mqtt *m, const char *topic, int qos) {
    return mosquitto_subscribe(m->mosq, NULL, topic, qos) == MOSQ_ERR_SUCCESS ? 0 : -1;
}

int fa_mqtt_publish(fa_mqtt *m, const char *topic, const void *payload, size_t len, int *mid) {
    if (len > (size_t)MQTT_MAX_PAYLOAD)
        return -1;
    return mosquitto_publish(m->mosq, mid, topic, (int)len, payload, 1, false) == MOSQ_ERR_SUCCESS
               ? 0
               : -1;
}

int fa_mqtt_socket(fa_mqtt *m) { return m != NULL ? mosquitto_socket(m->mosq) : -1; }

int fa_mqtt_want_write(fa_mqtt *m) { return m != NULL && mosquitto_want_write(m->mosq); }

void fa_mqtt_close(fa_mqtt *m) {
    if (m == NULL)
        return;
    if (m->connected &&
        mosquitto_disconnect_v5(m->mosq, MQTT_RC_NORMAL_DISCONNECTION, NULL) == MOSQ_ERR_SUCCESS) {
        /* Until the DISCONNECT has left and libmosquitto closed the socket. */
        for (int waited = 0; waited < CLOSE_WAIT_MS; waited += CLOSE_STEP_MS)
            if (mosquitto_loop(m->mosq, CLOSE_STEP_MS, 1) != MOSQ_ERR_SUCCESS)
                break;
    }
    mosquitto_destroy(m->mosq);
    free(m);
}
