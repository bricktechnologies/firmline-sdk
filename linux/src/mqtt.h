/* SPDX-License-Identifier: Apache-2.0 */
/* One MQTT connection to the broker, with libmosquitto: MQTT 5, clean start, keepalive 60 s, no
 * user name or password (the broker takes them from the certificate). TLS 1.2 or later; the
 * device presents its certificate with the company intermediate and verifies the broker with the
 * platform root, host name included.
 *
 * Single-threaded: the caller drives the connection with fa_mqtt_loop from its own loop (no
 * libmosquitto thread), and the events arrive as calls from inside fa_mqtt_loop. A new connection
 * is a new fa_mqtt, so certificate files replaced in between (renewal) are read again. */
#ifndef FIRMLINE_AGENT_MQTT_H
#define FIRMLINE_AGENT_MQTT_H

#include <stddef.h>

#define FA_MQTT_KEEPALIVE_S 60
#define FA_MQTT_ERROR_MAX 160

typedef struct fa_mqtt fa_mqtt;

typedef struct {
    /* CONNACK: reason 0 = accepted, otherwise the MQTT 5 reason code of the refusal. */
    void (*on_connect)(void *ctx, int reason);
    /* SUBACK of a subscription: the granted QoS (0..2), or a reason code >= 0x80. */
    void (*on_subscribe)(void *ctx, int granted);
    /* A message of a subscription. The topic is NUL-terminated; the payload is not. */
    void (*on_message)(void *ctx, const char *topic, const void *payload, size_t len);
    void *ctx;
} fa_mqtt_events;

typedef struct {
    const char *host;
    int port;
    const char *client_id;
    const char *ca_file;   /* the platform root */
    const char *cert_file; /* the device certificate, then the intermediate */
    const char *key_file;
} fa_mqtt_settings;

/* The text of an MQTT 5 reason code, for the log. */
const char *fa_mqtt_reason(int reason);

/* Around everything else, once per process. 0, or -1. */
int fa_mqtt_lib_init(void);
void fa_mqtt_lib_cleanup(void);

/* Opens the TCP connection and sends CONNECT; the TLS handshake and the CONNACK come during
 * fa_mqtt_loop. NULL with a reason in err when the connection cannot even start. */
fa_mqtt *fa_mqtt_connect(const fa_mqtt_settings *s, const fa_mqtt_events *events,
                         char err[FA_MQTT_ERROR_MAX]);

/* Waits up to timeout_ms for network traffic and handles it (events included), plus the
 * keepalive. 0 while the connection is up; -1 with a reason in err when it is gone. A signal ends
 * the wait early (0). */
int fa_mqtt_loop(fa_mqtt *m, int timeout_ms, char err[FA_MQTT_ERROR_MAX]);

/* Queues a SUBSCRIBE (no options but the QoS). 0, or -1. */
int fa_mqtt_subscribe(fa_mqtt *m, const char *topic, int qos);

/* Queues a PUBLISH with QoS 1, without retain. 0, or -1. */
int fa_mqtt_publish(fa_mqtt *m, const char *topic, const void *payload, size_t len);

/* Sends DISCONNECT (normal disconnection) when the connection is up, waits up to 2 s for it to
 * leave, then frees everything. NULL is allowed. */
void fa_mqtt_close(fa_mqtt *m);

#endif
