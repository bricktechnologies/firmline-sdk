/* SPDX-License-Identifier: Apache-2.0 */
/* The service of `firmline-agent run`: one connection to the broker, the offer topic subscribed
 * with QoS 1 before the first status, the status at every status_interval, a growing wait between
 * connection attempts, a clean stop on SIGTERM or SIGINT.
 *
 * One thread. The loop wakes at least once a second (and at each network event), so the CPU is
 * idle between events; the hooks below are where the updates (Task 9) and the certificate
 * renewal (Task 10) plug in. */
#ifndef FIRMLINE_AGENT_SERVICE_H
#define FIRMLINE_AGENT_SERVICE_H

#include "config.h"
#include "firmline/fl_common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Files of the data folder that the service reads or writes, besides those of register. */
#define FA_DEVICE_CHAIN                                                                            \
    "device-chain.pem"                  /* device.pem + the intermediate: presented to the broker */
#define FA_CONNECTION "connection.json" /* {"lastConnection": UTC ISO 8601}, for `status` */
#define FA_ENDPOINT "endpoint.json" /* {"https", "broker", "brokerPort"}: the relay, `endpoint` */

/* The identity that register (or the last renewal) saved in device.json. */
typedef struct {
    char device_id[37];
    char family_id[37]; /* "" for a device registered before T178, until a renewal brings one */
    char client_id[80];
    char topic_root[96];
    char ota_offer_topic[112];
} fa_identity;

/* Reads device.json from dir: 0, or -1 when it is missing (errno ENOENT) or cannot be read. */
int fa_identity_load(const char *dir, fa_identity *out);

/* Where the renewal, the downloads and the broker connection go: the configuration's addresses,
 * or those of a relay while endpoint.json exists. Through a relay every HTTPS request is
 * verified with the root received at registration (root.pem in the data folder), since the
 * relay's certificate is signed by the company intermediate; directly with ca_file, or the
 * system authorities when it is not set. The broker is always verified with root.pem. */
typedef struct {
    bool relay;
    char https[256];    /* the base URL: platform.url, or "https" of endpoint.json */
    char https_ca[512]; /* the CA file of HTTPS requests; "" = the system authorities */
    char broker[256];
    int broker_port;
} fa_endpoint;

/* Reads endpoint.json of cfg->data_dir, or takes the configuration when the file is missing.
 * 0, or -1 when the file exists but cannot be read or holds wrong values. */
int fa_endpoint_load(const fa_config *cfg, fa_endpoint *out);

/* Writes dir/device-chain.pem as device.pem followed by the first certificate of chain.pem (the
 * intermediate), when it is missing or different. Runs before every connection, so a renewed
 * device.pem is presented at the next one. 0; FA_CHAIN_UNREADABLE when device.pem or chain.pem
 * cannot be read or holds no certificate (the identity is incomplete); FA_CHAIN_UNWRITABLE when
 * only the write of device-chain.pem failed (a full or read-only disk: the identity is fine),
 * with errno set. */
#define FA_CHAIN_UNREADABLE (-1)
#define FA_CHAIN_UNWRITABLE (-2)
int fa_device_chain_update(const char *dir);

/* Runs the service until SIGTERM or SIGINT: 0 then. 1 when it cannot start (not registered,
 * update_key not a P-256 public key, data folder incomplete, device.key not the key of
 * device.pem, endpoint.json unreadable, libmosquitto failed). */
int fa_service_run(const fa_config *cfg);

/* ---- What the hooks can use ------------------------------------------------------------- */

typedef struct fa_service fa_service;

const fa_config *fa_service_config(const fa_service *s);
const fa_identity *fa_service_identity(const fa_service *s);
/* The addresses in use: read at start and again before every connection attempt. */
const fa_endpoint *fa_service_endpoint(const fa_service *s);

/* device.json was replaced (a renewal): the identity is read again, the family included. */
void fa_service_identity_changed(fa_service *s);
/* The update verification key as DER (SubjectPublicKeyInfo, P-256), checked at start. */
const uint8_t *fa_service_update_key(const fa_service *s, size_t *len);

/* Publishes payload on {topicRoot}/{subtopic} (for example "ota/result") with QoS 1, without
 * retain: its message id (> 0), whose PUBACK the service hands to fa_ota_published. -1 when the
 * service is not connected with the offer topic subscribed: the caller keeps the message and tries
 * again later (a tick, or after the next status). */
int fa_service_publish(fa_service *s, const char *subtopic, const char *payload, size_t len);

/* The number of the current connection with the offer topic subscribed (it grows at every
 * subscription): a message id belongs to the connection it was published on. */
unsigned fa_service_session(const fa_service *s);

/* True once SIGTERM or SIGINT has come (the loop ends at the end of this turn). */
bool fa_service_stopping(const fa_service *s);

/* A status as soon as the service is connected (for example after an installation). */
void fa_service_request_status(fa_service *s);

/* Closes the connection cleanly and connects again after the usual wait (for example with a
 * renewed certificate). Nothing while the link is down: the next attempt reads the files anyway. */
void fa_service_request_reconnect(fa_service *s);

/* ---- Hook points: the updates (ota.c) use the offer, tick and status hooks, the renewal
 * (renewal.c) the before_connect, tick and status ones. All run in the service's thread. `now` is
 * the wall clock (UTC seconds, possibly not yet synchronized); intervals use the monotonic
 * clock. ------------------------------------------------------------------------------------ */

/* Before every connection attempt, after the wait: the renewal may replace device.key and
 * device.pem here (device-chain.pem is rebuilt right after). */
void fa_hook_before_connect(fa_service *s, fl_time now);

/* A message received on otaOfferTopic. Called from inside the MQTT event handling: keep it short
 * (check and queue the offer); downloads and installations belong in fa_hook_tick. */
void fa_hook_offer(fa_service *s, const char *payload, size_t len);

/* Once per loop turn (at least once a second), connected or not. */
void fa_hook_tick(fa_service *s, fl_time now);

/* After every status published (the platform repeats an offer without an outcome only after a
 * status); the renewal is checked here too. */
void fa_hook_after_status(fa_service *s, fl_time now);

#endif
