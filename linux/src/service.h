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

/* The identity that register saved in device.json. */
typedef struct {
    char device_id[37];
    char family_id[37]; /* "" for a device registered before T178 */
    char client_id[80];
    char topic_root[96];
    char ota_offer_topic[112];
} fa_identity;

/* Reads device.json from dir: 0, or -1 when it is missing (errno ENOENT) or cannot be read. */
int fa_identity_load(const char *dir, fa_identity *out);

/* Writes dir/device-chain.pem as device.pem followed by the first certificate of chain.pem (the
 * intermediate), when it is missing or different. Runs before every connection, so a renewed
 * device.pem is presented at the next one. 0, or -1. */
int fa_device_chain_update(const char *dir);

/* Runs the service until SIGTERM or SIGINT: 0 then. 1 when it cannot start (not registered,
 * update_key not a P-256 public key, data folder incomplete, libmosquitto failed). */
int fa_service_run(const fa_config *cfg);

/* ---- What the hooks can use ------------------------------------------------------------- */

typedef struct fa_service fa_service;

const fa_config *fa_service_config(const fa_service *s);
const fa_identity *fa_service_identity(const fa_service *s);
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
 * renewed certificate). */
void fa_service_request_reconnect(fa_service *s);

/* ---- Hook points (empty in Task 8; Task 9 fills the offer, tick and status hooks, Task 10 the
 * tick and before_connect ones). All run in the service's thread. `now` is the wall clock (UTC
 * seconds, possibly not yet synchronized); intervals use the monotonic clock. ---------------- */

/* Before every connection attempt, after the wait: the renewal may replace device.key and
 * device.pem here (device-chain.pem is rebuilt right after). */
void fa_hook_before_connect(fa_service *s, fl_time now);

/* A message received on otaOfferTopic. Called from inside the MQTT event handling: keep it short
 * (check and queue the offer); downloads and installations belong in fa_hook_tick. */
void fa_hook_offer(fa_service *s, const char *payload, size_t len);

/* Once per loop turn (at least once a second), connected or not. */
void fa_hook_tick(fa_service *s, fl_time now);

/* After every status published (the platform repeats an offer without an outcome only after a
 * status). */
void fa_hook_after_status(fa_service *s, fl_time now);

#endif
