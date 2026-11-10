/* SPDX-License-Identifier: Apache-2.0 */
/* Timing rules of the device: download retries, certificate renewal, broker reconnection. */
#ifndef FIRMLINE_FL_POLICY_H
#define FIRMLINE_FL_POLICY_H

#include <stdbool.h>
#include <stdint.h>

#include "fl_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* When to retry a download that ended with `http_status` (0 = network error), after `attempt`
 * earlier retries (0 for the first), at time `now`, for a link valid until `url_expires`.
 * 429: now + 60 s. 0 or 5xx: now + min(5 * 2^attempt, 60) s. Any other status: -1. A retry time
 * at or after url_expires: -1. -1 means "stop without a result": a network error or an expired
 * link is not a result for the platform. */
fl_time fl_download_retry_at(int http_status, int attempt, fl_time now, fl_time url_expires);

/* True when the device certificate should be renewed: not_before <= now < not_after,
 * now >= not_after - 60 days, and the last attempt (0 = never) is at least a day ago. A clock not
 * yet set (before not_before) never makes it due. */
bool fl_renewal_due(fl_time not_before, fl_time not_after, fl_time now, fl_time last_attempt);

/* Seconds to wait before the next broker connection after `attempt` failures (0 for the first):
 * 5 * 2^attempt capped at 300, moved by up to 20 % up or down according to `random`, never under
 * 5 (at most 12 connections a minute, under the 15 after which the broker bans). Deterministic:
 * the caller supplies the random number. Result 5..360. */
uint32_t fl_backoff_seconds(uint32_t attempt, uint32_t random);

#ifdef __cplusplus
}
#endif

#endif
