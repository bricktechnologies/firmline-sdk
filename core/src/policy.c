/* SPDX-License-Identifier: Apache-2.0 */
#include "firmline/fl_policy.h"

#define DAY_SECONDS ((fl_time)86400)
#define RENEWAL_WINDOW ((fl_time)60 * 86400)

fl_time fl_download_retry_at(int http_status, int attempt, fl_time now, fl_time url_expires) {
    fl_time delay;
    fl_time retry;
    if (http_status == 429) {
        delay = 60;
    } else if (http_status == 0 || (http_status >= 500 && http_status <= 599)) {
        int shift = attempt < 0 ? 0 : (attempt > 4 ? 4 : attempt); /* 5 * 2^4 = 80, over the cap */
        delay = (fl_time)5 << shift;
        if (delay > 60)
            delay = 60;
    } else {
        return -1;
    }
    if (now > INT64_MAX - delay)
        return -1;
    retry = now + delay;
    return retry >= url_expires ? -1 : retry;
}

bool fl_renewal_due(fl_time not_before, fl_time not_after, fl_time now, fl_time last_attempt) {
    if (now < not_before || now >= not_after)
        return false;
    if (not_after < INT64_MIN + RENEWAL_WINDOW || now < not_after - RENEWAL_WINDOW)
        return false;
    /* last_attempt 0: never tried. now >= last + 1 day, written so that it cannot overflow. */
    if (last_attempt != 0 && (now < INT64_MIN + DAY_SECONDS || last_attempt > now - DAY_SECONDS))
        return false;
    return true;
}

uint32_t fl_backoff_seconds(uint32_t attempt, uint32_t random) {
    uint32_t base = 5u << (attempt > 6 ? 6 : attempt); /* 5 * 2^6 = 320: over the cap */
    uint32_t jitter;
    int64_t result;
    if (base > 300)
        base = 300;
    jitter = base / 5;
    result = (int64_t)base + (int64_t)(random % (2 * jitter + 1)) - (int64_t)jitter;
    return result < 5 ? 5u : (uint32_t)result;
}
