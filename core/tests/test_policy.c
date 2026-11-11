/* SPDX-License-Identifier: Apache-2.0 */
#include "firmline/fl_policy.h"

#include "check.h"

#include <stdint.h>

#define DAY 86400
#define NOW 1800000000 /* some time in 2027 */

static void retry_after_429_is_one_minute(void) {
    CHECK_EQ_INT(fl_download_retry_at(429, 0, NOW, NOW + 3600), NOW + 60);
    CHECK_EQ_INT(fl_download_retry_at(429, 9, NOW, NOW + 3600), NOW + 60);
    /* 0 and 5xx: 5 * 2^attempt, at most 60 s */
    CHECK_EQ_INT(fl_download_retry_at(0, 0, NOW, NOW + 3600), NOW + 5);
    CHECK_EQ_INT(fl_download_retry_at(503, 1, NOW, NOW + 3600), NOW + 10);
    CHECK_EQ_INT(fl_download_retry_at(500, 3, NOW, NOW + 3600), NOW + 40);
    CHECK_EQ_INT(fl_download_retry_at(599, 4, NOW, NOW + 3600), NOW + 60);
    CHECK_EQ_INT(fl_download_retry_at(0, 1000000, NOW, NOW + 3600), NOW + 60);
    CHECK_EQ_INT(fl_download_retry_at(0, -1, NOW, NOW + 3600), NOW + 5);
}

static void retry_stops_at_the_deadline(void) {
    CHECK_EQ_INT(fl_download_retry_at(429, 0, NOW, NOW + 60), -1);       /* equal: stop */
    CHECK_EQ_INT(fl_download_retry_at(429, 0, NOW, NOW + 61), NOW + 60); /* just before */
    CHECK_EQ_INT(fl_download_retry_at(0, 2, NOW, NOW + 20), -1);
    CHECK_EQ_INT(fl_download_retry_at(0, 2, NOW, NOW + 21), NOW + 20);
    CHECK_EQ_INT(fl_download_retry_at(503, 0, NOW, NOW - 1), -1); /* already past */
}

/* The agent passes monotonic seconds (since boot, so small numbers) and a deadline one window after
 * the link arrived: retries go on for FL_DOWNLOAD_RETRY_WINDOW seconds, whatever urlExpires and the
 * wall clock say. */
static void retries_last_one_window_from_the_link(void) {
    fl_time received = 12, deadline = received + FL_DOWNLOAD_RETRY_WINDOW;
    CHECK_EQ_INT(FL_DOWNLOAD_RETRY_WINDOW, 3600);
    CHECK_EQ_INT(fl_download_retry_at(0, 0, received, deadline), received + 5);
    CHECK_EQ_INT(fl_download_retry_at(429, 0, deadline - 61, deadline), deadline - 1);
    CHECK_EQ_INT(fl_download_retry_at(429, 0, deadline - 60, deadline), -1);
    CHECK_EQ_INT(fl_download_retry_at(503, 7, deadline - 61, deadline), deadline - 1);
    CHECK_EQ_INT(fl_download_retry_at(503, 7, deadline - 30, deadline), -1);
    CHECK_EQ_INT(fl_download_retry_at(0, 0, deadline + 1, deadline), -1); /* window over */
}

static void retry_on_404_stops_without_result(void) {
    CHECK_EQ_INT(fl_download_retry_at(404, 0, NOW, NOW + 3600), -1);
    CHECK_EQ_INT(fl_download_retry_at(403, 0, NOW, NOW + 3600), -1);
    CHECK_EQ_INT(fl_download_retry_at(410, 0, NOW, NOW + 3600), -1);
    CHECK_EQ_INT(fl_download_retry_at(200, 0, NOW, NOW + 3600), -1);
    CHECK_EQ_INT(fl_download_retry_at(600, 0, NOW, NOW + 3600), -1);
    CHECK_EQ_INT(fl_download_retry_at(-5, 0, NOW, NOW + 3600), -1);
}

static void renewal_due_from_60_days_before_expiry(void) {
    fl_time not_before = NOW - 300 * DAY, not_after = NOW + 100 * DAY;
    CHECK(!fl_renewal_due(not_before, not_after, NOW, 0));
    CHECK(!fl_renewal_due(not_before, not_after, not_after - 60 * DAY - 1, 0));
    CHECK(fl_renewal_due(not_before, not_after, not_after - 60 * DAY, 0));
    CHECK(fl_renewal_due(not_before, not_after, not_after - 1, 0));
    CHECK(!fl_renewal_due(not_before, not_after, not_after, 0)); /* expired: not a renewal */
    CHECK(!fl_renewal_due(not_before, not_after, not_after + DAY, 0));
}

static void renewal_not_twice_in_a_day(void) {
    fl_time not_before = NOW - 300 * DAY, not_after = NOW + 10 * DAY;
    CHECK(!fl_renewal_due(not_before, not_after, NOW, NOW - 1));
    CHECK(!fl_renewal_due(not_before, not_after, NOW, NOW - DAY + 1));
    CHECK(fl_renewal_due(not_before, not_after, NOW, NOW - DAY));
    CHECK(fl_renewal_due(not_before, not_after, NOW, NOW - 5 * DAY));
    CHECK(!fl_renewal_due(not_before, not_after, NOW, NOW + 100)); /* clock went back */
}

/* Review Focus 2: a clock not yet set (1970) never decides that a certificate is due. */
static void renewal_not_due_before_certificate_start(void) {
    fl_time not_before = 1782864000; /* 2026-07-01 */
    fl_time not_after = not_before + 90 * DAY;
    CHECK(!fl_renewal_due(not_before, not_after, 0, 0));
    CHECK(!fl_renewal_due(not_before, not_after, 0, -DAY));
    CHECK(!fl_renewal_due(not_before, not_after, not_before - 1, 0));
    CHECK(fl_renewal_due(not_before, not_after, not_before + 40 * DAY, 0));
    /* never overflows at the extremes */
    CHECK(!fl_renewal_due(INT64_MIN, INT64_MIN, INT64_MIN, 0));
    CHECK(!fl_renewal_due(0, INT64_MAX, INT64_MAX, INT64_MIN));
}

static void backoff_never_allows_15_connections_a_minute(void) {
    uint32_t attempt, r, i;
    const uint32_t randoms[] = {0, 1, 12345, 0x7fffffffu, UINT32_MAX};
    for (attempt = 0; attempt <= 20; attempt++) {
        for (i = 0; i < sizeof randoms / sizeof randoms[0]; i++) {
            r = fl_backoff_seconds(attempt, randoms[i]);
            CHECK(r >= 5);
            CHECK(r <= 360);
        }
    }
    CHECK(fl_backoff_seconds(UINT32_MAX, UINT32_MAX) <= 360);
    CHECK(fl_backoff_seconds(UINT32_MAX, 0) >= 5);
    /* the jitter is +-20 %: 5 s * 2^3 = 40 s -> 32..48 s; capped base 300 s -> 240..360 s */
    for (r = 0; r < 200; r++) {
        uint32_t a = fl_backoff_seconds(3, r), b = fl_backoff_seconds(10, r);
        CHECK(a >= 32 && a <= 48);
        CHECK(b >= 240 && b <= 360);
    }
    CHECK_EQ_INT(fl_backoff_seconds(3, 7), fl_backoff_seconds(3, 7)); /* deterministic */
}

int main(void) {
    RUN(retry_after_429_is_one_minute);
    RUN(retry_stops_at_the_deadline);
    RUN(retries_last_one_window_from_the_link);
    RUN(retry_on_404_stops_without_result);
    RUN(renewal_due_from_60_days_before_expiry);
    RUN(renewal_not_twice_in_a_day);
    RUN(renewal_not_due_before_certificate_start);
    RUN(backoff_never_allows_15_connections_a_minute);
    return CHECK_RESULT;
}
