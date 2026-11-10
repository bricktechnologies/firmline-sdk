/* SPDX-License-Identifier: Apache-2.0 */
#include "firmline/fl_queue.h"

#include "check.h"

#include <stdio.h>
#include <string.h>

#define REL_A "8c1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b"
#define REL_B "11111111-2222-4333-8444-555555555555"
#define REL_C "66666666-7777-4888-9999-aaaaaaaaaaaa"

static fl_offer make_offer(const char *release, const char *component, const char *url,
                           fl_offer_action action, fl_time wait_until) {
    fl_offer o;
    memset(&o, 0, sizeof o);
    o.action = action;
    o.wait_until = wait_until;
    strcpy(o.release, release);
    strcpy(o.component, component);
    strcpy(o.url, url);
    return o;
}

static void queue_replaces_same_release_with_new_url(void) {
    fl_queue q;
    fl_offer a = make_offer(REL_A, "firmware", "https://x/old", FL_OFFER_INSTALL, 0);
    fl_offer b = make_offer(REL_B, "firmware", "https://x/b", FL_OFFER_INSTALL, 0);
    fl_offer a2 = make_offer("8C1F2A3B-4C5D-4E6F-8A9B-0C1D2E3F4A5B", "firmware", "https://x/new",
                             FL_OFFER_WAIT, 500);
    memset(&q, 0, sizeof q);
    CHECK_EQ_INT(fl_queue_put(&q, &a), FL_OK);
    CHECK_EQ_INT(fl_queue_put(&q, &b), FL_OK);
    CHECK_EQ_INT(fl_queue_put(&q, &a2), FL_OK);
    CHECK_EQ_INT(q.count, 2);
    /* same position, whole new offer */
    CHECK_EQ_STR(q.item[0].url, "https://x/new");
    CHECK_EQ_INT(q.item[0].action, FL_OFFER_WAIT);
    CHECK_EQ_INT(q.item[0].wait_until, 500);
    CHECK_EQ_STR(q.item[1].url, "https://x/b");
    /* only IGNORE and REJECT are refused */
    a.action = FL_OFFER_IGNORE;
    CHECK_EQ_INT(fl_queue_put(&q, &a), FL_ERR_ARG);
    a.action = FL_OFFER_REJECT;
    CHECK_EQ_INT(fl_queue_put(&q, &a), FL_ERR_ARG);
    CHECK_EQ_INT(fl_queue_put(NULL, &a), FL_ERR_ARG);
    CHECK_EQ_INT(fl_queue_put(&q, NULL), FL_ERR_ARG);
}

static void queue_keeps_arrival_order_across_components(void) {
    fl_queue q;
    fl_offer a = make_offer(REL_A, "firmware", "https://x/a", FL_OFFER_INSTALL, 0);
    fl_offer b = make_offer(REL_B, "modem", "https://x/b", FL_OFFER_INSTALL, 0);
    fl_offer c = make_offer(REL_C, "firmware", "https://x/c", FL_OFFER_INSTALL, 0);
    memset(&q, 0, sizeof q);
    CHECK_EQ_INT(fl_queue_put(&q, &a), FL_OK);
    CHECK_EQ_INT(fl_queue_put(&q, &b), FL_OK);
    CHECK_EQ_INT(fl_queue_put(&q, &c), FL_OK);
    CHECK_EQ_STR(fl_queue_next(&q, 10)->release, REL_A);
    fl_queue_remove(&q, REL_A);
    CHECK_EQ_INT(q.count, 2);
    CHECK_EQ_STR(fl_queue_next(&q, 10)->release, REL_B);
    fl_queue_remove(&q, "66666666-7777-4888-9999-AAAAAAAAAAAA"); /* ignoring case */
    CHECK_EQ_INT(q.count, 1);
    CHECK_EQ_STR(fl_queue_next(&q, 10)->release, REL_B);
    fl_queue_remove(&q, REL_C); /* not there: nothing happens */
    CHECK_EQ_INT(q.count, 1);
    fl_queue_remove(&q, REL_B);
    CHECK(fl_queue_next(&q, 10) == NULL);
}

static void queue_full_refuses_ninth(void) {
    fl_queue q;
    int i;
    fl_offer o;
    memset(&q, 0, sizeof q);
    for (i = 0; i < FL_QUEUE_MAX; i++) {
        char release[37];
        snprintf(release, sizeof release, "00000000-0000-4000-8000-%012d", i);
        o = make_offer(release, "firmware", "https://x/u", FL_OFFER_INSTALL, 0);
        CHECK_EQ_INT(fl_queue_put(&q, &o), FL_OK);
    }
    o = make_offer(REL_A, "firmware", "https://x/u", FL_OFFER_INSTALL, 0);
    CHECK_EQ_INT(fl_queue_put(&q, &o), FL_ERR_FULL);
    CHECK_EQ_INT(q.count, FL_QUEUE_MAX);
    /* a release already queued still replaces when full */
    o = make_offer("00000000-0000-4000-8000-000000000003", "firmware", "https://x/new",
                   FL_OFFER_INSTALL, 0);
    CHECK_EQ_INT(fl_queue_put(&q, &o), FL_OK);
    CHECK_EQ_STR(q.item[3].url, "https://x/new");
    /* removing makes room */
    fl_queue_remove(&q, "00000000-0000-4000-8000-000000000000");
    o = make_offer(REL_A, "firmware", "https://x/u", FL_OFFER_INSTALL, 0);
    CHECK_EQ_INT(fl_queue_put(&q, &o), FL_OK);
}

static void queue_next_skips_waiting_offers(void) {
    fl_queue q;
    fl_offer a = make_offer(REL_A, "firmware", "https://x/a", FL_OFFER_WAIT, 1000);
    fl_offer b = make_offer(REL_B, "modem", "https://x/b", FL_OFFER_INSTALL, 0);
    memset(&q, 0, sizeof q);
    CHECK(fl_queue_next(&q, 0) == NULL);
    CHECK_EQ_INT(fl_queue_put(&q, &a), FL_OK);
    CHECK(fl_queue_next(&q, 999) == NULL);
    CHECK_EQ_INT(fl_queue_put(&q, &b), FL_OK);
    CHECK_EQ_STR(fl_queue_next(&q, 999)->release, REL_B);  /* the waiting one is skipped */
    CHECK_EQ_STR(fl_queue_next(&q, 1000)->release, REL_A); /* its time came: first in arrival */
    CHECK(fl_queue_next(NULL, 0) == NULL);
}

int main(void) {
    RUN(queue_replaces_same_release_with_new_url);
    RUN(queue_keeps_arrival_order_across_components);
    RUN(queue_full_refuses_ninth);
    RUN(queue_next_skips_waiting_offers);
    return CHECK_RESULT;
}
