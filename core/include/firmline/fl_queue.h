/* SPDX-License-Identifier: Apache-2.0 */
/* The offers a device has accepted and not yet installed, in arrival order. */
#ifndef FIRMLINE_FL_QUEUE_H
#define FIRMLINE_FL_QUEUE_H

#include "fl_offer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FL_QUEUE_MAX 8

/* Holds offers whose action is FL_OFFER_INSTALL or FL_OFFER_WAIT. Zero-initialise before use. */
typedef struct {
    fl_offer item[FL_QUEUE_MAX];
    int count;
} fl_queue;

/* Adds a copy of *o. An offer for a release already queued (releases compared ignoring case)
 * replaces it in place: same position in arrival order, whole new offer (url, urlExpires, and
 * possibly another action or time). Otherwise it is appended.
 * FL_ERR_ARG for NULL arguments or an action other than INSTALL or WAIT; FL_ERR_FULL when a new
 * release does not fit. */
int fl_queue_put(fl_queue *q, const fl_offer *o);

/* The first offer, in arrival order, that is INSTALL, or WAIT with wait_until <= now.
 * NULL if there is none. The pointer is valid until the queue changes. */
const fl_offer *fl_queue_next(const fl_queue *q, fl_time now);

/* Removes the offer of `release` (ignoring case), keeping the order of the others. Not there: no
 * effect. */
void fl_queue_remove(fl_queue *q, const char *release);

#ifdef __cplusplus
}
#endif

#endif
