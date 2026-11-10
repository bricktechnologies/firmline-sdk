/* SPDX-License-Identifier: Apache-2.0 */
#include "firmline/fl_queue.h"

#include <string.h>

static char lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c; }

static bool same_release(const char *a, const char *b) {
    for (; *a != '\0' && *b != '\0'; a++, b++)
        if (lower(*a) != lower(*b))
            return false;
    return *a == *b;
}

static int find(const fl_queue *q, const char *release) {
    int i;
    for (i = 0; i < q->count; i++)
        if (same_release(q->item[i].release, release))
            return i;
    return -1;
}

int fl_queue_put(fl_queue *q, const fl_offer *o) {
    int i;
    if (q == NULL || o == NULL || (o->action != FL_OFFER_INSTALL && o->action != FL_OFFER_WAIT))
        return FL_ERR_ARG;
    if (q->count < 0 || q->count > FL_QUEUE_MAX)
        return FL_ERR_ARG;
    i = find(q, o->release);
    if (i < 0) {
        if (q->count == FL_QUEUE_MAX)
            return FL_ERR_FULL;
        i = q->count++;
    }
    q->item[i] = *o;
    return FL_OK;
}

const fl_offer *fl_queue_next(const fl_queue *q, fl_time now) {
    int i;
    if (q == NULL || q->count < 0 || q->count > FL_QUEUE_MAX)
        return NULL;
    for (i = 0; i < q->count; i++) {
        const fl_offer *o = &q->item[i];
        if (o->action == FL_OFFER_INSTALL || (o->action == FL_OFFER_WAIT && o->wait_until <= now))
            return o;
    }
    return NULL;
}

void fl_queue_remove(fl_queue *q, const char *release) {
    int i;
    if (q == NULL || release == NULL || q->count < 0 || q->count > FL_QUEUE_MAX)
        return;
    i = find(q, release);
    if (i < 0)
        return;
    memmove(&q->item[i], &q->item[i + 1], (size_t)(q->count - i - 1) * sizeof q->item[0]);
    q->count--;
    memset(&q->item[q->count], 0, sizeof q->item[0]);
}
