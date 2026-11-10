/* SPDX-License-Identifier: Apache-2.0 */
/* Renewal of the device certificate (POST /api/v1/provisioning/renewal): from 60 days before the
 * expiry, at most once a day (fl_renewal_due), checked at start and after each status.
 *
 * Before the request, the new key and the exact request body are saved (renewal-new.key, 0600;
 * renewal-request.json): an answer that does not come (network or TLS error, 429, 5xx, a 200 that
 * cannot be read) leaves both, and the next check sends the same bytes again; the platform then
 * answers with the certificate it already issued for that key. A refusal (any other 4xx, or a 200
 * for another device or for another key) removes both; the next try is a day later.
 *
 * The swap after a 200, so that a crash at any step leaves a device that connects:
 *   1. the new certificate, chain, root and device.json are written under pending names
 *      (renewal-device.pem, renewal-chain.pem, renewal-root.pem, renewal-device.json);
 *   2. the commit marker renewal-commit is written: from here on the swap is decided;
 *   3. each pending file, and renewal-new.key, is renamed over its live name (device.pem,
 *      chain.pem, root.pem, device.key, device.json), each rename atomic and synced;
 *   4. the marker is removed, then renewal-request.json.
 * Before the marker, the live files are untouched (the pending ones are removed at the next
 * start); after it, the next start completes the renames (fa_renewal_recover) before anything
 * reads them. A device that cannot connect with the old certificate is never left: the old pair
 * stays in place until the new pair is complete on disk.
 *
 * Runs in the service's thread; the request is a libcurl multi transfer driven from the loop, so
 * the MQTT connection keeps turning while it waits (up to 60 s). */
#ifndef FIRMLINE_AGENT_RENEWAL_H
#define FIRMLINE_AGENT_RENEWAL_H

#include "firmline/fl_common.h"
#include "service.h"

#include <stdbool.h>

#define FA_RENEWAL_STATE "renewal.json" /* {"lastAttempt": UTC ISO 8601}: the daily limit */

/* At start, before the identity is read: completes a swap whose marker exists, then removes what
 * a crash before the marker left (pending files; a new key without its request, or a request
 * without its key). 0, or -1 (logged) when a swap cannot be completed. */
int fa_renewal_recover(const char *dir);

typedef struct fa_renewal fa_renewal;

/* NULL when out of memory (logged). */
fa_renewal *fa_renewal_open(fa_service *s);

/* Drops a request in flight (its files stay for the next start). NULL is allowed. */
void fa_renewal_close(fa_renewal *r);

/* At start and after each status: sends the saved request again, or starts a new one when the
 * certificate is due. Logs once that an expired certificate cannot be renewed. */
void fa_renewal_check(fa_renewal *r, fl_time now);

/* Every loop turn: moves the request on and handles its answer. */
void fa_renewal_tick(fa_renewal *r, fl_time now);

/* Before every connection attempt: a swap that failed half-way (a rename refused) is tried
 * again, so that the connection uses a key and a certificate that belong together. */
void fa_renewal_before_connect(fa_renewal *r, fl_time now);

/* True while the request is in flight: the loop then waits with fa_renewal_wait. */
bool fa_renewal_busy(const fa_renewal *r);

/* Waits up to timeout_ms for the request or for `fd` (the MQTT socket, -1 for none; with POLLOUT
 * too when want_write). */
void fa_renewal_wait(fa_renewal *r, int fd, bool want_write, int timeout_ms);

#endif
