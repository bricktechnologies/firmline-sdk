/* SPDX-License-Identifier: Apache-2.0 */
/* Updates: offer -> queue -> download -> install -> result, one release at a time.
 *
 * Every offer is checked with fl_offer_check (signature over the manifest bytes, kid, tenant,
 * family, component, version); only INSTALL and WAIT are queued (fl_queue, arrival order), a
 * refusal becomes its result at once. The download is checked byte by byte against the size and
 * SHA-256 of the signed manifest (fl_download_*); nothing is installed before fl_download_finish
 * accepts the whole file. Each release gets one result, stored in the data folder before it is
 * sent; an offer for a release with a stored result gets that result again, nothing else.
 *
 * Data folder (flat names; <release> in lower case):
 *   offer-<release>.json    the offer as received, while the release is queued: the queue is
 *                           rebuilt from these at start (each checked again)
 *   download-<release>.part the bytes downloaded so far; hashed again from disk before resuming
 *   download-<release>.bin  the verified file, while its script (or apply) runs
 *   install.json            {release, component, version, state, bootId} while an installation
 *                           is under way: state "running" while the script runs (at the next
 *                           start: installed when the component reports the version, else failed
 *                           install_failed), "reboot" while a script that exited 10 waits for the
 *                           reboot (at the next boot: installed or failed boot_failed), "apply"
 *                           from the start of apply to its outcome (at the next start: followed)
 *   result-<release>.json   {seq, published, payload}: the exact result message, the 32 most
 *                           recent by seq; published = PUBACK received
 * and, for a docker-compose component, the files of `apply` (apply.h, cmd_apply.c), which the
 * agent reads: apply.json (the outcome), package.json (the version source package:), and
 * compose-previous.yml, written back to compose_file when an apply cut short had already
 * replaced it.
 *
 * A docker-compose component is installed by `firmline-agent apply --release <id> --config
 * <the agent's configuration>` in the container firmline-apply, started with the agent's image
 * and --volumes-from its container (only an agent in a container installs one: otherwise the
 * offer is failed install_failed before the download). The agent waits for an earlier
 * firmline-apply that still runs (up to 30 minutes, then the release is failed install_failed
 * and that container left as it is) and removes one that has ended. Its outcome in apply.json is
 * the result; the container gone without one (or docker silent for 5 minutes) is failed
 * install_failed, or installed when package.json already has the version, and the composition of
 * compose_file is brought up again (docker compose up --detach --remove-orphans --pull=never, in
 * a firmline-apply container too).
 *
 * Runs in the service's thread, from its hooks; never blocks the loop for long: the download is
 * a libcurl multi transfer and the script a child process, both polled from the loop; the docker
 * commands of apply are short (docker ps once a second). */
#ifndef FIRMLINE_AGENT_OTA_H
#define FIRMLINE_AGENT_OTA_H

#include "firmline/fl_common.h"
#include "service.h"

#include <stdbool.h>
#include <stddef.h>

typedef struct fa_ota fa_ota;

/* Starts the crypto library, loads the stored results, settles install.json and rebuilds the
 * queue from the stored offers. NULL when it cannot start (logged). */
fa_ota *fa_ota_open(fa_service *s, fl_time now);

/* At the stop of the service: the transfer is dropped (the .part stays for the next start) and a
 * script still running is stopped. NULL is allowed. */
void fa_ota_close(fa_ota *o);

/* An offer from otaOfferTopic: checked and queued only (inside the MQTT event handling). */
void fa_ota_offer(fa_ota *o, const char *payload, size_t len, fl_time now);

/* Every loop turn: moves the download and the script on, starts the next release, sends the
 * results that wait for the connection. */
void fa_ota_tick(fa_ota *o, fl_time now);

/* The PUBACK of a message: the result it carried is marked as delivered. */
void fa_ota_published(fa_ota *o, int mid, int reason);

/* The identity was read again (a renewal): the family of the offer check follows device.json. */
void fa_ota_identity_changed(fa_ota *o);

/* True while a transfer, a script or a rehash runs: the loop then waits with fa_ota_wait. */
bool fa_ota_busy(const fa_ota *o);

/* Waits up to timeout_ms for the transfer, the script's output, or `fd` (the MQTT socket, -1 for
 * none; with POLLOUT too when want_write). */
void fa_ota_wait(fa_ota *o, int fd, bool want_write, int timeout_ms);

#endif
