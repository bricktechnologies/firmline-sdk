/* SPDX-License-Identifier: Apache-2.0 */
/* The installation of the package of a Docker Compose application (spec §6.3), for `apply`.
 *
 * The package is <data_dir>/download-<release>.bin (release in lower case), the tar of `pack`
 * (cmd_pack.c). In order:
 *  1. the tar holds exactly firmline-package.json, docker-compose.yml and images.tar.gz; the
 *     description is a valid package (package.h) of the release's version and of the daemon's
 *     architecture (`docker version`); the composition, as Compose reads it, has exactly the
 *     services and images of the description;
 *  2. the agent service: when the package has no <agent_service> and the composition in use
 *     (compose_file) has one, that service is added to the new composition as Compose renders it
 *     (`config <agent_service>`: its definition with the named volumes and networks it uses), so
 *     that its container stays as it is; a service it depends on is refused (it would replace the
 *     package's). `docker load` of the images, then each name must be the image ID of the
 *     description; images.tar.gz is removed at once;
 *  3. the new composition, rendered by Compose with -p <project> and the folder of compose_file as
 *     the project folder, is written next to compose_file as <compose_file>.new, and compose_file
 *     is copied to <data_dir>/compose-previous.yml;
 *  4. `docker compose -p <project> -f <compose_file>.new up --detach --remove-orphans
 *     --pull=never`;
 *  5. every 2 s for health_timeout seconds each service has its containers, each `running` and
 *     never restarted; with a healthcheck `unhealthy` fails at once and anything but `healthy` at
 *     the end fails;
 *  6. success: <compose_file>.new replaces compose_file, package.json in the data folder is the
 *     description, and the images of the previous package (its package.json) that the new one
 *     does not use lose their names and, when they have no other name, are removed;
 *  7. failure: a name of the package that named another image before the load (one tag for two
 *     versions, 1.0+a and 1.0_a) names it again, and after step 4 compose_file (never changed)
 *     is started again the same way.
 * Up to step 3 nothing of the running application is touched. The working files are in
 * <data_dir>/apply.tmp, removed at the end with compose-previous.yml and a .new left by a
 * failure. Values from the package or the composition reach docker and tar only after `--` or as
 * `--option=value`. */
#ifndef FIRMLINE_AGENT_APPLY_H
#define FIRMLINE_AGENT_APPLY_H

#include "config.h"

typedef enum {
    FA_APPLY_INSTALLED,
    FA_APPLY_INSTALL_FAILED,      /* steps 1 to 4, or step 6 could not complete */
    FA_APPLY_HEALTH_CHECK_FAILED, /* step 5 */
} fa_apply_outcome;

/* The data folder files of apply. */
#define FA_APPLY_STATE "apply.json"
#define FA_APPLY_PREVIOUS "compose-previous.yml"
#define FA_APPLY_WORK "apply.tmp"
#define FA_APPLY_PACKAGE "package.json"

/* Installs the package of `release` for comp (install = docker-compose), whose version must be
 * `version` (the release's). On FA_APPLY_INSTALLED, installed is the version of the package; the
 * reason of a failure is logged as one error line. */
fa_apply_outcome fa_apply_install(const fa_config *cfg, const fa_component *comp,
                                  const char *release, const char *version, char installed[65]);

#endif
