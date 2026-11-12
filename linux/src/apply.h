/* SPDX-License-Identifier: Apache-2.0 */
/* The installation of the package of a Docker Compose application (spec §6.3), for `apply`.
 *
 * The package is <data_dir>/download-<release>.bin (release in lower case), the tar of `pack`
 * (cmd_pack.c). In order:
 *  1. the tar holds exactly firmline-package.json, docker-compose.yml and images.tar.gz; the
 *     description is a valid package (package.h) of the release's version and of the daemon's
 *     architecture (`docker version`); the composition, as Compose reads it, has exactly the
 *     services and images of the description; images.tar.gz, extracted into the working folder,
 *     has in its manifest.json every image of the description, with its name and ID;
 *  2. the agent service: when the package has no <agent_service> and the composition in use
 *     (compose_file) has one, that service is added to the new composition as Compose renders it
 *     (`config <agent_service>`: its definition with the named volumes and networks it uses), so
 *     that its container stays as it is; a service it depends on is refused (it would replace the
 *     package's). `docker load` of the images, then each name must be the image ID of the
 *     description; images.tar.gz is removed at once;
 *  3. the new composition, rendered by Compose with -p <project> and the folder of compose_file as
 *     the project folder, is written next to compose_file as <compose_file>.new, and compose_file
 *     is copied to <data_dir>/compose-previous.yml;
 *  4. the restart counts of the project's containers are noted, then `docker compose -p <project>
 *     -f <compose_file>.new up --detach --remove-orphans --pull=never`;
 *  5. every 2 s for health_timeout seconds each service has its containers, each `running` and
 *     not restarted since step 4 (a container kept by up keeps its count of before); with a
 *     healthcheck `unhealthy` fails at once and anything but `healthy` at the end fails;
 *  6. success: <compose_file>.new replaces compose_file and package.json in the data folder is the
 *     description;
 *  7. failure: a name of the package that named another image before the load (one tag for two
 *     versions, 1.0+a and 1.0_a) names it again, compose_file is the previous composition (written
 *     back when step 6 had replaced it), and after step 4 it is started again the same way.
 * Up to the load in step 2 nothing on the device changes but the working folder. The working
 * files are in <data_dir>/apply.tmp, removed at the end with compose-previous.yml and a .new left
 * by a failure. Values from the package or the composition reach docker and tar only after `--`
 * or as `--option=value`. */
#ifndef FIRMLINE_AGENT_APPLY_H
#define FIRMLINE_AGENT_APPLY_H

#include "config.h"
#include "package.h"

#include <stdbool.h>

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

/* The images of the services of a composition: the package's, and an agent service kept. */
#define FA_APPLY_IN_USE_MAX (FA_MAX_COMPONENTS + 16)

/* The package installed before (package.json, when it could be read) and the one installed, and
 * the images that the composition installed names (have_in_use false when Compose could not list
 * them): each name and its image ID ("" when the name names no image). These include the image of
 * an agent service kept from the composition in use, which may be one of the previous package. */
typedef struct {
    fa_package previous, installed;
    bool have_previous, have_in_use;
    int in_use_count;
    struct {
        char image[256];
        char id[128];
    } in_use[FA_APPLY_IN_USE_MAX];
} fa_apply_packages;

/* Installs the package of `release` for comp (install = docker-compose), whose version must be
 * `version` (the release's). On FA_APPLY_INSTALLED, packages holds the two packages (the version
 * installed is packages->installed.version) and the images in use; the reason of a failure is
 * logged as one error line. */
fa_apply_outcome fa_apply_install(const fa_config *cfg, const fa_component *comp,
                                  const char *release, const char *version,
                                  fa_apply_packages *packages);

/* After a success, once the outcome is written (a power loss here loses no result): the images of
 * the previous package that the installed one does not use lose their names of that package
 * (docker removes an image with its last name), and an image of it left with no name at all (its
 * name now names an image of the installed package) is removed. Never another image or name, and
 * never a name or image ID that a service of the composition installed uses (the agent service
 * kept runs an image of the previous package); without the images in use, nothing is removed. A
 * removal that fails is logged. */
void fa_apply_remove_previous_images(const fa_apply_packages *packages);

/* Removes <data_dir>/apply.tmp and its files, as an apply cut short left them (nothing when there
 * is none): for the agent, which shares the data folder, after it settles such an apply. */
void fa_apply_remove_work(const char *data_dir);

#endif
