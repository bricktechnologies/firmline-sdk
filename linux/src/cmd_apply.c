/* SPDX-License-Identifier: Apache-2.0 */
/* firmline-agent apply --release <id> [--config <path>]: installs the package of a Docker Compose
 * application that `run` has downloaded and verified (<data_dir>/download-<release>.bin), with a
 * health check and the way back to the previous composition (apply.h). `run` starts it in a
 * container of its own (same image, --volumes-from the agent's container), so that it outlives a
 * recreation of the agent, and leaves install.json {release, component, version, state:
 * "apply"} first.
 *
 * The outcome is apply.json in the data folder, written only here, atomically:
 *   {"release":"<id>","state":"running|installed|failed","detail":null|"install_failed"|
 *    "health_check_failed","version":"<v>"|null}
 * `running` at the start, then `installed` (version: the package's) or `failed` (version: the one
 * the component reports, as after a failed install script). A failure before the package is
 * touched (install.json missing, for another release or component, or not "apply") is
 * install_failed. Exit 0 when installed; 1 when failed, and for a usage or configuration error,
 * which writes no apply.json. */
#define _POSIX_C_SOURCE 200809L
#include "commands.h"

#include "apply.h"
#include "components.h"
#include "config.h"
#include "firmline/fl_json.h"
#include "log.h"
#include "package.h"
#include "store.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define INSTALL_STATE "install.json"
#define RELEASE_LEN 36

static void usage(void) {
    fputs("usage: firmline-agent apply --release <id> [--config <path>]\n", stderr);
}

static int parse_options(int argc, char **argv, const char **release, const char **config) {
    *release = *config = NULL;
    for (int i = 0; i < argc; i++) {
        const char **slot = NULL;
        if (strcmp(argv[i], "--release") == 0)
            slot = release;
        else if (strcmp(argv[i], "--config") == 0)
            slot = config;
        if (slot == NULL || *slot != NULL || i + 1 >= argc || argv[i + 1][0] == '\0') {
            fa_log("error", "apply: unknown, repeated or empty argument (number %d)", i + 1);
            return -1;
        }
        *slot = argv[++i];
    }
    if (*release == NULL) {
        fa_log("error", "apply: --release is needed");
        return -1;
    }
    return 0;
}

/* A GUID: 8-4-4-4-12 hexadecimal digits. */
static bool release_ok(const char *r) {
    if (strlen(r) != RELEASE_LEN)
        return false;
    for (int i = 0; i < RELEASE_LEN; i++) {
        bool dash = i == 8 || i == 13 || i == 18 || i == 23;
        char c = r[i];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (dash ? c != '-' : !hex)
            return false;
    }
    return true;
}

/* A string member, or null for NULL. */
static void member(fl_jw *w, const char *key, const char *value) {
    if (value != NULL)
        fl_jw_string(w, key, value);
    else
        fl_jw_null(w, key);
}

static int write_state(const fa_config *cfg, const char *release, const char *state,
                       const char *detail, const char *version) {
    char json[1024];
    fl_jw w;
    fl_jw_begin(&w, json, sizeof json);
    fl_jw_string(&w, "release", release);
    fl_jw_string(&w, "state", state);
    member(&w, "detail", detail);
    member(&w, "version", version);
    int n = fl_jw_end(&w);
    if (n < 0 || fa_store_write(cfg->data_dir, FA_APPLY_STATE, json, (size_t)n, 0644) != 0) {
        fa_log("error", "apply: cannot write %s/%s", cfg->data_dir, FA_APPLY_STATE);
        return -1;
    }
    return 0;
}

/* install.json must be the one `run` writes before it starts apply for this release. 0 and the
 * release's version, or -1 (logged). */
static int read_install_state(const fa_config *cfg, const fa_component *comp, const char *release,
                              char version[65]) {
    char *data = NULL;
    size_t len = 0;
    if (fa_store_read(cfg->data_dir, INSTALL_STATE, &data, &len) != 0) {
        fa_log("error", "apply: %s/%s cannot be read", cfg->data_dir, INSTALL_STATE);
        return -1;
    }
    fl_json j;
    char stored[RELEASE_LEN + 2], component[65], state[16];
    bool ok = fl_json_parse(&j, data, len) == FL_OK &&
              fl_json_string(&j, "release", stored, sizeof stored) == FL_OK &&
              fl_json_string(&j, "component", component, sizeof component) == FL_OK &&
              fl_json_string(&j, "version", version, 65) == FL_OK &&
              fl_json_string(&j, "state", state, sizeof state) == FL_OK;
    free(data);
    if (!ok) {
        fa_log("error", "apply: %s/%s is not an install state", cfg->data_dir, INSTALL_STATE);
        return -1;
    }
    if (strcasecmp(stored, release) != 0) {
        fa_log("error", "apply: %s is for another release", INSTALL_STATE);
        return -1;
    }
    if (comp == NULL) {
        fa_log("error", "apply: no component of the configuration has install = docker-compose");
        return -1;
    }
    if (strcmp(component, comp->code) != 0) {
        fa_log("error", "apply: %s names the component %s, not %s (install = docker-compose)",
               INSTALL_STATE, component, comp->code);
        return -1;
    }
    if (strcmp(state, "apply") != 0) {
        fa_log("error", "apply: %s is in the state %s, not apply", INSTALL_STATE, state);
        return -1;
    }
    if (!fa_package_version_ok(version)) {
        fa_log("error", "apply: the version in %s is not a firmware version", INSTALL_STATE);
        return -1;
    }
    return 0;
}

int fa_cmd_apply(int argc, char **argv) {
    const char *release, *config;
    if (parse_options(argc, argv, &release, &config) != 0) {
        usage();
        return 1;
    }
    if (!release_ok(release)) {
        fa_log("error", "apply: --release is the ID of a release (a GUID)");
        return 1;
    }
    static fa_config cfg;
    char err[256];
    if (fa_config_load(config != NULL ? config : FA_DEFAULT_CONFIG, &cfg, err) != 0) {
        fa_log("error", "configuration: %s", err);
        return 1;
    }
    const fa_component *comp = NULL;
    for (int i = 0; i < cfg.component_count; i++)
        if (cfg.component[i].install == FA_INSTALL_DOCKER_COMPOSE)
            comp = &cfg.component[i];

    char current[65], version[65];
    static fa_apply_packages packages;
    bool known = comp != NULL && fa_component_version(&cfg, comp, current) == 0;
    if (write_state(&cfg, release, "running", NULL, known ? current : NULL) != 0)
        return 1;
    fa_apply_outcome outcome = FA_APPLY_INSTALL_FAILED;
    if (read_install_state(&cfg, comp, release, version) == 0)
        outcome = fa_apply_install(&cfg, comp, release, version, &packages);
    if (outcome == FA_APPLY_INSTALLED) {
        /* The outcome first: the images go after it, so a power loss among them loses no
         * result. */
        int rc = write_state(&cfg, release, "installed", NULL, packages.installed.version);
        fa_apply_remove_previous_images(&packages);
        return rc == 0 ? 0 : 1;
    }

    known = comp != NULL && fa_component_version(&cfg, comp, current) == 0;
    const char *detail =
        outcome == FA_APPLY_HEALTH_CHECK_FAILED ? "health_check_failed" : "install_failed";
    write_state(&cfg, release, "failed", detail, known ? current : NULL);
    return 1;
}
