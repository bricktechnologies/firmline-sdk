/* SPDX-License-Identifier: Apache-2.0 */
/* firmline-agent run [--config <path>] [--wait-registration]: the service, until a stop signal. */
#include "commands.h"

#include "config.h"
#include "log.h"
#include "service.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

int fa_cmd_run(int argc, char **argv) {
    const char *config = NULL;
    bool wait_registration = false;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--wait-registration") == 0 && !wait_registration) {
            wait_registration = true;
            continue;
        }
        if (strcmp(argv[i], "--config") != 0 || config != NULL || i + 1 >= argc ||
            argv[i + 1][0] == '\0') {
            fa_log("error", "run: unknown or repeated argument (number %d)", i + 1);
            fputs("usage: firmline-agent run [--config <path>] [--wait-registration]\n", stderr);
            return 1;
        }
        config = argv[++i];
    }
    fa_config cfg;
    char err[256];
    if (fa_config_load(config != NULL ? config : FA_DEFAULT_CONFIG, &cfg, err) != 0) {
        fa_log("error", "configuration: %s", err);
        return 1;
    }
    return fa_service_run(&cfg, wait_registration);
}
