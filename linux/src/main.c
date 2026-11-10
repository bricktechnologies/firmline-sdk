/* SPDX-License-Identifier: Apache-2.0 */
#include "commands.h"
#include "http.h"
#include "log.h"

#include <stdio.h>
#include <string.h>

static const struct {
    const char *name;
    int (*run)(int argc, char **argv);
} COMMANDS[] = {
    {"register", fa_cmd_register},
};

static void usage(FILE *out) {
    fputs("usage: firmline-agent <command> [options]\n"
          "\n"
          "Commands:\n"
          "  register (--token <token> | --token-file <path>) [--serial <serial>]\n"
          "           [--config <path>]\n"
          "           create the device key and register the device with the platform\n"
          "\n"
          "  --config  the configuration file (default " FA_DEFAULT_CONFIG ")\n"
          "  --help    show this text\n",
          out);
}

int main(int argc, char **argv) {
    if (argc >= 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        usage(stdout);
        return 0;
    }
    for (size_t i = 0; argc >= 2 && i < sizeof COMMANDS / sizeof COMMANDS[0]; i++) {
        if (strcmp(argv[1], COMMANDS[i].name) != 0)
            continue;
        if (fa_http_global_init() != 0) {
            fa_log("error", "cannot start libcurl");
            return 1;
        }
        int rc = COMMANDS[i].run(argc - 2, argv + 2);
        fa_http_global_cleanup();
        return rc;
    }
    if (argc >= 2)
        fprintf(stderr, "firmline-agent: unknown command '%.60s'\n", argv[1]);
    usage(stderr);
    return 1;
}
