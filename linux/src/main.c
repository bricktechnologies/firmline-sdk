/* SPDX-License-Identifier: Apache-2.0 */
#include "commands.h"
#include "http.h"
#include "log.h"
#include "version.h"

#include <stdio.h>
#include <string.h>

static const struct {
    const char *name;
    int (*run)(int argc, char **argv);
} COMMANDS[] = {
    {"register", fa_cmd_register}, {"run", fa_cmd_run},   {"status", fa_cmd_status},
    {"endpoint", fa_cmd_endpoint}, {"pack", fa_cmd_pack},
};

static void usage(FILE *out) {
    fputs("usage: firmline-agent <command> [options]\n"
          "\n"
          "Commands:\n"
          "  register (--token <token> | --token-file <path>) [--serial <serial>]\n"
          "           [--config <path>]\n"
          "           create the device key and register the device with the platform\n"
          "  run [--config <path>] [--wait-registration]\n"
          "           the service: broker connection, status, updates, certificate renewal\n"
          "           (stops on SIGTERM); --wait-registration waits for register instead of\n"
          "           exiting when the device is not registered (a container with a restart\n"
          "           policy)\n"
          "  status [--config <path>]\n"
          "           print the registration, certificate expiry, last connection and queued\n"
          "           releases as one JSON object (files only, no network)\n"
          "  endpoint (--relay <host> [--https-port <port>] [--broker-port <port>] | --direct)\n"
          "           [--config <path>]\n"
          "           use a relay on this site (HTTPS 443 and broker 8883 by default, verified\n"
          "           with the root received at registration), or the configuration again\n"
          "  pack --compose <file> --version <version> --output <file.tar>\n"
          "           build the package of a Docker Compose application for a release, where\n"
          "           its images are (never pulled): images renamed\n"
          "           firmline.local/<service>:<version>, composition and images in one tar\n"
          "\n"
          "  --config  the configuration file (default " FA_DEFAULT_CONFIG ")\n"
          "  --help    show this text\n"
          "  --version print the version\n",
          out);
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--version") == 0) {
        printf("firmline-agent %s\n", FIRMLINE_AGENT_VERSION);
        return 0;
    }
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
