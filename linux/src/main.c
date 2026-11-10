/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <string.h>

static void usage(FILE *out) {
    fputs("usage: firmline-agent <command> [options]\n"
          "\n"
          "Commands are added as the agent grows; none is available yet.\n"
          "  --help    show this text\n",
          out);
}

int main(int argc, char **argv) {
    if (argc >= 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        usage(stdout);
        return 0;
    }
    if (argc >= 2)
        fprintf(stderr, "firmline-agent: unknown command '%.60s'\n", argv[1]);
    usage(stderr);
    return 1;
}
