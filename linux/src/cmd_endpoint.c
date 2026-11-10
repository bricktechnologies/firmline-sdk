/* SPDX-License-Identifier: Apache-2.0 */
/* firmline-agent endpoint: which addresses the agent uses on a site.
 *   --relay <host> [--https-port <p>] [--broker-port <p>]  endpoint.json in the data folder
 *       {https, broker, brokerPort} (defaults 443 and 8883): from then on the renewal, the
 *       downloads and the broker go through the relay, verified with the root received at
 *       registration (root.pem), as the relay's certificates are signed by the company
 *       intermediate.
 *   --direct  removes endpoint.json: the configuration's addresses again.
 * `register` always uses the configuration (the platform refuses a registration through a
 * relay). A running agent reads the file again before each connection attempt to the broker, so
 * the change takes effect at its next connection; restart the service to apply it at once. */
#define _POSIX_C_SOURCE 200809L
#include "commands.h"

#include "config.h"
#include "firmline/fl_json.h"
#include "log.h"
#include "service.h"
#include "store.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define HOST_MAX 253

typedef struct {
    const char *relay, *https_port, *broker_port, *config;
    bool direct;
} options;

static void usage(void) {
    fputs("usage: firmline-agent endpoint (--relay <host> [--https-port <port>] "
          "[--broker-port <port>] | --direct) [--config <path>]\n",
          stderr);
}

static int parse_options(int argc, char **argv, options *o) {
    memset(o, 0, sizeof *o);
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--direct") == 0) {
            if (o->direct) {
                fa_log("error", "endpoint: --direct is given twice");
                return -1;
            }
            o->direct = true;
            continue;
        }
        const char **slot = NULL;
        if (strcmp(argv[i], "--relay") == 0)
            slot = &o->relay;
        else if (strcmp(argv[i], "--https-port") == 0)
            slot = &o->https_port;
        else if (strcmp(argv[i], "--broker-port") == 0)
            slot = &o->broker_port;
        else if (strcmp(argv[i], "--config") == 0)
            slot = &o->config;
        if (slot == NULL) {
            fa_log("error", "endpoint: unknown argument (number %d)", i + 1);
            return -1;
        }
        if (*slot != NULL) {
            fa_log("error", "endpoint: %s is given twice", argv[i]);
            return -1;
        }
        if (i + 1 >= argc || argv[i + 1][0] == '\0') {
            fa_log("error", "endpoint: %s needs a value", argv[i]);
            return -1;
        }
        *slot = argv[++i];
    }
    if (o->direct == (o->relay != NULL)) {
        fa_log("error", "endpoint: give either --relay <host> or --direct");
        return -1;
    }
    if (o->direct && (o->https_port != NULL || o->broker_port != NULL)) {
        fa_log("error", "endpoint: --https-port and --broker-port go with --relay");
        return -1;
    }
    return 0;
}

/* A port number 1..65535, digits only. */
static int parse_port(const char *text, const char *option, int *out) {
    long v = 0;
    size_t n = strlen(text);
    for (size_t i = 0; i < n && v <= 65535; i++) {
        if (text[i] < '0' || text[i] > '9') {
            v = 0;
            break;
        }
        v = v * 10 + (text[i] - '0');
    }
    if (n == 0 || n > 5 || v < 1 || v > 65535) {
        fa_log("error", "endpoint: %s must be a port number from 1 to 65535", option);
        return -1;
    }
    *out = (int)v;
    return 0;
}

/* A host name, an IPv4 address or an IPv6 address (with ':'): letters, digits, '.', '-' and, for
 * IPv6, ':'; not starting with '-' or '.'. Nothing that could change the meaning of a URL. */
static bool valid_host(const char *host, bool *ipv6) {
    size_t n = strlen(host);
    *ipv6 = strchr(host, ':') != NULL;
    if (n == 0 || n > HOST_MAX || host[0] == '-' || host[0] == '.')
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = host[i];
        bool ok = (c >= '0' && c <= '9') || c == '.' ||
                  (*ipv6 ? ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':')
                         : ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-'));
        if (!ok)
            return false;
    }
    return true;
}

static int set_relay(const fa_config *cfg, const options *o) {
    int https_port = 443, broker_port = 8883;
    bool ipv6 = false;
    if (!valid_host(o->relay, &ipv6)) {
        fa_log("error", "endpoint: '%.64s' is not a host name or an IP address", o->relay);
        return 1;
    }
    if ((o->https_port != NULL && parse_port(o->https_port, "--https-port", &https_port) != 0) ||
        (o->broker_port != NULL && parse_port(o->broker_port, "--broker-port", &broker_port) != 0))
        return 1;
    char https[300], json[700];
    snprintf(https, sizeof https, ipv6 ? "https://[%s]:%d" : "https://%s:%d", o->relay, https_port);
    fl_jw w;
    fl_jw_begin(&w, json, sizeof json);
    fl_jw_string(&w, "https", https);
    fl_jw_string(&w, "broker", o->relay);
    fl_jw_int(&w, "brokerPort", broker_port);
    int n = fl_jw_end(&w);
    if (n < 0 || fa_store_write(cfg->data_dir, FA_ENDPOINT, json, (size_t)n, 0644) != 0) {
        fa_log("error", "endpoint: cannot write %s/%s", cfg->data_dir, FA_ENDPOINT);
        return 1;
    }
    fa_log("info",
           "endpoint: relay %s (HTTPS port %d, broker port %d), verified with the root of the "
           "registration; a running agent uses it from its next connection",
           o->relay, https_port, broker_port);
    return 0;
}

int fa_cmd_endpoint(int argc, char **argv) {
    options o;
    if (parse_options(argc, argv, &o) != 0) {
        usage();
        return 1;
    }
    fa_config cfg;
    char err[256];
    if (fa_config_load(o.config != NULL ? o.config : FA_DEFAULT_CONFIG, &cfg, err) != 0) {
        fa_log("error", "configuration: %s", err);
        return 1;
    }
    if (mkdir(cfg.data_dir, 0700) != 0 && errno != EEXIST) {
        fa_log("error", "endpoint: cannot create the data folder %s: %s", cfg.data_dir,
               strerror(errno));
        return 1;
    }
    if (!o.direct)
        return set_relay(&cfg, &o);
    if (fa_store_remove(cfg.data_dir, FA_ENDPOINT) != 0) {
        fa_log("error", "endpoint: cannot remove %s/%s: %s", cfg.data_dir, FA_ENDPOINT,
               strerror(errno));
        return 1;
    }
    fa_log("info", "endpoint: direct, to the addresses of the configuration; a running agent uses "
                   "them from its next connection");
    return 0;
}
