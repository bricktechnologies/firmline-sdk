/* SPDX-License-Identifier: Apache-2.0 */
/* Agent configuration: /etc/firmline/agent.conf, INI with [platform] and one [component <code>]
 * per component. Written into the image by the manufacturer. */
#ifndef FIRMLINE_AGENT_CONFIG_H
#define FIRMLINE_AGENT_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    FA_VERSION_FIXED,
    FA_VERSION_OS_RELEASE,
    FA_VERSION_FILE,
    FA_VERSION_COMMAND,
    FA_VERSION_PACKAGE /* version of the last package installed (data_dir/package.json), else
                          source_arg */
} fa_version_source;
typedef enum { FA_INSTALL_SCRIPT, FA_INSTALL_NONE, FA_INSTALL_DOCKER_COMPOSE } fa_install;

#define FA_MAX_COMPONENTS 16

typedef struct {
    char code[65];
    bool main;
    fa_version_source source;
    char source_arg[256];
    fa_install install;
    char script[256];
    int timeout_s;
    /* install = docker-compose only */
    char compose_file[256];
    char project[65];
    char agent_service[65];
    int health_timeout_s;
} fa_component;

typedef struct {
    char platform_url[256], broker_host[256];
    int broker_port;      /* default 8883 */
    char ca_file[256];    /* optional: CA for the platform HTTPS; default the system authorities */
    char update_key[256]; /* PEM of the update verification key */
    char family[37];      /* optional, devices registered before T178 */
    char serial[256];     /* "devicetree", "file:<path>", "command:<path>", or "" = --serial */
    char data_dir[256];   /* default /var/lib/firmline */
    char os_release[256]; /* default /etc/os-release */
    char reboot_command[256]; /* run after a script exits 10; "" = the script reboots itself */
    int status_interval_s;    /* default 3600 */
    fa_component component[FA_MAX_COMPONENTS];
    int component_count;
    char path[4096]; /* the file it was read from, as given (`run` starts `apply` with it) */
} fa_config;

/* Reads and validates the file. 0, or -1 with a message (line-numbered when it is about a line). */
int fa_config_load(const char *path, fa_config *out, char err[256]);

/* Every configuration key, as "platform.<key>" or "component.<key>": the one table the parser uses
 * to refuse unknown keys, and the list the guide is checked against. */
const char *const *fa_config_keys(size_t *count);

#endif
