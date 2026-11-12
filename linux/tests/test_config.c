/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "check.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* Writes n bytes to a new temp file and loads it. The file is removed afterwards. */
static int load_bytes(const char *text, size_t n, fa_config *cfg, char err[256]) {
    char path[] = "/tmp/fa-conf-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
        return -2;
    if (write(fd, text, n) != (ssize_t)n) {
        close(fd);
        return -2;
    }
    close(fd);
    int rc = fa_config_load(path, cfg, err);
    unlink(path);
    return rc;
}

static int load_text(const char *text, fa_config *cfg, char err[256]) {
    return load_bytes(text, strlen(text), cfg, err);
}

/* Seven lines: the platform section (1-4) and one main component (5-7); an added line is line 8. */
static const char *MINIMAL = "[platform]\n"
                             "url = https://platform.example\n"
                             "broker = broker.example\n"
                             "update_key = /etc/firmline/update.pem\n"
                             "[component os]\n"
                             "main = true\n"
                             "version = fixed:1.0.0\n";

static void config_reads_every_key(void) {
    static fa_config cfg;
    char err[256] = "";
    const char *text = "# a comment\n"
                       "; another comment\n"
                       "\n"
                       "[platform]\n"
                       "url = https://platform.example\n"
                       "broker=broker.example\n"
                       "broker_port = 443\n"
                       "ca_file = /etc/firmline/ca.pem\n"
                       "update_key   =   /etc/firmline/update.pem   \n"
                       "family = 11111111-2222-3333-4444-555555555555\n"
                       "serial = file:/etc/serial\n"
                       "data_dir = /data/firmline\n"
                       "os_release = /host/os-release\n"
                       "reboot_command = /sbin/reboot now\n"
                       "status_interval = 900\n"
                       "[component main-app]\n"
                       "main = true\n"
                       "version = command:/usr/bin/app-version\n"
                       "install = script:/usr/lib/firmline/install.sh\n"
                       "timeout = 120\n"
                       "[component base.os]\n"
                       "main = false\n"
                       "version = os-release:VERSION_ID\n"
                       "install = none\n"
                       "[component cfg_1]\n"
                       "version = file:/etc/cfg-version\n";
    CHECK_EQ_INT(load_text(text, &cfg, err), 0);
    CHECK_EQ_STR(cfg.platform_url, "https://platform.example");
    CHECK_EQ_STR(cfg.broker_host, "broker.example");
    CHECK_EQ_INT(cfg.broker_port, 443);
    CHECK_EQ_STR(cfg.ca_file, "/etc/firmline/ca.pem");
    CHECK_EQ_STR(cfg.update_key, "/etc/firmline/update.pem");
    CHECK_EQ_STR(cfg.family, "11111111-2222-3333-4444-555555555555");
    CHECK_EQ_STR(cfg.serial, "file:/etc/serial");
    CHECK_EQ_STR(cfg.data_dir, "/data/firmline");
    CHECK_EQ_STR(cfg.os_release, "/host/os-release");
    CHECK_EQ_STR(cfg.reboot_command, "/sbin/reboot now");
    CHECK_EQ_INT(cfg.status_interval_s, 900);
    CHECK_EQ_INT(cfg.component_count, 3);
    CHECK_EQ_STR(cfg.component[0].code, "main-app");
    CHECK(cfg.component[0].main);
    CHECK_EQ_INT(cfg.component[0].source, FA_VERSION_COMMAND);
    CHECK_EQ_STR(cfg.component[0].source_arg, "/usr/bin/app-version");
    CHECK_EQ_INT(cfg.component[0].install, FA_INSTALL_SCRIPT);
    CHECK_EQ_STR(cfg.component[0].script, "/usr/lib/firmline/install.sh");
    CHECK_EQ_INT(cfg.component[0].timeout_s, 120);
    CHECK_EQ_STR(cfg.component[1].code, "base.os");
    CHECK(!cfg.component[1].main);
    CHECK_EQ_INT(cfg.component[1].source, FA_VERSION_OS_RELEASE);
    CHECK_EQ_STR(cfg.component[1].source_arg, "VERSION_ID");
    CHECK_EQ_INT(cfg.component[1].install, FA_INSTALL_NONE);
    CHECK_EQ_INT(cfg.component[2].source, FA_VERSION_FILE);
    CHECK_EQ_STR(cfg.component[2].source_arg, "/etc/cfg-version");

    /* a semicolon inside a value is not a comment */
    char buf[1024];
    snprintf(buf, sizeof buf, "%sinstall = script:/opt/a;b\n", MINIMAL);
    CHECK_EQ_INT(load_text(buf, &cfg, err), 0);
    CHECK_EQ_STR(cfg.component[0].script, "/opt/a;b");
}

static void config_defaults(void) {
    static fa_config cfg;
    char err[256] = "";
    CHECK_EQ_INT(load_text(MINIMAL, &cfg, err), 0);
    CHECK_EQ_INT(cfg.broker_port, 8883);
    CHECK_EQ_STR(cfg.data_dir, "/var/lib/firmline");
    CHECK_EQ_STR(cfg.os_release, "/etc/os-release");
    CHECK_EQ_INT(cfg.status_interval_s, 3600);
    CHECK_EQ_INT(cfg.component[0].timeout_s, 600);
    CHECK_EQ_INT(cfg.component[0].install, FA_INSTALL_NONE);
    CHECK_EQ_INT(cfg.component[0].source, FA_VERSION_FIXED);
    CHECK_EQ_STR(cfg.component[0].source_arg, "1.0.0");
    CHECK_EQ_STR(cfg.ca_file, "");
    CHECK_EQ_STR(cfg.serial, "");
    CHECK_EQ_STR(cfg.family, "");
    CHECK_EQ_STR(cfg.reboot_command, "");
}

static void config_refuses_two_main_components(void) {
    static fa_config cfg;
    char err[256] = "";
    char buf[1024];
    snprintf(buf, sizeof buf, "%s[component app]\nmain = true\nversion = fixed:2\n", MINIMAL);
    CHECK_EQ_INT(load_text(buf, &cfg, err), -1);
    CHECK(strstr(err, "main") != NULL);
    /* none at all */
    CHECK_EQ_INT(load_text("[platform]\nurl = https://p\nbroker = b\nupdate_key = /k\n"
                           "[component os]\nversion = fixed:1\n",
                           &cfg, err),
                 -1);
    CHECK(strstr(err, "main") != NULL);
}

static void config_refuses_unknown_key_with_line_number(void) {
    static fa_config cfg;
    char err[256] = "";
    CHECK_EQ_INT(load_text("[platform]\nurl = https://p\nbrokr = b\n", &cfg, err), -1);
    CHECK(strstr(err, "line 3") != NULL);
    CHECK(strstr(err, "brokr") != NULL);
    /* unknown section */
    CHECK_EQ_INT(load_text("\n[plateform]\n", &cfg, err), -1);
    CHECK(strstr(err, "line 2") != NULL);
    /* a component key in [platform] and the reverse */
    CHECK_EQ_INT(load_text("[platform]\nmain = true\n", &cfg, err), -1);
    CHECK(strstr(err, "line 2") != NULL);
    char buf[1024];
    snprintf(buf, sizeof buf, "%surl = x\n", MINIMAL);
    CHECK_EQ_INT(load_text(buf, &cfg, err), -1);
    CHECK(strstr(err, "line 8") != NULL);
}

static void config_accepts_docker_compose_with_defaults(void) {
    static fa_config cfg;
    char err[256] = "";
    char buf[1024];
    snprintf(buf, sizeof buf, "%sinstall = docker-compose\n", MINIMAL);
    CHECK_EQ_INT(load_text(buf, &cfg, err), 0);
    CHECK_EQ_INT(cfg.component[0].install, FA_INSTALL_DOCKER_COMPOSE);
    CHECK_EQ_STR(cfg.component[0].compose_file,
                 "/var/sota/storage/docker-compose/docker-compose.yml");
    CHECK_EQ_STR(cfg.component[0].project, "torizon");
    CHECK_EQ_STR(cfg.component[0].agent_service, "firmline-agent");
    CHECK_EQ_INT(cfg.component[0].health_timeout_s, 120);
    CHECK_EQ_STR(cfg.component[0].script, "");
}

static void config_reads_docker_compose_keys_in_any_order(void) {
    static fa_config cfg;
    char err[256] = "";
    char buf[1024];
    snprintf(buf, sizeof buf,
             "%scompose_file = /opt/app/compose.yml\nproject = my_app-1\n"
             "install = docker-compose\nagent_service = agent\nhealth_timeout = 10\n"
             "version = package:1.0.0\n",
             "[platform]\nurl = https://p\nbroker = b\nupdate_key = /k\n[component os]\n"
             "main = true\n");
    CHECK_EQ_INT(load_text(buf, &cfg, err), 0);
    CHECK_EQ_STR(cfg.component[0].compose_file, "/opt/app/compose.yml");
    CHECK_EQ_STR(cfg.component[0].project, "my_app-1");
    CHECK_EQ_STR(cfg.component[0].agent_service, "agent");
    CHECK_EQ_INT(cfg.component[0].health_timeout_s, 10);
    CHECK_EQ_INT(cfg.component[0].source, FA_VERSION_PACKAGE);
    CHECK_EQ_STR(cfg.component[0].source_arg, "1.0.0");
    snprintf(buf, sizeof buf, "%sinstall = docker-compose\nhealth_timeout = 3600\n", MINIMAL);
    CHECK_EQ_INT(load_text(buf, &cfg, err), 0);
    CHECK_EQ_INT(cfg.component[0].health_timeout_s, 3600);
}

static void config_refuses_a_second_docker_compose_component(void) {
    static fa_config cfg;
    char err[256] = "";
    char buf[1024];
    snprintf(buf, sizeof buf,
             "%sinstall = docker-compose\n[component two]\nversion = fixed:1\n"
             "install = docker-compose\n",
             MINIMAL);
    CHECK_EQ_INT(load_text(buf, &cfg, err), -1);
    CHECK(strstr(err, "line 11") != NULL);
    CHECK(strstr(err, "docker-compose") != NULL);
}

static void config_refuses_bad_docker_compose_values(void) {
    static fa_config cfg;
    char err[256] = "";
    char buf[1024];
    const char *bad[] = {"compose_file = docker-compose.yml",
                         "compose_file = /",
                         "project = Upper",
                         "project = -lead",
                         "project =",
                         "project = has space",
                         "agent_service = a.b",
                         "agent_service = _x",
                         "health_timeout = 9",
                         "health_timeout = 3601",
                         "health_timeout = 1x",
                         "health_timeout ="};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        snprintf(buf, sizeof buf, "%sinstall = docker-compose\n%s\n", MINIMAL, bad[i]);
        CHECK_EQ_INT(load_text(buf, &cfg, err), -1);
        CHECK(strstr(err, "line 9") != NULL);
    }
    char name[80];
    memset(name, 'a', 64);
    name[64] = '\0';
    snprintf(buf, sizeof buf, "%sinstall = docker-compose\nproject = %s\n", MINIMAL, name);
    CHECK_EQ_INT(load_text(buf, &cfg, err), 0); /* 64 characters is the limit */
    snprintf(buf, sizeof buf, "%sinstall = docker-compose\nproject = %sa\n", MINIMAL, name);
    CHECK_EQ_INT(load_text(buf, &cfg, err), -1);
}

static void config_refuses_docker_compose_keys_on_other_components(void) {
    static fa_config cfg;
    char err[256] = "";
    char buf[1024];
    const char *keys[] = {"compose_file = /a/b.yml", "project = p", "agent_service = s",
                          "health_timeout = 30"};
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        snprintf(buf, sizeof buf, "%sinstall = script:/opt/i.sh\n%s\n", MINIMAL, keys[i]);
        CHECK_EQ_INT(load_text(buf, &cfg, err), -1);
        CHECK(strstr(err, "only with install = docker-compose") != NULL);
        CHECK(strstr(err, "line 9") != NULL);
        /* no install key at all (none) */
        snprintf(buf, sizeof buf, "%s%s\n", MINIMAL, keys[i]);
        CHECK_EQ_INT(load_text(buf, &cfg, err), -1);
        CHECK(strstr(err, "only with install = docker-compose") != NULL);
        CHECK(strstr(err, "line 8") != NULL);
    }
}

static void config_refuses_malformed_input(void) {
    static fa_config cfg;
    char err[256] = "";
    char buf[4096];
    /* missing required platform keys */
    CHECK_EQ_INT(load_text("[platform]\nbroker = b\nupdate_key = /k\n[component a]\nmain = true\n"
                           "version = fixed:1\n",
                           &cfg, err),
                 -1);
    CHECK(strstr(err, "url") != NULL);
    CHECK_EQ_INT(load_text("[component a]\nmain = true\nversion = fixed:1\n", &cfg, err), -1);
    /* key outside a section, line without '=' */
    CHECK_EQ_INT(load_text("url = x\n", &cfg, err), -1);
    CHECK(strstr(err, "line 1") != NULL);
    CHECK_EQ_INT(load_text("[platform]\nurl\n", &cfg, err), -1);
    CHECK(strstr(err, "line 2") != NULL);
    /* repeated key, repeated section, repeated component code */
    CHECK_EQ_INT(load_text("[platform]\nurl = https://a\nurl = b\n", &cfg, err), -1);
    CHECK(strstr(err, "line 3") != NULL);
    CHECK_EQ_INT(load_text("[platform]\nurl = https://a\n[platform]\n", &cfg, err), -1);
    CHECK(strstr(err, "line 3") != NULL);
    snprintf(buf, sizeof buf, "%s[component os]\nversion = fixed:2\n", MINIMAL);
    CHECK_EQ_INT(load_text(buf, &cfg, err), -1);
    CHECK(strstr(err, "line 8") != NULL);
    /* bad component codes */
    const char *bad[] = {"UPPER", "-lead", "", "has space", ".dot"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        snprintf(buf, sizeof buf, "[platform]\nurl = https://a\n[component %s]\n", bad[i]);
        CHECK_EQ_INT(load_text(buf, &cfg, err), -1);
        CHECK(strstr(err, "line 3") != NULL);
    }
    strcpy(buf, "[platform]\nurl = https://a\n[component ");
    memset(buf + strlen(buf), 'a', 65);
    strcpy(buf + strlen(buf) + 0, "]\n");
    CHECK_EQ_INT(load_text(buf, &cfg, err), -1);
    /* more than 16 components */
    strcpy(buf, "[platform]\nurl = https://a\n");
    for (int i = 0; i < 17; i++)
        sprintf(buf + strlen(buf), "[component c%d]\nversion = fixed:1\n", i);
    CHECK_EQ_INT(load_text(buf, &cfg, err), -1);
    CHECK(strstr(err, "line 35") != NULL);
    /* a line over 1023 bytes */
    strcpy(buf, "[platform]\nurl = https://");
    memset(buf + strlen(buf), 'x', 1100);
    strcpy(buf + strlen(buf), "\n");
    CHECK_EQ_INT(load_text(buf, &cfg, err), -1);
    CHECK(strstr(err, "line 2") != NULL);
    /* a value too long for its field */
    strcpy(buf, "[platform]\nurl = https://");
    memset(buf + strlen(buf), 'x', 300);
    strcpy(buf + strlen(buf), "\n");
    CHECK_EQ_INT(load_text(buf, &cfg, err), -1);
    CHECK(strstr(err, "line 2") != NULL);
    /* forms: relative paths, unknown schemes, bad numbers */
    const char *bad_lines[] = {"serial = file:relative\n", "serial = magic\n",
                               "serial = command:\n",      "broker_port = 0\n",
                               "broker_port = 99999\n",    "broker_port = 8x\n",
                               "status_interval = -5\n",   "update_key\n"};
    for (size_t i = 0; i < sizeof bad_lines / sizeof bad_lines[0]; i++) {
        snprintf(buf, sizeof buf, "[platform]\n%s", bad_lines[i]);
        CHECK_EQ_INT(load_text(buf, &cfg, err), -1);
        CHECK(strstr(err, "line 2") != NULL);
    }
    const char *bad_comp[] = {"version = file:rel\n",
                              "version = command:rel\n",
                              "version = os-release:lower\n",
                              "version = fixed:\n",
                              "version = nothing\n",
                              "install = script:rel\n",
                              "install = magic\n",
                              "main = yes\n",
                              "timeout = 0\n"};
    for (size_t i = 0; i < sizeof bad_comp / sizeof bad_comp[0]; i++) {
        snprintf(buf, sizeof buf, "%s[component x]\n%s", MINIMAL, bad_comp[i]);
        CHECK_EQ_INT(load_text(buf, &cfg, err), -1);
        CHECK(strstr(err, "line 9") != NULL);
    }
    /* a component without a version */
    snprintf(buf, sizeof buf, "%s[component x]\ninstall = none\n", MINIMAL);
    CHECK_EQ_INT(load_text(buf, &cfg, err), -1);
    /* a missing file */
    CHECK_EQ_INT(fa_config_load("/nonexistent/agent.conf", &cfg, err), -1);
}

static void config_handles_line_endings_and_nul_bytes(void) {
    static fa_config cfg;
    char err[256] = "";
    char buf[1024];
    /* CRLF line endings are accepted, the CR is not part of any value */
    CHECK_EQ_INT(load_text("[platform]\r\nurl = https://p\r\nbroker = b\r\nupdate_key = /k\r\n"
                           "[component os]\r\nmain = true\r\nversion = fixed:1.0\r\n",
                           &cfg, err),
                 0);
    CHECK_EQ_STR(cfg.platform_url, "https://p");
    CHECK_EQ_STR(cfg.component[0].source_arg, "1.0");
    /* the last line without a newline is accepted */
    CHECK_EQ_INT(load_text("[platform]\nurl = https://p\nbroker = b\nupdate_key = /k\n"
                           "[component os]\nmain = true\nversion = fixed:2.0",
                           &cfg, err),
                 0);
    CHECK_EQ_STR(cfg.component[0].source_arg, "2.0");
    /* an equals sign inside a value is kept */
    snprintf(buf, sizeof buf, "%sinstall = script:/opt/a=b\n", MINIMAL);
    CHECK_EQ_INT(load_text(buf, &cfg, err), 0);
    CHECK_EQ_STR(cfg.component[0].script, "/opt/a=b");
    CHECK_EQ_INT(load_text("[platform]\nurl = https://p?a=b\nbroker = b\nupdate_key = /k\n"
                           "[component os]\nmain = true\nversion = fixed:a=b\n",
                           &cfg, err),
                 0);
    CHECK_EQ_STR(cfg.platform_url, "https://p?a=b");
    CHECK_EQ_STR(cfg.component[0].source_arg, "a=b");
    /* a NUL byte anywhere is an error with its line number */
    CHECK_EQ_INT(load_bytes("[platform]\n\0url = https://p\n", 29, &cfg, err), -1);
    CHECK(strstr(err, "line 2") != NULL);
    CHECK_EQ_INT(load_bytes("[platform]\nurl = https://p\0junk\n", 32, &cfg, err), -1);
    CHECK(strstr(err, "line 2") != NULL);
    CHECK_EQ_INT(load_bytes("\0", 1, &cfg, err), -1);
    CHECK(strstr(err, "line 1") != NULL);
}

static void config_platform_value_rules(void) {
    static fa_config cfg;
    char err[256] = "";
    CHECK_EQ_INT(load_text("[platform]\nurl = http://p\n", &cfg, err), -1);
    CHECK(strstr(err, "line 2") != NULL);
    CHECK(strstr(err, "https://") != NULL);
    CHECK_EQ_INT(load_text("[platform]\nurl = https://\n", &cfg, err), -1);
    CHECK_EQ_INT(load_text("[platform]\nupdate_key = key.pem\n", &cfg, err), -1);
    CHECK(strstr(err, "line 2") != NULL);
    CHECK(strstr(err, "absolute") != NULL);
    CHECK_EQ_INT(load_text("[platform]\nreboot_command = reboot now\n", &cfg, err), -1);
    CHECK(strstr(err, "line 2") != NULL);
    CHECK(strstr(err, "absolute") != NULL);
}

static void config_key_table_is_exposed(void) {
    size_t n = 0;
    const char *const *keys = fa_config_keys(&n);
    CHECK_EQ_INT(n, 19);
    int platform = 0, component = 0;
    for (size_t i = 0; i < n; i++) {
        if (strncmp(keys[i], "platform.", 9) == 0)
            platform++;
        if (strncmp(keys[i], "component.", 10) == 0)
            component++;
    }
    CHECK_EQ_INT(platform, 11);
    CHECK_EQ_INT(component, 8);
}

/* The example of the guide (examples/debian-script/agent.conf) is a configuration the agent loads.
 * The test file's own path (absolute in the CMake build) gives the repository root. */
static void example_configuration_is_valid(void) {
    static fa_config cfg;
    char err[256] = "", path[1024];
    const char *here = __FILE__;
    const char *tail = "linux/tests/test_config.c";
    size_t n = strlen(here), t = strlen(tail);
    CHECK(n > t && strcmp(here + n - t, tail) == 0);
    snprintf(path, sizeof path, "%.*sexamples/debian-script/agent.conf", (int)(n - t), here);
    CHECK_EQ_INT(fa_config_load(path, &cfg, err), 0);
    CHECK_EQ_STR(err, "");
    CHECK_EQ_INT(cfg.component_count, 1);
    CHECK(cfg.component[0].main);
    CHECK_EQ_INT(cfg.component[0].install, FA_INSTALL_SCRIPT);
    CHECK_EQ_STR(cfg.component[0].script, "/usr/lib/firmline/install.sh");
    CHECK_EQ_STR(cfg.path, path); /* as given: `run` starts `apply` with it */
}

static void config_path_too_long_is_refused(void) {
    static fa_config cfg;
    static char path[5000];
    char err[256] = "";
    memset(path, 'a', sizeof path - 1);
    path[0] = '/';
    path[sizeof path - 1] = '\0';
    CHECK_EQ_INT(fa_config_load(path, &cfg, err), -1);
    CHECK_EQ_STR(err, "the path of the configuration file is too long");
}

int main(void) {
    RUN(config_reads_every_key);
    RUN(config_defaults);
    RUN(config_refuses_two_main_components);
    RUN(config_refuses_unknown_key_with_line_number);
    RUN(config_accepts_docker_compose_with_defaults);
    RUN(config_reads_docker_compose_keys_in_any_order);
    RUN(config_refuses_a_second_docker_compose_component);
    RUN(config_refuses_bad_docker_compose_values);
    RUN(config_refuses_docker_compose_keys_on_other_components);
    RUN(config_refuses_malformed_input);
    RUN(config_handles_line_endings_and_nul_bytes);
    RUN(config_platform_value_rules);
    RUN(config_key_table_is_exposed);
    RUN(example_configuration_is_valid);
    RUN(config_path_too_long_is_refused);
    return CHECK_RESULT;
}
