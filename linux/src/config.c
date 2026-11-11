/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE 1023

/* Every configuration key, once. The parser refuses what is not here, and fa_config_keys() hands
 * the table to the check against the integration guide. */
typedef enum {
    K_URL,
    K_BROKER,
    K_BROKER_PORT,
    K_CA_FILE,
    K_UPDATE_KEY,
    K_FAMILY,
    K_SERIAL,
    K_DATA_DIR,
    K_OS_RELEASE,
    K_REBOOT_COMMAND,
    K_STATUS_INTERVAL,
    K_MAIN,
    K_VERSION,
    K_INSTALL,
    K_TIMEOUT,
    K_COUNT
} key_id;

static const char *const KEY_NAMES[K_COUNT] = {
    "platform.url",
    "platform.broker",
    "platform.broker_port",
    "platform.ca_file",
    "platform.update_key",
    "platform.family",
    "platform.serial",
    "platform.data_dir",
    "platform.os_release",
    "platform.reboot_command",
    "platform.status_interval",
    "component.main",
    "component.version",
    "component.install",
    "component.timeout",
};

const char *const *fa_config_keys(size_t *count) {
    *count = K_COUNT;
    return KEY_NAMES;
}

typedef enum { SEC_NONE, SEC_PLATFORM, SEC_COMPONENT } section_kind;

typedef struct {
    fa_config *cfg;
    char *err;
    int line;
    section_kind section;
    fa_component *comp; /* the component being read */
    bool seen[K_COUNT]; /* keys already given in the current section */
    bool platform_seen;
    bool comp_has_version;
    bool main_seen;
    bool have_url, have_broker, have_update_key;
} parser;

static int fail(parser *p, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int fail(parser *p, const char *fmt, ...) {
    int n = 0;
    if (p->line > 0)
        n = snprintf(p->err, 256, "line %d: ", p->line);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(p->err + n, (size_t)(256 - n), fmt, ap);
    va_end(ap);
    return -1;
}

static char *trim(char *s) {
    while (isspace((unsigned char)*s))
        s++;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1]))
        s[--n] = '\0';
    return s;
}

/* Copies value into dst when it fits with its terminator. */
static bool set_str(char *dst, size_t size, const char *value) {
    size_t n = strlen(value);
    if (n >= size)
        return false;
    memcpy(dst, value, n + 1);
    return true;
}

static bool is_abs_path(const char *s) { return s[0] == '/' && s[1] != '\0'; }

static bool parse_int(const char *s, int min, int max, int *out) {
    if (*s == '\0' || strlen(s) > 9)
        return false;
    for (const char *c = s; *c != '\0'; c++)
        if (!isdigit((unsigned char)*c))
            return false;
    int v = atoi(s);
    if (v < min || v > max)
        return false;
    *out = v;
    return true;
}

static bool valid_code(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n > 64)
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        bool alnum = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        if (!(alnum || (i > 0 && (c == '.' || c == '_' || c == '-'))))
            return false;
    }
    return true;
}

static bool valid_os_release_key(const char *s) {
    if (*s == '\0')
        return false;
    for (; *s != '\0'; s++)
        if (!((*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9') || *s == '_'))
            return false;
    return true;
}

static bool printable(const char *s) {
    for (; *s != '\0'; s++)
        if ((unsigned char)*s < 0x20 || *s == 0x7f)
            return false;
    return true;
}

static int platform_value(parser *p, key_id key, const char *v) {
    fa_config *c = p->cfg;
    switch (key) {
    case K_URL:
        if (!set_str(c->platform_url, sizeof c->platform_url, v))
            return fail(p, "url is too long");
        if (strncmp(v, "https://", 8) != 0 || v[8] == '\0')
            return fail(p, "url must start with https://");
        p->have_url = true;
        return 0;
    case K_BROKER:
        if (!set_str(c->broker_host, sizeof c->broker_host, v))
            return fail(p, "broker is too long");
        p->have_broker = v[0] != '\0';
        return 0;
    case K_BROKER_PORT:
        if (!parse_int(v, 1, 65535, &c->broker_port))
            return fail(p, "broker_port must be a number from 1 to 65535");
        return 0;
    case K_CA_FILE:
        return set_str(c->ca_file, sizeof c->ca_file, v) ? 0 : fail(p, "ca_file is too long");
    case K_UPDATE_KEY:
        if (!set_str(c->update_key, sizeof c->update_key, v))
            return fail(p, "update_key is too long");
        if (!is_abs_path(v))
            return fail(p, "update_key must be an absolute path");
        p->have_update_key = true;
        return 0;
    case K_FAMILY:
        return set_str(c->family, sizeof c->family, v) ? 0 : fail(p, "family is too long");
    case K_SERIAL:
        if (v[0] != '\0' && strcmp(v, "devicetree") != 0 &&
            !((strncmp(v, "file:", 5) == 0 && is_abs_path(v + 5)) ||
              (strncmp(v, "command:", 8) == 0 && is_abs_path(v + 8))))
            return fail(p, "serial must be devicetree, file:<absolute path> or "
                           "command:<absolute path>");
        return set_str(c->serial, sizeof c->serial, v) ? 0 : fail(p, "serial is too long");
    case K_DATA_DIR:
        return set_str(c->data_dir, sizeof c->data_dir, v) ? 0 : fail(p, "data_dir is too long");
    case K_OS_RELEASE:
        return set_str(c->os_release, sizeof c->os_release, v) ? 0
                                                               : fail(p, "os_release is too long");
    case K_REBOOT_COMMAND:
        /* split on spaces and spawned without a shell: the program must be a full path */
        if (v[0] != '\0' && !is_abs_path(v))
            return fail(p, "reboot_command must start with an absolute path");
        return set_str(c->reboot_command, sizeof c->reboot_command, v)
                   ? 0
                   : fail(p, "reboot_command is too long");
    case K_STATUS_INTERVAL:
        if (!parse_int(v, 1, 86400, &c->status_interval_s))
            return fail(p, "status_interval must be a number of seconds from 1 to 86400");
        return 0;
    default:
        return fail(p, "internal error");
    }
}

static int version_value(parser *p, fa_component *comp, const char *v) {
    if (strncmp(v, "fixed:", 6) == 0) {
        size_t n = strlen(v + 6);
        if (n == 0 || n > 64 || !printable(v + 6))
            return fail(p, "fixed version must be 1 to 64 printable characters");
        comp->source = FA_VERSION_FIXED;
        memcpy(comp->source_arg, v + 6, n + 1);
    } else if (strncmp(v, "os-release:", 11) == 0) {
        if (!valid_os_release_key(v + 11))
            return fail(p, "os-release key must be upper case letters, digits and '_'");
        comp->source = FA_VERSION_OS_RELEASE;
        if (!set_str(comp->source_arg, sizeof comp->source_arg, v + 11))
            return fail(p, "version is too long");
    } else if (strncmp(v, "file:", 5) == 0 || strncmp(v, "command:", 8) == 0) {
        bool is_file = v[0] == 'f';
        const char *path = v + (is_file ? 5 : 8);
        if (!is_abs_path(path))
            return fail(p, "the path in version must be absolute");
        comp->source = is_file ? FA_VERSION_FILE : FA_VERSION_COMMAND;
        if (!set_str(comp->source_arg, sizeof comp->source_arg, path))
            return fail(p, "version is too long");
    } else {
        return fail(p, "version must be fixed:<v>, os-release:<KEY>, file:<path> or "
                       "command:<path>");
    }
    p->comp_has_version = true;
    return 0;
}

static int component_value(parser *p, key_id key, const char *v) {
    fa_component *comp = p->comp;
    switch (key) {
    case K_MAIN:
        if (strcmp(v, "true") != 0 && strcmp(v, "false") != 0)
            return fail(p, "main must be true or false");
        comp->main = strcmp(v, "true") == 0;
        return 0;
    case K_VERSION:
        return version_value(p, comp, v);
    case K_INSTALL:
        if (strcmp(v, "none") == 0) {
            comp->install = FA_INSTALL_NONE;
            comp->script[0] = '\0';
            return 0;
        }
        if (strcmp(v, "docker-compose") == 0)
            return fail(p, "install = docker-compose is supported from T179");
        if (strncmp(v, "script:", 7) == 0) {
            if (!is_abs_path(v + 7))
                return fail(p, "the script path must be absolute");
            comp->install = FA_INSTALL_SCRIPT;
            return set_str(comp->script, sizeof comp->script, v + 7)
                       ? 0
                       : fail(p, "install is too long");
        }
        return fail(p, "install must be script:<path> or none");
    case K_TIMEOUT:
        if (!parse_int(v, 1, 86400, &comp->timeout_s))
            return fail(p, "timeout must be a number of seconds from 1 to 86400");
        return 0;
    default:
        return fail(p, "internal error");
    }
}

/* Closes the component being read: it needs a version. */
static int finish_component(parser *p) {
    if (p->section == SEC_COMPONENT && !p->comp_has_version) {
        p->line = 0;
        return fail(p, "component %s has no version", p->comp->code);
    }
    return 0;
}

static int open_section(parser *p, char *name) {
    if (finish_component(p) != 0)
        return -1;
    memset(p->seen, 0, sizeof p->seen);
    if (strcmp(name, "platform") == 0) {
        if (p->platform_seen)
            return fail(p, "section [platform] is given twice");
        p->platform_seen = true;
        p->section = SEC_PLATFORM;
        return 0;
    }
    if (strncmp(name, "component", 9) == 0 && isspace((unsigned char)name[9])) {
        char *code = trim(name + 9);
        if (!valid_code(code))
            return fail(p, "a component code is 1 to 64 characters of [a-z0-9._-], "
                           "starting with a letter or digit");
        if (p->cfg->component_count >= FA_MAX_COMPONENTS)
            return fail(p, "more than %d components", FA_MAX_COMPONENTS);
        for (int i = 0; i < p->cfg->component_count; i++)
            if (strcmp(p->cfg->component[i].code, code) == 0)
                return fail(p, "component %s is given twice", code);
        p->comp = &p->cfg->component[p->cfg->component_count++];
        memset(p->comp, 0, sizeof *p->comp);
        memcpy(p->comp->code, code, strlen(code) + 1);
        p->comp->install = FA_INSTALL_NONE;
        p->comp->timeout_s = 600;
        p->comp_has_version = false;
        p->section = SEC_COMPONENT;
        return 0;
    }
    return fail(p, "unknown section [%.60s]", name);
}

static int key_value(parser *p, char *line) {
    char *eq = strchr(line, '=');
    if (eq == NULL)
        return fail(p, "expected key = value");
    *eq = '\0';
    char *key = trim(line);
    char *value = trim(eq + 1);
    if (p->section == SEC_NONE)
        return fail(p, "key '%.60s' outside a section", key);

    const char *prefix = p->section == SEC_PLATFORM ? "platform." : "component.";
    size_t plen = strlen(prefix);
    key_id id = K_COUNT;
    for (int i = 0; i < K_COUNT; i++)
        if (strncmp(KEY_NAMES[i], prefix, plen) == 0 && strcmp(KEY_NAMES[i] + plen, key) == 0)
            id = (key_id)i;
    if (id == K_COUNT)
        return fail(p, "unknown key '%.60s' in [%s]", key,
                    p->section == SEC_PLATFORM ? "platform" : "component");
    if (p->seen[id])
        return fail(p, "key '%s' is given twice in the section", key);
    p->seen[id] = true;
    return p->section == SEC_PLATFORM ? platform_value(p, id, value)
                                      : component_value(p, id, value);
}

static int final_checks(parser *p) {
    p->line = 0;
    if (!p->have_url)
        return fail(p, "missing url in [platform]");
    if (!p->have_broker)
        return fail(p, "missing broker in [platform]");
    if (!p->have_update_key)
        return fail(p, "missing update_key in [platform]");
    int mains = 0;
    for (int i = 0; i < p->cfg->component_count; i++)
        if (p->cfg->component[i].main)
            mains++;
    if (mains != 1)
        return fail(p, "exactly one component must have main = true (found %d)", mains);
    return 0;
}

int fa_config_load(const char *path, fa_config *out, char err[256]) {
    err[0] = '\0';
    memset(out, 0, sizeof *out);
    out->broker_port = 8883;
    out->status_interval_s = 3600;
    snprintf(out->data_dir, sizeof out->data_dir, "/var/lib/firmline");
    snprintf(out->os_release, sizeof out->os_release, "/etc/os-release");

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        snprintf(err, 256, "cannot read %.150s: %s", path, strerror(errno));
        return -1;
    }
    parser p;
    memset(&p, 0, sizeof p);
    p.cfg = out;
    p.err = err;

    char buf[MAX_LINE + 1];
    int rc = 0;
    for (;;) {
        /* Read byte by byte, so the real length is known: a NUL byte is an error, not a cut. */
        size_t n = 0;
        int ch, got_any = 0, too_long = 0, has_nul = 0;
        while ((ch = fgetc(f)) != EOF && ch != '\n') {
            got_any = 1;
            if (ch == '\0')
                has_nul = 1;
            if (n < MAX_LINE)
                buf[n++] = (char)ch;
            else
                too_long = 1;
        }
        if (ch == EOF && !got_any)
            break;
        p.line++;
        if (has_nul) {
            rc = fail(&p, "the file contains a NUL byte");
            break;
        }
        if (too_long) {
            rc = fail(&p, "line is longer than %d bytes", MAX_LINE);
            break;
        }
        buf[n] = '\0';
        char *line = trim(buf);
        if (*line == '\0' || *line == '#' || *line == ';')
            continue;
        if (*line == '[') {
            size_t len = strlen(line);
            if (line[len - 1] != ']') {
                rc = fail(&p, "section header must end with ']'");
                break;
            }
            line[len - 1] = '\0';
            rc = open_section(&p, trim(line + 1));
        } else {
            rc = key_value(&p, line);
        }
        if (rc != 0)
            break;
    }
    if (rc == 0 && ferror(f)) {
        p.line = 0;
        rc = fail(&p, "cannot read %.150s", path);
    }
    fclose(f);
    if (rc == 0)
        rc = finish_component(&p);
    if (rc == 0)
        rc = final_checks(&p);
    return rc;
}
