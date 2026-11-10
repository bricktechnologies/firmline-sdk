/* SPDX-License-Identifier: Apache-2.0 */
/* firmline-agent register: a new device key and its CSR, POST /api/v1/provisioning with the
 * one-time token and the serial number, then the identity in the data folder.
 *
 * Order of the writes, so that a crash at any point leaves an unregistered device: the key is made
 * under a temporary name before the request; after the 200 come device.pem, chain.pem, root.pem,
 * the key renamed to device.key, and last device.json, whose existence means "registered".
 * The token, the key, the CSR and the certificates are never logged; the log names only the
 * deviceId and the platform's code. */
#define _POSIX_C_SOURCE 200809L
#include "commands.h"

#include "components.h"
#include "config.h"
#include "firmline/fl_json.h"
#include "firmline/fl_messages.h"
#include "http.h"
#include "keys.h"
#include "log.h"
#include "store.h"

#include <ctype.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define EXIT_LOCAL 1 /* usage, configuration or local failure */
#define EXIT_REFUSED 2
#define EXIT_NETWORK 3

#define PROVISIONING_PATH "/api/v1/provisioning"
#define DEVICETREE_SERIAL "/proc/device-tree/serial-number"
#define TEMP_KEY "register.key" /* the new key, until the identity is saved */
#define IDENTITY "device.json"
#define TOKEN_MAX 512
#define SERIAL_MAX 64 /* the platform's limit; a source giving more is unreadable */
#define SOURCE_READ_MAX 4096
#define CSR_MAX 4096
#define REQUEST_MAX 8192

static const char CERT_BEGIN[] = "-----BEGIN CERTIFICATE-----";
static const char CERT_END[] = "-----END CERTIFICATE-----";

typedef struct {
    const char *token, *token_file, *serial, *config;
} options;

typedef struct {
    int exit_code;
    int delete_token; /* the token is used up or refused: its file goes */
} outcome;

static void usage(void) {
    fputs("usage: firmline-agent register (--token <token> | --token-file <path>) "
          "[--serial <serial>] [--config <path>]\n",
          stderr);
}

static int parse_options(int argc, char **argv, options *o) {
    memset(o, 0, sizeof *o);
    for (int i = 0; i < argc; i++) {
        const char **slot = NULL;
        if (strcmp(argv[i], "--token") == 0)
            slot = &o->token;
        else if (strcmp(argv[i], "--token-file") == 0)
            slot = &o->token_file;
        else if (strcmp(argv[i], "--serial") == 0)
            slot = &o->serial;
        else if (strcmp(argv[i], "--config") == 0)
            slot = &o->config;
        if (slot == NULL) {
            /* not echoed: it could be a token typed without --token */
            fa_log("error", "register: unknown argument (number %d)", i + 1);
            return -1;
        }
        if (*slot != NULL) {
            fa_log("error", "register: %s is given twice", argv[i]);
            return -1;
        }
        if (i + 1 >= argc || argv[i + 1][0] == '\0') {
            fa_log("error", "register: %s needs a value", argv[i]);
            return -1;
        }
        *slot = argv[++i];
    }
    if ((o->token == NULL) == (o->token_file == NULL)) {
        fa_log("error", "register: give either --token or --token-file");
        return -1;
    }
    return 0;
}

/* The first line of text, up to a newline or a NUL byte (device-tree strings end with one),
 * without spaces at the sides: 0, or -1 when it is empty or does not fit in cap (with the NUL). */
static int first_value(const char *text, size_t len, char *out, size_t cap) {
    size_t end = 0;
    while (end < len && text[end] != '\n' && text[end] != '\0')
        end++;
    size_t start = 0;
    while (start < end && isspace((unsigned char)text[start]))
        start++;
    while (end > start && isspace((unsigned char)text[end - 1]))
        end--;
    if (end == start || end - start >= cap)
        return -1;
    memcpy(out, text + start, end - start);
    out[end - start] = '\0';
    return 0;
}

/* first_value of the start of a file. The bytes read are wiped (the file may hold the token). */
static int value_from_file(const char *path, char *out, size_t cap) {
    char buf[SOURCE_READ_MAX];
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return -1;
    size_t n = fread(buf, 1, sizeof buf, f);
    int failed = ferror(f);
    fclose(f);
    int rc = failed ? -1 : first_value(buf, n, out, cap);
    OPENSSL_cleanse(buf, sizeof buf);
    return rc;
}

/* The serial number from the source of the configuration: devicetree, file:<path>, command:<path>.
 */
static int serial_from_source(const fa_config *cfg, char serial[SERIAL_MAX + 1]) {
    if (strcmp(cfg->serial, "devicetree") == 0)
        return value_from_file(DEVICETREE_SERIAL, serial, SERIAL_MAX + 1);
    if (strncmp(cfg->serial, "file:", 5) == 0)
        return value_from_file(cfg->serial + 5, serial, SERIAL_MAX + 1);
    /* command:<path>, run as a version command is: no shell, 10 s, first line trimmed */
    fa_component source;
    memset(&source, 0, sizeof source);
    source.source = FA_VERSION_COMMAND;
    snprintf(source.source_arg, sizeof source.source_arg, "%s", cfg->serial + 8);
    return fa_component_version(cfg, &source, serial);
}

static int exists(const char *dir, const char *name) {
    char path[600];
    struct stat st;
    snprintf(path, sizeof path, "%s/%s", dir, name);
    return stat(path, &st) == 0;
}

/* A code as the platform writes them (letters, digits, '_', '-', '.'): safe on stdout and in the
 * log. */
static int plain_code(const char *code) {
    if (code[0] == '\0')
        return 0;
    for (const char *p = code; *p != '\0'; p++)
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-' && *p != '.')
            return 0;
    return 1;
}

/* The last certificate of the chain (the platform root), up to its END line, plus a newline. */
static int last_certificate(const char *chain, char *out, size_t cap) {
    const char *begin = NULL;
    for (const char *p = chain; (p = strstr(p, CERT_BEGIN)) != NULL; p++)
        begin = p;
    const char *end = begin != NULL ? strstr(begin, CERT_END) : NULL;
    if (end == NULL)
        return -1;
    size_t n = (size_t)(end - begin) + strlen(CERT_END);
    if (n + 2 > cap)
        return -1;
    memcpy(out, begin, n);
    out[n] = '\n';
    out[n + 1] = '\0';
    return 0;
}

static int write_identity(const char *dir, const fl_provisioned *p) {
    char json[1024];
    fl_jw w;
    fl_jw_begin(&w, json, sizeof json);
    fl_jw_string(&w, "deviceId", p->device_id);
    fl_jw_string(&w, "familyId", p->family_id);
    fl_jw_string(&w, "clientId", p->client_id);
    fl_jw_string(&w, "topicRoot", p->topic_root);
    fl_jw_string(&w, "otaOfferTopic", p->ota_offer_topic);
    int n = fl_jw_end(&w);
    return n < 0 ? -1 : fa_store_write(dir, IDENTITY, json, (size_t)n, 0644);
}

/* Certificate, chain, root, key, then device.json. On a failure everything written is removed,
 * so the folder is again that of an unregistered device. */
static int save_identity(const char *dir, const fl_provisioned *p, const char *root) {
    int ok = fa_store_write(dir, "device.pem", p->certificate, strlen(p->certificate), 0644) == 0 &&
             fa_store_write(dir, "chain.pem", p->chain, strlen(p->chain), 0644) == 0 &&
             fa_store_write(dir, "root.pem", root, strlen(root), 0644) == 0 &&
             fa_store_rename(dir, TEMP_KEY, "device.key") == 0 && write_identity(dir, p) == 0;
    if (ok)
        return 0;
    static const char *const written[] = {"device.key", "root.pem", "chain.pem", "device.pem"};
    for (size_t i = 0; i < sizeof written / sizeof written[0]; i++)
        fa_store_remove(dir, written[i]);
    return -1;
}

static outcome network_error(const char *why, int status) {
    puts("network_error");
    if (status > 0)
        fa_log("error", "register: %s (HTTP %d)", why, status);
    else
        fa_log("error", "register: %s", why);
    return (outcome){EXIT_NETWORK, 0};
}

static outcome on_success(const char *dir, const fa_http_response *res) {
    char *pem = malloc(FA_HTTP_BODY_MAX);
    char root[8192];
    fl_provisioned p;
    if (pem == NULL)
        return network_error("no memory for the answer", 0);
    /* A 200 that cannot be read is an answer lost: the token is used, the device exists on the
     * platform, and trying again tells provisioning_token_invalid. */
    if (fl_provisioned_parse(res->body, res->len, pem, FA_HTTP_BODY_MAX, &p) != FL_OK ||
        strstr(p.certificate, CERT_BEGIN) == NULL ||
        last_certificate(p.chain, root, sizeof root) != 0) {
        free(pem);
        return network_error("the answer of the platform cannot be read", 0);
    }
    outcome out = {0, 1};
    if (save_identity(dir, &p, root) != 0) {
        fa_log("error",
               "register: device %s is registered, but the data folder cannot be written; "
               "revoke it and register again with a new token",
               p.device_id);
        out.exit_code = EXIT_LOCAL;
    } else {
        printf("%s\n", p.device_id);
        fa_log("info", "registered as device %s", p.device_id);
    }
    free(pem);
    return out;
}

static outcome on_answer(const char *dir, const fa_http_response *res) {
    if (res->status == 200)
        return on_success(dir, res);
    if (res->status >= 500) /* the platform or a proxy failed: the token is not used */
        return network_error("the platform failed", res->status);
    char code[64];
    if (fl_problem_code(res->body, res->len, code) != FL_OK || !plain_code(code))
        snprintf(code, sizeof code, "http_%d", res->status);
    puts(code);
    fa_log("error", "register: the platform refused the registration: %s (HTTP %d)", code,
           res->status);
    /* 429: too many requests from this address, the same token works a minute later */
    return (outcome){EXIT_REFUSED, res->status != 429};
}

static outcome provision(const fa_config *cfg, const char *token, const char *serial) {
    const outcome local = {EXIT_LOCAL, 0};
    const char *dir = cfg->data_dir;
    char csr[CSR_MAX], url[512], request[REQUEST_MAX];

    if (fa_key_generate(dir, TEMP_KEY) != 0 || fa_csr_create(dir, TEMP_KEY, csr, sizeof csr) != 0) {
        fa_log("error", "register: cannot create the device key in %s", dir);
        fa_store_remove(dir, TEMP_KEY);
        return local;
    }
    size_t base = strlen(cfg->platform_url);
    while (base > 0 && cfg->platform_url[base - 1] == '/')
        base--;
    int url_len =
        snprintf(url, sizeof url, "%.*s%s", (int)base, cfg->platform_url, PROVISIONING_PATH);
    if (url_len < 0 || (size_t)url_len >= sizeof url ||
        fl_registration_body(request, sizeof request, token, serial, csr) < 0) {
        fa_log("error", "register: the request cannot be built");
        OPENSSL_cleanse(request, sizeof request);
        fa_store_remove(dir, TEMP_KEY);
        return local;
    }

    fa_http_response res;
    int rc = fa_http_post_json(url, cfg->ca_file, request, &res);
    OPENSSL_cleanse(request, sizeof request); /* it holds the token */
    outcome out =
        rc != 0 ? network_error("the platform cannot be reached", 0) : on_answer(dir, &res);
    fa_http_response_free(&res);
    if (out.exit_code != 0)
        fa_store_remove(dir, TEMP_KEY); /* a key is kept only with its certificate */
    return out;
}

int fa_cmd_register(int argc, char **argv) {
    options o;
    if (parse_options(argc, argv, &o) != 0) {
        usage();
        return EXIT_LOCAL;
    }
    fa_config cfg;
    char err[256];
    if (fa_config_load(o.config != NULL ? o.config : FA_DEFAULT_CONFIG, &cfg, err) != 0) {
        fa_log("error", "configuration: %s", err);
        return EXIT_LOCAL;
    }
    if (cfg.serial[0] != '\0' && o.serial != NULL) {
        fa_log("error",
               "register: the configuration reads the serial number (serial = %s): "
               "--serial is not allowed",
               cfg.serial);
        return EXIT_LOCAL;
    }
    if (cfg.serial[0] == '\0' && o.serial == NULL) {
        fa_log("error", "register: no serial number: give --serial, or serial in the "
                        "configuration");
        return EXIT_LOCAL;
    }
    if (mkdir(cfg.data_dir, 0700) != 0 && errno != EEXIST) {
        fa_log("error", "register: cannot create the data folder %s: %s", cfg.data_dir,
               strerror(errno));
        return EXIT_LOCAL;
    }
    if (exists(cfg.data_dir, IDENTITY)) {
        puts("already_registered");
        fa_log("error", "register: the device is already registered (%s/%s exists)", cfg.data_dir,
               IDENTITY);
        return EXIT_LOCAL;
    }

    char serial_buf[SERIAL_MAX + 1];
    const char *serial = o.serial;
    if (serial == NULL) {
        if (serial_from_source(&cfg, serial_buf) != 0) {
            fa_log("error", "register: cannot read the serial number (serial = %s)", cfg.serial);
            return EXIT_LOCAL;
        }
        serial = serial_buf;
    }

    char token[TOKEN_MAX + 1];
    if (o.token_file != NULL) {
        if (value_from_file(o.token_file, token, sizeof token) != 0) {
            fa_log("error", "register: cannot read a token from %s", o.token_file);
            return EXIT_LOCAL;
        }
    } else if (strlen(o.token) > TOKEN_MAX) {
        fa_log("error", "register: the token is longer than %d characters", TOKEN_MAX);
        return EXIT_LOCAL;
    } else {
        memcpy(token, o.token, strlen(o.token) + 1);
    }

    outcome out = provision(&cfg, token, serial);
    OPENSSL_cleanse(token, sizeof token);
    if (o.token_file != NULL && out.delete_token && unlink(o.token_file) != 0 && errno != ENOENT)
        fa_log("warning", "register: cannot delete the token file %s: %s", o.token_file,
               strerror(errno));
    return out.exit_code;
}
