/* SPDX-License-Identifier: Apache-2.0 */
/* firmline-agent status [--config <path>]: one JSON object on stdout, for the test station and
 * for support, from the files of the data folder only (never the network, never a command):
 *   registered           device.json exists
 *   deviceId, familyId   from device.json (familyId null before T178)
 *   certificateNotAfter  the expiry of device.pem, UTC ISO 8601
 *   endpoint             "relay" while endpoint.json exists, otherwise "direct"
 *   lastConnection       from connection.json (the last connection to the broker)
 *   queue                [{release, component, version}] of the stored offers, oldest first
 *   pendingInstall       {release, component, version} of install.json (a script that runs or
 *                        waits for the restart)
 * A value that is unknown or cannot be read is null; when device.json is missing, everything but
 * `registered` (false) is null. Exit 0; 1 for a usage or configuration error. */
#define _POSIX_C_SOURCE 200809L
#include "commands.h"

#include "config.h"
#include "firmline/fl_json.h"
#include "keys.h"
#include "log.h"
#include "service.h"
#include "store.h"

#include <dirent.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MAX_OFFERS 64
#define RELEASE_LEN 36
#define MANIFEST_B64_MAX 8192

/* ---- Output ------------------------------------------------------------------------------- */

typedef struct {
    char *data;
    size_t len, cap;
    bool failed;
} text;

static void put(text *t, const char *s, size_t n) {
    if (t->failed)
        return;
    if (t->len + n + 1 > t->cap) {
        size_t cap = (t->cap + n + 1) * 2;
        char *grown = realloc(t->data, cap);
        if (grown == NULL) {
            t->failed = true;
            return;
        }
        t->data = grown;
        t->cap = cap;
    }
    memcpy(t->data + t->len, s, n);
    t->len += n;
    t->data[t->len] = '\0';
}

static void put_str(text *t, const char *s) { put(t, s, strlen(s)); }

/* A JSON string (", \ and control characters escaped), or null for NULL. */
static void put_value(text *t, const char *s) {
    if (s == NULL) {
        put_str(t, "null");
        return;
    }
    put_str(t, "\"");
    for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; p++) {
        char esc[8];
        if (*p == '"' || *p == '\\') {
            esc[0] = '\\';
            esc[1] = (char)*p;
            put(t, esc, 2);
        } else if (*p < 0x20) {
            snprintf(esc, sizeof esc, "\\u%04x", *p);
            put_str(t, esc);
        } else {
            put(t, (const char *)p, 1);
        }
    }
    put_str(t, "\"");
}

static void put_key(text *t, const char *key, bool first) {
    if (!first)
        put_str(t, ",");
    put_value(t, key);
    put_str(t, ":");
}

/* ---- Reading ------------------------------------------------------------------------------ */

static bool exists(const char *dir, const char *name) {
    char path[PATH_MAX];
    struct stat st;
    int n = snprintf(path, sizeof path, "%s/%s", dir, name);
    return n > 0 && (size_t)n < sizeof path && lstat(path, &st) == 0;
}

/* One string member of a JSON file of the data folder: 0, or -1. */
static int file_string(const char *dir, const char *name, const char *key, char *out, size_t cap) {
    char *data = NULL;
    size_t len = 0;
    fl_json j;
    int rc = fa_store_read(dir, name, &data, &len) == 0 && fl_json_parse(&j, data, len) == FL_OK &&
                     fl_json_string(&j, key, out, cap) == FL_OK
                 ? 0
                 : -1;
    free(data);
    return rc;
}

/* release, component and version of a JSON text: 0, or -1. */
typedef struct {
    char release[RELEASE_LEN + 1], component[65], version[65];
} release_info;

static int release_fields(const char *json, size_t len, release_info *out) {
    fl_json j;
    return fl_json_parse(&j, json, len) == FL_OK &&
                   fl_json_string(&j, "release", out->release, sizeof out->release) == FL_OK &&
                   fl_json_string(&j, "component", out->component, sizeof out->component) ==
                       FL_OK &&
                   fl_json_string(&j, "version", out->version, sizeof out->version) == FL_OK
               ? 0
               : -1;
}

static void put_release(text *t, const release_info *info) {
    put_str(t, "{");
    put_key(t, "release", true);
    put_value(t, info->release);
    put_key(t, "component", false);
    put_value(t, info->component);
    put_key(t, "version", false);
    put_value(t, info->version);
    put_str(t, "}");
}

/* The manifest of a stored offer, decoded from base64, read for display only: the agent checks
 * the signature when it runs. 0, or -1. */
static int offer_fields(const char *dir, const char *name, release_info *out) {
    char *data = NULL, *b64 = malloc(MANIFEST_B64_MAX), *manifest = malloc(MANIFEST_B64_MAX);
    size_t len = 0;
    fl_json j;
    int rc = -1;
    if (b64 != NULL && manifest != NULL && fa_store_read(dir, name, &data, &len) == 0 &&
        fl_json_parse(&j, data, len) == FL_OK &&
        fl_json_string(&j, "manifest", b64, MANIFEST_B64_MAX) == FL_OK) {
        size_t n = strlen(b64);
        int decoded = n > 0 && n % 4 == 0 ? EVP_DecodeBlock((unsigned char *)manifest,
                                                            (const unsigned char *)b64, (int)n)
                                          : -1;
        if (decoded > 0) {
            for (size_t i = n; i > 0 && b64[i - 1] == '='; i--)
                decoded--; /* EVP_DecodeBlock counts the padding as bytes */
            rc = decoded > 0 ? release_fields(manifest, (size_t)decoded, out) : -1;
        }
    }
    free(data);
    free(b64);
    free(manifest);
    return rc;
}

typedef struct {
    char name[NAME_MAX + 1];
    struct timespec mtime;
} offer_file;

static int by_arrival(const void *a, const void *b) {
    const offer_file *x = a, *y = b;
    if (x->mtime.tv_sec != y->mtime.tv_sec)
        return x->mtime.tv_sec < y->mtime.tv_sec ? -1 : 1;
    if (x->mtime.tv_nsec != y->mtime.tv_nsec)
        return x->mtime.tv_nsec < y->mtime.tv_nsec ? -1 : 1;
    return strcmp(x->name, y->name);
}

/* "offer-<release>.json" as the agent names stored offers. */
static bool offer_name(const char *name) {
    static const char prefix[] = "offer-", suffix[] = ".json";
    size_t n = strlen(name);
    return n == sizeof prefix - 1 + RELEASE_LEN + sizeof suffix - 1 &&
           strncmp(name, prefix, sizeof prefix - 1) == 0 &&
           strcmp(name + n - (sizeof suffix - 1), suffix) == 0;
}

/* The queue: the stored offers, oldest first (the order the agent rebuilds it in). */
static void put_queue(text *t, const char *dir) {
    offer_file *files = calloc(MAX_OFFERS, sizeof *files);
    DIR *d = files != NULL ? opendir(dir) : NULL;
    if (d == NULL) {
        free(files);
        put_str(t, "null");
        return;
    }
    int count = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && count < MAX_OFFERS) {
        char path[PATH_MAX];
        struct stat st;
        int n = snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        if (!offer_name(e->d_name) || n < 0 || (size_t)n >= sizeof path || lstat(path, &st) != 0)
            continue;
        snprintf(files[count].name, sizeof files[count].name, "%s", e->d_name);
        files[count++].mtime = st.st_mtim;
    }
    closedir(d);
    qsort(files, (size_t)count, sizeof *files, by_arrival);
    put_str(t, "[");
    bool first = true;
    for (int i = 0; i < count; i++) {
        release_info info;
        if (offer_fields(dir, files[i].name, &info) != 0)
            continue;
        if (!first)
            put_str(t, ",");
        put_release(t, &info);
        first = false;
    }
    put_str(t, "]");
    free(files);
}

static void put_pending_install(text *t, const char *dir) {
    char *data = NULL;
    size_t len = 0;
    release_info info;
    if (fa_store_read(dir, "install.json", &data, &len) != 0 ||
        release_fields(data, len, &info) != 0) {
        put_str(t, "null");
    } else {
        put_release(t, &info);
    }
    free(data);
}

static void put_status(text *t, const fa_config *cfg) {
    const char *dir = cfg->data_dir;
    bool registered = exists(dir, "device.json");
    put_str(t, "{");
    put_key(t, "registered", true);
    put_str(t, registered ? "true" : "false");
    if (!registered) {
        static const char *const rest[] = {"deviceId",      "familyId",       "certificateNotAfter",
                                           "endpoint",      "lastConnection", "queue",
                                           "pendingInstall"};
        for (size_t i = 0; i < sizeof rest / sizeof rest[0]; i++) {
            put_key(t, rest[i], false);
            put_str(t, "null");
        }
        put_str(t, "}");
        return;
    }

    fa_identity id;
    bool known = fa_identity_load(dir, &id) == 0;
    put_key(t, "deviceId", false);
    put_value(t, known ? id.device_id : NULL);
    put_key(t, "familyId", false);
    put_value(t, known && id.family_id[0] != '\0' ? id.family_id : NULL);

    char *pem = NULL, iso[26];
    size_t len = 0;
    fl_time not_before = 0, not_after = 0;
    bool expiry = fa_store_read(dir, "device.pem", &pem, &len) == 0 &&
                  fa_certificate_validity(pem, len, &not_before, &not_after) == 0 &&
                  fl_time_format(not_after, 0, iso) == FL_OK;
    free(pem);
    put_key(t, "certificateNotAfter", false);
    put_value(t, expiry ? iso : NULL);

    put_key(t, "endpoint", false);
    put_value(t, exists(dir, FA_ENDPOINT) ? "relay" : "direct");

    char last[32];
    fl_time ignored;
    bool connected = file_string(dir, FA_CONNECTION, "lastConnection", last, sizeof last) == 0 &&
                     fl_time_parse(last, strlen(last), &ignored) == FL_OK;
    put_key(t, "lastConnection", false);
    put_value(t, connected ? last : NULL);

    put_key(t, "queue", false);
    put_queue(t, dir);
    put_key(t, "pendingInstall", false);
    put_pending_install(t, dir);
    put_str(t, "}");
}

int fa_cmd_status(int argc, char **argv) {
    const char *config = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--config") != 0 || config != NULL || i + 1 >= argc ||
            argv[i + 1][0] == '\0') {
            fa_log("error", "status: unknown or repeated argument (number %d)", i + 1);
            fputs("usage: firmline-agent status [--config <path>]\n", stderr);
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
    text t = {NULL, 0, 0, false};
    put_status(&t, &cfg);
    if (t.failed) {
        fa_log("error", "status: out of memory");
        free(t.data);
        return 1;
    }
    printf("%s\n", t.data);
    free(t.data);
    return 0;
}
