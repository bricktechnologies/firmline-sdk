/* SPDX-License-Identifier: Apache-2.0 */
/* jsmn itself, strict and static, for the readers of docker's JSON (as in core/src/json.c); it
 * must come before fl_json.h. */
#define JSMN_STRICT
#define JSMN_STATIC
#include "jsmn.h"

#include "package.h"

#include "firmline/fl_json.h"

#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 9 tokens around the images and 7 per image: 121 for 16 images. The table holds more, so that a
 * package of 17 or a few more images is refused for its count, with that reason. */
#define PACKAGE_TOKENS 256
#define ID_PREFIX "sha256:"
#define ID_HEX 64

static int fail(char err[256], const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int fail(char err[256], const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, 256, fmt, ap);
    va_end(ap);
    return -1;
}

static bool is_lower_alnum(char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); }

static bool tag_char(char c) {
    return (c >= 'A' && c <= 'Z') || is_lower_alnum(c) || c == '_' || c == '.' || c == '-';
}

/* As the platform takes a firmware version: 1 to 64 bytes, no control character, no white space
 * at either end (the platform trims it, and the version must stay the same text). */
bool fa_package_version_ok(const char *v) {
    if (v == NULL)
        return false;
    size_t n = strlen(v);
    if (n < 1 || n > 64 || v[0] == ' ' || v[n - 1] == ' ')
        return false;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)v[i] < 0x20 || v[i] == 0x7f)
            return false;
    return true;
}

void fa_package_tag(const char *version, char tag[FA_PACKAGE_TAG_MAX + 1]) {
    size_t n = 0;
    if (version[0] == '.' || version[0] == '-')
        tag[n++] = '_';
    for (const char *c = version; *c != '\0' && n < FA_PACKAGE_TAG_MAX; c++)
        tag[n++] = tag_char(*c) ? *c : '_';
    tag[n] = '\0';
}

/* A path component of an image name (the Docker reference grammar): [a-z0-9]+ groups joined by
 * '.', '_', '__' or one or more '-'. */
bool fa_package_service_ok(const char *s) {
    if (s == NULL)
        return false;
    size_t n = strlen(s), i = 0;
    if (n < 1 || n > 64)
        return false;
    for (;;) {
        if (i >= n || !is_lower_alnum(s[i]))
            return false; /* a group must start here */
        while (i < n && is_lower_alnum(s[i]))
            i++;
        if (i == n)
            return true;
        if (s[i] == '.')
            i++;
        else if (s[i] == '_')
            i += (i + 1 < n && s[i + 1] == '_') ? 2 : 1;
        else if (s[i] == '-')
            while (i < n && s[i] == '-')
                i++;
        else
            return false;
    }
}

bool fa_package_id_ok(const char *id) {
    if (id == NULL || strlen(id) != sizeof ID_PREFIX - 1 + ID_HEX ||
        strncmp(id, ID_PREFIX, sizeof ID_PREFIX - 1) != 0)
        return false;
    for (const char *h = id + sizeof ID_PREFIX - 1; *h != '\0'; h++)
        if (!((*h >= '0' && *h <= '9') || (*h >= 'a' && *h <= 'f')))
            return false;
    return true;
}

static bool architecture_ok(const char *a) {
    size_t n = strlen(a);
    if (n < 1 || n > 15)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!is_lower_alnum(a[i]))
            return false;
    return true;
}

/* The checks of a whole package, shared by the parser and the writer. */
static int check(const fa_package *p, char err[256]) {
    if (p->format != FA_PACKAGE_FORMAT)
        return fail(err, "format is not %d", FA_PACKAGE_FORMAT);
    if (memchr(p->architecture, '\0', sizeof p->architecture) == NULL ||
        !architecture_ok(p->architecture))
        return fail(err, "architecture is not 1 to 15 of a-z 0-9");
    if (memchr(p->version, '\0', sizeof p->version) == NULL || !fa_package_version_ok(p->version))
        return fail(err, "version is not 1 to 64 bytes without a control character or a space at "
                         "either end");
    if (p->image_count < 1 || p->image_count > FA_MAX_COMPONENTS)
        return fail(err, "images: 1 to %d, not %d", FA_MAX_COMPONENTS, p->image_count);
    for (int i = 0; i < p->image_count; i++) {
        const char *service = p->image[i].service;
        char expected[256], tag[FA_PACKAGE_TAG_MAX + 1];
        if (memchr(service, '\0', sizeof p->image[i].service) == NULL ||
            !fa_package_service_ok(service))
            return fail(err, "image %d: the service is not a name usable in an image name", i + 1);
        for (int k = 0; k < i; k++)
            if (strcmp(p->image[k].service, service) == 0)
                return fail(err, "image %d: the service %s is there twice", i + 1, service);
        fa_package_tag(p->version, tag);
        snprintf(expected, sizeof expected, FA_PACKAGE_REGISTRY "/%s:%s", service, tag);
        if (memchr(p->image[i].image, '\0', sizeof p->image[i].image) == NULL ||
            strcmp(p->image[i].image, expected) != 0)
            return fail(err, "image %d: the image is not %s", i + 1, expected);
        if (memchr(p->image[i].id, '\0', sizeof p->image[i].id) == NULL ||
            !fa_package_id_ok(p->image[i].id))
            return fail(err, "image %d: the id is not sha256: and 64 lowercase hex", i + 1);
    }
    return 0;
}

/* A string member into a field: a value too long for it is refused like any other bad value. */
static int member(const fl_json *j, int object, const char *key, char *out, size_t cap) {
    return fl_json_member_string(j, object, key, out, cap) == FL_OK ? 0 : -1;
}

static int parse(const char *json, size_t len, fa_package *out, char err[256]) {
    jsmntok_t tok[PACKAGE_TOKENS];
    fl_json j;
    int64_t format = 0;
    int first = 0, count = 0;
    if (fl_json_parse_tokens(&j, json, len, tok, PACKAGE_TOKENS) != FL_OK)
        return fail(err, "not a JSON object, or over %d tokens", PACKAGE_TOKENS);
    if (j.tok[0].size != 4)
        return fail(err, "not exactly the keys format, architecture, version and images");
    if (fl_json_int(&j, "format", &format) != FL_OK)
        return fail(err, "format is missing or not an integer");
    if (format != FA_PACKAGE_FORMAT)
        return fail(err, "format is not %d", FA_PACKAGE_FORMAT);
    out->format = FA_PACKAGE_FORMAT;
    if (fl_json_string(&j, "architecture", out->architecture, sizeof out->architecture) != FL_OK)
        return fail(err, "architecture is missing, not a string or too long");
    if (fl_json_string(&j, "version", out->version, sizeof out->version) != FL_OK)
        return fail(err, "version is missing, not a string or too long");
    if (fl_json_array(&j, "images", &first, &count) != FL_OK)
        return fail(err, "images is missing or not an array");
    if (count < 1 || count > FA_MAX_COMPONENTS)
        return fail(err, "images: 1 to %d, not %d", FA_MAX_COMPONENTS, count);
    for (int i = 0, t = first; i < count; i++, t = fl_json_next(&j, t)) {
        /* Exactly three members, each found: no other key, none repeated. */
        if (j.tok[t].type != JSMN_OBJECT || j.tok[t].size != 3 ||
            member(&j, t, "service", out->image[i].service, sizeof out->image[i].service) != 0 ||
            member(&j, t, "image", out->image[i].image, sizeof out->image[i].image) != 0 ||
            member(&j, t, "id", out->image[i].id, sizeof out->image[i].id) != 0)
            return fail(err, "image %d: not an object of exactly service, image and id strings",
                        i + 1);
    }
    out->image_count = count;
    return check(out, err);
}

int fa_package_parse(const char *json, size_t len, fa_package *out, char err[256]) {
    memset(out, 0, sizeof *out);
    err[0] = '\0';
    if (json == NULL) {
        fail(err, "no document");
        return -1;
    }
    if (parse(json, len, out, err) == 0)
        return 0;
    memset(out, 0, sizeof *out);
    return -1;
}

/* Appends to a NUL-terminated text; after the first overflow nothing more is written. */
typedef struct {
    char *out;
    size_t cap, len;
    bool ok;
} text;

static void put(text *t, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void put(text *t, const char *fmt, ...) {
    if (!t->ok)
        return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(t->out + t->len, t->cap - t->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= t->cap - t->len)
        t->ok = false;
    else
        t->len += (size_t)n;
}

int fa_package_write(const fa_package *p, char *out, size_t cap) {
    char err[256];
    if (p == NULL || out == NULL || cap == 0 || check(p, err) != 0)
        return -1;
    /* Every value passed the checks: only the version can hold a character JSON must escape, and
     * no control character, so " and \ are all there is to escape. */
    char version[2 * sizeof p->version];
    size_t n = 0;
    for (const char *c = p->version; *c != '\0'; c++) {
        if (*c == '"' || *c == '\\')
            version[n++] = '\\';
        version[n++] = *c;
    }
    version[n] = '\0';
    text t = {out, cap, 0, true};
    put(&t, "{\"format\":%d,\"architecture\":\"%s\",\"version\":\"%s\",\"images\":[", p->format,
        p->architecture, version);
    for (int i = 0; i < p->image_count; i++)
        put(&t, "%s{\"service\":\"%s\",\"image\":\"%s\",\"id\":\"%s\"}", i > 0 ? "," : "",
            p->image[i].service, p->image[i].image, p->image[i].id);
    put(&t, "]}");
    if (!t.ok || t.len > INT_MAX) {
        out[0] = '\0';
        return -1;
    }
    return (int)t.len;
}

/* ---- what docker gives pack ------------------------------------------------------------ */

/* A document of docker, its tokens in a table of the size jsmn counted. */
typedef struct {
    const char *js;
    jsmntok_t *tok;
    int count;
} doc;

/* Parses a whole document whose root is of type `root`. 0, or -1 (d->tok is then NULL). */
static int doc_parse(doc *d, const char *json, size_t len, jsmntype_t root) {
    jsmn_parser parser;
    d->js = json;
    d->tok = NULL;
    d->count = 0;
    if (json == NULL || len == 0 || len > INT_MAX)
        return -1;
    jsmn_init(&parser);
    int n = jsmn_parse(&parser, json, len, NULL, 0);
    if (n < 1 || (d->tok = calloc((size_t)n, sizeof(jsmntok_t))) == NULL)
        return -1;
    jsmn_init(&parser);
    if (jsmn_parse(&parser, json, len, d->tok, (unsigned int)n) != n || d->tok[0].type != root) {
        free(d->tok);
        d->tok = NULL;
        return -1;
    }
    d->count = n;
    return 0;
}

/* The index of the token after the value at v. */
static int skip(const doc *d, int v) {
    int n = v + 1;
    while (n < d->count && d->tok[n].start < d->tok[v].end)
        n++;
    return n;
}

static bool token_is(const doc *d, int i, const char *text) {
    size_t n = strlen(text);
    return d->tok[i].type == JSMN_STRING && (size_t)(d->tok[i].end - d->tok[i].start) == n &&
           memcmp(d->js + d->tok[i].start, text, n) == 0;
}

/* The value of `key` in the object at token o, or -1. */
static int doc_member(const doc *d, int o, const char *key) {
    if (o < 0 || o >= d->count || d->tok[o].type != JSMN_OBJECT)
        return -1;
    int i = o + 1;
    for (int p = 0; p < d->tok[o].size && i + 1 < d->count; p++) {
        if (token_is(d, i, key))
            return i + 1;
        i = skip(d, i + 1);
    }
    return -1;
}

/* A string token copied as it is (escapes are not decoded: a service name, an image reference or
 * a file name of docker has none, and one with a backslash is refused). 0, or -1 when it is not a
 * string, does not fit or has one. */
static int copy_token(const doc *d, int i, char *out, size_t cap) {
    if (i < 0 || i >= d->count || d->tok[i].type != JSMN_STRING)
        return -1;
    size_t n = (size_t)(d->tok[i].end - d->tok[i].start);
    if (n >= cap || memchr(d->js + d->tok[i].start, '\\', n) != NULL)
        return -1;
    memcpy(out, d->js + d->tok[i].start, n);
    out[n] = '\0';
    return 0;
}

static int compose_services(const doc *d, fa_compose_service out[FA_MAX_COMPONENTS], int *count,
                            char err[256]) {
    int list = doc_member(d, 0, "services");
    if (list < 0 || d->tok[list].type != JSMN_OBJECT)
        return fail(err, "cannot read the services from what docker compose config gives");
    int n = d->tok[list].size;
    if (n == 0)
        return fail(err, "the composition has no services");
    if (n > FA_MAX_COMPONENTS)
        return fail(err, "the composition has %d services, a package holds at most %d", n,
                    FA_MAX_COMPONENTS);
    for (int k = 0, i = list + 1; k < n; k++, i = skip(d, i + 1)) {
        char *service = out[k].service;
        if (copy_token(d, i, service, sizeof out[k].service) != 0 ||
            !fa_package_service_ok(service)) {
            int shown = d->tok[i].end - d->tok[i].start;
            return fail(err,
                        "the service name %.*s cannot be part of an image name (lowercase "
                        "letters and digits joined by . _ __ or -, 64 at most)",
                        shown > 64 ? 64 : shown, d->js + d->tok[i].start);
        }
        int image = doc_member(d, i + 1, "image");
        if (image < 0)
            return fail(err,
                        "the service %s has no image: (with only build:, build and tag the image "
                        "first and name it in image:)",
                        service);
        if (copy_token(d, image, out[k].image, sizeof out[k].image) != 0 || out[k].image[0] == '\0')
            return fail(err, "the image of the service %s is not a plain image name", service);
    }
    *count = n;
    return 0;
}

int fa_compose_services(const char *json, size_t len, fa_compose_service out[FA_MAX_COMPONENTS],
                        int *count, char err[256]) {
    doc d;
    err[0] = '\0';
    *count = 0;
    if (doc_parse(&d, json, len, JSMN_OBJECT) != 0)
        return fail(err, "cannot read what docker compose config gives");
    int rc = compose_services(&d, out, count, err);
    free(d.tok);
    return rc;
}

/* "sha256:<hex>" from the Config of a manifest entry: "<hex>.json" or "blobs/sha256/<hex>". */
static int config_id(const char *config, char id[72]) {
    static const char blobs[] = "blobs/sha256/";
    size_t n = strlen(config);
    const char *hex = NULL;
    if (n == ID_HEX + 5 && strcmp(config + ID_HEX, ".json") == 0)
        hex = config;
    else if (n == sizeof blobs - 1 + ID_HEX && strncmp(config, blobs, sizeof blobs - 1) == 0)
        hex = config + sizeof blobs - 1;
    if (hex == NULL)
        return -1;
    memcpy(id, ID_PREFIX, sizeof ID_PREFIX - 1);
    memcpy(id + sizeof ID_PREFIX - 1, hex, ID_HEX);
    id[sizeof ID_PREFIX - 1 + ID_HEX] = '\0';
    return fa_package_id_ok(id) ? 0 : -1;
}

/* Whether the RepoTags of the entry at token e hold name: 1, 0 (also for none or null: an image
 * without a tag), or -1 when RepoTags is not an array of strings. */
static int entry_has_tag(const doc *d, int e, const char *name) {
    int tags = doc_member(d, e, "RepoTags");
    if (tags < 0 ||
        (d->tok[tags].type == JSMN_PRIMITIVE && d->tok[tags].end - d->tok[tags].start == 4 &&
         memcmp(d->js + d->tok[tags].start, "null", 4) == 0))
        return 0;
    if (d->tok[tags].type != JSMN_ARRAY)
        return -1;
    int found = 0;
    for (int k = 0, t = tags + 1; k < d->tok[tags].size; k++, t = skip(d, t)) {
        if (d->tok[t].type != JSMN_STRING)
            return -1;
        if (token_is(d, t, name))
            found = 1;
    }
    return found;
}

static int manifest_ids(const doc *d, fa_package *p, char err[256]) {
    for (int i = 0; i < p->image_count; i++) {
        int entry = -1;
        for (int k = 0, e = 1; k < d->tok[0].size; k++, e = skip(d, e)) {
            if (d->tok[e].type != JSMN_OBJECT)
                return fail(err, "the manifest of docker save has an entry that is not an object");
            int has = entry_has_tag(d, e, p->image[i].image);
            if (has < 0)
                return fail(err, "the manifest of docker save has RepoTags that are not names");
            if (has == 1 && entry >= 0)
                return fail(err, "the manifest of docker save has %s in two entries",
                            p->image[i].image);
            if (has == 1)
                entry = e;
        }
        if (entry < 0)
            return fail(err, "the manifest of docker save has no entry for %s", p->image[i].image);
        char config[160], id[72];
        if (copy_token(d, doc_member(d, entry, "Config"), config, sizeof config) != 0 ||
            config_id(config, id) != 0)
            return fail(err, "the manifest of docker save has no image configuration for %s",
                        p->image[i].image);
        memcpy(p->image[i].id, id, sizeof id);
    }
    return 0;
}

int fa_package_ids_from_manifest(const char *json, size_t len, fa_package *p, char err[256]) {
    doc d;
    err[0] = '\0';
    if (doc_parse(&d, json, len, JSMN_ARRAY) != 0)
        return fail(err, "cannot read the manifest of docker save");
    int rc = manifest_ids(&d, p, err);
    free(d.tok);
    return rc;
}
