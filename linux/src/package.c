/* SPDX-License-Identifier: Apache-2.0 */
#include "package.h"

#include "firmline/fl_json.h"

#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
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

bool fa_package_version_ok(const char *v) {
    if (v == NULL)
        return false;
    size_t n = strlen(v);
    if (n < 1 || n > 64 || v[0] == '.' || v[0] == '-')
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = v[i];
        if (!((c >= 'A' && c <= 'Z') || is_lower_alnum(c) || c == '_' || c == '.' || c == '-'))
            return false;
    }
    return true;
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
        return fail(err, "version is not 1 to 64 of A-Z a-z 0-9 _ . - (not starting with . or -)");
    if (p->image_count < 1 || p->image_count > FA_MAX_COMPONENTS)
        return fail(err, "images: 1 to %d, not %d", FA_MAX_COMPONENTS, p->image_count);
    for (int i = 0; i < p->image_count; i++) {
        const char *service = p->image[i].service;
        char expected[sizeof p->image[i].image];
        if (memchr(service, '\0', sizeof p->image[i].service) == NULL ||
            !fa_package_service_ok(service))
            return fail(err, "image %d: the service is not a name usable in an image name", i + 1);
        for (int k = 0; k < i; k++)
            if (strcmp(p->image[k].service, service) == 0)
                return fail(err, "image %d: the service %s is there twice", i + 1, service);
        snprintf(expected, sizeof expected, FA_PACKAGE_REGISTRY "/%s:%s", service, p->version);
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
    /* Every value passed the checks: none holds a character JSON must escape. */
    text t = {out, cap, 0, true};
    put(&t, "{\"format\":%d,\"architecture\":\"%s\",\"version\":\"%s\",\"images\":[", p->format,
        p->architecture, p->version);
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
