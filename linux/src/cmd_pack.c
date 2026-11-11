/* SPDX-License-Identifier: Apache-2.0 */
/* firmline-agent pack --compose <file> --version <v> --output <file.tar>: the package of a Docker
 * Compose application, to upload as the firmware of a release. It runs where the images are
 * built (a developer's machine or a CI job), not on the device, with the docker CLI and its
 * Compose plugin, tar and gzip.
 *
 * The package is an uncompressed tar of exactly, in this order:
 *   firmline-package.json  the description (package.h): architecture, version, and per service
 *                          its image firmline.local/<service>:<version> and the image ID;
 *   docker-compose.yml     the composition as Compose renders it with an override that gives each
 *                          service that image, `pull_policy: never` and no `build:`. It is not
 *                          normalized and paths are not resolved, so that the device's project
 *                          names the volumes and networks and no path of this machine goes in;
 *   images.tar.gz          `docker save` of the images under their new names, `gzip -n`.
 * Every service must name its image, present on this machine (pack never pulls), all of one
 * architecture; the new names stay tagged here. The files are made in a temporary folder next to
 * the output, removed on every exit, also on SIGINT, SIGTERM and SIGHUP; the output appears only
 * complete (a rename) and replaces a file of the same name. */
#define _GNU_SOURCE /* mkdtemp, strdup */
/* The rendered composition nests deeper than the core JSON reader allows (healthcheck.test is at
 * level 5): it is read with jsmn directly, compiled here as in core/src/json.c. */
#define JSMN_STRICT
#define JSMN_STATIC
#include "jsmn.h"

#include "commands.h"

#include "docker.h"
#include "log.h"
#include "package.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define COMPOSE_JSON_MAX (256 * 1024) /* the composition as JSON; larger is refused */
#define INSPECT_MAX 512               /* "<id> <architecture>\n" */
#define IMAGE_REF_MAX 256             /* the image of a service in the composition */
#define SHORT_MS (60 * 1000)          /* compose config, image inspect, tag */
#define LONG_MS (30 * 60 * 1000)      /* save, gzip, tar */

typedef struct {
    const char *compose, *version, *output;
} options;

/* The services as the composition names them, and their images here. */
typedef struct {
    int count;
    struct {
        char service[65];
        char source[IMAGE_REF_MAX];
        char architecture[16];
    } s[FA_MAX_COMPONENTS];
} services;

static volatile sig_atomic_t interrupted = 0;

static void on_signal(int sig) {
    (void)sig;
    interrupted = 1;
    fa_command_cancel();
}

static void usage(void) {
    fputs("usage: firmline-agent pack --compose <file> --version <version> --output <file.tar>\n",
          stderr);
}

static int parse_options(int argc, char **argv, options *o) {
    memset(o, 0, sizeof *o);
    for (int i = 0; i < argc; i++) {
        const char **slot = NULL;
        if (strcmp(argv[i], "--compose") == 0)
            slot = &o->compose;
        else if (strcmp(argv[i], "--version") == 0)
            slot = &o->version;
        else if (strcmp(argv[i], "--output") == 0)
            slot = &o->output;
        if (slot == NULL) {
            fa_log("error", "pack: unknown argument (number %d)", i + 1);
            return -1;
        }
        if (*slot != NULL) {
            fa_log("error", "pack: %s is given twice", argv[i]);
            return -1;
        }
        if (i + 1 >= argc || argv[i + 1][0] == '\0') {
            fa_log("error", "pack: %s needs a value", argv[i]);
            return -1;
        }
        *slot = argv[++i];
    }
    if (o->compose == NULL || o->version == NULL || o->output == NULL) {
        fa_log("error", "pack: --compose, --version and --output are all needed");
        return -1;
    }
    return 0;
}

/* ---- the composition as JSON ----------------------------------------------------------- */

typedef struct {
    const char *js;
    jsmntok_t *tok;
    int count;
} doc;

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
static int member(const doc *d, int o, const char *key) {
    if (d->tok[o].type != JSMN_OBJECT)
        return -1;
    int i = o + 1;
    for (int p = 0; p < d->tok[o].size && i + 1 < d->count; p++) {
        if (token_is(d, i, key))
            return i + 1;
        i = skip(d, i + 1);
    }
    return -1;
}

/* A string token copied as it is (escapes are not decoded: a service name or an image reference
 * has none, and one with a backslash is refused). 0, or -1 when it does not fit or has one. */
static int copy_token(const doc *d, int i, char *out, size_t cap) {
    size_t n = (size_t)(d->tok[i].end - d->tok[i].start);
    if (d->tok[i].type != JSMN_STRING || n >= cap || memchr(d->js + d->tok[i].start, '\\', n))
        return -1;
    memcpy(out, d->js + d->tok[i].start, n);
    out[n] = '\0';
    return 0;
}

/* The services of `docker compose config --format json` and the image each names. */
static int read_services(const char *json, size_t len, services *out) {
    jsmn_parser parser;
    jsmn_init(&parser);
    int n = jsmn_parse(&parser, json, len, NULL, 0);
    if (n < 1) {
        fa_log("error", "pack: cannot read what docker compose config gives");
        return -1;
    }
    doc d = {json, calloc((size_t)n, sizeof(jsmntok_t)), n};
    if (d.tok == NULL) {
        fa_log("error", "pack: out of memory");
        return -1;
    }
    int rc = -1;
    jsmn_init(&parser);
    int list;
    if (jsmn_parse(&parser, json, len, d.tok, (unsigned int)n) != n ||
        d.tok[0].type != JSMN_OBJECT || (list = member(&d, 0, "services")) < 0 ||
        d.tok[list].type != JSMN_OBJECT) {
        fa_log("error", "pack: cannot read the services from what docker compose config gives");
    } else if (d.tok[list].size == 0) {
        fa_log("error", "pack: the composition has no services");
    } else if (d.tok[list].size > FA_MAX_COMPONENTS) {
        fa_log("error", "pack: the composition has %d services, a package holds at most %d",
               d.tok[list].size, FA_MAX_COMPONENTS);
    } else {
        rc = 0;
        out->count = d.tok[list].size;
        for (int k = 0, i = list + 1; k < out->count && rc == 0; k++, i = skip(&d, i + 1)) {
            char *service = out->s[k].service;
            int image = member(&d, i + 1, "image");
            if (copy_token(&d, i, service, sizeof out->s[k].service) != 0 ||
                !fa_package_service_ok(service)) {
                fa_log("error",
                       "pack: the service name %.*s cannot be part of an image name (lowercase "
                       "letters and digits joined by . _ __ or -, 64 at most)",
                       d.tok[i].end - d.tok[i].start > 64 ? 64 : d.tok[i].end - d.tok[i].start,
                       json + d.tok[i].start);
                rc = -1;
            } else if (image < 0) {
                fa_log("error",
                       "pack: the service %s has no image: (with only build:, build and tag the "
                       "image first and name it in image:)",
                       service);
                rc = -1;
            } else if (copy_token(&d, image, out->s[k].source, sizeof out->s[k].source) != 0 ||
                       out->s[k].source[0] == '\0') {
                fa_log("error", "pack: the image of the service %s is not a plain image name",
                       service);
                rc = -1;
            }
        }
    }
    free(d.tok);
    return rc;
}

/* ---- the steps --------------------------------------------------------------------------- */

/* The JSON of the composition, NUL-terminated in a buffer the caller frees. */
static char *compose_json(const char *compose) {
    char *json = malloc(COMPOSE_JSON_MAX);
    if (json == NULL) {
        fa_log("error", "pack: out of memory");
        return NULL;
    }
    const char *argv[] = {"compose",  "-f",   compose,          "config",
                          "--format", "json", "--no-normalize", "--no-path-resolution",
                          NULL};
    if (fa_docker_run(argv, json, COMPOSE_JSON_MAX, SHORT_MS) != 0) {
        if (!interrupted)
            fa_log("error", "pack: docker compose cannot read the composition %s", compose);
        free(json);
        return NULL;
    }
    return json;
}

/* The ID and architecture of each source image, into the package. */
static int inspect_images(const services *sv, fa_package *p, services *arch) {
    for (int i = 0; i < sv->count; i++) {
        char out[INSPECT_MAX], id[INSPECT_MAX], architecture[INSPECT_MAX];
        const char *argv[] = {"image",         "inspect", "--format", "{{.Id}} {{.Architecture}}",
                              sv->s[i].source, NULL};
        int rc = fa_docker_run(argv, out, sizeof out, SHORT_MS);
        if (interrupted)
            return -1;
        if (rc != 0) {
            fa_log("error",
                   "pack: the image %s of the service %s is not on this machine (pack does not "
                   "pull: pull or build it first)",
                   sv->s[i].source, sv->s[i].service);
            return -1;
        }
        char extra;
        if (sscanf(out, "%511s %511s %c", id, architecture, &extra) != 2 || !fa_package_id_ok(id) ||
            strlen(architecture) >= sizeof p->architecture) {
            fa_log("error", "pack: cannot read the ID and architecture of the image %s",
                   sv->s[i].source);
            return -1;
        }
        snprintf(p->image[i].service, sizeof p->image[i].service, "%s", sv->s[i].service);
        snprintf(p->image[i].image, sizeof p->image[i].image, FA_PACKAGE_REGISTRY "/%s:%s",
                 sv->s[i].service, p->version);
        memcpy(p->image[i].id, id, strlen(id) + 1); /* checked: 71 bytes */
        memcpy(arch->s[i].architecture, architecture, strlen(architecture) + 1);
        if (i > 0 && strcmp(architecture, arch->s[0].architecture) != 0) {
            fa_log("error",
                   "pack: the images are of two architectures: %s (service %s) and %s (service "
                   "%s); a package is for one",
                   arch->s[0].architecture, sv->s[0].service, architecture, sv->s[i].service);
            return -1;
        }
    }
    p->image_count = sv->count;
    snprintf(p->architecture, sizeof p->architecture, "%s", arch->s[0].architecture);
    return 0;
}

static int write_file(const char *dir, const char *name, const char *text) {
    char path[PATH_MAX];
    if (snprintf(path, sizeof path, "%s/%s", dir, name) >= (int)sizeof path)
        return -1;
    FILE *f = fopen(path, "w");
    if (f == NULL)
        return -1;
    size_t len = strlen(text);
    int failed = fwrite(text, 1, len, f) != len;
    failed |= fclose(f) != 0;
    return failed ? -1 : 0;
}

/* The override that renames the images: service names and image names need no YAML escaping
 * (package.h rules), they are quoted all the same so that no name reads as a number or a bool. */
static int write_override(const char *dir, const fa_package *p) {
    char text[FA_MAX_COMPONENTS * 300 + 64];
    size_t len = (size_t)snprintf(text, sizeof text, "services:\n");
    for (int i = 0; i < p->image_count && len < sizeof text; i++)
        len += (size_t)snprintf(text + len, sizeof text - len,
                                "  \"%s\":\n    image: \"%s\"\n    pull_policy: never\n"
                                "    build: !reset null\n",
                                p->image[i].service, p->image[i].image);
    if (len >= sizeof text)
        return -1;
    return write_file(dir, "override.yml", text);
}

static int render_composition(const char *dir, const char *compose) {
    char override[PATH_MAX], rendered[PATH_MAX];
    if (snprintf(override, sizeof override, "%s/override.yml", dir) >= (int)sizeof override ||
        snprintf(rendered, sizeof rendered, "%s/docker-compose.yml", dir) >= (int)sizeof rendered)
        return -1;
    const char *argv[] = {"compose",
                          "-f",
                          compose,
                          "-f",
                          override,
                          "config",
                          "--no-normalize",
                          "--no-path-resolution",
                          "-o",
                          rendered,
                          NULL};
    return fa_docker_run(argv, NULL, 0, SHORT_MS) == 0 ? 0 : -1;
}

static int tag_and_save(const char *dir, const fa_package *p) {
    for (int i = 0; i < p->image_count; i++) {
        const char *argv[] = {"tag", p->image[i].id, p->image[i].image, NULL};
        if (fa_docker_run(argv, NULL, 0, SHORT_MS) != 0) {
            if (!interrupted)
                fa_log("error", "pack: cannot tag the image of the service %s as %s",
                       p->image[i].service, p->image[i].image);
            return -1;
        }
    }
    char archive[PATH_MAX];
    if (snprintf(archive, sizeof archive, "%s/images.tar", dir) >= (int)sizeof archive)
        return -1;
    const char *save[FA_MAX_COMPONENTS + 4] = {"save", "-o", archive};
    for (int i = 0; i < p->image_count; i++)
        save[3 + i] = p->image[i].image;
    save[3 + p->image_count] = NULL;
    if (fa_docker_run(save, NULL, 0, LONG_MS) != 0) {
        if (!interrupted)
            fa_log("error", "pack: docker save of the images failed");
        return -1;
    }
    const char *gzip[] = {"gzip", "-n", "--", archive, NULL};
    if (fa_command_run(gzip, NULL, 0, LONG_MS) != 0) {
        if (!interrupted)
            fa_log("error", "pack: gzip of the images failed");
        return -1;
    }
    return 0;
}

static int write_tar(const char *dir) {
    char archive[PATH_MAX];
    if (snprintf(archive, sizeof archive, "%s/package.tar", dir) >= (int)sizeof archive)
        return -1;
    const char *argv[] = {"tar",
                          "--create",
                          "--file",
                          archive,
                          "--directory",
                          dir,
                          "--owner=0",
                          "--group=0",
                          "--numeric-owner",
                          "--mode=u=rw,go=r",
                          "--",
                          "firmline-package.json",
                          "docker-compose.yml",
                          "images.tar.gz",
                          NULL};
    if (fa_command_run(argv, NULL, 0, LONG_MS) != 0) {
        if (!interrupted)
            fa_log("error", "pack: tar of the package failed");
        return -1;
    }
    return 0;
}

/* Removes the temporary folder and whatever is in it (flat: the steps make only files). */
static void remove_folder(const char *dir) {
    DIR *d = opendir(dir);
    if (d != NULL) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            char path[PATH_MAX];
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                continue;
            if (snprintf(path, sizeof path, "%s/%s", dir, e->d_name) < (int)sizeof path)
                unlink(path);
        }
        closedir(d);
    }
    if (rmdir(dir) != 0)
        fa_log("warning", "pack: cannot remove the temporary folder %s (%s)", dir, strerror(errno));
}

/* Everything between the temporary folder and the rename of the package to the output. */
static int build(const options *o, const char *dir) {
    static services sv, arch;
    static fa_package p;
    char description[8192], renamed[PATH_MAX];
    memset(&sv, 0, sizeof sv);
    memset(&arch, 0, sizeof arch);
    memset(&p, 0, sizeof p);
    p.format = FA_PACKAGE_FORMAT;
    snprintf(p.version, sizeof p.version, "%s", o->version);

    char *json = compose_json(o->compose);
    if (json == NULL)
        return -1;
    int rc = read_services(json, strlen(json), &sv);
    free(json);
    if (rc != 0 || inspect_images(&sv, &p, &arch) != 0)
        return -1;
    if (fa_package_write(&p, description, sizeof description) < 0 ||
        write_file(dir, "firmline-package.json", description) != 0 ||
        write_override(dir, &p) != 0) {
        fa_log("error", "pack: cannot write the description in %s", dir);
        return -1;
    }
    if (render_composition(dir, o->compose) != 0) {
        if (!interrupted)
            fa_log("error", "pack: docker compose cannot render the composition with the new image "
                            "names");
        return -1;
    }
    if (tag_and_save(dir, &p) != 0 || write_tar(dir) != 0)
        return -1;
    if (interrupted)
        return -1;
    if (snprintf(renamed, sizeof renamed, "%s/package.tar", dir) >= (int)sizeof renamed ||
        rename(renamed, o->output) != 0) {
        fa_log("error", "pack: cannot write %s (%s)", o->output, strerror(errno));
        return -1;
    }
    fa_log("info", "pack: %s: version %s, %s, %d images", o->output, p.version, p.architecture,
           p.image_count);
    return 0;
}

int fa_cmd_pack(int argc, char **argv) {
    options o;
    if (parse_options(argc, argv, &o) != 0) {
        usage();
        return 1;
    }
    if (!fa_package_version_ok(o.version)) {
        fa_log("error", "pack: the version is the tag of the images and the firmware version: 1 "
                        "to 64 of A-Z a-z 0-9 _ . - (not starting with . or -)");
        return 1;
    }
    struct stat st;
    if (stat(o.output, &st) == 0 && S_ISDIR(st.st_mode)) {
        fa_log("error", "pack: --output %s is a folder", o.output);
        return 1;
    }
    char dir[PATH_MAX];
    const char *slash = strrchr(o.output, '/');
    int n = slash == NULL ? snprintf(dir, sizeof dir, ".firmline-pack-XXXXXX")
                          : snprintf(dir, sizeof dir, "%.*s/.firmline-pack-XXXXXX",
                                     (int)(slash - o.output), o.output);
    if (n < 0 || n >= (int)sizeof dir) {
        fa_log("error", "pack: the path of --output is too long");
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    if (mkdtemp(dir) == NULL) {
        fa_log("error", "pack: cannot make a temporary folder next to %s (%s)", o.output,
               strerror(errno));
        return 1;
    }
    int rc = build(&o, dir);
    remove_folder(dir);
    if (rc != 0 && interrupted)
        fa_log("error", "pack: interrupted, no package written");
    return rc == 0 ? 0 : 1;
}
