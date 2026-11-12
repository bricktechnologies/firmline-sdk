/* SPDX-License-Identifier: Apache-2.0 */
/* firmline-agent pack --compose <file> --version <v> --output <file.tar>: the package of a Docker
 * Compose application, to upload as the firmware of a release. It runs where the images are
 * built (a developer's machine or a CI job), not on the device, with the docker CLI and its
 * Compose plugin, tar and gzip.
 *
 * The package is an uncompressed tar of exactly, in this order:
 *   firmline-package.json  the description (package.h): architecture, version, and per service
 *                          its image firmline.local/<service>:<tag> (the version made a
 *                          Docker tag, fa_package_tag) and the image ID, the digest of its
 *                          configuration as the manifest of `docker save` gives it: the ID
 *                          `docker load` gives it on the device, whatever image store this
 *                          machine's daemon uses;
 *   docker-compose.yml     the composition as Compose renders it with an override that gives each
 *                          service that image, `pull_policy: never` and no `build:`. It is not
 *                          normalized and paths are not resolved, so that the device's project
 *                          names the volumes and networks and no path of this machine goes in;
 *   images.tar.gz          `docker save` of the images under their new names, `gzip -n`.
 * Every service must name its image, present on this machine (pack never pulls), all of one
 * architecture; the new names stay tagged here. The files are made in a temporary folder next to
 * the output, removed on every exit, also on SIGINT, SIGTERM and SIGHUP; the output appears only
 * complete (a rename) and replaces a file of the same name. A value from the command line or the
 * composition never reaches docker, tar or gzip where it could read as an option. */
#define _GNU_SOURCE /* mkdtemp */
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
#define MANIFEST_MAX (256 * 1024)     /* manifest.json of docker save; larger is refused */
#define INSPECT_MAX 512               /* "<id> <architecture>\n" */
#define SHORT_MS (60 * 1000)          /* compose config, image inspect, tag, manifest */
#define LONG_MS (30 * 60 * 1000)      /* save, gzip, tar */

typedef struct {
    const char *compose, *version, *output;
} options;

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

/* "<option>=<value>" into out: a value that starts with '-' stays the option's value. */
static int with_value(char *out, size_t cap, const char *option, const char *value) {
    int n = snprintf(out, cap, "%s=%s", option, value);
    return n >= 0 && (size_t)n < cap ? 0 : -1;
}

/* ---- the steps --------------------------------------------------------------------------- */

/* The services of the composition and the image each names. */
static int read_services(const char *compose, fa_compose_service sv[FA_MAX_COMPONENTS],
                         int *count) {
    char file[PATH_MAX + 8], err[256];
    if (with_value(file, sizeof file, "--file", compose) != 0) {
        fa_log("error", "pack: the path of --compose is too long");
        return -1;
    }
    char *json = malloc(COMPOSE_JSON_MAX);
    if (json == NULL) {
        fa_log("error", "pack: out of memory");
        return -1;
    }
    const char *argv[] = {
        "compose", file, "config", "--format", "json", "--no-normalize", "--no-path-resolution",
        NULL};
    int rc = fa_docker_run(argv, json, COMPOSE_JSON_MAX, SHORT_MS);
    if (rc != 0) {
        if (!interrupted)
            fa_log("error", "pack: docker compose cannot read the composition %s", compose);
        free(json);
        return -1;
    }
    rc = fa_compose_services(json, strlen(json), sv, count, err);
    free(json);
    if (rc != 0)
        fa_log("error", "pack: %s", err);
    return rc;
}

/* Each source image: its ID here (to tag exactly the image inspected) and its architecture; and
 * the new names into the package. */
static int inspect_images(const fa_compose_service *sv, int count, fa_package *p,
                          char source_id[][INSPECT_MAX]) {
    char first[INSPECT_MAX] = "";
    for (int i = 0; i < count; i++) {
        char out[INSPECT_MAX], architecture[INSPECT_MAX], extra;
        const char *argv[] = {"image", "inspect",   "--format", "{{.Id}} {{.Architecture}}",
                              "--",    sv[i].image, NULL};
        int rc = fa_docker_run(argv, out, sizeof out, SHORT_MS);
        if (interrupted)
            return -1;
        if (rc != 0) {
            fa_log("error",
                   "pack: the image %s of the service %s is not on this machine (pack does not "
                   "pull: pull or build it first)",
                   sv[i].image, sv[i].service);
            return -1;
        }
        if (sscanf(out, "%511s %511s %c", source_id[i], architecture, &extra) != 2 ||
            strncmp(source_id[i], "sha256:", 7) != 0 ||
            strlen(architecture) >= sizeof p->architecture) {
            fa_log("error", "pack: cannot read the ID and architecture of the image %s",
                   sv[i].image);
            return -1;
        }
        if (i == 0) {
            memcpy(first, architecture, strlen(architecture) + 1);
        } else if (strcmp(architecture, first) != 0) {
            fa_log("error",
                   "pack: the images are of two architectures: %s (service %s) and %s (service "
                   "%s); a package is for one",
                   first, sv[0].service, architecture, sv[i].service);
            return -1;
        }
        char tag[FA_PACKAGE_TAG_MAX + 1], image[256];
        fa_package_tag(p->version, tag);
        int len = snprintf(image, sizeof image, FA_PACKAGE_REGISTRY "/%s:%s", sv[i].service, tag);
        if (len < 0 || (size_t)len >= sizeof p->image[i].image) {
            fa_log("error", "pack: the image name of the service %s is too long", sv[i].service);
            return -1;
        }
        memcpy(p->image[i].service, sv[i].service, strlen(sv[i].service) + 1);
        memcpy(p->image[i].image, image, (size_t)len + 1);
    }
    p->image_count = count;
    memcpy(p->architecture, first, strlen(first) + 1);
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
    if (len >= sizeof text || write_file(dir, "override.yml", text) != 0) {
        fa_log("error", "pack: cannot write the override of the composition in %s", dir);
        return -1;
    }
    return 0;
}

static int render_composition(const char *dir, const char *compose) {
    char file[PATH_MAX + 8], override[PATH_MAX + 8], rendered[PATH_MAX + 16];
    int ok =
        with_value(file, sizeof file, "--file", compose) == 0 &&
        snprintf(override, sizeof override, "--file=%s/override.yml", dir) < (int)sizeof override &&
        snprintf(rendered, sizeof rendered, "--output=%s/docker-compose.yml", dir) <
            (int)sizeof rendered;
    const char *argv[] = {
        "compose", file, override, "config", "--no-normalize", "--no-path-resolution",
        rendered,  NULL};
    if (!ok || fa_docker_run(argv, NULL, 0, SHORT_MS) != 0) {
        if (!interrupted)
            fa_log("error",
                   "pack: docker compose cannot render the composition with the new image names");
        return -1;
    }
    return 0;
}

/* Tags the images with their new names and saves them; the ids of the package come from the
 * manifest of the archive. */
static int tag_and_save(const char *dir, fa_package *p, char source_id[][INSPECT_MAX]) {
    for (int i = 0; i < p->image_count; i++) {
        const char *argv[] = {"tag", "--", source_id[i], p->image[i].image, NULL};
        if (fa_docker_run(argv, NULL, 0, SHORT_MS) != 0) {
            if (!interrupted)
                fa_log("error", "pack: cannot tag the image of the service %s as %s",
                       p->image[i].service, p->image[i].image);
            return -1;
        }
    }
    char archive[PATH_MAX], output[PATH_MAX + 16], file[PATH_MAX + 16];
    if (snprintf(archive, sizeof archive, "%s/images.tar", dir) >= (int)sizeof archive ||
        with_value(output, sizeof output, "--output", archive) != 0 ||
        with_value(file, sizeof file, "--file", archive) != 0)
        return -1;
    const char *save[FA_MAX_COMPONENTS + 4] = {"save", output, "--"};
    for (int i = 0; i < p->image_count; i++)
        save[3 + i] = p->image[i].image;
    save[3 + p->image_count] = NULL;
    if (fa_docker_run(save, NULL, 0, LONG_MS) != 0) {
        if (!interrupted)
            fa_log("error", "pack: docker save of the images failed");
        return -1;
    }

    char *manifest = malloc(MANIFEST_MAX), err[256];
    if (manifest == NULL) {
        fa_log("error", "pack: out of memory");
        return -1;
    }
    const char *extract[] = {"tar", "--extract", "--to-stdout", file, "--", "manifest.json", NULL};
    int rc = fa_command_run(extract, manifest, MANIFEST_MAX, SHORT_MS);
    if (rc != 0) {
        if (!interrupted)
            fa_log("error", "pack: cannot read manifest.json in the archive of docker save");
    } else if ((rc = fa_package_ids_from_manifest(manifest, strlen(manifest), p, err)) != 0) {
        fa_log("error", "pack: %s", err);
    }
    free(manifest);
    if (rc != 0)
        return -1;

    const char *gzip[] = {"gzip", "-n", "--", archive, NULL};
    if (fa_command_run(gzip, NULL, 0, LONG_MS) != 0) {
        if (!interrupted)
            fa_log("error", "pack: gzip of the images failed");
        return -1;
    }
    return 0;
}

static int write_tar(const char *dir) {
    char archive[PATH_MAX + 16], directory[PATH_MAX + 16];
    if (snprintf(archive, sizeof archive, "--file=%s/package.tar", dir) >= (int)sizeof archive ||
        with_value(directory, sizeof directory, "--directory", dir) != 0)
        return -1;
    const char *argv[] = {"tar",
                          "--create",
                          archive,
                          directory,
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
    static fa_compose_service sv[FA_MAX_COMPONENTS];
    static char source_id[FA_MAX_COMPONENTS][INSPECT_MAX];
    static fa_package p;
    char description[8192], renamed[PATH_MAX];
    int count = 0;
    memset(&p, 0, sizeof p);
    p.format = FA_PACKAGE_FORMAT;
    snprintf(p.version, sizeof p.version, "%s", o->version);

    if (read_services(o->compose, sv, &count) != 0 ||
        inspect_images(sv, count, &p, source_id) != 0 || write_override(dir, &p) != 0 ||
        render_composition(dir, o->compose) != 0 || tag_and_save(dir, &p, source_id) != 0)
        return -1;
    if (fa_package_write(&p, description, sizeof description) < 0 ||
        write_file(dir, "firmline-package.json", description) != 0) {
        fa_log("error", "pack: cannot write the description in %s", dir);
        return -1;
    }
    if (write_tar(dir) != 0 || interrupted)
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
        fa_log("error", "pack: the version is the firmware version of the release: 1 to 64 bytes "
                        "without a control character or a space at either end");
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
