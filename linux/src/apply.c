/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE /* NAME_MAX */
#include "apply.h"

#include "docker.h"
#include "log.h"
#include "package.h"
#include "store.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SHORT_MS (60 * 1000)     /* tar --list, the small members, config, inspect, ps, rm */
#define LONG_MS (30 * 60 * 1000) /* extraction and load of the images, up */
#define POLL_MS 2000             /* between two looks at the containers */
#define DESCRIPTION_MAX (64 * 1024)
#define COMPOSE_MAX (512 * 1024) /* a composition, as YAML or JSON; larger is refused */
#define LIST_MAX (16 * 1024)     /* names, IDs, inspect lines */
#define MAX_SERVICES 64          /* of the new composition: the package's and the agent's */
#define OPTION_MAX (PATH_MAX + 32)
#define AGENT_FILE "agent-service.json"
#define MANIFEST_MAX (256 * 1024) /* manifest.json of docker save; larger is refused */
#define MAX_KEPT 64               /* containers of the project before up */
/* One line per container: ID, service, state, restarts, health ("none" without a healthcheck). */
#define CONTAINER_FORMAT                                                                           \
    "{{.ID}} {{index .Config.Labels \"com.docker.compose.service\"}} {{.State.Status}} "           \
    "{{.RestartCount}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}"

static const char *const MEMBERS[] = {"firmline-package.json", "docker-compose.yml",
                                      "images.tar.gz"};
#define MEMBER_COUNT 3

typedef struct {
    const fa_config *cfg;
    const fa_component *comp;
    char bin[OPTION_MAX];        /* --file=<the package> */
    char work[PATH_MAX];         /* <data_dir>/apply.tmp */
    char dir[PATH_MAX];          /* the folder of compose_file */
    char name[NAME_MAX + 1];     /* the file name of compose_file */
    char new_name[NAME_MAX + 5]; /* <name>.new */
    char new_path[PATH_MAX];
    char project[96];             /* --project-name=<project> */
    char project_dir[OPTION_MAX]; /* --project-directory=<dir> */
    fa_package pkg, previous;
    bool have_previous, package_has_agent, copy_agent, new_written;
    /* The IDs the package's image names had before docker load ("" = no such name): a name the
     * new package takes from the composition in use (one tag, two versions) is given back on a
     * failure. */
    char before[FA_MAX_COMPONENTS][128];
    bool loaded;
    char *saved; /* compose_file as it was */
    size_t saved_len;
    bool replacing; /* finish() has started to put the new composition in place */
    /* The project's containers before up and their restart counts: a container that up keeps
     * (the agent's, say) fails the check only if it restarts again. */
    struct {
        char id[72];
        int restarts;
    } kept[MAX_KEPT];
    int kept_count;
} job;

static int fail(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static int fail(const char *fmt, ...) {
    char message[768];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(message, sizeof message, fmt, ap);
    va_end(ap);
    fa_log("error", "apply: %s", message);
    return -1;
}

/* "<option>=<value>": a value that starts with '-' stays the option's value. */
static int with_value(char *out, size_t cap, const char *option, const char *value) {
    int n = snprintf(out, cap, "%s=%s", option, value);
    return n >= 0 && (size_t)n < cap ? 0 : -1;
}

static int join(char *out, size_t cap, const char *dir, const char *name) {
    int n = snprintf(out, cap, "%s/%s", dir, name);
    return n >= 0 && (size_t)n < cap ? 0 : -1;
}

/* The next non-empty line of a text cut into lines in place, or NULL at its end. */
static char *next_line(char **cursor) {
    char *s = *cursor;
    while (*s == '\n')
        s++;
    if (*s == '\0')
        return NULL;
    char *end = strchr(s, '\n');
    if (end != NULL) {
        *end = '\0';
        *cursor = end + 1;
    } else {
        *cursor = s + strlen(s);
    }
    return s;
}

static void trim_end(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' '))
        s[--n] = '\0';
}

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void sleep_ms(long long ms) {
    struct timespec nap = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000L};
    while (nanosleep(&nap, &nap) != 0 && errno == EINTR) {
    }
}

/* The image ID that a name or ID has on the daemon, into id: 0, or -1 when there is none. */
static int image_id(const char *reference, char id[128]) {
    const char *argv[] = {"image", "inspect", "--format", "{{.Id}}", "--", reference, NULL};
    if (fa_docker_run(argv, id, 128, SHORT_MS) != 0)
        return -1;
    trim_end(id);
    return 0;
}

/* ---- the working folder ----------------------------------------------------------------- */

/* Removes the working folder and the files in it (flat: apply makes only files there). */
static void remove_work(const char *work) {
    DIR *d = opendir(work);
    if (d == NULL)
        return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        char path[PATH_MAX];
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0 &&
            join(path, sizeof path, work, e->d_name) == 0)
            unlink(path);
    }
    closedir(d);
    if (rmdir(work) != 0)
        fa_log("warning", "apply: cannot remove the folder %s (%s)", work, strerror(errno));
}

static int setup(job *j, const fa_config *cfg, const fa_component *comp, const char *release) {
    char bin[PATH_MAX], low[40];
    size_t n = 0;
    for (; release[n] != '\0' && n < sizeof low - 1; n++)
        low[n] =
            (release[n] >= 'A' && release[n] <= 'Z') ? (char)(release[n] - 'A' + 'a') : release[n];
    low[n] = '\0';
    j->cfg = cfg;
    j->comp = comp;
    const char *file = comp->compose_file, *slash = strrchr(file, '/');
    if (slash == NULL || slash[1] == '\0')
        return fail("compose_file %s is not the path of a file", file);
    size_t dir_len = slash == file ? 1 : (size_t)(slash - file);
    int ok =
        snprintf(bin, sizeof bin, "%s/download-%s.bin", cfg->data_dir, low) < (int)sizeof bin &&
        with_value(j->bin, sizeof j->bin, "--file", bin) == 0 &&
        join(j->work, sizeof j->work, cfg->data_dir, FA_APPLY_WORK) == 0 &&
        dir_len < sizeof j->dir && strlen(slash + 1) + 4 < sizeof j->new_name &&
        with_value(j->project, sizeof j->project, "--project-name", comp->project) == 0;
    if (!ok)
        return fail("a path is too long");
    memcpy(j->dir, file, dir_len);
    j->dir[dir_len] = '\0';
    snprintf(j->name, sizeof j->name, "%s", slash + 1);
    snprintf(j->new_name, sizeof j->new_name, "%s.new", j->name);
    if (join(j->new_path, sizeof j->new_path, j->dir, j->new_name) != 0 ||
        with_value(j->project_dir, sizeof j->project_dir, "--project-directory", j->dir) != 0)
        return fail("a path is too long");

    char *text = NULL;
    size_t len = 0;
    char err[256];
    if (fa_store_read(cfg->data_dir, FA_APPLY_PACKAGE, &text, &len) == 0) {
        j->have_previous = fa_package_parse(text, len, &j->previous, err) == 0;
        if (!j->have_previous)
            fa_log("warning", "apply: %s/%s cannot be read (%s): no images will be removed",
                   cfg->data_dir, FA_APPLY_PACKAGE, err);
        free(text);
    }

    remove_work(j->work); /* what an apply cut short left */
    if (mkdir(j->work, 0700) != 0)
        return fail("cannot make the folder %s (%s)", j->work, strerror(errno));
    return 0;
}

/* ---- step 1: the package ---------------------------------------------------------------- */

static int check_members(job *j) {
    char list[4096];
    bool seen[MEMBER_COUNT] = {false};
    int count = 0;
    const char *argv[] = {"tar", "--list", j->bin, NULL};
    if (fa_command_run(argv, list, sizeof list, SHORT_MS) != 0)
        return fail("the package cannot be read as a tar");
    char *cursor = list, *line;
    while ((line = next_line(&cursor)) != NULL) {
        int k = 0;
        while (k < MEMBER_COUNT && strcmp(line, MEMBERS[k]) != 0)
            k++;
        if (k == MEMBER_COUNT || seen[k])
            return fail("the package is not one of pack: it holds %.80s", line);
        seen[k] = true;
        count++;
    }
    if (count != MEMBER_COUNT)
        return fail("the package is not one of pack: it lacks one of firmline-package.json, "
                    "docker-compose.yml and images.tar.gz");
    return 0;
}

/* A small member of the package, NUL-terminated, into out. */
static int read_member(job *j, const char *member, char *out, size_t cap) {
    const char *argv[] = {"tar", "--extract", "--to-stdout", j->bin, "--", member, NULL};
    if (fa_command_run(argv, out, cap, SHORT_MS) != 0)
        return fail("cannot read %s in the package", member);
    return 0;
}

static int read_description(job *j, const char *version) {
    char err[256], arch[64];
    char *text = malloc(DESCRIPTION_MAX);
    if (text == NULL)
        return fail("out of memory");
    int rc = read_member(j, MEMBERS[0], text, DESCRIPTION_MAX);
    if (rc == 0 && fa_package_parse(text, strlen(text), &j->pkg, err) != 0)
        rc = fail("firmline-package.json of the package: %s", err);
    free(text);
    if (rc != 0)
        return -1;
    if (strcmp(j->pkg.version, version) != 0)
        return fail("the package is version %s, the release is version %s", j->pkg.version,
                    version);
    const char *argv[] = {"version", "--format", "{{.Server.Arch}}", NULL};
    if (fa_docker_run(argv, arch, sizeof arch, SHORT_MS) != 0)
        return fail("cannot read the architecture of the Docker daemon");
    trim_end(arch);
    if (strcmp(arch, j->pkg.architecture) != 0)
        return fail("the package is for the architecture %s, this device is %s",
                    j->pkg.architecture, arch);
    return 0;
}

/* The composition of the package into the working folder, and its services checked against the
 * description. */
static int check_composition(job *j) {
    char path[PATH_MAX], file[OPTION_MAX], err[256];
    fa_compose_service sv[FA_MAX_COMPONENTS];
    int count = 0, rc = -1;
    char *text = malloc(COMPOSE_MAX);
    if (text == NULL)
        return fail("out of memory");
    if (read_member(j, MEMBERS[1], text, COMPOSE_MAX) != 0)
        goto done;
    if (fa_store_write(j->work, MEMBERS[1], text, strlen(text), 0600) != 0) {
        fail("cannot write %s/%s (%s)", j->work, MEMBERS[1], strerror(errno));
        goto done;
    }
    if (join(path, sizeof path, j->work, MEMBERS[1]) != 0 ||
        with_value(file, sizeof file, "--file", path) != 0) {
        fail("a path is too long");
        goto done;
    }
    const char *argv[] = {"compose",  j->project, j->project_dir,     file, "config",
                          "--format", "json",     "--no-interpolate", NULL};
    if (fa_docker_run(argv, text, COMPOSE_MAX, SHORT_MS) != 0) {
        fail("docker compose cannot read the composition of the package");
        goto done;
    }
    if (fa_compose_services(text, strlen(text), sv, &count, err) != 0) {
        fail("the composition of the package: %s", err);
        goto done;
    }
    if (count != j->pkg.image_count) {
        fail("the composition of the package has %d services, its description %d images", count,
             j->pkg.image_count);
        goto done;
    }
    for (int k = 0; k < count; k++) {
        int i = 0;
        while (i < j->pkg.image_count && strcmp(j->pkg.image[i].service, sv[k].service) != 0)
            i++;
        if (i == j->pkg.image_count || strcmp(j->pkg.image[i].image, sv[k].image) != 0) {
            fail("the service %s of the composition does not run an image of the description",
                 sv[k].service);
            goto done;
        }
        if (strcmp(sv[k].service, j->comp->agent_service) == 0)
            j->package_has_agent = true;
    }
    rc = 0;
done:
    free(text);
    return rc;
}

/* ---- step 2: the agent service and the images ------------------------------------------- */

/* The services of a composition (file: --file=<path>), one per line into out. Compose lists them
 * all even when services are named after --services, so none is. */
static int services_of(job *j, const char *file, char *out, size_t cap) {
    const char *argv[] = {"compose", j->project, file, "config", "--services", NULL};
    return fa_docker_run(argv, out, cap, SHORT_MS) == 0 ? 0 : -1;
}

static bool has_line(char *text, const char *wanted, int *lines) {
    bool found = false;
    char *cursor = text, *line;
    *lines = 0;
    while ((line = next_line(&cursor)) != NULL) {
        (*lines)++;
        found |= strcmp(line, wanted) == 0;
    }
    return found;
}

/* When the package has no agent service and the composition in use has one: that service, as
 * Compose renders it with the volumes and networks it uses, into the working folder. Compose adds
 * the services it depends on to the rendering: they would replace the package's, so they are
 * refused. */
static int keep_agent_service(job *j) {
    const char *agent = j->comp->agent_service;
    char file[OPTION_MAX], path[PATH_MAX], rendered[OPTION_MAX], services[LIST_MAX];
    int lines = 0, rc = -1;
    if (j->package_has_agent)
        return 0;
    if (with_value(file, sizeof file, "--file", j->comp->compose_file) != 0 ||
        join(path, sizeof path, j->work, AGENT_FILE) != 0 ||
        with_value(rendered, sizeof rendered, "--file", path) != 0)
        return fail("a path is too long");
    if (services_of(j, file, services, sizeof services) != 0)
        return fail("docker compose cannot read the composition in use %s", j->comp->compose_file);
    if (!has_line(services, agent, &lines)) {
        fa_log("info", "apply: the composition in use has no service %s: no agent service to keep",
               agent);
        return 0;
    }
    char *json = malloc(COMPOSE_MAX);
    if (json == NULL)
        return fail("out of memory");
    const char *argv[] = {"compose", j->project, file,  "config", "--format",
                          "json",    "--",       agent, NULL};
    if (fa_docker_run(argv, json, COMPOSE_MAX, SHORT_MS) != 0)
        fail("docker compose cannot render the service %s of the composition in use", agent);
    else if (fa_store_write(j->work, AGENT_FILE, json, strlen(json), 0600) != 0)
        fail("cannot write %s/%s (%s)", j->work, AGENT_FILE, strerror(errno));
    else if (services_of(j, rendered, services, sizeof services) != 0)
        fail("docker compose cannot read the service %s rendered", agent);
    else if (!has_line(services, agent, &lines) || lines != 1)
        fail("the service %s of the composition in use depends on other services: put the agent "
             "service in the package",
             agent);
    else
        rc = 0;
    free(json);
    if (rc == 0) {
        j->copy_agent = true;
        fa_log("info", "apply: the service %s of the composition in use is kept", agent);
    }
    return rc;
}

/* images.tar.gz into the working folder, and its manifest.json against the description: every
 * image of the package is there, with its name and ID, before anything is loaded. */
static int check_archive(job *j) {
    char directory[OPTION_MAX], path[PATH_MAX], file[OPTION_MAX], err[256];
    struct stat st;
    if (with_value(directory, sizeof directory, "--directory", j->work) != 0 ||
        join(path, sizeof path, j->work, MEMBERS[2]) != 0 ||
        with_value(file, sizeof file, "--file", path) != 0)
        return fail("a path is too long");
    const char *extract[] = {"tar", "--extract", j->bin, directory, "--", MEMBERS[2], NULL};
    if (fa_command_run(extract, NULL, 0, LONG_MS) != 0)
        return fail("cannot extract images.tar.gz from the package (is there room on the disk?)");
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return fail("images.tar.gz of the package is not a file");
    char *manifest = malloc(MANIFEST_MAX);
    if (manifest == NULL)
        return fail("out of memory");
    const char *list[] = {"tar", "--extract", "--to-stdout",   "--gzip",
                          file,  "--",        "manifest.json", NULL};
    fa_package found = j->pkg;
    int rc = fa_command_run(list, manifest, MANIFEST_MAX, LONG_MS);
    if (rc != 0)
        fail("cannot read manifest.json in images.tar.gz of the package (a damaged archive?)");
    else if ((rc = fa_package_ids_from_manifest(manifest, strlen(manifest), &found, err)) != 0)
        fail("images.tar.gz of the package: %s", err);
    free(manifest);
    if (rc != 0)
        return -1;
    for (int i = 0; i < j->pkg.image_count; i++)
        if (strcmp(found.image[i].id, j->pkg.image[i].id) != 0)
            return fail("images.tar.gz of the package holds %s with the ID %s, not %s as in the "
                        "description",
                        j->pkg.image[i].image, found.image[i].id, j->pkg.image[i].id);
    return 0;
}

static int load_images(job *j) {
    char path[PATH_MAX], input[OPTION_MAX];
    if (join(path, sizeof path, j->work, MEMBERS[2]) != 0 ||
        with_value(input, sizeof input, "--input", path) != 0)
        return fail("a path is too long");
    for (int i = 0; i < j->pkg.image_count; i++)
        if (image_id(j->pkg.image[i].image, j->before[i]) != 0)
            j->before[i][0] = '\0';
    fa_log("info", "apply: loading the images of version %s", j->pkg.version);
    const char *load[] = {"load", "--quiet", input, NULL};
    j->loaded = true;
    int rc = fa_docker_run(load, NULL, 0, LONG_MS);
    unlink(path); /* the room it takes, before the containers start */
    if (rc != 0)
        return fail("docker load of the images of the package failed");
    for (int i = 0; i < j->pkg.image_count; i++) {
        char id[128];
        if (image_id(j->pkg.image[i].image, id) != 0)
            return fail("the image %s is not in the package", j->pkg.image[i].image);
        if (strcmp(id, j->pkg.image[i].id) != 0)
            return fail("the image %s is %.80s after docker load, not %s as in the description",
                        j->pkg.image[i].image, id, j->pkg.image[i].id);
    }
    return 0;
}

/* After a failure: the names of the package back on the images they named before the load. */
static void give_back_names(job *j) {
    for (int i = 0; j->loaded && i < j->pkg.image_count; i++) {
        if (j->before[i][0] == '\0' || strcmp(j->before[i], j->pkg.image[i].id) == 0)
            continue;
        const char *argv[] = {"tag", "--", j->before[i], j->pkg.image[i].image, NULL};
        if (fa_docker_run(argv, NULL, 0, SHORT_MS) != 0)
            fa_log("warning", "apply: cannot give the name %s back to the image it had",
                   j->pkg.image[i].image);
    }
}

/* ---- step 3: the new composition and the previous one ----------------------------------- */

static int write_new_composition(job *j) {
    char path[PATH_MAX], file[OPTION_MAX], agent_path[PATH_MAX], agent[OPTION_MAX];
    if (join(path, sizeof path, j->work, MEMBERS[1]) != 0 ||
        with_value(file, sizeof file, "--file", path) != 0 ||
        join(agent_path, sizeof agent_path, j->work, AGENT_FILE) != 0 ||
        with_value(agent, sizeof agent, "--file", agent_path) != 0)
        return fail("a path is too long");
    /* Already interpolated (by pack, and by config for the agent service); paths left as they
     * are written, so that they mean the same from compose_file's folder. */
    const char *argv[10] = {"compose", j->project, j->project_dir, file};
    int n = 4;
    if (j->copy_agent)
        argv[n++] = agent;
    argv[n++] = "config";
    argv[n++] = "--no-interpolate";
    argv[n++] = "--no-path-resolution";
    argv[n] = NULL;
    char *text = malloc(COMPOSE_MAX);
    if (text == NULL)
        return fail("out of memory");
    int rc = -1;
    if (fa_docker_run(argv, text, COMPOSE_MAX, SHORT_MS) != 0)
        fail("docker compose cannot render the new composition");
    else if (fa_store_write(j->dir, j->new_name, text, strlen(text), 0644) != 0)
        fail("cannot write %s (%s)", j->new_path, strerror(errno));
    else
        rc = 0;
    free(text);
    j->new_written = rc == 0;
    return rc;
}

static int save_previous(job *j) {
    if (fa_store_read(j->dir, j->name, &j->saved, &j->saved_len) != 0)
        return fail("cannot read the composition in use %s", j->comp->compose_file);
    if (fa_store_write(j->cfg->data_dir, FA_APPLY_PREVIOUS, j->saved, j->saved_len, 0600) != 0)
        return fail("cannot write %s/%s (%s)", j->cfg->data_dir, FA_APPLY_PREVIOUS,
                    strerror(errno));
    return 0;
}

/* ---- steps 4, 5 and 7: up, the health check, the way back -------------------------------- */

/* As Torizon starts its composition; never a pull. */
static int compose_up(job *j, const char *path) {
    char file[OPTION_MAX];
    if (with_value(file, sizeof file, "--file", path) != 0)
        return -1;
    const char *argv[] = {"compose",  j->project,         file,           "up",
                          "--detach", "--remove-orphans", "--pull=never", NULL};
    return fa_docker_run(argv, NULL, 0, LONG_MS) == 0 ? 0 : -1;
}

static void start_previous(job *j) {
    fa_log("info", "apply: starting the previous composition %s again", j->comp->compose_file);
    if (compose_up(j, j->comp->compose_file) != 0)
        fa_log("error", "apply: the previous composition %s did not start again",
               j->comp->compose_file);
}

/* The restart counts of the project's containers before up (none at all is no error). */
static int note_restarts(job *j) {
    char filter[160], ids[LIST_MAX], out[LIST_MAX];
    int len = snprintf(filter, sizeof filter, "--filter=label=com.docker.compose.project=%s",
                       j->comp->project);
    if (len < 0 || (size_t)len >= sizeof filter)
        return fail("a name is too long");
    const char *ls[] = {"container", "ls", "--all", "--quiet", "--no-trunc", filter, NULL};
    if (fa_docker_run(ls, ids, sizeof ids, SHORT_MS) != 0)
        return fail("cannot list the containers of the project %s", j->comp->project);
    const char *inspect[FA_COMMAND_MAX_ARGS] = {"container", "inspect", "--format",
                                                "{{.ID}} {{.RestartCount}}", "--"};
    int n = 5;
    char *cursor = ids, *line;
    while ((line = next_line(&cursor)) != NULL) {
        if (n >= FA_COMMAND_MAX_ARGS - 2 || n - 5 >= MAX_KEPT)
            return fail("the project %s has more than %d containers", j->comp->project, n - 5);
        inspect[n++] = line;
    }
    inspect[n] = NULL;
    if (n == 5)
        return 0;
    if (fa_docker_run(inspect, out, sizeof out, SHORT_MS) != 0)
        return fail("cannot read the containers of the project %s", j->comp->project);
    cursor = out;
    while ((line = next_line(&cursor)) != NULL && j->kept_count < MAX_KEPT) {
        if (sscanf(line, "%71s %d", j->kept[j->kept_count].id, &j->kept[j->kept_count].restarts) !=
            2)
            return fail("cannot read the restart count of a container: %.80s", line);
        j->kept_count++;
    }
    return 0;
}

/* The restart count of a container before up: 0 for a container up made. */
static int restarts_before(const job *j, const char *id) {
    for (int i = 0; i < j->kept_count; i++)
        if (strcmp(j->kept[i].id, id) == 0)
            return j->kept[i].restarts;
    return 0;
}

typedef enum { HEALTH_OK, HEALTH_WAIT, HEALTH_FAILED } health;

typedef struct {
    char name[MAX_SERVICES][66];
    int count;
} service_list;

/* One look at the containers of the new composition. HEALTH_WAIT: all running, one still
 * `starting` (its service in waiting). */
static health look(job *j, const char *file, const service_list *sv, char waiting[66]) {
    char ids[LIST_MAX], out[LIST_MAX];
    bool seen[MAX_SERVICES] = {false};
    const char *ps[] = {"compose", j->project, file, "ps", "--all", "--quiet", NULL};
    if (fa_docker_run(ps, ids, sizeof ids, SHORT_MS) != 0) {
        fail("docker compose ps of the new composition failed");
        return HEALTH_FAILED;
    }
    const char *inspect[FA_COMMAND_MAX_ARGS] = {"container", "inspect", "--format",
                                                CONTAINER_FORMAT, "--"};
    int n = 5;
    char *cursor = ids, *line;
    while ((line = next_line(&cursor)) != NULL) {
        if (n >= FA_COMMAND_MAX_ARGS - 2) {
            fail("the new composition has more than %d containers", FA_COMMAND_MAX_ARGS - 7);
            return HEALTH_FAILED;
        }
        inspect[n++] = line;
    }
    inspect[n] = NULL;
    if (n == 5) {
        fail("the new composition has no containers");
        return HEALTH_FAILED;
    }
    if (fa_docker_run(inspect, out, sizeof out, SHORT_MS) != 0) {
        fail("the containers of the new composition cannot be read");
        return HEALTH_FAILED;
    }
    health result = HEALTH_OK;
    cursor = out;
    while ((line = next_line(&cursor)) != NULL) {
        char id[72], service[66], state[32], status[32];
        int restarts = 0;
        if (sscanf(line, "%71s %65s %31s %d %31s", id, service, state, &restarts, status) != 5) {
            fail("cannot read the state of a container: %.80s", line);
            return HEALTH_FAILED;
        }
        int k = 0;
        while (k < sv->count && strcmp(sv->name[k], service) != 0)
            k++;
        if (k == sv->count)
            continue; /* not a service of the new composition */
        seen[k] = true;
        if (strcmp(state, "running") != 0) {
            fail("the container of the service %s is %s", service, state);
            return HEALTH_FAILED;
        }
        int before = restarts_before(j, id);
        if (restarts > before) {
            fail("the container of the service %s restarted %d times", service, restarts - before);
            return HEALTH_FAILED;
        }
        if (strcmp(status, "unhealthy") == 0) {
            fail("the container of the service %s is unhealthy", service);
            return HEALTH_FAILED;
        }
        if (strcmp(status, "none") != 0 && strcmp(status, "healthy") != 0) {
            memcpy(waiting, service, sizeof service);
            result = HEALTH_WAIT;
        }
    }
    for (int k = 0; k < sv->count; k++)
        if (!seen[k]) {
            fail("the service %s has no container", sv->name[k]);
            return HEALTH_FAILED;
        }
    return result;
}

static fa_apply_outcome health_check(job *j) {
    char file[OPTION_MAX], text[LIST_MAX], waiting[66] = "";
    static service_list sv;
    memset(&sv, 0, sizeof sv);
    if (with_value(file, sizeof file, "--file", j->new_path) != 0 ||
        services_of(j, file, text, sizeof text) != 0) {
        fail("docker compose cannot read the new composition");
        return FA_APPLY_HEALTH_CHECK_FAILED;
    }
    char *cursor = text, *line;
    while ((line = next_line(&cursor)) != NULL) {
        if (sv.count == MAX_SERVICES || strlen(line) >= sizeof sv.name[0]) {
            fail("the new composition has more than %d services", MAX_SERVICES);
            return FA_APPLY_HEALTH_CHECK_FAILED;
        }
        memcpy(sv.name[sv.count++], line, strlen(line) + 1);
    }
    fa_log("info", "apply: checking the new composition (services: %d) for %d s", sv.count,
           j->comp->health_timeout_s);
    long long deadline = now_ms() + (long long)j->comp->health_timeout_s * 1000;
    for (;;) {
        health h = look(j, file, &sv, waiting);
        if (h == HEALTH_FAILED)
            return FA_APPLY_HEALTH_CHECK_FAILED;
        long long left = deadline - now_ms();
        if (left <= 0) {
            if (h == HEALTH_OK)
                return FA_APPLY_INSTALLED;
            fail("the container of the service %s is not healthy after %d s", waiting,
                 j->comp->health_timeout_s);
            return FA_APPLY_HEALTH_CHECK_FAILED;
        }
        sleep_ms(left < POLL_MS ? left : POLL_MS);
    }
}

/* ---- step 6: success --------------------------------------------------------------------- */

/* The new composition in place of compose_file and the description in package.json. A failure
 * here may come after compose_file was replaced (the rename done, the folder's fsync failed):
 * the caller writes the previous composition back. */
static fa_apply_outcome finish(job *j) {
    char description[8192];
    j->replacing = true;
    if (fa_store_rename(j->dir, j->new_name, j->name) != 0) {
        fail("cannot put %s in place of %s (%s)", j->new_path, j->comp->compose_file,
             strerror(errno));
        return FA_APPLY_INSTALL_FAILED;
    }
    j->new_written = false;
    int n = fa_package_write(&j->pkg, description, sizeof description);
    if (n < 0 ||
        fa_store_write(j->cfg->data_dir, FA_APPLY_PACKAGE, description, (size_t)n, 0644) != 0) {
        fail("cannot write %s/%s: the previous composition goes back", j->cfg->data_dir,
             FA_APPLY_PACKAGE);
        return FA_APPLY_INSTALL_FAILED;
    }
    fa_log("info", "apply: version %s installed", j->pkg.version);
    return FA_APPLY_INSTALLED;
}

/* The images that compose_file, now the composition installed, names, each with its image ID,
 * into packages; have_in_use stays false when Compose cannot list them (then no image of the
 * previous package is removed). */
static void note_images_in_use(job *j, fa_apply_packages *packages) {
    char file[OPTION_MAX], text[LIST_MAX];
    const char *argv[] = {"compose", j->project, file, "config", "--images", NULL};
    if (with_value(file, sizeof file, "--file", j->comp->compose_file) != 0 ||
        fa_docker_run(argv, text, sizeof text, SHORT_MS) != 0) {
        fa_log("warning", "apply: docker compose cannot list the images of %s: no image is removed",
               j->comp->compose_file);
        return;
    }
    char *cursor = text, *line;
    while ((line = next_line(&cursor)) != NULL) {
        if (packages->in_use_count == FA_APPLY_IN_USE_MAX ||
            strlen(line) >= sizeof packages->in_use[0].image) {
            fa_log("warning",
                   "apply: %s names more than %d images or a name too long: no image "
                   "is removed",
                   j->comp->compose_file, FA_APPLY_IN_USE_MAX);
            packages->in_use_count = 0;
            return;
        }
        int k = packages->in_use_count++;
        memcpy(packages->in_use[k].image, line, strlen(line) + 1);
        if (image_id(line, packages->in_use[k].id) != 0)
            packages->in_use[k].id[0] = '\0';
    }
    packages->have_in_use = true;
}

fa_apply_outcome fa_apply_install(const fa_config *cfg, const fa_component *comp,
                                  const char *release, const char *version,
                                  fa_apply_packages *packages) {
    job *j = calloc(1, sizeof *j);
    fa_apply_outcome outcome = FA_APPLY_INSTALL_FAILED;
    memset(packages, 0, sizeof *packages);
    if (j == NULL) {
        fail("out of memory");
        return outcome;
    }
    bool started = false;
    if (setup(j, cfg, comp, release) == 0 && check_members(j) == 0 &&
        read_description(j, version) == 0 && check_composition(j) == 0 && check_archive(j) == 0 &&
        keep_agent_service(j) == 0 && load_images(j) == 0 && write_new_composition(j) == 0 &&
        save_previous(j) == 0 && note_restarts(j) == 0) {
        fa_log("info", "apply: starting the composition of version %s", j->pkg.version);
        started = true;
        if (compose_up(j, j->new_path) != 0)
            fail("docker compose up of the new composition failed");
        else if ((outcome = health_check(j)) == FA_APPLY_INSTALLED)
            outcome = finish(j);
    }
    if (outcome == FA_APPLY_INSTALLED) {
        packages->previous = j->previous;
        packages->installed = j->pkg;
        packages->have_previous = j->have_previous;
        if (j->have_previous)
            note_images_in_use(j, packages);
    } else {
        give_back_names(j);
        if (j->replacing && fa_store_write(j->dir, j->name, j->saved, j->saved_len, 0644) != 0)
            fa_log("error", "apply: cannot write the previous composition back to %s",
                   j->comp->compose_file);
        if (started)
            start_previous(j);
    }
    if (j->work[0] != '\0')
        remove_work(j->work);
    if (j->new_written && unlink(j->new_path) != 0)
        fa_log("warning", "apply: cannot remove %s (%s)", j->new_path, strerror(errno));
    if (fa_store_remove(cfg->data_dir, FA_APPLY_PREVIOUS) != 0)
        fa_log("warning", "apply: cannot remove %s/%s", cfg->data_dir, FA_APPLY_PREVIOUS);
    free(j->saved);
    free(j);
    return outcome;
}

/* ---- after the outcome: the images of the previous package ------------------------------- */

static bool uses_name(const fa_package *p, const char *image) {
    for (int i = 0; i < p->image_count; i++)
        if (strcmp(p->image[i].image, image) == 0)
            return true;
    return false;
}

static bool uses_id(const fa_package *p, const char *id) {
    for (int i = 0; i < p->image_count; i++)
        if (strcmp(p->image[i].id, id) == 0)
            return true;
    return false;
}

/* Whether a service of the composition installed uses the name, or the image ID. */
static bool in_use(const fa_apply_packages *p, const char *image, const char *id) {
    for (int i = 0; i < p->in_use_count; i++)
        if ((image != NULL && strcmp(p->in_use[i].image, image) == 0) ||
            (id != NULL && strcmp(p->in_use[i].id, id) == 0))
            return true;
    return false;
}

static void remove_image(const char *reference) {
    const char *argv[] = {"image", "rm", "--", reference, NULL};
    if (fa_docker_run(argv, NULL, 0, SHORT_MS) != 0)
        fa_log("warning", "apply: cannot remove the image %s", reference);
}

void fa_apply_remove_previous_images(const fa_apply_packages *packages) {
    const fa_package *previous = &packages->previous, *now = &packages->installed;
    if (!packages->have_previous || !packages->have_in_use)
        return;
    for (int i = 0; i < previous->image_count; i++) {
        const char *image = previous->image[i].image, *old = previous->image[i].id;
        char id[128];
        if (!uses_name(now, image) && !in_use(packages, image, NULL) && image_id(image, id) == 0 &&
            strcmp(id, old) == 0)
            remove_image(image);
        if (uses_id(now, old) || in_use(packages, NULL, old))
            continue;
        const char *argv[] = {"image", "inspect", "--format", "{{len .RepoTags}}", "--", old, NULL};
        char tags[32];
        if (fa_docker_run(argv, tags, sizeof tags, SHORT_MS) != 0)
            continue; /* gone with its last name */
        trim_end(tags);
        if (strcmp(tags, "0") == 0)
            remove_image(old);
    }
}

void fa_apply_remove_work(const char *data_dir) {
    char work[PATH_MAX];
    if (join(work, sizeof work, data_dir, FA_APPLY_WORK) == 0)
        remove_work(work);
}
