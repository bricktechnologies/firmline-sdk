/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE /* pipe2 */
#include "components.h"

#include "firmline/fl_json.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define COMMAND_TIMEOUT_MS 10000
#define SOURCE_LIMIT 4096        /* bytes read from a version file or command */
#define PACKAGE_JSON_LIMIT 65536 /* bytes read from <data_dir>/package.json */

int fa_first_line_value(const char *text, size_t len, char out[65]) {
    size_t end = 0;
    while (end < len && text[end] != '\n')
        end++;
    size_t start = 0;
    while (start < end && isspace((unsigned char)text[start]))
        start++;
    while (end > start && isspace((unsigned char)text[end - 1]))
        end--;
    if (end == start || end - start > 64)
        return -1;
    memcpy(out, text + start, end - start);
    out[end - start] = '\0';
    return 0;
}

static int version_from_file(const char *path, char out[65]) {
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return -1;
    char buf[SOURCE_LIMIT];
    size_t n = fread(buf, 1, sizeof buf, f);
    int failed = ferror(f);
    fclose(f);
    return failed ? -1 : fa_first_line_value(buf, n, out);
}

/* The version of the last installed package: "version" of <data_dir>/package.json, the same
 * content as the firmline-package.json of the package. A file over the limit, not JSON, without a
 * version or with one that is not 1 to 64 printable characters is unreadable. */
static int version_from_package(const fa_config *c, char out[65]) {
    char path[300];
    if (snprintf(path, sizeof path, "%s/package.json", c->data_dir) >= (int)sizeof path)
        return -1;
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return -1;
    char *buf = malloc(PACKAGE_JSON_LIMIT + 1);
    if (buf == NULL) {
        fclose(f);
        return -1;
    }
    size_t n = fread(buf, 1, PACKAGE_JSON_LIMIT + 1, f);
    int failed = ferror(f);
    fclose(f);
    int rc = -1;
    fl_json j;
    if (!failed && n <= PACKAGE_JSON_LIMIT && fl_json_parse(&j, buf, n) == FL_OK &&
        fl_json_string(&j, "version", out, 65) == FL_OK && out[0] != '\0') {
        rc = 0;
        for (const char *s = out; *s != '\0'; s++)
            if ((unsigned char)*s < 0x20 || *s == 0x7f)
                rc = -1;
    }
    free(buf);
    return rc;
}

/* KEY=value, KEY="value" or KEY='value' in an os-release file. */
static int version_from_os_release(const char *path, const char *key, char out[65]) {
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return -1;
    size_t key_len = strlen(key);
    char line[1024];
    int rc = -1;
    while (fgets(line, sizeof line, f) != NULL) {
        if (strncmp(line, key, key_len) != 0 || line[key_len] != '=')
            continue;
        char *value = line + key_len + 1;
        size_t n = strcspn(value, "\r\n");
        value[n] = '\0';
        if (n >= 2 && (value[0] == '"' || value[0] == '\'') && value[n - 1] == value[0]) {
            value[n - 1] = '\0';
            value++;
        }
        rc = fa_first_line_value(value, strlen(value), out);
        break;
    }
    fclose(f);
    return rc;
}

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Starts `path` in its own process group with stdin on /dev/null, stdout on `out_fd`, stderr on
 * /dev/null, an empty signal mask and default dispositions for the signals the agent handles.
 * 0, or -1 when any step fails. */
static int spawn_command(const char *path, int out_fd, pid_t *pid) {
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;
    if (posix_spawn_file_actions_init(&actions) != 0)
        return -1;
    if (posix_spawnattr_init(&attr) != 0) {
        posix_spawn_file_actions_destroy(&actions);
        return -1;
    }
    sigset_t none, defaults;
    sigemptyset(&none);
    sigemptyset(&defaults);
    sigaddset(&defaults, SIGPIPE);
    sigaddset(&defaults, SIGTERM);
    sigaddset(&defaults, SIGINT);
    sigaddset(&defaults, SIGHUP);
    sigaddset(&defaults, SIGCHLD);

    int rc = -1;
    char *argv[] = {(char *)(size_t)path, NULL};
    if (posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) == 0 &&
        posix_spawn_file_actions_adddup2(&actions, out_fd, STDOUT_FILENO) == 0 &&
        posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0 &&
        posix_spawnattr_setsigmask(&attr, &none) == 0 &&
        posix_spawnattr_setsigdefault(&attr, &defaults) == 0 &&
        posix_spawnattr_setpgroup(&attr, 0) == 0 &&
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK |
                                            POSIX_SPAWN_SETSIGDEF) == 0 &&
        posix_spawn(pid, path, &actions, &attr, argv, environ) == 0)
        rc = 0;
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);
    return rc;
}

/* Runs `path` with no arguments and no shell, stdin closed, stderr dropped. Reads the start of its
 * stdout and waits for it to exit with status 0, all within timeout_ms; past that the process
 * group is killed. */
static int version_from_command(const char *path, int timeout_ms, char out[65]) {
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0)
        return -1;
    pid_t pid;
    int spawn_rc = spawn_command(path, pipefd[1], &pid);
    close(pipefd[1]);
    if (spawn_rc != 0) {
        close(pipefd[0]);
        return -1;
    }

    long long deadline = now_ms() + timeout_ms;
    char buf[SOURCE_LIMIT];
    size_t used = 0;
    int timed_out = 0;
    for (;;) { /* until end of file; output past the buffer is read and dropped */
        long long left = deadline - now_ms();
        if (left <= 0) {
            timed_out = 1;
            break;
        }
        struct pollfd pfd = {pipefd[0], POLLIN, 0};
        int pr = poll(&pfd, 1, (int)left);
        if (pr < 0 && errno == EINTR)
            continue;
        if (pr <= 0) {
            timed_out = 1;
            break;
        }
        char chunk[1024];
        ssize_t n = read(pipefd[0], chunk, sizeof chunk);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        if (used < sizeof buf) {
            size_t take = (size_t)n < sizeof buf - used ? (size_t)n : sizeof buf - used;
            memcpy(buf + used, chunk, take);
            used += take;
        }
    }
    close(pipefd[0]);

    int status = 0, exited = 0;
    while (!timed_out) {
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            exited = 1;
            break;
        }
        if (w < 0 && errno != EINTR)
            break;
        if (now_ms() >= deadline) {
            timed_out = 1;
            break;
        }
        struct timespec nap = {0, 5 * 1000 * 1000};
        nanosleep(&nap, NULL);
    }
    if (!exited) {
        kill(-pid, SIGKILL);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        }
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;
    return fa_first_line_value(buf, used, out);
}

int fa_component_version_timeout(const fa_config *c, const fa_component *comp, char out[65],
                                 int command_timeout_ms) {
    switch (comp->source) {
    case FA_VERSION_FIXED:
        return fa_first_line_value(comp->source_arg, strlen(comp->source_arg), out);
    case FA_VERSION_OS_RELEASE:
        return version_from_os_release(c->os_release, comp->source_arg, out);
    case FA_VERSION_FILE:
        return version_from_file(comp->source_arg, out);
    case FA_VERSION_COMMAND:
        return version_from_command(comp->source_arg, command_timeout_ms, out);
    case FA_VERSION_PACKAGE:
        if (version_from_package(c, out) == 0)
            return 0;
        return fa_first_line_value(comp->source_arg, strlen(comp->source_arg), out);
    }
    return -1;
}

int fa_component_version(const fa_config *c, const fa_component *comp, char out[65]) {
    return fa_component_version_timeout(c, comp, out, COMMAND_TIMEOUT_MS);
}
