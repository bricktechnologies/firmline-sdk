/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE /* pipe2 */
#include "docker.h"

#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define LINE_MAX_BYTES 400 /* of a stderr line in the log */
#define LOGGED_LINES 40    /* stderr lines logged per run */
#define SLICE_MS 100       /* how often a running command checks fa_command_cancel */

static volatile sig_atomic_t cancelled = 0;

void fa_command_cancel(void) { cancelled = 1; }

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static const char *base_name(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash != NULL ? slash + 1 : path;
}

/* The stderr of a command, logged a line at a time. */
typedef struct {
    const char *program;
    char line[LINE_MAX_BYTES + 1];
    size_t len;
    bool cut; /* the rest of an over-long line is skipped */
    int logged, dropped;
} stderr_log;

static void end_line(stderr_log *s) {
    if (s->len > 0) {
        if (s->logged < LOGGED_LINES) {
            s->line[s->len] = '\0';
            fa_log("info", "%s: %s", s->program, s->line);
            s->logged++;
        } else {
            s->dropped++;
        }
    }
    s->len = 0;
    s->cut = false;
}

static void add_stderr(stderr_log *s, const char *data, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (data[i] == '\n') {
            end_line(s);
        } else if (!s->cut) {
            s->line[s->len++] = data[i];
            if (s->len == LINE_MAX_BYTES) {
                end_line(s);
                s->cut = true;
            }
        }
    }
}

/* Starts argv in its own process group, stdin on /dev/null, stdout on out_fd (or /dev/null when
 * it is -1), stderr on err_fd, an empty signal mask and the default action for the signals the
 * agent handles. 0, or the error number of the step that failed. */
static int spawn(const char *const argv[], int out_fd, int err_fd, pid_t *pid) {
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;
    if (posix_spawn_file_actions_init(&actions) != 0)
        return ENOMEM;
    if (posix_spawnattr_init(&attr) != 0) {
        posix_spawn_file_actions_destroy(&actions);
        return ENOMEM;
    }
    sigset_t none, defaults;
    sigemptyset(&none);
    sigemptyset(&defaults);
    sigaddset(&defaults, SIGPIPE);
    sigaddset(&defaults, SIGTERM);
    sigaddset(&defaults, SIGINT);
    sigaddset(&defaults, SIGHUP);
    sigaddset(&defaults, SIGCHLD);
    int rc = EINVAL;
    if (posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) == 0 &&
        (out_fd >= 0 ? posix_spawn_file_actions_adddup2(&actions, out_fd, STDOUT_FILENO)
                     : posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null",
                                                        O_WRONLY, 0)) == 0 &&
        posix_spawn_file_actions_adddup2(&actions, err_fd, STDERR_FILENO) == 0 &&
        posix_spawnattr_setsigmask(&attr, &none) == 0 &&
        posix_spawnattr_setsigdefault(&attr, &defaults) == 0 &&
        posix_spawnattr_setpgroup(&attr, 0) == 0 &&
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK |
                                            POSIX_SPAWN_SETSIGDEF) == 0)
        rc = posix_spawnp(pid, argv[0], &actions, &attr, (char *const *)(uintptr_t)argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);
    return rc;
}

static void kill_and_reap(pid_t pid) {
    int status;
    kill(-pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
}

int fa_command_run(const char *const argv[], char *out, size_t cap, int timeout_ms) {
    if (argv == NULL || argv[0] == NULL || (out != NULL && cap == 0))
        return -1;
    const char *program = base_name(argv[0]);
    if (cancelled) {
        fa_log("warning", "%s: not started, the command was interrupted", program);
        return -1;
    }
    int out_pipe[2] = {-1, -1}, err_pipe[2];
    if (pipe2(err_pipe, O_CLOEXEC) != 0)
        return -1;
    if (out != NULL && pipe2(out_pipe, O_CLOEXEC) != 0) {
        close(err_pipe[0]);
        close(err_pipe[1]);
        return -1;
    }
    pid_t pid;
    int spawned = spawn(argv, out_pipe[1], err_pipe[1], &pid);
    close(err_pipe[1]);
    if (out_pipe[1] >= 0)
        close(out_pipe[1]);
    if (spawned != 0) {
        fa_log("warning", "%s: cannot start it (%s)", program, strerror(spawned));
        close(err_pipe[0]);
        if (out_pipe[0] >= 0)
            close(out_pipe[0]);
        return -1;
    }

    stderr_log log = {.program = program};
    size_t used = 0;
    const char *stopped = NULL; /* why the command was killed */
    long long deadline = now_ms() + timeout_ms;
    struct pollfd fds[2] = {{err_pipe[0], POLLIN, 0}, {out_pipe[0], POLLIN, 0}};
    int open_fds = out != NULL ? 2 : 1;
    while (open_fds > 0 && stopped == NULL) {
        long long left = deadline - now_ms();
        if (cancelled) {
            stopped = "interrupted";
            break;
        }
        if (left <= 0) {
            stopped = "out of time";
            break;
        }
        int pr = poll(fds, 2, left < SLICE_MS ? (int)left : SLICE_MS);
        if (pr <= 0)
            continue; /* a slice gone by, or EINTR: check again */
        for (int i = 0; i < 2 && stopped == NULL; i++) {
            if (fds[i].fd < 0 || fds[i].revents == 0)
                continue;
            char chunk[4096];
            ssize_t n = read(fds[i].fd, chunk, sizeof chunk);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0) {
                close(fds[i].fd);
                fds[i].fd = -1;
                open_fds--;
            } else if (i == 0) {
                add_stderr(&log, chunk, (size_t)n);
            } else if ((size_t)n > cap - 1 - used) {
                stopped = "output too long";
            } else {
                memcpy(out + used, chunk, (size_t)n);
                used += (size_t)n;
            }
        }
    }
    for (int i = 0; i < 2; i++)
        if (fds[i].fd >= 0)
            close(fds[i].fd);
    end_line(&log);
    if (log.dropped > 0)
        fa_log("info", "%s: %d more lines of its error output left out", program, log.dropped);

    int status = 0;
    while (stopped == NULL) { /* the pipes are closed: wait for the exit, within the time */
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid)
            break;
        if (w < 0 && errno != EINTR) {
            stopped = "lost";
        } else if (cancelled) {
            stopped = "interrupted";
        } else if (now_ms() >= deadline) {
            stopped = "out of time";
        } else {
            struct timespec nap = {0, 5 * 1000 * 1000};
            nanosleep(&nap, NULL);
        }
    }
    if (stopped != NULL) {
        kill_and_reap(pid);
        if (strcmp(stopped, "output too long") == 0)
            fa_log("warning", "%s: stopped, its output is over %zu bytes", program, cap - 1);
        else if (strcmp(stopped, "out of time") == 0)
            fa_log("warning", "%s: stopped after %d s", program, timeout_ms / 1000);
        else
            fa_log("warning", "%s: stopped, %s", program, stopped);
        if (out != NULL)
            out[0] = '\0';
        return -1;
    }
    if (out != NULL)
        out[used] = '\0';
    if (!WIFEXITED(status)) {
        fa_log("warning", "%s: ended by signal %d", program,
               WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        return -1;
    }
    return WEXITSTATUS(status);
}

int fa_docker_run(const char *const argv[], char *out, size_t cap, int timeout_ms) {
    const char *full[FA_COMMAND_MAX_ARGS + 1];
    size_t n = 0;
    full[n++] = "docker";
    for (; argv != NULL && argv[n - 1] != NULL; n++) {
        if (n >= FA_COMMAND_MAX_ARGS) {
            fa_log("warning", "docker: more than %d arguments", FA_COMMAND_MAX_ARGS);
            return -1;
        }
        full[n] = argv[n - 1];
    }
    full[n] = NULL;
    return fa_command_run(full, out, cap, timeout_ms);
}
