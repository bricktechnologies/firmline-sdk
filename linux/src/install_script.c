/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE /* pipe2, posix_spawn_file_actions_addchdir_np */
#include "install_script.h"

#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define REBOOT_TIMEOUT_S 60
#define STOP_GRACE_MS 5000
#define KILL_WAIT_MS 1000
#define MAX_ARGS 16

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* One line of output to the log: control characters (escape sequences included) become '?'. */
static void flush_line(fa_child *c) {
    if (c->line_len == 0)
        return;
    for (size_t i = 0; i < c->line_len; i++) {
        unsigned char ch = (unsigned char)c->line[i];
        if ((ch < 0x20 && ch != '\t') || ch == 0x7f)
            c->line[i] = '?';
    }
    fa_log("info", "script: %.*s", (int)c->line_len, c->line);
    c->line_len = 0;
}

/* Reads what is there without waiting; at the end of the output the pipe is closed. */
static void read_output(fa_child *c) {
    while (c->out >= 0) {
        char buf[1024];
        ssize_t n = read(c->out, buf, sizeof buf);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        if (n <= 0) { /* end of the output (or an error): nothing more will come */
            close(c->out);
            c->out = -1;
            flush_line(c);
            return;
        }
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] == '\n') {
                flush_line(c);
                continue;
            }
            if (buf[i] == '\r')
                continue;
            if (c->line_len == sizeof c->line)
                flush_line(c);
            c->line[c->line_len++] = buf[i];
        }
    }
}

static int spawn(fa_child *c, char *const argv[], int timeout_s) {
    memset(c, 0, sizeof *c);
    c->out = -1;
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0)
        return -1;
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;
    if (posix_spawn_file_actions_init(&actions) != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (posix_spawnattr_init(&attr) != 0) {
        posix_spawn_file_actions_destroy(&actions);
        close(pipefd[0]);
        close(pipefd[1]);
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

    pid_t pid = 0;
    int rc = -1;
    if (posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) == 0 &&
        posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO) == 0 &&
        posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDERR_FILENO) == 0 &&
        posix_spawn_file_actions_addchdir_np(&actions, "/") == 0 &&
        /* nothing of the agent beyond 0-2 (the broker socket, the download, the data folder) */
        posix_spawn_file_actions_addclosefrom_np(&actions, 3) == 0 &&
        posix_spawnattr_setsigmask(&attr, &none) == 0 &&
        posix_spawnattr_setsigdefault(&attr, &defaults) == 0 &&
        posix_spawnattr_setpgroup(&attr, 0) == 0 &&
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK |
                                            POSIX_SPAWN_SETSIGDEF) == 0)
        rc = posix_spawn(&pid, argv[0], &actions, &attr, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);
    close(pipefd[1]);
    if (rc != 0) {
        close(pipefd[0]);
        errno = rc > 0 ? rc : errno;
        return -1;
    }
    int flags = fcntl(pipefd[0], F_GETFL);
    if (flags >= 0)
        fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
    c->pid = pid;
    c->out = pipefd[0];
    c->deadline = timeout_s > 0 ? now_ms() + (long long)timeout_s * 1000 : 0;
    return 0;
}

int fa_install_script_start(fa_child *c, const fa_component *comp, const char *file,
                            const char *version, const char *release) {
    char *argv[] = {(char *)(size_t)comp->script, (char *)(size_t)file, (char *)(size_t)version,
                    (char *)(size_t)release, NULL};
    if (spawn(c, argv, comp->timeout_s) != 0) {
        fa_log("error", "cannot start the install script %s: %s", comp->script, strerror(errno));
        return -1;
    }
    return 0;
}

int fa_reboot_start(fa_child *c, const char *command) {
    char words[sizeof((fa_config *)0)->reboot_command];
    char *argv[MAX_ARGS + 1];
    int n = 0;
    snprintf(words, sizeof words, "%s", command);
    for (char *save = NULL, *w = strtok_r(words, " ", &save); w != NULL;
         w = strtok_r(NULL, " ", &save)) {
        if (n == MAX_ARGS) {
            fa_log("error", "reboot_command has more than %d words", MAX_ARGS);
            return -1;
        }
        argv[n++] = w;
    }
    argv[n] = NULL;
    if (n == 0 || spawn(c, argv, REBOOT_TIMEOUT_S) != 0) {
        fa_log("error", "cannot start reboot_command %s: %s", n > 0 ? argv[0] : "",
               n > 0 ? strerror(errno) : "empty");
        return -1;
    }
    return 0;
}

/* The process group of the program; also the program itself while it is not reaped (its pid
 * cannot be reused before), in case it left the group. */
static void kill_group(fa_child *c, int sig, bool reaped) {
    kill(-c->pid, sig);
    if (!reaped)
        kill(c->pid, sig);
}

/* The program is gone (reaped, or no longer our child): its output is closed. */
static void forget(fa_child *c) {
    read_output(c); /* what it wrote last; a background process it left may keep the pipe */
    if (c->out >= 0) {
        close(c->out);
        c->out = -1;
    }
    flush_line(c);
    c->pid = 0;
}

int fa_child_poll(fa_child *c, int *exit_code, bool *timed_out) {
    *exit_code = -1;
    *timed_out = c->timed_out;
    if (c->pid == 0)
        return 0;
    read_output(c);
    int status = 0;
    pid_t w = waitpid(c->pid, &status, WNOHANG);
    if (w == c->pid) {
        forget(c);
        if (!c->killed)
            *exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        return 0;
    }
    if (w < 0 && errno != EINTR) { /* not our child any more: nothing to wait for */
        forget(c);
        return 0;
    }
    if (!c->killed && c->deadline != 0 && now_ms() >= c->deadline) {
        /* Never waited for here: a process in uninterruptible sleep would block the loop. It is
         * reaped by a later poll. */
        kill_group(c, SIGKILL, false);
        c->killed = true;
        c->timed_out = true;
    }
    return 1;
}

/* Polls for the exit until `until` (monotonic ms) without blocking longer than 100 ms at once.
 * True when it was reaped. */
static bool wait_exit(fa_child *c, long long until) {
    int status;
    while (now_ms() < until) {
        read_output(c);
        pid_t w = waitpid(c->pid, &status, WNOHANG);
        if (w == c->pid || (w < 0 && errno != EINTR))
            return true;
        struct pollfd pfd = {c->out, POLLIN, 0};
        poll(&pfd, c->out >= 0 ? 1 : 0, 100);
    }
    return false;
}

void fa_child_stop(fa_child *c) {
    if (c->pid == 0)
        return;
    if (!c->killed)
        kill_group(c, SIGTERM, false);
    if (!wait_exit(c, now_ms() + STOP_GRACE_MS)) {
        kill_group(c, SIGKILL, false);
        if (!wait_exit(c, now_ms() + KILL_WAIT_MS))
            fa_log("warning", "process %ld does not end after SIGKILL: left behind", (long)c->pid);
    } else {
        kill_group(c, SIGKILL, true); /* what it left behind in its group */
    }
    forget(c);
}
