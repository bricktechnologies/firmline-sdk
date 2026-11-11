/* SPDX-License-Identifier: Apache-2.0 */
/* Programs the agent runs for an update: the install script of a component and the reboot
 * command. They run in the background while the service goes on: started with posix_spawn (no
 * shell) in a process group of their own, with stdin on /dev/null and the working folder "/";
 * nothing of the agent is inherited but stdin, stdout and stderr; their
 * stdout and stderr go to the agent's log line by line ("script: <line>"), and the caller
 * polls them from its loop. Past the time limit the whole process group is killed. */
#ifndef FIRMLINE_AGENT_INSTALL_SCRIPT_H
#define FIRMLINE_AGENT_INSTALL_SCRIPT_H

#include "config.h"

#include <stdbool.h>
#include <sys/types.h>

#define FA_CHILD_LINE 512 /* longer lines of output are logged in pieces */

typedef struct {
    pid_t pid;          /* 0: nothing running */
    int out;            /* read end of its stdout and stderr, -1 once closed */
    long long deadline; /* monotonic ms; 0 = no limit */
    bool killed;        /* SIGKILL sent at the deadline, not reaped yet */
    bool timed_out;
    char line[FA_CHILD_LINE];
    size_t line_len;
} fa_child;

/* Exit code of an install script: installed at the next start (the device reboots). */
#define FA_SCRIPT_LATER 10

/* `<script> <file> <version> <release>` for the component, with its timeout. 0, or -1 when it
 * cannot start (logged). */
int fa_install_script_start(fa_child *c, const fa_component *comp, const char *file,
                            const char *version, const char *release);

/* reboot_command split on spaces (the first word an absolute path), with a limit of 60 s. 0, or
 * -1 when it cannot start (logged). */
int fa_reboot_start(fa_child *c, const char *command);

/* The output so far goes to the log; then the exit, or the deadline. Never blocks: at the deadline
 * the process group gets SIGKILL and the program stays "running" until a later poll reaps it (a
 * process in uninterruptible sleep must not stop the loop). 1 while it runs (or is not reaped yet).
 * 0 when it has ended: *exit_code is its exit status, or -1 when a signal ended it or it was
 * killed at the deadline (*timed_out true then). */
int fa_child_poll(fa_child *c, int *exit_code, bool *timed_out);

/* Ends a program still running (the agent stops): SIGTERM to its process group, up to 5 s, then
 * SIGKILL and up to 1 s more (a process that still does not end is left behind, logged); closes
 * its output. Harmless when nothing runs. */
void fa_child_stop(fa_child *c);

#endif
