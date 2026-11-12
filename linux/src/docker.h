/* SPDX-License-Identifier: Apache-2.0 */
/* Running docker and the programs that go with it (tar, gzip) for `pack` and `apply`: posix_spawnp
 * (found in PATH), never a shell; stdin on /dev/null; its own process group; the agent's
 * environment (DOCKER_HOST and the like reach docker). */
#ifndef FIRMLINE_AGENT_DOCKER_H
#define FIRMLINE_AGENT_DOCKER_H

#include <stddef.h>

/* At most this many arguments, the program included. */
#define FA_COMMAND_MAX_ARGS 64

/* Runs argv[0] with argv (NULL-terminated). Its stdout goes into out, NUL-terminated, at most
 * cap - 1 bytes; output beyond that is an error, never cut: the process group is killed and the
 * result is -1. With out NULL (cap ignored) stdout goes to /dev/null. Its stderr goes to the log,
 * one "info <program>: <line>" per line (lines over 400 bytes are cut, at most 40 lines per run,
 * then a count of the lines left out), never into out. Past timeout_ms the process group is
 * killed: -1. The exit code (0 to 255), or -1 when it cannot start, is ended by a signal, times
 * out, writes too much, or fa_command_cancel was called; the reason of a -1 is logged as a
 * warning. */
int fa_command_run(const char *const argv[], char *out, size_t cap, int timeout_ms);

/* fa_command_run of `docker` with argv as its arguments: the words after "docker",
 * NULL-terminated, for example {"image", "inspect", "--format", "{{.Id}}", ref, NULL}. */
int fa_docker_run(const char *const argv[], char *out, size_t cap, int timeout_ms);

/* Async-signal-safe, for a SIGTERM or SIGINT handler: the running command is killed within 0.1 s
 * and every later one is refused, all with -1. */
void fa_command_cancel(void);

/* The ID (64 lowercase hex digits) of the Docker container the agent runs in, from
 * /proc/self/mountinfo: the bind on /etc/hostname of <data root>/containers/<ID>/hostname, which
 * Docker makes for every container (HOSTNAME is not used: a composition may set it). 0, or -1
 * outside a container (or in one that Docker did not make), with id unchanged. The file can be
 * changed with the environment variable FIRMLINE_MOUNTINFO_FILE: for the integration tests only,
 * which play an agent outside a container inside the test container. */
int fa_docker_own_container(char id[65]);

/* The same from the text of a mountinfo file (len bytes, no NUL needed). */
int fa_docker_container_of_mountinfo(const char *text, size_t len, char id[65]);

#endif
