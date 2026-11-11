/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "check.h"
#include "docker.h"

#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static char log_path[64];

/* The test's stderr (the agent's log) goes into a file while fn runs; its text is returned. */
static const char *logged(void (*fn)(void)) {
    static char text[8192];
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    int fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    dup2(fd, STDERR_FILENO);
    close(fd);
    fn();
    fflush(stderr);
    dup2(saved, STDERR_FILENO);
    close(saved);
    FILE *f = fopen(log_path, "r");
    size_t n = f != NULL ? fread(text, 1, sizeof text - 1, f) : 0;
    if (f != NULL)
        fclose(f);
    text[n] = '\0';
    return text;
}

static long long elapsed_ms(const struct timespec *a) {
    struct timespec b;
    clock_gettime(CLOCK_MONOTONIC, &b);
    return (b.tv_sec - a->tv_sec) * 1000LL + (b.tv_nsec - a->tv_nsec) / 1000000;
}

static void command_captures_stdout_and_returns_the_exit_code(void) {
    char out[16];
    const char *printf_abc[] = {"printf", "abc", NULL};
    CHECK_EQ_INT(fa_command_run(printf_abc, out, sizeof out, 5000), 0);
    CHECK_EQ_STR(out, "abc");
    const char *exit3[] = {"sh", "-c", "printf x; exit 3", NULL};
    CHECK_EQ_INT(fa_command_run(exit3, out, sizeof out, 5000), 3);
    CHECK_EQ_STR(out, "x");
    /* stdout to /dev/null */
    CHECK_EQ_INT(fa_command_run(printf_abc, NULL, 0, 5000), 0);
    /* a program that is not there, a NULL or empty argv */
    const char *missing[] = {"firmline-no-such-program", NULL};
    CHECK_EQ_INT(fa_command_run(missing, out, sizeof out, 5000), -1);
    const char *empty[] = {NULL};
    CHECK_EQ_INT(fa_command_run(empty, out, sizeof out, 5000), -1);
    CHECK_EQ_INT(fa_command_run(NULL, out, sizeof out, 5000), -1);
    CHECK_EQ_INT(fa_command_run(printf_abc, out, 0, 5000), -1);
    /* ended by a signal */
    const char *killed[] = {"sh", "-c", "kill -9 $$", NULL};
    CHECK_EQ_INT(fa_command_run(killed, out, sizeof out, 5000), -1);
}

static void command_output_over_the_buffer_is_an_error_not_cut(void) {
    char out[8];
    const char *seven[] = {"printf", "1234567", NULL};
    CHECK_EQ_INT(fa_command_run(seven, out, sizeof out, 5000), 0);
    CHECK_EQ_STR(out, "1234567");
    const char *eight[] = {"printf", "12345678", NULL};
    CHECK_EQ_INT(fa_command_run(eight, out, sizeof out, 5000), -1);
    CHECK_EQ_STR(out, "");
    /* a command that would write much more is stopped at once */
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    const char *endless[] = {"sh", "-c", "while :; do echo xxxxxxxxxxxxxxxx; done", NULL};
    CHECK_EQ_INT(fa_command_run(endless, out, sizeof out, 20000), -1);
    CHECK(elapsed_ms(&start) < 5000);
}

static void run_stderr(void) {
    char out[64];
    const char *both[] = {"sh", "-c", "echo out; echo first >&2; echo second >&2", NULL};
    CHECK_EQ_INT(fa_command_run(both, out, sizeof out, 5000), 0);
    CHECK_EQ_STR(out, "out\n");
}

static void run_many_lines(void) {
    const char *many[] = {"sh", "-c",
                          "i=0; while [ $i -lt 50 ]; do echo line$i >&2; i=$((i+1)); done", NULL};
    CHECK_EQ_INT(fa_command_run(many, NULL, 0, 5000), 0);
}

static void command_stderr_goes_to_the_log_not_to_the_output(void) {
    const char *text = logged(run_stderr);
    CHECK(strstr(text, "info sh: first\ninfo sh: second\n") != NULL);
    CHECK(strstr(text, "out") == NULL);
    text = logged(run_many_lines);
    CHECK(strstr(text, "info sh: line39\n") != NULL);
    CHECK(strstr(text, "line40") == NULL);
    CHECK(strstr(text, "10 more lines") != NULL);
}

static void command_past_its_time_is_killed_with_its_group(void) {
    char out[16];
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    const char *sleeper[] = {"sleep", "30", NULL};
    CHECK_EQ_INT(fa_command_run(sleeper, out, sizeof out, 300), -1);
    CHECK(elapsed_ms(&start) < 3000);
    /* a child in the background keeps the pipe open: still bounded by the time */
    clock_gettime(CLOCK_MONOTONIC, &start);
    const char *background[] = {"sh", "-c", "sleep 30 & echo started", NULL};
    CHECK_EQ_INT(fa_command_run(background, out, sizeof out, 300), -1);
    CHECK(elapsed_ms(&start) < 3000);
}

static void docker_run_puts_docker_in_front(void) {
    char out[256];
    const char *version[] = {"--version", NULL};
    CHECK_EQ_INT(fa_docker_run(version, out, sizeof out, 10000), 0);
    CHECK(strncmp(out, "Docker version ", 15) == 0);
    const char *many[FA_COMMAND_MAX_ARGS + 1];
    for (int i = 0; i < FA_COMMAND_MAX_ARGS; i++)
        many[i] = "x";
    many[FA_COMMAND_MAX_ARGS] = NULL; /* docker and 64 more: over the limit */
    CHECK_EQ_INT(fa_docker_run(many, out, sizeof out, 10000), -1);
}

static void command_after_cancel_is_refused(void) {
    char out[16];
    const char *printf_abc[] = {"printf", "abc", NULL};
    fa_command_cancel();
    CHECK_EQ_INT(fa_command_run(printf_abc, out, sizeof out, 5000), -1);
}

int main(void) {
    snprintf(log_path, sizeof log_path, "/tmp/fa-docker-log-%ld", (long)getpid());
    RUN(command_captures_stdout_and_returns_the_exit_code);
    RUN(command_output_over_the_buffer_is_an_error_not_cut);
    RUN(command_stderr_goes_to_the_log_not_to_the_output);
    RUN(command_past_its_time_is_killed_with_its_group);
    RUN(docker_run_puts_docker_in_front);
    RUN(command_after_cancel_is_refused); /* last: a cancel is for good */
    unlink(log_path);
    return CHECK_RESULT;
}
