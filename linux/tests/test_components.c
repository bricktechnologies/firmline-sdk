/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "check.h"
#include "components.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static char tmpdir[64];

static void put(const char *name, const char *text, mode_t mode, char path[256]) {
    snprintf(path, 256, "%s/%s", tmpdir, name);
    FILE *f = fopen(path, "w");
    fputs(text, f);
    fclose(f);
    chmod(path, mode);
}

static fa_component comp(fa_version_source source, const char *arg) {
    fa_component c;
    memset(&c, 0, sizeof c);
    strcpy(c.code, "x");
    c.source = source;
    snprintf(c.source_arg, sizeof c.source_arg, "%s", arg);
    return c;
}

static void version_fixed(void) {
    static fa_config cfg;
    char out[65];
    fa_component c = comp(FA_VERSION_FIXED, "1.2.3");
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), 0);
    CHECK_EQ_STR(out, "1.2.3");
}

static void version_from_os_release_key(void) {
    static fa_config cfg;
    char path[256], out[65];
    put("os-release",
        "NAME=\"Torizon OS\"\nVERSION_ID=\"7.2.0\"\nBUILD_ID='b-9'\nPLAIN=3.1\nEMPTY=\"\"\n"
        "XVERSION_ID=\"bad\"\n",
        0644, path);
    snprintf(cfg.os_release, sizeof cfg.os_release, "%s", path);
    fa_component c = comp(FA_VERSION_OS_RELEASE, "VERSION_ID");
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), 0);
    CHECK_EQ_STR(out, "7.2.0");
    snprintf(c.source_arg, sizeof c.source_arg, "BUILD_ID");
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), 0);
    CHECK_EQ_STR(out, "b-9");
    snprintf(c.source_arg, sizeof c.source_arg, "PLAIN");
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), 0);
    CHECK_EQ_STR(out, "3.1");
    snprintf(c.source_arg, sizeof c.source_arg, "EMPTY");
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), -1);
    snprintf(c.source_arg, sizeof c.source_arg, "MISSING");
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), -1);
    snprintf(cfg.os_release, sizeof cfg.os_release, "%s/none", tmpdir);
    snprintf(c.source_arg, sizeof c.source_arg, "VERSION_ID");
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), -1);
}

static void version_from_file_trims_newline(void) {
    static fa_config cfg;
    char path[256], out[65];
    put("ver", "  2.5.1 \t\r\nsecond line\n", 0644, path);
    fa_component c = comp(FA_VERSION_FILE, path);
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), 0);
    CHECK_EQ_STR(out, "2.5.1");
    put("empty", "\n", 0644, path);
    snprintf(c.source_arg, sizeof c.source_arg, "%s", path);
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), -1);
    char longv[200];
    memset(longv, '7', 65);
    longv[65] = '\0';
    put("long", longv, 0644, path);
    snprintf(c.source_arg, sizeof c.source_arg, "%s", path);
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), -1);
    longv[64] = '\0'; /* exactly 64 bytes is fine */
    put("long64", longv, 0644, path);
    snprintf(c.source_arg, sizeof c.source_arg, "%s", path);
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), 0);
    CHECK_EQ_INT(strlen(out), 64);
    snprintf(c.source_arg, sizeof c.source_arg, "%s/none", tmpdir);
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), -1);
}

static void version_from_command_first_line(void) {
    static fa_config cfg;
    char path[256], out[65];
    put("v.sh", "#!/bin/sh\necho '  3.0.9  '\necho second\n", 0755, path);
    fa_component c = comp(FA_VERSION_COMMAND, path);
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), 0);
    CHECK_EQ_STR(out, "3.0.9");
    /* the path is the program, with no shell: a space in it is just a space */
    put("with space.sh", "#!/bin/sh\necho 1\n", 0755, path);
    snprintf(c.source_arg, sizeof c.source_arg, "%s", path);
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), 0);
    CHECK_EQ_STR(out, "1");
    /* stdin is closed: a program that reads it gets end of file at once */
    put("stdin.sh", "#!/bin/sh\nread x; echo \"in:$x\"\n", 0755, path);
    snprintf(c.source_arg, sizeof c.source_arg, "%s", path);
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), 0);
    CHECK_EQ_STR(out, "in:");
    /* a lot of output is fine: only the first line counts */
    put("big.sh", "#!/bin/sh\necho 4.4\nyes | head -c 200000\n", 0755, path);
    snprintf(c.source_arg, sizeof c.source_arg, "%s", path);
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), 0);
    CHECK_EQ_STR(out, "4.4");
}

static void version_from_failing_command_is_unreadable(void) {
    static fa_config cfg;
    char path[256], out[65];
    put("fail.sh", "#!/bin/sh\necho 9.9\nexit 3\n", 0755, path);
    fa_component c = comp(FA_VERSION_COMMAND, path);
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), -1);
    put("silent.sh", "#!/bin/sh\nexit 0\n", 0755, path);
    snprintf(c.source_arg, sizeof c.source_arg, "%s", path);
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), -1);
    snprintf(c.source_arg, sizeof c.source_arg, "%s/nonexistent", tmpdir);
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), -1);
    put("long.sh", "#!/bin/sh\nyes 7 | head -c 200 | tr -d '\\n'; echo\n", 0755, path);
    snprintf(c.source_arg, sizeof c.source_arg, "%s", path);
    CHECK_EQ_INT(fa_component_version(&cfg, &c, out), -1);
}

static void version_from_hanging_command_is_killed(void) {
    static fa_config cfg;
    char path[256], out[65];
    put("hang.sh", "#!/bin/sh\necho 1.0\nsleep 30\n", 0755, path);
    fa_component c = comp(FA_VERSION_COMMAND, path);
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    CHECK_EQ_INT(fa_component_version_timeout(&cfg, &c, out, 300), -1);
    clock_gettime(CLOCK_MONOTONIC, &b);
    CHECK((b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000 < 5000);
}

int main(void) {
    snprintf(tmpdir, sizeof tmpdir, "/tmp/fa-comp-XXXXXX");
    if (mkdtemp(tmpdir) == NULL)
        return 1;
    RUN(version_fixed);
    RUN(version_from_os_release_key);
    RUN(version_from_file_trims_newline);
    RUN(version_from_command_first_line);
    RUN(version_from_failing_command_is_unreadable);
    RUN(version_from_hanging_command_is_killed);
    return CHECK_RESULT;
}
