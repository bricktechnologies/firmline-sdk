/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "check.h"
#include "log.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

/* Runs fa_log once with stderr redirected to a file and returns what it wrote. */
static size_t capture(char *buf, size_t size, const char *level, const char *msg) {
    char path[] = "/tmp/fa-log-XXXXXX";
    int fd = mkstemp(path);
    int saved = dup(2);
    dup2(fd, 2);
    fa_log(level, "%s", msg);
    dup2(saved, 2);
    close(saved);
    lseek(fd, 0, SEEK_SET);
    ssize_t n = read(fd, buf, size - 1);
    close(fd);
    unlink(path);
    if (n < 0)
        n = 0;
    buf[n] = '\0';
    return (size_t)n;
}

static void log_writes_one_line_with_level(void) {
    char buf[4096];
    capture(buf, sizeof buf, "info", "started 3 components");
    CHECK_EQ_STR(buf, "info started 3 components\n");
    capture(buf, sizeof buf, "error", "two\nlines\r\n");
    CHECK_EQ_STR(buf, "error two lines  \n");
}

static void log_never_exceeds_1024_bytes(void) {
    char msg[3000], buf[4096];
    memset(msg, 'a', sizeof msg);
    msg[sizeof msg - 1] = '\0';
    size_t n = capture(buf, sizeof buf, "warn", msg);
    CHECK(n <= 1024);
    CHECK(n > 1000);
    CHECK(memcmp(buf + n - 4, "\xe2\x80\xa6\n", 4) == 0);
    /* a multi-byte character is never cut in half */
    memset(msg, 0, sizeof msg);
    for (int i = 0; i < 900; i++)
        strcat(msg, "\xc3\xa8"); /* e grave, 2 bytes */
    n = capture(buf, sizeof buf, "warn", msg);
    CHECK(n <= 1024);
    CHECK(memcmp(buf + n - 4, "\xe2\x80\xa6\n", 4) == 0);
    CHECK_EQ_INT((unsigned char)buf[n - 5], 0xa8);
    CHECK_EQ_INT((unsigned char)buf[n - 6], 0xc3);
}

int main(void) {
    RUN(log_writes_one_line_with_level);
    RUN(log_never_exceeds_1024_bytes);
    return CHECK_RESULT;
}
