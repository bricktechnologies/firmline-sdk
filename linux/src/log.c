/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define LOG_MAX 1024 /* the whole line, newline included */

void fa_log(const char *level, const char *fmt, ...) {
    static const char ellipsis[] = "\xe2\x80\xa6";
    char line[LOG_MAX + 8];
    int head = snprintf(line, sizeof line, "%s ", level);
    if (head < 0 || head >= LOG_MAX - 8)
        head = 0;

    va_list ap;
    va_start(ap, fmt);
    int body = vsnprintf(line + head, sizeof line - (size_t)head, fmt, ap);
    va_end(ap);
    if (body < 0)
        body = 0;
    size_t len = (size_t)head + (size_t)body;
    if (len > sizeof line - 1)
        len = sizeof line - 1;

    for (size_t i = 0; i < len; i++)
        if (line[i] == '\n' || line[i] == '\r')
            line[i] = ' ';

    if (len > LOG_MAX - 1) { /* room for the newline: cut, never inside a UTF-8 sequence */
        len = LOG_MAX - 1 - (sizeof ellipsis - 1);
        while (len > 0 && ((unsigned char)line[len] & 0xc0) == 0x80)
            len--;
        memcpy(line + len, ellipsis, sizeof ellipsis - 1);
        len += sizeof ellipsis - 1;
    }
    line[len++] = '\n';

    /* One write, so that lines from the agent never interleave mid-line. */
    ssize_t ignored = write(STDERR_FILENO, line, len);
    (void)ignored;
}
