/* SPDX-License-Identifier: Apache-2.0 */
#include "firmline/fl_version.h"

#include <stddef.h>
#include <stdint.h>

#define MAX_PART_DIGITS 19 /* the largest such number always fits uint64_t */

static bool is_digit(char c) { return c >= '0' && c <= '9'; }

static char lower(char c) { return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c; }

/* Reads the dotted number at *s and moves *s past it, and past the dot if another number follows
 * (so is_digit(*s) tells whether one does). False if there is no number or it is too long. */
static bool next_part(const char **s, uint64_t *value) {
    const char *p = *s;
    int n = 0;
    uint64_t v = 0;
    if (!is_digit(*p))
        return false;
    for (; is_digit(*p); p++, n++) {
        if (n >= MAX_PART_DIGITS)
            return false;
        v = v * 10 + (uint64_t)(*p - '0');
    }
    *value = v;
    *s = (*p == '.' && is_digit(p[1])) ? p + 1 : p;
    return true;
}

/* True if s starts with dotted numbers that all fit. */
static bool is_numeric(const char *s) {
    uint64_t v;
    do {
        if (!next_part(&s, &v))
            return false;
    } while (is_digit(*s));
    return true;
}

static bool equal_ignore_case(const char *a, const char *b) {
    for (; *a != '\0' && *b != '\0'; a++, b++)
        if (lower(*a) != lower(*b))
            return false;
    return *a == *b;
}

bool fl_version_too_old(const char *candidate, const char *installed) {
    if (candidate == NULL || installed == NULL)
        return false;
    if (is_numeric(candidate) && is_numeric(installed)) {
        const char *c = candidate, *i = installed;
        bool c_more = true, i_more = true;
        while (c_more || i_more) {
            uint64_t cv = 0, iv = 0; /* a missing part counts as 0 */
            if (c_more) {
                (void)next_part(&c, &cv);
                c_more = is_digit(*c);
            }
            if (i_more) {
                (void)next_part(&i, &iv);
                i_more = is_digit(*i);
            }
            if (cv != iv)
                return cv < iv;
        }
    }
    return equal_ignore_case(candidate, installed);
}
