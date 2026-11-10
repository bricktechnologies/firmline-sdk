/* SPDX-License-Identifier: Apache-2.0 */
/* Minimal test helpers, no framework. A test file defines `static void test_x(void)` functions and
 * a main that calls RUN(test_x) for each and returns CHECK_RESULT. */
#ifndef FIRMLINE_TESTS_CHECK_H
#define FIRMLINE_TESTS_CHECK_H

#include <stdio.h>
#include <string.h>

static int check_failures = 0;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);               \
            check_failures++;                                                                      \
        }                                                                                          \
    } while (0)

#define CHECK_EQ_INT(actual, expected)                                                             \
    do {                                                                                           \
        long long check_a = (long long)(actual), check_e = (long long)(expected);                  \
        if (check_a != check_e) {                                                                  \
            fprintf(stderr, "%s:%d: %s: expected %lld, got %lld\n", __FILE__, __LINE__, #actual,   \
                    check_e, check_a);                                                             \
            check_failures++;                                                                      \
        }                                                                                          \
    } while (0)

#define CHECK_EQ_STR(actual, expected)                                                             \
    do {                                                                                           \
        const char *check_a = (actual), *check_e = (expected);                                     \
        if (check_a == NULL || strcmp(check_a, check_e) != 0) {                                    \
            fprintf(stderr, "%s:%d: %s: expected \"%s\", got \"%s\"\n", __FILE__, __LINE__,        \
                    #actual, check_e, check_a == NULL ? "(null)" : check_a);                       \
            check_failures++;                                                                      \
        }                                                                                          \
    } while (0)

#define CHECK_EQ_MEM(actual, expected, len)                                                        \
    do {                                                                                           \
        if (memcmp((actual), (expected), (len)) != 0) {                                            \
            fprintf(stderr, "%s:%d: %s: memory differs (%zu bytes)\n", __FILE__, __LINE__,         \
                    #actual, (size_t)(len));                                                       \
            check_failures++;                                                                      \
        }                                                                                          \
    } while (0)

#define RUN(test)                                                                                  \
    do {                                                                                           \
        int check_before = check_failures;                                                         \
        test();                                                                                    \
        printf("%s %s\n", check_failures == check_before ? "PASS" : "FAIL", #test);                \
    } while (0)

#define CHECK_RESULT (check_failures == 0 ? 0 : 1)

#endif
