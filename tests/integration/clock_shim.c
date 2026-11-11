/* SPDX-License-Identifier: Apache-2.0 */
/* Test helper, never part of the agent: preloaded into it (LD_PRELOAD, see harness.clock_env).
 *  - time() runs FIRMLINE_TEST_CLOCK_OFFSET seconds ahead (or behind), as a device clock that
 *    jumped forward or back would. The agent reads its wall clock with time().
 *  - clock_gettime(CLOCK_MONOTONIC) runs ahead by the whole seconds written in the file named by
 *    FIRMLINE_TEST_MONOTONIC_OFFSET_FILE (missing or unreadable file: 0). The file is read again
 *    at most every 100 ms of real time, so a test moves the monotonic clock of a running agent by
 *    rewriting it (harness.MonotonicClock). Only CLOCK_MONOTONIC: it is the one the agent uses
 *    for its own timers; other clocks (libcurl may use CLOCK_MONOTONIC_RAW) are left alone. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

time_t time(time_t *out) {
    static time_t (*real)(time_t *) = NULL;
    if (real == NULL)
        *(void **)&real = dlsym(RTLD_NEXT, "time");
    const char *offset = getenv("FIRMLINE_TEST_CLOCK_OFFSET");
    time_t now = real(NULL) + (offset != NULL ? (time_t)strtoll(offset, NULL, 10) : 0);
    if (out != NULL)
        *out = now;
    return now;
}

static long long read_offset(const char *path) {
    char buf[32];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0)
        return 0;
    buf[n] = '\0';
    return strtoll(buf, NULL, 10);
}

int clock_gettime(clockid_t id, struct timespec *ts) {
    static int (*real)(clockid_t, struct timespec *) = NULL;
    static long long offset = 0;     /* seconds; a race between threads only costs a re-read */
    static long long next_read = -1; /* real monotonic nanoseconds */
    if (real == NULL)
        *(void **)&real = dlsym(RTLD_NEXT, "clock_gettime");
    int rc = real(id, ts);
    const char *path = getenv("FIRMLINE_TEST_MONOTONIC_OFFSET_FILE");
    if (rc != 0 || id != CLOCK_MONOTONIC || path == NULL)
        return rc;
    long long now = (long long)ts->tv_sec * 1000000000LL + ts->tv_nsec;
    long long due = __atomic_load_n(&next_read, __ATOMIC_RELAXED);
    if (due < 0 || now >= due) {
        __atomic_store_n(&offset, read_offset(path), __ATOMIC_RELAXED);
        __atomic_store_n(&next_read, now + 100000000LL, __ATOMIC_RELAXED);
    }
    ts->tv_sec += (time_t)__atomic_load_n(&offset, __ATOMIC_RELAXED);
    return rc;
}
