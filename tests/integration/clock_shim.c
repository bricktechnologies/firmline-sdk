/* SPDX-License-Identifier: Apache-2.0 */
/* Test helper, never part of the agent: preloaded into it (LD_PRELOAD, see harness.clock_env), it
 * moves what time() returns by FIRMLINE_TEST_CLOCK_OFFSET seconds, as a device clock that jumped
 * forward or back would. The agent reads its wall clock with time(). */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <time.h>

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
