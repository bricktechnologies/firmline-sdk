/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FIRMLINE_FL_VERSION_H
#define FIRMLINE_FL_VERSION_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* True if the device must refuse `candidate` because `installed` is newer or the same.
 * When both versions start with dotted numbers and those differ, they are compared as numbers
 * (missing parts count as 0); otherwise only the same version, ignoring case, is refused.
 * installed == NULL never refuses. */
bool fl_version_too_old(const char *candidate, const char *installed);

#ifdef __cplusplus
}
#endif

#endif
