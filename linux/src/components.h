/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FIRMLINE_AGENT_COMPONENTS_H
#define FIRMLINE_AGENT_COMPONENTS_H

#include "config.h"

/* The installed version of a component, from where the configuration says. `command:` runs the
 * program with posix_spawn (no shell, stdin closed) and gives it 10 seconds. The result is the
 * first line, trimmed, 1 to 64 bytes. 0, or -1 when unreadable. */
int fa_component_version(const fa_config *c, const fa_component *comp, char out[65]);

/* Same with the time limit of a `command:` source given (milliseconds); for tests. */
int fa_component_version_timeout(const fa_config *c, const fa_component *comp, char out[65],
                                 int command_timeout_ms);

/* First line of `text` (of `len` bytes), trimmed, as a version into out: 0, or -1 when empty or
 * longer than 64 bytes. Shared by the sources and the serial number. */
int fa_first_line_value(const char *text, size_t len, char out[65]);

#endif
