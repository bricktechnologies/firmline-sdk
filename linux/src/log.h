/* SPDX-License-Identifier: Apache-2.0 */
/* The only way the agent logs: one line on stderr, "<level> <message>", no timestamp (journald adds
 * it), at most 1024 bytes including the newline (longer: cut and ended with an ellipsis). Newlines
 * in the message become spaces. Callers never pass tokens, download URLs, keys or certificates. */
#ifndef FIRMLINE_AGENT_LOG_H
#define FIRMLINE_AGENT_LOG_H

void fa_log(const char *level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#endif
