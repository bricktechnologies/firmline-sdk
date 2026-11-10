/* SPDX-License-Identifier: Apache-2.0 */
/* The persistent data folder (/var/lib/firmline). Flat: names have no '/'. Every write is atomic.
 */
#ifndef FIRMLINE_AGENT_STORE_H
#define FIRMLINE_AGENT_STORE_H

#include <stddef.h>
#include <sys/types.h>

/* Temp file in the same folder (created O_EXCL with `mode`, subject to the umask, never chmod
 * afterwards), fsync, rename, fsync of the folder. On failure the temp file is removed: -1. */
int fa_store_write(const char *dir, const char *name, const void *data, size_t len, mode_t mode);

/* Reads up to 1 MiB into a NUL-terminated buffer that the caller frees. -1 when missing, larger
 * or unreadable. */
int fa_store_read(const char *dir, const char *name, char **data, size_t *len);

/* Removes the file; a file that is already missing is success (0). -1 on any other error. */
int fa_store_remove(const char *dir, const char *name);

#endif
