/* SPDX-License-Identifier: Apache-2.0 */
/* The persistent data folder (/var/lib/firmline). Flat: names have no '/'. Every write is atomic.
 */
#ifndef FIRMLINE_AGENT_STORE_H
#define FIRMLINE_AGENT_STORE_H

#include <stddef.h>
#include <sys/types.h>

/* Temp file in the same folder (created O_EXCL, set to exactly `mode` before any byte is written),
 * fsync, rename, fsync of the folder. On failure the temp file is removed: -1, errno of the step
 * that failed (unset for an invalid name or a path too long). */
int fa_store_write(const char *dir, const char *name, const void *data, size_t len, mode_t mode);

/* Reads up to 1 MiB into a NUL-terminated buffer that the caller frees. -1 when missing, larger
 * or unreadable. */
int fa_store_read(const char *dir, const char *name, char **data, size_t *len);

/* Removes the file; a file that is already missing is success (0). -1 on any other error. */
int fa_store_remove(const char *dir, const char *name);

/* Renames `from` to `to` in one step (replacing `to`, keeping the mode), then fsync of the folder.
 * -1 when a name is not valid, `from` is missing or the rename fails. */
int fa_store_rename(const char *dir, const char *from, const char *to);

/* Removes the temporary files that a write cut short (power loss, kill) left in the folder: names
 * of the form ".<name>.<pid>.<n>.tmp" whose process is gone or is this one (at start-up nothing
 * is being written yet; after a reboot the same pid can come back). A write in progress in
 * another living process is left alone. The number of files removed, or -1 when the folder cannot
 * be read. */
int fa_store_remove_stale(const char *dir);

#endif
