/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "store.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define READ_LIMIT (1024 * 1024)

/* Flat folder: a plain name, no separator, not "." or "..". */
static int valid_name(const char *name) {
    return name[0] != '\0' && strchr(name, '/') == NULL && strcmp(name, ".") != 0 &&
           strcmp(name, "..") != 0;
}

static int make_path(char *out, size_t size, const char *dir, const char *name) {
    int n = snprintf(out, size, "%s/%s", dir, name);
    return n > 0 && (size_t)n < size ? 0 : -1;
}

static int write_all(int fd, const char *p, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int sync_dir(const char *dir) {
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int rc = fsync(fd);
    close(fd);
    return rc;
}

int fa_store_write(const char *dir, const char *name, const void *data, size_t len, mode_t mode) {
    char path[PATH_MAX], tmp[PATH_MAX], tmp_name[NAME_MAX + 64];
    if (!valid_name(name) || make_path(path, sizeof path, dir, name) != 0)
        return -1;

    /* The temp file is created exclusively with the final mode, so a key is never readable by
     * anyone else, not even for an instant; its name carries the process id and a counter. */
    int fd = -1;
    for (int attempt = 0; attempt < 100 && fd < 0; attempt++) {
        snprintf(tmp_name, sizeof tmp_name, ".%s.%ld.%d.tmp", name, (long)getpid(), attempt);
        if (make_path(tmp, sizeof tmp, dir, tmp_name) != 0)
            return -1;
        fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
        if (fd < 0 && errno != EEXIST)
            return -1;
    }
    if (fd < 0)
        return -1;

    /* The umask can only have narrowed the mode at creation. Set it exactly now, before any byte
     * is written: the file is still empty and private to the agent, never wider than asked. */
    if (fchmod(fd, mode) != 0 || write_all(fd, data, len) != 0 || fsync(fd) != 0) {
        close(fd);
        unlink(tmp);
        return -1;
    }
    if (close(fd) != 0 || rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return sync_dir(dir);
}

int fa_store_read(const char *dir, const char *name, char **data, size_t *len) {
    char path[PATH_MAX];
    *data = NULL;
    if (!valid_name(name) || make_path(path, sizeof path, dir, name) != 0)
        return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    char *buf = malloc(READ_LIMIT + 2);
    if (buf == NULL) {
        close(fd);
        return -1;
    }
    size_t used = 0;
    for (;;) {
        ssize_t n = read(fd, buf + used, READ_LIMIT + 1 - used);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            used = READ_LIMIT + 1; /* an error: refuse below */
            break;
        }
        if (n == 0)
            break;
        used += (size_t)n;
        if (used > READ_LIMIT)
            break;
    }
    close(fd);
    if (used > READ_LIMIT) {
        free(buf);
        return -1;
    }
    char *shrunk = realloc(buf, used + 1);
    if (shrunk != NULL)
        buf = shrunk;
    buf[used] = '\0';
    *data = buf;
    *len = used;
    return 0;
}

int fa_store_remove(const char *dir, const char *name) {
    char path[PATH_MAX];
    if (!valid_name(name) || make_path(path, sizeof path, dir, name) != 0)
        return -1;
    if (unlink(path) != 0)
        return errno == ENOENT ? 0 : -1;
    return sync_dir(dir);
}

/* The pid in a temporary name ".<name>.<pid>.<n>.tmp" of fa_store_write, or -1 when the name has
 * another form. */
static long temp_pid(const char *entry) {
    size_t len = strlen(entry);
    if (len < 9 || entry[0] != '.' || strcmp(entry + len - 4, ".tmp") != 0)
        return -1;
    size_t end = len - 4, dots[2] = {0, 0},
           found = 0; /* the two dots before ".tmp", from the right */
    for (size_t i = end; i-- > 1 && found < 2;)
        if (entry[i] == '.')
            dots[found++] = i;
    if (found < 2 || dots[1] < 2) /* ".<name>" needs a name */
        return -1;
    long pid = 0;
    for (size_t i = dots[1] + 1; i < dots[0]; i++) {
        if (entry[i] < '0' || entry[i] > '9' || pid > 99999999)
            return -1;
        pid = pid * 10 + (entry[i] - '0');
    }
    for (size_t i = dots[0] + 1; i < end; i++)
        if (entry[i] < '0' || entry[i] > '9')
            return -1;
    return dots[0] > dots[1] + 1 && end > dots[0] + 1 && pid > 0 ? pid : -1;
}

int fa_store_remove_stale(const char *dir) {
    DIR *d = opendir(dir);
    if (d == NULL)
        return -1;
    int removed = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        long pid = temp_pid(e->d_name);
        if (pid < 0)
            continue;
        if (pid != (long)getpid() && (kill((pid_t)pid, 0) == 0 || errno != ESRCH))
            continue; /* its process lives: a write in progress */
        char path[PATH_MAX];
        if (make_path(path, sizeof path, dir, e->d_name) == 0 && unlink(path) == 0)
            removed++;
    }
    closedir(d);
    if (removed > 0)
        sync_dir(dir);
    return removed;
}

int fa_store_rename(const char *dir, const char *from, const char *to) {
    char from_path[PATH_MAX], to_path[PATH_MAX];
    if (!valid_name(from) || !valid_name(to) ||
        make_path(from_path, sizeof from_path, dir, from) != 0 ||
        make_path(to_path, sizeof to_path, dir, to) != 0)
        return -1;
    if (rename(from_path, to_path) != 0)
        return -1;
    return sync_dir(dir);
}
