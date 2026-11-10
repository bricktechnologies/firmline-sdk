/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "check.h"
#include "store.h"

#include <dirent.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static void make_dir(char path[], size_t size) {
    snprintf(path, size, "/tmp/fa-store-XXXXXX");
    if (mkdtemp(path) == NULL)
        path[0] = '\0';
}

static int count_entries(const char *dir) {
    int n = 0;
    DIR *d = opendir(dir);
    struct dirent *e;
    while (d != NULL && (e = readdir(d)) != NULL)
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
            n++;
    if (d != NULL)
        closedir(d);
    return n;
}

static void store_write_is_atomic(void) {
    umask(022);
    char dir[64];
    make_dir(dir, sizeof dir);
    CHECK_EQ_INT(fa_store_write(dir, "device.key", "old", 3, 0600), 0);
    CHECK_EQ_INT(fa_store_write(dir, "device.key", "new content", 11, 0600), 0);
    CHECK_EQ_INT(count_entries(dir), 1); /* no temp file left */

    char path[128];
    snprintf(path, sizeof path, "%s/device.key", dir);
    struct stat st;
    CHECK_EQ_INT(stat(path, &st), 0);
    CHECK_EQ_INT(st.st_mode & 0777, 0600);
    CHECK_EQ_INT(st.st_size, 11);

    char *data = NULL;
    size_t len = 0;
    CHECK_EQ_INT(fa_store_read(dir, "device.key", &data, &len), 0);
    CHECK_EQ_INT(len, 11);
    CHECK_EQ_STR(data, "new content");
    free(data);

    /* another mode, and binary content with a zero byte */
    CHECK_EQ_INT(fa_store_write(dir, "cert.pem", "a\0b", 3, 0644), 0);
    snprintf(path, sizeof path, "%s/cert.pem", dir);
    CHECK_EQ_INT(stat(path, &st), 0);
    CHECK_EQ_INT(st.st_mode & 0777, 0644);
    CHECK_EQ_INT(fa_store_read(dir, "cert.pem", &data, &len), 0);
    CHECK_EQ_INT(len, 3);
    CHECK_EQ_INT(data[3], 0);
    free(data);

    /* a failed write leaves no temp file: the target is a folder, so the rename fails */
    char sub[128];
    snprintf(sub, sizeof sub, "%s/folder", dir);
    CHECK_EQ_INT(mkdir(sub, 0700), 0);
    CHECK_EQ_INT(fa_store_write(dir, "folder", "x", 1, 0600), -1);
    CHECK_EQ_INT(count_entries(dir), 3);

    /* a folder that does not exist */
    CHECK_EQ_INT(fa_store_write("/nonexistent-dir-fa", "x", "x", 1, 0600), -1);
}

static void store_mode_is_exact_whatever_the_umask(void) {
    mode_t saved = umask(0);
    mode_t umasks[] = {077, 0, 027};
    mode_t modes[] = {0644, 0600, 0640, 0755};
    for (size_t u = 0; u < sizeof umasks / sizeof umasks[0]; u++) {
        umask(umasks[u]);
        for (size_t m = 0; m < sizeof modes / sizeof modes[0]; m++) {
            char dir[64], path[128];
            make_dir(dir, sizeof dir);
            CHECK_EQ_INT(fa_store_write(dir, "f", "x", 1, modes[m]), 0);
            snprintf(path, sizeof path, "%s/f", dir);
            struct stat st;
            CHECK_EQ_INT(stat(path, &st), 0);
            CHECK_EQ_INT(st.st_mode & 0777, modes[m]);
        }
    }
    umask(saved);
}

static void store_refuses_bad_names(void) {
    char dir[64];
    make_dir(dir, sizeof dir);
    char *data = NULL;
    size_t len = 0;
    const char *bad[] = {"a/b", "..", ".", "", "/etc/passwd"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        CHECK_EQ_INT(fa_store_write(dir, bad[i], "x", 1, 0600), -1);
        CHECK_EQ_INT(fa_store_read(dir, bad[i], &data, &len), -1);
        CHECK_EQ_INT(fa_store_remove(dir, bad[i]), -1);
    }
    CHECK_EQ_INT(count_entries(dir), 0);
}

static void store_read_missing_is_error(void) {
    char dir[64];
    make_dir(dir, sizeof dir);
    char *data = NULL;
    size_t len = 5;
    CHECK_EQ_INT(fa_store_read(dir, "nothing", &data, &len), -1);
    CHECK(data == NULL);
}

static void store_read_limit_is_one_mebibyte(void) {
    char dir[64];
    make_dir(dir, sizeof dir);
    size_t max = 1024 * 1024;
    char *big = malloc(max + 1);
    memset(big, 'a', max + 1);
    CHECK_EQ_INT(fa_store_write(dir, "ok", big, max, 0600), 0);
    CHECK_EQ_INT(fa_store_write(dir, "big", big, max + 1, 0600), 0);
    char *data = NULL;
    size_t len = 0;
    CHECK_EQ_INT(fa_store_read(dir, "ok", &data, &len), 0);
    CHECK_EQ_INT(len, max);
    free(data);
    CHECK_EQ_INT(fa_store_read(dir, "big", &data, &len), -1);
    free(big);
    /* an empty file reads as an empty string */
    CHECK_EQ_INT(fa_store_write(dir, "empty", "", 0, 0600), 0);
    CHECK_EQ_INT(fa_store_read(dir, "empty", &data, &len), 0);
    CHECK_EQ_INT(len, 0);
    CHECK_EQ_STR(data, "");
    free(data);
}

static void store_remove_deletes_and_tolerates_missing(void) {
    char dir[64];
    make_dir(dir, sizeof dir);
    CHECK_EQ_INT(fa_store_write(dir, "token", "t", 1, 0600), 0);
    CHECK_EQ_INT(fa_store_remove(dir, "token"), 0);
    CHECK_EQ_INT(count_entries(dir), 0);
    CHECK_EQ_INT(fa_store_remove(dir, "token"), 0);
}

static void store_rename_replaces_in_one_step(void) {
    umask(022);
    char dir[64];
    make_dir(dir, sizeof dir);
    CHECK_EQ_INT(fa_store_write(dir, "new.key", "fresh", 5, 0600), 0);
    CHECK_EQ_INT(fa_store_write(dir, "device.key", "old", 3, 0600), 0);
    CHECK_EQ_INT(fa_store_rename(dir, "new.key", "device.key"), 0);
    CHECK_EQ_INT(count_entries(dir), 1);

    char *data = NULL;
    size_t len = 0;
    CHECK_EQ_INT(fa_store_read(dir, "device.key", &data, &len), 0);
    CHECK_EQ_STR(data, "fresh");
    free(data);
    char path[128];
    struct stat st;
    snprintf(path, sizeof path, "%s/device.key", dir);
    CHECK_EQ_INT(stat(path, &st), 0);
    CHECK_EQ_INT(st.st_mode & 0777, 0600); /* the mode moves with the file */

    CHECK_EQ_INT(fa_store_rename(dir, "missing", "device.key"), -1);
    CHECK_EQ_INT(fa_store_rename(dir, "device.key", "../device.key"), -1);
    CHECK_EQ_INT(fa_store_rename(dir, "..", "device.key"), -1);
    CHECK_EQ_INT(count_entries(dir), 1);
}

static int present(const char *dir, const char *name) {
    char path[128];
    struct stat st;
    snprintf(path, sizeof path, "%s/%s", dir, name);
    return lstat(path, &st) == 0;
}

static void store_removes_stale_temp_files(void) {
    char dir[64], own[64];
    make_dir(dir, sizeof dir);
    /* the temporary file of a write cut by a power loss: its process is gone; one with this
     * process id is from before a reboot (nothing is being written yet at start-up) */
    snprintf(own, sizeof own, ".device.json.%ld.0.tmp", (long)getpid());
    const char *stale[] = {".device.json.4194304.0.tmp", ".device.key.4194304.12.tmp", own};
    /* a write in progress in a living process (pid 1 always exists), and other files */
    const char *kept[] = {
        ".device.json.1.0.tmp", "device.json", ".hidden", "x.tmp", ".a.b.tmp", ".a.12.tmp",
        ".a.x1.0.tmp"};
    for (size_t i = 0; i < sizeof stale / sizeof stale[0]; i++)
        CHECK_EQ_INT(fa_store_write(dir, stale[i], "{", 1, 0644), 0);
    for (size_t i = 0; i < sizeof kept / sizeof kept[0]; i++)
        CHECK_EQ_INT(fa_store_write(dir, kept[i], "{", 1, 0644), 0);

    CHECK_EQ_INT(fa_store_remove_stale(dir), 3);
    for (size_t i = 0; i < sizeof stale / sizeof stale[0]; i++)
        CHECK(!present(dir, stale[i]));
    for (size_t i = 0; i < sizeof kept / sizeof kept[0]; i++)
        CHECK(present(dir, kept[i]));
    CHECK_EQ_INT(fa_store_remove_stale(dir), 0);
    CHECK_EQ_INT(fa_store_remove_stale("/nonexistent/fa-store"), -1);
}

int main(void) {
    RUN(store_write_is_atomic);
    RUN(store_mode_is_exact_whatever_the_umask);
    RUN(store_refuses_bad_names);
    RUN(store_read_missing_is_error);
    RUN(store_read_limit_is_one_mebibyte);
    RUN(store_remove_deletes_and_tolerates_missing);
    RUN(store_rename_replaces_in_one_step);
    RUN(store_removes_stale_temp_files);
    return CHECK_RESULT;
}
