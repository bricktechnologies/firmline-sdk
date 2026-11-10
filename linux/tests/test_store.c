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

int main(void) {
    RUN(store_write_is_atomic);
    RUN(store_refuses_bad_names);
    RUN(store_read_missing_is_error);
    RUN(store_read_limit_is_one_mebibyte);
    RUN(store_remove_deletes_and_tolerates_missing);
    return CHECK_RESULT;
}
