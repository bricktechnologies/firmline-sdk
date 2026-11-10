/* SPDX-License-Identifier: Apache-2.0 */
#include "firmline/fl_download.h"

#include "check.h"

#include <stdio.h>
#include <string.h>

static const uint8_t vector_sha256[32] = {
    0xc3, 0x44, 0x86, 0x1c, 0x7d, 0xd2, 0xb9, 0xa3, 0xbf, 0xaa, 0x0f, 0x5f, 0x97, 0xb8, 0x15, 0x55,
    0x53, 0xcf, 0xe3, 0xc8, 0xd8, 0x12, 0x8e, 0x43, 0xee, 0xf4, 0x51, 0x1a, 0xb7, 0x95, 0x37, 0x2b};

static uint8_t firmware[1000];
static size_t firmware_len;

static void load_firmware(void) {
    FILE *f = fopen(FL_VECTOR_DIR "/ota/firmware.bin", "rb");
    if (f != NULL) {
        firmware_len = fread(firmware, 1, sizeof firmware, f);
        fclose(f);
    }
}

static int feed(fl_download *d, const uint8_t *data, size_t len, size_t chunk) {
    size_t off = 0;
    while (off < len) {
        size_t n = len - off < chunk ? len - off : chunk;
        int rc = fl_download_update(d, data + off, n);
        if (rc != FL_OK)
            return rc;
        off += n;
    }
    return FL_OK;
}

static void download_of_the_vector_in_chunks_passes(void) {
    static const size_t chunks[] = {1, 7, 1000};
    size_t i;
    CHECK_EQ_INT(firmware_len, 1000);
    for (i = 0; i < sizeof chunks / sizeof chunks[0]; i++) {
        fl_download d;
        const char *detail = "unset";
        CHECK_EQ_INT(fl_download_begin(&d, vector_sha256, 1000), FL_OK);
        CHECK_EQ_INT(feed(&d, firmware, firmware_len, chunks[i]), FL_OK);
        CHECK_EQ_INT(fl_download_finish(&d, &detail), FL_OK);
    }
}

static void download_one_byte_more_is_size_mismatch(void) {
    fl_download d;
    const char *detail = NULL;
    uint8_t extra = 0;
    CHECK_EQ_INT(fl_download_begin(&d, vector_sha256, 1000), FL_OK);
    CHECK_EQ_INT(feed(&d, firmware, firmware_len, 100), FL_OK);
    CHECK_EQ_INT(fl_download_update(&d, &extra, 1), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_download_update(&d, &extra, 1), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_download_finish(&d, &detail), FL_ERR_FORMAT);
    CHECK_EQ_STR(detail, "size_mismatch");
    /* many bytes in one call, past the size */
    CHECK_EQ_INT(fl_download_begin(&d, vector_sha256, 10), FL_OK);
    CHECK_EQ_INT(fl_download_update(&d, firmware, 11), FL_ERR_FORMAT);
    detail = NULL;
    CHECK_EQ_INT(fl_download_finish(&d, &detail), FL_ERR_FORMAT);
    CHECK_EQ_STR(detail, "size_mismatch");
}

static void download_one_byte_less_is_size_mismatch(void) {
    fl_download d;
    const char *detail = NULL;
    CHECK_EQ_INT(fl_download_begin(&d, vector_sha256, 1000), FL_OK);
    CHECK_EQ_INT(feed(&d, firmware, firmware_len - 1, 64), FL_OK);
    CHECK_EQ_INT(fl_download_finish(&d, &detail), FL_ERR_FORMAT);
    CHECK_EQ_STR(detail, "size_mismatch");
}

static void download_altered_byte_is_hash_mismatch(void) {
    fl_download d;
    uint8_t copy[1000];
    const char *detail = NULL;
    memcpy(copy, firmware, sizeof copy);
    copy[500] ^= 1;
    CHECK_EQ_INT(fl_download_begin(&d, vector_sha256, 1000), FL_OK);
    CHECK_EQ_INT(feed(&d, copy, sizeof copy, 333), FL_OK);
    CHECK_EQ_INT(fl_download_finish(&d, &detail), FL_ERR_FORMAT);
    CHECK_EQ_STR(detail, "hash_mismatch");
}

/* Every ending leaves nothing behind: the struct serves a new download, also after an abort. */
static void download_struct_can_be_reused_after_any_ending(void) {
    fl_download d;
    const char *detail = NULL;
    uint8_t copy[1000];
    memcpy(copy, firmware, sizeof copy);
    copy[0] ^= 0x80;
    CHECK_EQ_INT(fl_download_begin(&d, vector_sha256, 1000), FL_OK);
    CHECK_EQ_INT(feed(&d, copy, sizeof copy, 1000), FL_OK);
    CHECK_EQ_INT(fl_download_finish(&d, &detail), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_download_begin(&d, vector_sha256, 1000), FL_OK);
    CHECK_EQ_INT(feed(&d, firmware, 300, 100), FL_OK);
    fl_download_abort(&d);
    fl_download_abort(&d); /* twice is harmless */
    CHECK_EQ_INT(fl_download_begin(&d, vector_sha256, 1000), FL_OK);
    CHECK_EQ_INT(feed(&d, firmware, firmware_len, 128), FL_OK);
    CHECK_EQ_INT(fl_download_finish(&d, &detail), FL_OK);
    CHECK_EQ_INT(fl_download_begin(NULL, vector_sha256, 1), FL_ERR_ARG);
    CHECK_EQ_INT(fl_download_begin(&d, NULL, 1), FL_ERR_ARG);
}

int main(void) {
    CHECK_EQ_INT(fl_init(), FL_OK);
    load_firmware();
    RUN(download_of_the_vector_in_chunks_passes);
    RUN(download_one_byte_more_is_size_mismatch);
    RUN(download_one_byte_less_is_size_mismatch);
    RUN(download_altered_byte_is_hash_mismatch);
    RUN(download_struct_can_be_reused_after_any_ending);
    return CHECK_RESULT;
}
