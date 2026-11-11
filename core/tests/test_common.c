/* SPDX-License-Identifier: Apache-2.0 */
#include "check.h"
#include "firmline/fl_common.h"

static void test_time_parse(void) {
    fl_time t = 0;
    CHECK_EQ_INT(fl_time_parse("2027-03-10T08:00:00Z", 20, &t), FL_OK);
    CHECK(t == 1804665600);
    CHECK_EQ_INT(fl_time_parse("2027-03-10T09:00:00+01:00", 25, &t), FL_OK);
    CHECK(t == 1804665600);
    CHECK_EQ_INT(fl_time_parse("2027-03-09T20:30:00-11:30", 25, &t), FL_OK);
    CHECK(t == 1804665600);
    CHECK_EQ_INT(fl_time_parse("1970-01-01T00:00:00Z", 20, &t), FL_OK);
    CHECK(t == 0);
    CHECK_EQ_INT(fl_time_parse("2028-02-29T00:00:00Z", 20, &t), FL_OK); /* leap year */
}

static void test_time_parse_rejects(void) {
    fl_time t = 0;
    CHECK_EQ_INT(fl_time_parse("2027-02-29T00:00:00Z", 20, &t), FL_ERR_FORMAT); /* not leap */
    CHECK_EQ_INT(fl_time_parse("2100-02-29T00:00:00Z", 20, &t), FL_ERR_FORMAT); /* not leap */
    CHECK_EQ_INT(fl_time_parse("2027-03-10 08:00:00Z", 20, &t), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_time_parse("2027-13-10T08:00:00Z", 20, &t), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_time_parse("2027-04-31T08:00:00Z", 20, &t), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_time_parse("2027-03-10T24:00:00Z", 20, &t), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_time_parse("2027-03-10T08:60:00Z", 20, &t), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_time_parse("2027-03-10T08:00:60Z", 20, &t), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_time_parse("2027-03-10T08:00:00", 19, &t), FL_ERR_FORMAT); /* no offset */
    CHECK_EQ_INT(fl_time_parse("2027-03-10T08:00:00z", 20, &t), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_time_parse("2027-03-10T08:00:00+0100", 24, &t), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_time_parse("2027-03-10T08:00:00+24:00", 25, &t), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_time_parse("2027-03-10T08:00:00+01:60", 25, &t), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_time_parse("2027-03-10T08:00:00Zx", 21, &t), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_time_parse("2027-03-10T08:00:0", 17, &t), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_time_parse("2027-03-1xT08:00:00Z", 20, &t), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_time_parse("", 0, &t), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_time_parse(NULL, 20, &t), FL_ERR_ARG);
    CHECK_EQ_INT(fl_time_parse("2027-03-10T08:00:00Z", 20, NULL), FL_ERR_ARG);
}

static void test_time_format(void) {
    char s[26];
    CHECK_EQ_INT(fl_time_format(1804665600, 0, s), FL_OK);
    CHECK_EQ_STR(s, "2027-03-10T08:00:00Z");
    CHECK_EQ_INT(fl_time_format(1804665600, 60, s), FL_OK);
    CHECK_EQ_STR(s, "2027-03-10T09:00:00+01:00");
    CHECK_EQ_INT(fl_time_format(1804665600, -330, s), FL_OK);
    CHECK_EQ_STR(s, "2027-03-10T02:30:00-05:30");
    CHECK_EQ_INT(fl_time_format(0, 0, s), FL_OK);
    CHECK_EQ_STR(s, "1970-01-01T00:00:00Z");
    CHECK_EQ_INT(fl_time_format(-1, 0, s), FL_OK);
    CHECK_EQ_STR(s, "1969-12-31T23:59:59Z");
    CHECK_EQ_INT(fl_time_format(1804665600, 1440, s), FL_ERR_ARG);
    CHECK_EQ_INT(fl_time_format(300000000000LL, 0, s), FL_ERR_ARG);  /* year over 9999 */
    CHECK_EQ_INT(fl_time_format(-100000000000LL, 0, s), FL_ERR_ARG); /* year before 0 */
}

static void test_time_round_trip(void) {
    /* Times around the 2027 DST changes and a leap day: the clock is plain UTC seconds. */
    fl_time samples[] = {1804665600, 1805000000, 1806000000, 1824000000, 1835000000, 951782400};
    size_t i;
    for (i = 0; i < sizeof samples / sizeof samples[0]; i++) {
        char s[26];
        fl_time back = 0;
        CHECK_EQ_INT(fl_time_format(samples[i], 120, s), FL_OK);
        CHECK_EQ_INT(fl_time_parse(s, strlen(s), &back), FL_OK);
        CHECK(back == samples[i]);
    }
}

static void test_sha256_of_vector(void) {
    static const uint8_t expected[32] = {0xc3, 0x44, 0x86, 0x1c, 0x7d, 0xd2, 0xb9, 0xa3,
                                         0xbf, 0xaa, 0x0f, 0x5f, 0x97, 0xb8, 0x15, 0x55,
                                         0x53, 0xcf, 0xe3, 0xc8, 0xd8, 0x12, 0x8e, 0x43,
                                         0xee, 0xf4, 0x51, 0x1a, 0xb7, 0x95, 0x37, 0x2b};
    uint8_t firmware[1000], h[32];
    FILE *f = fopen(FL_VECTOR_DIR "/ota/firmware.bin", "rb");
    CHECK(f != NULL);
    if (f == NULL)
        return;
    CHECK(fread(firmware, 1, sizeof firmware, f) == sizeof firmware);
    fclose(f);
    CHECK_EQ_INT(fl_init(), FL_OK);
    CHECK_EQ_INT(fl_sha256(firmware, sizeof firmware, h), FL_OK);
    CHECK_EQ_MEM(h, expected, 32);
    CHECK_EQ_INT(fl_sha256(NULL, 1, h), FL_ERR_ARG);
    CHECK_EQ_INT(fl_sha256(firmware, 1, NULL), FL_ERR_ARG);
    /* SHA-256 of the empty input: NULL data is allowed for length 0. */
    CHECK_EQ_INT(fl_sha256(NULL, 0, h), FL_OK);
    CHECK(h[0] == 0xe3 && h[1] == 0xb0 && h[31] == 0x55);
}

int main(void) {
    RUN(test_time_parse);
    RUN(test_time_parse_rejects);
    RUN(test_time_format);
    RUN(test_time_round_trip);
    RUN(test_sha256_of_vector);
    return CHECK_RESULT;
}
