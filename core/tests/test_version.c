/* SPDX-License-Identifier: Apache-2.0 */
#include "check.h"
#include "firmline/fl_version.h"

static void test_numeric_order(void) {
    CHECK(fl_version_too_old("1.4.9", "1.4.10"));
    CHECK(!fl_version_too_old("1.4.10", "1.4.9"));
    CHECK(!fl_version_too_old("2.0", "1.9.9"));
    CHECK(fl_version_too_old("2.0", "2.0.1"));
}

static void test_same_version(void) {
    CHECK(fl_version_too_old("1.4.3", "1.4.3"));
    CHECK(fl_version_too_old("1.4.3+build.7", "1.4.3+BUILD.7"));
}

static void test_same_numbers_different_text(void) {
    CHECK(!fl_version_too_old("1.4.3+build.8", "1.4.3+build.7"));
}

static void test_not_numeric(void) {
    CHECK(!fl_version_too_old("beta", "alpha"));
    CHECK(fl_version_too_old("Beta", "beta"));
    CHECK(!fl_version_too_old("1.0", "beta"));
}

static void test_no_installed_version(void) { CHECK(!fl_version_too_old("1.0", NULL)); }

static void test_huge_part_is_not_numeric(void) {
    /* A part over 19 digits makes the version non-numeric: only the same text is refused. */
    CHECK(!fl_version_too_old("1.5", "1.99999999999999999999"));
    CHECK(fl_version_too_old("1.99999999999999999999", "1.99999999999999999999"));
}

int main(void) {
    RUN(test_numeric_order);
    RUN(test_same_version);
    RUN(test_same_numbers_different_text);
    RUN(test_not_numeric);
    RUN(test_no_installed_version);
    RUN(test_huge_part_is_not_numeric);
    return CHECK_RESULT;
}
