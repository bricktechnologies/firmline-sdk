/* SPDX-License-Identifier: Apache-2.0 */
#include "firmline/fl_common.h"

#include <psa/crypto.h>
#include <stdbool.h>

int fl_init(void) { return psa_crypto_init() == PSA_SUCCESS ? FL_OK : FL_ERR_CRYPTO; }

int fl_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    static const uint8_t empty = 0;
    size_t out_len = 0;
    if (out == NULL || (data == NULL && len != 0))
        return FL_ERR_ARG;
    if (data == NULL)
        data = &empty;
    if (psa_hash_compute(PSA_ALG_SHA_256, data, len, out, 32, &out_len) != PSA_SUCCESS ||
        out_len != 32)
        return FL_ERR_CRYPTO;
    return FL_OK;
}

/* Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's days_from_civil). */
static int64_t days_from_civil(int64_t y, int m, int d) {
    int64_t era, yoe, doy, doe;
    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* Inverse of days_from_civil (civil_from_days). */
static void civil_from_days(int64_t z, int64_t *y, int *m, int *d) {
    int64_t era, doe, yoe, doy, mp;
    z += 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = z - era * 146097;
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    *d = (int)(doy - (153 * mp + 2) / 5 + 1);
    *m = (int)(mp < 10 ? mp + 3 : mp - 9);
    *y = yoe + era * 400 + (*m <= 2);
}

static bool is_leap(int y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }

static int days_in_month(int y, int m) {
    static const int days[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return m == 2 && is_leap(y) ? 29 : days[m - 1];
}

/* Reads exactly `n` ASCII digits at s; -1 if any is not a digit. */
static int digits(const char *s, int n) {
    int v = 0, i;
    for (i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return -1;
        v = v * 10 + (s[i] - '0');
    }
    return v;
}

int fl_time_parse(const char *iso, size_t len, fl_time *out) {
    int year, month, day, hour, minute, second, offset = 0;
    if (iso == NULL || out == NULL)
        return FL_ERR_ARG;
    /* "YYYY-MM-DDThh:mm:ss" (19 characters), then "Z" (20 in all) or "+hh:mm" (25 in all). */
    if (len != 20 && len != 25)
        return FL_ERR_FORMAT;
    if (iso[4] != '-' || iso[7] != '-' || iso[10] != 'T' || iso[13] != ':' || iso[16] != ':')
        return FL_ERR_FORMAT;
    year = digits(iso, 4);
    month = digits(iso + 5, 2);
    day = digits(iso + 8, 2);
    hour = digits(iso + 11, 2);
    minute = digits(iso + 14, 2);
    second = digits(iso + 17, 2);
    if (year < 0 || month < 1 || month > 12 || day < 1 || hour < 0 || hour > 23 || minute < 0 ||
        minute > 59 || second < 0 || second > 59)
        return FL_ERR_FORMAT;
    if (day > days_in_month(year, month))
        return FL_ERR_FORMAT;
    if (len == 20) {
        if (iso[19] != 'Z')
            return FL_ERR_FORMAT;
    } else {
        int oh, om;
        if ((iso[19] != '+' && iso[19] != '-') || iso[22] != ':')
            return FL_ERR_FORMAT;
        oh = digits(iso + 20, 2);
        om = digits(iso + 23, 2);
        if (oh < 0 || oh > 23 || om < 0 || om > 59)
            return FL_ERR_FORMAT;
        offset = oh * 60 + om;
        if (iso[19] == '-')
            offset = -offset;
    }
    *out = days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second -
           (fl_time)offset * 60;
    return FL_OK;
}

/* Writes v as exactly n decimal digits (0 <= v < 10^n) and returns the position after them. */
static char *put_digits(char *p, int v, int n) {
    int i;
    for (i = n - 1; i >= 0; i--) {
        p[i] = (char)('0' + v % 10);
        v /= 10;
    }
    return p + n;
}

int fl_time_format(fl_time t, int offset_minutes, char out[26]) {
    int64_t days, secs, year;
    int month, day, o;
    char *p = out;
    if (out == NULL || offset_minutes < -1439 || offset_minutes > 1439)
        return FL_ERR_ARG;
    /* Reject far-away times first, so the arithmetic below cannot overflow. */
    if (t < -62167219200LL - 172800LL || t > 253402300799LL + 172800LL)
        return FL_ERR_ARG;
    t += (fl_time)offset_minutes * 60;
    days = t >= 0 ? t / 86400 : -((-t + 86399) / 86400);
    secs = t - days * 86400;
    civil_from_days(days, &year, &month, &day);
    if (year < 0 || year > 9999)
        return FL_ERR_ARG;
    p = put_digits(p, (int)year, 4);
    *p++ = '-';
    p = put_digits(p, month, 2);
    *p++ = '-';
    p = put_digits(p, day, 2);
    *p++ = 'T';
    p = put_digits(p, (int)(secs / 3600), 2);
    *p++ = ':';
    p = put_digits(p, (int)(secs / 60 % 60), 2);
    *p++ = ':';
    p = put_digits(p, (int)(secs % 60), 2);
    if (offset_minutes == 0) {
        *p++ = 'Z';
    } else {
        o = offset_minutes < 0 ? -offset_minutes : offset_minutes;
        *p++ = offset_minutes < 0 ? '-' : '+';
        p = put_digits(p, o / 60, 2);
        *p++ = ':';
        p = put_digits(p, o % 60, 2);
    }
    *p = '\0';
    return FL_OK;
}
