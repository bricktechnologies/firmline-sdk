/* SPDX-License-Identifier: Apache-2.0 */
/* jsmn is compiled here only, strict and static; it must come before fl_json.h. */
#define JSMN_STRICT
#define JSMN_STATIC
#include "jsmn.h"

#include "firmline/fl_json.h"

#include <limits.h>
#include <string.h>

#define MAX_DEPTH 4
#define MAX_KEY_BYTES 127

/* ---- reading ---------------------------------------------------------------------------- */

static int hex4(const char *s, unsigned *out) {
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = s[i];
        unsigned d;
        if (c >= '0' && c <= '9')
            d = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            d = (unsigned)(c - 'a') + 10;
        else if (c >= 'A' && c <= 'F')
            d = (unsigned)(c - 'A') + 10;
        else
            return FL_ERR_FORMAT;
        v = v * 16 + d;
    }
    *out = v;
    return FL_OK;
}

static int put_byte(char *out, size_t cap, size_t *len, unsigned b) {
    if (*len >= cap)
        return FL_ERR_SPACE;
    out[(*len)++] = (char)b;
    return FL_OK;
}

static int put_utf8(char *out, size_t cap, size_t *len, unsigned cp) {
    unsigned bytes[4];
    int n;
    if (cp < 0x80) {
        bytes[0] = cp;
        n = 1;
    } else if (cp < 0x800) {
        bytes[0] = 0xC0 | (cp >> 6);
        bytes[1] = 0x80 | (cp & 0x3F);
        n = 2;
    } else if (cp < 0x10000) {
        bytes[0] = 0xE0 | (cp >> 12);
        bytes[1] = 0x80 | ((cp >> 6) & 0x3F);
        bytes[2] = 0x80 | (cp & 0x3F);
        n = 3;
    } else {
        bytes[0] = 0xF0 | (cp >> 18);
        bytes[1] = 0x80 | ((cp >> 12) & 0x3F);
        bytes[2] = 0x80 | ((cp >> 6) & 0x3F);
        bytes[3] = 0x80 | (cp & 0x3F);
        n = 4;
    }
    for (int i = 0; i < n; i++) {
        int rc = put_byte(out, cap, len, bytes[i]);
        if (rc != FL_OK)
            return rc;
    }
    return FL_OK;
}

/* Decodes the escape sequence after a backslash; s[*i] is the character after it. */
static int unescape_one(const char *s, size_t n, size_t *i, char *out, size_t cap, size_t *len) {
    char e = s[(*i)++];
    unsigned cp;
    switch (e) {
    case '"':
    case '\\':
    case '/':
        return put_byte(out, cap, len, (unsigned char)e);
    case 'b':
        return put_byte(out, cap, len, '\b');
    case 'f':
        return put_byte(out, cap, len, '\f');
    case 'n':
        return put_byte(out, cap, len, '\n');
    case 'r':
        return put_byte(out, cap, len, '\r');
    case 't':
        return put_byte(out, cap, len, '\t');
    case 'u':
        break;
    default:
        return FL_ERR_FORMAT;
    }
    if (*i + 4 > n || hex4(s + *i, &cp) != FL_OK)
        return FL_ERR_FORMAT;
    *i += 4;
    if (cp >= 0xD800 && cp <= 0xDBFF) {
        unsigned lo;
        if (*i + 6 > n || s[*i] != '\\' || s[*i + 1] != 'u' || hex4(s + *i + 2, &lo) != FL_OK ||
            lo < 0xDC00 || lo > 0xDFFF)
            return FL_ERR_FORMAT;
        *i += 6;
        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
    } else if ((cp >= 0xDC00 && cp <= 0xDFFF) || cp == 0) {
        return FL_ERR_FORMAT;
    }
    return put_utf8(out, cap, len, cp);
}

/* Unescapes the string body s[0..n) into out (no NUL written). FL_ERR_FORMAT for a bad escape, a
 * lone surrogate, \u0000 or a raw control character; FL_ERR_SPACE if more than cap bytes. */
static int unescape(const char *s, size_t n, char *out, size_t cap, size_t *outlen) {
    size_t len = 0;
    size_t i = 0;
    while (i < n) {
        unsigned char c = (unsigned char)s[i++];
        int rc;
        if (c < 0x20)
            return FL_ERR_FORMAT;
        if (c != '\\')
            rc = put_byte(out, cap, &len, c);
        else if (i >= n)
            return FL_ERR_FORMAT;
        else
            rc = unescape_one(s, n, &i, out, cap, &len);
        if (rc != FL_OK)
            return rc;
    }
    *outlen = len;
    return FL_OK;
}

static int unescape_token(const fl_json *j, int i, char *out, size_t cap, size_t *len) {
    const jsmntok_t *t = &j->tok[i];
    return unescape(j->js + t->start, (size_t)(t->end - t->start), out, cap, len);
}

static bool key_matches(const fl_json *j, int i, const char *key) {
    char buf[MAX_KEY_BYTES + 1];
    size_t len;
    if (unescape_token(j, i, buf, MAX_KEY_BYTES, &len) != FL_OK)
        return false;
    return len == strlen(key) && memcmp(buf, key, len) == 0;
}

/* Index of the token after the value at v (v and everything inside it are skipped). */
static int after_value(const fl_json *j, int v) {
    int n = v + 1;
    while (n < j->count && j->tok[n].start < j->tok[v].end)
        n++;
    return n;
}

/* Token index of the root value of key, or -1. */
static int find_value(const fl_json *j, const char *key) {
    int i = 1;
    for (int p = 0; p < j->tok[0].size && i + 1 < j->count; p++) {
        if (key_matches(j, i, key))
            return i + 1;
        i = after_value(j, i + 1);
    }
    return -1;
}

static int check_depth(const fl_json *j) {
    int ends[MAX_DEPTH];
    int sp = 0;
    for (int i = 0; i < j->count; i++) {
        const jsmntok_t *t = &j->tok[i];
        while (sp > 0 && ends[sp - 1] <= t->start)
            sp--;
        if (t->type == JSMN_OBJECT || t->type == JSMN_ARRAY) {
            if (sp == MAX_DEPTH)
                return FL_ERR_FORMAT;
            ends[sp++] = t->end;
        }
    }
    return FL_OK;
}

/* Every root key must be readable (valid escapes, short enough) and appear once. */
static int check_root_keys(const fl_json *j) {
    char first[MAX_KEY_BYTES + 1], other[MAX_KEY_BYTES + 1];
    int a = 1;
    for (int p = 0; p < j->tok[0].size; p++) {
        size_t alen;
        int b;
        if (a + 1 >= j->count)
            return FL_ERR_FORMAT;
        b = after_value(j, a + 1);
        if (unescape_token(j, a, first, MAX_KEY_BYTES, &alen) != FL_OK)
            return FL_ERR_FORMAT;
        for (int q = p + 1; q < j->tok[0].size; q++) {
            size_t blen;
            if (b + 1 >= j->count)
                return FL_ERR_FORMAT;
            if (unescape_token(j, b, other, MAX_KEY_BYTES, &blen) != FL_OK)
                return FL_ERR_FORMAT;
            if (alen == blen && memcmp(first, other, alen) == 0)
                return FL_ERR_FORMAT;
            b = after_value(j, b + 1);
        }
        a = after_value(j, a + 1);
    }
    return FL_OK;
}

static bool is_digit(char c) { return c >= '0' && c <= '9'; }

/* RFC 8259: true, false, null, or -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)? */
static bool primitive_is_valid(const char *s, size_t n) {
    size_t i = 0;
    if ((n == 4 && memcmp(s, "true", 4) == 0) || (n == 5 && memcmp(s, "false", 5) == 0) ||
        (n == 4 && memcmp(s, "null", 4) == 0))
        return true;
    if (i < n && s[i] == '-')
        i++;
    if (i >= n || !is_digit(s[i]))
        return false;
    if (s[i] == '0')
        i++;
    else
        while (i < n && is_digit(s[i]))
            i++;
    if (i < n && s[i] == '.') {
        i++;
        if (i >= n || !is_digit(s[i]))
            return false;
        while (i < n && is_digit(s[i]))
            i++;
    }
    if (i < n && (s[i] == 'e' || s[i] == 'E')) {
        i++;
        if (i < n && (s[i] == '+' || s[i] == '-'))
            i++;
        if (i >= n || !is_digit(s[i]))
            return false;
        while (i < n && is_digit(s[i]))
            i++;
    }
    return i == n;
}

/* Extent of a token in the text including the quotes of a string. */
static int tok_begin(const jsmntok_t *t) {
    return t->type == JSMN_STRING ? t->start - 1 : t->start;
}
static int tok_end(const jsmntok_t *t) { return t->type == JSMN_STRING ? t->end + 1 : t->end; }

/* True if js[from..to) is white space and, when sep is not 0, exactly one sep. */
static bool gap_ok(const fl_json *j, int from, int to, int sep) {
    int seps = 0;
    if (from < 0 || to < from || (size_t)to > j->len)
        return false;
    for (int i = from; i < to; i++) {
        char c = j->js[i];
        if (sep != 0 && c == sep)
            seps++;
        else if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
            return false;
    }
    return seps == (sep != 0 ? 1 : 0);
}

/* Walks the value at token i the way a reader will: objects are string keys each followed by one
 * value, sizes must match the walk, every index stays below count, primitives follow RFC 8259.
 * Sets *next to the index after the value. Recursion is bounded by check_depth. */
static int validate_value(const fl_json *j, int i, int *next) {
    const jsmntok_t *t;
    int k;
    if (i < 0 || i >= j->count)
        return FL_ERR_FORMAT;
    t = &j->tok[i];
    if (t->start < 0 || t->end < t->start || (size_t)t->end > j->len)
        return FL_ERR_FORMAT;
    k = i + 1;
    switch (t->type) {
    case JSMN_STRING:
        break;
    case JSMN_PRIMITIVE:
        if (!primitive_is_valid(j->js + t->start, (size_t)(t->end - t->start)))
            return FL_ERR_FORMAT;
        break;
    case JSMN_OBJECT:
    case JSMN_ARRAY: {
        int cursor = t->start + 1; /* just after the opening bracket */
        for (int p = 0; p < t->size; p++) {
            int sep = p > 0 ? ',' : 0;
            int v;
            if (t->type == JSMN_OBJECT) {
                if (k >= j->count || j->tok[k].type != JSMN_STRING)
                    return FL_ERR_FORMAT;
                if (!gap_ok(j, cursor, tok_begin(&j->tok[k]), sep))
                    return FL_ERR_FORMAT;
                cursor = tok_end(&j->tok[k]);
                k++;
                sep = ':';
            }
            v = k;
            if (v >= j->count || !gap_ok(j, cursor, tok_begin(&j->tok[v]), sep))
                return FL_ERR_FORMAT;
            if (validate_value(j, v, &k) != FL_OK)
                return FL_ERR_FORMAT;
            cursor = tok_end(&j->tok[v]);
        }
        if (!gap_ok(j, cursor, t->end - 1, 0)) /* no trailing comma */
            return FL_ERR_FORMAT;
        break;
    }
    default:
        return FL_ERR_FORMAT;
    }
    /* the tokens walked are exactly those inside the value */
    for (int m = i + 1; m < k; m++)
        if (j->tok[m].start < t->start || j->tok[m].end > t->end)
            return FL_ERR_FORMAT;
    if (k < j->count && j->tok[k].start < t->end)
        return FL_ERR_FORMAT;
    *next = k;
    return FL_OK;
}

static int check_structure(const fl_json *j) {
    int next = 0;
    if (validate_value(j, 0, &next) != FL_OK || next != j->count)
        return FL_ERR_FORMAT;
    return FL_OK;
}

int fl_json_parse(fl_json *j, const char *js, size_t len) {
    jsmn_parser parser;
    int n;
    if (j == NULL || js == NULL)
        return FL_ERR_ARG;
    memset(j, 0, sizeof *j);
    if (len == 0 || len > (size_t)INT_MAX)
        return FL_ERR_FORMAT;
    jsmn_init(&parser);
    n = jsmn_parse(&parser, js, len, j->tok, FL_JSON_MAX_TOKENS);
    if (n < 1 || j->tok[0].type != JSMN_OBJECT)
        return FL_ERR_FORMAT;
    for (size_t i = (size_t)j->tok[0].end; i < len; i++) {
        char c = js[i];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
            return FL_ERR_FORMAT; /* a second value, a NUL, or other trailing bytes */
    }
    j->js = js;
    j->len = len;
    j->count = n;
    if (check_depth(j) != FL_OK || check_structure(j) != FL_OK || check_root_keys(j) != FL_OK) {
        memset(j, 0, sizeof *j);
        return FL_ERR_FORMAT;
    }
    return FL_OK;
}

int fl_json_string(const fl_json *j, const char *key, char *out, size_t cap) {
    size_t len;
    int v, rc;
    if (j == NULL || key == NULL || out == NULL || cap == 0)
        return FL_ERR_ARG;
    v = find_value(j, key);
    if (v < 0 || j->tok[v].type != JSMN_STRING)
        return FL_ERR_FORMAT;
    rc = unescape_token(j, v, out, cap - 1, &len);
    if (rc != FL_OK)
        return rc;
    out[len] = '\0';
    return FL_OK;
}

int fl_json_int(const fl_json *j, const char *key, int64_t *out) {
    int v;
    const char *s;
    size_t n, i = 0;
    bool neg = false;
    uint64_t mag = 0;
    if (j == NULL || key == NULL || out == NULL)
        return FL_ERR_ARG;
    v = find_value(j, key);
    if (v < 0 || j->tok[v].type != JSMN_PRIMITIVE)
        return FL_ERR_FORMAT;
    s = j->js + j->tok[v].start;
    n = (size_t)(j->tok[v].end - j->tok[v].start);
    if (n > 0 && s[0] == '-') {
        neg = true;
        i = 1;
    }
    if (i >= n || (s[i] == '0' && n - i > 1))
        return FL_ERR_FORMAT;
    for (; i < n; i++) {
        uint64_t d;
        if (!is_digit(s[i]))
            return FL_ERR_FORMAT;
        d = (uint64_t)(s[i] - '0');
        if (mag > (UINT64_MAX - d) / 10)
            return FL_ERR_FORMAT;
        mag = mag * 10 + d;
    }
    if (neg ? mag > (uint64_t)INT64_MAX + 1 : mag > (uint64_t)INT64_MAX)
        return FL_ERR_FORMAT;
    *out = neg ? (int64_t)(0 - mag) : (int64_t)mag;
    return FL_OK;
}

int fl_json_bool(const fl_json *j, const char *key, bool *out) {
    int v;
    const char *s;
    size_t n;
    if (j == NULL || key == NULL || out == NULL)
        return FL_ERR_ARG;
    v = find_value(j, key);
    if (v < 0 || j->tok[v].type != JSMN_PRIMITIVE)
        return FL_ERR_FORMAT;
    s = j->js + j->tok[v].start;
    n = (size_t)(j->tok[v].end - j->tok[v].start);
    if (n == 4 && memcmp(s, "true", 4) == 0)
        *out = true;
    else if (n == 5 && memcmp(s, "false", 5) == 0)
        *out = false;
    else
        return FL_ERR_FORMAT;
    return FL_OK;
}

int fl_json_object(const fl_json *j, const char *key, int *first, int *pairs) {
    int v;
    if (j == NULL || key == NULL || first == NULL || pairs == NULL)
        return FL_ERR_ARG;
    v = find_value(j, key);
    if (v < 0 || j->tok[v].type != JSMN_OBJECT)
        return FL_ERR_FORMAT;
    *first = v + 1;
    *pairs = j->tok[v].size;
    return FL_OK;
}

/* ---- writing ---------------------------------------------------------------------------- */

static void jw_put(fl_jw *w, char c) {
    if (w->err != FL_OK)
        return;
    if (w->len + 1 >= w->cap) { /* keep one byte for the NUL */
        w->err = FL_ERR_SPACE;
        return;
    }
    w->out[w->len++] = c;
    w->out[w->len] = '\0';
}

static void jw_text(fl_jw *w, const char *s) {
    for (; *s != '\0'; s++)
        jw_put(w, *s);
}

static void jw_quoted(fl_jw *w, const char *s) {
    static const char hex[] = "0123456789abcdef";
    jw_put(w, '"');
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            jw_put(w, '\\');
            jw_put(w, (char)c);
        } else if (c < 0x20) {
            jw_text(w, "\\u00");
            jw_put(w, hex[c >> 4]);
            jw_put(w, hex[c & 0xF]);
        } else {
            jw_put(w, (char)c);
        }
    }
    jw_put(w, '"');
}

static void jw_key(fl_jw *w, const char *key) {
    if (key == NULL) {
        if (w->err == FL_OK)
            w->err = FL_ERR_ARG;
        return;
    }
    if (!w->first)
        jw_put(w, ',');
    w->first = false;
    jw_quoted(w, key);
    jw_put(w, ':');
}

void fl_jw_begin(fl_jw *w, char *out, size_t cap) {
    w->out = out;
    w->cap = cap;
    w->len = 0;
    w->err = FL_OK;
    w->first = true;
    if (out == NULL || cap == 0) {
        w->err = out == NULL ? FL_ERR_ARG : FL_ERR_SPACE;
        return;
    }
    out[0] = '\0';
    jw_put(w, '{');
}

void fl_jw_string(fl_jw *w, const char *key, const char *value) {
    jw_key(w, key);
    if (value == NULL) {
        if (w->err == FL_OK)
            w->err = FL_ERR_ARG;
        return;
    }
    jw_quoted(w, value);
}

void fl_jw_int(fl_jw *w, const char *key, int64_t value) {
    char digits[21];
    int n = 0;
    uint64_t mag = value < 0 ? 0 - (uint64_t)value : (uint64_t)value;
    jw_key(w, key);
    do {
        digits[n++] = (char)('0' + mag % 10);
        mag /= 10;
    } while (mag != 0);
    if (value < 0)
        jw_put(w, '-');
    while (n > 0)
        jw_put(w, digits[--n]);
}

void fl_jw_object_begin(fl_jw *w, const char *key) {
    jw_key(w, key);
    jw_put(w, '{');
    w->first = true;
}

void fl_jw_object_end(fl_jw *w) {
    jw_put(w, '}');
    w->first = false;
}

int fl_jw_end(fl_jw *w) {
    jw_put(w, '}');
    if (w->err != FL_OK)
        return w->err;
    return (int)w->len;
}

int fl_json_next(const fl_json *j, int index) {
    if (j == NULL || index < 0 || index >= j->count)
        return j == NULL ? 0 : j->count;
    return after_value(j, index);
}
