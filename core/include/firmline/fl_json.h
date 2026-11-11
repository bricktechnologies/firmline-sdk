/* SPDX-License-Identifier: Apache-2.0 */
/* JSON reading (over jsmn, no allocation) and writing (into a caller buffer). */
#ifndef FIRMLINE_FL_JSON_H
#define FIRMLINE_FL_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Only the token types are needed here: jsmn's declarations without its code. json.c includes the
 * full jsmn.h first (with JSMN_STRICT and JSMN_STATIC), so there the guard makes this a no-op. The
 * macro is undefined again so that it does not leak into the includer. */
#ifndef JSMN_H
#define JSMN_HEADER
#include "jsmn.h"
#undef JSMN_HEADER
#endif

#include "fl_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FL_JSON_MAX_TOKENS 64

/* A parsed document. It points into the text given to fl_json_parse, which must outlive it. tok is
 * the token table: j->table for fl_json_parse, the caller's for fl_json_parse_tokens. A parsed
 * fl_json is used where it was parsed, never copied (tok may point into it). */
typedef struct {
    const char *js;
    size_t len;
    int count;
    jsmntok_t *tok;
    jsmntok_t table[FL_JSON_MAX_TOKENS];
} fl_json;

/* FL_ERR_FORMAT: invalid JSON (strict), trailing bytes after the root, root not an object, a root
 * key repeated (compared unescaped; root keys over 127 bytes are refused), nesting over 4 levels
 * (the root object is level 1), more than FL_JSON_MAX_TOKENS tokens. FL_ERR_ARG: NULL argument. */
int fl_json_parse(fl_json *j, const char *js, size_t len);

/* fl_json_parse with the caller's token table of cap entries in place of j->table, for a
 * document of more than FL_JSON_MAX_TOKENS tokens (no allocation: the caller sizes it). The table
 * must outlive j. The same rules, with cap as the token limit; FL_ERR_ARG also for a NULL tok or a
 * cap of 0 or over INT_MAX. After a refusal j reads as an empty document, as with fl_json_parse. */
int fl_json_parse_tokens(fl_json *j, const char *js, size_t len, jsmntok_t *tok, size_t cap);

/* Root-level string value, unescaped (\uXXXX to UTF-8, surrogate pairs combined) and
 * NUL-terminated. FL_ERR_FORMAT: key missing, value not a string, bad escape, lone surrogate,
 * \u0000, raw control character. FL_ERR_SPACE: cap too small for the text and its NUL. */
int fl_json_string(const fl_json *j, const char *key, char *out, size_t cap);

/* Root-level integer value (no fraction or exponent) in the int64_t range. FL_ERR_FORMAT
 * otherwise. */
int fl_json_int(const fl_json *j, const char *key, int64_t *out);

/* Root-level true or false. FL_ERR_FORMAT otherwise. */
int fl_json_bool(const fl_json *j, const char *key, bool *out);

/* Root-level nested object: *first is the token index of its first key (key and value tokens
 * follow in pairs in j->tok, a value that is itself nested spans several tokens), *pairs the
 * number of pairs. FL_ERR_FORMAT if missing or not an object. */
int fl_json_object(const fl_json *j, const char *key, int *first, int *pairs);

/* Root-level array: *first is the token index of its first element, *count the number of
 * elements; the next element is at fl_json_next(j, element). FL_ERR_FORMAT if missing or not an
 * array. */
int fl_json_array(const fl_json *j, const char *key, int *first, int *count);

/* String member `key` of the object at token index `object` (the root is 0; an element of an
 * array or a nested value otherwise), unescaped as by fl_json_string; the first one when the key
 * is repeated (only root keys are checked for repeats). FL_ERR_FORMAT: index outside the table,
 * not an object, key missing, value not a string, or the escapes fl_json_string refuses.
 * FL_ERR_SPACE: cap too small. */
int fl_json_member_string(const fl_json *j, int object, const char *key, char *out, size_t cap);

/* Index of the token after the whole value at index (a nested value and all its tokens are
 * skipped), at most j->count; j->count for an index outside the table. To walk the pairs of an
 * object found with fl_json_object: i = first; then, pairs times, the key is j->tok[i], its value
 * is j->tok[i + 1], and i = fl_json_next(j, i + 1) moves to the next key. */
int fl_json_next(const fl_json *j, int index);

/* Writer of a flat or one-level-nested object into a caller buffer. After the first error nothing
 * more is written; fl_jw_end reports it. The text is NUL-terminated (cap must hold it). */
typedef struct {
    char *out;
    size_t cap;
    size_t len;
    int err;
    bool first;
} fl_jw;

void fl_jw_begin(fl_jw *w, char *out, size_t cap);
/* Escapes " and \ and control characters (below 0x20) as \uXXXX. */
void fl_jw_string(fl_jw *w, const char *key, const char *value);
void fl_jw_int(fl_jw *w, const char *key, int64_t value);
void fl_jw_object_begin(fl_jw *w, const char *key);
void fl_jw_object_end(fl_jw *w);
/* Closes the root object. The length of the text (without the NUL), or the first error:
 * FL_ERR_SPACE if the output did not fit (never cut silently), FL_ERR_ARG for a NULL argument. */
int fl_jw_end(fl_jw *w);

#ifdef __cplusplus
}
#endif

#endif
