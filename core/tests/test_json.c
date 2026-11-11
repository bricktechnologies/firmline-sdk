/* SPDX-License-Identifier: Apache-2.0 */
#include "firmline/fl_json.h"

#include "check.h"

#include <stdio.h>
#include <string.h>

#define PARSE(j, text) fl_json_parse(&(j), (text), strlen(text))

static void json_reads_the_manifest_of_the_vector(void) {
    static char text[1024];
    fl_json j;
    char s[128];
    int64_t n = 0;
    bool b = true;
    FILE *f = fopen(FL_VECTOR_DIR "/ota/manifest.json", "rb");
    size_t len = 0;
    CHECK(f != NULL);
    if (f == NULL)
        return;
    len = fread(text, 1, sizeof text, f);
    fclose(f);
    CHECK_EQ_INT(fl_json_parse(&j, text, len), FL_OK);
    CHECK_EQ_INT(j.count, 23);

    CHECK_EQ_INT(fl_json_int(&j, "v", &n), FL_OK);
    CHECK_EQ_INT(n, 1);
    CHECK_EQ_INT(fl_json_string(&j, "release", s, sizeof s), FL_OK);
    CHECK_EQ_STR(s, "8c1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b");
    CHECK_EQ_INT(fl_json_string(&j, "tenant", s, sizeof s), FL_OK);
    CHECK_EQ_STR(s, "11111111-2222-4333-8444-555555555555");
    CHECK_EQ_INT(fl_json_string(&j, "family", s, sizeof s), FL_OK);
    CHECK_EQ_STR(s, "66666666-7777-4888-9999-aaaaaaaaaaaa");
    CHECK_EQ_INT(fl_json_string(&j, "component", s, sizeof s), FL_OK);
    CHECK_EQ_STR(s, "firmware");
    CHECK_EQ_INT(fl_json_string(&j, "kid", s, sizeof s), FL_OK);
    CHECK_EQ_STR(s, "70203f39f1a767927b55ac11efeab380e9b452dd5dff073807eb1ee82d7dc623");
    CHECK_EQ_INT(fl_json_string(&j, "version", s, sizeof s), FL_OK);
    CHECK_EQ_STR(s, "1.4.3+build.7");
    CHECK_EQ_INT(fl_json_string(&j, "sha256", s, sizeof s), FL_OK);
    CHECK_EQ_STR(s, "c344861c7dd2b9a3bfaa0f5f97b8155553cfe3c8d8128e43eef4511ab795372b");
    CHECK_EQ_INT(fl_json_int(&j, "size", &n), FL_OK);
    CHECK_EQ_INT(n, 1000);
    CHECK_EQ_INT(fl_json_string(&j, "notBefore", s, sizeof s), FL_OK);
    CHECK_EQ_STR(s, "2027-03-25T00:00:00Z");
    CHECK_EQ_INT(fl_json_bool(&j, "rollback", &b), FL_OK);
    CHECK(!b);

    /* wrong type or missing key */
    CHECK_EQ_INT(fl_json_int(&j, "version", &n), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_string(&j, "v", s, sizeof s), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_string(&j, "absent", s, sizeof s), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_bool(&j, "v", &b), FL_ERR_FORMAT);
}

static void json_refuses_repeated_root_key(void) {
    fl_json j;
    CHECK_EQ_INT(PARSE(j, "{\"v\":1,\"v\":2}"), FL_ERR_FORMAT);
    CHECK_EQ_INT(PARSE(j, "{\"v\":1,\"\\u0076\":2}"), FL_ERR_FORMAT); /* same key, escaped */
    CHECK_EQ_INT(PARSE(j, "{\"v\":1,\"w\":{\"v\":2}}"), FL_OK);       /* nested is not the root */
}

static void json_refuses_nesting_over_four_levels(void) {
    fl_json j;
    CHECK_EQ_INT(PARSE(j, "{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":1}}}}}"),
                 FL_ERR_FORMAT);                                            /* 5 levels */
    CHECK_EQ_INT(PARSE(j, "{\"a\":{\"b\":{\"c\":{\"d\":1}}}}"), FL_OK);     /* 4 levels */
    CHECK_EQ_INT(PARSE(j, "{\"a\":{\"b\":{\"c\":1}}}"), FL_OK);             /* 3 levels */
    CHECK_EQ_INT(PARSE(j, "{\"a\":{\"b\":{\"c\":[1]}}}"), FL_OK);           /* 4 levels */
    CHECK_EQ_INT(PARSE(j, "{\"a\":{\"b\":{\"c\":[[1]]}}}"), FL_ERR_FORMAT); /* 5 levels */
}

static void json_refuses_invalid_documents(void) {
    fl_json j;
    CHECK_EQ_INT(PARSE(j, ""), FL_ERR_FORMAT);
    CHECK_EQ_INT(PARSE(j, "[1]"), FL_ERR_FORMAT);
    CHECK_EQ_INT(PARSE(j, "\"x\""), FL_ERR_FORMAT);
    CHECK_EQ_INT(PARSE(j, "{\"a\":1"), FL_ERR_FORMAT);
    CHECK_EQ_INT(PARSE(j, "{a:1}"), FL_ERR_FORMAT);
    CHECK_EQ_INT(PARSE(j, "{\"a\":1} x"), FL_ERR_FORMAT);
    CHECK_EQ_INT(PARSE(j, "{\"a\":1}{\"b\":2}"), FL_ERR_FORMAT);
    CHECK_EQ_INT(PARSE(j, " {\"a\":1}\n"), FL_OK);
    CHECK_EQ_INT(fl_json_parse(&j, "{\"a\":1}\0x", 9), FL_ERR_FORMAT); /* NUL then bytes */
    CHECK_EQ_INT(fl_json_parse(NULL, "{}", 2), FL_ERR_ARG);
}

static void json_refuses_more_tokens_than_the_table(void) {
    char text[512];
    fl_json j;
    size_t n = 0;
    int i;
    text[n++] = '{';
    for (i = 0; i < 40; i++) /* 1 + 40 * 2 tokens */
        n += (size_t)snprintf(text + n, sizeof text - n, "%s\"k%d\":%d", i ? "," : "", i, i);
    text[n++] = '}';
    CHECK_EQ_INT(fl_json_parse(&j, text, n), FL_ERR_FORMAT);
    n = 0;
    text[n++] = '{';
    for (i = 0; i < 31; i++) /* 1 + 31 * 2 = 63 tokens */
        n += (size_t)snprintf(text + n, sizeof text - n, "%s\"k%d\":%d", i ? "," : "", i, i);
    text[n++] = '}';
    CHECK_EQ_INT(fl_json_parse(&j, text, n), FL_OK);
}

static void json_unescapes_pem_newlines(void) {
    fl_json j;
    char s[16];
    CHECK_EQ_INT(PARSE(j, "{\"p\":\"a\\nb\"}"), FL_OK);
    CHECK_EQ_INT(fl_json_string(&j, "p", s, sizeof s), FL_OK);
    CHECK_EQ_INT(strlen(s), 3);
    CHECK_EQ_MEM(s, "a\nb", 4);
}

static void json_decodes_unicode_escapes(void) {
    fl_json j;
    char s[16];
    CHECK_EQ_INT(PARSE(j, "{\"p\":\"\\u00e8\\u20ac\\ud83d\\ude00\\\"\\\\\\/\"}"), FL_OK);
    CHECK_EQ_INT(fl_json_string(&j, "p", s, sizeof s), FL_OK);
    CHECK_EQ_STR(s, "\xC3\xA8\xE2\x82\xAC\xF0\x9F\x98\x80\"\\/");

    CHECK_EQ_INT(PARSE(j, "{\"p\":\"\\ud83d\"}"), FL_OK); /* lone high surrogate */
    CHECK_EQ_INT(fl_json_string(&j, "p", s, sizeof s), FL_ERR_FORMAT);
    CHECK_EQ_INT(PARSE(j, "{\"p\":\"\\ud83dx\"}"), FL_OK);
    CHECK_EQ_INT(fl_json_string(&j, "p", s, sizeof s), FL_ERR_FORMAT);
    CHECK_EQ_INT(PARSE(j, "{\"p\":\"\\ude00\"}"), FL_OK); /* lone low surrogate */
    CHECK_EQ_INT(fl_json_string(&j, "p", s, sizeof s), FL_ERR_FORMAT);
    CHECK_EQ_INT(PARSE(j, "{\"p\":\"\\ud83d\\u0041\"}"), FL_OK); /* high + non-low */
    CHECK_EQ_INT(fl_json_string(&j, "p", s, sizeof s), FL_ERR_FORMAT);
    CHECK_EQ_INT(PARSE(j, "{\"p\":\"a\\u0000b\"}"), FL_OK);
    CHECK_EQ_INT(fl_json_string(&j, "p", s, sizeof s), FL_ERR_FORMAT);
    CHECK_EQ_INT(PARSE(j, "{\"p\":\"\\x\"}"), FL_ERR_FORMAT); /* jsmn refuses */
    CHECK_EQ_INT(PARSE(j, "{\"p\":\"a\tb\"}"), FL_OK);        /* raw control character */
    CHECK_EQ_INT(fl_json_string(&j, "p", s, sizeof s), FL_ERR_FORMAT);
}

static void json_string_too_long_is_space_error(void) {
    fl_json j;
    char s[4];
    CHECK_EQ_INT(PARSE(j, "{\"p\":\"abc\"}"), FL_OK);
    CHECK_EQ_INT(fl_json_string(&j, "p", s, 4), FL_OK);
    CHECK_EQ_STR(s, "abc");
    CHECK_EQ_INT(fl_json_string(&j, "p", s, 3), FL_ERR_SPACE); /* no room for the NUL */
    CHECK_EQ_INT(fl_json_string(&j, "p", s, 1), FL_ERR_SPACE);
}

static void json_reads_integers_strictly(void) {
    fl_json j;
    int64_t n = 7;
    CHECK_EQ_INT(PARSE(j, "{\"a\":-5,\"b\":9223372036854775807,\"c\":-9223372036854775808}"),
                 FL_OK);
    CHECK_EQ_INT(fl_json_int(&j, "a", &n), FL_OK);
    CHECK_EQ_INT(n, -5);
    CHECK_EQ_INT(fl_json_int(&j, "b", &n), FL_OK);
    CHECK(n == INT64_MAX);
    CHECK_EQ_INT(fl_json_int(&j, "c", &n), FL_OK);
    CHECK(n == INT64_MIN);
    CHECK_EQ_INT(PARSE(j, "{\"a\":9223372036854775808}"), FL_OK);
    CHECK_EQ_INT(fl_json_int(&j, "a", &n), FL_ERR_FORMAT);
    /* valid JSON, but not integers */
    CHECK_EQ_INT(PARSE(j, "{\"a\":1.5,\"b\":1e3,\"e\":true,\"f\":null,\"g\":-0.5E+2}"), FL_OK);
    CHECK_EQ_INT(fl_json_int(&j, "a", &n), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_int(&j, "b", &n), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_int(&j, "e", &n), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_int(&j, "f", &n), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_int(&j, "g", &n), FL_ERR_FORMAT);
}

static void json_refuses_malformed_primitives(void) {
    static const char *const bad[] = {
        "{\"a\":tru}", "{\"a\":1.}",    "{\"a\":-}",     "{\"a\":1e}",  "{\"a\":01}",
        "{\"a\":.5}",  "{\"a\":+1}",    "{\"a\":1e+}",   "{\"a\":nul}", "{\"a\":True}",
        "{\"a\":--1}", "{\"a\":1.2.3}", "{\"a\":truee}",
    };
    fl_json j;
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        int rc = fl_json_parse(&j, bad[i], strlen(bad[i]));
        if (rc != FL_ERR_FORMAT)
            fprintf(stderr, "not refused: %s\n", bad[i]);
        CHECK_EQ_INT(rc, FL_ERR_FORMAT);
    }
}

static void json_refuses_broken_structure(void) {
    static const char *const bad[] = {
        "{\"v\":1 \"v\":2}",     /* missing comma hides a repeated key */
        "{\"a\":1 \"b\":2}",     /* missing comma */
        "{\"a\":,\"b\":1}",      /* missing value */
        "{\"a\":}",              /* missing value */
        "{\"a\"}",               /* key without value */
        "{\"a\":1,}",            /* trailing comma */
        "{\"a\":[1 2]}",         /* missing comma in array */
        "{\"a\":{\"b\" \"c\"}}", /* nested key without value */
        "{1:2}",                 /* key not a string */
    };
    fl_json j;
    char text[1024];
    size_t n = 0;
    int i;
    for (size_t k = 0; k < sizeof bad / sizeof bad[0]; k++) {
        int rc = fl_json_parse(&j, bad[k], strlen(bad[k]));
        if (rc != FL_ERR_FORMAT)
            fprintf(stderr, "not refused: %s\n", bad[k]);
        CHECK_EQ_INT(rc, FL_ERR_FORMAT);
    }
    /* 63 keys without values: 64 tokens, root size 63, used to read past the table */
    text[n++] = '{';
    for (i = 0; i < 63; i++)
        n += (size_t)snprintf(text + n, sizeof text - n, "%s\"k%d\":", i ? "," : "", i);
    text[n++] = '}';
    CHECK_EQ_INT(fl_json_parse(&j, text, n), FL_ERR_FORMAT);
    /* same, one value-less key last */
    CHECK_EQ_INT(PARSE(j, "{\"a\":1,\"b\":}"), FL_ERR_FORMAT);
}

static void json_walks_a_nested_object_with_next(void) {
    fl_json j;
    int first = 0, pairs = 0, i, seen = 0;
    char s[8];
    static const char *const keys[] = {"x", "arr", "o", "y"};
    CHECK_EQ_INT(
        PARSE(j, "{\"c\":{\"x\":\"1\",\"arr\":[1,[2,3],{\"q\":4}],\"o\":{\"p\":[]},\"y\":true},"
                 "\"z\":\"after\"}"),
        FL_OK);
    CHECK_EQ_INT(fl_json_object(&j, "c", &first, &pairs), FL_OK);
    CHECK_EQ_INT(pairs, 4);
    i = first;
    for (int p = 0; p < pairs; p++) {
        const jsmntok_t *k = &j.tok[i];
        CHECK_EQ_INT(k->type, JSMN_STRING);
        CHECK_EQ_INT((size_t)(k->end - k->start), strlen(keys[p]));
        CHECK_EQ_MEM(j.js + k->start, keys[p], strlen(keys[p]));
        i = fl_json_next(&j, i + 1); /* past the value, however nested */
        seen++;
    }
    CHECK_EQ_INT(seen, 4);
    /* after the last pair we are at the key "z" of the root */
    CHECK_EQ_INT(j.tok[i].type, JSMN_STRING);
    CHECK_EQ_INT(j.js[j.tok[i].start], 'z');
    CHECK_EQ_INT(fl_json_string(&j, "z", s, sizeof s), FL_OK);
    CHECK_EQ_STR(s, "after");
    /* past the end of the table */
    CHECK_EQ_INT(fl_json_next(&j, j.count - 1), j.count);
    CHECK_EQ_INT(fl_json_next(&j, j.count + 5), j.count);
    CHECK_EQ_INT(fl_json_next(&j, 0), j.count);
}

static void json_reads_booleans_and_nested_objects(void) {
    fl_json j;
    bool b = false;
    int first = 0, pairs = 0;
    char s[8];
    CHECK_EQ_INT(PARSE(j, "{\"t\":true,\"c\":{\"a\":\"x\",\"b\":\"y\"},\"z\":\"q\",\"n\":1}"),
                 FL_OK);
    CHECK_EQ_INT(fl_json_bool(&j, "t", &b), FL_OK);
    CHECK(b);
    CHECK_EQ_INT(fl_json_object(&j, "c", &first, &pairs), FL_OK);
    CHECK_EQ_INT(pairs, 2);
    CHECK_EQ_INT(j.tok[first].type, JSMN_STRING);
    CHECK_EQ_INT(j.tok[first].end - j.tok[first].start, 1);
    CHECK_EQ_INT(j.js[j.tok[first].start], 'a');
    CHECK_EQ_INT(fl_json_object(&j, "t", &first, &pairs), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_object(&j, "absent", &first, &pairs), FL_ERR_FORMAT);
    /* keys after a nested object are still found */
    CHECK_EQ_INT(fl_json_string(&j, "z", s, sizeof s), FL_OK);
    CHECK_EQ_STR(s, "q");
}

static void json_writer_writes_and_escapes(void) {
    char out[128];
    fl_jw w;
    int len;
    fl_jw_begin(&w, out, sizeof out);
    fl_jw_string(&w, "fw", "1.0\"\\\n\x01");
    fl_jw_int(&w, "uptime", 42);
    fl_jw_int(&w, "neg", INT64_MIN);
    fl_jw_object_begin(&w, "components");
    fl_jw_string(&w, "a", "1");
    fl_jw_object_end(&w);
    fl_jw_int(&w, "z", 0);
    len = fl_jw_end(&w);
    CHECK_EQ_STR(out,
                 "{\"fw\":\"1.0\\\"\\\\\\u000a\\u0001\",\"uptime\":42,\"neg\":-9223372036854775808,"
                 "\"components\":{\"a\":\"1\"},\"z\":0}");
    CHECK_EQ_INT(len, strlen(out));

    fl_jw_begin(&w, out, sizeof out);
    CHECK_EQ_INT(fl_jw_end(&w), 2);
    CHECK_EQ_STR(out, "{}");
}

static void json_writer_escapes_and_never_cuts(void) {
    char out[64], small[64];
    fl_jw w;
    int len, cap;
    fl_jw_begin(&w, out, sizeof out);
    fl_jw_string(&w, "k", "va\"lue");
    len = fl_jw_end(&w);
    CHECK(len > 0);
    for (cap = len + 1; cap >= 1; cap--) {
        fl_jw_begin(&w, small, (size_t)cap);
        fl_jw_string(&w, "k", "va\"lue");
        if (cap == len + 1) {
            CHECK_EQ_INT(fl_jw_end(&w), len);
            CHECK_EQ_STR(small, out);
        } else {
            CHECK_EQ_INT(fl_jw_end(&w), FL_ERR_SPACE); /* one byte short, and every shorter */
        }
    }
    fl_jw_begin(&w, small, 0);
    CHECK_EQ_INT(fl_jw_end(&w), FL_ERR_SPACE);
    fl_jw_begin(&w, NULL, 10);
    CHECK_EQ_INT(fl_jw_end(&w), FL_ERR_ARG);
}

static void json_writer_output_is_read_back(void) {
    char out[128], s[16];
    fl_jw w;
    fl_json j;
    int64_t n = 0;
    fl_jw_begin(&w, out, sizeof out);
    fl_jw_string(&w, "p", "a\nb\"c");
    fl_jw_int(&w, "n", -3);
    CHECK(fl_jw_end(&w) > 0);
    CHECK_EQ_INT(fl_json_parse(&j, out, strlen(out)), FL_OK);
    CHECK_EQ_INT(fl_json_string(&j, "p", s, sizeof s), FL_OK);
    CHECK_EQ_STR(s, "a\nb\"c");
    CHECK_EQ_INT(fl_json_int(&j, "n", &n), FL_OK);
    CHECK_EQ_INT(n, -3);
}

/* A document of 1 + pairs * 2 tokens: {"k0":0,"k1":1,...}. */
static size_t many_pairs(char *text, size_t cap, int pairs) {
    size_t n = 0;
    text[n++] = '{';
    for (int i = 0; i < pairs; i++)
        n += (size_t)snprintf(text + n, cap - n, "%s\"k%d\":%d", i ? "," : "", i, i);
    text[n++] = '}';
    return n;
}

static void json_parses_more_tokens_with_a_table_of_the_caller(void) {
    static char text[2048];
    jsmntok_t tok[128];
    fl_json j;
    int64_t v = 0;
    char s[8];
    size_t n = many_pairs(text, sizeof text, 60); /* 121 tokens: over FL_JSON_MAX_TOKENS */
    CHECK_EQ_INT(fl_json_parse(&j, text, n), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_parse_tokens(&j, text, n, tok, 128), FL_OK);
    CHECK_EQ_INT(j.count, 121);
    CHECK(j.tok == tok);
    CHECK_EQ_INT(fl_json_int(&j, "k59", &v), FL_OK);
    CHECK_EQ_INT(v, 59);
    CHECK_EQ_INT(fl_json_parse_tokens(&j, text, n, tok, 121), FL_OK);
    CHECK_EQ_INT(fl_json_parse_tokens(&j, text, n, tok, 120), FL_ERR_FORMAT);
    /* after a refusal the document reads as empty, never through the caller's table */
    CHECK_EQ_INT(j.count, 0);
    CHECK_EQ_INT(fl_json_int(&j, "k0", &v), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_string(&j, "k0", s, sizeof s), FL_ERR_FORMAT);
    /* the same rules as fl_json_parse */
    CHECK_EQ_INT(fl_json_parse_tokens(&j, "{\"a\":1,\"a\":2}", 13, tok, 128), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_parse_tokens(&j, "[1]", 3, tok, 128), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_parse_tokens(&j, "{\"a\":[[[[1]]]]}", 15, tok, 128), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_parse_tokens(NULL, "{}", 2, tok, 128), FL_ERR_ARG);
    CHECK_EQ_INT(fl_json_parse_tokens(&j, NULL, 2, tok, 128), FL_ERR_ARG);
    CHECK_EQ_INT(fl_json_parse_tokens(&j, "{}", 2, NULL, 128), FL_ERR_ARG);
    CHECK_EQ_INT(fl_json_parse_tokens(&j, "{}", 2, tok, 0), FL_ERR_ARG);
    /* fl_json_parse uses the table of j again */
    CHECK_EQ_INT(fl_json_parse(&j, "{\"x\":\"y\"}", 9), FL_OK);
    CHECK(j.tok != tok);
    CHECK_EQ_INT(fl_json_string(&j, "x", s, sizeof s), FL_OK);
    CHECK_EQ_STR(s, "y");
}

static void json_reads_an_array_of_objects(void) {
    static const char text[] =
        "{\"n\":1,\"list\":[{\"a\":\"x\",\"b\":{\"c\":1}},{\"b\":2,\"a\":\"y\u00e8\"},"
        "{\"a\":3},\"s\"],\"empty\":[],\"o\":{\"a\":\"z\"}}";
    fl_json j;
    int first = -1, count = -1, i;
    char s[8];
    CHECK_EQ_INT(PARSE(j, text), FL_OK);
    CHECK_EQ_INT(fl_json_array(&j, "list", &first, &count), FL_OK);
    CHECK_EQ_INT(count, 4);
    i = first;
    CHECK_EQ_INT(fl_json_member_string(&j, i, "a", s, sizeof s), FL_OK);
    CHECK_EQ_STR(s, "x");
    CHECK_EQ_INT(fl_json_member_string(&j, i, "b", s, sizeof s), FL_ERR_FORMAT); /* an object */
    CHECK_EQ_INT(fl_json_member_string(&j, i, "c", s, sizeof s), FL_ERR_FORMAT); /* not a member */
    i = fl_json_next(&j, i);
    CHECK_EQ_INT(fl_json_member_string(&j, i, "a", s, sizeof s), FL_OK);
    CHECK_EQ_STR(s, "y\xc3\xa8");
    CHECK_EQ_INT(fl_json_member_string(&j, i, "a", s, 3), FL_ERR_SPACE);
    i = fl_json_next(&j, i);
    CHECK_EQ_INT(fl_json_member_string(&j, i, "a", s, sizeof s), FL_ERR_FORMAT); /* a number */
    i = fl_json_next(&j, i);
    CHECK_EQ_INT(j.tok[i].type, JSMN_STRING);
    CHECK_EQ_INT(fl_json_member_string(&j, i, "a", s, sizeof s), FL_ERR_FORMAT); /* not an object */
    /* after the array: the key "empty" of the root */
    i = fl_json_next(&j, i);
    CHECK_EQ_INT(j.js[j.tok[i].start], 'e');
    CHECK_EQ_INT(fl_json_array(&j, "empty", &first, &count), FL_OK);
    CHECK_EQ_INT(count, 0);
    CHECK_EQ_INT(fl_json_array(&j, "o", &first, &count), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_array(&j, "n", &first, &count), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_array(&j, "absent", &first, &count), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_array(NULL, "list", &first, &count), FL_ERR_ARG);
    /* the root is an object too; indexes outside the table are refused */
    CHECK_EQ_INT(fl_json_member_string(&j, 0, "a", s, sizeof s), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_member_string(&j, -1, "a", s, sizeof s), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_member_string(&j, j.count, "a", s, sizeof s), FL_ERR_FORMAT);
    CHECK_EQ_INT(fl_json_member_string(&j, 0, NULL, s, sizeof s), FL_ERR_ARG);
    CHECK_EQ_INT(PARSE(j, "{\"a\":\"q\"}"), FL_OK);
    CHECK_EQ_INT(fl_json_member_string(&j, 0, "a", s, sizeof s), FL_OK);
    CHECK_EQ_STR(s, "q");
}

int main(void) {
    RUN(json_reads_the_manifest_of_the_vector);
    RUN(json_refuses_repeated_root_key);
    RUN(json_refuses_nesting_over_four_levels);
    RUN(json_refuses_invalid_documents);
    RUN(json_refuses_more_tokens_than_the_table);
    RUN(json_unescapes_pem_newlines);
    RUN(json_decodes_unicode_escapes);
    RUN(json_string_too_long_is_space_error);
    RUN(json_reads_integers_strictly);
    RUN(json_refuses_malformed_primitives);
    RUN(json_refuses_broken_structure);
    RUN(json_walks_a_nested_object_with_next);
    RUN(json_reads_booleans_and_nested_objects);
    RUN(json_writer_writes_and_escapes);
    RUN(json_writer_escapes_and_never_cuts);
    RUN(json_writer_output_is_read_back);
    RUN(json_parses_more_tokens_with_a_table_of_the_caller);
    RUN(json_reads_an_array_of_objects);
    return CHECK_RESULT;
}
