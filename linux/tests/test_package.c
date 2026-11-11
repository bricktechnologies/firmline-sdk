/* SPDX-License-Identifier: Apache-2.0 */
#include "check.h"
#include "package.h"

#include <stdio.h>
#include <string.h>

#define ID_A "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define ID_B "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

static const char VALID[] =
    "{\"format\":1,\"architecture\":\"arm64\",\"version\":\"2.1.0\","
    "\"images\":[{\"service\":\"web\",\"image\":\"firmline.local/web:2.1.0\","
    "\"id\":\"" ID_A "\"},{\"service\":\"db\",\"image\":\"firmline.local/"
    "db:2.1.0\",\"id\":\"" ID_B "\"}]}";

static int parse(const char *text, fa_package *p, char err[256]) {
    return fa_package_parse(text, strlen(text), p, err);
}

/* A package of n images of services s0, s1, ... as JSON, with the keys in another order than the
 * writer's. */
static void n_images(char *out, size_t cap, int n) {
    size_t len = (size_t)snprintf(out, cap, "{\"version\":\"1.0\",\"images\":[");
    for (int i = 0; i < n; i++)
        len += (size_t)snprintf(out + len, cap - len,
                                "%s{\"id\":\"" ID_A "\",\"service\":\"s%d\",\"image\":\"firmline."
                                "local/s%d:1.0\"}",
                                i ? "," : "", i, i);
    snprintf(out + len, cap - len, "],\"architecture\":\"amd64\",\"format\":1}");
}

static void package_reads_a_valid_document(void) {
    fa_package p;
    char err[256] = "";
    CHECK_EQ_INT(parse(VALID, &p, err), 0);
    CHECK_EQ_STR(err, "");
    CHECK_EQ_INT(p.format, 1);
    CHECK_EQ_STR(p.architecture, "arm64");
    CHECK_EQ_STR(p.version, "2.1.0");
    CHECK_EQ_INT(p.image_count, 2);
    CHECK_EQ_STR(p.image[0].service, "web");
    CHECK_EQ_STR(p.image[0].image, "firmline.local/web:2.1.0");
    CHECK_EQ_STR(p.image[0].id, ID_A);
    CHECK_EQ_STR(p.image[1].service, "db");
    CHECK_EQ_STR(p.image[1].id, ID_B);
}

static void package_write_and_parse_round_trip(void) {
    fa_package p, q;
    char out[8192], err[256];
    CHECK_EQ_INT(parse(VALID, &p, err), 0);
    int len = fa_package_write(&p, out, sizeof out);
    CHECK(len > 0);
    CHECK_EQ_INT((size_t)len, strlen(out));
    CHECK_EQ_STR(out, VALID); /* the writer's order and no spaces */
    CHECK_EQ_INT(fa_package_parse(out, (size_t)len, &q, err), 0);
    CHECK_EQ_MEM(&q, &p, sizeof p);
    /* never cut: one byte short of the text and its NUL */
    CHECK_EQ_INT(fa_package_write(&p, out, (size_t)len), -1);
    CHECK_EQ_INT(fa_package_write(&p, out, (size_t)len + 1), len);
}

static void package_of_sixteen_images_is_read_and_seventeen_refused(void) {
    static char text[8192], out[8192];
    fa_package p, q;
    char err[256];
    n_images(text, sizeof text, 16);
    CHECK_EQ_INT(parse(text, &p, err), 0);
    CHECK_EQ_INT(p.image_count, 16);
    CHECK_EQ_STR(p.image[15].service, "s15");
    CHECK_EQ_STR(p.image[15].image, "firmline.local/s15:1.0");
    int len = fa_package_write(&p, out, sizeof out);
    CHECK(len > 0);
    CHECK_EQ_INT(fa_package_parse(out, (size_t)len, &q, err), 0);
    CHECK_EQ_INT(q.image_count, 16);

    n_images(text, sizeof text, 17);
    err[0] = '\0';
    CHECK_EQ_INT(parse(text, &p, err), -1);
    CHECK(strstr(err, "16") != NULL);
    CHECK_EQ_INT(p.image_count, 0); /* cleared */
    n_images(text, sizeof text, 0);
    CHECK_EQ_INT(parse(text, &p, err), -1);
}

static void package_refuses_what_the_format_does_not_allow(void) {
#define IMG(s, i, id) "{\"service\":\"" s "\",\"image\":\"" i "\",\"id\":\"" id "\"}"
#define DOC(format, arch, version, images)                                                         \
    "{\"format\":" format ",\"architecture\":\"" arch "\",\"version\":\"" version                  \
    "\",\"images\":[" images "]}"
    static const char *const invalid[] = {
        "",
        "not json",
        "{\"format\":1,",
        "[1]",
        /* format */
        DOC("2", "arm64", "1.0", IMG("a", "firmline.local/a:1.0", ID_A)),
        DOC("0", "arm64", "1.0", IMG("a", "firmline.local/a:1.0", ID_A)),
        DOC("\"1\"", "arm64", "1.0", IMG("a", "firmline.local/a:1.0", ID_A)),
        DOC("1.0", "arm64", "1.0", IMG("a", "firmline.local/a:1.0", ID_A)),
        /* missing fields */
        "{\"architecture\":\"arm64\",\"version\":\"1.0\",\"images\":[" IMG(
            "a", "firmline.local/a:1.0", ID_A) "]}",
        "{\"format\":1,\"version\":\"1.0\",\"images\":[" IMG("a", "firmline.local/a:1.0",
                                                             ID_A) "]}",
        "{\"format\":1,\"architecture\":\"arm64\",\"images\":[" IMG("a", "firmline.local/a:1.0",
                                                                    ID_A) "]}",
        "{\"format\":1,\"architecture\":\"arm64\",\"version\":\"1.0\"}",
        DOC("1", "arm64", "1.0",
            "{\"image\":\"firmline.local/a:1.0\",\"id\":\"" ID_A "\",\"x\":\"a\"}"),
        DOC("1", "arm64", "1.0", "{\"service\":\"a\",\"id\":\"" ID_A "\",\"x\":\"\"}"),
        DOC("1", "arm64", "1.0", "{\"service\":\"a\",\"image\":\"firmline.local/a:1.0\"}"),
        /* keys of their own */
        "{\"format\":1,\"architecture\":\"arm64\",\"version\":\"1.0\",\"images\":[" IMG(
            "a", "firmline.local/a:1.0", ID_A) "],\"extra\":1}",
        DOC("1", "arm64", "1.0",
            "{\"service\":\"a\",\"image\":\"firmline.local/a:1.0\",\"id\":\"" ID_A "\",\"x\":1}"),
        /* a repeated key inside an image */
        DOC("1", "arm64", "1.0",
            "{\"service\":\"a\",\"service\":\"a\",\"image\":\"firmline.local/a:1.0\"}"),
        /* the id: sha256: and 64 lowercase hex */
        DOC("1", "arm64", "1.0", IMG("a", "firmline.local/a:1.0", "sha256:x")),
        DOC("1", "arm64", "1.0",
            IMG("a", "firmline.local/a:1.0",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")),
        DOC("1", "arm64", "1.0",
            IMG("a", "firmline.local/a:1.0",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0")),
        DOC("1", "arm64", "1.0",
            IMG("a", "firmline.local/a:1.0",
                "sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef")),
        DOC("1", "arm64", "1.0",
            IMG("a", "firmline.local/a:1.0",
                "sha512:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")),
        DOC("1", "arm64", "1.0",
            IMG("a", "firmline.local/a:1.0",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")),
        /* a service twice */
        DOC("1", "arm64", "1.0",
            IMG("a", "firmline.local/a:1.0", ID_A) "," IMG("a", "firmline.local/a:1.0", ID_B)),
        /* service names outside [a-zA-Z0-9._-], and what an image name cannot hold */
        DOC("1", "arm64", "1.0", IMG("a b", "firmline.local/a b:1.0", ID_A)),
        DOC("1", "arm64", "1.0", IMG("a/b", "firmline.local/a/b:1.0", ID_A)),
        DOC("1", "arm64", "1.0", IMG("a:b", "firmline.local/a:b:1.0", ID_A)),
        DOC("1", "arm64", "1.0", IMG("\\u00e8", "firmline.local/\\u00e8:1.0", ID_A)),
        DOC("1", "arm64", "1.0", IMG("", "firmline.local/:1.0", ID_A)),
        DOC("1", "arm64", "1.0", IMG("Web", "firmline.local/Web:1.0", ID_A)),
        DOC("1", "arm64", "1.0", IMG("-a", "firmline.local/-a:1.0", ID_A)),
        DOC("1", "arm64", "1.0", IMG("a.", "firmline.local/a.:1.0", ID_A)),
        DOC("1", "arm64", "1.0", IMG("a..b", "firmline.local/a..b:1.0", ID_A)),
        DOC("1", "arm64", "1.0", IMG("a___b", "firmline.local/a___b:1.0", ID_A)),
        DOC("1", "arm64", "1.0",
            IMG("a0123456789012345678901234567890123456789012345678901234567890123",
                "firmline.local/a0123456789012345678901234567890123456789012345678901234567890123:"
                "1.0",
                ID_A)),
        /* the image name is the one of the service and the version */
        DOC("1", "arm64", "1.0", IMG("a", "firmline.local/b:1.0", ID_A)),
        DOC("1", "arm64", "1.0", IMG("a", "firmline.local/a:1.1", ID_A)),
        DOC("1", "arm64", "1.0", IMG("a", "docker.io/a:1.0", ID_A)),
        DOC("1", "arm64", "1.0", IMG("a", "firmline.local/a", ID_A)),
        /* the version is valid as fw; the image carries its tag, not the version itself */
        DOC("1", "arm64", "", IMG("a", "firmline.local/a:", ID_A)),
        DOC("1", "arm64", "1\\u0001", IMG("a", "firmline.local/a:1_", ID_A)),
        DOC("1", "arm64", "1\\n", IMG("a", "firmline.local/a:1_", ID_A)),
        DOC("1", "arm64", "1\\u007f", IMG("a", "firmline.local/a:1_", ID_A)),
        DOC("1", "arm64", "1.0+b", IMG("a", "firmline.local/a:1.0+b", ID_A)),
        DOC("1", "arm64", ".1", IMG("a", "firmline.local/a:.1", ID_A)),
        DOC("1", "arm64", "-1", IMG("a", "firmline.local/a:-1", ID_A)),
        DOC("1", "arm64", "1 0", IMG("a", "firmline.local/a:1 0", ID_A)),
        DOC("1", "arm64", "01234567890123456789012345678901234567890123456789012345678901234",
            IMG("a",
                "firmline.local/"
                "a:01234567890123456789012345678901234567890123456789012345678901234",
                ID_A)),
        /* the architecture */
        DOC("1", "", "1.0", IMG("a", "firmline.local/a:1.0", ID_A)),
        DOC("1", "ARM64", "1.0", IMG("a", "firmline.local/a:1.0", ID_A)),
        DOC("1", "arm/v7", "1.0", IMG("a", "firmline.local/a:1.0", ID_A)),
        DOC("1", "a234567890123456", "1.0", IMG("a", "firmline.local/a:1.0", ID_A)),
        /* not an array of objects */
        "{\"format\":1,\"architecture\":\"arm64\",\"version\":\"1.0\",\"images\":{}}",
        DOC("1", "arm64", "1.0", "\"a\""),
        DOC("1", "arm64", "1.0", IMG("a", "firmline.local/a:1.0", ID_A) ",1"),
    };
#undef IMG
#undef DOC
    for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; i++) {
        fa_package p;
        char err[256] = "";
        int rc = parse(invalid[i], &p, err);
        if (rc != -1 || err[0] == '\0')
            fprintf(stderr, "case %zu accepted or without a reason: %s\n", i, invalid[i]);
        CHECK_EQ_INT(rc, -1);
        CHECK(err[0] != '\0');
    }
}

static void package_accepts_the_edges_of_the_rules(void) {
    fa_package p;
    char err[256];
    CHECK_EQ_INT(parse("{\"format\":1,\"architecture\":\"arm\",\"version\":\"_v1.0-rc.1_A\","
                       "\"images\":[{\"service\":\"my-app__x.y_z--w0\",\"image\":\"firmline.local/"
                       "my-app__x.y_z--w0:_v1.0-rc.1_A\",\"id\":\"" ID_A "\"}]}",
                       &p, err),
                 0);
    CHECK_EQ_STR(p.image[0].service, "my-app__x.y_z--w0");
    /* the same image ID for two services */
    CHECK_EQ_INT(parse("{\"format\":1,\"architecture\":\"amd64\",\"version\":\"1\",\"images\":["
                       "{\"service\":\"a\",\"image\":\"firmline.local/a:1\",\"id\":\"" ID_A "\"},"
                       "{\"service\":\"b\",\"image\":\"firmline.local/b:1\",\"id\":\"" ID_A "\"}]}",
                       &p, err),
                 0);
    /* white space between the tokens */
    CHECK_EQ_INT(parse("{ \"format\" : 1 ,\n \"architecture\":\"amd64\",\"version\":\"1\","
                       "\"images\":[ {\"service\":\"a\",\"image\":\"firmline.local/a:1\","
                       "\"id\":\"" ID_A "\"} ] }\n",
                       &p, err),
                 0);
    /* a version that is not a Docker tag: the images carry the tag made from it */
    CHECK_EQ_INT(
        parse("{\"format\":1,\"architecture\":\"arm64\",\"version\":\"1.4.3+build.7\","
              "\"images\":[{\"service\":\"a\",\"image\":\"firmline.local/a:1.4.3_build.7\","
              "\"id\":\"" ID_A "\"}]}",
              &p, err),
        0);
    CHECK_EQ_STR(p.version, "1.4.3+build.7");
    CHECK_EQ_INT(parse("{\"format\":1,\"architecture\":\"arm64\",\"version\":\"-1 \\u00fc\","
                       "\"images\":[{\"service\":\"a\",\"image\":\"firmline.local/a:_-1___\","
                       "\"id\":\"" ID_A "\"}]}",
                       &p, err),
                 0);
    CHECK_EQ_STR(p.version, "-1 \xc3\xbc");
    /* 64 bytes of version and of service */
    CHECK(
        fa_package_version_ok("0123456789012345678901234567890123456789012345678901234567890123"));
    CHECK(
        fa_package_service_ok("a012345678901234567890123456789012345678901234567890123456789012"));
    CHECK(!fa_package_version_ok(
        "01234567890123456789012345678901234567890123456789012345678901234"));
    CHECK(!fa_package_version_ok(""));
    CHECK(!fa_package_version_ok("1\t0"));
    CHECK(fa_package_version_ok("1.0 beta"));
    CHECK(!fa_package_version_ok(" 1.0"));
    CHECK(!fa_package_version_ok("1.0 "));
    CHECK(!fa_package_version_ok(NULL));
    CHECK(!fa_package_service_ok(NULL));
    CHECK(!fa_package_id_ok(NULL));
    CHECK(fa_package_id_ok(ID_B));
}

static void package_tag_is_the_version_made_a_docker_tag(void) {
    static const char *const cases[][2] = {
        {"1.2.0", "1.2.0"},
        {"1.4.3+build.7", "1.4.3_build.7"},
        {"_a-B.9", "_a-B.9"},
        {".1", "_.1"},
        {"-1", "_-1"},
        {"1 0/x:y", "1_0_x_y"},
        {"\xc3\xbc", "__"},
        {"0123456789012345678901234567890123456789012345678901234567890123",
         "0123456789012345678901234567890123456789012345678901234567890123"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        char tag[FA_PACKAGE_TAG_MAX + 1];
        fa_package_tag(cases[i][0], tag);
        CHECK_EQ_STR(tag, cases[i][1]);
    }
}

static void package_write_escapes_the_version(void) {
    fa_package p, q;
    char out[8192], err[256];
    memset(&p, 0, sizeof p);
    p.format = 1;
    strcpy(p.architecture, "arm64");
    strcpy(p.version, "1.0 \"rc\"\\x");
    p.image_count = 1;
    strcpy(p.image[0].service, "web");
    strcpy(p.image[0].image, "firmline.local/web:1.0__rc__x");
    strcpy(p.image[0].id, ID_A);
    int len = fa_package_write(&p, out, sizeof out);
    CHECK(len > 0);
    CHECK(strstr(out, "\"version\":\"1.0 \\\"rc\\\"\\\\x\"") != NULL);
    CHECK_EQ_INT(fa_package_parse(out, (size_t)len, &q, err), 0);
    CHECK_EQ_MEM(&q, &p, sizeof p);
}

static void package_write_refuses_what_parse_refuses(void) {
    fa_package p, bad;
    char out[8192], err[256];
    CHECK_EQ_INT(parse(VALID, &p, err), 0);
    bad = p;
    bad.format = 2;
    CHECK_EQ_INT(fa_package_write(&bad, out, sizeof out), -1);
    bad = p;
    strcpy(bad.image[1].service, "web");
    strcpy(bad.image[1].image, "firmline.local/web:2.1.0");
    CHECK_EQ_INT(fa_package_write(&bad, out, sizeof out), -1);
    bad = p;
    strcpy(bad.image[0].id, "sha256:x");
    CHECK_EQ_INT(fa_package_write(&bad, out, sizeof out), -1);
    bad = p;
    bad.image_count = 17;
    CHECK_EQ_INT(fa_package_write(&bad, out, sizeof out), -1);
    bad = p;
    bad.image_count = 0;
    CHECK_EQ_INT(fa_package_write(&bad, out, sizeof out), -1);
    bad = p;
    strcpy(bad.version, "2.1.1");
    CHECK_EQ_INT(fa_package_write(&bad, out, sizeof out), -1);
    bad = p;
    bad.architecture[0] = '\0';
    CHECK_EQ_INT(fa_package_write(&bad, out, sizeof out), -1);
    CHECK_EQ_INT(fa_package_write(NULL, out, sizeof out), -1);
    CHECK_EQ_INT(fa_package_write(&p, NULL, 0), -1);
}

#define HEX_A "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define HEX_B "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
#define HEX_C "1111111111111111111111111111111111111111111111111111111111111111"

/* A package of web and db at 2.1.0 with ids that the manifest must replace. */
static void two_services(fa_package *p) {
    char err[256];
    CHECK_EQ_INT(parse(VALID, p, err), 0);
    strcpy(p->image[0].id, "sha256:" HEX_C);
    strcpy(p->image[1].id, "sha256:" HEX_C);
}

static int manifest(const char *text, fa_package *p, char err[256]) {
    err[0] = '\0';
    return fa_package_ids_from_manifest(text, strlen(text), p, err);
}

static void manifest_gives_the_config_digests_of_both_layouts(void) {
    fa_package p;
    char err[256];
    /* the classic layout of docker save: <hex>.json */
    two_services(&p);
    CHECK_EQ_INT(
        manifest("[{\"Config\":\"" HEX_A ".json\",\"RepoTags\":[\"firmline.local/web:2.1.0\"],"
                 "\"Layers\":[\"" HEX_C "/layer.tar\"]},"
                 "{\"Config\":\"" HEX_B ".json\",\"RepoTags\":[\"firmline.local/db:2.1.0\"],"
                 "\"Layers\":[]}]",
                 &p, err),
        0);
    CHECK_EQ_STR(p.image[0].id, "sha256:" HEX_A);
    CHECK_EQ_STR(p.image[1].id, "sha256:" HEX_B);
    /* the OCI layout (Docker 25 and later, and the containerd image store): blobs/sha256/<hex>,
     * with other images and other keys around */
    two_services(&p);
    CHECK_EQ_INT(
        manifest("[{\"Config\":\"blobs/sha256/" HEX_C "\",\"RepoTags\":null,\"Layers\":[]},"
                 "{\"Config\":\"blobs/sha256/" HEX_B
                 "\",\"RepoTags\":[\"firmline.local/db:2.1.0\"],"
                 "\"Layers\":[\"blobs/sha256/" HEX_C "\"],\"LayerSources\":{\"x\":{\"size\":1}}},"
                 "{\"Config\":\"blobs/sha256/" HEX_A "\",\"RepoTags\":[\"other/x:1\","
                 "\"firmline.local/web:2.1.0\"],\"Layers\":[]}]\n",
                 &p, err),
        0);
    CHECK_EQ_STR(p.image[0].id, "sha256:" HEX_A);
    CHECK_EQ_STR(p.image[1].id, "sha256:" HEX_B);
    /* two services of one image: one entry with both tags */
    two_services(&p);
    CHECK_EQ_INT(manifest("[{\"Config\":\"blobs/sha256/" HEX_A "\",\"RepoTags\":["
                          "\"firmline.local/web:2.1.0\",\"firmline.local/db:2.1.0\"]}]",
                          &p, err),
                 0);
    CHECK_EQ_STR(p.image[0].id, "sha256:" HEX_A);
    CHECK_EQ_STR(p.image[1].id, "sha256:" HEX_A);
}

static void manifest_without_a_clear_entry_is_refused(void) {
    static const char *const invalid[] = {
        "",
        "not json",
        "{\"Config\":\"" HEX_A ".json\"}",
        "[]",
        /* db has no entry */
        "[{\"Config\":\"" HEX_A ".json\",\"RepoTags\":[\"firmline.local/web:2.1.0\"]}]",
        /* web is in two entries */
        "[{\"Config\":\"" HEX_A ".json\",\"RepoTags\":[\"firmline.local/web:2.1.0\","
        "\"firmline.local/db:2.1.0\"]},{\"Config\":\"" HEX_B ".json\",\"RepoTags\":["
        "\"firmline.local/web:2.1.0\"]}]",
        /* a Config that is not a digest of either layout */
        "[{\"Config\":\"" HEX_A "\",\"RepoTags\":[\"firmline.local/web:2.1.0\","
        "\"firmline.local/db:2.1.0\"]}]",
        "[{\"Config\":\"blobs/sha512/" HEX_A "\",\"RepoTags\":[\"firmline.local/web:2.1.0\","
        "\"firmline.local/db:2.1.0\"]}]",
        "[{\"Config\":\"x/" HEX_A ".json\",\"RepoTags\":[\"firmline.local/web:2.1.0\","
        "\"firmline.local/db:2.1.0\"]}]",
        "[{\"Config\":\"" HEX_A "0.json\",\"RepoTags\":[\"firmline.local/web:2.1.0\","
        "\"firmline.local/db:2.1.0\"]}]",
        "[{\"Config\":\"blobs/sha256/"
        "ABCDEF6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
        "\"RepoTags\":[\"firmline.local/web:2.1.0\",\"firmline.local/db:2.1.0\"]}]",
        "[{\"RepoTags\":[\"firmline.local/web:2.1.0\",\"firmline.local/db:2.1.0\"]}]",
        "[{\"Config\":1,\"RepoTags\":[\"firmline.local/web:2.1.0\",\"firmline.local/db:2.1.0\"]}]",
        /* RepoTags not an array of strings */
        "[{\"Config\":\"" HEX_A ".json\",\"RepoTags\":\"firmline.local/web:2.1.0\"}]",
        "[{\"Config\":\"" HEX_A ".json\",\"RepoTags\":[1]}]",
        "[1]",
    };
    for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; i++) {
        fa_package p;
        char err[256];
        two_services(&p);
        int rc = manifest(invalid[i], &p, err);
        if (rc != -1 || err[0] == '\0')
            fprintf(stderr, "case %zu accepted or without a reason: %s\n", i, invalid[i]);
        CHECK_EQ_INT(rc, -1);
        CHECK(err[0] != '\0');
    }
}

static void compose_services_are_read_with_their_images(void) {
    fa_compose_service s[FA_MAX_COMPONENTS];
    int count = -1;
    char err[256] = "";
    static const char json[] =
        "{\"name\":\"app\",\"services\":{\"web\":{\"image\":\"example/web:1\",\"healthcheck\":{"
        "\"test\":[\"CMD\",\"true\"]},\"volumes\":[{\"type\":\"volume\",\"source\":\"data\"}]},"
        "\"db\":{\"build\":{\"context\":\"./db\"},\"image\":\"registry:5000/db@sha256:" HEX_A
        "\"}},"
        "\"volumes\":{\"data\":{}}}";
    CHECK_EQ_INT(fa_compose_services(json, strlen(json), s, &count, err), 0);
    CHECK_EQ_INT(count, 2);
    CHECK_EQ_STR(s[0].service, "web");
    CHECK_EQ_STR(s[0].image, "example/web:1");
    CHECK_EQ_STR(s[1].service, "db");
    CHECK_EQ_STR(s[1].image, "registry:5000/db@sha256:" HEX_A);

    static const char *const invalid[][2] = {
        {"not json", "read"},
        {"[]", "read"},
        {"{\"name\":\"x\"}", "services"},
        {"{\"services\":{}}", "no services"},
        {"{\"services\":{\"tool\":{\"build\":\".\"}}}", "tool"},
        {"{\"services\":{\"Web\":{\"image\":\"x\"}}}", "Web"},
        {"{\"services\":{\"a\":{\"image\":\"\"}}}", "image"},
        {"{\"services\":{\"a\":{\"image\":\"x\\u0041y\"}}}", "image"},
        {"{\"services\":{\"a\":{\"image\":1}}}", "image"},
    };
    for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; i++) {
        err[0] = '\0';
        CHECK_EQ_INT(fa_compose_services(invalid[i][0], strlen(invalid[i][0]), s, &count, err), -1);
        if (strstr(err, invalid[i][1]) == NULL)
            fprintf(stderr, "case %zu: \"%s\" does not name %s\n", i, err, invalid[i][1]);
        CHECK(strstr(err, invalid[i][1]) != NULL);
    }
    /* 17 services */
    char many[2048];
    size_t len = (size_t)snprintf(many, sizeof many, "{\"services\":{");
    for (int i = 0; i < 17; i++)
        len += (size_t)snprintf(many + len, sizeof many - len, "%s\"s%d\":{\"image\":\"x\"}",
                                i ? "," : "", i);
    snprintf(many + len, sizeof many - len, "}}");
    CHECK_EQ_INT(fa_compose_services(many, strlen(many), s, &count, err), -1);
    CHECK(strstr(err, "16") != NULL);
}

int main(void) {
    RUN(package_reads_a_valid_document);
    RUN(package_write_and_parse_round_trip);
    RUN(package_of_sixteen_images_is_read_and_seventeen_refused);
    RUN(package_refuses_what_the_format_does_not_allow);
    RUN(package_accepts_the_edges_of_the_rules);
    RUN(package_tag_is_the_version_made_a_docker_tag);
    RUN(package_write_escapes_the_version);
    RUN(package_write_refuses_what_parse_refuses);
    RUN(manifest_gives_the_config_digests_of_both_layouts);
    RUN(manifest_without_a_clear_entry_is_refused);
    RUN(compose_services_are_read_with_their_images);
    return CHECK_RESULT;
}
