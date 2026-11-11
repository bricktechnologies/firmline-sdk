/* SPDX-License-Identifier: Apache-2.0 */
/* firmline-package.json, the description inside the package of a Docker Compose application
 * (built by `pack`, read by `apply` and by the `package:` version source):
 *   {"format":1,"architecture":"<arch>","version":"<v>",
 *    "images":[{"service":"<s>","image":"firmline.local/<s>:<v>","id":"sha256:<64 hex>"}]}
 * exactly these keys. architecture is Docker's Architecture of the images (amd64, arm64, arm: 1 to
 * 15 of [a-z0-9]). The version is the tag of the images: 1 to 64 of [A-Za-z0-9_.-], not starting
 * with '.' or '-'. 1 to FA_MAX_COMPONENTS images, one per service; a service name is a component
 * of an image name: lowercase letters and digits in groups joined by one '.', one or two '_' or
 * any number of '-', 64 bytes at most; services are distinct. The id is the image ID (the SHA-256
 * of its configuration), lowercase hex. */
#ifndef FIRMLINE_AGENT_PACKAGE_H
#define FIRMLINE_AGENT_PACKAGE_H

#include "config.h"

#include <stdbool.h>
#include <stddef.h>

#define FA_PACKAGE_FORMAT 1
/* The image names of a package: <registry>/<service>:<version>. */
#define FA_PACKAGE_REGISTRY "firmline.local"

typedef struct {
    int format;
    char architecture[16];
    char version[65];
    int image_count;
    struct {
        char service[65];
        char image[160];
        char id[72];
    } image[FA_MAX_COMPONENTS];
} fa_package;

/* Reads and checks the whole document. 0, or -1 with the reason in err (out is then cleared). */
int fa_package_parse(const char *json, size_t len, fa_package *out, char err[256]);

/* Writes the document, NUL-terminated, after the same checks as fa_package_parse. Its length, or
 * -1 for a package that the parser would refuse or a buffer too small (never cut). */
int fa_package_write(const fa_package *p, char *out, size_t cap);

/* The rules above, for `pack`: a version usable as the tag of the images, a service name usable in
 * an image name, an image ID. */
bool fa_package_version_ok(const char *version);
bool fa_package_service_ok(const char *service);
bool fa_package_id_ok(const char *id);

#endif
