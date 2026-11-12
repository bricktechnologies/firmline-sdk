/* SPDX-License-Identifier: Apache-2.0 */
/* The update path of `run`. One job at a time, in this order:
 *   REHASH   (only when a .part is on disk) the bytes already downloaded are hashed again from
 *            the file, a piece per loop turn;
 *   DOWNLOAD a libcurl transfer appends to the .part and feeds the check;
 *   RETRY    waiting for fl_download_retry_at after a 429, a 5xx or a network error;
 *   INSTALL  the component's script runs with the verified file;
 *   REBOOT   reboot_command runs after a script that exited 10;
 *   APPLY    (install = docker-compose) `firmline-agent apply` runs in the container
 *            firmline-apply, started from the agent's own (same image, --volumes-from), so that
 *            it outlives a recreation of the agent; its outcome is read from apply.json every
 *            second. An agent that starts with install.json in the state "apply" follows it the
 *            same way: the result is sent by whichever agent reads the outcome first, and stored
 *            before it is sent, so a recreated agent sends that result again, never another.
 * A job ends with a result, or without one when the platform has to offer again (a link expired
 * or refused, a check that could not run): never with a file that was not verified.
 * Whether a link has expired is the server's answer (404), never the device clock's: a link is
 * always tried, and retries are bounded by the monotonic clock, FL_DOWNLOAD_RETRY_WINDOW seconds
 * from the moment the link arrived (from the start of the agent for an offer read from the data
 * folder). The wall clock against urlExpires only adds a warning to the log. */
#define _POSIX_C_SOURCE 200809L
#include "ota.h"

#include "apply.h"
#include "components.h"
#include "docker.h"
#include "firmline/fl_download.h"
#include "firmline/fl_json.h"
#include "firmline/fl_messages.h"
#include "firmline/fl_offer.h"
#include "firmline/fl_policy.h"
#include "firmline/fl_queue.h"
#include "firmline/fl_version.h"
#include "http.h"
#include "install_script.h"
#include "log.h"
#include "store.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

#define RESULTS_KEEP 32
#define SPACE_MARGIN (1024 * 1024)     /* left free on the data folder besides the file */
#define REHASH_CHUNK (4 * 1024 * 1024) /* hashed from disk per loop turn */
#define MAX_OFFER_FILES 64             /* read at start; the queue holds FL_QUEUE_MAX */
#define RESULT_TOPIC "ota/result"
#define INSTALL_STATE "install.json"
#define RELEASE_LEN 36
#define CLOSE_GRACE_S 5 /* for a running script to end when the agent stops */
#define APPLY_CONTAINER "firmline-apply"
#define APPLY_POLL_MS 1000         /* how often the container and apply.json are looked at */
#define APPLY_UNANSWERED_MS 300000 /* docker silent that long: the apply container has ended */
#define APPLY_WAIT_S 1800 /* for an earlier firmline-apply container to end before apply starts */
#define DOCKER_QUICK_MS 30000 /* docker ps, inspect, rm */
#define DOCKER_RUN_MS 120000  /* docker run --detach */

typedef struct {
    char release[RELEASE_LEN + 1]; /* lower case */
    int64_t seq;
    bool published; /* a PUBACK came once (stored in the file) */
    bool send;      /* to be sent on the current connection */
    int mid;        /* in flight on connection `session`: its message id; 0 = none */
    unsigned session;
    char payload[FL_RESULT_MAX + 1];
    size_t len;
} stored_result;

typedef enum {
    JOB_NONE,
    JOB_REHASH,
    JOB_DOWNLOAD,
    JOB_RETRY,
    JOB_INSTALL,
    JOB_REBOOT,
    JOB_APPLY
} job_state;

typedef enum {
    SINK_OK,
    SINK_TOO_LONG,
    SINK_WRITE,
    SINK_NO_SPACE,
    SINK_RANGE,
    SINK_CRYPTO
} sink_state;

struct fa_ota {
    fa_service *svc;
    const fa_config *cfg;
    char tenant[80];
    fl_device dev;
    char version_buf[65]; /* installed_version() of the offer check */
    fl_queue queue;
    stored_result results[RESULTS_KEEP];
    int result_count;
    int64_t next_seq;

    job_state state;
    bool reboot_pending; /* a script exited 10: nothing more is installed before the restart */
    bool stopping;       /* fa_ota_close: no reboot_command any more */
    char reboot_release[RELEASE_LEN + 1];
    fl_offer job; /* the release being worked on (its link refreshed from the queue) */
    const fa_component *comp;
    int fd; /* the .part, -1 */
    fl_download check;
    bool checking;         /* `check` holds a hash state */
    uint64_t have;         /* bytes of the .part already hashed */
    uint64_t on_disk;      /* REHASH: bytes found in the .part at the start of the job */
    uint64_t request_from; /* offset of the running request */
    bool from_disk;        /* bytes from a former run are part of the file */
    bool restarted;        /* the one restart from byte 0 (416, wrong range) is used */
    bool progress;         /* the running request brought bytes */
    bool clock_warned;     /* the warning on urlExpires by the device clock is in the log */
    int attempt;           /* retries since the last progress */
    sink_state sink;
    int sink_errno;   /* of a failed write */
    fl_time retry_at; /* monotonic seconds */
    /* When each queued release's current link arrived (monotonic seconds): the retries of a
     * link end FL_DOWNLOAD_RETRY_WINDOW after it. Keyed by release (lower case), "" = free. */
    struct {
        char release[RELEASE_LEN + 1];
        fl_time received;
    } links[FL_QUEUE_MAX];
    fa_http_download *http;
    fa_child child;
    /* JOB_APPLY */
    bool apply_started; /* apply was started (or is followed from install.json at start) */
    long long
        apply_waiting_since_ms;      /* monotonic: waiting for an earlier firmline-apply; 0 = not */
    long long apply_silent_since_ms; /* monotonic: docker has not answered since; 0 = it has */
    long long apply_next_ms;         /* monotonic: the next look */
    char own_id[65];                 /* the agent's container, "" = not known */
};

/* ---- Names -------------------------------------------------------------------------------- */

static void lower_release(const char *in, char out[RELEASE_LEN + 1]) {
    size_t i = 0;
    for (; in[i] != '\0' && i < RELEASE_LEN; i++)
        out[i] = (in[i] >= 'A' && in[i] <= 'Z') ? (char)(in[i] - 'A' + 'a') : in[i];
    out[i] = '\0';
}

static bool same_release(const char *a, const char *b) {
    char la[RELEASE_LEN + 1], lb[RELEASE_LEN + 1];
    lower_release(a, la);
    lower_release(b, lb);
    return strcmp(la, lb) == 0;
}

/* "<prefix><release in lower case><suffix>" */
static void file_name(char *out, size_t cap, const char *prefix, const char *release,
                      const char *suffix) {
    char low[RELEASE_LEN + 1];
    lower_release(release, low);
    snprintf(out, cap, "%s%s%s", prefix, low, suffix);
}

static int data_path(const fa_ota *o, const char *name, char out[PATH_MAX]) {
    int n = snprintf(out, PATH_MAX, "%s/%s", o->cfg->data_dir, name);
    return n > 0 && n < PATH_MAX ? 0 : -1;
}

/* The release of "<prefix><36 characters><suffix>", or false. */
static bool release_of(const char *name, const char *prefix, const char *suffix,
                       char out[RELEASE_LEN + 1]) {
    size_t p = strlen(prefix), s = strlen(suffix), n = strlen(name);
    if (n != p + RELEASE_LEN + s || strncmp(name, prefix, p) != 0 ||
        strcmp(name + p + RELEASE_LEN, suffix) != 0)
        return false;
    for (size_t i = 0; i < RELEASE_LEN; i++) {
        char c = name[p + i];
        bool dash = i == 8 || i == 13 || i == 18 || i == 23;
        if (dash ? c != '-' : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    memcpy(out, name + p, RELEASE_LEN);
    out[RELEASE_LEN] = '\0';
    return true;
}

static void remove_file(const fa_ota *o, const char *prefix, const char *release,
                        const char *suffix) {
    char name[96];
    file_name(name, sizeof name, prefix, release, suffix);
    if (fa_store_remove(o->cfg->data_dir, name) != 0)
        fa_log("warning", "cannot remove %s/%s: %s", o->cfg->data_dir, name, strerror(errno));
}

static const char *result_text(fl_result r) {
    switch (r) {
    case FL_RESULT_INSTALLED:
        return "installed";
    case FL_RESULT_FAILED:
        return "failed";
    case FL_RESULT_REJECTED_SIGNATURE:
        return "rejected_signature";
    }
    return "?";
}

/* ---- What the offer check asks of the device ---------------------------------------------- */

static const fa_component *find_component(const fa_config *cfg, const char *code) {
    for (int i = 0; i < cfg->component_count; i++)
        if (strcmp(cfg->component[i].code, code) == 0)
            return &cfg->component[i];
    return NULL;
}

static bool installable(void *ctx, const char *component) {
    const fa_ota *o = ctx;
    const fa_component *c = find_component(o->cfg, component);
    return c != NULL &&
           (c->install == FA_INSTALL_SCRIPT || c->install == FA_INSTALL_DOCKER_COMPOSE);
}

static const char *installed_version(void *ctx, const char *component) {
    fa_ota *o = ctx;
    const fa_component *c = find_component(o->cfg, component);
    return c != NULL && fa_component_version(o->cfg, c, o->version_buf) == 0 ? o->version_buf
                                                                             : NULL;
}

/* ---- Results ------------------------------------------------------------------------------ */

static stored_result *find_result(fa_ota *o, const char *release) {
    for (int i = 0; i < o->result_count; i++)
        if (same_release(o->results[i].release, release))
            return &o->results[i];
    return NULL;
}

/* {"seq":N,"published":0|1,"payload":"<the result message>"} */
static void save_result(const fa_ota *o, const stored_result *r) {
    char json[3 * FL_RESULT_MAX], name[96];
    fl_jw w;
    fl_jw_begin(&w, json, sizeof json);
    fl_jw_int(&w, "seq", r->seq);
    fl_jw_int(&w, "published", r->published ? 1 : 0);
    fl_jw_string(&w, "payload", r->payload);
    int n = fl_jw_end(&w);
    file_name(name, sizeof name, "result-", r->release, ".json");
    if (n < 0 || fa_store_write(o->cfg->data_dir, name, json, (size_t)n, 0644) != 0)
        fa_log("warning", "cannot write %s/%s: the result is kept in memory only", o->cfg->data_dir,
               name);
}

/* A free entry: the oldest result (lowest seq) goes when all RESULTS_KEEP are used. */
static stored_result *result_slot(fa_ota *o) {
    if (o->result_count < RESULTS_KEEP)
        return &o->results[o->result_count++];
    stored_result *oldest = &o->results[0];
    for (int i = 1; i < o->result_count; i++)
        if (o->results[i].seq < oldest->seq)
            oldest = &o->results[i];
    remove_file(o, "result-", oldest->release, ".json");
    return oldest;
}

/* The one result of a release: stored first, then sent (now, or once connected). */
static void add_result(fa_ota *o, const char *release, fl_result result, const char *fw,
                       const char *detail) {
    char payload[FL_RESULT_MAX + 1];
    int len = fl_result_build(payload, sizeof payload, release, result, fw, detail);
    if (len < 0 && fw != NULL) /* a version the contract does not accept: without it */
        len = fl_result_build(payload, sizeof payload, release, result, NULL, detail);
    if (len < 0) {
        fa_log("error", "release %s: the result cannot be built (error %d)", release, len);
        return;
    }
    stored_result *r = find_result(o, release);
    if (r == NULL)
        r = result_slot(o);
    memset(r, 0, sizeof *r);
    lower_release(release, r->release);
    r->seq = o->next_seq++;
    r->send = true;
    memcpy(r->payload, payload, (size_t)len + 1);
    r->len = (size_t)len;
    save_result(o, r);
    if (detail != NULL && detail[0] != '\0')
        fa_log(result == FL_RESULT_INSTALLED ? "info" : "warning", "release %s: result %s (%s)",
               release, result_text(result), detail);
    else
        fa_log(result == FL_RESULT_INSTALLED ? "info" : "warning", "release %s: result %s", release,
               result_text(result));
}

/* Sends what waits: new results, and those not acknowledged on an earlier connection. */
static void send_results(fa_ota *o) {
    unsigned session = fa_service_session(o->svc);
    for (int i = 0; i < o->result_count; i++) {
        stored_result *r = &o->results[i];
        if (!r->send || (r->mid != 0 && r->session == session))
            continue;
        int mid = fa_service_publish(o->svc, RESULT_TOPIC, r->payload, r->len);
        if (mid < 0)
            return; /* not connected: at the next subscription */
        r->mid = mid;
        r->session = session;
    }
}

void fa_ota_published(fa_ota *o, int mid, int reason) {
    if (o == NULL || mid <= 0)
        return;
    unsigned session = fa_service_session(o->svc);
    for (int i = 0; i < o->result_count; i++) {
        stored_result *r = &o->results[i];
        if (r->mid != mid || r->session != session)
            continue;
        r->mid = 0;
        r->send = false;
        if (reason >= 0x80) {
            fa_log("warning", "release %s: the broker refused the result", r->release);
            return;
        }
        if (!r->published) {
            r->published = true;
            save_result(o, r);
        }
        fa_log("info", "release %s: result delivered", r->release);
        return;
    }
}

/* ---- Queue -------------------------------------------------------------------------------- */

/* The release leaves the queue, and its stored offer the data folder. */
static void forget_offer(fa_ota *o, const char *release) {
    fl_queue_remove(&o->queue, release);
    remove_file(o, "offer-", release, ".json");
}

static const fl_offer *queued(const fa_ota *o, const char *release) {
    for (int i = 0; i < o->queue.count; i++)
        if (same_release(o->queue.item[i].release, release))
            return &o->queue.item[i];
    return NULL;
}

/* ---- Link windows (monotonic time) ---------------------------------------------------------- */

/* Seconds of a clock that never jumps (it restarts with the agent's machine, not with the wall
 * clock): download retries are measured with it. */
static fl_time monotonic_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (fl_time)t.tv_sec;
}

/* A new link for `release` (just queued): its retry window starts now. The release is in the
 * queue, so of the FL_QUEUE_MAX slots one is its own, free, or of a release no longer queued. */
static void note_link(fa_ota *o, const char *release) {
    int slot = -1;
    for (int i = 0; i < FL_QUEUE_MAX && slot < 0; i++)
        if (o->links[i].release[0] != '\0' && same_release(o->links[i].release, release))
            slot = i;
    for (int i = 0; i < FL_QUEUE_MAX && slot < 0; i++)
        if (o->links[i].release[0] == '\0' || queued(o, o->links[i].release) == NULL)
            slot = i;
    if (slot < 0)
        return; /* not reached: link_deadline then counts from now */
    lower_release(release, o->links[slot].release);
    o->links[slot].received = monotonic_s();
}

/* The monotonic moment after which the current link of `release` is not retried any more. */
static fl_time link_deadline(const fa_ota *o, const char *release) {
    for (int i = 0; i < FL_QUEUE_MAX; i++)
        if (o->links[i].release[0] != '\0' && same_release(o->links[i].release, release))
            return o->links[i].received + FL_DOWNLOAD_RETRY_WINDOW;
    return monotonic_s() + FL_DOWNLOAD_RETRY_WINDOW;
}

/* Removes the downloads no queued release needs: every .bin (a script that never ended) but the
 * one of an apply being followed, and the .part files of releases no longer queued (except
 * `keep`). */
static void clean_downloads(fa_ota *o, const char *keep) {
    DIR *d = opendir(o->cfg->data_dir);
    if (d == NULL)
        return;
    char names[16][NAME_MAX + 1];
    int n = 0;
    struct dirent *e;
    char release[RELEASE_LEN + 1];
    while ((e = readdir(d)) != NULL && n < 16) {
        bool bin = release_of(e->d_name, "download-", ".bin", release);
        bool part = !bin && release_of(e->d_name, "download-", ".part", release);
        if (bin && o->state == JOB_APPLY && same_release(release, o->job.release))
            continue; /* apply may still read it */
        if (bin ||
            (part && queued(o, release) == NULL && (keep == NULL || !same_release(release, keep))))
            snprintf(names[n++], sizeof names[0], "%s", e->d_name);
    }
    closedir(d);
    for (int i = 0; i < n; i++)
        fa_store_remove(o->cfg->data_dir, names[i]);
}

/* ---- The job ------------------------------------------------------------------------------ */

static void stop_check(fa_ota *o) {
    if (o->checking)
        fl_download_abort(&o->check);
    o->checking = false;
}

/* Back to no job: the transfer, the hash state and the .part descriptor are released. */
static void end_job(fa_ota *o) {
    fa_http_download_free(o->http);
    o->http = NULL;
    stop_check(o);
    if (o->fd >= 0)
        close(o->fd);
    o->fd = -1;
    o->state = JOB_NONE;
}

/* The job's release gets its result; its files go. */
static void finish(fa_ota *o, fl_result result, const char *detail, const char *fw) {
    end_job(o);
    add_result(o, o->job.release, result, fw, detail);
    remove_file(o, "download-", o->job.release, ".part");
    remove_file(o, "download-", o->job.release, ".bin");
    forget_offer(o, o->job.release);
    fa_store_remove(o->cfg->data_dir, INSTALL_STATE); /* after the result: it settles it now */
    if (result == FL_RESULT_INSTALLED)
        fa_service_request_status(o->svc);
}

/* No result: the platform offers the release again (a network error or a link that cannot be
 * used is not a result). The .part stays, for a new offer of the same release. */
static void give_up(fa_ota *o, const char *why) {
    fa_log("warning", "release %s: %s: no result, waiting for a new offer", o->job.release, why);
    end_job(o);
    forget_offer(o, o->job.release);
}

/* The installed version of the job's component, for a failed result; NULL when unreadable. */
static const char *current_version(fa_ota *o) {
    return fa_component_version(o->cfg, o->comp, o->version_buf) == 0 ? o->version_buf : NULL;
}

static int start_check(fa_ota *o) {
    stop_check(o);
    if (fl_download_begin(&o->check, o->job.sha256, o->job.size) != FL_OK)
        return -1;
    o->checking = true;
    o->have = 0;
    return 0;
}

static int on_bytes(void *ctx, int status, int64_t range_start, const void *data, size_t len);

/* The next request, from the bytes already checked on. */
static void start_request(fa_ota *o, fl_time now) {
    const fl_offer *latest = queued(o, o->job.release); /* a newer offer brings a new link */
    if (latest != NULL) {
        memcpy(o->job.url, latest->url, sizeof o->job.url);
        o->job.url_expires = latest->url_expires;
    }
    if (now >= o->job.url_expires && !o->clock_warned) {
        /* Only a warning, once per job: the server says whether the link is still valid (a
         * wrong device clock must not block updates). */
        o->clock_warned = true;
        char iso[26];
        if (fl_time_format(o->job.url_expires, 0, iso) != FL_OK)
            snprintf(iso, sizeof iso, "?");
        fa_log("warning",
               "release %s: by the device clock the download link expired at %s (the device "
               "clock may be wrong): trying it, the server decides",
               o->job.release, iso);
    }
    if (ftruncate(o->fd, (off_t)o->have) != 0 || lseek(o->fd, (off_t)o->have, SEEK_SET) < 0) {
        give_up(o, "the download cannot be written");
        return;
    }
    o->request_from = o->have;
    o->progress = false;
    o->sink = SINK_OK;
    if (o->have == 0)
        fa_log("info", "release %s: downloading %llu bytes", o->job.release,
               (unsigned long long)o->job.size);
    else
        fa_log("info", "release %s: resuming the download at byte %llu of %llu", o->job.release,
               (unsigned long long)o->have, (unsigned long long)o->job.size);
    o->state = JOB_DOWNLOAD;
    /* The link comes from the offer; it is verified as the endpoint in use says (root.pem
     * through a relay, ca_file or the system authorities directly). */
    o->http = fa_http_download_start(o->job.url, fa_service_endpoint(o->svc)->https_ca, o->have,
                                     on_bytes, o);
    if (o->http == NULL) {
        o->state = JOB_RETRY;
        o->retry_at =
            fl_download_retry_at(0, o->attempt++, monotonic_s(), link_deadline(o, o->job.release));
        if (o->retry_at < 0)
            give_up(o, "the download cannot start");
    }
}

/* From byte 0 again, with a new check. */
static void restart_from_zero(fa_ota *o, fl_time now) {
    if (start_check(o) != 0) {
        give_up(o, "the check of the download cannot start");
        return;
    }
    o->from_disk = false;
    start_request(o, now);
}

/* Starts the job of the release in o->job: space, the .part (hashed again when it has bytes),
 * then the download. */
static void begin_download(fa_ota *o, fl_time now) {
    char name[96], path[PATH_MAX];
    file_name(name, sizeof name, "download-", o->job.release, ".part");
    if (data_path(o, name, path) != 0) {
        give_up(o, "the data folder path is too long");
        return;
    }
    struct stat st;
    uint64_t on_disk = 0;
    if (lstat(path, &st) == 0 && S_ISREG(st.st_mode) && (uint64_t)st.st_size <= o->job.size)
        on_disk = (uint64_t)st.st_size;

    struct statvfs vfs;
    if (statvfs(o->cfg->data_dir, &vfs) == 0) {
        uint64_t free_bytes = (uint64_t)vfs.f_bavail * (uint64_t)vfs.f_frsize;
        uint64_t needed = (o->job.size - on_disk) + SPACE_MARGIN;
        if (free_bytes < needed) {
            fa_log("warning", "release %s: %llu bytes needed in %s, %llu free", o->job.release,
                   (unsigned long long)needed, o->cfg->data_dir, (unsigned long long)free_bytes);
            finish(o, FL_RESULT_FAILED, "no_space", NULL);
            return;
        }
    } else {
        fa_log("warning", "release %s: the free space of %s cannot be read: %s", o->job.release,
               o->cfg->data_dir, strerror(errno));
    }

    o->fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (o->fd < 0) {
        fa_log("error", "cannot open %s: %s", path, strerror(errno));
        give_up(o, "the download cannot be written");
        return;
    }
    if (start_check(o) != 0) {
        give_up(o, "the check of the download cannot start");
        return;
    }
    o->on_disk = on_disk;
    o->from_disk = on_disk > 0;
    o->restarted = false;
    o->clock_warned = false;
    o->attempt = 0;
    if (on_disk > 0) {
        fa_log("info", "release %s: checking the %llu bytes already downloaded", o->job.release,
               (unsigned long long)on_disk);
        o->state = JOB_REHASH;
        return;
    }
    start_request(o, now);
}

static void verify(fa_ota *o, fl_time now);

/* REHASH: a piece of the .part per turn into the check; then the download goes on from there. */
static void rehash(fa_ota *o, fl_time now) {
    static unsigned char buf[64 * 1024];
    uint64_t done = 0;
    while (o->have < o->on_disk && done < REHASH_CHUNK) {
        uint64_t left = o->on_disk - o->have;
        size_t want = left < sizeof buf ? (size_t)left : sizeof buf;
        ssize_t n = pread(o->fd, buf, want, (off_t)o->have);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) { /* shorter than it was, or unreadable: keep what was hashed */
            o->on_disk = o->have;
            break;
        }
        if (fl_download_update(&o->check, buf, (size_t)n) != FL_OK) {
            give_up(o, "the check of the download failed");
            return;
        }
        o->have += (uint64_t)n;
        done += (uint64_t)n;
    }
    if (o->have < o->on_disk)
        return; /* next turn */
    if (o->have == o->job.size)
        verify(o, now);
    else
        start_request(o, now);
}

/* The body of the answer, as it arrives. */
static int on_bytes(void *ctx, int status, int64_t range_start, const void *data, size_t len) {
    fa_ota *o = ctx;
    if (status != 200 && status != 206)
        return 0; /* the body of an error answer is not the file */
    if (!o->progress && status == 206 && range_start != (int64_t)o->request_from) {
        o->sink = SINK_RANGE;
        return -1;
    }
    if (!o->progress && status == 200 && o->request_from > 0) {
        /* The server ignored the Range: the whole file comes again, from byte 0. */
        if (start_check(o) != 0) {
            o->sink = SINK_CRYPTO;
            return -1;
        }
        if (ftruncate(o->fd, 0) != 0 || lseek(o->fd, 0, SEEK_SET) < 0) {
            o->sink_errno = errno;
            o->sink = SINK_WRITE;
            return -1;
        }
        o->request_from = 0;
        o->from_disk = false;
    }
    if ((uint64_t)len > o->job.size - o->have) {
        fl_download_update(&o->check, data, len); /* past the size: finish says size_mismatch */
        o->sink = SINK_TOO_LONG;
        return -1;
    }
    const char *p = data;
    size_t left = len;
    while (left > 0) {
        ssize_t n = write(o->fd, p, left);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            o->sink_errno = errno;
            o->sink = errno == ENOSPC || errno == EDQUOT ? SINK_NO_SPACE : SINK_WRITE;
            return -1;
        }
        p += n;
        left -= (size_t)n;
    }
    if (fl_download_update(&o->check, data, len) != FL_OK) {
        o->sink = SINK_CRYPTO;
        return -1;
    }
    o->have += len;
    o->progress = true;
    return 0;
}

/* The boot id of the running system (a new one at every boot), "" when unreadable. The path can
 * be changed with the environment variable FIRMLINE_BOOT_ID_FILE: for the integration tests only,
 * which play a reboot without rebooting. */
static void boot_id(char out[65]) {
    const char *path = getenv("FIRMLINE_BOOT_ID_FILE");
    if (path == NULL || path[0] == '\0')
        path = "/proc/sys/kernel/random/boot_id";
    char buf[128];
    FILE *f = fopen(path, "r");
    size_t n = f != NULL ? fread(buf, 1, sizeof buf, f) : 0;
    if (f != NULL)
        fclose(f);
    if (fa_first_line_value(buf, n, out) != 0)
        out[0] = '\0';
}

/* install.json for the job: {release, component, version, state, bootId}. state "running" while
 * the script runs, "reboot" after it exited 10. 0, or -1. */
static int save_install_state(fa_ota *o, const char *state) {
    char json[512], boot[65];
    boot_id(boot);
    fl_jw w;
    fl_jw_begin(&w, json, sizeof json);
    fl_jw_string(&w, "release", o->job.release);
    fl_jw_string(&w, "component", o->comp->code);
    fl_jw_string(&w, "version", o->job.version);
    fl_jw_string(&w, "state", state);
    fl_jw_string(&w, "bootId", boot);
    int n = fl_jw_end(&w);
    if (n < 0 || fa_store_write(o->cfg->data_dir, INSTALL_STATE, json, (size_t)n, 0644) != 0) {
        fa_log("error", "cannot write %s/%s", o->cfg->data_dir, INSTALL_STATE);
        return -1;
    }
    return 0;
}

/* ---- install = docker-compose: apply in a container of its own ----------------------------- */

static long long monotonic_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* The agent's own container (ruling 5), looked up once: 0, or -1 outside a container. */
static int own_container(fa_ota *o) {
    return o->own_id[0] != '\0' ? 0 : fa_docker_own_container(o->own_id);
}

typedef enum { APPLY_NONE, APPLY_ENDED, APPLY_ALIVE, APPLY_UNKNOWN } apply_presence;

/* Whether a container named firmline-apply exists, and whether it has ended (created, exited,
 * dead) or still runs (running, restarting, paused, or being removed after its end). */
static apply_presence apply_container(void) {
    static char out[16384];
    const char *argv[] = {"ps",         "--all",
                          "--no-trunc", "--filter=name=" APPLY_CONTAINER,
                          "--format",   "{{.Names}} {{.State}}",
                          NULL};
    if (fa_docker_run(argv, out, sizeof out, DOCKER_QUICK_MS) != 0)
        return APPLY_UNKNOWN;
    char *rest = NULL;
    for (char *line = strtok_r(out, "\n", &rest); line != NULL;
         line = strtok_r(NULL, "\n", &rest)) {
        char *space = strchr(line, ' ');
        if (space == NULL)
            continue;
        *space = '\0';
        if (strcmp(line, APPLY_CONTAINER) != 0) /* the filter matches parts of names too */
            continue;
        const char *state = space + 1;
        return strcmp(state, "created") == 0 || strcmp(state, "exited") == 0 ||
                       strcmp(state, "dead") == 0
                   ? APPLY_ENDED
                   : APPLY_ALIVE;
    }
    return APPLY_NONE;
}

/* docker run --detach --rm --name firmline-apply --volumes-from <agent> [--entrypoint=<e>]
 * <the agent's image ID> <args>: the same image and mounts as the agent (socket, data folder,
 * composition folder, configuration). A firmline-apply container that has ended is removed
 * first. 0, or -1 (logged). */
static int run_apply_container(fa_ota *o, const char *entrypoint, const char *const args[]) {
    char image[256];
    const char *inspect[] = {"inspect", "--type=container", "--format={{.Image}}", o->own_id, NULL};
    if (own_container(o) != 0) {
        fa_log("error", "release %s: not in a container: no %s container can be started",
               o->job.release, APPLY_CONTAINER);
        return -1;
    }
    if (fa_docker_run(inspect, image, sizeof image, DOCKER_QUICK_MS) != 0)
        image[0] = '\0';
    image[strcspn(image, "\n")] = '\0';
    if (!fa_package_id_ok(image)) {
        fa_log("error", "release %s: the image of the agent's container %.12s cannot be read",
               o->job.release, o->own_id);
        return -1;
    }
    if (apply_container() == APPLY_ENDED) {
        const char *rm[] = {"rm", APPLY_CONTAINER, NULL};
        if (fa_docker_run(rm, NULL, 0, DOCKER_QUICK_MS) == 0)
            fa_log("info", "release %s: the %s container left by an earlier run is removed",
                   o->job.release, APPLY_CONTAINER);
    }
    char volumes[96], entry[64];
    snprintf(volumes, sizeof volumes, "--volumes-from=%s", o->own_id);
    const char *argv[FA_COMMAND_MAX_ARGS];
    int n = 0;
    argv[n++] = "run";
    argv[n++] = "--detach";
    argv[n++] = "--rm";
    argv[n++] = "--name=" APPLY_CONTAINER;
    argv[n++] = volumes;
    if (entrypoint != NULL) {
        snprintf(entry, sizeof entry, "--entrypoint=%s", entrypoint);
        argv[n++] = entry;
    }
    argv[n++] = image;
    for (int i = 0; args[i] != NULL && n < FA_COMMAND_MAX_ARGS - 1; i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    if (fa_docker_run(argv, NULL, 0, DOCKER_RUN_MS) != 0) {
        fa_log("error", "release %s: the %s container cannot be started", o->job.release,
               APPLY_CONTAINER);
        return -1;
    }
    return 0;
}

/* The folder and the file name of compose_file (an absolute path). 0, or -1. */
static int split_compose_file(const fa_component *c, char dir[256], char name[256]) {
    const char *slash = strrchr(c->compose_file, '/');
    if (slash == NULL || slash[1] == '\0')
        return -1;
    size_t dir_len = slash == c->compose_file ? 1 : (size_t)(slash - c->compose_file);
    memcpy(dir, c->compose_file, dir_len);
    dir[dir_len] = '\0';
    snprintf(name, 256, "%s", slash + 1);
    return 0;
}

/* What an apply cut short leaves of its own: apply.tmp (up to the size of the package: left
 * there, it would fail the free-space check of every next download, which comes before the next
 * apply), <compose_file>.new, and compose-previous.yml (the composition before it). With put_back
 * the latter is written to compose_file first when the two differ: the cut came after apply had
 * put the new composition in place, before package.json (apply.h, step 6), so the composition
 * goes back with the version. */
static void drop_apply_files(fa_ota *o, bool put_back) {
    char dir[256], name[256], new_name[300];
    fa_apply_remove_work(o->cfg->data_dir);
    if (split_compose_file(o->comp, dir, name) != 0)
        return;
    char *previous = NULL, *current = NULL;
    size_t previous_len = 0, current_len = 0;
    if (put_back &&
        fa_store_read(o->cfg->data_dir, FA_APPLY_PREVIOUS, &previous, &previous_len) == 0) {
        bool same = fa_store_read(dir, name, &current, &current_len) == 0 &&
                    current_len == previous_len && memcmp(current, previous, current_len) == 0;
        free(current);
        if (!same && fa_store_write(dir, name, previous, previous_len, 0644) != 0) {
            fa_log("error", "release %s: cannot write the previous composition back to %s (%s)",
                   o->job.release, o->comp->compose_file, strerror(errno));
            free(previous);
            return; /* compose-previous.yml stays */
        }
        if (!same)
            fa_log("warning", "release %s: %s is the previous composition again", o->job.release,
                   o->comp->compose_file);
        free(previous);
    }
    if (fa_store_remove(o->cfg->data_dir, FA_APPLY_PREVIOUS) != 0)
        fa_log("warning", "cannot remove %s/%s: %s", o->cfg->data_dir, FA_APPLY_PREVIOUS,
               strerror(errno));
    snprintf(new_name, sizeof new_name, "%s.new", name);
    if (fa_store_remove(dir, new_name) != 0)
        fa_log("warning", "cannot remove %s/%s: %s", dir, new_name, strerror(errno));
}

/* After an apply cut short the composition that runs may be the new one, never checked: the
 * composition of compose_file is brought up again as Torizon starts it, so that the device runs
 * what the file says. In a firmline-apply container too, since this agent's container may be
 * one of those it recreates. */
static void bring_up(fa_ota *o) {
    char project[96], file[300];
    snprintf(project, sizeof project, "--project-name=%s", o->comp->project);
    snprintf(file, sizeof file, "--file=%s", o->comp->compose_file);
    const char *args[] = {"compose",          project,        file, "up", "--detach",
                          "--remove-orphans", "--pull=never", NULL};
    fa_log("info", "release %s: bringing the composition of %s up again", o->job.release,
           o->comp->compose_file);
    if (run_apply_container(o, "docker", args) != 0)
        fa_log("error", "release %s: the composition of %s is not brought up again", o->job.release,
               o->comp->compose_file);
}

/* The outcome of the job's release in apply.json: true with the result, its detail ("" for
 * none) and version ("" for none); false while there is none (missing, another release's,
 * `running`, unreadable). */
static bool apply_outcome(fa_ota *o, fl_result *result, char detail[32], char version[65]) {
    char *text = NULL;
    size_t len = 0;
    if (fa_store_read(o->cfg->data_dir, FA_APPLY_STATE, &text, &len) != 0)
        return false;
    fl_json j;
    char release[RELEASE_LEN + 2], state[16], read_detail[32];
    bool ok = fl_json_parse(&j, text, len) == FL_OK &&
              fl_json_string(&j, "release", release, sizeof release) == FL_OK &&
              strlen(release) == RELEASE_LEN && same_release(release, o->job.release) &&
              fl_json_string(&j, "state", state, sizeof state) == FL_OK;
    if (ok && fl_json_string(&j, "version", version, 65) != FL_OK)
        version[0] = '\0';
    if (ok && fl_json_string(&j, "detail", read_detail, sizeof read_detail) != FL_OK)
        read_detail[0] = '\0';
    free(text);
    if (!ok)
        return false;
    detail[0] = '\0';
    if (strcmp(state, "installed") == 0) {
        *result = FL_RESULT_INSTALLED;
        if (version[0] == '\0')
            snprintf(version, 65, "%s", o->job.version);
        return true;
    }
    if (strcmp(state, "failed") == 0) {
        *result = FL_RESULT_FAILED;
        snprintf(detail, 32, "%s",
                 strcmp(read_detail, "health_check_failed") == 0 ? read_detail : "install_failed");
        return true;
    }
    return false;
}

/* apply has gone without an outcome in apply.json: stopped, cut by a restart or a power loss, or
 * never started. The version tells whether its last step was done (package.json is written
 * only after the health check): then the release is installed; else it failed install_failed and
 * the composition before it is put back. Either way compose_file is brought up again. */
static void apply_cut(fa_ota *o) {
    fa_log("warning", "release %s: the apply container ended without an outcome", o->job.release);
    const char *now = current_version(o);
    if (now != NULL && strcmp(now, o->job.version) == 0) {
        fa_log("info", "release %s: version %s is in place: it passed the health check",
               o->job.release, now);
        drop_apply_files(o, false);
        finish(o, FL_RESULT_INSTALLED, NULL, o->job.version);
    } else {
        drop_apply_files(o, true);
        finish(o, FL_RESULT_FAILED, "install_failed", current_version(o));
    }
    bring_up(o);
}

/* How long an earlier firmline-apply container is waited for before apply starts: APPLY_WAIT_S,
 * or the seconds (1 to APPLY_WAIT_S) of the environment variable FIRMLINE_APPLY_WAIT_S: for the
 * integration tests only, which cannot wait 30 minutes. */
static int apply_wait_s(void) {
    const char *text = getenv("FIRMLINE_APPLY_WAIT_S");
    char *end = NULL;
    long s = text != NULL && text[0] != '\0' ? strtol(text, &end, 10) : 0;
    return end != NULL && *end == '\0' && s >= 1 && s <= APPLY_WAIT_S ? (int)s : APPLY_WAIT_S;
}

/* The job follows the apply of o->job from now on (o->apply_started: already started). */
static void begin_apply(fa_ota *o, bool started) {
    o->state = JOB_APPLY;
    o->apply_started = started;
    o->apply_waiting_since_ms = 0;
    o->apply_silent_since_ms = 0;
    o->apply_next_ms = 0;
}

/* APPLY: once a second. Before apply runs, an earlier firmline-apply container that still runs
 * (an apply removing old images after its outcome, a composition being brought up) is waited
 * for, never removed, up to 30 minutes: then the release fails install_failed. Then the outcome in
 * apply.json, or the container's end without one. Nothing is decided while the agent stops: the
 * next start follows it again. */
static void apply_step(fa_ota *o) {
    long long now = monotonic_ms();
    if (now < o->apply_next_ms || o->stopping || fa_service_stopping(o->svc))
        return;
    o->apply_next_ms = now + APPLY_POLL_MS;
    apply_presence presence = apply_container();
    if (presence == APPLY_UNKNOWN) {
        /* Measured from the first look without an answer (a look may itself wait up to
         * DOCKER_QUICK_MS): docker silent that long is taken as the container gone. */
        if (o->apply_silent_since_ms == 0)
            o->apply_silent_since_ms = now;
        if (monotonic_ms() - o->apply_silent_since_ms < APPLY_UNANSWERED_MS)
            return;
        fa_log("warning", "release %s: docker has not answered for %d s", o->job.release,
               APPLY_UNANSWERED_MS / 1000);
        presence = APPLY_NONE;
    }
    o->apply_silent_since_ms = 0;
    if (!o->apply_started) {
        if (presence == APPLY_ALIVE) {
            if (o->apply_waiting_since_ms == 0) {
                fa_log("info", "release %s: an earlier %s container still runs: waiting for it",
                       o->job.release, APPLY_CONTAINER);
                o->apply_waiting_since_ms = now;
            }
            int limit = apply_wait_s();
            if (now - o->apply_waiting_since_ms < (long long)limit * 1000)
                return;
            /* Paused, restarted by a policy, hung, or someone else's: nothing of this release
             * has touched the device yet, so it fails here and the queue goes on; the container
             * is left as it is. */
            if (limit % 60 == 0)
                fa_log("warning", "release %s: an earlier %s container still runs after %d min",
                       o->job.release, APPLY_CONTAINER, limit / 60);
            else
                fa_log("warning", "release %s: an earlier %s container still runs after %d s",
                       o->job.release, APPLY_CONTAINER, limit);
            finish(o, FL_RESULT_FAILED, "install_failed", current_version(o));
            return;
        }
        /* A stop before this point leaves no install.json: at the next start the stored offer
         * is queued again, as for any release not yet installed. */
        if (save_install_state(o, "apply") != 0) {
            remove_file(o, "download-", o->job.release, ".bin");
            give_up(o, "the installation cannot be recorded");
            return;
        }
        fa_log("info", "release %s: installing %s version %s with apply in the container %s",
               o->job.release, o->comp->code, o->job.version, APPLY_CONTAINER);
        const char *args[] = {"apply", "--release", o->job.release, "--config", o->cfg->path, NULL};
        o->apply_started = true;
        run_apply_container(o, NULL, args); /* when it cannot start, it ends without an outcome */
        return;
    }
    fl_result result;
    char detail[32], version[65];
    if (apply_outcome(o, &result, detail, version)) { /* read after the look at the container */
        finish(o, result, detail[0] != '\0' ? detail : NULL, version[0] != '\0' ? version : NULL);
        return;
    }
    if (presence == APPLY_NONE || presence == APPLY_ENDED)
        apply_cut(o);
}

/* install.json in the state "apply" at start: the apply of the former run (or of the agent this
 * one replaces) is followed until its outcome. */
static void follow_apply(fa_ota *o, const char *release, const char *version,
                         const fa_component *c) {
    memset(&o->job, 0, sizeof o->job);
    snprintf(o->job.release, sizeof o->job.release, "%s", release);
    snprintf(o->job.component, sizeof o->job.component, "%s", c->code);
    snprintf(o->job.version, sizeof o->job.version, "%s", version);
    o->comp = c;
    begin_apply(o, true);
    fa_log("info", "release %s: following its installation in the container %s", release,
           APPLY_CONTAINER);
}

static void start_install(fa_ota *o) {
    char part[96], bin[96], path[PATH_MAX];
    file_name(part, sizeof part, "download-", o->job.release, ".part");
    file_name(bin, sizeof bin, "download-", o->job.release, ".bin");
    end_job(o); /* closes the .part */
    /* The version again right before the script: another release may have installed a newer one
     * since the offer was checked (no rollback without `rollback`). */
    const char *installed = current_version(o);
    if (!o->job.rollback && fl_version_too_old(o->job.version, installed)) {
        fa_log("warning", "release %s: %s %s is installed now", o->job.release, o->comp->code,
               installed);
        finish(o, FL_RESULT_FAILED, "older_version", NULL);
        return;
    }
    if (fa_store_rename(o->cfg->data_dir, part, bin) != 0 || data_path(o, bin, path) != 0) {
        fa_log("error", "cannot rename %s/%s: %s", o->cfg->data_dir, part, strerror(errno));
        give_up(o, "the verified file cannot be kept");
        return;
    }
    /* Recorded before the script (or apply) starts: a stop or a power loss while it runs must not
     * make the release look new at the next start (installed again, or refused as
     * older_version). */
    if (o->comp->install == FA_INSTALL_DOCKER_COMPOSE) {
        begin_apply(o, false); /* started (and recorded) once no other apply runs */
        return;
    }
    if (save_install_state(o, "running") != 0) {
        remove_file(o, "download-", o->job.release, ".bin");
        give_up(o, "the installation cannot be recorded");
        return;
    }
    fa_log("info", "release %s: installing %s version %s with %s", o->job.release, o->comp->code,
           o->job.version, o->comp->script);
    if (fa_install_script_start(&o->child, o->comp, path, o->job.version, o->job.release) != 0) {
        finish(o, FL_RESULT_FAILED, "install_failed", current_version(o));
        return;
    }
    o->state = JOB_INSTALL;
}

/* The whole file arrived: nothing is installed unless fl_download_finish accepts it. */
static void verify(fa_ota *o, fl_time now) {
    const char *detail = NULL;
    int rc = fl_download_finish(&o->check, &detail);
    o->checking = false;
    if (rc == FL_OK) {
        fa_log("info", "release %s: downloaded and verified", o->job.release);
        start_install(o);
        return;
    }
    if (rc != FL_ERR_FORMAT) {
        give_up(o, "the check of the download failed");
        return;
    }
    if (o->from_disk) {
        /* Bytes of a former run may not have reached the disk whole (power loss): the file is
         * downloaded again from the start once before it counts as a wrong file. */
        fa_log("warning",
               "release %s: the file does not match (%s) after resuming from the bytes on disk: "
               "downloading it again from the start",
               o->job.release, detail);
        restart_from_zero(o, now);
        return;
    }
    fa_log("warning", "release %s: the downloaded file does not match the manifest (%s)",
           o->job.release, detail);
    finish(o, FL_RESULT_REJECTED_SIGNATURE, detail, NULL);
}

/* DOWNLOAD: the transfer moves on; at its end, the next step. */
static void download_step(fa_ota *o, fl_time now) {
    fa_http_outcome out;
    if (fa_http_download_step(o->http, &out) == 1)
        return;
    fa_http_download_free(o->http);
    o->http = NULL;
    if (o->progress)
        o->attempt = 0;
    switch (o->sink) {
    case SINK_TOO_LONG:
        verify(o, now);
        return;
    case SINK_NO_SPACE:
        finish(o, FL_RESULT_FAILED, "no_space", NULL);
        return;
    case SINK_WRITE:
        fa_log("error", "release %s: cannot write the download: %s", o->job.release,
               strerror(o->sink_errno));
        give_up(o, "the download cannot be written");
        return;
    case SINK_CRYPTO:
        give_up(o, "the check of the download failed");
        return;
    case SINK_RANGE:
    case SINK_OK:
        break;
    }
    if (o->sink == SINK_OK && out.complete && (out.status == 200 || out.status == 206)) {
        verify(o, now);
        return;
    }
    if (o->sink == SINK_RANGE || (out.complete && out.status == 416)) {
        if (o->restarted) {
            give_up(o, "the server does not resume the download");
            return;
        }
        o->restarted = true;
        fa_log("warning", "release %s: the server refused the range: downloading from the start",
               o->job.release);
        restart_from_zero(o, now);
        return;
    }
    int status = out.complete ? out.status : 0;
    fl_time mono = monotonic_s();
    fl_time at = fl_download_retry_at(status, o->attempt, mono, link_deadline(o, o->job.release));
    char why[160];
    if (status == 0)
        snprintf(why, sizeof why, "download interrupted (%s)", out.reason);
    else
        snprintf(why, sizeof why, "download refused (HTTP %d)", status);
    if (at < 0) {
        give_up(o, why);
        return;
    }
    o->attempt++;
    o->retry_at = at;
    o->state = JOB_RETRY;
    fa_log("warning", "release %s: %s; next attempt in %lld s", o->job.release, why,
           (long long)(at - mono));
}

/* A script exited 10: the installation completes at the next start. */
static void install_later(fa_ota *o) {
    if (save_install_state(o, "reboot") != 0) {
        fa_log("error", "release %s: the installation cannot be followed after the restart",
               o->job.release);
        finish(o, FL_RESULT_FAILED, "install_failed", current_version(o));
        return;
    }
    remove_file(o, "download-", o->job.release, ".bin");
    forget_offer(o, o->job.release);
    end_job(o);
    o->reboot_pending = true;
    lower_release(o->job.release, o->reboot_release);
    fa_log("info", "release %s: installed at the next start of the device", o->job.release);
    if (o->stopping) /* the agent stops (the system may be going down already) */
        return;
    if (o->cfg->reboot_command[0] == '\0') {
        fa_log("info", "no reboot_command: the install script restarts the device");
        return;
    }
    fa_log("info", "running reboot_command");
    if (fa_reboot_start(&o->child, o->cfg->reboot_command) == 0)
        o->state = JOB_REBOOT;
}

static void install_step(fa_ota *o) {
    int code = -1;
    bool timed_out = false;
    if (fa_child_poll(&o->child, &code, &timed_out) == 1)
        return;
    if (timed_out) {
        fa_log("warning", "release %s: the install script did not end within %d s: stopped",
               o->job.release, o->comp->timeout_s);
        finish(o, FL_RESULT_FAILED, "install_failed", current_version(o));
    } else if (code == 0) {
        finish(o, FL_RESULT_INSTALLED, NULL, o->job.version);
    } else if (code == FA_SCRIPT_LATER) {
        install_later(o);
    } else if (code < 0 && (o->stopping || fa_service_stopping(o->svc))) {
        /* The stop signal reached the script too (the unit uses KillMode=mixed, which avoids it,
         * but another setup may signal the whole group): its death
         * says nothing of the update, which may already be in place. install.json stays
         * "running", and the next start decides from the version. */
        fa_log("warning",
               "release %s: the install script was ended by a signal while the agent stops: "
               "settled at the next start",
               o->job.release);
        end_job(o);
    } else {
        if (code < 0)
            fa_log("warning", "release %s: the install script was ended by a signal",
                   o->job.release);
        else
            fa_log("warning", "release %s: the install script exited with %d", o->job.release,
                   code);
        finish(o, FL_RESULT_FAILED, "install_failed", current_version(o));
    }
}

static void reboot_step(fa_ota *o) {
    int code = -1;
    bool timed_out = false;
    if (fa_child_poll(&o->child, &code, &timed_out) == 1)
        return;
    if (code == 0)
        fa_log("info", "reboot_command ended; waiting for the restart");
    else
        fa_log("warning", "reboot_command %s; the update completes at the next start",
               timed_out ? "did not end within 60 s" : "failed");
    o->state = JOB_NONE; /* reboot_pending stays: nothing more until the restart */
}

static void start_next(fa_ota *o, fl_time now) {
    if (o->state != JOB_NONE || o->reboot_pending)
        return;
    const fl_offer *next = fl_queue_next(&o->queue, now);
    if (next == NULL)
        return;
    fl_offer d = *next;
    /* The offer is checked again now, with the time and the versions installed now: since it was
     * queued, another release may have installed a newer version (no rollback through the queue),
     * and notBefore may not have passed yet. */
    char name[96];
    char *text = NULL;
    size_t len = 0;
    file_name(name, sizeof name, "offer-", d.release, ".json");
    if (fa_store_read(o->cfg->data_dir, name, &text, &len) == 0) {
        char release[RELEASE_LEN + 1];
        lower_release(d.release, release);
        int rc = fl_offer_check(&o->dev, text, len, now, &d);
        free(text);
        if (rc != FL_OK || d.action == FL_OFFER_IGNORE || !same_release(d.release, release)) {
            fa_log("warning", "release %s: the queued offer no longer passes the check (error %d)",
                   release, rc);
            forget_offer(o, release);
            return;
        }
        if (d.action == FL_OFFER_REJECT) {
            fa_log("warning", "release %s: queued offer refused", d.release);
            add_result(o, d.release, d.result, NULL, d.detail);
            forget_offer(o, d.release);
            remove_file(o, "download-", d.release, ".part");
            return;
        }
        fl_queue_put(&o->queue, &d); /* same release: replaced in place */
        if (d.action == FL_OFFER_WAIT)
            return; /* notBefore not reached by this clock: it stays queued */
    } else if (!d.rollback && fl_version_too_old(d.version, installed_version(o, d.component))) {
        /* The stored offer is missing (it could not be written): the version at least. */
        add_result(o, d.release, FL_RESULT_FAILED, NULL, "older_version");
        forget_offer(o, d.release);
        return;
    }
    o->job = d;
    o->comp = find_component(o->cfg, o->job.component);
    if (o->comp == NULL || o->comp->install == FA_INSTALL_NONE) { /* checked with the offer */
        finish(o, FL_RESULT_FAILED, "component_mismatch", NULL);
        return;
    }
    if (o->comp->install == FA_INSTALL_DOCKER_COMPOSE && own_container(o) != 0) {
        /* apply must outlive the agent's container: without one, nothing to download */
        fa_log("warning",
               "release %s: not in a container: %s (install = docker-compose) is installed only "
               "by an agent running in a Docker container",
               o->job.release, o->comp->code);
        finish(o, FL_RESULT_FAILED, "install_failed", current_version(o));
        return;
    }
    clean_downloads(o, o->job.release);
    begin_download(o, now);
}

/* ---- Offers ------------------------------------------------------------------------------- */

/* What to do with a checked offer: `stored` is true when it comes from the data folder. */
static void take_offer(fa_ota *o, const fl_offer *d, const char *raw, size_t len, bool stored) {
    char iso[26];
    stored_result *r = find_result(o, d->release);
    if (r != NULL) { /* the result went out and was lost: the same result again, nothing else */
        fa_log("info", "release %s: result already sent: sending it again", d->release);
        r->send = true;
        if (stored)
            remove_file(o, "offer-", d->release, ".json");
        return;
    }
    if (o->reboot_pending && same_release(d->release, o->reboot_release)) {
        fa_log("info", "release %s: installed at the next start: offer ignored", d->release);
        return;
    }
    bool active = o->state != JOB_NONE && same_release(d->release, o->job.release);
    if (d->action == FL_OFFER_REJECT) {
        if (active) { /* the release being installed: its own outcome counts */
            fa_log("info", "release %s: offer refused while it is being installed: ignored",
                   d->release);
            return;
        }
        fa_log("warning", "release %s: offer refused", d->release);
        add_result(o, d->release, d->result, NULL, d->detail);
        forget_offer(o, d->release);
        remove_file(o, "download-", d->release, ".part");
        return;
    }
    if (!stored) {
        char name[96];
        file_name(name, sizeof name, "offer-", d->release, ".json");
        if (fa_store_write(o->cfg->data_dir, name, raw, len, 0600) != 0)
            fa_log("warning", "cannot write %s/%s: the offer is lost at a restart",
                   o->cfg->data_dir, name);
    }
    if (fl_queue_put(&o->queue, d) != FL_OK) {
        fa_log("warning", "release %s: the queue is full (%d releases): offer dropped", d->release,
               FL_QUEUE_MAX);
        remove_file(o, "offer-", d->release, ".json");
        return;
    }
    note_link(o, d->release); /* a new link, or one read again at start: retried from now */
    if (active)
        fa_log("info", "release %s: new download link", d->release);
    else if (d->action == FL_OFFER_WAIT && fl_time_format(d->wait_until, 0, iso) == FL_OK)
        fa_log("info", "release %s: offer queued (component %s, version %s), not before %s",
               d->release, d->component, d->version, iso);
    else
        fa_log("info", "release %s: offer queued (component %s, version %s)", d->release,
               d->component, d->version);
}

void fa_ota_offer(fa_ota *o, const char *payload, size_t len, fl_time now) {
    fl_offer d;
    int rc = fl_offer_check(&o->dev, payload, len, now, &d);
    if (rc != FL_OK) {
        fa_log("error", "an offer cannot be checked (error %d): dropped, the platform offers again",
               rc);
        return;
    }
    if (d.action == FL_OFFER_IGNORE) {
        fa_log("warning", "an offer without a readable manifest or release was ignored");
        return;
    }
    take_offer(o, &d, payload, len, false);
}

/* ---- Start -------------------------------------------------------------------------------- */

static void load_results(fa_ota *o) {
    DIR *d = opendir(o->cfg->data_dir);
    if (d == NULL)
        return;
    struct dirent *e;
    char release[RELEASE_LEN + 1];
    while ((e = readdir(d)) != NULL) {
        if (!release_of(e->d_name, "result-", ".json", release))
            continue;
        char *text = NULL;
        size_t len = 0;
        stored_result r;
        memset(&r, 0, sizeof r);
        fl_json j, p;
        int64_t published = 0;
        char payload_release[RELEASE_LEN + 2];
        bool ok = fa_store_read(o->cfg->data_dir, e->d_name, &text, &len) == 0 &&
                  fl_json_parse(&j, text, len) == FL_OK &&
                  fl_json_int(&j, "seq", &r.seq) == FL_OK &&
                  fl_json_int(&j, "published", &published) == FL_OK &&
                  fl_json_string(&j, "payload", r.payload, sizeof r.payload) == FL_OK &&
                  fl_json_parse(&p, r.payload, strlen(r.payload)) == FL_OK &&
                  fl_json_string(&p, "release", payload_release, sizeof payload_release) == FL_OK &&
                  same_release(payload_release, release) && strlen(payload_release) == RELEASE_LEN;
        free(text);
        if (!ok) {
            fa_log("warning", "%s/%s cannot be read: removed", o->cfg->data_dir, e->d_name);
            fa_store_remove(o->cfg->data_dir, e->d_name);
            continue;
        }
        memcpy(r.release, release, sizeof r.release);
        r.published = published != 0;
        r.send = !r.published;
        r.len = strlen(r.payload);
        if (r.seq >= o->next_seq)
            o->next_seq = r.seq + 1;
        *result_slot(o) = r;
    }
    closedir(d);
}

/* An installation the former run left (install.json), settled before the queue is rebuilt: its
 * release is never checked again as a new offer.
 *  - the component reports the manifest version: installed;
 *  - state "running" (the script was stopped with the agent, or the power went): install_failed;
 *  - state "reboot" (the script exited 10): a new boot without the version is boot_failed; in the
 *    same boot (only the agent restarted) it keeps waiting for the reboot, with no result and
 *    nothing run again;
 *  - state "apply" (install = docker-compose): before anything else, its apply is followed as if
 *    this run had started it (apply_step). When the component is no longer install =
 *    docker-compose (its configuration changed), there is no apply to follow: as "running", with
 *    apply's files in the data folder removed (compose-previous.yml, apply.tmp), never a reboot.
 */
static void settle_install(fa_ota *o) {
    char *text = NULL;
    size_t len = 0;
    if (fa_store_read(o->cfg->data_dir, INSTALL_STATE, &text, &len) != 0)
        return;
    fl_json j;
    char release[RELEASE_LEN + 2], component[65], version[65], now_version[65];
    char state[16] = "reboot", stored_boot[65] = "", boot[65];
    bool ok = fl_json_parse(&j, text, len) == FL_OK &&
              fl_json_string(&j, "release", release, sizeof release) == FL_OK &&
              strlen(release) == RELEASE_LEN &&
              fl_json_string(&j, "component", component, sizeof component) == FL_OK &&
              fl_json_string(&j, "version", version, sizeof version) == FL_OK;
    if (ok && fl_json_string(&j, "state", state, sizeof state) != FL_OK)
        snprintf(state, sizeof state, "reboot");
    if (ok && fl_json_string(&j, "bootId", stored_boot, sizeof stored_boot) != FL_OK)
        stored_boot[0] = '\0';
    free(text);
    const fa_component *c = ok ? find_component(o->cfg, component) : NULL;
    if (c == NULL) {
        fa_log("warning", "%s/%s cannot be read or names an unknown component: removed",
               o->cfg->data_dir, INSTALL_STATE);
        fa_store_remove(o->cfg->data_dir, INSTALL_STATE);
        return;
    }
    remove_file(o, "offer-", release, ".json"); /* never a new offer again */
    if (find_result(o, release) != NULL) {      /* stored just before the former run ended */
        fa_store_remove(o->cfg->data_dir, INSTALL_STATE);
        return;
    }
    bool apply = strcmp(state, "apply") == 0;
    if (apply && c->install == FA_INSTALL_DOCKER_COMPOSE) {
        follow_apply(o, release, version, c);
        return; /* install.json stays until the outcome */
    }
    if (apply) {
        fa_log("warning",
               "release %s: component %s is no longer installed with docker-compose: "
               "its apply is not followed",
               release, component);
        fa_apply_remove_work(o->cfg->data_dir);
        if (fa_store_remove(o->cfg->data_dir, FA_APPLY_PREVIOUS) != 0)
            fa_log("warning", "cannot remove %s/%s: %s", o->cfg->data_dir, FA_APPLY_PREVIOUS,
                   strerror(errno));
    }
    bool readable = fa_component_version(o->cfg, c, now_version) == 0;
    boot_id(boot);
    if (readable && strcmp(now_version, version) == 0) {
        add_result(o, release, FL_RESULT_INSTALLED, version, NULL);
        fa_service_request_status(o->svc);
    } else if (strcmp(state, "running") == 0 || apply) {
        if (!apply)
            fa_log("warning", "release %s: the install script was stopped before it ended",
                   release);
        add_result(o, release, FL_RESULT_FAILED, readable ? now_version : NULL, "install_failed");
    } else if (stored_boot[0] != '\0' && strcmp(stored_boot, boot) == 0) {
        o->reboot_pending = true;
        lower_release(release, o->reboot_release);
        fa_log("info",
               "release %s: installed at the next start of the device: waiting for the "
               "restart",
               release);
        return; /* install.json stays for the next start */
    } else {
        fa_log("warning", "release %s: component %s reports %s after the restart, not %s", release,
               component, readable ? now_version : "no version", version);
        add_result(o, release, FL_RESULT_FAILED, readable ? now_version : NULL, "boot_failed");
    }
    fa_store_remove(o->cfg->data_dir, INSTALL_STATE);
}

typedef struct {
    char name[NAME_MAX + 1];
    struct timespec mtime;
} offer_file;

static int by_arrival(const void *a, const void *b) {
    const offer_file *x = a, *y = b;
    if (x->mtime.tv_sec != y->mtime.tv_sec)
        return x->mtime.tv_sec < y->mtime.tv_sec ? -1 : 1;
    if (x->mtime.tv_nsec != y->mtime.tv_nsec)
        return x->mtime.tv_nsec < y->mtime.tv_nsec ? -1 : 1;
    return strcmp(x->name, y->name);
}

/* The queue again from the stored offers, oldest first, each checked again now. */
static void rebuild_queue(fa_ota *o, fl_time now) {
    DIR *d = opendir(o->cfg->data_dir);
    if (d == NULL)
        return;
    offer_file *files = calloc(MAX_OFFER_FILES, sizeof *files);
    int n = 0;
    struct dirent *e;
    char release[RELEASE_LEN + 1], path[PATH_MAX];
    while (files != NULL && (e = readdir(d)) != NULL && n < MAX_OFFER_FILES) {
        struct stat st;
        if (!release_of(e->d_name, "offer-", ".json", release) ||
            data_path(o, e->d_name, path) != 0 || lstat(path, &st) != 0)
            continue;
        snprintf(files[n].name, sizeof files[n].name, "%s", e->d_name);
        files[n++].mtime = st.st_mtim;
    }
    closedir(d);
    if (files == NULL)
        return;
    qsort(files, (size_t)n, sizeof *files, by_arrival);
    for (int i = 0; i < n; i++) {
        release_of(files[i].name, "offer-", ".json", release);
        char *text = NULL;
        size_t len = 0;
        fl_offer offer;
        if (fa_store_read(o->cfg->data_dir, files[i].name, &text, &len) != 0)
            continue;
        int rc = fl_offer_check(&o->dev, text, len, now, &offer);
        free(text);
        if (rc != FL_OK) {
            fa_log("error", "release %s: the stored offer cannot be checked (error %d)", release,
                   rc);
            continue; /* kept: checked again at the next start */
        }
        if (offer.action == FL_OFFER_IGNORE || !same_release(offer.release, release)) {
            fa_store_remove(o->cfg->data_dir, files[i].name);
            continue;
        }
        take_offer(o, &offer, NULL, 0, true);
    }
    free(files);
}

void fa_ota_identity_changed(fa_ota *o) {
    const fa_identity *id = fa_service_identity(o->svc);
    const char *family = id->family_id[0] != '\0' ? id->family_id : o->cfg->family;
    if (family != o->dev.family && family[0] != '\0') /* until now the configuration's, or none */
        fa_log("info", "the device family is now %s (from the renewal)", family);
    o->dev.family = family;
}

fa_ota *fa_ota_open(fa_service *s, fl_time now) {
    fa_ota *o = calloc(1, sizeof *o);
    if (o == NULL) {
        fa_log("error", "run: out of memory");
        return NULL;
    }
    o->svc = s;
    o->cfg = fa_service_config(s);
    o->fd = -1;
    o->child.out = -1;
    o->next_seq = 1;
    const fa_identity *id = fa_service_identity(s);
    const char *dot = strchr(id->client_id, '.');
    if (fl_init() != FL_OK || dot == NULL || (size_t)(dot - id->client_id) >= sizeof o->tenant) {
        fa_log("error", "run: the update check cannot start (crypto library or clientId)");
        free(o);
        return NULL;
    }
    memcpy(o->tenant, id->client_id, (size_t)(dot - id->client_id));
    o->dev.tenant = o->tenant;
    /* familyId of the registration or the renewal; before T178 the configuration's, until the
     * first renewal brings one. */
    o->dev.family = id->family_id[0] != '\0' ? id->family_id : o->cfg->family;
    o->dev.update_key_der = fa_service_update_key(s, &o->dev.update_key_der_len);
    o->dev.installable = installable;
    o->dev.installed_version = installed_version;
    o->dev.ctx = o;
    if (o->dev.family[0] == '\0')
        fa_log("warning", "the device family is unknown (registered before T178 and no family in "
                          "the configuration): offers are answered failed family_unknown");

    load_results(o);
    settle_install(o);
    if (o->reboot_pending && o->cfg->reboot_command[0] != '\0') {
        /* Same boot, the reboot after exit 10 never came: nothing else would ever restart the
         * device. reboot_command once more (no result, the script is not run again). */
        fa_log("info", "release %s: still waiting for the restart: running reboot_command again",
               o->reboot_release);
        if (fa_reboot_start(&o->child, o->cfg->reboot_command) == 0)
            o->state = JOB_REBOOT;
    }
    rebuild_queue(o, now);
    clean_downloads(o, NULL);
    if (o->queue.count > 0)
        fa_log("info", "%d release(s) queued from the data folder", o->queue.count);
    return o;
}

void fa_ota_close(fa_ota *o) {
    if (o == NULL)
        return;
    o->stopping = true;
    if (o->state == JOB_INSTALL && o->child.pid != 0) {
        /* A script that has ended, or ends within a short grace, still gets its outcome stored
         * (the signal may have come between its exit and the next tick); otherwise it is stopped
         * and install.json ("running") settles it at the next start. */
        struct timespec until;
        clock_gettime(CLOCK_MONOTONIC, &until);
        until.tv_sec += CLOSE_GRACE_S;
        for (;;) {
            install_step(o);
            if (o->state != JOB_INSTALL || o->child.pid == 0)
                break;
            struct timespec t;
            clock_gettime(CLOCK_MONOTONIC, &t);
            if (t.tv_sec > until.tv_sec || (t.tv_sec == until.tv_sec && t.tv_nsec >= until.tv_nsec))
                break;
            struct pollfd pfd = {o->child.out, POLLIN, 0};
            poll(&pfd, o->child.out >= 0 ? 1 : 0, 100);
        }
    }
    if (o->child.pid != 0) {
        fa_log("warning", "the agent stops: ending %s",
               o->state == JOB_INSTALL ? "the install script" : "reboot_command");
        fa_child_stop(&o->child);
    }
    if (o->state == JOB_APPLY && o->apply_started)
        fa_log("info", "release %s: the agent stops while apply runs: followed at the next start",
               o->job.release);
    end_job(o);
    free(o);
}

/* ---- The loop ----------------------------------------------------------------------------- */

void fa_ota_tick(fa_ota *o, fl_time now) {
    switch (o->state) {
    case JOB_REHASH:
        rehash(o, now);
        break;
    case JOB_DOWNLOAD:
        download_step(o, now);
        break;
    case JOB_RETRY:
        if (monotonic_s() >= o->retry_at)
            start_request(o, now);
        break;
    case JOB_INSTALL:
        install_step(o);
        break;
    case JOB_APPLY:
        apply_step(o);
        break;
    case JOB_REBOOT:
        reboot_step(o);
        break;
    case JOB_NONE:
        break;
    }
    start_next(o, now);
    send_results(o);
}

bool fa_ota_busy(const fa_ota *o) {
    return o->state == JOB_REHASH || o->http != NULL || o->child.pid != 0;
}

void fa_ota_wait(fa_ota *o, int fd, bool want_write, int timeout_ms) {
    struct pollfd fds[2];
    int n = 0;
    if (fd >= 0)
        fds[n++] = (struct pollfd){fd, (short)(POLLIN | (want_write ? POLLOUT : 0)), 0};
    if (o->child.pid != 0 && o->child.out >= 0)
        fds[n++] = (struct pollfd){o->child.out, POLLIN, 0};
    if (o->state == JOB_REHASH)
        timeout_ms = 0; /* work to do: only what is already there */
    if (o->http != NULL) {
        fa_http_download_wait(o->http, fds, n, timeout_ms);
    } else if (n > 0) {
        poll(fds, (nfds_t)n, timeout_ms);
    } else if (timeout_ms > 0) {
        struct timespec ts = {timeout_ms / 1000, (long)(timeout_ms % 1000) * 1000000L};
        nanosleep(&ts, NULL);
    }
}
