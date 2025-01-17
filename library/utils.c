// Copyright (c) 2022-2024. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <uv.h>
#include <tlsuv/tlsuv.h>
#include <ziti/ziti_model.h>
#include <ziti/ziti_log.h>
#include <stdarg.h>

#include "utils.h"
#include "tlsuv/http.h"
#include "ziti/errors.h"

#if _WIN32
#include <time.h>
#endif


#if !defined(ZITI_VERSION)
#define ZITI_VERSION unknown
#endif

#if !defined(ZITI_BRANCH)
#define ZITI_BRANCH "<no-branch>"
#define ZITI_COMMIT "<sha>"
#endif

/*
 * https://sourceforge.net/p/predef/wiki/OperatingSystems/
 */
#if defined(WIN32)
#define ZITI_OS Windows
#elif defined(__ANDROID__)
#define ZITI_OS Android
#elif defined(__linux__)
#define ZITI_OS Linux
#elif defined(__FreeBSD__)
#define ZITI_OS FreeBSD
#elif defined(__APPLE__)
#define ZITI_OS MacOS
#else
#define ZITI_OS UKNOWN
#endif

#ifndef MAXPATHLEN
#ifdef _MAX_PATH
#define MAXPATHLEN _MAX_PATH
#elif _WIN32
#define MAXPATHLEN 260
#else
#define MAXPATHLEN 4096
#endif
#endif

/*
 * from https://sourceforge.net/p/predef/wiki/Architectures/
 */
#if defined(__aarch64__)
#define ZITI_ARCH arm64
#elif defined(__arm__)
#define ZITI_ARCH arm
#elif defined(__amd64__)
#define ZITI_ARCH amd64
#elif defined(__i386__)
#define ZITI_ARCH x86
#else
#define ZITI_ARCH UKNOWN
#endif

#define LEVEL_LBL(lvl) #lvl,
static const char *const level_labels[] = {
        DEBUG_LEVELS(LEVEL_LBL)
};

static const char *basename(const char *path);

const char *ziti_get_build_version(int verbose) {
    if (verbose) {
        return "\n\tVersion:\t" to_str(ZITI_VERSION)
               "\n\tBuild Date:\t" __DATE__ " " __TIME__
               "\n\tGit Branch:\t" to_str(ZITI_BRANCH)
               "\n\tGit SHA:\t" to_str(ZITI_COMMIT)
               "\n\tOS:\t" to_str(ZITI_OS)
               "\n\tArch:\t" to_str(ZITI_ARCH)
               "\n";

    }
#ifdef ZITI_BUILDNUM
    return to_str(ZITI_VERSION) "-" to_str(ZITI_BUILDNUM);
#else
    return to_str(ZITI_VERSION);
#endif
}

const char* ziti_git_branch() {
    return to_str(ZITI_BRANCH);
}

const char* ziti_git_commit() {
    return to_str(ZITI_COMMIT);
}

static const char *TLSUV_MODULE = "tlsuv";

static model_map log_levels;
static int ziti_log_lvl = ZITI_LOG_DEFAULT_LEVEL;
static FILE *ziti_debug_out;
static bool log_initialized = false;
static uv_pid_t log_pid = 0;

static const char *(*get_elapsed)();

static const char *get_elapsed_time();

static const char *get_utc_time();

static void default_log_writer(int level, const char *loc, const char *msg, size_t msglen);

static uv_loop_t *ts_loop;
static uint64_t starttime;
static uint64_t last_update;
static char log_timestamp[32];

static uv_key_t logbufs;

static log_writer logger = NULL;

static void init_debug(uv_loop_t *loop);

static void init_uv_mbed_log();

void ziti_log_init(uv_loop_t *loop, int level, log_writer log_func) {
    init_uv_mbed_log();

    init_debug(loop);

    if (level == ZITI_LOG_DEFAULT_LEVEL) {
        level = ziti_log_lvl;
    }

    if (log_func == NULL) {
        // keep the logger if it was already set
        ziti_log_set_logger(logger ? logger : default_log_writer);
    } else {
        ziti_log_set_logger(log_func);
    }

    ziti_log_set_level(level, NULL);

    uv_timeval64_t start_time;
    uv_gettimeofday(&start_time);

    char time_str[32];
    ziti_fmt_time(time_str, sizeof(time_str), &start_time);

    ZITI_LOG(INFO, "Ziti C SDK version %s @%s(%s) starting at (%s.%03d)",
            ziti_get_build_version(false), ziti_git_commit(), ziti_git_branch(),
            time_str, start_time.tv_usec / 1000);

}

void ziti_log_set_level(int level, const char *marker) {
    if (level > TRACE) {
        level = TRACE;
    } else if (level < 0) {
        level = ZITI_LOG_DEFAULT_LEVEL;
    }

    if (level == ZITI_LOG_DEFAULT_LEVEL) {
        if (marker) {
            model_map_remove(&log_levels, marker);
        }
    } else {
        if (marker) {
            model_map_set(&log_levels, marker, (void *) (uintptr_t) level);
            if (strcmp(marker, TLSUV_MODULE) == 0) {
                tlsuv_set_debug(level, tlsuv_logger);
            }
        } else {
            ziti_log_lvl = level;
        }
    }

    if (logger) {
        int l = level == ZITI_LOG_DEFAULT_LEVEL ? ziti_log_lvl : level;
        const char *lbl = level_labels[l];
        ZITI_LOG(INFO, "set log level: %s=%d/%s", marker ? marker : "root", l, lbl);
    }
}

int ziti_log_level(const char *module, const char *file) {
    int level;

    file = basename(file);
    if (file) {
        level = (int) (uintptr_t) model_map_get(&log_levels, file);
        if (level) { return level; }
    }

    if (module) {
        level = (int) (uintptr_t) model_map_get(&log_levels, module);
        if (level) { return level; }
    }

    return ziti_log_lvl;
}

const char* ziti_log_level_label() {
    int num_levels = sizeof(level_labels) / sizeof(const char *);
    if (ziti_log_lvl >= 0 && ziti_log_lvl < num_levels) {
        return level_labels[ziti_log_lvl];
    } else {
        return NULL;
    }
}

void ziti_log_set_level_by_label(const char* log_level) {
    int lvl = ZITI_LOG_DEFAULT_LEVEL;
    int num_levels = sizeof(level_labels) / sizeof(const char *);
    for (int i = 0;i < num_levels; i++) {
        if (strcasecmp(log_level, level_labels[i]) == 0) {
            lvl = i;
        }
    }
    if (lvl != ZITI_LOG_DEFAULT_LEVEL) {
        ziti_log_set_level(lvl, NULL);
    }
}

void ziti_log_set_logger(log_writer log) {
    logger = log;
}

static void init_uv_mbed_log() {
    char *lvl;
    if ((lvl = getenv("TLSUV_DEBUG")) != NULL) {
        int l = (int) strtol(lvl, NULL, 10);
        tlsuv_set_debug(l, tlsuv_logger);
    }
}

static void child_init() {
    log_initialized = false;
    log_pid = uv_os_getpid();
}

static void init_debug(uv_loop_t *loop) {
    if (log_initialized) {
        return;
    }
#if defined(PTHREAD_ONCE_INIT)
    pthread_atfork(NULL, NULL, child_init);
#endif
    uv_key_create(&logbufs);
    log_pid = uv_os_getpid();
    get_elapsed = get_elapsed_time;
    char *ts_format = getenv("ZITI_TIME_FORMAT");
    if (ts_format && strcasecmp("utc", ts_format) == 0) {
        get_elapsed = get_utc_time;
    }
    ts_loop = loop;
    log_initialized = true;

    if (ziti_log_lvl == ZITI_LOG_DEFAULT_LEVEL) {
        ziti_log_lvl = ERROR;
    }

    // always log TLSUV errors
    ziti_log_set_level(ERROR, TLSUV_MODULE);
    model_list levels = {0};
    str_split(getenv("ZITI_LOG"), ";", &levels);

    const char *lvl;
    int l;
    MODEL_LIST_FOREACH(lvl, levels) {
        char *eq = strchr(lvl, '=');
        if (eq) {
            l = (int) strtol(eq + 1, NULL, 10);
            model_map_set_key(&log_levels, lvl, eq - lvl, (void *) (intptr_t) l);
        }
        else {
            l = (int) strtol(lvl, NULL, 10);
            ziti_log_lvl = l;
        }
    }
    model_list_clear(&levels, free);

    int tlsuv_level = (int) (intptr_t) model_map_get(&log_levels, TLSUV_MODULE);
    if (tlsuv_level > 0) {
        tlsuv_set_debug(tlsuv_level, tlsuv_logger);
    }

    ziti_debug_out = stderr;

    starttime = uv_now(loop);
}

#if _WIN32 && defined(_MSC_VER)
static const char DIR_SEP = '\\';
#else
static const char DIR_SEP = '/';
#endif

static const char *basename(const char *path) {
    if (path == NULL) { return NULL; }

    char *last_slash = strrchr(path, DIR_SEP);
    if (last_slash) { return last_slash + 1; }
    return path;
}

void ziti_logger(int level, const char *module, const char *file, unsigned int line, const char *func, FORMAT_STRING(const char *fmt), ...) {
#ifdef ZITI_DEBUG
    static size_t loglinelen = 32768;
#else
    static size_t loglinelen = 1024;
#endif

    log_writer logfunc = logger;
    if (logfunc == NULL) { return; }

    char *logbuf = (char *) uv_key_get(&logbufs);
    if (!logbuf) {
        logbuf = malloc(loglinelen);
        uv_key_set(&logbufs, logbuf);
    }

    char location[128];
    char *last_slash = strrchr(file, DIR_SEP);

    int modlen = 16;
    if (module == NULL) {
        if (last_slash == NULL) {
            modlen = 0;
        }
        else {
            char *p = last_slash;
            while (p > file) {
                p--;
                if (*p == DIR_SEP) {
                    p++;
                    break;
                }
            }
            module = p;
            modlen = (int) (last_slash - p);
        }
    }

    if (last_slash) {
        file = last_slash + 1;
    }
    if (func && func[0]) {
        snprintf(location, sizeof(location), "%.*s:%s:%u %s()", modlen, module, file, line, func);
    }
    else {
        snprintf(location, sizeof(location), "%.*s:%s:%u", modlen, module, file, line);
    }

    va_list argp;
    va_start(argp, fmt);
    int len = vsnprintf(logbuf, loglinelen, fmt, argp);
    va_end(argp);

    if (len > loglinelen) {
        len = (int) loglinelen;
    }

    logfunc(level, location, logbuf, len);
}

static void default_log_writer(int level, const char *loc, const char *msg, size_t msglen) {
    const char *elapsed = get_elapsed();
    fprintf(ziti_debug_out, "(%u)[%s] %7s %s %.*s\n", log_pid, elapsed, level_labels[level], loc, (unsigned int) msglen, msg);
}

void tlsuv_logger(int level, const char *file, unsigned int line, const char *msg) {
    ziti_logger(level, TLSUV_MODULE, file, line, NULL, "%s", msg);
}

static const char *get_elapsed_time() {
    uint64_t now = uv_now(ts_loop);
    if (now > last_update) {
        last_update = now;
        unsigned long long elapsed = now - starttime;
        snprintf(log_timestamp, sizeof(log_timestamp), "%9llu.%03llu", (elapsed / 1000), (elapsed % 1000));
    }
    return log_timestamp;
}

static const char *get_utc_time() {
    uint64_t now = uv_now(ts_loop);
    if (now > last_update) {
        last_update = now;

        uv_timeval64_t ts;
        uv_gettimeofday(&ts);
        time_t t = ts.tv_sec;
        struct tm *tm = gmtime(&t);

        snprintf(log_timestamp, sizeof(log_timestamp), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                 1900 + tm->tm_year, tm->tm_mon + 1, tm->tm_mday,
                 tm->tm_hour, tm->tm_min, tm->tm_sec, ts.tv_usec / 1000
        );
    }
    return log_timestamp;
}

int lt_zero(int v) { return v < 0; }

void hexDump (char *desc, void *addr, int len) {
    ZITI_LOG(DEBUG, " ");
    int i;
    unsigned char buffLine[17];
    unsigned char *pc = (unsigned char*)addr;
    if (desc != NULL){
       printf ("%s:\n", desc);
    }
    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0) {
                printf ("  %s\n", buffLine);
            }
            printf ("  %07x ", i);
        }
        printf ("%02x", pc[i]);
        if ((i % 2) == 1) {
            printf (" "); 
        }
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buffLine[i % 16] = '.';
        }
        else{
           buffLine[i % 16] = pc[i];
        }    

        buffLine[(i % 16) + 1] = '\0'; //Clears the next array buffLine
    }
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }
    printf ("  %s\n", buffLine);
    fflush(stdout); 
    ZITI_LOG(DEBUG, " ");
}

void ziti_fmt_time(char* time_str, size_t time_str_sz, uv_timeval64_t* tv) {
    if (tv == NULL) {
        strncpy(time_str, "null tv", time_str_sz);
    } else {
        time_t t = tv->tv_sec;
        struct tm* start_tm = gmtime(&t);
        strftime(time_str, time_str_sz, "%Y-%m-%dT%H:%M:%S", start_tm);
    }
}

void hexify(const uint8_t *bin, size_t bin_len, char sep, char **buf) {
    static char hex[] = "0123456789abcdef";
    size_t out_size = sep ? bin_len * 3 : bin_len * 2 + 1;
    char *out = malloc(out_size);
    char *p = out;
    for (int i = 0; i < bin_len; i++) {
        unsigned char b = bin[i];
        if (sep && i > 0) { *p++ = sep; }
        *p++ = hex[b >> 4];
        *p++ = hex[b & 0xf];
    }
    *p = 0;
    *buf = out;
}


size_t str_split(const char *str, const char *delim, model_list *result) {
    size_t count = 0;
    if (str) {
        const char *sep = str;
        do {
            const char *s = sep;
            char *val;
            if ((sep = strpbrk(s, delim)) != NULL) {
                size_t tok_len = sep++ - s;
                val = calloc(1, tok_len + 1);
                strncpy(val, s, tok_len);
            }
            else {
                val = strdup(s);
            }
            model_list_append(result, val);
            count++;
        } while (sep);
    }

    return count;
}

#define CHECK_OPT(v, o) if (strncmp(v, #o "=", strlen(#o "=")) == 0) { \
                    (o) = (v) + strlen(#o "="); \
                    continue; \
                }

typedef int (*parse_cb)(tls_context *tls, void *ctx, const char *lib, const char *slot, const char *pin, const char *id,
                        const char *label);

static int parse_pkcs11_uri(const char *keyuri, tls_context *tls, void *ctx, parse_cb cb) {
    struct tlsuv_url_s uri;
    int rc;
    if (tlsuv_parse_url(&uri, keyuri) == 0) {
        if (uri.scheme_len == strlen("pkcs11") && strncmp(uri.scheme, "pkcs11", uri.scheme_len) == 0) {
            char lib[MAXPATHLEN] = "";
#ifdef _WIN32
            if (uri.path[0] == '/' && uri.path[2] == ':') {
                strncpy_s(lib, sizeof(lib), uri.path + 1, uri.path_len - 1);
            } else {
                ZITI_LOG(ERROR, "invalid pkcs11 key URI, `pkcs11:///C:/...` format expected");
                return -1;
            }
#else
            strncpy(lib, uri.path, uri.path_len);
#endif

            const char *slot = NULL, *pin = NULL, *id = NULL, *label = NULL;

            model_list opts = {0};
            str_split(uri.query, "&", &opts);
            char *opt;
            MODEL_LIST_FOREACH(opt, opts) {
                CHECK_OPT(opt, slot);
                CHECK_OPT(opt, pin);
                CHECK_OPT(opt, id);
                CHECK_OPT(opt, label);
            }

            rc = cb(tls, ctx, lib, slot, pin, id, label);
            model_list_clear(&opts, free);
            return rc;
        }
    }

    return ZITI_INVALID_CONFIG;
}

static int pkcs11_load(tls_context *tls, tlsuv_private_key_t *key, const char *lib, const char *slot, const char *pin,
                       const char *id, const char *label) {
    if (tls->load_pkcs11_key(key, lib, slot, pin, id, label)) {
        return ZITI_INVALID_CONFIG;
    }
    return ZITI_OK;
}

int load_key_internal(tls_context *tls, tlsuv_private_key_t *key, const char *keystr) {
    struct tlsuv_url_s uri;
    int rc;

    if (parse_pkcs11_uri(keystr, tls, key, (parse_cb) pkcs11_load) == 0) {
        return 0;
    }

    if (strncmp(keystr, "keychain:", strlen("keychain:")) == 0) {
        const char *keyname = strchr(keystr, ':') + 1;
        rc = tls->load_keychain_key(key, keyname);
        if (rc != 0) {
            ZITI_LOG(WARN, "failed to load keychain key[%s]", keyname);
            return ZITI_INVALID_CONFIG;
        }
        return 0;
    }

    if (tlsuv_parse_url(&uri, keystr) == 0) {
        if (uri.scheme_len == strlen("file") && strncmp(uri.scheme, "file", uri.scheme_len) == 0) {
            rc = tls->load_key(key, uri.path, uri.path_len);
            return rc != 0 ? ZITI_INVALID_CONFIG : 0;
        }
    }

    if (strncmp("pem:", keystr, strlen("pem:")) == 0) {
        keystr += strlen("pem:");
    }
    rc = tls->load_key(key, keystr, strlen(keystr));
    return rc != 0 ? ZITI_INVALID_CONFIG : 0;
}

static int pkcs11_gen(tls_context *tls, tlsuv_private_key_t *key, const char *lib, const char *slot, const char *pin,
                      const char *id, const char *label) {

    if (tls->generate_pkcs11_key == NULL) {
        ZITI_LOG(WARN, "pkcs11 key generation is not supported by TLS driver[%s]", tls->version());
        return ZITI_KEY_GENERATION_FAILED;
    }

    if (tls->generate_pkcs11_key(key, lib, slot, pin, label)) {
        return ZITI_KEY_GENERATION_FAILED;
    }
    return ZITI_OK;
}

int gen_p11_key_internal(tls_context *tls, tlsuv_private_key_t *key, const char *keyuri) {
    return parse_pkcs11_uri(keyuri, tls, key, (parse_cb) pkcs11_gen);
}

int load_file(const char *path, size_t pathlen, char **content, size_t *size) {
    char filename[MAXPATHLEN];
    if (pathlen >= MAXPATHLEN) return UV_ENOMEM;
    uv_file f = -1;
    uv_fs_t fs_req = {0};

    if (pathlen > 0) {
        strncpy(filename, path, pathlen);
        filename[pathlen] = 0;
        path = filename;
    }

    size_t content_len = 0;
    char *content_buf = NULL;
    int rc = 0;

    if (strcmp(path, "-") == 0) {
        if (*content == NULL) {
            ZITI_LOG(VERBOSE, "buffer is required when reading stdin");
            return UV_EINVAL;
        }
        content_buf = *content;
        content_len = *size;
        f = fileno(stdin);
    } else {
        rc = uv_fs_stat(NULL, &fs_req, path, NULL);
        if (rc) {
            ZITI_LOG(VERBOSE, "path[%.*s..] - %d/%s", 16, path, rc, uv_strerror(rc));
            return rc;
        }
        content_len = fs_req.statbuf.st_size;
        if (*content != NULL) {
            if (*size > 0 && *size < content_len) {
                ZITI_LOG(VERBOSE, "%s - not enough space to read", path);
                return UV_ENOMEM;
            }
            content_buf = *content;
        }

        uv_fs_req_cleanup(&fs_req);
        f = uv_fs_open(NULL, &fs_req, path, 0, O_RDONLY, NULL);
    }

    if (f < 0) {
        ZITI_LOG(VERBOSE, "%s - %s", path, strerror(errno));
        return rc;
    }

    if (content_buf == NULL) {
        content_buf = malloc(content_len + 1);
    }

    size_t read = 0;
    while (read < content_len) {
        uv_fs_req_cleanup(&fs_req);

        uv_buf_t buf = uv_buf_init(content_buf + read, content_len - read);
        rc = uv_fs_read(NULL, &fs_req, f, &buf, 1, -1, NULL);
        if (rc == 0) {
            break;
        }
        read += rc;
    }

    uv_fs_req_cleanup(&fs_req);
    uv_fs_close(NULL, &fs_req, f, NULL);
    content_buf[read] = 0;
    *content = content_buf;
    if (size) *size = read;

    return ZITI_OK;
}

uint64_t next_backoff(int *count, int max, uint64_t base) {
    int c = *count + 1;
    int backoff = MIN(c, max);

    uint32_t random;
    uv_random(NULL, NULL, &random, sizeof(random), 0, NULL);

    *count = c;
    return random % ((1U << backoff) * base);
}