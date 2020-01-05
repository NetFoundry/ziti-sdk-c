/*
Copyright 2019 Netfoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


#include <stdlib.h>
#include <string.h>

#include <nf/ziti.h>
#include <uv.h>
#include "utils.h"
#include "zt_internal.h"
#include <http_parser.h>

#ifndef MAXPATHLEN
#ifdef _MAX_PATH
#define MAXPATHLEN _MAX_PATH
#elif _WIN32
#define MAXPATHLEN 260
#else
#define MAXPATHLEN 4096
#endif
#endif

#if _WIN32
#define strncasecmp _strnicmp
#endif

#define DEFAULT_TIMEOUT 5000

struct nf_init_req {
    nf_context nf;
    int init_status;
    nf_init_cb init_cb;
    void* init_ctx;
};

int code_to_error(const char *code);
static void version_cb(ctrl_version* v, ziti_error* err, void* ctx);
static void session_cb(ziti_session *session, ziti_error *err, void *ctx);

static size_t parse_ref(const char *val, const char **res) {
    size_t len = 0;
    *res = NULL;
    if (val != NULL) {
        if (strncmp("file:", val, 5) == 0) {
            // load file
            *res = val + strlen("file://");
            len = strlen(*res) + 1;
        }
        else if (strncmp("pem:", val, 4) == 0) {
            // load inline PEM
            *res = val + 4;
            len = strlen(val + 4) + 1;
        }
    }
    return len;
}

static int parse_getopt(const char *q, const char *opt, char *out, size_t maxout) {
    int optlen = strlen(opt);
    do {
        // found it
        if (strncasecmp(q, opt, optlen) == 0 && (q[optlen] == '=' || q[optlen] == 0)) {
            const char *val = q + optlen + 1;
            char *end = strchr(val, '&');
            int vlen = (int)(end == NULL ? strlen(val) : end - val);
            snprintf(out, maxout, "%*.*s", vlen, vlen, val);
            return 0;

        }
        else { // skip to next '&'
            q = strchr(q, '&');
            if (q == NULL) {
                break;
            }
            q += 1;
        }
    } while (q != NULL);
    out[0] = '\0';
    return ZITI_INVALID_CONFIG;
}

int load_tls(nf_config *cfg, tls_context **ctx) {
     PREP(ziti);

    // load ca from nf config if present
    const char *ca, *cert;
    size_t ca_len = parse_ref(cfg->ca, &ca);
    size_t cert_len = parse_ref(cfg->cert, &cert);
    tls_context *tls = default_tls_context(ca, ca_len);

    if (strncmp(cfg->key, "pkcs11://", strlen("pkcs11://")) == 0) {
        char path[MAXPATHLEN] = {0};
        char pin[32] = {0};
        char slot[32] = {0};
        char id[32] = {0};

        char *p = cfg->key + strlen("pkcs11://");
        char *endp = strchr(p, '?');
        char *q = endp + 1;
        if (endp == NULL) {
            TRY(ziti, ("invalid pkcs11 key specification", ZITI_INVALID_CONFIG));
        }
        sprintf(path, "%*.*s", (int)(endp - p), (int)(endp - p), p);

        TRY(ziti, parse_getopt(q, "pin", pin, sizeof(pin)));
        TRY(ziti, parse_getopt(q, "slot", slot, sizeof(slot)));
        TRY(ziti, parse_getopt(q, "id", id, sizeof(id)));

        tls->api->set_own_cert_pkcs11(tls->ctx, cert, cert_len, path, pin, slot, id);
    } else {
        const char *key;
        size_t key_len = parse_ref(cfg->key, &key);
        tls->api->set_own_cert(tls->ctx, cert, cert_len, key, key_len);
    }

     CATCH(ziti) {
        return ERR(ziti);
    }

    *ctx = tls;
    return ZITI_OK;
}

int NF_init(const char* config, uv_loop_t* loop, nf_init_cb init_cb, void* init_ctx) {
    init_debug();

    ZITI_LOG(INFO, "ZitiSDK version %s @%s(%s)", ziti_get_version(false), ziti_git_commit(), ziti_git_branch());

    PREP(ziti);
    nf_config *cfg;
    tls_context *tls = NULL;

    TRY(ziti, load_config(config, &cfg));
    TRY(ziti, load_tls(cfg, &tls));

    CATCH(ziti) {
        return ERR(ziti);
    }

    return NF_init_with_tls(cfg->controller_url, tls, loop, init_cb, init_ctx);
}

int
NF_init_with_tls(const char *ctrl_url, tls_context *tls_context, uv_loop_t *loop, nf_init_cb init_cb, void *init_ctx) {
    init_debug();
    ZITI_LOG(INFO, "ZitiSDK version %s @%s(%s)", ziti_get_version(false), ziti_git_commit(), ziti_git_branch());

    if (tls_context == NULL) {
        ZITI_LOG(ERROR, "tls context is required");
        return ZITI_CONFIG_NOT_FOUND;
    }

    NEWP(ctx, struct nf_ctx);
    ctx->tlsCtx = tls_context;
    ctx->loop = loop;
    ctx->ziti_timeout = DEFAULT_TIMEOUT;

    ziti_ctrl_init(loop, &ctx->controller, ctrl_url, tls_context);
    ziti_ctrl_get_version(&ctx->controller, version_cb, &ctx->controller);

    NEWP(init_req, struct nf_init_req);
    init_req->init_cb = init_cb;
    init_req->init_ctx = init_ctx;
    init_req->nf = ctx;
    ziti_ctrl_login(&ctx->controller, session_cb, init_req);

    return ZITI_OK;
}

int NF_set_timeout(nf_context ctx, int timeout) {
    if (timeout > 0) {
        ctx->ziti_timeout = timeout;
    }
    else {
        ctx->ziti_timeout = DEFAULT_TIMEOUT;
    }
    return 0;
}

int NF_shutdown(nf_context ctx) {
    ZITI_LOG(INFO, "Ziti is shutting down");

    ziti_ctrl_close(&ctx->controller);
    ziti_close_channels(ctx);

    ziti_ctrl_logout(&ctx->controller, NULL, NULL);

    return ZITI_OK;
}

int NF_free(nf_context *ctxp) {
    if ((*ctxp)->tlsCtx != NULL) {
        (*ctxp)->tlsCtx->api->free_ctx((*ctxp)->tlsCtx);
    }
    free(*ctxp);
    *ctxp = NULL;

    ZITI_LOG(INFO, "shutdown is complete\n");
    return 0;
}

void NF_dump(struct nf_ctx *ctx) {
    printf("\n=================\nSession:\n");
    dump_ziti_session(ctx->session, 0);

    printf("\n=================\nServices:\n");
    ziti_service *zs;
    SLIST_FOREACH(zs, &ctx->services, _next) {
        dump_ziti_service(zs, 0);
    }

    printf("\n==================\nNet Sessions:\n");
    ziti_net_session *it;
    SLIST_FOREACH(it, &ctx->net_sessions, _next) {
        dump_ziti_net_session(it, 0);
    }
}

int NF_conn_init(nf_context nf_ctx, nf_connection *conn, void *data) {
    struct nf_ctx *ctx = nf_ctx;
    NEWP(c, struct nf_conn);
    c->nf_ctx = nf_ctx;
    c->data = data;
    c->channel = NULL;
    c->state = Initial;
    c->timeout = ctx->ziti_timeout;

    *conn = c;
    return ZITI_OK;
}

void *NF_conn_data(nf_connection conn) {
    return conn->data;
}

int NF_dial(nf_connection conn, const char *service, nf_conn_cb conn_cb, nf_data_cb data_cb) {
    return ziti_dial(conn, service, conn_cb, data_cb);
}

int NF_close(nf_connection *conn) {
    struct nf_conn *c = *conn;

    ziti_disconnect(c);

    *conn = NULL;

    return 0;
}

int NF_write(nf_connection conn, uint8_t *buf, size_t length, nf_write_cb cb, void *ctx) {

    NEWP(req, struct nf_write_req);
    req->conn = conn;
    req->buf = buf;
    req->len = length;
    req->cb = cb;
    req->ctx = ctx;

    return ziti_write(req);
}

int NF_service_available(nf_context nf, const char *service) {
    ziti_service *s;
    SLIST_FOREACH (s, &nf->services, _next) {
        if (strcmp(service, s->name) == 0) {
            return ZITI_OK;
        }
    }

    return ZITI_SERVICE_UNAVALABLE;
}

extern int NF_listen(nf_connection serv_conn, const char *service, nf_listen_cb lcb, nf_client_cb cb) {
    return ziti_bind(serv_conn, service, lcb, cb);
}

extern int NF_accept(nf_connection clt, nf_conn_cb cb, nf_data_cb data_cb) {
    return ziti_accept(clt, cb, data_cb);
}

static void session_cb(ziti_session *session, ziti_error *err, void *ctx) {
    struct nf_init_req *init_req = ctx;

    int errCode = err ? code_to_error(err->code) : ZITI_OK;

    if (init_req != NULL) {
        init_req->nf->session = session;
        init_req->init_cb(init_req->nf, errCode, init_req->init_ctx);
    }
    else {
        FREE(session);
    }
    FREE(err);
    free(init_req);
}

static void version_cb(ctrl_version *v, ziti_error *err, void *ctx) {
    ziti_controller *ctrl = ctx;
    if (err != NULL) {
        ZITI_LOG(ERROR, "failed to get controller version from %s:%s %s(%s)",
                 ctrl->client.host, ctrl->client.port, err->code, err->message);
        free_ziti_error(err);
    }
    else {
        ZITI_LOG(INFO, "connected to controller %s:%s version %s(%s %s)",
                 ctrl->client.host, ctrl->client.port, v->version, v->revision, v->build_date);
        free_ctrl_version(v);
    }
}