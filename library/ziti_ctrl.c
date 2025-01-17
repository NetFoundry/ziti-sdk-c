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

#include <inttypes.h>
#include <stdlib.h>

#include "utils.h"
#include "zt_internal.h"
#include <ziti_ctrl.h>
#include <tlsuv/http.h>
#include <assert.h>


#define DEFAULT_PAGE_SIZE 25
#define ZITI_CTRL_KEEPALIVE 0
#define ZITI_CTRL_TIMEOUT 15000
// one minute in millis
#define ONE_MINUTE (1 * 60 * 1000)

const char *const PC_DOMAIN_TYPE = "DOMAIN";
const char *const PC_OS_TYPE = "OS";
const char *const PC_PROCESS_TYPE = "PROCESS";
const char *const PC_PROCESS_MULTI_TYPE = "PROCESS_MULTI";
const char *const PC_MAC_TYPE = "MAC";
const char *const PC_ENDPOINT_STATE_TYPE = "ENDPOINT_STATE";

const char *const ERROR_CODE_UNAUTHORIZED = "UNAUTHORIZED";
const char *const ERROR_MSG_NO_API_SESSION_TOKEN = "no api session token set for ziti_controller";

#undef MODEL_API
#define MODEL_API static

#define PAGINATION_MODEL(XX, ...) \
XX(limit, model_number, none, limit, __VA_ARGS__) \
XX(offset, model_number, none, offset, __VA_ARGS__) \
XX(total, model_number, none, totalCount, __VA_ARGS__) \

DECLARE_MODEL(resp_pagination, PAGINATION_MODEL)

#define RESP_META_MODEL(XX, ...) \
XX(pagination,resp_pagination,none,pagination, __VA_ARGS__)

DECLARE_MODEL(resp_meta, RESP_META_MODEL)

IMPL_MODEL(resp_pagination, PAGINATION_MODEL)

IMPL_MODEL(resp_meta, RESP_META_MODEL)

int code_to_error(const char *code) {

#define CODE_MAP(XX) \
XX(NOT_FOUND, ZITI_NOT_FOUND)                           \
XX(CONTROLLER_UNAVAILABLE, ZITI_CONTROLLER_UNAVAILABLE) \
XX(NO_ROUTABLE_INGRESS_NODES, ZITI_GATEWAY_UNAVAILABLE) \
XX(NO_EDGE_ROUTERS_AVAILABLE, ZITI_GATEWAY_UNAVAILABLE) \
XX(INVALID_AUTHENTICATION, ZITI_AUTHENTICATION_FAILED)  \
XX(REQUIRES_CERT_AUTH, ZITI_AUTHENTICATION_FAILED)      \
XX(UNAUTHORIZED, ZITI_AUTHENTICATION_FAILED)            \
XX(INVALID_POSTURE, ZITI_INVALID_POSTURE)               \
XX(INVALID_AUTH, ZITI_AUTHENTICATION_FAILED)            \
XX(MFA_INVALID_TOKEN, ZITI_MFA_INVALID_TOKEN)           \
XX(MFA_EXISTS, ZITI_MFA_EXISTS)                         \
XX(MFA_NOT_ENROLLED, ZITI_MFA_NOT_ENROLLED)             \
XX(INVALID_ENROLLMENT_TOKEN, ZITI_JWT_INVALID)          \
XX(INVALID_CONTROLLER_RESPONSE, ZITI_INVALID_STATE)     \
XX(CERT_IN_USE, ZITI_CERT_IN_USE)                       \
XX(CERT_FAILED_VALIDATION, ZITI_CERT_FAILED_VALIDATION) \
XX(MISSING_CERT_CLAIM, ZITI_MISSING_CERT_CLAIM)         \
XX(COULD_NOT_VALIDATE, ZITI_NOT_AUTHORIZED)


#define CODE_MATCH(c, err) if (strcmp(code,#c) == 0) return err;

    if (code == NULL) { return ZITI_OK; }

    CODE_MAP(CODE_MATCH)

    ZITI_LOG(WARN, "unmapped error code: %s", code);
    return ZITI_WTF;
}

#define CTRL_LOG(lvl, fmt, ...) ZITI_LOG(lvl, "ctrl[%s:%s] " fmt, \
ctrl->client->host, ctrl->client->port, ##__VA_ARGS__)

#define MAKE_RESP(ctrl, cb, parser, ctx) prepare_resp(ctrl, (ctrl_resp_cb_t)(cb), (body_parse_fn)(parser), ctx)

typedef struct ctrl_resp ctrl_resp_t;
typedef void (*ctrl_cb_t)(void *, const ziti_error *, ctrl_resp_t *);
typedef void (*ctrl_resp_cb_t)(void *, const ziti_error *, void *);
typedef int (*body_parse_fn)(void *, json_object *);

enum ctrl_content_type {
    ctrl_content_text,
    ctrl_content_json,
};

struct ctrl_resp {
    int status;
    enum ctrl_content_type resp_content;
    void *content_proc;
    void *content;
    json_object *resp_json;

    uv_timeval64_t start;
    uv_timeval64_t all_start;

    bool paging;
    const char *base_path;
    unsigned int limit;
    unsigned int total;
    unsigned int recd;

    body_parse_fn body_parse_func;
    ctrl_resp_cb_t resp_cb;

    void *ctx;

    char *new_address;
    ziti_controller *ctrl;

    ctrl_cb_t ctrl_cb;
};

static void internal_get_version(ziti_controller *ctrl);

static struct ctrl_resp *prepare_resp(ziti_controller *ctrl, ctrl_resp_cb_t cb, body_parse_fn parser, void *ctx);

static void ctrl_paging_req(struct ctrl_resp *resp);

static void ctrl_default_cb(void *s, const ziti_error *e, struct ctrl_resp *resp);

static void ctrl_body_cb(tlsuv_http_req_t *req, char *b, ssize_t len);

static const char* ctrl_next_ep(ziti_controller *ctrl, const char *current);

static tlsuv_http_req_t *
start_request(tlsuv_http_t *http, const char *method, const char *path, tlsuv_http_resp_cb cb, struct ctrl_resp *resp) {
    ziti_controller *ctrl = resp->ctrl;
    ctrl->active_reqs++;
    uv_gettimeofday(&resp->start);
    CTRL_LOG(VERBOSE, "starting %s[%s]", method, path);
    return tlsuv_http_req(http, method, path, cb, resp);
}

static const char *find_header(tlsuv_http_resp_t *r, const char *name) {
    tlsuv_http_hdr *h;
    LIST_FOREACH(h, &r->headers, _next) {
        if (strcasecmp(h->name, name) == 0) {
            return h->value;
        }
    }
    return NULL;
}

static void ctrl_resp_cb(tlsuv_http_resp_t *r, void *data) {
    struct ctrl_resp *resp = data;
    ziti_controller *ctrl = resp->ctrl;

    assert(ctrl->active_reqs > 0);
        ctrl->active_reqs--;

    resp->status = r->code;
    if (r->code < 0) {
        int e = ZITI_CONTROLLER_UNAVAILABLE;
        const char *code = "CONTROLLER_UNAVAILABLE";

        // cancellation is cased by closing of ziti context
        // do not log error
        if (r->code == UV_ECANCELED) {
            e = ZITI_DISABLED;
            code = ziti_errorstr(ZITI_DISABLED);
        } else {
            CTRL_LOG(WARN, "request failed: %d(%s)", r->code, uv_strerror(r->code));

            if (ctrl->active_reqs == 0) {
                CTRL_LOG(INFO, "attempting to switch endpoint");
                const char *next_ep = ctrl_next_ep(ctrl, ctrl->url);
                if (next_ep != NULL) {
                    FREE(ctrl->url);
                    ctrl->url = strdup(next_ep);
                    CTRL_LOG(INFO, "switching to endpoint[%s]", ctrl->url);
                    tlsuv_http_set_url(ctrl->client, next_ep);
                    internal_get_version(ctrl);
                }
            }
        }

        ziti_error err = {
                .err = e,
                .code = (char *) code,
                .message = (char *) uv_strerror(r->code),
        };

        (resp->ctrl_cb ? resp->ctrl_cb : ctrl_default_cb)(NULL, &err, resp);
    } else {
        CTRL_LOG(VERBOSE, "received headers %s[%s]", r->req->method, r->req->path);
        r->body_cb = ctrl_body_cb;

        const char *hv;
        if ((hv = find_header(r, "content-type")) != NULL &&
            strncmp(hv, "application/json", strlen("application/json")) == 0) {
            resp->resp_content = ctrl_content_json;
            resp->content_proc = json_tokener_new();
        } else {
            resp->resp_content = ctrl_content_text;
            resp->content_proc = new_string_buf();
            if (resp->body_parse_func) {
                CTRL_LOG(ERROR, "received unexpected content: %s", hv);
            }
        }

        const char *new_addr = find_header(r, "ziti-ctrl-address");
        if (new_addr) {
            FREE(resp->new_address);
            resp->new_address = strdup(new_addr);
        }

        const char *instance_id = find_header(r, "ziti-instance-id");

        if (instance_id &&
            (resp->ctrl->instance_id == NULL || strcmp(instance_id, resp->ctrl->instance_id) != 0)) {
            FREE(resp->ctrl->instance_id);
            resp->ctrl->instance_id = strdup(instance_id);
        }
    }
}

static void ctrl_default_cb(void *s, const ziti_error *e, struct ctrl_resp *resp) {
    ziti_controller *ctrl = resp->ctrl;
    if (resp->new_address && strcmp(resp->new_address, ctrl->url) != 0) {
        CTRL_LOG(INFO, "controller supplied new address[%s]", resp->new_address);

        const char *k;
        ziti_controller_detail *detail;
        MODEL_MAP_FOREACH(k, detail, &ctrl->endpoints) {
            if (strcasecmp(k, ctrl->url) == 0) {
                model_map_remove(&ctrl->endpoints, k);
                break;
            }
        }
        FREE(ctrl->url);
        ctrl->url = resp->new_address;
        resp->new_address = NULL;
        if(detail == NULL) {
            detail = alloc_ziti_controller_detail();
        }
        FREE(detail->name);
        detail->name = strdup(ctrl->url);
        model_map_set(&ctrl->endpoints, detail->name, detail);

        tlsuv_http_set_url(ctrl->client, ctrl->url);

        if (resp->ctrl->redirect_cb) {
            ctrl->redirect_cb(ctrl->url, ctrl->cb_ctx);
        }
    }

    if (resp->resp_cb) {
        resp->resp_cb(s, e, resp->ctx);
    }

    FREE(resp->new_address);
    if (resp->resp_json != NULL) {
        json_object_put(resp->resp_json);
    }
    if (resp->content_proc != NULL) {
        if (resp->resp_content == ctrl_content_json)
            json_tokener_free(resp->content_proc);
        else {
            string_buf_free(resp->content_proc);
            FREE(resp->content_proc);
        }
    }
    free(resp);
}

static void internal_ctrl_list_cb(ziti_controller_detail_array arr, const ziti_error *err, void *ctx) {
    ziti_controller *ctrl = ctx;
    ziti_controller_detail *d;
    bool change = false;
    model_map new_eps = {0};

    if (err) {
        CTRL_LOG(WARN, "failed to get list of HA controllers: %s", err->message);
        return;
    }

    FOR (d, arr) {
        api_address *addr = NULL;
        MODEL_LIST_FOREACH(addr, d->apis.edge) {
            CTRL_LOG(VERBOSE, "%s/%s", addr->version, addr->url);
            if (strcmp(addr->version, "v1") == 0) {
                break;
            }
            addr = NULL;
        }

        if (addr != NULL) {
            model_map_set(&new_eps, addr->url, d);

            ziti_controller_detail *old_detail = model_map_get(&ctrl->endpoints, addr->url);
            if (old_detail == NULL) { // new controller discovered
                change = true;
            } else {
                change = change || (old_detail->is_online != d->is_online);
            }
        } else {
            free_ziti_controller_detail_ptr(d);
        }
    }

    if (model_map_size(&new_eps) == 0) {
        CTRL_LOG(WARN, "empty new controller list");
    } else if (change || (model_map_size(&new_eps) != model_map_size(&ctrl->endpoints))) {
        model_map old = ctrl->endpoints;
        ctrl->endpoints = new_eps;
        model_map_clear(&old, (void (*)(void *)) free_ziti_controller_detail_ptr);
        if (ctrl->is_ha) {
            ctrl->change_cb(ctrl->cb_ctx, &ctrl->endpoints);
        }
    } else {
        CTRL_LOG(VERBOSE, "no ctrl list change");
        model_map_clear(&new_eps, (void (*)(void *)) free_ziti_controller_detail_ptr);
    }
    free(arr);
}

static void internal_version_cb(ziti_version *v, ziti_error *e, struct ctrl_resp *resp) {
    ziti_controller *ctrl = resp->ctrl;
    if (e) {
        CTRL_LOG(WARN, "%s(%s)", e->code, e->message);
    }

    if (v) {
        if (ctrl->version.version != NULL &&
            strcmp(ctrl->version.version, v->version) != 0) {
            CTRL_LOG(INFO, "controller updated to %s(%s)[%s]",
                     v->version, v->revision, v->build_date);
        }
        free_ziti_version(&ctrl->version);
        ctrl->version = *v;

        api_path *path = NULL;
        if (v->api_versions) {
            path = model_map_get(&v->api_versions->edge, "v1");
        }

        if (path) {
            tlsuv_http_set_path_prefix(resp->ctrl->client, path->path);
        } else {
            CTRL_LOG(WARN, "controller did not provide expected(v1) API version path");
        }

        ctrl->is_ha = ziti_has_capability(&ctrl->version, ziti_ctrl_caps.HA_CONTROLLER);

        // data was moved to ctrl.version
        free(v);
        v = &ctrl->version;
    }

    if (ctrl->version_cb) {
        ctrl->version_cb(v, e, ctrl->version_cb_ctx);
    }

    ctrl->version_req = NULL;
    ctrl->version_cb = NULL;
    ctrl->version_cb_ctx = NULL;

    ctrl_default_cb(NULL, e, resp);
}

void ziti_ctrl_clear_api_session(ziti_controller *ctrl) {
    ctrl->has_token = false;
    if (ctrl->client) {
        CTRL_LOG(DEBUG, "clearing api session token for ziti_controller");
        tlsuv_http_header(ctrl->client, "zt-session", NULL);
        ziti_ctrl_set_token(ctrl, NULL);
    }
}

static void ctrl_login_cb(ziti_api_session *s, ziti_error *e, struct ctrl_resp *resp) {
    ziti_controller *ctrl = resp->ctrl;
    if (e) {
        CTRL_LOG(ERROR, "%s(%s)", e->code, e->message);
        ziti_ctrl_clear_api_session(resp->ctrl);
    }

    if (s) {
        CTRL_LOG(DEBUG, "authenticated successfully session[%s]", s->id);
        ctrl->has_token = true;
        tlsuv_http_header(ctrl->client, "zt-session", s->token);
    }
    ctrl_default_cb(s, e, resp);
}

static void ctrl_logout_cb(void *s, ziti_error *e, struct ctrl_resp *resp) {
    ziti_controller *ctrl = resp->ctrl;
    CTRL_LOG(DEBUG, "logged out");

    ctrl->has_token = false;
    tlsuv_http_header(ctrl->client, "zt-session", NULL);
    ctrl_default_cb(s, e, resp);
}

static void ctrl_service_cb(ziti_service **services, ziti_error *e, struct ctrl_resp *resp) {
    ziti_service *s = services != NULL ? services[0] : NULL;
    ctrl_default_cb(s, e, resp);
    free(services);
}

static void free_body_cb(tlsuv_http_req_t * UNUSED(req), char *body, ssize_t UNUSED(len)) {
    free(body);
}

static void ctrl_body_cb(tlsuv_http_req_t *req, char *b, ssize_t len) {
    struct ctrl_resp *resp = req->data;
    ziti_controller *ctrl = resp->ctrl;

    if (len > 0) {
        if (resp->resp_content == ctrl_content_json) {
            if (resp->content == NULL) {
#ifdef ZITI_DEBUG
                CTRL_LOG(DEBUG, "HTTP RESPONSE: %s", b);
#endif
                resp->content = json_tokener_parse_ex(resp->content_proc, b, (int) len);
                if (resp->content == NULL && json_tokener_get_error(resp->content_proc) != json_tokener_continue) {
                    CTRL_LOG(WARN, "parsing error: %s",
                             json_tokener_error_desc(json_tokener_get_error(resp->content_proc)));
                }
            } else {
                CTRL_LOG(WARN, "dropping unexpected extra data after JSON payload: %.*s",
                         (int)len, b);
            }
        } else {
            string_buf_appendn(resp->content_proc, b, len);
        }
    } else if (len == UV_EOF) {
        void *resp_obj = NULL;
        uv_timeval64_t now;
        uv_gettimeofday(&now);

        ziti_error error = {};
        if (resp->resp_content == ctrl_content_text) {
            if (resp->body_parse_func) {
                error.code = strdup("INVALID_CONTROLLER_RESPONSE");
                error.message = strdup("received non-JSON response");
            } else {
                resp_obj = string_buf_to_string(resp->content_proc, NULL);
            }
            string_buf_free(resp->content_proc);
            FREE(resp->content_proc);
        } else {
            json_object *err_json = json_object_object_get(resp->content, "error");
            if (err_json) {
                if (ziti_error_from_json(&error, err_json) != 0) {
                    error.code = strdup("INVALID_CONTROLLER_RESPONSE");
                    error.message = strdup(json_object_get_string(err_json));
                }
            }
            resp_meta meta = {0};
            resp_meta_from_json(&meta, json_object_object_get(resp->content, "meta"));
            json_object *data = json_object_object_get(resp->content, "data");
            data = json_object_get(data);
            json_object_put(resp->content);
            resp->content = NULL;

            if (resp->paging) {
                bool last_page = meta.pagination.total <=
                                 meta.pagination.offset + meta.pagination.limit;
                if (json_object_get_type(data) == json_type_array) {
                    resp->recd += json_object_array_length(data);
                    if (resp->resp_json == NULL) {
                        resp->resp_json = data;
                    } else {
                        for (int idx = 0; idx < json_object_array_length(data); idx++) {
                            json_object *o = json_object_array_get_idx(data, idx);
                            json_object_array_add(resp->resp_json, json_object_get(o));
                        }
                        json_object_put(data);
                        data = NULL;
                    }
                    CTRL_LOG(DEBUG, "received %d/%d for paging request GET[%s]",
                             resp->recd, (int)meta.pagination.total, resp->base_path);
                }
                if (!last_page) {
                    json_tokener_free(resp->content_proc);
                    resp->content_proc = NULL;
                    ctrl_paging_req(resp);
                    return;
                }
                uint64_t elapsed = (now.tv_sec * 1000000 + now.tv_usec) - (resp->all_start.tv_sec * 1000000 + resp->all_start.tv_usec);
                CTRL_LOG(DEBUG, "completed paging request GET[%s] in %" PRIu64 ".%03" PRIu64 " s",
                         resp->base_path, elapsed / 1000000, (elapsed / 1000) % 1000);

            } else {
                uint64_t elapsed = (now.tv_sec * 1000000 + now.tv_usec) - (resp->start.tv_sec * 1000000 + resp->start.tv_usec);
                CTRL_LOG(DEBUG, "completed %s[%s] in %" PRIu64 ".%03" PRIu64 " s",
                         req->method, req->path, elapsed / 1000000, (elapsed / 1000) % 1000);
                resp->resp_json = data;
            }
            
            if (resp->body_parse_func && resp->resp_json != NULL) {
                if (resp->body_parse_func(&resp_obj, resp->resp_json) < 0) {
                    CTRL_LOG(ERROR, "error parsing response data for req[%s]", req->path);
                    error.code = strdup("INVALID_CONTROLLER_RESPONSE");
                    error.message = strdup("unexpected response JSON");
                }
                json_object_put(resp->resp_json);
                resp->resp_json = NULL;
                json_tokener_free(resp->content_proc);
                resp->content_proc = NULL;
            }
        }

        if (error.code) {
            error.err = code_to_error(error.code);
            error.http_code = req->resp.code;

            CTRL_LOG(ERROR, "API request[%s] failed code[%s] message[%s]",
                     req->path, error.code, error.message);
        }
        if (error.err != ZITI_OK) {
            resp->ctrl_cb(NULL, &error, resp);
        } else {
            resp->ctrl_cb(resp_obj, NULL, resp);
        }
        free_ziti_error(&error);
    } else {
        CTRL_LOG(WARN, "failed to read response body: %zd[%s]", len, uv_strerror(len));
        if (resp->resp_content == ctrl_content_json) {
            json_tokener_free(resp->content_proc);
            json_object_put(resp->resp_json);
            resp->resp_json = NULL;
        } else {
            string_buf_free(resp->content_proc);
            FREE(resp->content_proc);
        }
        resp->content_proc = NULL;
        ziti_error err = {
                .err = ZITI_CONTROLLER_UNAVAILABLE,
                .code = "CONTROLLER_UNAVAILABLE",
                .message = (char *) uv_strerror((int)len),
        };

        if (len == UV_ECANCELED) {
            err.err = ZITI_DISABLED;
            err.code = "CONTEXT_DISABLED";
        }
        resp->resp_cb(NULL, &err, resp);
    }
}

// pick next random endpoint
static const char* ctrl_next_ep(ziti_controller *ctrl, const char *current) {
    if(model_map_size(&ctrl->endpoints) == 0) {
        CTRL_LOG(WARN, "empty endpoints map");
        return NULL;
    }
    uint64_t now = uv_now(ctrl->loop);
    ziti_controller_detail *curr = current ?
            model_map_get(&ctrl->endpoints, current) : NULL;

    if (curr) {
        curr->is_online = false;
        curr->offline_time = (model_number)now;
    }

    model_list online = {};
    model_list check = {};
    const char *url;
    ziti_controller_detail *d;
    MODEL_MAP_FOREACH(url, d, &ctrl->endpoints) {
        if (d == NULL || d->is_online) {
            model_list_append(&online, (void*)url);
        } else if ((uint64_t)d->offline_time < (now - ONE_MINUTE)) {
            model_list_append(&check, (void*)url);
        }
    }
    const char *next = NULL;
    if (model_list_size(&online) > 0) {
        int rand = (int) (uv_now(ctrl->loop) % model_list_size(&online));
        model_list_iter it = model_list_iterator(&online);
        for (int i = 0; i < rand; i++) {
            it = model_list_it_next(it);
        }
        next = model_list_it_element(it);
    } else if (model_list_size(&check) > 0) {
        model_list_iter it = model_list_iterator(&check);

        // no controller is online just try random one from the check list
        int rand = (int) (uv_now(ctrl->loop) % model_map_size(&ctrl->endpoints));
        for (int i = 0; i < rand; i++) {
            it = model_list_it_next(it);
        }
        next = model_list_it_element(it);
    } else {
        CTRL_LOG(WARN, "no controllers are online");
    }
    model_list_clear(&online, NULL);
    model_list_clear(&check, NULL);
    return next;
}

int ziti_ctrl_init(uv_loop_t *loop, ziti_controller *ctrl, model_list *urls, tls_context *tls) {
    *ctrl = (ziti_controller){0};
    if (model_list_size(urls) == 0) {
        ZITI_LOG(ERROR, "no ziti controller endpoints");
        return ZITI_INVALID_CONFIG;
    }
    ctrl->page_size = DEFAULT_PAGE_SIZE;
    ctrl->loop = loop;
    memset(&ctrl->version, 0, sizeof(ctrl->version));
    ctrl->client = calloc(1, sizeof(tlsuv_http_t));

    const char *ep;
    MODEL_LIST_FOREACH(ep, *urls) {
        ziti_controller_detail *detail = alloc_ziti_controller_detail();
        detail->name = strdup(ep);
        model_map_set(&ctrl->endpoints, ep, detail);
    }

    const char *initial_ep = ctrl_next_ep(ctrl, NULL);
    ctrl->url = strdup(initial_ep);
    CTRL_LOG(INFO, "using %s", ctrl->url);
    if (tlsuv_http_init(loop, ctrl->client, ep) != 0) {
        return ZITI_INVALID_CONFIG;
    }

    tlsuv_http_set_path_prefix(ctrl->client, "");
    ctrl->client->data = ctrl;
    tlsuv_http_set_ssl(ctrl->client, tls);
    tlsuv_http_idle_keepalive(ctrl->client, ZITI_CTRL_KEEPALIVE);
    tlsuv_http_connect_timeout(ctrl->client, ZITI_CTRL_TIMEOUT);
    tlsuv_http_header(ctrl->client, "Accept", "application/json");
    ctrl->has_token = false;
    ctrl->instance_id = NULL;

    CTRL_LOG(DEBUG, "ziti controller client initialized");
    internal_get_version(ctrl);
    return ZITI_OK;
}

int ziti_ctrl_set_token(ziti_controller *ctrl, const char *token) {
    if (token == NULL) {
        tlsuv_http_header(ctrl->client, "Authorization", NULL);
        ctrl->has_token = false;
        return 0;
    }

    string_buf_t *b = new_string_buf();
    string_buf_fmt(b, "Bearer %s", token);
    char *header = string_buf_to_string(b, NULL);

    ctrl->has_token = true;
    tlsuv_http_header(ctrl->client, "Authorization", header);

    free(header);
    delete_string_buf(b);

    if (ctrl->is_ha) {
        ziti_ctrl_list_controllers(ctrl, internal_ctrl_list_cb, ctrl);
    }

    return ZITI_OK;
}

void ziti_ctrl_set_page_size(ziti_controller *ctrl, unsigned int size) {
    ctrl->page_size = size;
}

void ziti_ctrl_set_callbacks(ziti_controller *ctrl, void *ctx,
                             ziti_ctrl_redirect_cb redirect_cb,
                             ziti_ctrl_change_cb change_cb) {
    ctrl->change_cb = change_cb;
    ctrl->redirect_cb = redirect_cb;
    ctrl->cb_ctx = ctx;
}

static void on_http_close(tlsuv_http_t *clt) {
    free(clt);
}

int ziti_ctrl_cancel(ziti_controller *ctrl) {
    return tlsuv_http_cancel_all(ctrl->client);
}

int ziti_ctrl_close(ziti_controller *ctrl) {
    free_ziti_version(&ctrl->version);
    model_map_clear(&ctrl->endpoints, (void (*)(void *)) free_ziti_controller_detail_ptr);
    FREE(ctrl->url);
    FREE(ctrl->instance_id);
    if (ctrl->client) {
        tlsuv_http_close(ctrl->client, on_http_close);
    }
    ctrl->client = NULL;
    return ZITI_OK;
}

static void internal_get_version(ziti_controller *ctrl) {
    struct ctrl_resp *resp = MAKE_RESP(ctrl, NULL, ziti_version_ptr_from_json, NULL);
    resp->ctrl_cb = (ctrl_cb_t) internal_version_cb;

    ctrl->version_req = start_request(ctrl->client, "GET", "/version", ctrl_resp_cb, resp);
}

void ziti_ctrl_get_version(ziti_controller *ctrl, ctrl_version_cb cb, void *ctx) {
    // already received version just callback with it
    if (ctrl->version.version != NULL) {
        cb(&ctrl->version, NULL, ctx);
        return;
    }
    ctrl->version_cb = cb;
    ctrl->version_cb_ctx = ctx;

    // if no version present and no active request
    // /version might have failed previously so try requesting it again
    if (ctrl->version_req == NULL) {
        internal_get_version(ctrl);
    }
}

void ziti_ctrl_login(
        ziti_controller *ctrl,
        model_list *cfg_types,
        void(*cb)(ziti_api_session *, const ziti_error *, void *),
        void *ctx) {

    ziti_auth_req authreq = {
            .sdk_info = {
                    .type = "ziti-sdk-c",
                    .version = (char *) ziti_get_build_version(0),
                    .revision = (char *) ziti_git_commit(),
                    .branch = (char *) ziti_git_branch(),
                    .app_id = (char *) APP_ID,
                    .app_version = (char *) APP_VERSION,
            },
            .env_info = (ziti_env_info *)get_env_info(),
            .config_types = {0}
    };
    if (cfg_types) {
        authreq.config_types = *cfg_types;
    }

    size_t body_len;
    char *body = ziti_auth_req_to_json(&authreq, 0, &body_len);


    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_api_session_ptr_from_json, ctx);
    resp->ctrl_cb = (ctrl_cb_t)ctrl_login_cb;

    tlsuv_http_req_t *req = start_request(ctrl->client, "POST", "/authenticate?method=cert", ctrl_resp_cb, resp);
    tlsuv_http_req_header(req, "Content-Type", "application/json");
    tlsuv_http_req_data(req, body, body_len, free_body_cb);

    if (ctrl->is_ha) {
        ziti_ctrl_list_controllers(ctrl, internal_ctrl_list_cb, ctrl);
    }
}


void ziti_ctrl_login_ext_jwt(ziti_controller *ctrl, const char *jwt,
                             void (*cb)(ziti_api_session *, const ziti_error *, void *),
                             void *ctx) {
    ziti_auth_req authreq = {
            .sdk_info = {
                    .type = "ziti-sdk-c",
                    .version = (char *) ziti_get_build_version(0),
                    .revision = (char *) ziti_git_commit(),
                    .branch = (char *) ziti_git_branch(),
                    .app_id = (char *) APP_ID,
                    .app_version = (char *) APP_VERSION,
            },
            .env_info = (ziti_env_info *)get_env_info(),
            .config_types = {0}
    };

    size_t body_len;
    char *body = ziti_auth_req_to_json(&authreq, 0, &body_len);

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_api_session_ptr_from_json, ctx);
    resp->ctrl_cb = (ctrl_cb_t)ctrl_login_cb;

    string_buf_t *auth = new_string_buf();
    string_buf_append(auth, "Bearer ");
    string_buf_append(auth, jwt);
    char *auth_hdr = string_buf_to_string(auth, NULL);

    tlsuv_http_req_t *req = start_request(ctrl->client, "POST", "/authenticate", ctrl_resp_cb, resp);
    tlsuv_http_req_header(req, "authorization", auth_hdr);
    tlsuv_http_req_header(req, "Content-Type", "application/json");
    tlsuv_http_req_query(req, 1, &(tlsuv_http_pair){"method", "ext-jwt"});
    tlsuv_http_req_data(req, body, body_len, free_body_cb);

    free(auth_hdr);
    string_buf_free(auth);
    FREE(auth);
}


static bool verify_api_session(ziti_controller *ctrl, ctrl_resp_cb_t cb, void *ctx) {
    if(!ctrl->has_token) {
        CTRL_LOG(WARN, "no API session");
        ziti_error err = {
                .err = ZITI_AUTHENTICATION_FAILED,
                .code = ERROR_CODE_UNAUTHORIZED,
                .message = ERROR_MSG_NO_API_SESSION_TOKEN,
        };
        cb(NULL, &err, ctx);
        return false;
    }

    return true;
}

void ziti_ctrl_current_identity(ziti_controller *ctrl, void(*cb)(ziti_identity_data *, const ziti_error *, void *), void *ctx) {
    if(!verify_api_session(ctrl, (void (*)(void *, const ziti_error *, void *)) cb, ctx)) return;

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_identity_data_ptr_from_json, ctx);
    start_request(ctrl->client, "GET", "/current-identity", ctrl_resp_cb, resp);
}

void ziti_ctrl_current_api_session(ziti_controller *ctrl, void(*cb)(ziti_api_session *, const ziti_error *, void *), void *ctx) {
    if(!verify_api_session(ctrl, (void (*)(void *, const ziti_error *, void *)) cb, ctx)) return;

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_api_session_ptr_from_json, ctx);
    resp->ctrl_cb = (ctrl_cb_t) ctrl_login_cb;

    start_request(ctrl->client, "GET", "/current-api-session", ctrl_resp_cb, resp);
}

void ziti_ctrl_list_controllers(ziti_controller *ctrl,
                                void (*cb)(ziti_controller_detail_array, const ziti_error*, void *ctx), void *ctx) {
    if(!verify_api_session(ctrl, (void (*)(void *, const ziti_error *, void *)) cb, ctx)) return;

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_controller_detail_array_from_json, ctx);
    resp->paging = true;
    resp->base_path = "/controllers";
    ctrl_paging_req(resp);
}

void ziti_ctrl_list_ext_jwt_signers(
        ziti_controller *ctrl,
        void (*cb)(ziti_jwt_signer_array, const ziti_error*, void *ctx), void *ctx) {
    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_jwt_signer_array_from_json, ctx);
    resp->paging = true;
    resp->base_path = "/external-jwt-signers";
    ctrl_paging_req(resp);
}

void ziti_ctrl_get_network_jwt(ziti_controller *ctrl, void(*cb)(ziti_network_jwt_array, const ziti_error*, void *ctx), void *ctx) {
    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_network_jwt_array_from_json, ctx);
    resp->paging = true;
    resp->base_path = "/network-jwts";
    ctrl_paging_req(resp);
}

void ziti_ctrl_logout(ziti_controller *ctrl, void(*cb)(void *, const ziti_error *, void *), void *ctx) {
    if(!verify_api_session(ctrl, cb, ctx)) return;

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, NULL, ctx);
    resp->ctrl_cb = (ctrl_cb_t) ctrl_logout_cb;

    start_request(ctrl->client, "DELETE", "/current-api-session", ctrl_resp_cb, resp);
}

void ziti_ctrl_get_services_update(ziti_controller *ctrl, void (*cb)(ziti_service_update *, const ziti_error *, void *), void *ctx) {
    if(!verify_api_session(ctrl, (void (*)(void *, const ziti_error *, void *)) cb, ctx)) return;

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_service_update_ptr_from_json, ctx);
    start_request(ctrl->client, "GET", "/current-api-session/service-updates", ctrl_resp_cb, resp);
}

void ziti_ctrl_get_services(ziti_controller *ctrl, void (*cb)(ziti_service_array, const ziti_error *, void *), void *ctx) {
    if(!verify_api_session(ctrl, (void (*)(void *, const ziti_error *, void *)) cb, ctx)) return;

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_service_array_from_json, ctx);

    resp->paging = true;
    resp->base_path = "/services?configTypes=all";
    ctrl_paging_req(resp);
}

void ziti_ctrl_current_edge_routers(ziti_controller *ctrl, void (*cb)(ziti_edge_router_array, const ziti_error *, void *),
                                    void *ctx) {
    if(!verify_api_session(ctrl, (void (*)(void *, const ziti_error *, void *)) cb, ctx)) return;

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_edge_router_array_from_json, ctx);
    resp->paging = true;
    resp->base_path = "/current-identity/edge-routers";
    ctrl_paging_req(resp);

    // piggy back controller list request
    if (ctrl->is_ha) {
        ziti_ctrl_list_controllers(ctrl, internal_ctrl_list_cb, ctrl);
    }
}

void
ziti_ctrl_get_service(ziti_controller *ctrl, const char *service_name, void (*cb)(ziti_service *, const ziti_error *, void *),
                      void *ctx) {
    if(!verify_api_session(ctrl, (void (*)(void *, const ziti_error *, void *)) cb, ctx)) return;

    char name_clause[1024];
    snprintf(name_clause, sizeof(name_clause), "name=\"%s\"", service_name);

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_service_array_from_json, ctx);
    resp->ctrl_cb = (ctrl_cb_t) ctrl_service_cb;

    tlsuv_http_req_t *req = start_request(ctrl->client, "GET", "/services", ctrl_resp_cb, resp);
    tlsuv_http_req_query(req, 1, &(tlsuv_http_pair){
        "filter", name_clause
    });
}

void ziti_ctrl_list_service_routers(ziti_controller *ctrl, const ziti_service *srv, routers_cb cb, void *ctx) {
    if(!verify_api_session(ctrl, (void (*)(void *, const ziti_error *, void *)) cb, ctx)) return;

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_service_routers_ptr_from_json, ctx);
    resp->ctrl_cb = (ctrl_cb_t) ctrl_default_cb;

    char path[512];
    snprintf(path, sizeof(path), "/services/%s/edge-routers", srv->id);
    tlsuv_http_req_t *req = start_request(ctrl->client, "GET", path, ctrl_resp_cb, resp);
    tlsuv_http_req_query(req, 2, (tlsuv_http_pair[]){
            { "offset", "0" },
            { "limit", "100" }
    });
}

void ziti_ctrl_get_session(
        ziti_controller *ctrl, const char *session_id,
        void (*cb)(ziti_session *, const ziti_error *, void *), void *ctx) {

    if (!verify_api_session(ctrl, (void (*)(void *, const ziti_error *, void *)) cb, ctx)) return;

    char req_path[128];
    snprintf(req_path, sizeof(req_path), "/sessions/%s", session_id);

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_session_ptr_from_json, ctx);
    tlsuv_http_req_t *req = start_request(ctrl->client, "GET", req_path, ctrl_resp_cb, resp);
    tlsuv_http_req_header(req, "Content-Type", "application/json");
}

void ziti_ctrl_create_session(
        ziti_controller *ctrl, const char *service_id, ziti_session_type type,
        void (*cb)(ziti_session *, const ziti_error *, void *), void *ctx) {

    if (!verify_api_session(ctrl, (void (*)(void *, const ziti_error *, void *)) cb, ctx)) return;

    char *content = malloc(128);
    size_t len = snprintf(content, 128,
                          "{\"serviceId\": \"%s\", \"type\": \"%s\"}",
                          service_id, ziti_session_types.name(type));

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_session_ptr_from_json, ctx);
    resp->ctrl = ctrl;
    tlsuv_http_req_t *req = start_request(ctrl->client, "POST", "/sessions", ctrl_resp_cb, resp);
    tlsuv_http_req_header(req, "Content-Type", "application/json");
    tlsuv_http_req_data(req, content, len, free_body_cb);
}

void ziti_ctrl_get_sessions(
        ziti_controller *ctrl, void (*cb)(ziti_session **, const ziti_error *, void *), void *ctx) {
    if(!verify_api_session(ctrl, (ctrl_resp_cb_t)cb, ctx)) return;

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_session_array_from_json, ctx);
    resp->paging = true;
    resp->base_path = "/sessions";
    ctrl_paging_req(resp);
}

static void enroll_pem_cb(void *body, const ziti_error *err, struct ctrl_resp *resp) {
    ziti_enrollment_resp *er = alloc_ziti_enrollment_resp();
    er->cert = (char *) body;
    if (resp->resp_cb) {
        resp->resp_cb(er, err, resp->ctx);
    }
}

static void ctrl_enroll_http_cb(tlsuv_http_resp_t *http_resp, void *data) {
    if (http_resp->code < 0) {
        ctrl_resp_cb(http_resp, data);
    }
    else {
        const char *content_type = tlsuv_http_resp_header(http_resp, "content-type");
        if (content_type != NULL && strcasecmp("application/x-pem-file", content_type) == 0) {
            struct ctrl_resp *resp = data;
            resp->resp_content = ctrl_content_text;
            resp->ctrl_cb = enroll_pem_cb;
        }
        ctrl_resp_cb(http_resp, data);
    }
}

void
ziti_ctrl_enroll(ziti_controller *ctrl, ziti_enrollment_method method, const char *token, const char *csr,
                 const char *name,
                 void (*cb)(ziti_enrollment_resp *, const ziti_error *, void *),
                 void *ctx) {
    char *csr_copy = csr ? strdup(csr) : NULL;

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_enrollment_resp_ptr_from_json, ctx);

    tlsuv_http_req_t *req = start_request(ctrl->client, "POST", "/enroll", ctrl_enroll_http_cb, resp);
    size_t q_count = method == ziti_enrollment_method_ca ? 1 : 2;
    const tlsuv_http_pair q_params[] = {
        { "method", ziti_enrollment_methods.name(method)},
        { "token",  token },
    };
    tlsuv_http_req_query(req, q_count, q_params);

    if (csr_copy) {
        tlsuv_http_req_header(req, "Content-Type", "text/plain");
        tlsuv_http_req_data(req, csr_copy, strlen(csr_copy), free_body_cb);
    } else {
        tlsuv_http_req_header(req, "Content-Type", "application/json");
        if (name != NULL) {
            ziti_identity id = {.name = name};
            size_t body_len;
            char *body = ziti_identity_to_json(&id, MODEL_JSON_COMPACT, &body_len);
            tlsuv_http_req_data(req, body, body_len, free_body_cb);
        }
    }
}

void
ziti_ctrl_get_well_known_certs(ziti_controller *ctrl, void (*cb)(char *, const ziti_error *, void *), void *ctx) {
    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, NULL, ctx);
    resp->resp_content = ctrl_content_text;   // Make no attempt in ctrl_resp_cb to parse response as JSON
    tlsuv_http_req_t *req = start_request(ctrl->client, "GET", "/.well-known/est/cacerts", ctrl_resp_cb, resp);
    tlsuv_http_req_header(req, "Accept", "application/pkcs7-mime");
}

void ziti_pr_post(ziti_controller *ctrl, char *body, size_t body_len,
                  void(*cb)(ziti_pr_response *, const ziti_error *, void *), void *ctx) {
    if (!verify_api_session(ctrl, (ctrl_resp_cb_t) cb, ctx)) { return; }

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_pr_response_ptr_from_json, ctx);

    tlsuv_http_req_t *req = start_request(ctrl->client, "POST", "/posture-response", ctrl_resp_cb, resp);
    tlsuv_http_req_header(req, "Content-Type", "application/json");
    tlsuv_http_req_data(req, body, body_len, free_body_cb);
}

void ziti_pr_post_bulk(ziti_controller *ctrl, char *body, size_t body_len,
                       void(*cb)(ziti_pr_response *, const ziti_error *, void *), void *ctx) {
    if (!verify_api_session(ctrl, (ctrl_resp_cb_t) cb, ctx)) { return; }

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_pr_response_ptr_from_json, ctx);

    tlsuv_http_req_t *req = start_request(ctrl->client, "POST", "/posture-response-bulk", ctrl_resp_cb, resp);
    tlsuv_http_req_header(req, "Content-Type", "application/json");
    tlsuv_http_req_data(req, body, body_len, free_body_cb);
}

static void ctrl_paging_req(struct ctrl_resp *resp) {
    ziti_controller *ctrl = resp->ctrl;
    if (resp->limit == 0) {
        resp->limit = ctrl->page_size;
    }
    if (resp->recd == 0) {
        uv_gettimeofday(&resp->all_start);
        CTRL_LOG(DEBUG, "starting paging request GET[%s]", resp->base_path);
    }
    char query = strchr(resp->base_path, '?') ? '&' : '?';
    char path[128];
    snprintf(path, sizeof(path), "%s%climit=%d&offset=%d", resp->base_path, query, resp->limit, resp->recd);
    CTRL_LOG(VERBOSE, "requesting %s", path);
    start_request(resp->ctrl->client, "GET", path, ctrl_resp_cb, resp);
}


void ziti_ctrl_login_mfa(ziti_controller *ctrl, char *body, size_t body_len, void(*cb)(void *, const ziti_error *, void *), void *ctx) {
    if (!verify_api_session(ctrl, cb, ctx)) { return; }

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, NULL, ctx);
    tlsuv_http_req_t *req = start_request(ctrl->client, "POST", "/authenticate/mfa", ctrl_resp_cb, resp);
    tlsuv_http_req_header(req, "Content-Type", "application/json");
    tlsuv_http_req_data(req, body, body_len, free_body_cb);
}

void ziti_ctrl_post_mfa(ziti_controller *ctrl, void(*cb)(void *, const ziti_error *, void *), void *ctx) {
    if (!verify_api_session(ctrl, cb, ctx)) { return; }

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, NULL, ctx);
    tlsuv_http_req_t *req = start_request(ctrl->client, "POST", "/current-identity/mfa", ctrl_resp_cb, resp);
    tlsuv_http_req_header(req, "Content-Type", "application/json");
    tlsuv_http_req_data(req, NULL, 0, free_body_cb);
}

void ziti_ctrl_get_mfa(ziti_controller *ctrl, void(*cb)(ziti_mfa_enrollment *, const ziti_error *, void *), void *ctx) {
    if (!verify_api_session(ctrl, (ctrl_resp_cb_t) cb, ctx)) { return; }

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_mfa_enrollment_ptr_from_json, ctx);

    tlsuv_http_req_t *req = start_request(ctrl->client, "GET", "/current-identity/mfa", ctrl_resp_cb, resp);
    tlsuv_http_req_header(req, "Content-Type", "application/json");
}

void ziti_ctrl_delete_mfa(ziti_controller *ctrl, char *code, void(*cb)(void *, const ziti_error *, void *), void *ctx) {
    if (!verify_api_session(ctrl, cb, ctx)) { return; }

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, NULL, ctx);
    tlsuv_http_req_t *req = start_request(ctrl->client, "DELETE", "/current-identity/mfa", ctrl_resp_cb, resp);
    tlsuv_http_req_header(req, "Content-Type", "application/json");
    tlsuv_http_req_header(req, "mfa-validation-code", code);
}

void ziti_ctrl_post_mfa_verify(ziti_controller *ctrl, char *body, size_t body_len, void(*cb)(void *, const ziti_error *, void *), void *ctx) {
    if (!verify_api_session(ctrl, cb, ctx)) { return; }

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, NULL, ctx);
    tlsuv_http_req_t *req = start_request(ctrl->client, "POST", "/current-identity/mfa/verify", ctrl_resp_cb, resp);
    tlsuv_http_req_header(req, "Content-Type", "application/json");
    tlsuv_http_req_data(req, body, body_len, free_body_cb);
}

void ziti_ctrl_get_mfa_recovery_codes(ziti_controller *ctrl, char *code, void(*cb)(ziti_mfa_recovery_codes *, const ziti_error *, void *), void *ctx) {
    if (!verify_api_session(ctrl, (ctrl_resp_cb_t) cb, ctx)) { return; }

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_mfa_recovery_codes_ptr_from_json, ctx);

    tlsuv_http_req_t *req = start_request(ctrl->client, "GET", "/current-identity/mfa/recovery-codes", ctrl_resp_cb,
                                          resp);
    tlsuv_http_req_header(req, "mfa-validation-code", code);
    tlsuv_http_req_header(req, "Content-Type", "application/json");
}

void ziti_ctrl_post_mfa_recovery_codes(ziti_controller *ctrl, char *body, size_t body_len, void(*cb)(void *, const ziti_error *, void *), void *ctx) {
    if (!verify_api_session(ctrl, cb, ctx)) { return; }

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, NULL, ctx);

    tlsuv_http_req_t *req = start_request(ctrl->client, "POST", "/current-identity/mfa/recovery-codes", ctrl_resp_cb,
                                          resp);
    tlsuv_http_req_header(req, "Content-Type", "application/json");
    tlsuv_http_req_data(req, body, body_len, free_body_cb);
}

void ziti_ctrl_extend_cert_authenticator(ziti_controller *ctrl, const char *authenticatorId, const char *csr, void(*cb)(ziti_extend_cert_authenticator_resp*, const ziti_error *, void *), void *ctx) {
    if(!verify_api_session(ctrl, (ctrl_resp_cb_t) cb, ctx)) return;

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_extend_cert_authenticator_resp_ptr_from_json, ctx);

    char path[128];
    snprintf(path, sizeof(path), "/current-identity/authenticators/%s/extend", authenticatorId);

    ziti_extend_cert_authenticator_req extend_req;
    extend_req.client_cert_csr = csr;

    size_t body_len;
    char *body = ziti_extend_cert_authenticator_req_to_json(&extend_req, 0, &body_len);

    tlsuv_http_req_t *req = start_request(ctrl->client, "POST", path, ctrl_resp_cb, resp);
    tlsuv_http_req_header(req, "Content-Type", "application/json");
    tlsuv_http_req_data(req, body, body_len, free_body_cb);
}

void ziti_ctrl_verify_extend_cert_authenticator(ziti_controller *ctrl, const char *authenticatorId, const char *client_cert, void(*cb)(void *, const ziti_error *, void *), void *ctx) {
    if(!verify_api_session(ctrl, cb, ctx)) return;

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, NULL, ctx);

    char path[256];
    snprintf(path, sizeof(path), "/current-identity/authenticators/%s/extend-verify", authenticatorId);

    ziti_verify_extend_cert_authenticator_req verify_req;
    verify_req.client_cert = client_cert;

    size_t body_len;
    char *body = ziti_verify_extend_cert_authenticator_req_to_json(&verify_req, 0, &body_len);

    tlsuv_http_req_t *req = start_request(ctrl->client, "POST", path, ctrl_resp_cb, resp);
    tlsuv_http_req_header(req, "Content-Type", "application/json");
    tlsuv_http_req_data(req, body, body_len, free_body_cb);
}

void ziti_ctrl_create_api_certificate(ziti_controller *ctrl, const char *csr_pem,
                                      void(*cb)(ziti_create_api_cert_resp *, const ziti_error *, void *), void *ctx) {

    if(!verify_api_session(ctrl, (ctrl_resp_cb_t) cb, ctx)) return;

    struct ctrl_resp *resp = MAKE_RESP(ctrl, cb, ziti_create_api_cert_resp_ptr_from_json, ctx);

    const char *path = "/current-api-session/certificates";

    ziti_create_api_cert_req cert_req = {
            .client_cert_csr = (char*)csr_pem
    };

    size_t body_len;
    char *body = ziti_create_api_cert_req_to_json(&cert_req, 0, &body_len);

    tlsuv_http_req_t *req = start_request(ctrl->client, "POST", path, ctrl_resp_cb, resp);
    tlsuv_http_req_header(req, "Content-Type", "application/json");
    tlsuv_http_req_data(req, body, body_len, free_body_cb);
}

static struct ctrl_resp *prepare_resp(ziti_controller *ctrl, ctrl_resp_cb_t cb, body_parse_fn parser, void *ctx) {
    struct ctrl_resp *resp = calloc(1, sizeof(struct ctrl_resp));
    resp->body_parse_func = parser;
    resp->resp_cb = cb;
    resp->ctx = ctx;
    resp->ctrl = ctrl;
    resp->ctrl_cb = ctrl_default_cb;
    return resp;
}