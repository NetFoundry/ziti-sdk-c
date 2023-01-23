// Copyright (c) 2022-2023.  NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "zt_internal.h"
#include "utils.h"

#define BRIDGE_MSG_SIZE (32 * 1024)
#define BRIDGE_POOL_SIZE 16

struct fd_bridge_s {
    uv_os_fd_t in;
    uv_os_fd_t out;

    void (*close_cb)(void *ctx);

    void *ctx;
};

struct ziti_bridge_s {
    bool closed;
    bool ziti_eof;
    bool input_eof;
    ziti_connection conn;
    uv_stream_t *input;
    uv_stream_t *output;
    uv_close_cb close_cb;
    void *data;
    struct fd_bridge_s *fdbr;
    pool_t *input_pool;
    bool input_throttle;
};

static ssize_t on_ziti_data(ziti_connection conn, const uint8_t *data, ssize_t len);

static void bridge_alloc(uv_handle_t *h, size_t req, uv_buf_t *b);

static void on_input(uv_stream_t *s, ssize_t len, const uv_buf_t *b);


extern int ziti_conn_bridge(ziti_connection conn, uv_stream_t *stream, uv_close_cb on_close) {
    NEWP(br, struct ziti_bridge_s);
    br->conn = conn;
    br->input = stream;
    br->output = stream;
    br->close_cb = on_close;
    br->data = uv_handle_get_data((const uv_handle_t *) stream);
    br->input_pool = pool_new(BRIDGE_MSG_SIZE, BRIDGE_POOL_SIZE, NULL);

    uv_handle_set_data((uv_handle_t *) stream, br);
    ziti_conn_set_data(conn, br);

    ziti_conn_set_data_cb(conn, on_ziti_data);
    uv_read_start(br->input, bridge_alloc, on_input);

    return ZITI_OK;
}

static void on_sock_close(uv_handle_t *h) {
    struct fd_bridge_s *fdbr = h->data;
    if (fdbr) {
        if (fdbr->close_cb) {
            fdbr->close_cb(fdbr->ctx);
        }
        free(fdbr);
    }
    uv_close(h, (uv_close_cb) free);
}

static void on_pipes_close(uv_handle_t *h) {
    struct ziti_bridge_s *br = h->data;
    uv_close((uv_handle_t *) br->input, (uv_close_cb) free);
    uv_close((uv_handle_t *) br->output, (uv_close_cb) free);
    if (br->fdbr) {
        if (br->fdbr->close_cb) {
            br->fdbr->close_cb(br->fdbr->ctx);
        }
        free(br->fdbr);
    }
}

extern int ziti_conn_bridge_fds(ziti_connection conn, uv_os_fd_t input, uv_os_fd_t output, void (*close_cb)(void *ctx), void *ctx) {
    uv_loop_t *l = ziti_conn_context(conn)->loop;

    NEWP(fdbr, struct fd_bridge_s);
    fdbr->in = input;
    fdbr->out = output;
    fdbr->close_cb = close_cb;
    fdbr->ctx = ctx;

    if (input == output) {
        uv_tcp_t *sock = calloc(1, sizeof(uv_tcp_t));
        uv_tcp_init(l, sock);
        uv_tcp_open(sock, input);
        sock->data = fdbr;
        return ziti_conn_bridge(conn, (uv_stream_t *) sock, on_sock_close);
    }

    NEWP(br, struct ziti_bridge_s);
    br->conn = conn;
    br->input = calloc(1, sizeof(uv_pipe_t));
    br->output = calloc(1, sizeof(uv_pipe_t));
    br->input_pool = pool_new(BRIDGE_MSG_SIZE, BRIDGE_POOL_SIZE, NULL);

    uv_pipe_init(l, (uv_pipe_t *) br->input, 0);
    uv_pipe_init(l, (uv_pipe_t *) br->output, 0);
    uv_pipe_open((uv_pipe_t *) br->input, input);
    uv_pipe_open((uv_pipe_t *) br->output, output);
    br->input->data = br;
    br->output->data = br;

    br->close_cb = on_pipes_close;

    br->data = br;
    br->fdbr = fdbr;

    uv_handle_set_data((uv_handle_t *) br->input, br);
    ziti_conn_set_data(conn, br);

    ziti_conn_set_data_cb(conn, on_ziti_data);
    uv_read_start(br->input, bridge_alloc, on_input);

    return ZITI_OK;
}

static void on_ziti_close(ziti_connection conn) {
    struct ziti_bridge_s *br = ziti_conn_data(conn);
    pool_destroy(br->input_pool);
    free(br);
}

static void close_bridge(struct ziti_bridge_s *br) {
    if (br == NULL || br->closed) { return; }

    br->closed = true;

    if (br->input) {
        uv_handle_set_data((uv_handle_t *) br->input, br->data);
        br->close_cb((uv_handle_t *) br->input);
        br->input = NULL;
    }

    ziti_close(br->conn, on_ziti_close);
}

static void on_output(uv_write_t *wr, int status) {
    if (status != 0) {
        struct ziti_bridge_s *br = wr->handle->data;
        ZITI_LOG(WARN, "write failed: %d(%s)", status, uv_strerror(status));
        close_bridge(br);
    }
    free(wr->data);
    free(wr);
}

static void on_shutdown(uv_shutdown_t *sr, int status) {
    if (status != 0) {
        ZITI_LOG(WARN, "shutdown failed: %d(%s)", status, uv_strerror(status));
        close_bridge(sr->handle->data);
    }
    free(sr);
}

ssize_t on_ziti_data(ziti_connection conn, const uint8_t *data, ssize_t len) {
    struct ziti_bridge_s *br = ziti_conn_data(conn);
    if (len > 0) {
        NEWP(wr, uv_write_t);
        uv_buf_t b = uv_buf_init(malloc(len), len);
        memcpy(b.base, data, len);
        wr->data = b.base;
        uv_write(wr, br->output, &b, 1, on_output);
        return len;
    } else if (len == ZITI_EOF) {
        br->ziti_eof = true;
        if (br->input_eof) {
            ZITI_LOG(VERBOSE, "both sides are EOF");
            close_bridge(br);
        } else {
            NEWP(sr, uv_shutdown_t);
            uv_shutdown(sr, br->output, on_shutdown);
        }
    } else {
        close_bridge(br);
    }
    return 0;
}

void bridge_alloc(uv_handle_t *h, size_t req, uv_buf_t *b) {
    struct ziti_bridge_s *br = h->data;
    b->base = pool_alloc_obj(br->input_pool);
    b->len = pool_obj_size(b->base);
    if (b->base != NULL) {
        if (br->input_throttle) {
            ZITI_LOG(TRACE, "unstalled ziti_conn[%d.%d]", br->conn->ziti_ctx->id, br->conn->conn_id);
        }
        br->input_throttle = false;
    }
}

static void on_ziti_write(ziti_connection conn, ssize_t status, void *ctx) {
    pool_return_obj(ctx);
    if (status < ZITI_OK) {
        close_bridge(ziti_conn_data(conn));
    }
}

void on_input(uv_stream_t *s, ssize_t len, const uv_buf_t *b) {
    struct ziti_bridge_s *br = s->data;
    if (len > 0) {
        ziti_write(br->conn, b->base, len, on_ziti_write, b->base);
    } else {
        pool_return_obj(b->base);
        if (len == UV_ENOBUFS) {
            if (!br->input_throttle) {
                ZITI_LOG(TRACE, "stalled ziti_conn[%d.%d]", br->conn->ziti_ctx->id, br->conn->conn_id);
                br->input_throttle = true;
            }
        } else if (len == UV_EOF) {
            br->input_eof = true;
            if (br->ziti_eof) {
                ZITI_LOG(VERBOSE, "both sides are EOF");
                close_bridge(br);
            } else {
                ziti_close_write(br->conn);
            }
        } else if (len < 0) {
            ZITI_LOG(WARN, "err = %zd", len);
            close_bridge(br);
        }
    }
}
