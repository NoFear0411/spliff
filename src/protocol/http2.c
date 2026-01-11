/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "http2.h"
#include "../util/safe_str.h"
#include "../output/display.h"
#include "../content/decompressor.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <strings.h>

#ifdef HAVE_NGHTTP2
#include <nghttp2/nghttp2.h>
#include <unistd.h>
#include <libgen.h>

/*
 * Get real process name from /proc/PID/exe (not thread name).
 * For threaded processes like Firefox, /proc/PID/comm gives thread name
 * (e.g., "Socket Thread"), but /proc/PID/exe gives the actual executable.
 */
static void h2_get_process_name(uint32_t pid, char *buf, size_t bufsize) {
    char path[64];
    char link[256];

    if (bufsize == 0) return;
    buf[0] = '\0';

    snprintf(path, sizeof(path), "/proc/%u/exe", pid);
    ssize_t len = readlink(path, link, sizeof(link) - 1);
    if (len > 0) {
        link[len] = '\0';
        /* Extract basename */
        char *base = strrchr(link, '/');
        if (base) {
            base++;
        } else {
            base = link;
        }
        /* Copy, handling " (deleted)" suffix if process exited */
        char *deleted = strstr(base, " (deleted)");
        if (deleted) {
            size_t copylen = deleted - base;
            if (copylen >= bufsize) copylen = bufsize - 1;
            memcpy(buf, base, copylen);
            buf[copylen] = '\0';
        } else {
            size_t copylen = strlen(base);
            if (copylen >= bufsize) copylen = bufsize - 1;
            memcpy(buf, base, copylen);
            buf[copylen] = '\0';
        }
    }
}

/* Forward declarations */
static void h2_display_request(h2_stream_t *stream);
static void h2_display_response(h2_stream_t *stream);
static void h2_display_body(h2_stream_t *stream, direction_t dir);

/* Session direction - nghttp2 requires different parsers */
typedef enum {
    H2_DIR_CLIENT = 0,  /* Parses server->client data (responses) */
    H2_DIR_SERVER = 1   /* Parses client->server data (requests) */
} h2_dir_t;

/* Forward declaration */
typedef struct h2_callback_ctx h2_callback_ctx_t;

/* Response reassembly buffer size */
#define H2_REASSEMBLY_BUF_SIZE 65536

/* Per-connection HTTP/2 session state */
typedef struct {
    uint32_t pid;
    uint64_t ssl_ctx;        /* SSL context pointer for connection tracking */
    bool active;

    /* nghttp2 server session for parsing requests */
    nghttp2_session *server_session;

    /* HPACK inflater for decoding response headers directly */
    nghttp2_hd_inflater *response_inflater;

    /* Callback context for server session */
    h2_callback_ctx_t *server_ctx;

    /* Connection state */
    bool client_preface_seen;
    bool server_settings_seen;

    /* Response reassembly buffer for fragmented frames */
    uint8_t *response_buf;
    size_t response_buf_len;

    /* HPACK error tracking for mid-stream recovery */
    uint16_t hpack_error_count;    /* Consecutive HPACK decode errors */
    uint16_t hpack_success_count;  /* Consecutive successful decodes */
    bool mid_stream_joined;        /* Detected mid-stream join */

    /* Timestamp for cleanup */
    uint64_t last_activity_ns;

    /* Process name cache */
    char comm[TASK_COMM_LEN];

    /* ALPN negotiated protocol */
    char alpn_proto[16];
} h2_connection_t;

/* Context passed to nghttp2 callbacks */
struct h2_callback_ctx {
    uint32_t pid;
    uint64_t ssl_ctx;
    h2_connection_t *conn;
    const ssl_data_event_t *event;
    h2_dir_t direction;
};

/* Global state */
static h2_connection_t g_h2_connections[MAX_H2_SESSIONS];
static h2_stream_t g_h2_streams[MAX_H2_STREAMS];
static nghttp2_session_callbacks *g_h2_callbacks = NULL;
static bool g_h2_initialized = false;

/* Get current time in nanoseconds */
static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* Stream management */
h2_stream_t *http2_get_stream(uint32_t pid, uint64_t ssl_ctx, int32_t stream_id, bool create) {
    /* Find existing by (pid, ssl_ctx, stream_id) */
    for (int i = 0; i < MAX_H2_STREAMS; i++) {
        if (g_h2_streams[i].active &&
            g_h2_streams[i].pid == pid &&
            g_h2_streams[i].ssl_ctx == ssl_ctx &&
            g_h2_streams[i].stream_id == stream_id) {
            return &g_h2_streams[i];
        }
    }

    if (!create) return NULL;

    /* Find empty slot or evict closed stream */
    h2_stream_t *slot = NULL;
    for (int i = 0; i < MAX_H2_STREAMS; i++) {
        if (!g_h2_streams[i].active) {
            slot = &g_h2_streams[i];
            break;
        }
    }

    if (!slot) {
        /* Evict oldest closed stream */
        for (int i = 0; i < MAX_H2_STREAMS; i++) {
            if (g_h2_streams[i].state == H2_STREAM_CLOSED) {
                http2_free_stream(g_h2_streams[i].pid, g_h2_streams[i].ssl_ctx,
                                  g_h2_streams[i].stream_id);
                slot = &g_h2_streams[i];
                break;
            }
        }
    }

    if (!slot) return NULL;

    /* Initialize stream */
    memset(slot, 0, sizeof(*slot));
    slot->pid = pid;
    slot->ssl_ctx = ssl_ctx;
    slot->stream_id = stream_id;
    slot->active = true;
    slot->state = H2_STREAM_OPEN;

    /* Allocate body buffer */
    slot->body_buf_size = H2_BODY_BUFFER_SIZE;
    slot->body_buf = malloc(slot->body_buf_size);
    if (!slot->body_buf) {
        slot->active = false;
        slot->body_buf_size = 0;
        return NULL;  /* Allocation failed */
    }

    return slot;
}

void http2_free_stream(uint32_t pid, uint64_t ssl_ctx, int32_t stream_id) {
    for (int i = 0; i < MAX_H2_STREAMS; i++) {
        if (g_h2_streams[i].active &&
            g_h2_streams[i].pid == pid &&
            g_h2_streams[i].ssl_ctx == ssl_ctx &&
            g_h2_streams[i].stream_id == stream_id) {
            if (g_h2_streams[i].body_buf) {
                free(g_h2_streams[i].body_buf);
                g_h2_streams[i].body_buf = NULL;
            }
            g_h2_streams[i].active = false;
            return;
        }
    }
}

/* Forward declaration for cleanup */
static void h2_connection_cleanup(h2_connection_t *conn);

void http2_cleanup_pid(uint32_t pid) {
    /* Free all streams for this PID */
    for (int i = 0; i < MAX_H2_STREAMS; i++) {
        if (g_h2_streams[i].active && g_h2_streams[i].pid == pid) {
            if (g_h2_streams[i].body_buf) {
                free(g_h2_streams[i].body_buf);
                g_h2_streams[i].body_buf = NULL;
            }
            g_h2_streams[i].active = false;
        }
    }

    /* Free all connections for this PID */
    for (int i = 0; i < MAX_H2_SESSIONS; i++) {
        if (g_h2_connections[i].active && g_h2_connections[i].pid == pid) {
            h2_connection_cleanup(&g_h2_connections[i]);
        }
    }
}

/* nghttp2 callbacks */
static int on_begin_headers_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
    h2_callback_ctx_t *ctx = (h2_callback_ctx_t *)user_data;

    DEBUG_H2("on_begin_headers: stream=%d type=%d dir=%s",
             frame->hd.stream_id, frame->hd.type,
             ctx->direction == H2_DIR_SERVER ? "request" : "response");

    if (frame->hd.type != NGHTTP2_HEADERS) {
        return 0;
    }

    /* Only process on appropriate session */
    if (ctx->direction == H2_DIR_SERVER) {
        /* Server session sees requests - create/update stream state */
        h2_stream_t *stream = http2_get_stream(ctx->pid, ctx->ssl_ctx, frame->hd.stream_id, true);
        if (!stream) {
            return 0;
        }

        /* Reset headers for new block */
        stream->header_count = 0;

        /* Capture timing */
        if (ctx->event) {
            stream->request_time_ns = ctx->event->timestamp_ns;
            stream->delta_ns = ctx->event->delta_ns;
            /* Resolve actual process name (not thread name) */
            if (!stream->comm[0]) {
                h2_get_process_name(ctx->pid, stream->comm, sizeof(stream->comm));
                /* Fall back to event comm if resolution failed */
                if (!stream->comm[0] && ctx->event->comm[0]) {
                    safe_strcpy(stream->comm, sizeof(stream->comm), ctx->event->comm);
                }
            }
        }
    } else {
        /* Client session sees responses - update existing stream */
        h2_stream_t *stream = http2_get_stream(ctx->pid, ctx->ssl_ctx, frame->hd.stream_id, false);
        if (!stream) {
            DEBUG_H2("Response for unknown stream %d", frame->hd.stream_id);
            return 0;
        }

        /* Reset headers for response block */
        stream->header_count = 0;

        if (ctx->event) {
            stream->response_time_ns = ctx->event->timestamp_ns;
        }
    }

    return 0;
}

static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame,
                              const uint8_t *name, size_t namelen,
                              const uint8_t *value, size_t valuelen,
                              uint8_t flags,
                              void *user_data) {
    (void)session;
    (void)flags;
    h2_callback_ctx_t *ctx = (h2_callback_ctx_t *)user_data;

    DEBUG_H2("on_header: stream=%d '%.*s: %.*s'",
             frame->hd.stream_id, (int)namelen, name, (int)valuelen, value);

    h2_stream_t *stream = http2_get_stream(ctx->pid, ctx->ssl_ctx, frame->hd.stream_id, false);
    if (!stream) {
        DEBUG_H2("on_header: stream %d not found!", frame->hd.stream_id);
        return 0;
    }

    /* Handle pseudo-headers (start with ':') */
    if (namelen > 0 && name[0] == ':') {
        if (namelen == 7 && memcmp(name, ":method", 7) == 0) {
            size_t copylen = valuelen < sizeof(stream->method) - 1 ? valuelen : sizeof(stream->method) - 1;
            memcpy(stream->method, value, copylen);
            stream->method[copylen] = '\0';
        } else if (namelen == 5 && memcmp(name, ":path", 5) == 0) {
            size_t copylen = valuelen < sizeof(stream->path) - 1 ? valuelen : sizeof(stream->path) - 1;
            memcpy(stream->path, value, copylen);
            stream->path[copylen] = '\0';
        } else if (namelen == 10 && memcmp(name, ":authority", 10) == 0) {
            size_t copylen = valuelen < sizeof(stream->authority) - 1 ? valuelen : sizeof(stream->authority) - 1;
            memcpy(stream->authority, value, copylen);
            stream->authority[copylen] = '\0';
        } else if (namelen == 7 && memcmp(name, ":scheme", 7) == 0) {
            size_t copylen = valuelen < sizeof(stream->scheme) - 1 ? valuelen : sizeof(stream->scheme) - 1;
            memcpy(stream->scheme, value, copylen);
            stream->scheme[copylen] = '\0';
        } else if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
            char status_str[8] = {0};
            size_t copylen = valuelen < 7 ? valuelen : 7;
            memcpy(status_str, value, copylen);
            stream->status_code = atoi(status_str);
        }
        return 0;
    }

    /* Store regular header */
    if (stream->header_count < MAX_HEADERS) {
        http_header_t *hdr = &stream->headers[stream->header_count];
        size_t name_copylen = namelen < sizeof(hdr->name) - 1 ? namelen : sizeof(hdr->name) - 1;
        size_t val_copylen = valuelen < sizeof(hdr->value) - 1 ? valuelen : sizeof(hdr->value) - 1;

        memcpy(hdr->name, name, name_copylen);
        hdr->name[name_copylen] = '\0';
        memcpy(hdr->value, value, val_copylen);
        hdr->value[val_copylen] = '\0';

        stream->header_count++;

        /* Extract special headers */
        if (strcasecmp(hdr->name, "content-type") == 0) {
            safe_strcpy(stream->content_type, sizeof(stream->content_type), hdr->value);
        } else if (strcasecmp(hdr->name, "content-encoding") == 0) {
            safe_strcpy(stream->content_encoding, sizeof(stream->content_encoding), hdr->value);
        } else if (strcasecmp(hdr->name, "content-length") == 0) {
            stream->content_length = strtoull(hdr->value, NULL, 10);
        }
    }

    return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame,
                                  void *user_data) {
    (void)session;
    h2_callback_ctx_t *ctx = (h2_callback_ctx_t *)user_data;

    DEBUG_H2("on_frame_recv: type=%s(%d) stream=%d flags=0x%02x",
             http2_frame_name(frame->hd.type), frame->hd.type,
             frame->hd.stream_id, frame->hd.flags);

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        /* Headers complete - check END_HEADERS flag */
        if (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) {
            h2_stream_t *stream = http2_get_stream(ctx->pid, ctx->ssl_ctx, frame->hd.stream_id, false);
            if (stream) {
                if (ctx->direction == H2_DIR_SERVER) {
                    /* Request headers complete - only display once */
                    if (!stream->request_headers_done) {
                        stream->request_headers_done = true;
                        h2_display_request(stream);
                    }

                    /* If END_STREAM also set, request is complete (no body) */
                    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                        stream->request_complete = true;
                    }
                } else {
                    /* Response headers complete - only display once */
                    if (!stream->response_headers_done) {
                        stream->response_headers_done = true;
                        h2_display_response(stream);

                        /* If END_STREAM also set, response is complete (no body) */
                        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                            stream->response_complete = true;
                            printf("\n");
                        }
                    }
                }
            }
        }
        break;

    case NGHTTP2_DATA:
        /* DATA frame - check END_STREAM */
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            h2_stream_t *stream = http2_get_stream(ctx->pid, ctx->ssl_ctx, frame->hd.stream_id, false);
            if (stream) {
                if (ctx->direction == H2_DIR_SERVER) {
                    /* Request body complete */
                    stream->request_complete = true;
                    h2_display_body(stream, DIR_REQUEST);
                } else {
                    /* Response body complete */
                    stream->response_complete = true;
                    h2_display_body(stream, DIR_RESPONSE);
                }
            }
        }
        break;

    case NGHTTP2_SETTINGS:
        if (frame->hd.flags & NGHTTP2_FLAG_ACK) {
            /* SETTINGS ACK - connection fully established */
        } else {
            if (ctx->direction == H2_DIR_CLIENT) {
                ctx->conn->server_settings_seen = true;
            }
        }
        break;

    case NGHTTP2_GOAWAY:
        /* Connection closing - could cleanup sessions here */
        break;

    case NGHTTP2_RST_STREAM:
        /* Stream reset - mark as closed */
        {
            h2_stream_t *stream = http2_get_stream(ctx->pid, ctx->ssl_ctx, frame->hd.stream_id, false);
            if (stream) {
                stream->state = H2_STREAM_CLOSED;
            }
        }
        break;

    default:
        break;
    }

    return 0;
}

static int on_data_chunk_recv_callback(nghttp2_session *session,
                                       uint8_t flags,
                                       int32_t stream_id,
                                       const uint8_t *data,
                                       size_t len,
                                       void *user_data) {
    (void)session;
    (void)flags;
    h2_callback_ctx_t *ctx = (h2_callback_ctx_t *)user_data;

    h2_stream_t *stream = http2_get_stream(ctx->pid, ctx->ssl_ctx, stream_id, false);
    if (!stream || !stream->body_buf) return 0;

    /* Accumulate body data */
    size_t available = stream->body_buf_size - stream->body_len;
    size_t to_copy = (len < available) ? len : available;

    if (to_copy > 0) {
        memcpy(stream->body_buf + stream->body_len, data, to_copy);
        stream->body_len += to_copy;
    }

    return 0;
}

static int on_stream_close_callback(nghttp2_session *session,
                                    int32_t stream_id,
                                    uint32_t error_code,
                                    void *user_data) {
    (void)session;
    (void)error_code;
    h2_callback_ctx_t *ctx = (h2_callback_ctx_t *)user_data;

    h2_stream_t *stream = http2_get_stream(ctx->pid, ctx->ssl_ctx, stream_id, false);
    if (stream) {
        stream->state = H2_STREAM_CLOSED;

        /* Display any remaining body data if not yet shown */
        if (stream->body_len > 0 && !stream->response_complete) {
            h2_display_body(stream, DIR_RESPONSE);
        }
    }

    return 0;
}

static int on_invalid_frame_recv_callback(nghttp2_session *session,
                                          const nghttp2_frame *frame,
                                          int lib_error_code,
                                          void *user_data) {
    (void)session;
#ifdef DEBUG
    h2_callback_ctx_t *ctx = (h2_callback_ctx_t *)user_data;
    DEBUG_H2("INVALID FRAME: type=%s stream=%d error=%d (%s) dir=%s",
             http2_frame_name(frame->hd.type), frame->hd.stream_id,
             lib_error_code, nghttp2_strerror(lib_error_code),
             ctx->direction == H2_DIR_SERVER ? "server" : "client");
#else
    (void)frame;
    (void)lib_error_code;
    (void)user_data;
#endif
    return 0;
}

static int on_error_callback(nghttp2_session *session,
                             int lib_error_code,
                             const char *msg,
                             size_t len,
                             void *user_data) {
    (void)session;
    (void)user_data;
    DEBUG_H2("ERROR: code=%d msg=%.*s", lib_error_code, (int)len, msg);
    return 0;
}

/* Display functions */
static void h2_display_request(h2_stream_t *stream) {
    DEBUG_H2("h2_display_request: stream=%d method='%s' path='%s' authority='%s'",
             stream->stream_id, stream->method, stream->path, stream->authority);

    /* Build http_message_t from stream state */
    http_message_t msg = {0};

    msg.protocol = PROTO_HTTP2;
    msg.direction = DIR_REQUEST;
    msg.stream_id = stream->stream_id;
    msg.pid = stream->pid;
    msg.timestamp_ns = stream->request_time_ns;
    msg.delta_ns = stream->delta_ns;

    safe_strcpy(msg.method, sizeof(msg.method), stream->method);
    safe_strcpy(msg.path, sizeof(msg.path), stream->path);
    safe_strcpy(msg.authority, sizeof(msg.authority), stream->authority);
    safe_strcpy(msg.scheme, sizeof(msg.scheme),
                stream->scheme[0] ? stream->scheme : "https");
    safe_strcpy(msg.comm, sizeof(msg.comm), stream->comm);

    /* Get ALPN protocol from connection */
    const char *alpn = http2_get_alpn(stream->pid, stream->ssl_ctx);
    if (alpn && alpn[0]) {
        safe_strcpy(msg.alpn_proto, sizeof(msg.alpn_proto), alpn);
    }

    /* Copy headers */
    msg.header_count = stream->header_count;
    for (int i = 0; i < stream->header_count && i < MAX_HEADERS; i++) {
        memcpy(&msg.headers[i], &stream->headers[i], sizeof(http_header_t));
    }

    /* Display using existing functions */
    display_http_request(&msg);

    if (!g_config.compact_mode && msg.header_count > 0) {
        display_http_headers(&msg);
    }

    stream->headers_displayed = true;
    printf("\n");
    fflush(stdout);
}

static void h2_display_response(h2_stream_t *stream) {
    DEBUG_H2("h2_display_response: stream=%d status=%d content_type='%s'",
             stream->stream_id, stream->status_code, stream->content_type);

    /* Skip displaying if status is 0 (indicates HPACK decode failure) */
    if (stream->status_code == 0) {
        DEBUG_H2("Skipping display of stream %d with status=0 (decode failure)",
                 stream->stream_id);
        return;
    }

    http_message_t msg = {0};

    msg.protocol = PROTO_HTTP2;
    msg.direction = DIR_RESPONSE;
    msg.stream_id = stream->stream_id;
    msg.pid = stream->pid;
    msg.status_code = stream->status_code;
    msg.timestamp_ns = stream->response_time_ns;

    /* Calculate latency from request to response */
    if (stream->request_time_ns > 0 && stream->response_time_ns > 0) {
        msg.delta_ns = stream->response_time_ns - stream->request_time_ns;
    }

    safe_strcpy(msg.content_type, sizeof(msg.content_type), stream->content_type);
    msg.content_length = stream->content_length;
    safe_strcpy(msg.comm, sizeof(msg.comm), stream->comm);

    /* Get ALPN protocol from connection */
    const char *alpn = http2_get_alpn(stream->pid, stream->ssl_ctx);
    if (alpn && alpn[0]) {
        safe_strcpy(msg.alpn_proto, sizeof(msg.alpn_proto), alpn);
    }

    msg.header_count = stream->header_count;
    for (int i = 0; i < stream->header_count && i < MAX_HEADERS; i++) {
        memcpy(&msg.headers[i], &stream->headers[i], sizeof(http_header_t));
    }

    display_http_response(&msg);

    if (!g_config.compact_mode && msg.header_count > 0) {
        display_http_headers(&msg);
    }
    fflush(stdout);
}

static void h2_display_body(h2_stream_t *stream, direction_t dir) {
    (void)dir;

    if (!g_config.show_body || stream->body_len == 0) {
        printf("\n");
        return;
    }

    const uint8_t *body_data = stream->body_buf;
    size_t body_len = stream->body_len;

    /* Decompress if needed */
    static uint8_t decomp_buf[MAX_BODY_BUFFER];
    if (stream->content_encoding[0]) {
        int decomp_len = decompress_body(stream->body_buf, (int)stream->body_len,
                                         stream->content_encoding,
                                         decomp_buf, MAX_BODY_BUFFER);
        if (decomp_len > 0) {
            body_data = decomp_buf;
            body_len = (size_t)decomp_len;
        }
    }

    /* Display using existing function */
    display_body(body_data, body_len, stream->content_type);

    /* Clear body buffer after display */
    stream->body_len = 0;
    printf("\n");
    fflush(stdout);
}

/* Connection management */
static void h2_connection_cleanup(h2_connection_t *conn) {
    if (!conn || !conn->active) return;

    /* Free nghttp2 server session */
    if (conn->server_session) {
        nghttp2_session_del(conn->server_session);
        conn->server_session = NULL;
    }

    /* Free HPACK inflater for responses */
    if (conn->response_inflater) {
        nghttp2_hd_inflate_del(conn->response_inflater);
        conn->response_inflater = NULL;
    }

    /* Free response reassembly buffer */
    if (conn->response_buf) {
        free(conn->response_buf);
        conn->response_buf = NULL;
        conn->response_buf_len = 0;
    }

    /* Free callback context */
    free(conn->server_ctx);
    conn->server_ctx = NULL;

    /* Cleanup associated streams for this connection */
    for (int i = 0; i < MAX_H2_STREAMS; i++) {
        if (g_h2_streams[i].active &&
            g_h2_streams[i].pid == conn->pid &&
            g_h2_streams[i].ssl_ctx == conn->ssl_ctx) {
            http2_free_stream(g_h2_streams[i].pid, g_h2_streams[i].ssl_ctx,
                              g_h2_streams[i].stream_id);
        }
    }

    conn->active = false;
}

static h2_connection_t *get_h2_connection(uint32_t pid, uint64_t ssl_ctx, bool create) {
    /* Find existing by (pid, ssl_ctx) */
    for (int i = 0; i < MAX_H2_SESSIONS; i++) {
        if (g_h2_connections[i].active &&
            g_h2_connections[i].pid == pid &&
            g_h2_connections[i].ssl_ctx == ssl_ctx) {
            g_h2_connections[i].last_activity_ns = get_time_ns();
            return &g_h2_connections[i];
        }
    }

    if (!create) return NULL;

    /* Find empty slot (or evict oldest) */
    h2_connection_t *slot = NULL;
    uint64_t oldest = UINT64_MAX;

    for (int i = 0; i < MAX_H2_SESSIONS; i++) {
        if (!g_h2_connections[i].active) {
            slot = &g_h2_connections[i];
            break;
        }
        if (g_h2_connections[i].last_activity_ns < oldest) {
            oldest = g_h2_connections[i].last_activity_ns;
            slot = &g_h2_connections[i];
        }
    }

    /* Cleanup old session if reusing */
    if (slot && slot->active) {
        h2_connection_cleanup(slot);
    }

    if (!slot) return NULL;

    /* Initialize new connection */
    memset(slot, 0, sizeof(*slot));
    slot->pid = pid;
    slot->ssl_ctx = ssl_ctx;
    slot->active = true;
    slot->last_activity_ns = get_time_ns();

    /* Create callback context for server session */
    h2_callback_ctx_t *server_ctx = malloc(sizeof(h2_callback_ctx_t));
    if (!server_ctx) {
        slot->active = false;
        return NULL;
    }

    memset(server_ctx, 0, sizeof(*server_ctx));
    server_ctx->pid = pid;
    server_ctx->ssl_ctx = ssl_ctx;
    server_ctx->conn = slot;
    server_ctx->direction = H2_DIR_SERVER;

    /* Create nghttp2 server session with options for passive sniffing */
    int rv;
    nghttp2_option *server_opt = NULL;

    rv = nghttp2_option_new(&server_opt);
    if (rv != 0) {
        free(server_ctx);
        slot->active = false;
        return NULL;
    }

    /*
     * Critical for passive sniffing: we detect and skip the 24-byte
     * client magic preface in main.c before calling http2_process_frame().
     * Tell nghttp2 we've already consumed it so it doesn't expect it.
     */
    nghttp2_option_set_no_recv_client_magic(server_opt, 1);

    /*
     * Disable automatic WINDOW_UPDATE - we're passive sniffers,
     * not actual endpoints generating flow control.
     */
    nghttp2_option_set_no_auto_window_update(server_opt, 1);

    /* Server session (parses data FROM client = requests) */
    rv = nghttp2_session_server_new2(&slot->server_session, g_h2_callbacks,
                                      server_ctx, server_opt);
    nghttp2_option_del(server_opt);

    if (rv != 0) {
        free(server_ctx);
        slot->active = false;
        return NULL;
    }

    /* Create HPACK inflater for decoding response headers */
    rv = nghttp2_hd_inflate_new(&slot->response_inflater);
    if (rv != 0) {
        nghttp2_session_del(slot->server_session);
        free(server_ctx);
        slot->active = false;
        return NULL;
    }

    /* Allocate response reassembly buffer */
    slot->response_buf = malloc(H2_REASSEMBLY_BUF_SIZE);
    if (!slot->response_buf) {
        nghttp2_hd_inflate_del(slot->response_inflater);
        nghttp2_session_del(slot->server_session);
        free(server_ctx);
        slot->active = false;
        return NULL;
    }
    slot->response_buf_len = 0;

    /* Store context pointer for later cleanup and event updates */
    slot->server_ctx = server_ctx;

    /*
     * Important: Drain the initial SETTINGS frame that nghttp2 queues
     * upon session creation. This ensures our session is in the proper
     * state (SETTINGS "sent") before we receive any peer data.
     */
    for (;;) {
        const uint8_t *send_data;
        ssize_t send_len = nghttp2_session_mem_send(slot->server_session, &send_data);
        if (send_len <= 0) break;
    }

    DEBUG_H2("Created new session for PID %u", pid);
    return slot;
}

/* Public API */
int http2_init(void) {
    if (g_h2_initialized) return 0;

    memset(g_h2_connections, 0, sizeof(g_h2_connections));
    memset(g_h2_streams, 0, sizeof(g_h2_streams));

    /* Create shared callback structure */
    int rv = nghttp2_session_callbacks_new(&g_h2_callbacks);
    if (rv != 0) {
        return -1;
    }

    /* Set callbacks */
    nghttp2_session_callbacks_set_on_begin_headers_callback(
        g_h2_callbacks, on_begin_headers_callback);
    nghttp2_session_callbacks_set_on_header_callback(
        g_h2_callbacks, on_header_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(
        g_h2_callbacks, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        g_h2_callbacks, on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(
        g_h2_callbacks, on_stream_close_callback);
    nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(
        g_h2_callbacks, on_invalid_frame_recv_callback);
    nghttp2_session_callbacks_set_error_callback2(
        g_h2_callbacks, on_error_callback);

    g_h2_initialized = true;
    return 0;
}

void http2_cleanup(void) {
    /* Free all streams */
    for (int i = 0; i < MAX_H2_STREAMS; i++) {
        if (g_h2_streams[i].body_buf) {
            free(g_h2_streams[i].body_buf);
            g_h2_streams[i].body_buf = NULL;
        }
        g_h2_streams[i].active = false;
    }

    /* Free all connections */
    for (int i = 0; i < MAX_H2_SESSIONS; i++) {
        h2_connection_cleanup(&g_h2_connections[i]);
    }

    if (g_h2_callbacks) {
        nghttp2_session_callbacks_del(g_h2_callbacks);
        g_h2_callbacks = NULL;
    }

    g_h2_initialized = false;
}

const char *http2_frame_name(int type) {
    static const char *names[] = {
        "DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS",
        "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION"
    };
    return (type >= 0 && type < 10) ? names[type] : "UNKNOWN";
}

bool http2_is_preface(const uint8_t *data, size_t len) {
    const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    return len >= 24 && memcmp(data, preface, 24) == 0;
}

bool http2_has_session(uint32_t pid, uint64_t ssl_ctx) {
    for (int i = 0; i < MAX_H2_SESSIONS; i++) {
        if (g_h2_connections[i].active &&
            g_h2_connections[i].pid == pid &&
            g_h2_connections[i].ssl_ctx == ssl_ctx) {
            return true;
        }
    }
    return false;
}

void http2_set_alpn(uint32_t pid, uint64_t ssl_ctx, const char *alpn) {
    /* Find existing connection or create one */
    h2_connection_t *conn = get_h2_connection(pid, ssl_ctx, true);
    if (conn && alpn) {
        safe_strcpy(conn->alpn_proto, sizeof(conn->alpn_proto), alpn);
    }
}

const char *http2_get_alpn(uint32_t pid, uint64_t ssl_ctx) {
    for (int i = 0; i < MAX_H2_SESSIONS; i++) {
        if (g_h2_connections[i].active &&
            g_h2_connections[i].pid == pid &&
            g_h2_connections[i].ssl_ctx == ssl_ctx) {
            return g_h2_connections[i].alpn_proto;
        }
    }
    return "";
}

/* Process a single decoded header from HPACK inflater */
static void h2_process_response_header(h2_stream_t *stream, const nghttp2_nv *nv) {
    const uint8_t *name = nv->name;
    size_t namelen = nv->namelen;
    const uint8_t *value = nv->value;
    size_t valuelen = nv->valuelen;

    DEBUG_H2("Response header: '%.*s: %.*s'",
             (int)namelen, name, (int)valuelen, value);

    /* Handle pseudo-headers */
    if (namelen > 0 && name[0] == ':') {
        if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
            char status_str[8] = {0};
            size_t copylen = valuelen < 7 ? valuelen : 7;
            memcpy(status_str, value, copylen);
            stream->status_code = atoi(status_str);
        }
        return;
    }

    /* Store regular header */
    if (stream->header_count < MAX_HEADERS) {
        http_header_t *hdr = &stream->headers[stream->header_count];
        size_t name_copylen = namelen < sizeof(hdr->name) - 1 ? namelen : sizeof(hdr->name) - 1;
        size_t val_copylen = valuelen < sizeof(hdr->value) - 1 ? valuelen : sizeof(hdr->value) - 1;

        memcpy(hdr->name, name, name_copylen);
        hdr->name[name_copylen] = '\0';
        memcpy(hdr->value, value, val_copylen);
        hdr->value[val_copylen] = '\0';

        stream->header_count++;

        /* Extract special headers */
        if (strcasecmp(hdr->name, "content-type") == 0) {
            safe_strcpy(stream->content_type, sizeof(stream->content_type), hdr->value);
        } else if (strcasecmp(hdr->name, "content-encoding") == 0) {
            safe_strcpy(stream->content_encoding, sizeof(stream->content_encoding), hdr->value);
        } else if (strcasecmp(hdr->name, "content-length") == 0) {
            stream->content_length = strtoull(hdr->value, NULL, 10);
        }
    }
}

/* Process a complete HTTP/2 response frame */
static void h2_process_complete_response_frame(h2_connection_t *conn, const uint8_t *frame_data,
                                                size_t frame_total_len, const ssl_data_event_t *event) {
    (void)frame_total_len; /* Used for bounds checking at caller */

    /* Parse frame header */
    uint32_t frame_len = ((uint32_t)frame_data[0] << 16) | ((uint32_t)frame_data[1] << 8) | (uint32_t)frame_data[2];
    uint8_t frame_type = frame_data[3];
    uint8_t flags = frame_data[4];
    int32_t stream_id = (int32_t)(((uint32_t)(frame_data[5] & 0x7f) << 24) | ((uint32_t)frame_data[6] << 16) |
                         ((uint32_t)frame_data[7] << 8) | (uint32_t)frame_data[8]);

    const uint8_t *payload = frame_data + 9;
    uint32_t payload_len = frame_len;

    DEBUG_H2("Response frame: type=%s len=%u stream=%d flags=0x%02x",
             http2_frame_name(frame_type), frame_len, stream_id, flags);

    switch (frame_type) {
    case 0x01: /* HEADERS */
        {
            /* Get or create stream - for responses we need the stream to exist from request */
            h2_stream_t *stream = http2_get_stream(conn->pid, conn->ssl_ctx, stream_id, false);
            if (!stream) {
                DEBUG_H2("Response for unknown stream %d, creating", stream_id);
                stream = http2_get_stream(conn->pid, conn->ssl_ctx, stream_id, true);
                if (!stream) break;
            }

            /* Update timing */
            stream->response_time_ns = event->timestamp_ns;
            /* Resolve actual process name (not thread name) */
            if (!stream->comm[0]) {
                h2_get_process_name(conn->pid, stream->comm, sizeof(stream->comm));
                /* Fall back to event comm if resolution failed */
                if (!stream->comm[0] && event->comm[0]) {
                    safe_strcpy(stream->comm, sizeof(stream->comm), event->comm);
                }
            }

            /* Reset header count for response headers */
            stream->header_count = 0;

            /* Skip padding if present */
            const uint8_t *hdr_data = payload;
            uint32_t hdr_len = payload_len;

            if (flags & 0x08) { /* PADDED */
                if (hdr_len < 1) break;
                uint8_t pad_len = hdr_data[0];
                hdr_data++;
                hdr_len--;
                if (hdr_len < pad_len) break;
                hdr_len -= pad_len;
            }

            /* Skip priority if present */
            if (flags & 0x20) { /* PRIORITY */
                if (hdr_len < 5) break;
                hdr_data += 5;
                hdr_len -= 5;
            }

            /* Decode HPACK headers */
            int final = (flags & 0x04) ? 1 : 0; /* END_HEADERS flag */
            const uint8_t *hdr_pos = hdr_data;
            size_t hdr_remaining = hdr_len;

            DEBUG_H2("Decoding %u bytes of HPACK, final=%d", hdr_len, final);

            while (hdr_remaining > 0) {
                nghttp2_nv nv;
                int inflate_flags = 0;

                ssize_t consumed = nghttp2_hd_inflate_hd2(conn->response_inflater,
                                                          &nv, &inflate_flags,
                                                          hdr_pos, hdr_remaining,
                                                          final);
                if (consumed < 0) {
                    DEBUG_H2("HPACK inflate error: %zd (%s)",
                             consumed, nghttp2_strerror((int)consumed));

                    conn->hpack_error_count++;
                    conn->hpack_success_count = 0;

                    /* End current header block properly */
                    nghttp2_hd_inflate_end_headers(conn->response_inflater);

                    /*
                     * Mid-stream HPACK recovery strategy:
                     * - First few errors: Just skip this header block, don't reset table
                     *   (subsequent headers may decode fine if they don't need missing entries)
                     * - Persistent errors (5+): Recreate inflater with fresh state
                     *   This is the nuclear option for severely corrupted state
                     *
                     * This is better than the old approach which reset the table on every
                     * error, corrupting state for subsequent decodes.
                     */
                    if (conn->hpack_error_count >= 5) {
                        DEBUG_H2("Persistent HPACK errors, recreating inflater");
                        nghttp2_hd_inflater *new_inflater = NULL;
                        if (nghttp2_hd_inflate_new(&new_inflater) == 0) {
                            nghttp2_hd_inflate_del(conn->response_inflater);
                            conn->response_inflater = new_inflater;
                            conn->hpack_error_count = 0;
                            conn->mid_stream_joined = true;
                        }
                    }
                    break;
                }

                hdr_pos += consumed;
                hdr_remaining -= (size_t)consumed;

                if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
                    h2_process_response_header(stream, &nv);
                    /* Successful decode - track for error recovery */
                    conn->hpack_success_count++;
                    if (conn->hpack_success_count >= 3) {
                        /* Reset error count after consecutive successes */
                        conn->hpack_error_count = 0;
                    }
                }

                if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
                    nghttp2_hd_inflate_end_headers(conn->response_inflater);
                    break;
                }

                /* Prevent infinite loop if no progress */
                if (consumed == 0 && !(inflate_flags & NGHTTP2_HD_INFLATE_EMIT)) {
                    break;
                }
            }

            /* Display response if END_HEADERS is set */
            if (flags & 0x04) { /* END_HEADERS */
                if (!stream->response_headers_done) {
                    stream->response_headers_done = true;
                    h2_display_response(stream);

                    /* If END_STREAM also set, response is complete (no body) */
                    if (flags & 0x01) { /* END_STREAM */
                        stream->response_complete = true;
                        printf("\n");
                        fflush(stdout);
                    }
                }
            }
        }
        break;

    case 0x00: /* DATA */
        {
            h2_stream_t *stream = http2_get_stream(conn->pid, conn->ssl_ctx, stream_id, false);
            if (stream && stream->body_buf) {
                /* Skip padding if present */
                const uint8_t *body_data = payload;
                uint32_t body_len = payload_len;

                if (flags & 0x08) { /* PADDED */
                    if (body_len < 1) break;
                    uint8_t pad_len = body_data[0];
                    body_data++;
                    body_len--;
                    if (body_len < pad_len) break;
                    body_len -= pad_len;
                }

                /* Accumulate body data */
                size_t available = stream->body_buf_size - stream->body_len;
                size_t to_copy = (body_len < available) ? body_len : available;

                if (to_copy > 0) {
                    memcpy(stream->body_buf + stream->body_len, body_data, to_copy);
                    stream->body_len += to_copy;
                }

                /* Display body if END_STREAM */
                if (flags & 0x01) { /* END_STREAM */
                    stream->response_complete = true;
                    h2_display_body(stream, DIR_RESPONSE);
                }
            }
        }
        break;

    default:
        /* Other frame types (SETTINGS, WINDOW_UPDATE, etc.) - ignore for response parsing */
        break;
    }
}

/* Check if a frame header looks valid (sanity check for mid-stream joins) */
bool http2_is_valid_frame_header(const uint8_t *data) {
    uint32_t frame_len = ((uint32_t)data[0] << 16) |
                         ((uint32_t)data[1] << 8) |
                         (uint32_t)data[2];
    uint8_t frame_type = data[3];
    uint32_t stream_id = ((uint32_t)(data[5] & 0x7f) << 24) |
                         ((uint32_t)data[6] << 16) |
                         ((uint32_t)data[7] << 8) |
                         (uint32_t)data[8];

    /* Frame length must be reasonable */
    if (frame_len > H2_MAX_SANE_FRAME_LEN) {
        return false;
    }

    /* Frame type must be valid (0-9) */
    if (frame_type > H2_MAX_VALID_FRAME_TYPE) {
        return false;
    }

    /* Stream ID must be reasonable (not in the billions) */
    if (stream_id > H2_MAX_SANE_STREAM_ID) {
        return false;
    }

    /* Validate frame type vs stream_id per HTTP/2 spec:
     * - DATA (0x00) and HEADERS (0x01) must have stream_id > 0
     * - SETTINGS (0x04), PING (0x06), GOAWAY (0x07) must have stream_id == 0
     * - WINDOW_UPDATE (0x08) can be on any stream */
    switch (frame_type) {
    case 0x00: /* DATA */
    case 0x01: /* HEADERS */
    case 0x02: /* PRIORITY */
    case 0x03: /* RST_STREAM */
    case 0x05: /* PUSH_PROMISE */
    case 0x09: /* CONTINUATION */
        if (stream_id == 0) {
            return false;  /* Stream-specific frames must have stream_id > 0 */
        }
        break;
    case 0x04: /* SETTINGS */
    case 0x06: /* PING */
    case 0x07: /* GOAWAY */
        if (stream_id != 0) {
            return false;  /* Connection-level frames must have stream_id == 0 */
        }
        break;
    case 0x08: /* WINDOW_UPDATE */
        /* Can be on stream 0 (connection) or any stream */
        break;
    }

    return true;
}

/* Try to find a valid frame start in corrupted buffer by scanning for recognizable patterns */
static size_t h2_find_frame_start(const uint8_t *buf, size_t len) {
    /* Look for patterns that indicate frame boundaries:
     * - SETTINGS frame on stream 0: type=4, stream_id=0
     * - HEADERS frame with small stream ID: type=1, stream_id < 1000
     * - WINDOW_UPDATE on stream 0: type=8, stream_id=0
     */
    for (size_t i = 0; i + 9 <= len; i++) {
        if (http2_is_valid_frame_header(buf + i)) {
            /* Additional check: does the frame length make sense for remaining data? */
            uint32_t frame_len = ((uint32_t)buf[i] << 16) |
                                 ((uint32_t)buf[i + 1] << 8) |
                                 (uint32_t)buf[i + 2];
            size_t total_size = 9 + frame_len;

            /* If we have enough data for the complete frame, this might be real */
            if (i + total_size <= len) {
                DEBUG_H2("Found potential frame start at offset %zu (len=%u type=%d)",
                         i, frame_len, buf[i + 3]);
                return i;
            }
            /* Or if frame would fit in buffer, accept it for buffering */
            if (total_size <= H2_REASSEMBLY_BUF_SIZE) {
                DEBUG_H2("Found potential frame header at offset %zu (len=%u type=%d)",
                         i, frame_len, buf[i + 3]);
                return i;
            }
        }
    }
    return len; /* No valid frame found, discard everything */
}

/* Process response frames with reassembly for fragmented data */
static void h2_process_response_frame(h2_connection_t *conn, const uint8_t *data, int len,
                                       const ssl_data_event_t *event) {
    /* Append incoming data to reassembly buffer */
    size_t space_available = H2_REASSEMBLY_BUF_SIZE - conn->response_buf_len;
    size_t to_copy = ((size_t)len < space_available) ? (size_t)len : space_available;

    if (to_copy > 0) {
        memcpy(conn->response_buf + conn->response_buf_len, data, to_copy);
        conn->response_buf_len += to_copy;
    }

    if (to_copy < (size_t)len) {
        DEBUG_H2("Response buffer overflow, dropped %zu bytes", (size_t)len - to_copy);
    }

    /* Process all complete frames in the buffer */
    size_t pos = 0;
    while (conn->response_buf_len - pos >= 9) {
        const uint8_t *frame_start = conn->response_buf + pos;

        /* Parse frame header to get length */
        uint32_t frame_len = ((uint32_t)frame_start[0] << 16) |
                             ((uint32_t)frame_start[1] << 8) |
                             (uint32_t)frame_start[2];
        size_t total_frame_size = 9 + frame_len;

        /* Sanity check: validate frame header */
        if (!http2_is_valid_frame_header(frame_start)) {
            DEBUG_H2("Invalid frame header detected (len=%u type=%d), attempting recovery",
                     frame_len, frame_start[3]);

            /* Try to find next valid frame in remaining buffer */
            size_t skip = h2_find_frame_start(conn->response_buf + pos + 1,
                                               conn->response_buf_len - pos - 1);
            if (skip > 0 && skip < conn->response_buf_len - pos - 1) {
                DEBUG_H2("Recovered: skipping %zu bytes to next valid frame", skip + 1);
                pos += skip + 1;
                continue;
            } else {
                /* No valid frame found, discard entire buffer */
                DEBUG_H2("Recovery failed, discarding %zu bytes", conn->response_buf_len - pos);
                conn->response_buf_len = 0;
                return;
            }
        }

        /* Check if we have complete frame */
        if (conn->response_buf_len - pos < total_frame_size) {
            DEBUG_H2("Incomplete frame: need %zu, have %zu (buffering)",
                     total_frame_size, conn->response_buf_len - pos);
            break;
        }

        /* Process the complete frame */
        h2_process_complete_response_frame(conn, frame_start, total_frame_size, event);

        /* Move to next frame */
        pos += total_frame_size;
    }

    /* Move remaining data to beginning of buffer */
    if (pos > 0) {
        size_t remaining = conn->response_buf_len - pos;
        if (remaining > 0) {
            memmove(conn->response_buf, conn->response_buf + pos, remaining);
        }
        conn->response_buf_len = remaining;
    }
}

void http2_process_frame(const uint8_t *data, int len, const ssl_data_event_t *event) {
    if (!g_h2_initialized) {
        if (http2_init() != 0) {
            DEBUG_H2("http2_init() failed");
            return;
        }
    }

    DEBUG_H2("process_frame: PID=%u type=%s len=%d",
             event->pid, event->event_type == EVENT_SSL_WRITE ? "WRITE" : "READ", len);

    /* Get or create connection for this (PID, ssl_ctx) */
    h2_connection_t *conn = get_h2_connection(event->pid, event->ssl_ctx, true);
    if (!conn) {
        DEBUG_H2("get_h2_connection failed for PID %u ssl_ctx=0x%llx",
                 event->pid, (unsigned long long)event->ssl_ctx);
        return;
    }

    /* Resolve actual process name (not thread name) */
    if (!conn->comm[0]) {
        h2_get_process_name(event->pid, conn->comm, sizeof(conn->comm));
        /* Fall back to event comm if resolution failed */
        if (!conn->comm[0] && event->comm[0]) {
            safe_strcpy(conn->comm, sizeof(conn->comm), event->comm);
        }
    }

    /* Debug: print potential frame header for WRITE events only
     * (READ events may be partial frame payloads that get buffered,
     * so printing raw data as frame header would be misleading) */
#ifdef DEBUG
    if (len >= 9 && event->event_type == EVENT_SSL_WRITE) {
        uint32_t frame_len = ((uint32_t)data[0] << 16) | ((uint32_t)data[1] << 8) | (uint32_t)data[2];
        uint8_t frame_type = data[3];
        uint8_t flags = data[4];
        uint32_t stream_id = ((uint32_t)(data[5] & 0x7f) << 24) | ((uint32_t)data[6] << 16) |
                             ((uint32_t)data[7] << 8) | (uint32_t)data[8];
        /* Only log if it looks like a valid frame header */
        if (frame_type <= 9 && frame_len <= 65536) {
            DEBUG_H2("Frame header: len=%u type=%s(%d) flags=0x%02x stream=%u",
                     frame_len, http2_frame_name(frame_type), frame_type, flags, stream_id);
        }
    }
#endif

    if (event->event_type == EVENT_SSL_WRITE) {
        /* Client writing = request data going to server */
        /* Use nghttp2 server session for parsing requests */
        if (conn->server_ctx) conn->server_ctx->event = event;

        /*
         * Filter out SETTINGS ACK frames before feeding to server session.
         * The client sends SETTINGS ACK in response to the real server's SETTINGS,
         * not our session's SETTINGS. Feeding it causes protocol errors.
         * SETTINGS ACK is a 9-byte frame with type=4, flags=1, len=0.
         *
         * Also validate frames before feeding to prevent session corruption
         * when joining mid-stream.
         */
        const uint8_t *feed_data = data;
        int feed_len = len;

        while (feed_len >= 9) {
            uint32_t frame_len = ((uint32_t)feed_data[0] << 16) |
                                 ((uint32_t)feed_data[1] << 8) |
                                 (uint32_t)feed_data[2];
            uint8_t frame_type = feed_data[3];
            uint8_t flags = feed_data[4];

            size_t total_frame_size = 9 + frame_len;

            /* Sanity check: validate frame before feeding to nghttp2 */
            if (!http2_is_valid_frame_header(feed_data)) {
                DEBUG_H2("Invalid request frame header (len=%u type=%d), skipping %d bytes",
                         frame_len, frame_type, feed_len);
                /* Try to find next valid frame */
                size_t skip = h2_find_frame_start(feed_data + 1, (size_t)(feed_len - 1));
                if (skip > 0 && skip < (size_t)(feed_len - 1)) {
                    DEBUG_H2("Recovered request: skipping %zu bytes", skip + 1);
                    feed_data += skip + 1;
                    feed_len -= (int)(skip + 1);
                    continue;
                }
                /* No valid frame found, skip all data */
                break;
            }

            /* Check if we have complete frame */
            if ((int)total_frame_size > feed_len) {
                break; /* Incomplete frame, discard partial (we don't buffer requests) */
            }

            /* Skip SETTINGS ACK (type=4, flags=1, len=0) */
            if (frame_type == 0x04 && flags == 0x01 && frame_len == 0) {
                DEBUG_H2("Skipping SETTINGS ACK for server session");
                feed_data += total_frame_size;
                feed_len -= (int)total_frame_size;
                continue;
            }

            /* Feed this frame */
            ssize_t rv = nghttp2_session_mem_recv(conn->server_session, feed_data, total_frame_size);
            if (rv < 0) {
                DEBUG_H2("nghttp2_session_mem_recv error: %zd (%s)",
                         rv, nghttp2_strerror((int)rv));
                /* On error, session might be corrupted - skip remaining data */
                break;
            }

            /* Drain send buffer after each frame */
            for (;;) {
                const uint8_t *send_data;
                ssize_t send_len = nghttp2_session_mem_send(conn->server_session, &send_data);
                if (send_len <= 0) break;
            }

            feed_data += total_frame_size;
            feed_len -= (int)total_frame_size;
        }

        if (conn->server_ctx) conn->server_ctx->event = NULL;
    } else {
        /* Client reading = response data from server */
        /* Parse manually with HPACK inflater to avoid session state issues */
        h2_process_response_frame(conn, data, len, event);
    }
}

#else /* !HAVE_NGHTTP2 */

/* Stub implementation when nghttp2 is not available */
static bool g_h2_initialized = false;

int http2_init(void) {
    g_h2_initialized = true;
    return 0;
}

void http2_cleanup(void) {
    g_h2_initialized = false;
}

const char *http2_frame_name(int type) {
    static const char *names[] = {
        "DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS",
        "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION"
    };
    return (type >= 0 && type < 10) ? names[type] : "UNKNOWN";
}

bool http2_is_preface(const uint8_t *data, size_t len) {
    const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    return len >= 24 && memcmp(data, preface, 24) == 0;
}

bool http2_has_session(uint32_t pid, uint64_t ssl_ctx) {
    (void)pid;
    (void)ssl_ctx;
    return false;
}

void http2_set_alpn(uint32_t pid, uint64_t ssl_ctx, const char *alpn) {
    (void)pid;
    (void)ssl_ctx;
    (void)alpn;
}

const char *http2_get_alpn(uint32_t pid, uint64_t ssl_ctx) {
    (void)pid;
    (void)ssl_ctx;
    return "";
}

void http2_process_frame(const uint8_t *data, int len, const ssl_data_event_t *event) {
    (void)data;
    (void)len;
    (void)event;
    /* No-op without nghttp2 - HTTP/2 detection will just show connection message */
}

h2_stream_t *http2_get_stream(uint32_t pid, uint64_t ssl_ctx, int32_t stream_id, bool create) {
    (void)pid;
    (void)ssl_ctx;
    (void)stream_id;
    (void)create;
    return NULL;
}

void http2_free_stream(uint32_t pid, uint64_t ssl_ctx, int32_t stream_id) {
    (void)pid;
    (void)ssl_ctx;
    (void)stream_id;
}

void http2_cleanup_pid(uint32_t pid) {
    (void)pid;
}

#endif /* HAVE_NGHTTP2 */
