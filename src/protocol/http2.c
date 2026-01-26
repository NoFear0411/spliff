/**
 * @file http2.c
 * @brief HTTP/2 protocol parser implementation using nghttp2
 *
 * @details This module implements HTTP/2 frame parsing and session management
 * using the nghttp2 library. It handles the complexities of HTTP/2's binary
 * framing layer, HPACK header compression, and stream multiplexing.
 *
 * @par Architecture Overview:
 * @code
 *   SSL data (from BPF)
 *         │
 *         ▼
 *   http2_process_frame()
 *         │
 *         ├─── Get/create h2_session_t for (pid, ssl_ctx)
 *         │
 *         ├─── Feed to nghttp2_session (server-side parser)
 *         │         │
 *         │         └── Callbacks: on_header, on_data, on_frame_recv
 *         │
 *         └─── Manual HPACK decoding for response headers
 *                    │
 *                    └── hd_inflate_hd() for each HEADERS frame
 * @endcode
 *
 * @par Why Server-Side Session?
 * nghttp2 provides client-side and server-side session types. For passively
 * sniffing traffic, we use a server-side session to parse incoming data.
 * This is because:
 * - Server sessions parse client->server data (requests)
 * - For responses (server->client), we use manual HPACK decoding
 *
 * @par Stream Management:
 * Streams are tracked in a global array keyed by (pid, ssl_ctx, stream_id).
 * Each stream maintains:
 * - Request metadata (:method, :path, :authority)
 * - Response metadata (:status, headers)
 * - Body accumulation buffer
 * - Timing information for latency calculation
 *
 * @par Mid-Stream Join Handling:
 * When spliff attaches to an already-active HTTP/2 connection, HPACK
 * decompression may fail due to missing dynamic table state. The module
 * marks such streams with hpack_decode_failed and attempts fallback
 * parsing for subsequent frames.
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "http2.h"
#include "../util/safe_str.h"
#include "../output/display.h"
#include "../content/decompressor.h"
#include "../content/signatures.h"
#include "../correlation/flow_context.h"
#ifdef HAVE_THREADING
#include "../threading/threading.h"
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <strings.h>

#ifdef HAVE_NGHTTP2
#include <nghttp2/nghttp2.h>
#include <unistd.h>
#include <libgen.h>

/* Flow-based display functions */
static void h2_display_request_flow(flow_transaction_t *txn, flow_context_t *flow_ctx,
                                    const ssl_data_event_t *event);
static void h2_display_response_flow(flow_transaction_t *txn, flow_context_t *flow_ctx,
                                     const ssl_data_event_t *event);
static void h2_display_body_flow(flow_transaction_t *txn, flow_context_t *flow_ctx);

/* Forward declaration for frame validation helper */
static size_t h2_find_frame_start(const uint8_t *buf, size_t len);

/**
 * @brief HTTP/2 parsing direction
 *
 * nghttp2 requires separate sessions for parsing client vs server data.
 * This enum identifies which direction a session parses.
 *
 * @internal
 */
typedef enum {
    H2_DIR_CLIENT = 0,  /**< Parses server→client data (responses) */
    H2_DIR_SERVER = 1   /**< Parses client→server data (requests) */
} h2_dir_t;

/* Forward declaration */
typedef struct h2_callback_ctx h2_callback_ctx_t;

/**
 * @brief Response reassembly buffer size
 *
 * Used for buffering incomplete HTTP/2 frames across multiple
 * SSL_read calls.
 *
 * @internal
 */
#define H2_REASSEMBLY_BUF_SIZE 65536

/**
 * @brief Context passed to nghttp2 callbacks
 *
 * Contains all state needed by nghttp2 callback functions to process
 * HTTP/2 frames and associate them with the correct flow/stream.
 */
struct h2_callback_ctx {
    uint32_t pid;
    uint64_t ssl_ctx;
    const ssl_data_event_t *event;
    h2_dir_t direction;

    /* Flow-based storage - uses flow_context_t for all session/stream state */
    flow_context_t *flow_ctx;
};

/**
 * @brief Create callback context for flow-based HTTP/2 processing
 *
 * Allocates and initializes an h2_callback_ctx_t for use with flow_ctx's
 * nghttp2 session. The context is set up for server-side (request) parsing.
 *
 * @param flow_ctx Flow context that will own this callback context
 * @return Opaque callback context pointer, or NULL on allocation failure
 *
 * @note The returned pointer should be stored in flow_ctx->parser.h2.callback_ctx
 *       and passed to flow_h2_session_init() as user_data.
 * @note Caller is responsible for freeing via http2_free_callback_ctx()
 */
void *http2_create_callback_ctx(flow_context_t *flow_ctx) {
    if (!flow_ctx) {
        return NULL;
    }

    h2_callback_ctx_t *ctx = calloc(1, sizeof(h2_callback_ctx_t));
    if (!ctx) {
        return NULL;
    }

    /* For flow-based processing, pid/ssl_ctx come from event at runtime */
    ctx->pid = 0;
    ctx->ssl_ctx = 0;
    ctx->event = NULL; /* Set per-call */
    ctx->direction = H2_DIR_SERVER; /* Parses client requests */
    ctx->flow_ctx = flow_ctx;

    return ctx;
}

/**
 * @brief Free callback context created by http2_create_callback_ctx()
 *
 * @param callback_ctx Opaque callback context to free
 */
void http2_free_callback_ctx(void *callback_ctx) {
    free(callback_ctx);  /* free(NULL) is safe */
}

/**
 * @brief Set event in callback context for current processing call
 *
 * Updates the event pointer in a flow-based callback context.
 * Must be called before feeding data to the nghttp2 session.
 *
 * @param callback_ctx Opaque callback context
 * @param event        Current BPF event (may be NULL to clear)
 */
void http2_set_callback_event(void *callback_ctx, const ssl_data_event_t *event) {
    if (!callback_ctx) return;
    h2_callback_ctx_t *ctx = (h2_callback_ctx_t *)callback_ctx;
    ctx->event = event;
    if (event) {
        ctx->pid = event->pid;
        ctx->ssl_ctx = event->ssl_ctx;
    }
}

/* Global state - callbacks shared across all flow-based sessions */
static nghttp2_session_callbacks *g_h2_callbacks = NULL;
static bool g_h2_initialized = false;

/*
 * Flow-based stream helper (Phase 3.6 migration)
 *
 * Returns flow_transaction_t from flow_ctx if available, otherwise returns NULL.
 * Callers should fall back to http2_get_stream() when this returns NULL.
 */
static flow_transaction_t *get_flow_stream(h2_callback_ctx_t *ctx,
                                            int32_t stream_id,
                                            bool create) {
    if (!ctx || !ctx->flow_ctx) {
        return NULL;
    }

    /* Check for HPACK corruption - don't create new streams */
    if (ctx->flow_ctx->parser.h2.hpack_corrupted) {
        return NULL;
    }

    flow_transaction_t *txn = flow_h2_find_stream(ctx->flow_ctx, stream_id);
    if (txn) {
        txn->last_active_ms = flow_get_monotonic_ms();
        return txn;
    }

    if (!create) {
        return NULL;
    }

    return flow_h2_alloc_stream(ctx->flow_ctx, stream_id);
}

/* nghttp2 callbacks */
static int on_begin_headers_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
    (void)session;
    h2_callback_ctx_t *ctx = (h2_callback_ctx_t *)user_data;

    DEBUG_H2("on_begin_headers: stream=%d type=%d dir=%s",
             frame->hd.stream_id, frame->hd.type,
             ctx->direction == H2_DIR_SERVER ? "request" : "response");

    if (frame->hd.type != NGHTTP2_HEADERS) {
        return 0;
    }

    /* Only process on appropriate session */
    if (ctx->direction == H2_DIR_SERVER) {
        /* Server session sees requests - create stream state */
        flow_transaction_t *ftxn = get_flow_stream(ctx, frame->hd.stream_id, true);
        if (ftxn) {
            ftxn->state = TXN_STATE_OPEN;
            ftxn->direction = DIR_REQUEST;
            if (ctx->event) {
                ftxn->start_time_ns = ctx->event->timestamp_ns;
            }
        }
    } else {
        /* Client session sees responses - update existing stream */
        flow_transaction_t *ftxn = get_flow_stream(ctx, frame->hd.stream_id, false);
        if (!ftxn) {
            DEBUG_H2("Response for unknown stream %d", frame->hd.stream_id);
            return 0;
        }
        ftxn->direction = DIR_RESPONSE;
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

    flow_transaction_t *ftxn = get_flow_stream(ctx, frame->hd.stream_id, false);
    if (!ftxn) {
        DEBUG_H2("on_header: stream %d not found!", frame->hd.stream_id);
        return 0;
    }

    /* Handle pseudo-headers (start with ':') */
    if (namelen > 0 && name[0] == ':') {
        if (namelen == 7 && memcmp(name, ":method", 7) == 0) {
            size_t copylen = valuelen < sizeof(ftxn->method) - 1 ? valuelen : sizeof(ftxn->method) - 1;
            memcpy(ftxn->method, value, copylen);
            ftxn->method[copylen] = '\0';
        } else if (namelen == 5 && memcmp(name, ":path", 5) == 0) {
            size_t copylen = valuelen < sizeof(ftxn->path) - 1 ? valuelen : sizeof(ftxn->path) - 1;
            memcpy(ftxn->path, value, copylen);
            ftxn->path[copylen] = '\0';
        } else if (namelen == 10 && memcmp(name, ":authority", 10) == 0) {
            size_t copylen = valuelen < sizeof(ftxn->host) - 1 ? valuelen : sizeof(ftxn->host) - 1;
            memcpy(ftxn->host, value, copylen);
            ftxn->host[copylen] = '\0';
        } else if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
            char status_str[8] = {0};
            size_t copylen = valuelen < 7 ? valuelen : 7;
            memcpy(status_str, value, copylen);
            ftxn->status_code = atoi(status_str);
        }
        /* :scheme not stored - always https for HTTP/2 */
        return 0;
    }

    /* Extract special headers */
    if (namelen == 12 && strncasecmp((const char *)name, "content-type", 12) == 0) {
        size_t copylen = valuelen < sizeof(ftxn->content_type) - 1 ? valuelen : sizeof(ftxn->content_type) - 1;
        memcpy(ftxn->content_type, value, copylen);
        ftxn->content_type[copylen] = '\0';
    } else if (namelen == 16 && strncasecmp((const char *)name, "content-encoding", 16) == 0) {
        if (valuelen > 0) {
            ftxn->flags |= TXN_FLAG_COMPRESSED;
            size_t copylen = valuelen < sizeof(ftxn->encoding) - 1 ? valuelen : sizeof(ftxn->encoding) - 1;
            memcpy(ftxn->encoding, value, copylen);
            ftxn->encoding[copylen] = '\0';
        }
    } else if (namelen == 14 && strncasecmp((const char *)name, "content-length", 14) == 0) {
        char len_str[32] = {0};
        size_t copylen = valuelen < 31 ? valuelen : 31;
        memcpy(len_str, value, copylen);
        ftxn->content_length = strtoull(len_str, NULL, 10);
    } else if (namelen == 17 && strncasecmp((const char *)name, "transfer-encoding", 17) == 0) {
        if (valuelen >= 7 && strcasestr((const char *)value, "chunked")) {
            ftxn->flags |= TXN_FLAG_CHUNKED;
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

    /* Get flow-based transaction (required for display) */
    flow_transaction_t *ftxn = get_flow_stream(ctx, frame->hd.stream_id, false);

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        /* Headers complete - check END_HEADERS flag */
        if (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) {
            if (ftxn && ctx->flow_ctx) {
                if (ctx->direction == H2_DIR_SERVER) {
                    /* Request headers complete - only display once */
                    if (!(ftxn->flags & TXN_FLAG_REQ_HEADERS_DONE)) {
                        ftxn->flags |= TXN_FLAG_REQ_HEADERS_DONE;
                        h2_display_request_flow(ftxn, ctx->flow_ctx, ctx->event);
                    }

                    /* If END_STREAM also set, request is complete (no body) */
                    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                        ftxn->flags |= TXN_FLAG_REQ_END_STREAM;
                        ftxn->state = TXN_STATE_HALF_CLOSED_REMOTE;
                    }
                } else {
                    /* Response headers complete - only display once */
                    if (!(ftxn->flags & TXN_FLAG_RSP_HEADERS_DONE)) {
                        ftxn->flags |= TXN_FLAG_RSP_HEADERS_DONE;
                        h2_display_response_flow(ftxn, ctx->flow_ctx, ctx->event);

                        /* If END_STREAM also set, response is complete (no body) */
                        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                            ftxn->flags |= TXN_FLAG_RSP_END_STREAM;
                            if (ftxn->flags & TXN_FLAG_REQ_END_STREAM) {
                                ftxn->state = TXN_STATE_CLOSED;
                            } else {
                                ftxn->state = TXN_STATE_HALF_CLOSED_LOCAL;
                            }
                        }
                    }
                }
            }
        }
        break;

    case NGHTTP2_DATA:
        /* DATA frame - check END_STREAM */
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            if (ftxn) {
                if (ctx->direction == H2_DIR_SERVER) {
                    /* Request body complete */
                    ftxn->flags |= TXN_FLAG_REQ_END_STREAM;
                    ftxn->state = TXN_STATE_HALF_CLOSED_REMOTE;
                    /* Body display handled by flow_txn_append_body if enabled */
                } else {
                    /* Response body complete */
                    ftxn->flags |= TXN_FLAG_RSP_END_STREAM;
                    if (ftxn->flags & TXN_FLAG_REQ_END_STREAM) {
                        ftxn->state = TXN_STATE_CLOSED;
                    } else {
                        ftxn->state = TXN_STATE_HALF_CLOSED_LOCAL;
                    }
                    /* Body display handled by flow_txn_append_body if enabled */
                }
            }
        }
        break;

    case NGHTTP2_SETTINGS:
        /* SETTINGS frames are tracked by nghttp2 session state */
        break;

    case NGHTTP2_GOAWAY:
        /* Connection closing - mark HPACK as corrupted to stop processing */
        if (ctx->flow_ctx) {
            ctx->flow_ctx->parser.h2.hpack_corrupted = true;
        }
        break;

    case NGHTTP2_RST_STREAM:
        /* Stream reset - mark as closed */
        if (ftxn) {
            ftxn->state = TXN_STATE_RESET;
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

    /* Append to flow_transaction_t body buffer if configured */
    flow_transaction_t *ftxn = get_flow_stream(ctx, stream_id, false);
    if (ftxn && g_config.show_body) {
        flow_txn_append_body(ftxn, data, len);
    }

    return 0;
}

static int on_stream_close_callback(nghttp2_session *session,
                                    int32_t stream_id,
                                    uint32_t error_code,
                                    void *user_data) {
    (void)session;
    h2_callback_ctx_t *ctx = (h2_callback_ctx_t *)user_data;

    /* Update flow_transaction_t state */
    flow_transaction_t *ftxn = get_flow_stream(ctx, stream_id, false);
    if (ftxn) {
        if (error_code != 0) {
            ftxn->state = TXN_STATE_RESET;
        } else {
            ftxn->state = TXN_STATE_CLOSED;
        }
        ftxn->flags |= TXN_FLAG_DISPLAYED;  /* Mark as ready for cleanup */

        /* Display body if accumulated and not yet shown */
        if (ftxn->body_len > 0 && g_config.show_body && ctx->flow_ctx) {
            h2_display_body_flow(ftxn, ctx->flow_ctx);
        }
    }

    return 0;
}

static int on_invalid_frame_recv_callback(nghttp2_session *session,
                                          const nghttp2_frame *frame,
                                          int lib_error_code,
                                          void *user_data) {
    (void)session;
    h2_callback_ctx_t *ctx = (h2_callback_ctx_t *)user_data;

    DEBUG_H2("INVALID FRAME: type=%s stream=%d error=%d (%s) dir=%s",
             http2_frame_name(frame->hd.type), frame->hd.stream_id,
             lib_error_code, nghttp2_strerror(lib_error_code),
             ctx->direction == H2_DIR_SERVER ? "server" : "client");

    /* HPACK errors are connection-fatal (RFC 7540 Section 4.3) */
    if (lib_error_code == NGHTTP2_ERR_HEADER_COMP && ctx->flow_ctx) {
        ctx->flow_ctx->parser.h2.hpack_corrupted = true;
    }

    return 0;
}

static int on_error_callback(nghttp2_session *session,
                             int lib_error_code,
                             const char *msg,
                             size_t len,
                             void *user_data) {
    (void)session;
    h2_callback_ctx_t *ctx = (h2_callback_ctx_t *)user_data;

    DEBUG_H2("ERROR: code=%d msg=%.*s", lib_error_code, (int)len, msg);

    /* Mark HPACK as corrupted for compression errors */
    if (lib_error_code == NGHTTP2_ERR_HEADER_COMP && ctx && ctx->flow_ctx) {
        ctx->flow_ctx->parser.h2.hpack_corrupted = true;
    }

    return 0;
}

/**
 * @brief Display HTTP/2 request using flow-based transaction
 *
 * Flow-based version of h2_display_request() that uses flow_transaction_t
 * instead of the deprecated h2_stream_t global pool.
 *
 * @param[in] txn       Flow transaction containing request data
 * @param[in] flow_ctx  Flow context for connection metadata
 * @param[in] event     SSL event for timestamp
 */
static void h2_display_request_flow(flow_transaction_t *txn, flow_context_t *flow_ctx,
                                    const ssl_data_event_t *event) {
    DEBUG_H2("h2_display_request_flow: stream=%d method='%s' path='%s' host='%s'",
             txn->stream_id, txn->method, txn->path, txn->host);

    http_message_t msg = {0};

    msg.protocol = PROTO_HTTP2;
    msg.direction = DIR_REQUEST;
    msg.stream_id = txn->stream_id;
    msg.pid = flow_ctx->pid;
    msg.timestamp_ns = event ? event->timestamp_ns : 0;

    /* Copy request info from transaction */
    safe_strcpy(msg.method, sizeof(msg.method), txn->method);
    safe_strcpy(msg.path, sizeof(msg.path), txn->path);
    safe_strcpy(msg.authority, sizeof(msg.authority), txn->host);
    safe_strcpy(msg.scheme, sizeof(msg.scheme), "https");
    safe_strcpy(msg.comm, sizeof(msg.comm), flow_ctx->comm);

    /* Use ALPN from flow context if available */
    if (flow_ctx->alpn[0]) {
        safe_strcpy(msg.alpn_proto, sizeof(msg.alpn_proto), flow_ctx->alpn);
    }

    /* Use XDP flow correlation info from flow context ("Golden Thread" double-view) */
    if (flow_ctx->flags & FLOW_FLAG_HAS_XDP) {
        msg.has_flow_info = true;
        msg.flow_src_ip = flow_ctx->flow.saddr;
        msg.flow_dst_ip = flow_ctx->flow.daddr;
        msg.flow_src_port = flow_ctx->flow.sport;
        msg.flow_dst_port = flow_ctx->flow.dport;
        msg.flow_ip_version = flow_ctx->flow.ip_version;
        msg.flow_category = flow_ctx->xdp_category;
    }

    /* Store request start time for latency calculation */
    if (event && txn->start_time_ns == 0) {
        txn->start_time_ns = event->timestamp_ns;
    }

    display_http_request(&msg);

    if (!g_config.compact_mode) {
        /* TODO: Add header display when headers are stored in flow_transaction_t */
    }

    printf("\n");
    fflush(stdout);
}

/**
 * @brief Display HTTP/2 body using flow-based transaction
 *
 * @param[in] txn       Flow transaction containing body data
 * @param[in] flow_ctx  Flow context for connection metadata
 */
static void h2_display_body_flow(flow_transaction_t *txn, flow_context_t *flow_ctx) {
    (void)flow_ctx;

    if (!txn->body_buf || txn->body_len == 0) {
        return;
    }

    const uint8_t *display_data = txn->body_buf;
    size_t display_len = txn->body_len;

    /* Decompress if Content-Encoding present */
    uint8_t *decomp_buf = NULL;
    if (txn->encoding[0] != '\0') {
        /* Smart buffer allocation based on compressed size:
         * - Estimate 10x compression ratio (typical for text content)
         * - Minimum 8KB for small payloads
         * - Maximum 10MB to prevent memory bombs
         */
        size_t est_size = txn->body_len * 10;
        if (est_size < 8 * 1024) est_size = 8 * 1024;
        if (est_size > 10 * 1024 * 1024) est_size = 10 * 1024 * 1024;

        decomp_buf = malloc(est_size);
        if (decomp_buf) {
            int decomp_len = decompress_body(txn->body_buf, (int)txn->body_len,
                                             txn->encoding, decomp_buf, (int)est_size);
            if (decomp_len > 0) {
                display_data = decomp_buf;
                display_len = (size_t)decomp_len;
            }
        }
    }

    display_body(display_data, display_len, txn->content_type);
    fflush(stdout);

    if (decomp_buf) {
        free(decomp_buf);
    }
}

/* Public API */
int http2_init(void) {
    if (g_h2_initialized) return 0;

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

nghttp2_session_callbacks *http2_get_callbacks(void) {
    return g_h2_initialized ? g_h2_callbacks : NULL;
}

void http2_cleanup(void) {
    /* Free shared callbacks (flow sessions manage their own state) */
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

/*============================================================================
 * Flow-Based Response Processing (Phase 3.6.8)
 *
 * These functions process HTTP/2 responses using flow_context_t storage
 * instead of the global g_h2_connections pool. This enables proper
 * per-worker ownership and eliminates race conditions.
 *============================================================================*/

/**
 * @brief Process a single response header into flow_transaction_t
 *
 * Flow-based version of h2_process_response_header that stores
 * response headers in the unified flow_transaction_t structure.
 */
static void h2_process_response_header_flow(flow_transaction_t *txn, const nghttp2_nv *nv) {
    const uint8_t *name = nv->name;
    size_t namelen = nv->namelen;
    const uint8_t *value = nv->value;
    size_t valuelen = nv->valuelen;

    DEBUG_H2("Flow response header: '%.*s: %.*s'",
             (int)namelen, name, (int)valuelen, value);

    /* Handle pseudo-headers */
    if (namelen > 0 && name[0] == ':') {
        if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
            char status_str[8] = {0};
            size_t copylen = valuelen < 7 ? valuelen : 7;
            memcpy(status_str, value, copylen);
            txn->status_code = atoi(status_str);
        }
        return;
    }

    /* Extract special headers into flow_transaction_t */
    if (namelen == 12 && strncasecmp((const char *)name, "content-type", 12) == 0) {
        size_t copylen = valuelen < sizeof(txn->content_type) - 1 ? valuelen : sizeof(txn->content_type) - 1;
        memcpy(txn->content_type, value, copylen);
        txn->content_type[copylen] = '\0';
    } else if (namelen == 16 && strncasecmp((const char *)name, "content-encoding", 16) == 0) {
        if (valuelen > 0) {
            txn->flags |= TXN_FLAG_COMPRESSED;
            size_t copylen = valuelen < sizeof(txn->encoding) - 1 ? valuelen : sizeof(txn->encoding) - 1;
            memcpy(txn->encoding, value, copylen);
            txn->encoding[copylen] = '\0';
        }
    } else if (namelen == 14 && strncasecmp((const char *)name, "content-length", 14) == 0) {
        char len_str[32] = {0};
        size_t copylen = valuelen < 31 ? valuelen : 31;
        memcpy(len_str, value, copylen);
        txn->content_length = strtoull(len_str, NULL, 10);
    }
}

/**
 * @brief Display HTTP/2 response from flow_transaction_t
 *
 * Flow-based version of h2_display_response that uses the unified
 * transaction structure for output.
 */
static void h2_display_response_flow(flow_transaction_t *txn, flow_context_t *flow_ctx,
                                      const ssl_data_event_t *event) {
    DEBUG_H2("h2_display_response_flow: stream=%d status=%d",
             txn->stream_id, txn->status_code);

    /* Handle missing status (HPACK decode failure) */
    if (txn->status_code == 0) {
        char time_str[16];
        time_t now = time(NULL);
        struct tm *tm = localtime(&now);
        strftime(time_str, sizeof(time_str), "%H:%M:%S", tm);

        if (txn->method[0] && txn->host[0]) {
            printf("%s ← [HPACK decode error] https://%s%s stream:%d %s (%u)\n",
                   time_str,
                   txn->host,
                   txn->path[0] ? txn->path : "/",
                   txn->stream_id,
                   flow_ctx->comm[0] ? flow_ctx->comm : "unknown",
                   flow_ctx->pid);
        } else {
            printf("%s ← [HPACK decode error] stream:%d %s (%u)\n",
                   time_str,
                   txn->stream_id,
                   flow_ctx->comm[0] ? flow_ctx->comm : "unknown",
                   flow_ctx->pid);
        }
        fflush(stdout);
        return;
    }

    http_message_t msg = {0};
    msg.protocol = PROTO_HTTP2;
    msg.direction = DIR_RESPONSE;
    msg.stream_id = txn->stream_id;
    msg.pid = flow_ctx->pid;
    msg.status_code = txn->status_code;
    msg.timestamp_ns = event->timestamp_ns;

    /* Copy request info for correlation */
    safe_strcpy(msg.method, sizeof(msg.method), txn->method);
    safe_strcpy(msg.path, sizeof(msg.path), txn->path);
    safe_strcpy(msg.authority, sizeof(msg.authority), txn->host);
    safe_strcpy(msg.scheme, sizeof(msg.scheme), "https");

    /* Calculate latency */
    if (txn->start_time_ns > 0 && event->timestamp_ns > txn->start_time_ns) {
        msg.delta_ns = event->timestamp_ns - txn->start_time_ns;
    }

    safe_strcpy(msg.content_type, sizeof(msg.content_type), txn->content_type);
    msg.content_length = txn->content_length;
    safe_strcpy(msg.comm, sizeof(msg.comm), flow_ctx->comm);

    /* Use XDP flow info if available */
    if (flow_ctx->flags & FLOW_FLAG_HAS_XDP) {
        msg.has_flow_info = true;
        msg.flow_src_ip = flow_ctx->flow.saddr;
        msg.flow_dst_ip = flow_ctx->flow.daddr;
        msg.flow_src_port = flow_ctx->flow.sport;
        msg.flow_dst_port = flow_ctx->flow.dport;
        msg.flow_ip_version = flow_ctx->flow.ip_version;
        msg.flow_category = flow_ctx->xdp_category;
    }

    /* Use ALPN from flow context */
    if (flow_ctx->alpn[0]) {
        safe_strcpy(msg.alpn_proto, sizeof(msg.alpn_proto), flow_ctx->alpn);
    }

    display_http_response(&msg);
    printf("\n");
    fflush(stdout);
}

/**
 * @brief Process complete HTTP/2 response frame using flow context
 *
 * Flow-based version of h2_process_complete_response_frame that uses
 * flow_ctx->parser.h2.inflater for HPACK decompression and stores
 * response data in flow_transaction_t.
 */
static void h2_process_complete_response_frame_flow(flow_context_t *flow_ctx,
                                                     const uint8_t *frame_data,
                                                     size_t frame_total_len,
                                                     const ssl_data_event_t *event) {
    (void)frame_total_len;

    /* Parse frame header */
    uint32_t frame_len = ((uint32_t)frame_data[0] << 16) |
                         ((uint32_t)frame_data[1] << 8) |
                         (uint32_t)frame_data[2];
    uint8_t frame_type = frame_data[3];
    uint8_t flags = frame_data[4];
    int32_t stream_id = (int32_t)(((uint32_t)(frame_data[5] & 0x7f) << 24) |
                                  ((uint32_t)frame_data[6] << 16) |
                                  ((uint32_t)frame_data[7] << 8) |
                                  (uint32_t)frame_data[8]);

    const uint8_t *payload = frame_data + 9;
    uint32_t payload_len = frame_len;

    DEBUG_H2("Flow response frame: type=%s len=%u stream=%d flags=0x%02x",
             http2_frame_name(frame_type), frame_len, stream_id, flags);

    switch (frame_type) {
    case 0x01: /* HEADERS */
        {
            /* Find or create stream transaction */
            flow_transaction_t *txn = flow_h2_find_stream(flow_ctx, stream_id);
            if (!txn) {
                DEBUG_H2("Response for unknown stream %d, creating", stream_id);
                txn = flow_h2_alloc_stream(flow_ctx, stream_id);
                if (!txn) break;
            }

            /* Update timing */
            txn->last_active_ms = flow_get_monotonic_ms();

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

            /* Decode HPACK headers using flow context inflater */
            int final = (flags & 0x04) ? 1 : 0; /* END_HEADERS flag */
            const uint8_t *hdr_pos = hdr_data;
            size_t hdr_remaining = hdr_len;

            DEBUG_H2("Flow decoding %u bytes of HPACK, final=%d", hdr_len, final);

            while (hdr_remaining > 0) {
                nghttp2_nv nv;
                int inflate_flags = 0;

                ssize_t consumed = nghttp2_hd_inflate_hd2(flow_ctx->parser.h2.inflater,
                                                          &nv, &inflate_flags,
                                                          hdr_pos, hdr_remaining,
                                                          final);
                if (consumed < 0) {
                    DEBUG_H2("Flow HPACK inflate error: %zd (%s)",
                             consumed, nghttp2_strerror((int)consumed));

                    /* Mark HPACK corrupted for this connection */
                    flow_ctx->parser.h2.hpack_corrupted = true;

                    /* End current header block */
                    nghttp2_hd_inflate_end_headers(flow_ctx->parser.h2.inflater);
                    break;
                }

                hdr_pos += consumed;
                hdr_remaining -= (size_t)consumed;

                if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
                    h2_process_response_header_flow(txn, &nv);
                }

                if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
                    nghttp2_hd_inflate_end_headers(flow_ctx->parser.h2.inflater);
                    break;
                }

                /* Prevent infinite loop */
                if (consumed == 0 && !(inflate_flags & NGHTTP2_HD_INFLATE_EMIT)) {
                    break;
                }
            }

            /* Display response if END_HEADERS is set */
            if (flags & 0x04) { /* END_HEADERS */
                if (!(txn->flags & TXN_FLAG_DISPLAYED)) {
                    txn->flags |= TXN_FLAG_DISPLAYED;
                    h2_display_response_flow(txn, flow_ctx, event);

                    /* If END_STREAM also set, response is complete */
                    if (flags & 0x01) { /* END_STREAM */
                        txn->state = TXN_STATE_CLOSED;
                        txn->flags |= TXN_FLAG_RSP_END_STREAM;
                    }
                }
            }
        }
        break;

    case 0x00: /* DATA */
        {
            flow_transaction_t *txn = flow_h2_find_stream(flow_ctx, stream_id);
            if (txn) {
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

                /* Append body data if configured (allocates body_buf on first use) */
                if (body_len > 0 && g_config.show_body) {
                    flow_txn_append_body(txn, body_data, body_len);
                }

                /* Update activity timestamp */
                txn->last_active_ms = flow_get_monotonic_ms();

                /* Mark complete if END_STREAM */
                if (flags & 0x01) { /* END_STREAM */
                    txn->state = TXN_STATE_CLOSED;
                    txn->flags |= TXN_FLAG_RSP_END_STREAM;

                    /* Display body if accumulated and configured */
                    if (txn->body_len > 0 && g_config.show_body) {
                        h2_display_body_flow(txn, flow_ctx);
                    }
                }
            }
        }
        break;

    case 0x03: /* RST_STREAM */
        {
            flow_transaction_t *txn = flow_h2_find_stream(flow_ctx, stream_id);
            if (txn) {
                txn->state = TXN_STATE_RESET;
                DEBUG_H2("Stream %d reset", stream_id);
            }
        }
        break;

    default:
        /* Other frame types - ignore for response parsing */
        break;
    }
}

/**
 * @brief Process response frames with reassembly using flow context
 *
 * Flow-based version of h2_process_response_frame that uses
 * flow_ctx->parser.h2.reassembly_buf for frame reassembly.
 */
static void h2_process_response_frame_flow(flow_context_t *flow_ctx,
                                            const uint8_t *data, int len,
                                            const ssl_data_event_t *event) {
    h2_parser_ctx_t *h2 = &flow_ctx->parser.h2;

    /* Sanity check buffer length */
    if (h2->reassembly_len > h2->reassembly_capacity) {
        DEBUG_H2("WARNING: reassembly_len=%zu exceeds capacity, resetting", h2->reassembly_len);
        h2->reassembly_len = 0;
    }

    /* Append incoming data to reassembly buffer */
    size_t space_available = h2->reassembly_capacity - h2->reassembly_len;
    size_t to_copy = ((size_t)len < space_available) ? (size_t)len : space_available;

    if (to_copy > 0 && h2->reassembly_buf) {
        memcpy(h2->reassembly_buf + h2->reassembly_len, data, to_copy);
        h2->reassembly_len += to_copy;
    }

    if (to_copy < (size_t)len) {
        DEBUG_H2("Flow response buffer overflow, dropped %zu bytes", (size_t)len - to_copy);
    }

    /* Process all complete frames */
    size_t pos = 0;
    while (h2->reassembly_len - pos >= 9) {
        const uint8_t *frame_start = h2->reassembly_buf + pos;

        /* Parse frame header */
        uint32_t frame_len = ((uint32_t)frame_start[0] << 16) |
                             ((uint32_t)frame_start[1] << 8) |
                             (uint32_t)frame_start[2];
        size_t total_frame_size = 9 + frame_len;

        /* Validate frame header */
        if (!http2_is_valid_frame_header(frame_start, h2->reassembly_len - pos)) {
            DEBUG_H2("Invalid flow frame header, attempting recovery");

            if (h2->reassembly_len <= pos + 1) {
                h2->reassembly_len = 0;
                return;
            }
            size_t remaining = h2->reassembly_len - pos - 1;
            size_t skip = h2_find_frame_start(h2->reassembly_buf + pos + 1, remaining);
            if (skip > 0 && skip < remaining) {
                pos += skip + 1;
                continue;
            } else {
                h2->reassembly_len = 0;
                return;
            }
        }

        /* Check for complete frame */
        if (h2->reassembly_len - pos < total_frame_size) {
            DEBUG_H2("Incomplete flow frame: need %zu, have %zu",
                     total_frame_size, h2->reassembly_len - pos);
            break;
        }

        /* Process the complete frame */
        h2_process_complete_response_frame_flow(flow_ctx, frame_start, total_frame_size, event);

        pos += total_frame_size;
    }

    /* Move remaining data to beginning */
    if (pos > 0) {
        size_t remaining = h2->reassembly_len - pos;
        if (remaining > 0) {
            memmove(h2->reassembly_buf, h2->reassembly_buf + pos, remaining);
        }
        h2->reassembly_len = remaining;
    }
}

/* Check if a frame header looks valid (sanity check for mid-stream joins) */
bool http2_is_valid_frame_header(const uint8_t *data, size_t len) {
    /* Need at least 9 bytes for frame header */
    if (len < 9) {
        return false;
    }

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
    /* Need at least 9 bytes for a valid frame header */
    if (len < 9) {
        return len;  /* No valid frame possible */
    }

    /* Look for patterns that indicate frame boundaries:
     * - SETTINGS frame on stream 0: type=4, stream_id=0
     * - HEADERS frame with small stream ID: type=1, stream_id < 1000
     * - WINDOW_UPDATE on stream 0: type=8, stream_id=0
     */
    for (size_t i = 0; i + 9 <= len; i++) {
        if (http2_is_valid_frame_header(buf + i, len - i)) {
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

void http2_process_frame_flow(const uint8_t *data, int len,
                              const ssl_data_event_t *event,
                              flow_context_t *flow_ctx) {
    if (!g_h2_initialized) {
        if (http2_init() != 0) {
            DEBUG_H2("http2_init() failed");
            return;
        }
    }

    /* Check for HPACK corruption - stop processing if connection is dead */
    if (flow_ctx && flow_ctx->parser.h2.hpack_corrupted) {
        DEBUG_H2("HPACK corrupted, skipping frame processing");
        return;
    }

    /*
     * Lazy session initialization (Phase 3.6)
     *
     * If we have a flow_ctx with proto=HTTP2 but no session yet,
     * initialize it now. This handles:
     * - Preface detection setting proto before session init
     * - Mid-connection attach where ALPN already set proto
     * - ALPN event arriving before first data
     */
    if (flow_ctx && flow_ctx->proto == FLOW_PROTO_HTTP2 &&
        flow_ctx->parser.h2.session == NULL) {
        nghttp2_session_callbacks *cbs = http2_get_callbacks();
        if (cbs) {
            void *cb_ctx = http2_create_callback_ctx(flow_ctx);
            if (cb_ctx) {
                flow_ctx->parser.h2.callback_ctx = cb_ctx;
                if (flow_h2_session_init(flow_ctx, cbs, cb_ctx) != 0) {
                    DEBUG_H2("Failed to init H2 session for flow");
                    http2_free_callback_ctx(cb_ctx);
                    flow_ctx->parser.h2.callback_ctx = NULL;
                }
            }
        }
    }

    /*
     * Flow-based processing path (Phase 3.6 migration)
     *
     * When flow_ctx has an initialized session and callback context,
     * process directly using flow-based storage. This eliminates
     * dependency on global g_h2_connections pool.
     */
    if (flow_ctx && flow_ctx->parser.h2.session && flow_ctx->parser.h2.callback_ctx) {
        /* Set event for callbacks to access */
        http2_set_callback_event(flow_ctx->parser.h2.callback_ctx, event);

        if (event->event_type == EVENT_SSL_WRITE) {
            /* Client writing = request data going to server */

            const uint8_t *feed_data = data;
            int feed_len = len;

            while (feed_len >= 9) {
                uint32_t frame_len = ((uint32_t)feed_data[0] << 16) |
                                     ((uint32_t)feed_data[1] << 8) |
                                     (uint32_t)feed_data[2];
                uint8_t frame_type = feed_data[3];
                uint8_t flags = feed_data[4];

                size_t total_frame_size = 9 + frame_len;

                /* Validate frame header */
                if (!http2_is_valid_frame_header(feed_data, (size_t)feed_len)) {
                    DEBUG_H2("Invalid request frame (flow), skipping %d bytes", feed_len);
                    size_t skip = h2_find_frame_start(feed_data + 1, (size_t)(feed_len - 1));
                    if (skip > 0 && skip < (size_t)(feed_len - 1)) {
                        feed_data += skip + 1;
                        feed_len -= (int)(skip + 1);
                        continue;
                    }
                    break;
                }

                /* Check for complete frame */
                if ((int)total_frame_size > feed_len) {
                    break;
                }

                /* Skip SETTINGS ACK */
                if (frame_type == 0x04 && flags == 0x01 && frame_len == 0) {
                    feed_data += total_frame_size;
                    feed_len -= (int)total_frame_size;
                    continue;
                }

                /* Feed to flow-based session */
                ssize_t rv = nghttp2_session_mem_recv(flow_ctx->parser.h2.session,
                                                      feed_data, total_frame_size);
                if (rv < 0) {
                    DEBUG_H2("nghttp2 flow recv error: %zd", rv);
                    break;
                }

                /* Drain send buffer */
                for (;;) {
                    const uint8_t *send_data;
                    ssize_t send_len = nghttp2_session_mem_send(flow_ctx->parser.h2.session,
                                                                &send_data);
                    if (send_len <= 0) break;
                }

                feed_data += total_frame_size;
                feed_len -= (int)total_frame_size;
            }
        } else {
            /* Client reading = response data from server */
            /* Use flow-based response parsing with flow_ctx->parser.h2.inflater */
            h2_process_response_frame_flow(flow_ctx, data, len, event);
        }

        /* Clear event to avoid stale pointer */
        http2_set_callback_event(flow_ctx->parser.h2.callback_ctx, NULL);
        return;
    }

    /* No valid flow context - cannot process */
    DEBUG_H2("No flow_ctx or session for PID %u ssl_ctx=0x%llx, skipping",
             event->pid, (unsigned long long)event->ssl_ctx);
}

#ifdef HAVE_THREADING
/**
 * @brief Unified HTTP/2 event processing entry point
 *
 * Single entry point for all HTTP/2 processing from main.c.
 * Handles detection, session initialization, frame processing,
 * and noise suppression. Keeps all HTTP/2 logic in http2.c.
 *
 * @param[in] data       Raw data buffer
 * @param[in] len        Data length
 * @param[in] event      Worker event with full context
 * @param[in] worker     Worker context for output
 *
 * @return true if data was processed as HTTP/2, false to try other protocols
 */
bool http2_try_process_event(const uint8_t *data, size_t len,
                             worker_event_t *event,
                             worker_ctx_t *worker) {
    if (!data || len == 0 || !event || !worker) {
        return false;
    }

    worker_state_t *state = &worker->state;

    /* Check for existing HTTP/2 session (per-worker) */
    h2_connection_local_t *h2_conn = worker_get_h2_connection(state,
                                        event->pid, event->ssl_ctx, false);
    if (h2_conn && h2_conn->active) {
        /* Process HTTP/2 frame with per-worker session */
        ssl_data_event_t bpf_event = {
            .timestamp_ns = event->timestamp_ns,
            .delta_ns = event->delta_ns,
            .ssl_ctx = event->ssl_ctx,
            .pid = event->pid,
            .tid = event->tid,
            .uid = event->uid,
            .event_type = event->event_type,
            .buf_filled = event->data_len,
        };
        memcpy(bpf_event.comm, event->comm, TASK_COMM_LEN);
        memcpy(bpf_event.data, event->data, event->data_len);

        /* Use flow-aware processing when flow_ctx available */
        http2_process_frame_flow(data, len, &bpf_event, event->flow_ctx);
        return true;
    }

    /* Check for HTTP/2 connection preface */
    if (http2_is_preface(data, len)) {
        output_write(worker, "%s[HTTP/2 connection]%s PID %u (%s)\n",
                    display_color(C_YELLOW), display_color(C_RESET),
                    event->pid, event->comm);

        /* Set proto for flow context (handles ALPN timing issues) */
        if (event->flow_ctx && event->flow_ctx->proto == FLOW_PROTO_UNKNOWN) {
            event->flow_ctx->proto = FLOW_PROTO_HTTP2;
            /* Session initialization is handled lazily in http2_process_frame_flow() */
        }

        /* Create per-worker H2 connection */
        h2_conn = worker_get_h2_connection(state, event->pid, event->ssl_ctx, true);
        if (h2_conn) {
            h2_conn->client_preface_seen = true;
            safe_strcpy(h2_conn->comm, sizeof(h2_conn->comm), event->comm);
        }

        /* Process frames after preface */
        if (len > 24) {
            ssl_data_event_t bpf_event = {
                .timestamp_ns = event->timestamp_ns,
                .delta_ns = event->delta_ns,
                .ssl_ctx = event->ssl_ctx,
                .pid = event->pid,
                .tid = event->tid,
                .uid = event->uid,
                .event_type = event->event_type,
                .buf_filled = len - 24,
            };
            memcpy(bpf_event.comm, event->comm, TASK_COMM_LEN);
            memcpy(bpf_event.data, data + 24, len - 24);
            http2_process_frame_flow(data + 24, len - 24, &bpf_event, event->flow_ctx);
        }
        return true;
    }

    /* Check for HTTP/2 frames (mid-connection attach) */
    if (len >= 9) {
        uint32_t frame_len = ((uint32_t)data[0] << 16) |
                             ((uint32_t)data[1] << 8) |
                             (uint32_t)data[2];
        uint8_t frame_type = data[3];
        uint32_t stream_id = ((uint32_t)(data[5] & 0x7f) << 24) |
                             ((uint32_t)data[6] << 16) |
                             ((uint32_t)data[7] << 8) |
                             (uint32_t)data[8];

        if (frame_type <= 0x09 && frame_len <= 16384) {
            bool is_valid_h2 = false;
            if (frame_type == H2_FRAME_SETTINGS && stream_id == 0) is_valid_h2 = true;
            else if (frame_type == H2_FRAME_HEADERS && (stream_id & 1) != 0) is_valid_h2 = true;
            else if (frame_type == H2_FRAME_WINDOW_UPDATE && stream_id == 0) is_valid_h2 = true;
            else if (frame_type == H2_FRAME_DATA && (stream_id & 1) != 0 && frame_len > 0) is_valid_h2 = true;

            if (is_valid_h2 && (9 + frame_len) <= len) {
                output_write(worker, "%s[HTTP/2 connection]%s PID %u (%s)\n",
                            display_color(C_YELLOW), display_color(C_RESET),
                            event->pid, event->comm);

                /* Mid-connection attach: Set proto for pre-seeded connections */
                if (event->flow_ctx && event->flow_ctx->proto == FLOW_PROTO_UNKNOWN) {
                    event->flow_ctx->proto = FLOW_PROTO_HTTP2;
                }

                h2_conn = worker_get_h2_connection(state, event->pid, event->ssl_ctx, true);
                if (h2_conn) {
                    safe_strcpy(h2_conn->comm, sizeof(h2_conn->comm), event->comm);
                }

                ssl_data_event_t bpf_event = {
                    .timestamp_ns = event->timestamp_ns,
                    .delta_ns = event->delta_ns,
                    .ssl_ctx = event->ssl_ctx,
                    .pid = event->pid,
                    .tid = event->tid,
                    .uid = event->uid,
                    .event_type = event->event_type,
                    .buf_filled = len,
                };
                memcpy(bpf_event.comm, event->comm, TASK_COMM_LEN);
                memcpy(bpf_event.data, data, len);
                http2_process_frame_flow(data, len, &bpf_event, event->flow_ctx);
                return true;
            }
        }
    }

    /* HTTP/2 noise suppression in non-debug mode */
    if (!g_config.debug_mode) {
        /* HTTP/2 control frames (types 0x02-0x08) in small packets */
        if (len >= 9 && len <= 32) {
            uint8_t frame_type = data[3];
            if (frame_type >= 0x02 && frame_type <= 0x08) {
                return true;  /* Suppress - treat as handled */
            }
        }

        /* Small writes (<= 13 bytes) are likely HTTP/2 control frames */
        if (len <= 13 && event->event_type == EVENT_SSL_WRITE) {
            h2_conn = worker_get_h2_connection(state, event->pid, event->ssl_ctx, false);
            if (h2_conn) {
                return true;  /* Known H2 connection - suppress noise */
            }
            /* Also suppress small writes that look like H2 frames */
            if (len == 4 || len == 8 || len == 9 || len == 13) {
                return true;  /* Common H2 control frame sizes */
            }
        }

        /* Small reads on active H2 connections are partial frames */
        if (len <= 9 && event->event_type == EVENT_SSL_READ) {
            h2_conn = worker_get_h2_connection(state, event->pid, event->ssl_ctx, false);
            if (h2_conn && h2_conn->active) {
                return true;
            }
        }
    }

    return false;  /* Not HTTP/2 - let caller try other protocols */
}
#endif /* HAVE_THREADING */

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

void http2_process_frame_flow(const uint8_t *data, int len,
                              const ssl_data_event_t *event,
                              flow_context_t *flow_ctx) {
    (void)data;
    (void)len;
    (void)event;
    (void)flow_ctx;
    /* No-op without nghttp2 */
}

struct nghttp2_session_callbacks *http2_get_callbacks(void) {
    return NULL;
}

void *http2_create_callback_ctx(flow_context_t *flow_ctx) {
    (void)flow_ctx;
    return NULL;
}

void http2_free_callback_ctx(void *callback_ctx) {
    (void)callback_ctx;
}

void http2_set_callback_event(void *callback_ctx, const ssl_data_event_t *event) {
    (void)callback_ctx;
    (void)event;
}

bool http2_is_valid_frame_header(const uint8_t *data, size_t len) {
    (void)data;
    (void)len;
    return false;
}

#ifdef HAVE_THREADING
bool http2_try_process_event(const uint8_t *data, size_t len,
                             struct worker_event *event,
                             struct worker_ctx *worker) {
    (void)data;
    (void)len;
    (void)event;
    (void)worker;
    return false;  /* No HTTP/2 support without nghttp2 */
}
#endif /* HAVE_THREADING */

#endif /* HAVE_NGHTTP2 */
