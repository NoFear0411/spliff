/**
 * @file http1.c
 * @brief HTTP/1.1 parser implementation using llhttp
 *
 * @details This module implements HTTP/1.1 parsing using llhttp, the
 * official HTTP parser from Node.js. The parser uses callbacks to
 * extract message components incrementally.
 *
 * @par llhttp Callback Flow:
 * @code
 * on_message_begin()
 *       │
 *       ├── on_url() [requests] / on_status() [responses]
 *       │
 *       ├── on_header_field()  ─┐
 *       │                       │ (repeated for each header)
 *       ├── on_header_value()  ─┘
 *       │
 *       ├── on_headers_complete()
 *       │
 *       ├── on_body() (repeated for body chunks)
 *       │
 *       └── on_message_complete()
 * @endcode
 *
 * @par Chunked Encoding:
 * llhttp automatically decodes chunked transfer encoding. The on_body()
 * callback receives decoded data, not raw chunks.
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "http1.h"
#include "../include/spliff.h"
#include "../bpf/probe_handler.h"
#include "../util/safe_str.h"
#include "../correlation/flow_context.h"
#include "../output/display.h"
#include "../content/decompressor.h"
#ifdef HAVE_THREADING
#include "../threading/threading.h"
#endif
#include <llhttp.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * @brief Parser context structure
 *
 * Passed through llhttp via parser->data pointer. Maintains parsing
 * state and accumulates results into the http_message_t output.
 *
 * @internal
 */
typedef struct {
    http_message_t *msg;           /**< Output message structure */
    char current_header_name[MAX_HEADER_NAME]; /**< Current header name being parsed */
    size_t header_name_len;        /**< Current header name length */
    bool in_header_value;          /**< True if parsing header value */

    /** @name Body Tracking */
    /** @{ */
    uint8_t *body_buf;             /**< Body buffer (optional, may be NULL) */
    size_t body_buf_size;          /**< Body buffer capacity */
    size_t body_len;               /**< Current body length accumulated */
    /** @} */

    /** @name Parser State */
    /** @{ */
    bool headers_complete;         /**< Headers section finished */
    bool message_complete;         /**< Full message parsed */
    /** @} */
} parse_context_t;

/**
 * @brief Global llhttp settings with callbacks
 *
 * Initialized once by http1_init() and shared by all parse operations.
 *
 * @internal
 */
static llhttp_settings_t g_settings;

/**
 * @brief Initialization flag
 * @internal
 */
static bool g_initialized = false;

/**
 * @defgroup http1_callbacks llhttp Callbacks
 * @brief Parser callback implementations
 * @ingroup http1
 * @internal
 * @{
 */

/**
 * @brief Called at start of new HTTP message
 *
 * Resets parser context state for the new message.
 * Does not clear the output msg structure as caller may
 * have set metadata (pid, comm, etc.) before parsing.
 *
 * @param[in,out] parser llhttp parser instance
 * @return 0 to continue parsing
 */
static int on_message_begin(llhttp_t *parser) {
    parse_context_t *ctx = (parse_context_t *)parser->data;

    /* Reset context for new message */
    ctx->header_name_len = 0;
    ctx->in_header_value = false;
    ctx->headers_complete = false;
    ctx->message_complete = false;
    ctx->body_len = 0;

    /* Don't clear msg here - caller may have set metadata already */
    return 0;
}

/**
 * @brief Called with URL data (requests only)
 *
 * May be called multiple times as URL arrives in chunks.
 * Appends to msg->path.
 *
 * @param[in,out] parser llhttp parser instance
 * @param[in]     at     URL fragment pointer
 * @param[in]     len    URL fragment length
 * @return 0 to continue parsing
 */
static int on_url(llhttp_t *parser, const char *at, size_t len) {
    parse_context_t *ctx = (parse_context_t *)parser->data;
    http_message_t *msg = ctx->msg;

    /* Append to path (URL may come in multiple chunks) */
    size_t current_len = strlen(msg->path);
    if (current_len + len < sizeof(msg->path)) {
        memcpy(msg->path + current_len, at, len);
        msg->path[current_len + len] = '\0';
    }

    return 0;
}

/**
 * @brief Called with status text (responses only)
 *
 * Receives the status text portion (e.g., "OK" from "HTTP/1.1 200 OK").
 *
 * @param[in,out] parser llhttp parser instance
 * @param[in]     at     Status text fragment
 * @param[in]     len    Fragment length
 * @return 0 to continue parsing
 */
static int on_status(llhttp_t *parser, const char *at, size_t len) {
    parse_context_t *ctx = (parse_context_t *)parser->data;
    http_message_t *msg = ctx->msg;

    /* Append status text */
    size_t current_len = strlen(msg->status_text);
    if (current_len + len < sizeof(msg->status_text)) {
        memcpy(msg->status_text + current_len, at, len);
        msg->status_text[current_len + len] = '\0';
    }

    return 0;
}

/**
 * @brief Called with header field name
 *
 * May be called multiple times for one header if name arrives in chunks.
 * Accumulates into ctx->current_header_name.
 *
 * @param[in,out] parser llhttp parser instance
 * @param[in]     at     Header name fragment
 * @param[in]     len    Fragment length
 * @return 0 to continue parsing
 */
static int on_header_field(llhttp_t *parser, const char *at, size_t len) {
    parse_context_t *ctx = (parse_context_t *)parser->data;

    /* If we were in header value, we're starting a new header */
    if (ctx->in_header_value) {
        ctx->header_name_len = 0;
        ctx->in_header_value = false;
    }

    /* Append to header name (may come in chunks) */
    if (ctx->header_name_len + len < sizeof(ctx->current_header_name)) {
        memcpy(ctx->current_header_name + ctx->header_name_len, at, len);
        ctx->header_name_len += len;
        ctx->current_header_name[ctx->header_name_len] = '\0';
    }

    return 0;
}

/**
 * @brief Called with header field value
 *
 * May be called multiple times for one header if value arrives in chunks.
 * Copies header name from ctx->current_header_name on first call,
 * then appends value data.
 *
 * @param[in,out] parser llhttp parser instance
 * @param[in]     at     Header value fragment
 * @param[in]     len    Fragment length
 * @return 0 to continue parsing
 */
static int on_header_value(llhttp_t *parser, const char *at, size_t len) {
    parse_context_t *ctx = (parse_context_t *)parser->data;
    http_message_t *msg = ctx->msg;

    ctx->in_header_value = true;

    /* Ensure we have a header slot */
    if (msg->header_count >= MAX_HEADERS) {
        return 0;  /* Silently drop excess headers */
    }

    http_header_t *hdr = &msg->headers[msg->header_count];

    /* If header name not yet copied, copy it now */
    if (hdr->name[0] == '\0' && ctx->header_name_len > 0) {
        safe_strcpy(hdr->name, sizeof(hdr->name), ctx->current_header_name);
    }

    /* Append to header value (may come in chunks) */
    size_t current_len = strlen(hdr->value);
    if (current_len + len < sizeof(hdr->value)) {
        memcpy(hdr->value + current_len, at, len);
        hdr->value[current_len + len] = '\0';
    }

    return 0;
}

/**
 * @brief Called when header value is complete
 *
 * Extracts special headers (Host, Content-Type, Content-Encoding,
 * Content-Length, Transfer-Encoding) into dedicated msg fields.
 * Increments header_count and resets state for next header.
 *
 * @param[in,out] parser llhttp parser instance
 * @return 0 to continue parsing
 */
static int on_header_value_complete(llhttp_t *parser) {
    parse_context_t *ctx = (parse_context_t *)parser->data;
    http_message_t *msg = ctx->msg;

    if (msg->header_count >= MAX_HEADERS) {
        return 0;
    }

    http_header_t *hdr = &msg->headers[msg->header_count];

    /* Extract special headers */
    if (strcasecmp(hdr->name, "Host") == 0) {
        safe_strcpy(msg->authority, sizeof(msg->authority), hdr->value);
    } else if (strcasecmp(hdr->name, "Content-Type") == 0) {
        safe_strcpy(msg->content_type, sizeof(msg->content_type), hdr->value);
    } else if (strcasecmp(hdr->name, "Content-Encoding") == 0) {
        safe_strcpy(msg->content_encoding, sizeof(msg->content_encoding), hdr->value);
    } else if (strcasecmp(hdr->name, "Content-Length") == 0) {
        msg->content_length = (size_t)strtoull(hdr->value, NULL, 10);
    } else if (strcasecmp(hdr->name, "Transfer-Encoding") == 0) {
        /* Note: llhttp handles chunked decoding, but we track the header */
        msg->is_chunked = (strstr(hdr->value, "chunked") != NULL);
    }

    msg->header_count++;

    /* Reset for next header */
    ctx->header_name_len = 0;
    ctx->in_header_value = false;

    return 0;
}

/**
 * @brief Called when all headers have been parsed
 *
 * Determines message direction (request vs response) using llhttp_get_type().
 * For requests: extracts method name.
 * For responses: extracts status code.
 * Sets protocol to PROTO_HTTP1 and extracts HTTP version.
 *
 * @param[in,out] parser llhttp parser instance
 * @return 0 to continue parsing
 */
static int on_headers_complete(llhttp_t *parser) {
    parse_context_t *ctx = (parse_context_t *)parser->data;
    http_message_t *msg = ctx->msg;

    ctx->headers_complete = true;

    /* Get message type and status code */
    if (llhttp_get_type(parser) == HTTP_REQUEST) {
        msg->direction = DIR_REQUEST;
        msg->method[0] = '\0';  /* Will be set below */
        safe_strcpy(msg->scheme, sizeof(msg->scheme), "https");

        /* Get method name */
        uint8_t method = llhttp_get_method(parser);
        const char *method_name = llhttp_method_name(method);
        if (method_name) {
            safe_strcpy(msg->method, sizeof(msg->method), method_name);
        }
    } else {
        msg->direction = DIR_RESPONSE;
        msg->status_code = llhttp_get_status_code(parser);
    }

    msg->protocol = PROTO_HTTP1;

    /* Store HTTP version */
    msg->http_major = llhttp_get_http_major(parser);
    msg->http_minor = llhttp_get_http_minor(parser);

    return 0;
}

/**
 * @brief Called with body data
 *
 * May be called multiple times as body arrives. Data is already
 * decoded if chunked transfer encoding was used.
 *
 * If ctx->body_buf is provided, accumulates data there up to
 * ctx->body_buf_size.
 *
 * @param[in,out] parser llhttp parser instance
 * @param[in]     at     Body data fragment
 * @param[in]     len    Fragment length (already chunk-decoded)
 * @return 0 to continue parsing
 */
static int on_body(llhttp_t *parser, const char *at, size_t len) {
    parse_context_t *ctx = (parse_context_t *)parser->data;

    /* If body buffer provided, accumulate body data */
    /* Note: llhttp already decodes chunked encoding! */
    if (ctx->body_buf && ctx->body_buf_size > 0) {
        size_t available = ctx->body_buf_size - ctx->body_len;
        size_t to_copy = (len < available) ? len : available;

        if (to_copy > 0) {
            memcpy(ctx->body_buf + ctx->body_len, at, to_copy);
            ctx->body_len += to_copy;
        }
    }

    return 0;
}

/**
 * @brief Called when message is fully parsed
 *
 * Sets ctx->message_complete flag to indicate full message received.
 *
 * @param[in,out] parser llhttp parser instance
 * @return 0 to complete parsing
 */
static int on_message_complete(llhttp_t *parser) {
    parse_context_t *ctx = (parse_context_t *)parser->data;
    ctx->message_complete = true;
    return 0;
}

/** @} */ /* End of http1_callbacks group */

/**
 * @defgroup http1_public HTTP/1.1 Public API
 * @brief Public parsing functions
 * @ingroup http1
 * @{
 */

/**
 * @brief Initialize HTTP/1.1 parser module
 *
 * Sets up llhttp_settings_t with callback functions. Safe to call
 * multiple times; subsequent calls are no-ops.
 *
 * @return Always 0
 */
int http1_init(void) {
    if (g_initialized) return 0;

    llhttp_settings_init(&g_settings);

    /* Set up callbacks */
    g_settings.on_message_begin = on_message_begin;
    g_settings.on_url = on_url;
    g_settings.on_status = on_status;
    g_settings.on_header_field = on_header_field;
    g_settings.on_header_value = on_header_value;
    g_settings.on_header_value_complete = on_header_value_complete;
    g_settings.on_headers_complete = on_headers_complete;
    g_settings.on_body = on_body;
    g_settings.on_message_complete = on_message_complete;

    g_initialized = true;
    return 0;
}

llhttp_settings_t *http1_get_settings(void) {
    return g_initialized ? &g_settings : NULL;
}

/**
 * @brief Clean up parser resources
 *
 * Resets initialization flag. Currently no resources to free as
 * llhttp_settings_t is statically allocated.
 */
void http1_cleanup(void) {
    g_initialized = false;
}

/**
 * @brief Check if data appears to be HTTP/1.1 request
 *
 * Fast heuristic check for HTTP method prefixes without full parsing.
 * Checks for: GET, POST, PUT, HEAD, DELETE, OPTIONS, PATCH, CONNECT, TRACE.
 *
 * @param[in] data Data buffer to check
 * @param[in] len  Buffer length
 * @return true if data starts with HTTP method
 */
bool http1_is_request(const uint8_t *data, size_t len) {
    if (len < 4) return false;

    /* Check for common HTTP methods */
    return (memcmp(data, "GET ", 4) == 0 ||
            memcmp(data, "POST ", 5) == 0 ||
            memcmp(data, "PUT ", 4) == 0 ||
            memcmp(data, "HEAD ", 5) == 0 ||
            memcmp(data, "DELETE ", 7) == 0 ||
            memcmp(data, "OPTIONS ", 8) == 0 ||
            memcmp(data, "PATCH ", 6) == 0 ||
            memcmp(data, "CONNECT ", 8) == 0 ||
            memcmp(data, "TRACE ", 6) == 0);
}

/**
 * @brief Check if data appears to be HTTP/1.1 response
 *
 * Checks for "HTTP/1." prefix which indicates HTTP response status line.
 *
 * @param[in] data Data buffer to check
 * @param[in] len  Buffer length
 * @return true if data starts with HTTP version string
 */
bool http1_is_response(const uint8_t *data, size_t len) {
    return len >= 9 && memcmp(data, "HTTP/1.", 7) == 0;
}

/**
 * @brief Parse HTTP/1.1 message using llhttp
 *
 * Full HTTP/1.1 parser that extracts headers and optionally body.
 * Uses llhttp in HTTP_BOTH mode for automatic request/response detection.
 *
 * @par Implementation Notes:
 * - Message structure is zeroed before parsing
 * - Auto-initializes if http1_init() not called
 * - Partial messages are acceptable (headers complete is sufficient)
 * - Body data is already chunk-decoded by llhttp
 *
 * @param[in]  data          Raw HTTP data
 * @param[in]  len           Data length
 * @param[out] msg           Output message structure
 * @param[out] body_buf      Optional body accumulation buffer
 * @param[in]  body_buf_size Body buffer capacity
 * @param[out] body_len_out  Output: actual body bytes accumulated
 *
 * @return Data length on success (may have partial body), -1 on error
 */
int http1_parse(const uint8_t *data, size_t len, http_message_t *msg,
                uint8_t *body_buf, size_t body_buf_size, size_t *body_len_out) {
    if (!g_initialized) {
        http1_init();
    }

    /* Initialize message structure */
    memset(msg, 0, sizeof(*msg));

    /* Setup parser context */
    parse_context_t ctx = {0};
    ctx.msg = msg;
    ctx.body_buf = body_buf;
    ctx.body_buf_size = body_buf_size;

    /* Create parser with HTTP_BOTH (auto-detect request/response) */
    llhttp_t parser;
    llhttp_init(&parser, HTTP_BOTH, &g_settings);
    parser.data = &ctx;

    /* Execute parser */
    llhttp_errno_t err = llhttp_execute(&parser, (const char *)data, len);

    if (err != HPE_OK && err != HPE_PAUSED_UPGRADE) {
        /* Parse error - but we may have partial data */
        if (!ctx.headers_complete) {
            return -1;
        }
        /* Headers complete, might have truncated body - that's ok for sniffing */
    }

    /* Return body length if requested */
    if (body_len_out) {
        *body_len_out = ctx.body_len;
    }

    return (int)len;
}

/**
 * @brief Parse HTTP/1.1 headers only (compatibility wrapper)
 *
 * Simplified interface that parses headers without body accumulation.
 * Direction parameter is ignored; llhttp auto-detects.
 *
 * @param[in]  data Raw HTTP data
 * @param[in]  len  Data length
 * @param[out] msg  Output message structure
 * @param[in]  dir  Direction hint (ignored)
 *
 * @deprecated Use http1_parse() directly
 */
void http1_parse_headers(const uint8_t *data, size_t len, http_message_t *msg, direction_t dir) {
    (void)dir;  /* Ignored - llhttp auto-detects direction */

    /* Use http1_parse without body buffer */
    http1_parse(data, len, msg, NULL, 0, NULL);
}

/**
 * @brief Find body start position
 *
 * Locates the header terminator (\\r\\n\\r\\n) and returns the offset
 * where body content begins.
 *
 * @param[in] data Raw HTTP data
 * @param[in] len  Data length
 * @return Byte offset of body start, or -1 if not found
 *
 * @note Prefer http1_parse() which provides body data via callbacks
 */
int http1_find_body_start(const uint8_t *data, size_t len) {
    const uint8_t *pos = (const uint8_t *)memmem(data, len, "\r\n\r\n", 4);
    if (pos) {
        return (int)(pos - data) + 4;
    }
    return -1;
}

/**
 * @brief Decode chunked transfer encoding
 *
 * Manually decodes HTTP/1.1 chunked encoding for compatibility with
 * code that processes raw data outside the llhttp callback flow.
 *
 * @par Chunked Format:
 * @code
 * <hex-size>[;chunk-ext]\r\n
 * <chunk-data>\r\n
 * ...
 * 0\r\n
 * [trailer-headers]\r\n
 * @endcode
 *
 * @param[in]  in       Chunked-encoded input
 * @param[in]  in_len   Input length
 * @param[out] out      Decoded output buffer
 * @param[in]  out_size Output buffer capacity
 *
 * @return Bytes written to out, or -1 on error
 *
 * @note llhttp handles this automatically in on_body(); this function
 *       is provided for direct data manipulation scenarios
 */
int http1_decode_chunked(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_size) {
    const uint8_t *pos = in;
    const uint8_t *end = in + in_len;
    uint8_t *out_pos = out;
    uint8_t *out_end = out + out_size;

    while (pos < end) {
        /* Read chunk size (hex number followed by \r\n) */
        const uint8_t *crlf = (const uint8_t *)memmem(pos, (size_t)(end - pos), "\r\n", 2);
        if (!crlf) break;

        /* Parse hex chunk size */
        char size_str[32];
        size_t size_len = (size_t)(crlf - pos);
        if (size_len >= sizeof(size_str)) return -1;

        memcpy(size_str, pos, size_len);
        size_str[size_len] = '\0';

        /* Handle chunk extensions (after ';') */
        char *semicolon = strchr(size_str, ';');
        if (semicolon) *semicolon = '\0';

        unsigned long chunk_size = strtoul(size_str, NULL, 16);
        if (chunk_size == 0) break;  /* Last chunk */

        pos = crlf + 2;

        if (pos + chunk_size + 2 > end) break;  /* Incomplete */
        if (out_pos + chunk_size > out_end) return -1;  /* Output full */

        memcpy(out_pos, pos, chunk_size);
        out_pos += chunk_size;
        pos += chunk_size + 2;
    }

    return (int)(out_pos - out);
}

/** @} */ /* End of http1_public group */

/*============================================================================
 * Flow-Based HTTP/1 Parsing (Phase 3.6.5)
 *
 * These functions implement persistent HTTP/1 parsing using flow_context_t
 * storage. The parser maintains state across TCP segments and populates
 * flow_transaction_t for unified transaction handling.
 *
 * Key design: All parsing state is stored in h1_parser_ctx_t (inside flow_ctx)
 * so that fragmented headers and chunked bodies work correctly across
 * multiple SSL_read calls.
 *============================================================================*/

/**
 * @brief Minimal callback context for flow-based parsing
 *
 * Only holds pointers - actual state is in flow_ctx->parser.h1
 * which persists across TCP segments.
 */
typedef struct {
    struct flow_context *flow_ctx;      /**< Flow context (has persistent state) */
    const struct ssl_data_event *event; /**< Current SSL event */
} h1_flow_cb_ctx_t;

/* Forward declarations */
static void h1_display_message_flow(struct flow_context *flow_ctx,
                                     const struct ssl_data_event *event);
static void h1_display_body_flow(struct flow_context *flow_ctx);

/*--- Flow-based llhttp callbacks using persistent state ---*/

static int on_message_begin_flow(llhttp_t *parser) {
    h1_flow_cb_ctx_t *cb = (h1_flow_cb_ctx_t *)parser->data;
    h1_parser_ctx_t *h1 = &cb->flow_ctx->parser.h1;

    /*
     * Save request URL info before resetting for response display.
     * HTTP/1 is request-response, so if the previous message was a request,
     * save its URL for correlation with the upcoming response.
     */
    if (h1->txn.direction == DIR_REQUEST && h1->txn.host[0]) {
        safe_strcpy(h1->last_request_host, sizeof(h1->last_request_host), h1->txn.host);
        safe_strcpy(h1->last_request_path, sizeof(h1->last_request_path), h1->txn.path);
        safe_strcpy(h1->last_request_method, sizeof(h1->last_request_method), h1->txn.method);
    }

    /* Reset persistent parsing state for new message */
    h1->header_name_len = 0;
    h1->in_header_value = false;
    h1->headers_complete = false;
    h1->message_complete = false;

    /* Reset transaction for new message */
    flow_h1_reset_txn(cb->flow_ctx);
    h1->txn.state = TXN_STATE_OPEN;
    h1->txn.stream_id = 0;  /* HTTP/1 has no streams */

    /* Set start time from current event */
    if (cb->event) {
        h1->txn.start_time_ns = cb->event->timestamp_ns;
    }

    return 0;
}

static int on_url_flow(llhttp_t *parser, const char *at, size_t len) {
    h1_flow_cb_ctx_t *cb = (h1_flow_cb_ctx_t *)parser->data;
    flow_transaction_t *txn = &cb->flow_ctx->parser.h1.txn;

    /* Append to path (URL may arrive in multiple chunks) */
    size_t current_len = strlen(txn->path);
    size_t space = sizeof(txn->path) - current_len - 1;
    size_t to_copy = len < space ? len : space;

    if (to_copy > 0) {
        memcpy(txn->path + current_len, at, to_copy);
        txn->path[current_len + to_copy] = '\0';
    }

    return 0;
}

static int on_status_flow(llhttp_t *parser, const char *at, size_t len) {
    (void)parser;
    (void)at;
    (void)len;
    /* Status text not stored in flow_transaction_t */
    return 0;
}

static int on_header_field_flow(llhttp_t *parser, const char *at, size_t len) {
    h1_flow_cb_ctx_t *cb = (h1_flow_cb_ctx_t *)parser->data;
    h1_parser_ctx_t *h1 = &cb->flow_ctx->parser.h1;

    if (h1->in_header_value) {
        /* Starting new header - reset accumulated name */
        h1->header_name_len = 0;
        h1->in_header_value = false;
    }

    /* Accumulate header name (may arrive in chunks) */
    size_t space = sizeof(h1->current_header_name) - h1->header_name_len - 1;
    size_t to_copy = len < space ? len : space;

    if (to_copy > 0) {
        memcpy(h1->current_header_name + h1->header_name_len, at, to_copy);
        h1->header_name_len += to_copy;
        h1->current_header_name[h1->header_name_len] = '\0';
    }

    return 0;
}

static int on_header_value_flow(llhttp_t *parser, const char *at, size_t len) {
    h1_flow_cb_ctx_t *cb = (h1_flow_cb_ctx_t *)parser->data;
    h1_parser_ctx_t *h1 = &cb->flow_ctx->parser.h1;
    flow_transaction_t *txn = &h1->txn;

    h1->in_header_value = true;

    if (h1->header_name_len == 0) return 0;

    /* Extract important headers into flow_transaction_t */
    if (strcasecmp(h1->current_header_name, "Host") == 0) {
        size_t cur = strlen(txn->host);
        size_t space = sizeof(txn->host) - cur - 1;
        size_t to_copy = len < space ? len : space;
        if (to_copy > 0) {
            memcpy(txn->host + cur, at, to_copy);
            txn->host[cur + to_copy] = '\0';
        }
    } else if (strcasecmp(h1->current_header_name, "Content-Type") == 0) {
        size_t cur = strlen(txn->content_type);
        size_t space = sizeof(txn->content_type) - cur - 1;
        size_t to_copy = len < space ? len : space;
        if (to_copy > 0) {
            memcpy(txn->content_type + cur, at, to_copy);
            txn->content_type[cur + to_copy] = '\0';
        }
    } else if (strcasecmp(h1->current_header_name, "Content-Length") == 0) {
        char len_str[32] = {0};
        size_t to_copy = len < 31 ? len : 31;
        memcpy(len_str, at, to_copy);
        txn->content_length = strtoull(len_str, NULL, 10);
    } else if (strcasecmp(h1->current_header_name, "Content-Encoding") == 0) {
        size_t cur = strlen(txn->encoding);
        size_t space = sizeof(txn->encoding) - cur - 1;
        size_t to_copy = len < space ? len : space;
        if (to_copy > 0) {
            memcpy(txn->encoding + cur, at, to_copy);
            txn->encoding[cur + to_copy] = '\0';
            txn->flags |= TXN_FLAG_COMPRESSED;
        }
    }

    return 0;
}

static int on_header_value_complete_flow(llhttp_t *parser) {
    h1_flow_cb_ctx_t *cb = (h1_flow_cb_ctx_t *)parser->data;
    h1_parser_ctx_t *h1 = &cb->flow_ctx->parser.h1;

    h1->header_name_len = 0;
    h1->in_header_value = false;
    return 0;
}

static int on_headers_complete_flow(llhttp_t *parser) {
    h1_flow_cb_ctx_t *cb = (h1_flow_cb_ctx_t *)parser->data;
    h1_parser_ctx_t *h1 = &cb->flow_ctx->parser.h1;
    flow_transaction_t *txn = &h1->txn;

    h1->headers_complete = true;

    /* Set direction and extract method/status from parser */
    if (parser->type == HTTP_REQUEST) {
        txn->direction = DIR_REQUEST;
        const char *method_str = llhttp_method_name((llhttp_method_t)parser->method);
        if (method_str) {
            safe_strcpy(txn->method, sizeof(txn->method), method_str);
        }
    } else {
        txn->direction = DIR_RESPONSE;
        txn->status_code = (int)parser->status_code;
    }

    txn->state = TXN_STATE_OPEN;  /* Headers received, body may follow */

    /* Display immediately when headers complete */
    if (!(txn->flags & TXN_FLAG_DISPLAYED)) {
        txn->flags |= TXN_FLAG_DISPLAYED;
        h1_display_message_flow(cb->flow_ctx, cb->event);
    }

    return 0;
}

static int on_body_flow(llhttp_t *parser, const char *at, size_t len) {
    h1_flow_cb_ctx_t *cb = (h1_flow_cb_ctx_t *)parser->data;
    flow_transaction_t *txn = &cb->flow_ctx->parser.h1.txn;

    /* Only accumulate body if body display is enabled (-b flag) */
    if (g_config.show_body) {
        flow_txn_append_body(txn, (const uint8_t *)at, len);
    }

    return 0;
}

static int on_message_complete_flow(llhttp_t *parser) {
    h1_flow_cb_ctx_t *cb = (h1_flow_cb_ctx_t *)parser->data;
    h1_parser_ctx_t *h1 = &cb->flow_ctx->parser.h1;

    h1->message_complete = true;
    h1->txn.state = TXN_STATE_CLOSED;

    /*
     * Display body now that message is complete.
     * Headers were displayed in on_headers_complete for immediate feedback.
     * This mirrors h2_display_body_flow() pattern for consistent architecture.
     */
    if (g_config.show_body) {
        h1_display_body_flow(cb->flow_ctx);
    }

    /*
     * Check keep-alive status per llhttp docs:
     * llhttp_should_keep_alive() returns 1 if there might be any other
     * messages following the last that was successfully parsed.
     *
     * Note: For HTTP/1.1, Connection: keep-alive is default.
     * For HTTP/1.0, Connection: keep-alive must be explicit.
     */
    h1->txn.flags |= llhttp_should_keep_alive(parser) ? TXN_FLAG_KEEP_ALIVE : 0;

    return 0;
}

/**
 * @brief Reset callback for HTTP/1.1 keep-alive connections
 *
 * Called after on_message_complete and before on_message_begin when
 * a new message is received on the same parser (HTTP/1.1 keep-alive).
 * This is NOT called for the first message.
 *
 * @note Per llhttp docs: "Invoked after on_message_complete and before
 * on_message_begin when a new message is received on the same parser."
 */
static int on_reset_flow(llhttp_t *parser) {
    h1_flow_cb_ctx_t *cb = (h1_flow_cb_ctx_t *)parser->data;
    h1_parser_ctx_t *h1 = &cb->flow_ctx->parser.h1;

    /* Clear transaction for next message (keep-alive pipelining) */
    memset(&h1->txn, 0, sizeof(h1->txn));

    /* Reset header parsing state */
    h1->header_name_len = 0;
    h1->in_header_value = false;
    h1->headers_complete = false;
    h1->message_complete = false;

    return 0;
}

/* Global flow-based settings */
static llhttp_settings_t g_flow_settings;
static bool g_flow_settings_initialized = false;

/**
 * @brief Initialize flow-based llhttp settings
 */
static void http1_init_flow_settings(void) {
    if (g_flow_settings_initialized) return;

    llhttp_settings_init(&g_flow_settings);
    g_flow_settings.on_message_begin = on_message_begin_flow;
    g_flow_settings.on_url = on_url_flow;
    g_flow_settings.on_status = on_status_flow;
    g_flow_settings.on_header_field = on_header_field_flow;
    g_flow_settings.on_header_value = on_header_value_flow;
    g_flow_settings.on_header_value_complete = on_header_value_complete_flow;
    g_flow_settings.on_headers_complete = on_headers_complete_flow;
    g_flow_settings.on_body = on_body_flow;
    g_flow_settings.on_message_complete = on_message_complete_flow;
    g_flow_settings.on_reset = on_reset_flow;  /* HTTP/1.1 keep-alive support */

    g_flow_settings_initialized = true;
}

llhttp_settings_t *http1_get_flow_settings(void) {
    if (!g_flow_settings_initialized) {
        http1_init_flow_settings();
    }
    return &g_flow_settings;
}

/**
 * @brief Display HTTP/1 message from flow transaction
 */
static void h1_display_message_flow(struct flow_context *flow_ctx,
                                     const struct ssl_data_event *event) {
    flow_transaction_t *txn = &flow_ctx->parser.h1.txn;
    h1_parser_ctx_t *h1 = &flow_ctx->parser.h1;
    http_message_t msg = {0};

    msg.protocol = PROTO_HTTP1;
    msg.direction = txn->direction;
    msg.pid = flow_ctx->pid;
    msg.timestamp_ns = event ? event->timestamp_ns : 0;
    msg.delta_ns = event ? event->delta_ns : 0;

    safe_strcpy(msg.method, sizeof(msg.method), txn->method);
    safe_strcpy(msg.content_type, sizeof(msg.content_type), txn->content_type);
    msg.content_length = txn->content_length;
    safe_strcpy(msg.comm, sizeof(msg.comm), flow_ctx->comm);

    if (txn->direction == DIR_REQUEST) {
        /* Request: use current transaction's URL info */
        safe_strcpy(msg.path, sizeof(msg.path), txn->path);
        safe_strcpy(msg.authority, sizeof(msg.authority), txn->host);
    } else {
        /* Response: use saved request URL info for correlation */
        safe_strcpy(msg.path, sizeof(msg.path), h1->last_request_path);
        safe_strcpy(msg.authority, sizeof(msg.authority), h1->last_request_host);
    }
    msg.status_code = txn->status_code;

    /* Add ALPN protocol if negotiated */
    if (flow_ctx->alpn[0]) {
        safe_strcpy(msg.alpn_proto, sizeof(msg.alpn_proto), flow_ctx->alpn);
    }

    /* Add XDP flow correlation if available */
    if (flow_ctx->flags & FLOW_FLAG_HAS_XDP) {
        msg.has_flow_info = true;
        msg.flow_src_ip = flow_ctx->flow.saddr;
        msg.flow_dst_ip = flow_ctx->flow.daddr;
        msg.flow_src_port = flow_ctx->flow.sport;
        msg.flow_dst_port = flow_ctx->flow.dport;
        msg.flow_ip_version = flow_ctx->flow.ip_version;
        msg.flow_category = flow_ctx->xdp_category;
    }

    if (txn->direction == DIR_REQUEST) {
        display_http_request(&msg);
    } else {
        display_http_response(&msg);
    }
    printf("\n");
    fflush(stdout);
}

/**
 * @brief Display HTTP/1 body content from flow transaction
 *
 * Called from on_message_complete when body is fully accumulated.
 * Mirrors h2_display_body_flow() for consistent architecture.
 *
 * @param flow_ctx  Flow context containing transaction
 */
static void h1_display_body_flow(struct flow_context *flow_ctx) {
    flow_transaction_t *txn = &flow_ctx->parser.h1.txn;

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

int http1_parse_flow(struct flow_context *flow_ctx, const uint8_t *data, size_t len,
                     const struct ssl_data_event *event) {
    if (!flow_ctx || flow_ctx->proto != FLOW_PROTO_HTTP1) {
        return -1;
    }

    h1_parser_ctx_t *h1 = &flow_ctx->parser.h1;

    /* Initialize parser with flow-based settings if needed */
    if (!h1->initialized) {
        llhttp_settings_t *settings = http1_get_flow_settings();
        if (flow_h1_parser_init(flow_ctx, settings) != 0) {
            return -1;
        }
    }

    /*
     * Direction detection for bidirectional sniffing.
     *
     * llhttp's HTTP_BOTH mode auto-detects the FIRST message type, then
     * expects all subsequent messages to be the same type. For traffic
     * sniffing where we see both requests (SSL_write) and responses
     * (SSL_read), we need to reset the parser when direction changes.
     */
    bool is_response = http1_is_response(data, len);
    bool is_request = http1_is_request(data, len);
    llhttp_type_t current_type = h1->parser.type;

    if (is_response && (current_type == HTTP_REQUEST || current_type == HTTP_BOTH)) {
        /* Parser expects request but got response - reinit for response */
        llhttp_init(&h1->parser, HTTP_RESPONSE, &h1->settings);
        h1->headers_complete = false;
        h1->message_complete = false;
        if (g_config.debug_mode) {
            fprintf(stderr, "[DEBUG] H1 parser reinit: %s -> RESPONSE\n",
                    current_type == HTTP_REQUEST ? "REQUEST" : "BOTH");
        }
    } else if (is_request && (current_type == HTTP_RESPONSE || current_type == HTTP_BOTH)) {
        /* Parser expects response but got request - reinit for request */
        llhttp_init(&h1->parser, HTTP_REQUEST, &h1->settings);
        h1->headers_complete = false;
        h1->message_complete = false;
        if (g_config.debug_mode) {
            fprintf(stderr, "[DEBUG] H1 parser reinit: %s -> REQUEST\n",
                    current_type == HTTP_RESPONSE ? "RESPONSE" : "BOTH");
        }
    }

    /* Setup minimal callback context (just pointers, state is in h1) */
    h1_flow_cb_ctx_t cb_ctx = {
        .flow_ctx = flow_ctx,
        .event = event
    };

    /* Attach context to parser for this execution */
    h1->parser.data = &cb_ctx;

    /* Execute parser - llhttp maintains internal state across calls */
    llhttp_errno_t err = llhttp_execute(&h1->parser, (const char *)data, len);

    if (err == HPE_OK) {
        /* All data consumed successfully */
        return (int)len;
    }

    if (err == HPE_PAUSED_UPGRADE) {
        /* Connection upgrade (WebSocket, h2c, etc.) - normal completion */
        return (int)len;
    }

    /*
     * Parse error - use llhttp_get_error_pos() to determine bytes consumed.
     * This is important for partial parses where some data was processed.
     */
    const char *error_pos = llhttp_get_error_pos(&h1->parser);
    size_t parsed = error_pos ? (size_t)(error_pos - (const char *)data) : 0;

    /* Debug: show parse error details */
    if (g_config.debug_mode) {
        fprintf(stderr, "[DEBUG] H1 parse error: %s (%s), headers_complete=%d, parsed=%zu/%zu\n",
                llhttp_errno_name(err), llhttp_get_error_reason(&h1->parser),
                h1->headers_complete, parsed, len);
    }

    if (!h1->headers_complete) {
        /* Headers incomplete - real error */
        return -1;
    }

    /*
     * Headers done, truncated body is acceptable for sniffing.
     * This commonly happens when we don't receive the full body
     * in a single buffer, which is normal for large responses.
     */
    return (int)(parsed > 0 ? parsed : len);
}

#ifdef HAVE_THREADING
/**
 * @brief Unified HTTP/1 event processing entry point
 *
 * Single entry point for all HTTP/1 processing from main.c.
 * Handles detection, parser initialization, and parsing.
 * Keeps all HTTP/1 logic in http1.c.
 *
 * @param[in] data       Raw data buffer
 * @param[in] len        Data length
 * @param[in] event      Worker event with full context
 * @param[in] worker     Worker context for output
 *
 * @return true if data was processed as HTTP/1, false to try other protocols
 */
bool http1_try_process_event(const uint8_t *data, size_t len,
                             worker_event_t *event,
                             worker_ctx_t *worker) {
    if (!data || len == 0 || !event || !worker) {
        return false;
    }

    (void)worker;  /* Output handled via callbacks for now */

    /* Check if this is a known HTTP/1 flow or looks like HTTP/1 */
    bool is_known_http1_flow = event->flow_ctx &&
                               event->flow_ctx->proto == FLOW_PROTO_HTTP1;
    bool looks_like_http1 = http1_is_request(data, len) || http1_is_response(data, len);

    /* Debug: trace HTTP/1.1 parsing path */
    if (g_config.debug_mode) {
        fprintf(stderr, "[DEBUG] H1 check: flow_ctx=%p, proto=%d (H1=%d), looks_h1=%d, is_known_h1=%d, len=%zu\n",
                (void*)event->flow_ctx,
                event->flow_ctx ? (int)event->flow_ctx->proto : -1,
                (int)FLOW_PROTO_HTTP1,
                looks_like_http1, is_known_http1_flow, len);
        if (len >= 16) {
            fprintf(stderr, "[DEBUG] H1 data prefix: %.16s\n", data);
        }
    }

    if (!looks_like_http1 && !is_known_http1_flow) {
        return false;  /* Not HTTP/1 */
    }

    /* Set proto if manual detection succeeds but vectorscan missed it */
    if (looks_like_http1 && event->flow_ctx &&
        event->flow_ctx->proto == FLOW_PROTO_UNKNOWN) {
        event->flow_ctx->proto = FLOW_PROTO_HTTP1;
        /* Initialize parser for late-detected HTTP/1 */
        if (!event->flow_ctx->parser.h1.initialized) {
            llhttp_settings_t *settings = http1_get_flow_settings();
            flow_h1_parser_init(event->flow_ctx, settings);
        }
    }

    if (event->flow_ctx && event->flow_ctx->proto == FLOW_PROTO_HTTP1) {
        /* Build ssl_data_event_t for flow-based parser */
        ssl_data_event_t bpf_event = {
            .timestamp_ns = event->timestamp_ns,
            .delta_ns = event->delta_ns,
            .ssl_ctx = event->ssl_ctx,
            .pid = event->pid,
            .tid = event->tid,
            .uid = event->uid,
            .event_type = event->event_type,
            .buf_filled = (int32_t)event->data_len,
        };
        memcpy(bpf_event.comm, event->comm, TASK_COMM_LEN);

        /* Parse using persistent flow-based parser */
        int result = http1_parse_flow(event->flow_ctx, data, len, &bpf_event);
        if (g_config.debug_mode) {
            fprintf(stderr, "[DEBUG] H1 parse result=%d for flow_id=%u\n",
                    result, event->flow_ctx->self_id);
        }
        if (result >= 0) {
            return true;  /* Successfully parsed - display handled in callbacks */
        }
        /* Flow-based parser error - fall through to let caller try other handlers */
    }

    return false;  /* No flow context or flow-based parser failed */
}
#endif /* HAVE_THREADING */
