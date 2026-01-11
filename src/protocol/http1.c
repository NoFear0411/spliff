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
 *
 * http1.c - HTTP/1.1 parser using llhttp
 */

#include "http1.h"
#include "../util/safe_str.h"
#include <llhttp.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>

/* Parser context - passed via parser->data */
typedef struct {
    http_message_t *msg;           /* Output message structure */
    char current_header_name[MAX_HEADER_NAME];
    size_t header_name_len;
    bool in_header_value;

    /* Body tracking */
    uint8_t *body_buf;             /* Body buffer (optional) */
    size_t body_buf_size;
    size_t body_len;

    /* State */
    bool headers_complete;
    bool message_complete;
} parse_context_t;

/* Global settings (initialized once) */
static llhttp_settings_t g_settings;
static bool g_initialized = false;

/* ============================================================================
 * llhttp Callbacks
 * ============================================================================ */

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

static int on_message_complete(llhttp_t *parser) {
    parse_context_t *ctx = (parse_context_t *)parser->data;
    ctx->message_complete = true;
    return 0;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

/* Initialize HTTP/1.1 parser module */
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

/* Cleanup */
void http1_cleanup(void) {
    g_initialized = false;
}

/* Check if data looks like HTTP/1.1 request */
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

/* Check if data looks like HTTP/1.1 response */
bool http1_is_response(const uint8_t *data, size_t len) {
    return len >= 9 && memcmp(data, "HTTP/1.", 7) == 0;
}

/* Parse HTTP/1.1 message using llhttp
 *
 * This function parses HTTP headers and optionally the body.
 * If body_buf is provided, body data is accumulated there (already chunk-decoded).
 *
 * Returns: number of bytes parsed, or -1 on error
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

/* Parse HTTP/1.1 headers only (compatibility wrapper) */
void http1_parse_headers(const uint8_t *data, size_t len, http_message_t *msg, direction_t dir) {
    (void)dir;  /* Ignored - llhttp auto-detects direction */

    /* Use http1_parse without body buffer */
    http1_parse(data, len, msg, NULL, 0, NULL);
}

/* Find body start position (after \r\n\r\n)
 * Note: With llhttp, this is mainly for compatibility.
 * The on_body callback provides body data directly.
 */
int http1_find_body_start(const uint8_t *data, size_t len) {
    const uint8_t *pos = (const uint8_t *)memmem(data, len, "\r\n\r\n", 4);
    if (pos) {
        return (int)(pos - data) + 4;
    }
    return -1;
}

/* Decode chunked transfer encoding
 *
 * Note: llhttp handles chunked decoding automatically in the on_body callback.
 * This function is kept for compatibility with code that processes raw data.
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
