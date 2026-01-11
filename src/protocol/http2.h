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

#ifndef HTTP2_H
#define HTTP2_H

#include "../include/spliff.h"
#include "../bpf/probe_handler.h"
#include <stdbool.h>
#include <stdint.h>

/* HTTP/2 frame types */
#define H2_FRAME_DATA          0x0
#define H2_FRAME_HEADERS       0x1
#define H2_FRAME_PRIORITY      0x2
#define H2_FRAME_RST_STREAM    0x3
#define H2_FRAME_SETTINGS      0x4
#define H2_FRAME_PUSH_PROMISE  0x5
#define H2_FRAME_PING          0x6
#define H2_FRAME_GOAWAY        0x7
#define H2_FRAME_WINDOW_UPDATE 0x8
#define H2_FRAME_CONTINUATION  0x9

/* Configuration limits */
#define MAX_H2_SESSIONS     64
#define MAX_H2_STREAMS      512
#define H2_BODY_BUFFER_SIZE (256 * 1024)  /* 256KB per stream */

/* Frame validation limits (for mid-stream join recovery) */
#define H2_MAX_SANE_FRAME_LEN   65536      /* Max 64KB (buffer size) */
#define H2_MAX_VALID_FRAME_TYPE 9          /* CONTINUATION = 9 */
#define H2_MAX_SANE_STREAM_ID   0x00FFFFFF /* ~16M streams */

/* Stream state */
typedef enum {
    H2_STREAM_IDLE = 0,
    H2_STREAM_OPEN,
    H2_STREAM_HALF_CLOSED_LOCAL,
    H2_STREAM_HALF_CLOSED_REMOTE,
    H2_STREAM_CLOSED
} h2_stream_state_t;

/* Per-stream state */
typedef struct {
    /* Key - expanded to include ssl_ctx for per-connection tracking */
    uint32_t pid;
    uint64_t ssl_ctx;
    int32_t stream_id;
    bool active;

    /* State machine */
    h2_stream_state_t state;

    /* Request info (from HEADERS) */
    char method[MAX_METHOD_LEN];
    char path[MAX_PATH_LEN];
    char authority[MAX_HEADER_VALUE];
    char scheme[16];
    uint64_t request_time_ns;
    bool request_headers_done;
    bool request_complete;

    /* Response info */
    int status_code;
    char content_type[256];
    char content_encoding[64];
    size_t content_length;
    uint64_t response_time_ns;
    bool response_headers_done;
    bool response_complete;

    /* Headers storage */
    http_header_t headers[MAX_HEADERS];
    int header_count;
    bool headers_displayed;

    /* Body accumulation */
    uint8_t *body_buf;
    size_t body_buf_size;
    size_t body_len;

    /* Metadata for display */
    uint64_t delta_ns;
    char comm[TASK_COMM_LEN];
} h2_stream_t;

/* Initialize HTTP/2 parser (nghttp2-based) */
int http2_init(void);

/* Cleanup */
void http2_cleanup(void);

/* Get frame type name */
const char *http2_frame_name(int type);

/* Check if data looks like HTTP/2 connection preface */
bool http2_is_preface(const uint8_t *data, size_t len);

/* Process HTTP/2 data from BPF event */
void http2_process_frame(const uint8_t *data, int len, const ssl_data_event_t *event);

/* Check if (PID, ssl_ctx) has active HTTP/2 session */
bool http2_has_session(uint32_t pid, uint64_t ssl_ctx);

/* Set ALPN protocol for a connection */
void http2_set_alpn(uint32_t pid, uint64_t ssl_ctx, const char *alpn);

/* Get ALPN protocol for a connection (returns empty string if not set) */
const char *http2_get_alpn(uint32_t pid, uint64_t ssl_ctx);

/* Get stream info (for external use) */
h2_stream_t *http2_get_stream(uint32_t pid, uint64_t ssl_ctx, int32_t stream_id, bool create);

/* Free stream resources */
void http2_free_stream(uint32_t pid, uint64_t ssl_ctx, int32_t stream_id);

/* Cleanup all HTTP/2 resources for a specific PID (process exit handling) */
void http2_cleanup_pid(uint32_t pid);

/* Check if a frame header looks valid (exposed for testing) */
bool http2_is_valid_frame_header(const uint8_t *data);

#endif /* HTTP2_H */
