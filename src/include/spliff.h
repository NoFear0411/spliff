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

#ifndef SPLIFF_H
#define SPLIFF_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#define SPLIFF_VERSION "0.6.1"

/* Debug logging macros - only active in DEBUG builds */
#ifdef DEBUG
#define DEBUG_LOG(fmt, ...) fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_H2(fmt, ...) fprintf(stderr, "[H2 DEBUG] " fmt "\n", ##__VA_ARGS__)
#define DEBUG_MAIN(fmt, ...) fprintf(stderr, "[MAIN DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_LOG(fmt, ...) ((void)0)
#define DEBUG_H2(fmt, ...) ((void)0)
#define DEBUG_MAIN(fmt, ...) ((void)0)
#endif
#define SPLIFF_VERSION_MAJOR 0
#define SPLIFF_VERSION_MINOR 6
#define SPLIFF_VERSION_PATCH 1

/* Maximum sizes */
#define MAX_HEADER_NAME     256
#define MAX_HEADER_VALUE    4096
#define MAX_HEADERS         128
#define MAX_PATH_LEN        2048
#define MAX_METHOD_LEN      32
#define MAX_BODY_BUFFER     (1 << 20)  /* 1 MB */
#define TASK_COMM_LEN       16

/* Protocol types */
typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_HTTP1,
    PROTO_HTTP2,
    PROTO_HTTP3
} protocol_t;

/* Direction */
typedef enum {
    DIR_REQUEST = 0,
    DIR_RESPONSE = 1
} direction_t;

/* HTTP header */
typedef struct {
    char name[MAX_HEADER_NAME];
    char value[MAX_HEADER_VALUE];
} http_header_t;

/* Parsed HTTP message */
typedef struct {
    protocol_t protocol;
    direction_t direction;

    /* Request fields */
    char method[MAX_METHOD_LEN];
    char path[MAX_PATH_LEN];
    char authority[MAX_HEADER_VALUE];
    char scheme[16];

    /* Response fields */
    int status_code;
    char status_text[64];

    /* Headers */
    http_header_t headers[MAX_HEADERS];
    int header_count;

    /* Body info */
    size_t content_length;
    char content_type[256];
    char content_encoding[64];
    bool is_chunked;

    /* HTTP version (for HTTP/1.x) */
    uint8_t http_major;
    uint8_t http_minor;

    /* HTTP/2 specific */
    int32_t stream_id;

    /* ALPN negotiated protocol (e.g., "h2", "http/1.1") */
    char alpn_proto[16];

    /* Metadata */
    uint32_t pid;
    char comm[TASK_COMM_LEN];
    uint64_t timestamp_ns;
    uint64_t delta_ns;      /* SSL operation latency */
} http_message_t;

/* Captured SSL event from BPF */
typedef struct {
    uint32_t pid;
    uint32_t tid;
    uint64_t timestamp_ns;
    char comm[TASK_COMM_LEN];
    uint8_t direction;      /* 0=write(request), 1=read(response) */
    uint32_t len;
    uint8_t data[];         /* Flexible array member */
} ssl_event_t;

/* Configuration */
typedef struct {
    /* Filtering */
    uint32_t *pids;
    int pid_count;
    uint32_t ppid;
    char comm_filter[16];

    /* Library selection */
    bool use_openssl;
    bool use_gnutls;
    bool use_nss;

    /* Display options */
    bool compact_mode;
    bool show_body;
    bool show_headers;
    bool show_latency;
    bool show_handshake;
    bool hexdump_mode;
    bool hexdump_body;      /* Show body as hexdump with signature detection (-x) */
    bool use_colors;
    bool filter_ipc;        /* Filter out IPC/Unix socket traffic */
    bool debug_mode;        /* Debug mode - show raw events */

    /* Threading */
    int worker_threads;

    /* Output format */
    enum { FMT_TEXT, FMT_JSON, FMT_COMPACT } output_format;
} config_t;

/* Global config (set by main, read by all) */
extern config_t g_config;

#endif /* SPLIFF_H */
