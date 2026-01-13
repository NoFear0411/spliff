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

#define SPLIFF_VERSION "0.8.1"

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
#define SPLIFF_VERSION_MINOR 8
#define SPLIFF_VERSION_PATCH 1

/* Maximum sizes */
#define MAX_HEADER_NAME     256
#define MAX_HEADER_VALUE    4096
#define MAX_HEADERS         128
#define MAX_PATH_LEN        2048
#define MAX_METHOD_LEN      32
#define MAX_BODY_BUFFER     (1 << 20)  /* 1 MB */
#define TASK_COMM_LEN       16

/* Protocol types (application layer) */
typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_HTTP1,
    PROTO_HTTP2,
    PROTO_HTTP3
} protocol_t;

/* Event source - distinguishes XDP (packet layer) from uprobe (application layer) */
typedef enum {
    EVENT_SOURCE_UPROBE = 0,     /* SSL/TLS decrypted data from uprobes */
    EVENT_SOURCE_XDP             /* Raw encrypted packets from XDP */
} event_source_t;

/* =============================================================================
 * XDP Event Types & Structures
 * =============================================================================
 * Event type inference: The dispatcher infers event type from struct size + tcp_flags:
 *   - size == 172 && payload_len > 0  → AMBIGUOUS (send to PCRE2-JIT)
 *   - size == 56 && tcp_flags & (FIN|RST) → FLOW_END (terminated)
 *   - size == 56 otherwise → FLOW_NEW (new classified flow)
 */

/* TCP flags for flow lifecycle detection */
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_ACK  0x10

/* XDP packet event type identifier (always 6, matches BPF EVENT_XDP_PACKET) */
#define EVENT_XDP_PACKET 6

/* Maximum payload captured for PCRE2-JIT classification */
#define XDP_PAYLOAD_MAX 128

/* XDP protocol categories (matches BPF CAT_* defines in spliff.bpf.c) */
typedef enum {
    XDP_CAT_UNKNOWN = 0,         /* Unknown/unclassified - needs PCRE2-JIT */
    XDP_CAT_TLS_TCP = 1,         /* TLS over TCP (H1/H2) */
    XDP_CAT_QUIC = 2,            /* QUIC/H3 over UDP (stub) */
    XDP_CAT_PLAIN_HTTP = 3,      /* Unencrypted HTTP/1.x */
    XDP_CAT_H2_PREFACE = 4,      /* HTTP/2 connection preface */
    XDP_CAT_OTHER = 5            /* Non-HTTP traffic */
} xdp_category_t;

/* Flow key (5-tuple) for BPF map lookups - 16 bytes
 * Note: IPv4 only. IPv6 flows use XOR-hashed addresses in BPF but
 * socket cookie correlation is limited for IPv6.
 */
typedef struct {
    uint32_t saddr;              /* Source IP (network byte order) */
    uint32_t daddr;              /* Dest IP (network byte order) */
    uint16_t sport;              /* Source port (network byte order) */
    uint16_t dport;              /* Dest port (network byte order) */
    uint8_t  _pad[4];            /* Alignment to 16 bytes */
} __attribute__((packed)) flow_key_t;

/* XDP packet event (metadata only) - 56 bytes
 * Matches struct xdp_packet_event in spliff.bpf.c
 *
 * Sent for:
 *   - New flow discovery (category != UNKNOWN)
 *   - Flow termination (tcp_flags & FIN/RST)
 */
typedef struct {
    uint64_t timestamp_ns;       /* [8] Absolute time for latency calculations */
    uint64_t socket_cookie;      /* [8] The "Golden Thread" to uprobes/SSL */
    flow_key_t flow;             /* [16] 5-tuple for map lookup */

    uint32_t pkt_len;            /* [4] Wire length of packet */
    uint32_t ifindex;            /* [4] NIC interface index */
    uint32_t event_type;         /* [4] Always EVENT_XDP_PACKET (6) */

    uint16_t payload_off;        /* [2] L4 payload offset from packet start (layer 2) */
    uint8_t  category;           /* [1] xdp_category_t */
    uint8_t  tls_type;           /* [1] TLS record type if category == TLS_TCP */
    uint8_t  direction;          /* [1] 0=unknown, 1=ingress, 2=egress */
    uint8_t  tcp_flags;          /* [1] TCP flags (SYN/FIN/RST/ACK) */
    uint8_t  _pad[2];            /* [2] Align to 8-byte boundary */
} __attribute__((packed)) xdp_packet_event_t;

/* XDP payload event (includes payload for PCRE2-JIT) - 172 bytes
 * Matches struct xdp_payload_event in spliff.bpf.c
 *
 * Sent when:
 *   - category == UNKNOWN and payload_len > 0
 *   - Needs userspace PCRE2-JIT classification
 */
typedef struct {
    uint64_t timestamp_ns;       /* [8] Event time */
    uint64_t socket_cookie;      /* [8] Correlation key to uprobes */
    flow_key_t flow;             /* [16] 5-tuple for map lookup */

    uint32_t payload_len;        /* [4] Actual bytes captured (≤128) */
    uint32_t event_type;         /* [4] Always EVENT_XDP_PACKET (6) */
    uint8_t  category;           /* [1] Best-guess category from XDP */
    uint8_t  _pad[3];            /* [3] Alignment padding */
    uint8_t  payload[XDP_PAYLOAD_MAX]; /* [128] First 128 bytes for PCRE2 */
} __attribute__((packed)) xdp_payload_event_t;

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
