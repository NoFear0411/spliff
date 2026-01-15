/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * websocket.h - WebSocket frame parser (RFC 6455)
 */

#ifndef SPLIFF_WEBSOCKET_H
#define SPLIFF_WEBSOCKET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* WebSocket opcodes (RFC 6455 Section 5.2) */
typedef enum {
    WS_OPCODE_CONTINUATION = 0x0,
    WS_OPCODE_TEXT         = 0x1,
    WS_OPCODE_BINARY       = 0x2,
    /* 0x3-0x7 reserved for non-control frames */
    WS_OPCODE_CLOSE        = 0x8,
    WS_OPCODE_PING         = 0x9,
    WS_OPCODE_PONG         = 0xA,
    /* 0xB-0xF reserved for control frames */
} ws_opcode_t;

/* WebSocket close status codes (RFC 6455 Section 7.4.1) */
typedef enum {
    WS_CLOSE_NORMAL           = 1000,
    WS_CLOSE_GOING_AWAY       = 1001,
    WS_CLOSE_PROTOCOL_ERROR   = 1002,
    WS_CLOSE_UNSUPPORTED_DATA = 1003,
    WS_CLOSE_NO_STATUS        = 1005,
    WS_CLOSE_ABNORMAL         = 1006,
    WS_CLOSE_INVALID_PAYLOAD  = 1007,
    WS_CLOSE_POLICY_VIOLATION = 1008,
    WS_CLOSE_MESSAGE_TOO_BIG  = 1009,
    WS_CLOSE_EXTENSION_ERROR  = 1010,
    WS_CLOSE_INTERNAL_ERROR   = 1011,
} ws_close_code_t;

/* Parsed WebSocket frame */
typedef struct {
    bool fin;                   /* Final fragment flag */
    bool rsv1, rsv2, rsv3;      /* Reserved bits (used by extensions) */
    ws_opcode_t opcode;         /* Frame type */
    bool masked;                /* Client-to-server frames are masked */
    uint64_t payload_len;       /* Payload length */
    uint8_t mask_key[4];        /* Masking key (if masked) */
    const uint8_t *payload;     /* Pointer to payload data */
    size_t header_len;          /* Total header length (for offset) */

    /* For close frames */
    uint16_t close_code;        /* Close status code */
    char close_reason[128];     /* Close reason (optional) */
} ws_frame_t;

/* WebSocket connection state */
typedef struct {
    uint32_t pid;
    uint64_t ssl_ctx;
    bool active;

    /* Connection info from upgrade */
    char url[512];              /* WebSocket URL */
    char protocol[64];          /* Sec-WebSocket-Protocol */

    /* Fragmentation state */
    ws_opcode_t fragment_opcode; /* Opcode of fragmented message */
    uint8_t *fragment_buf;       /* Buffer for fragmented messages */
    size_t fragment_len;         /* Current fragment buffer length */
    size_t fragment_capacity;    /* Fragment buffer capacity */

    /* Statistics */
    uint64_t frames_sent;
    uint64_t frames_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
} ws_connection_t;

/* Maximum connections tracked per worker */
#define MAX_WS_CONNECTIONS_PER_WORKER 32

/* Maximum fragment buffer size (1MB) */
#define MAX_WS_FRAGMENT_SIZE (1024 * 1024)

/*
 * Parse a WebSocket frame from raw data
 *
 * @param data      Raw frame data
 * @param len       Length of data
 * @param frame     Output: parsed frame structure
 * @return          Number of bytes consumed, or -1 on error, 0 if need more data
 */
int ws_parse_frame(const uint8_t *data, size_t len, ws_frame_t *frame);

/*
 * Unmask WebSocket payload data in-place
 * Client-to-server frames are masked; server-to-client are not
 *
 * @param payload   Payload data to unmask
 * @param len       Payload length
 * @param mask_key  4-byte masking key
 */
void ws_unmask_payload(uint8_t *payload, size_t len, const uint8_t *mask_key);

/*
 * Get human-readable opcode name
 */
const char *ws_opcode_name(ws_opcode_t opcode);

/*
 * Get human-readable close code description
 */
const char *ws_close_code_name(uint16_t code);

/*
 * Check if data looks like a WebSocket frame
 * Used to detect WebSocket traffic after upgrade
 */
bool ws_is_frame(const uint8_t *data, size_t len);

/*
 * Check if HTTP request is a WebSocket upgrade
 */
bool ws_is_upgrade_request(const char *headers[], int header_count);

/*
 * Check if HTTP response is a WebSocket upgrade acceptance
 */
bool ws_is_upgrade_response(int status_code, const char *headers[], int header_count);

#endif /* SPLIFF_WEBSOCKET_H */
