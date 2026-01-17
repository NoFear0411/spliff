/**
 * @file websocket.h
 * @brief WebSocket frame parser (RFC 6455)
 *
 * @details This module provides WebSocket protocol support for parsing
 * frames after an HTTP upgrade handshake. It handles:
 *
 * - **Frame parsing**: Header decoding, payload extraction
 * - **Masking**: Unmasking client-to-server frames
 * - **Fragmentation**: Multi-frame message reassembly
 * - **Control frames**: Ping, pong, close handling
 *
 * @par WebSocket Frame Format (RFC 6455 Section 5.2):
 * @code
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-------+-+-------------+-------------------------------+
 * |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
 * |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
 * |N|V|V|V|       |S|             |   (if payload len==126/127)   |
 * | |1|2|3|       |K|             |                               |
 * +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
 * |     Extended payload length continued, if payload len == 127  |
 * + - - - - - - - - - - - - - - - +-------------------------------+
 * |                               |Masking-key, if MASK set to 1  |
 * +-------------------------------+-------------------------------+
 * | Masking-key (continued)       |          Payload Data         |
 * +-------------------------------- - - - - - - - - - - - - - - - +
 * :                     Payload Data continued ...                :
 * + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 * |                     Payload Data continued ...                |
 * +---------------------------------------------------------------+
 * @endcode
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef SPLIFF_WEBSOCKET_H
#define SPLIFF_WEBSOCKET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @defgroup websocket WebSocket Parser
 * @brief RFC 6455 WebSocket frame parsing
 * @{
 */

/**
 * @brief WebSocket frame opcodes (RFC 6455 Section 5.2)
 *
 * Defines the type of data in the frame payload:
 * - 0x0-0x2: Data frames (continuation, text, binary)
 * - 0x8-0xA: Control frames (close, ping, pong)
 * - Others: Reserved
 */
typedef enum {
    WS_OPCODE_CONTINUATION = 0x0, /**< Continuation frame (follows fragmented) */
    WS_OPCODE_TEXT         = 0x1, /**< UTF-8 text data */
    WS_OPCODE_BINARY       = 0x2, /**< Binary data */
    /* 0x3-0x7 reserved for non-control frames */
    WS_OPCODE_CLOSE        = 0x8, /**< Connection close */
    WS_OPCODE_PING         = 0x9, /**< Ping (keepalive request) */
    WS_OPCODE_PONG         = 0xA, /**< Pong (keepalive response) */
    /* 0xB-0xF reserved for control frames */
} ws_opcode_t;

/**
 * @brief WebSocket close status codes (RFC 6455 Section 7.4.1)
 *
 * Status codes sent in close frames to indicate reason for closure.
 */
typedef enum {
    WS_CLOSE_NORMAL           = 1000, /**< Normal closure */
    WS_CLOSE_GOING_AWAY       = 1001, /**< Endpoint going away (e.g., server shutdown) */
    WS_CLOSE_PROTOCOL_ERROR   = 1002, /**< Protocol error */
    WS_CLOSE_UNSUPPORTED_DATA = 1003, /**< Unsupported data type */
    WS_CLOSE_NO_STATUS        = 1005, /**< No status code present (reserved) */
    WS_CLOSE_ABNORMAL         = 1006, /**< Abnormal closure (reserved) */
    WS_CLOSE_INVALID_PAYLOAD  = 1007, /**< Invalid frame payload data */
    WS_CLOSE_POLICY_VIOLATION = 1008, /**< Policy violation */
    WS_CLOSE_MESSAGE_TOO_BIG  = 1009, /**< Message too big */
    WS_CLOSE_EXTENSION_ERROR  = 1010, /**< Expected extension not negotiated */
    WS_CLOSE_INTERNAL_ERROR   = 1011, /**< Unexpected server condition */
} ws_close_code_t;

/**
 * @brief Parsed WebSocket frame structure
 *
 * Contains all information extracted from a WebSocket frame header
 * plus payload pointer and optional close frame details.
 */
typedef struct {
    /** @name Frame Header Fields */
    /** @{ */
    bool fin;              /**< FIN bit: true if final fragment */
    bool rsv1;             /**< RSV1 bit: reserved for extensions */
    bool rsv2;             /**< RSV2 bit: reserved for extensions */
    bool rsv3;             /**< RSV3 bit: reserved for extensions */
    ws_opcode_t opcode;    /**< Frame type (text, binary, control, etc.) */
    bool masked;           /**< MASK bit: true for client→server frames */
    uint64_t payload_len;  /**< Payload length (7, 16, or 64 bit encoding) */
    uint8_t mask_key[4];   /**< Masking key (valid only if masked=true) */
    /** @} */

    /** @name Payload Information */
    /** @{ */
    const uint8_t *payload; /**< Pointer to payload data (within original buffer) */
    size_t header_len;      /**< Total header size in bytes (for offset calculation) */
    /** @} */

    /** @name Close Frame Fields */
    /** @{ */
    uint16_t close_code;      /**< Close status code (for CLOSE frames) */
    char close_reason[128];   /**< Close reason text (optional, for CLOSE frames) */
    /** @} */
} ws_frame_t;

/**
 * @brief WebSocket connection state tracking
 *
 * Maintains state for an active WebSocket connection including
 * fragmentation buffer and statistics.
 */
typedef struct {
    /** @name Connection Identification */
    /** @{ */
    uint32_t pid;      /**< Process ID */
    uint64_t ssl_ctx;  /**< SSL context for connection disambiguation */
    bool active;       /**< True if connection slot is in use */
    /** @} */

    /** @name Upgrade Information */
    /** @{ */
    char url[512];      /**< WebSocket URL (ws:// or wss://) */
    char protocol[64];  /**< Sec-WebSocket-Protocol subprotocol */
    /** @} */

    /** @name Fragmentation State */
    /** @{ */
    ws_opcode_t fragment_opcode;  /**< Opcode of current fragmented message */
    uint8_t *fragment_buf;        /**< Buffer for fragment reassembly */
    size_t fragment_len;          /**< Current accumulated fragment size */
    size_t fragment_capacity;     /**< Fragment buffer allocation size */
    /** @} */

    /** @name Connection Statistics */
    /** @{ */
    uint64_t frames_sent;     /**< Total frames sent */
    uint64_t frames_received; /**< Total frames received */
    uint64_t bytes_sent;      /**< Total payload bytes sent */
    uint64_t bytes_received;  /**< Total payload bytes received */
    /** @} */
} ws_connection_t;

/**
 * @defgroup ws_limits WebSocket Limits
 * @brief Buffer and tracking limits
 * @{
 */
/** Maximum WebSocket connections tracked per worker thread */
#define MAX_WS_CONNECTIONS_PER_WORKER 32

/** Maximum fragment reassembly buffer size (1MB) */
#define MAX_WS_FRAGMENT_SIZE (1024 * 1024)
/** @} */

/**
 * @brief Parse a WebSocket frame from raw data
 *
 * Parses the WebSocket frame header and locates the payload.
 * Handles all payload length encodings (7-bit, 16-bit, 64-bit).
 *
 * @param[in]  data  Raw frame data
 * @param[in]  len   Length of available data
 * @param[out] frame Output structure for parsed frame
 *
 * @return Number of bytes consumed (header + payload), or:
 *         - 0 if need more data (incomplete frame)
 *         - -1 on parse error
 *
 * @note The frame->payload pointer points into the original data buffer
 * @note Call ws_unmask_payload() after parsing if frame->masked is true
 *
 * @par Example:
 * @code
 * ws_frame_t frame;
 * int consumed = ws_parse_frame(data, len, &frame);
 * if (consumed > 0 && frame.masked) {
 *     uint8_t *payload_copy = malloc(frame.payload_len);
 *     memcpy(payload_copy, frame.payload, frame.payload_len);
 *     ws_unmask_payload(payload_copy, frame.payload_len, frame.mask_key);
 * }
 * @endcode
 */
int ws_parse_frame(const uint8_t *data, size_t len, ws_frame_t *frame);

/**
 * @brief Unmask WebSocket payload data in-place
 *
 * Applies the XOR unmasking operation to payload data.
 * Client-to-server frames are always masked per RFC 6455.
 *
 * @par Masking Algorithm (RFC 6455 Section 5.3):
 * @code
 * j = i MOD 4
 * transformed-octet-i = original-octet-i XOR masking-key-octet-j
 * @endcode
 *
 * @param[in,out] payload  Payload data to unmask (modified in-place)
 * @param[in]     len      Payload length
 * @param[in]     mask_key 4-byte masking key from frame header
 *
 * @note This operation is its own inverse; call again to re-mask
 */
void ws_unmask_payload(uint8_t *payload, size_t len, const uint8_t *mask_key);

/**
 * @brief Get human-readable opcode name
 *
 * @param[in] opcode WebSocket opcode value
 *
 * @return Static string with opcode name (e.g., "TEXT", "BINARY", "PING")
 */
const char *ws_opcode_name(ws_opcode_t opcode);

/**
 * @brief Get human-readable close code description
 *
 * @param[in] code WebSocket close status code
 *
 * @return Static string with code description
 */
const char *ws_close_code_name(uint16_t code);

/**
 * @brief Check if data looks like a WebSocket frame
 *
 * Performs heuristic validation on potential WebSocket frame data.
 * Used to detect WebSocket traffic after protocol upgrade.
 *
 * @param[in] data Data buffer to analyze
 * @param[in] len  Length of data buffer
 *
 * @return true if data appears to be a valid WebSocket frame
 */
bool ws_is_frame(const uint8_t *data, size_t len);

/**
 * @brief Check if HTTP request is a WebSocket upgrade
 *
 * Checks for required WebSocket upgrade headers:
 * - Upgrade: websocket
 * - Connection: Upgrade
 * - Sec-WebSocket-Key: (present)
 *
 * @param[in] headers      Array of header strings ("Name: Value" format)
 * @param[in] header_count Number of headers in array
 *
 * @return true if request is a WebSocket upgrade
 */
bool ws_is_upgrade_request(const char *headers[], int header_count);

/**
 * @brief Check if HTTP response is a WebSocket upgrade acceptance
 *
 * Checks for WebSocket upgrade response:
 * - Status code: 101 (Switching Protocols)
 * - Upgrade: websocket
 * - Sec-WebSocket-Accept: (present)
 *
 * @param[in] status_code  HTTP response status code
 * @param[in] headers      Array of header strings
 * @param[in] header_count Number of headers in array
 *
 * @return true if response accepts WebSocket upgrade
 */
bool ws_is_upgrade_response(int status_code, const char *headers[], int header_count);

/** @} */ /* End of websocket group */

#endif /* SPLIFF_WEBSOCKET_H */
