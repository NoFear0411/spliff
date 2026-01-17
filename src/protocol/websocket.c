/**
 * @file websocket.c
 * @brief WebSocket frame parser implementation (RFC 6455)
 *
 * @details This module implements WebSocket frame parsing according to
 * RFC 6455. It handles the binary frame format including:
 *
 * - Variable-length payload encoding (7/16/64 bit)
 * - Client-to-server masking
 * - Control frame validation
 * - Close frame status code extraction
 *
 * @par Frame Header Layout:
 * @code
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-------+-+-------------+-------------------------------+
 * |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
 * |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
 * |N|V|V|V|       |S|             |   (if payload len==126/127)   |
 * | |1|2|3|       |K|             |                               |
 * +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
 * @endcode
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "websocket.h"
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>

/**
 * @brief Parse WebSocket frame from raw data
 *
 * Parses the WebSocket frame header and validates structure.
 * Handles all three payload length encodings (7-bit, 16-bit, 64-bit)
 * and extracts masking key if present.
 *
 * @par Header Size Calculation:
 * - Base: 2 bytes (FIN/RSV/opcode + MASK/len7)
 * - +2 bytes if len7 == 126 (16-bit length)
 * - +8 bytes if len7 == 127 (64-bit length)
 * - +4 bytes if MASK bit set (masking key)
 *
 * @param[in]  data  Raw frame data buffer
 * @param[in]  len   Available data length
 * @param[out] frame Parsed frame structure
 *
 * @return Total frame size (header + payload) consumed, or:
 *         - 0 if need more data (incomplete frame)
 *         - Never returns negative; invalid frames return 0
 *
 * @note Close frames have status code extracted into frame->close_code
 */
int ws_parse_frame(const uint8_t *data, size_t len, ws_frame_t *frame) {
    if (!data || !frame || len < 2) {
        return 0;  /* Need more data */
    }

    memset(frame, 0, sizeof(*frame));

    /* First byte: FIN, RSV1-3, opcode */
    uint8_t byte0 = data[0];
    frame->fin  = (byte0 & 0x80) != 0;
    frame->rsv1 = (byte0 & 0x40) != 0;
    frame->rsv2 = (byte0 & 0x20) != 0;
    frame->rsv3 = (byte0 & 0x10) != 0;
    frame->opcode = (ws_opcode_t)(byte0 & 0x0F);

    /* Second byte: MASK, payload length */
    uint8_t byte1 = data[1];
    frame->masked = (byte1 & 0x80) != 0;
    uint8_t payload_len_7 = byte1 & 0x7F;

    size_t header_len = 2;
    uint64_t payload_len = 0;

    if (payload_len_7 <= 125) {
        /* Payload length is in the 7-bit field */
        payload_len = payload_len_7;
    } else if (payload_len_7 == 126) {
        /* Extended 16-bit payload length */
        if (len < 4) return 0;  /* Need more data */
        payload_len = ((uint64_t)data[2] << 8) | data[3];
        header_len = 4;
    } else if (payload_len_7 == 127) {
        /* Extended 64-bit payload length */
        if (len < 10) return 0;  /* Need more data */
        payload_len = ((uint64_t)data[2] << 56) |
                      ((uint64_t)data[3] << 48) |
                      ((uint64_t)data[4] << 40) |
                      ((uint64_t)data[5] << 32) |
                      ((uint64_t)data[6] << 24) |
                      ((uint64_t)data[7] << 16) |
                      ((uint64_t)data[8] << 8)  |
                      ((uint64_t)data[9]);
        header_len = 10;
    }

    /* Masking key (4 bytes if masked) */
    if (frame->masked) {
        if (len < header_len + 4) return 0;  /* Need more data */
        memcpy(frame->mask_key, data + header_len, 4);
        header_len += 4;
    }

    frame->header_len = header_len;
    frame->payload_len = payload_len;

    /* Check if we have the full frame */
    size_t total_len = header_len + payload_len;
    if (len < total_len) {
        return 0;  /* Need more data */
    }

    /* Point to payload */
    frame->payload = data + header_len;

    /* Parse close frame payload */
    if (frame->opcode == WS_OPCODE_CLOSE && payload_len >= 2) {
        frame->close_code = ((uint16_t)frame->payload[0] << 8) | frame->payload[1];
        if (payload_len > 2) {
            size_t reason_len = payload_len - 2;
            if (reason_len > sizeof(frame->close_reason) - 1) {
                reason_len = sizeof(frame->close_reason) - 1;
            }
            memcpy(frame->close_reason, frame->payload + 2, reason_len);
            frame->close_reason[reason_len] = '\0';
        }
    }

    return (int)total_len;
}

/**
 * @brief Unmask WebSocket payload data in-place
 *
 * Applies the XOR unmasking transformation required by RFC 6455.
 * Client-to-server frames must be masked; server-to-client frames
 * are not masked.
 *
 * @par XOR Algorithm:
 * For each byte at position i:
 * `unmasked[i] = masked[i] XOR mask_key[i % 4]`
 *
 * @param[in,out] payload Data to unmask (modified in-place)
 * @param[in]     len     Payload length in bytes
 * @param[in]     mask_key 4-byte masking key from frame header
 *
 * @note The operation is symmetric; can also be used for masking
 */
void ws_unmask_payload(uint8_t *payload, size_t len, const uint8_t *mask_key) {
    if (!payload || !mask_key) return;

    for (size_t i = 0; i < len; i++) {
        payload[i] ^= mask_key[i % 4];
    }
}

/**
 * @brief Get human-readable name for WebSocket opcode
 *
 * @param[in] opcode Frame opcode value
 *
 * @return Static string with opcode name:
 *         - "CONT" for continuation
 *         - "TEXT" for text data
 *         - "BIN" for binary data
 *         - "CLOSE" for close frame
 *         - "PING" for ping
 *         - "PONG" for pong
 *         - "UNKNOWN" for reserved/invalid
 */
const char *ws_opcode_name(ws_opcode_t opcode) {
    switch (opcode) {
        case WS_OPCODE_CONTINUATION: return "CONT";
        case WS_OPCODE_TEXT:         return "TEXT";
        case WS_OPCODE_BINARY:       return "BIN";
        case WS_OPCODE_CLOSE:        return "CLOSE";
        case WS_OPCODE_PING:         return "PING";
        case WS_OPCODE_PONG:         return "PONG";
        default:                     return "UNKNOWN";
    }
}

/**
 * @brief Get human-readable description for close status code
 *
 * Translates RFC 6455 Section 7.4.1 status codes to descriptions.
 *
 * @param[in] code Close status code (1000-1015 range)
 *
 * @return Static string with code description
 */
const char *ws_close_code_name(uint16_t code) {
    switch (code) {
        case WS_CLOSE_NORMAL:           return "Normal closure";
        case WS_CLOSE_GOING_AWAY:       return "Going away";
        case WS_CLOSE_PROTOCOL_ERROR:   return "Protocol error";
        case WS_CLOSE_UNSUPPORTED_DATA: return "Unsupported data";
        case WS_CLOSE_NO_STATUS:        return "No status";
        case WS_CLOSE_ABNORMAL:         return "Abnormal closure";
        case WS_CLOSE_INVALID_PAYLOAD:  return "Invalid payload";
        case WS_CLOSE_POLICY_VIOLATION: return "Policy violation";
        case WS_CLOSE_MESSAGE_TOO_BIG:  return "Message too big";
        case WS_CLOSE_EXTENSION_ERROR:  return "Extension error";
        case WS_CLOSE_INTERNAL_ERROR:   return "Internal error";
        default:                        return "Unknown";
    }
}

/**
 * @brief Validate potential WebSocket frame data
 *
 * Performs heuristic checks to determine if data looks like a
 * valid WebSocket frame. Used to detect WebSocket traffic after
 * HTTP upgrade.
 *
 * @par Validation Checks:
 * - Opcode in valid range (0x0-0x2 or 0x8-0xA)
 * - Control frames: payload <= 125 bytes, FIN must be set
 * - Sufficient data for extended length field if needed
 *
 * @param[in] data Data buffer to analyze
 * @param[in] len  Buffer length
 *
 * @return true if data appears to be valid WebSocket frame
 *
 * @note RSV bits are not validated (extensions may use them)
 */
bool ws_is_frame(const uint8_t *data, size_t len) {
    if (!data || len < 2) return false;

    uint8_t byte0 = data[0];
    uint8_t opcode = byte0 & 0x0F;

    /* Check for valid opcode */
    if (opcode > 0x0A) return false;
    if (opcode >= 0x03 && opcode <= 0x07) return false;  /* Reserved non-control */

    /* RSV bits should be 0 unless extensions negotiated */
    /* We'll be lenient here and not check RSV bits */

    uint8_t byte1 = data[1];
    uint8_t payload_len_7 = byte1 & 0x7F;

    /* Validate length encoding */
    if (payload_len_7 == 126 && len < 4) return false;
    if (payload_len_7 == 127 && len < 10) return false;

    /* Control frames (opcode >= 0x8) must have payload <= 125 bytes */
    if (opcode >= 0x08 && payload_len_7 > 125) return false;

    /* Control frames must not be fragmented (FIN must be 1) */
    if (opcode >= 0x08 && !(byte0 & 0x80)) return false;

    return true;
}

/**
 * @brief Check if HTTP request is WebSocket upgrade
 *
 * Validates presence of required WebSocket handshake headers
 * per RFC 6455 Section 4.1.
 *
 * @par Required Headers:
 * - Upgrade: websocket
 * - Connection: Upgrade (or includes "Upgrade")
 * - Sec-WebSocket-Key: (base64 nonce)
 * - Sec-WebSocket-Version: (protocol version)
 *
 * @param[in] headers      Array of header strings (name/value pairs)
 * @param[in] header_count Total count (headers array has header_count*2 elements)
 *
 * @return true if all required upgrade headers present
 *
 * @note Headers array format: [name0, value0, name1, value1, ...]
 */
bool ws_is_upgrade_request(const char *headers[], int header_count) {
    bool has_upgrade = false;
    bool has_connection_upgrade = false;
    bool has_ws_key = false;
    bool has_ws_version = false;

    for (int i = 0; i < header_count; i += 2) {
        const char *name = headers[i];
        const char *value = headers[i + 1];
        if (!name || !value) continue;

        if (strcasecmp(name, "Upgrade") == 0 && strcasecmp(value, "websocket") == 0) {
            has_upgrade = true;
        } else if (strcasecmp(name, "Connection") == 0 && strcasestr(value, "Upgrade") != NULL) {
            has_connection_upgrade = true;
        } else if (strcasecmp(name, "Sec-WebSocket-Key") == 0) {
            has_ws_key = true;
        } else if (strcasecmp(name, "Sec-WebSocket-Version") == 0) {
            has_ws_version = true;
        }
    }

    return has_upgrade && has_connection_upgrade && has_ws_key && has_ws_version;
}

/**
 * @brief Check if HTTP response accepts WebSocket upgrade
 *
 * Validates server response for successful WebSocket handshake
 * per RFC 6455 Section 4.2.2.
 *
 * @par Required Conditions:
 * - Status code: 101 (Switching Protocols)
 * - Upgrade: websocket
 * - Connection: Upgrade
 * - Sec-WebSocket-Accept: (computed hash)
 *
 * @param[in] status_code  HTTP response status code
 * @param[in] headers      Array of header strings (name/value pairs)
 * @param[in] header_count Total count (headers array has header_count*2 elements)
 *
 * @return true if response confirms WebSocket upgrade
 */
bool ws_is_upgrade_response(int status_code, const char *headers[], int header_count) {
    if (status_code != 101) return false;

    bool has_upgrade = false;
    bool has_connection_upgrade = false;
    bool has_ws_accept = false;

    for (int i = 0; i < header_count; i += 2) {
        const char *name = headers[i];
        const char *value = headers[i + 1];
        if (!name || !value) continue;

        if (strcasecmp(name, "Upgrade") == 0 && strcasecmp(value, "websocket") == 0) {
            has_upgrade = true;
        } else if (strcasecmp(name, "Connection") == 0 && strcasestr(value, "Upgrade") != NULL) {
            has_connection_upgrade = true;
        } else if (strcasecmp(name, "Sec-WebSocket-Accept") == 0) {
            has_ws_accept = true;
        }
    }

    return has_upgrade && has_connection_upgrade && has_ws_accept;
}
