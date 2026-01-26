/**
 * @file detector.h
 * @brief Vectorscan-powered protocol detection for spliff
 *
 * @copyright Copyright (C) 2025-2026 spliff authors
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * This module provides O(n) linear-time protocol detection using vectorscan's
 * NFA-based pattern matching engine. It detects HTTP/1.x, HTTP/2, TLS, and
 * WebSocket protocols from packet payloads.
 *
 * @par Architecture
 * The detector compiles all patterns into a single NFA database at startup.
 * Each worker thread gets its own scratch space (via thread-local storage)
 * for lock-free, concurrent scanning.
 *
 * @par Fallback
 * When vectorscan/hyperscan is unavailable, the module falls back to manual
 * detection using http1_is_request(), http2_is_preface(), etc.
 *
 * @see docs/PLAN-unified-v095.md for design documentation
 */

#ifndef PROTOCOL_DETECTOR_H
#define PROTOCOL_DETECTOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "../correlation/flow_context.h"

/**
 * @defgroup proto_detector Protocol Detector
 * @brief Vectorscan-powered protocol detection
 * @{
 */

/**
 * @brief Protocol detection result
 *
 * Detected via vectorscan pattern matching for O(n) linear time.
 * These are more granular than flow_proto_t to distinguish request/response.
 */
typedef enum {
    PROTO_DETECT_UNKNOWN    = 0,  /**< Unknown protocol */
    PROTO_DETECT_HTTP1_REQ  = 1,  /**< HTTP/1.x request (GET, POST, etc.) */
    PROTO_DETECT_HTTP1_RSP  = 2,  /**< HTTP/1.x response (HTTP/1.x 200) */
    PROTO_DETECT_HTTP2      = 3,  /**< HTTP/2 preface or frame */
    PROTO_DETECT_TLS        = 4,  /**< TLS record (encrypted) */
    PROTO_DETECT_WEBSOCKET  = 5,  /**< WebSocket frame */
} proto_detect_result_t;

/**
 * @brief Initialize protocol detector
 *
 * Compiles vectorscan patterns into a database. Call once at startup.
 * Thread-safe after initialization (database is read-only).
 *
 * @return 0 on success, -1 on failure
 *
 * @note Must be called before any worker threads start
 * @note Prints error message to stderr on failure
 */
int proto_detector_init(void);

/**
 * @brief Cleanup protocol detector
 *
 * Frees vectorscan database. Call once at shutdown.
 *
 * @note Also calls proto_detector_thread_cleanup() for main thread
 * @note Safe to call even if init was never called
 */
void proto_detector_cleanup(void);

/**
 * @brief Cleanup thread-local scratch space
 *
 * Frees the calling thread's vectorscan scratch space. Worker threads
 * must call this before exiting to prevent memory leaks.
 *
 * @note Safe to call multiple times or if scratch was never allocated
 * @note Called automatically by proto_detector_cleanup() for main thread
 */
void proto_detector_thread_cleanup(void);

/**
 * @brief Detect protocol from packet data
 *
 * Uses vectorscan for O(n) linear-time pattern matching.
 * Automatically allocates thread-local scratch on first call per thread.
 *
 * @param[in] data  Packet payload (must not be NULL if len > 0)
 * @param[in] len   Payload length
 *
 * @return Detection result
 *
 * @note Thread-safe (uses per-thread scratch via TLS)
 * @note Returns PROTO_DETECT_UNKNOWN if data is NULL or len is 0
 *
 * @par Example
 * @code
 *   proto_detect_result_t result = proto_detect(payload, payload_len);
 *   if (result == PROTO_DETECT_HTTP1_REQ) {
 *       // Handle HTTP/1.x request
 *   }
 * @endcode
 */
[[nodiscard]]
proto_detect_result_t proto_detect(const uint8_t *restrict data, size_t len);

/**
 * @brief Detect and initialize flow protocol
 *
 * Combines detection with flow_context initialization. If the flow already
 * has a known protocol, returns it immediately without re-scanning.
 *
 * @param[in,out] ctx   Flow context (may be NULL)
 * @param[in]     data  Packet payload
 * @param[in]     len   Payload length
 *
 * @return Detected flow protocol type
 *
 * @note Does not modify ctx->alpn (that's for negotiated protocol only)
 * @note Thread-safe
 *
 * @par Example
 * @code
 *   if (flow_ctx->proto == FLOW_PROTO_UNKNOWN) {
 *       proto_detect_and_init(flow_ctx, data, len);
 *   }
 * @endcode
 */
[[nodiscard]]
flow_proto_t proto_detect_and_init(flow_context_t *restrict ctx,
                                    const uint8_t *restrict data,
                                    size_t len);

/**
 * @brief Get detection engine name
 *
 * Returns the name of the pattern matching engine being used.
 *
 * @return "vectorscan", "hyperscan", "pcre2", or "manual"
 */
[[nodiscard]]
const char *proto_detector_engine_name(void);

/**
 * @brief Check if vectorscan/hyperscan is available
 *
 * @return true if using vectorscan or hyperscan, false if fallback
 */
[[nodiscard]]
bool proto_detector_is_nfa_engine(void);

/** @} */ /* end proto_detector group */

#endif /* PROTOCOL_DETECTOR_H */
