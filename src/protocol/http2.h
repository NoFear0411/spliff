/**
 * @file http2.h
 * @brief HTTP/2 protocol parser using nghttp2
 *
 * @details This module provides HTTP/2 parsing capabilities using the
 * nghttp2 library. It handles the binary framing layer, HPACK header
 * compression, and stream multiplexing.
 *
 * @par Key Features:
 * - **HPACK decompression**: Decodes compressed headers
 * - **Stream multiplexing**: Tracks multiple concurrent streams per connection
 * - **Mid-stream join recovery**: Handles connections started before capture
 * - **Body accumulation**: Buffers DATA frames per stream
 *
 * @par Architecture:
 * @code
 * SSL data → http2_is_preface() → Connection setup
 *               │
 *               ▼
 *         http2_process_frame_flow()
 *               │
 *               ├── HEADERS → HPACK decode → flow_transaction_t
 *               ├── DATA → flow body accumulation
 *               ├── RST_STREAM → Stream cleanup
 *               └── GOAWAY → Session cleanup
 * @endcode
 *
 * @par Session Management:
 * Sessions are managed per flow_context_t, with streams stored in
 * flow_transaction_t structures. Each flow maintains independent HPACK state.
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef HTTP2_H
#define HTTP2_H

#include "../include/spliff.h"
#include "../bpf/probe_handler.h"
#include <stdbool.h>
#include <stdint.h>

/* Forward declaration for flow-based processing */
struct flow_context;

/**
 * @defgroup http2 HTTP/2 Parser
 * @brief nghttp2-based HTTP/2 protocol parsing
 * @{
 */

/**
 * @defgroup h2_frame_types HTTP/2 Frame Types
 * @brief Frame type constants (RFC 7540 Section 6)
 * @{
 */
#define H2_FRAME_DATA          0x0  /**< DATA frame (stream payload) */
#define H2_FRAME_HEADERS       0x1  /**< HEADERS frame (request/response headers) */
#define H2_FRAME_PRIORITY      0x2  /**< PRIORITY frame (stream priority) */
#define H2_FRAME_RST_STREAM    0x3  /**< RST_STREAM frame (stream termination) */
#define H2_FRAME_SETTINGS      0x4  /**< SETTINGS frame (connection parameters) */
#define H2_FRAME_PUSH_PROMISE  0x5  /**< PUSH_PROMISE frame (server push) */
#define H2_FRAME_PING          0x6  /**< PING frame (connection liveness) */
#define H2_FRAME_GOAWAY        0x7  /**< GOAWAY frame (connection shutdown) */
#define H2_FRAME_WINDOW_UPDATE 0x8  /**< WINDOW_UPDATE frame (flow control) */
#define H2_FRAME_CONTINUATION  0x9  /**< CONTINUATION frame (header continuation) */
/** @} */

/**
 * @defgroup h2_limits HTTP/2 Configuration Limits
 * @brief Buffer sizes and tracking limits
 * @{
 */
#define MAX_H2_SESSIONS     64              /**< Maximum concurrent HTTP/2 sessions */
#define MAX_H2_STREAMS      512             /**< Maximum streams tracked globally */
#define H2_BODY_BUFFER_SIZE (256 * 1024)    /**< Body buffer per stream (256KB) */
/** @} */

/**
 * @defgroup h2_validation Frame Validation Limits
 * @brief Sanity checks for mid-stream join recovery
 *
 * When joining a connection mid-stream (after HPACK context is
 * established), these limits help detect invalid frame data.
 * @{
 */
#define H2_MAX_SANE_FRAME_LEN   65536       /**< Maximum sane frame length (64KB) */
#define H2_MAX_VALID_FRAME_TYPE 9           /**< Highest valid frame type (CONTINUATION) */
#define H2_MAX_SANE_STREAM_ID   0x00FFFFFF  /**< Maximum sane stream ID (~16M) */
/** @} */

/**
 * @brief HTTP/2 stream state machine states
 *
 * Tracks the lifecycle of an HTTP/2 stream according to RFC 7540.
 * Streams progress through states based on frame exchange.
 *
 * @par State Transitions:
 * @code
 *                        +--------+
 *                  PP    |        |    PP
 *               +------->| idle   |<-------+
 *               |        |        |        |
 *               |        +--------+        |
 *               |            |             |
 *               |    H      |H            |    H
 *               |   + ES   v + ES         |   + ES
 *               |        +--------+        |
 *               |        | open   |        |
 *               |        +--------+        |
 *               |   ES    |    |   ES     |
 *               |   +-----v    v-----+    |
 *               |       |        |        |
 *               |  +----+        +----+   |
 *               |  |                  |   |
 *               v  v                  v   v
 *            +-------+            +-------+
 *            | half  |            | half  |
 *            |closed |            |closed |
 *            |(remote|            |(local)|
 *            +-------+            +-------+
 *                |                    |
 *                |ES / RST            |ES / RST
 *                v                    v
 *                     +--------+
 *                     | closed |
 *                     +--------+
 * @endcode
 */
typedef enum {
    H2_STREAM_IDLE = 0,           /**< Initial state before HEADERS */
    H2_STREAM_OPEN,               /**< Active bidirectional stream */
    H2_STREAM_HALF_CLOSED_LOCAL,  /**< Local side closed (sent END_STREAM) */
    H2_STREAM_HALF_CLOSED_REMOTE, /**< Remote side closed (received END_STREAM) */
    H2_STREAM_CLOSED              /**< Stream fully closed */
} h2_stream_state_t;

/**
 * @brief Initialize HTTP/2 parser system
 *
 * Initializes nghttp2 session infrastructure and allocates
 * session/stream tracking structures. Must be called before
 * processing any HTTP/2 traffic.
 *
 * @return 0 on success, negative on error
 *
 * @see http2_cleanup()
 */
int http2_init(void);

/**
 * @brief Get the global nghttp2 session callbacks
 *
 * Returns a pointer to the shared nghttp2 callbacks structure,
 * allowing flow-based HTTP/2 sessions to use the same callback
 * functions as the global session pool.
 *
 * @note http2_init() must be called first
 *
 * @return Pointer to callbacks, or NULL if not initialized
 */
struct nghttp2_session_callbacks *http2_get_callbacks(void);

/**
 * @brief Create callback context for flow-based HTTP/2 processing
 *
 * Allocates and initializes an h2_callback_ctx_t for use with flow_ctx's
 * nghttp2 session. The context is set up for server-side (request) parsing.
 *
 * @param[in] flow_ctx Flow context that will own this callback context
 *
 * @return Opaque callback context pointer, or NULL on allocation failure
 *
 * @note Store returned pointer in flow_ctx->parser.h2.callback_ctx
 * @note Pass returned pointer to flow_h2_session_init() as user_data
 * @note Free with http2_free_callback_ctx() when flow is released
 */
void *http2_create_callback_ctx(struct flow_context *flow_ctx);

/**
 * @brief Free callback context created by http2_create_callback_ctx()
 *
 * @param[in] callback_ctx Opaque callback context to free (NULL is safe)
 */
void http2_free_callback_ctx(void *callback_ctx);

/**
 * @brief Set event in callback context for current processing call
 *
 * Updates the event pointer in a flow-based callback context.
 * Must be called before feeding data to the nghttp2 session.
 *
 * @param[in] callback_ctx Opaque callback context
 * @param[in] event        Current BPF event (NULL to clear)
 */
void http2_set_callback_event(void *callback_ctx, const ssl_data_event_t *event);

/**
 * @brief Clean up HTTP/2 parser resources
 *
 * Frees all sessions, streams, and nghttp2 resources.
 * Call at program shutdown.
 *
 * @see http2_init()
 */
void http2_cleanup(void);

/**
 * @brief Get human-readable frame type name
 *
 * Converts frame type constant to display string.
 *
 * @param[in] type Frame type (H2_FRAME_*)
 *
 * @return Static string with frame name (e.g., "HEADERS", "DATA")
 */
const char *http2_frame_name(int type);

/**
 * @brief Check if data looks like HTTP/2 connection preface
 *
 * Checks for the HTTP/2 connection preface:
 * "PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n" (24 bytes)
 *
 * @param[in] data Data buffer to analyze
 * @param[in] len  Length of data buffer
 *
 * @return true if data matches HTTP/2 preface
 */
bool http2_is_preface(const uint8_t *data, size_t len);

/**
 * @brief Process HTTP/2 data with flow context
 *
 * Main entry point for HTTP/2 frame processing. Feeds data into
 * the nghttp2 session using flow_context_t for stream storage.
 *
 * @param[in] data     Raw HTTP/2 frame data
 * @param[in] len      Length of frame data
 * @param[in] event    BPF event with connection context
 * @param[in] flow_ctx Flow context with embedded stream storage
 */
void http2_process_frame_flow(const uint8_t *data, int len,
                              const ssl_data_event_t *event,
                              struct flow_context *flow_ctx);

/**
 * @brief Validate HTTP/2 frame header
 *
 * Performs sanity checks on a 9-byte frame header to detect
 * invalid or corrupted data. Used for mid-stream join recovery.
 *
 * @par Validation Checks:
 * - Buffer has at least 9 bytes (H2 frame header size)
 * - Frame length <= H2_MAX_SANE_FRAME_LEN
 * - Frame type <= H2_MAX_VALID_FRAME_TYPE
 * - Stream ID <= H2_MAX_SANE_STREAM_ID
 *
 * @param[in] data Buffer containing frame header data
 * @param[in] len  Length of data buffer (must be >= 9)
 *
 * @return true if frame header appears valid, false if invalid or buffer too small
 */
bool http2_is_valid_frame_header(const uint8_t *data, size_t len);

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
struct worker_event;
struct worker_ctx;
bool http2_try_process_event(const uint8_t *data, size_t len,
                             struct worker_event *event,
                             struct worker_ctx *worker);

/** @} */ /* End of http2 group */

#endif /* HTTP2_H */
