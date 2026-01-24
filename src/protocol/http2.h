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
 *         http2_process_frame()
 *               │
 *               ├── HEADERS → HPACK decode → h2_stream_t.headers[]
 *               ├── DATA → h2_stream_t.body_buf accumulation
 *               ├── RST_STREAM → Stream cleanup
 *               └── GOAWAY → Session cleanup
 * @endcode
 *
 * @par Session Management:
 * Sessions are keyed by (PID, ssl_ctx) tuple to handle multiple connections
 * per process. Each session maintains independent HPACK state.
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
 * @brief Per-stream state tracking structure
 *
 * Maintains complete state for a single HTTP/2 stream including
 * request/response info, headers, and accumulated body data.
 *
 * @note Streams are uniquely identified by (pid, ssl_ctx, stream_id) tuple
 */
typedef struct {
    /**
     * @name Stream Identification
     * @{
     */
    uint32_t pid;           /**< Process ID owning the connection */
    uint64_t ssl_ctx;       /**< SSL context pointer for connection disambiguation */
    int32_t stream_id;      /**< HTTP/2 stream identifier (odd=client, even=server) */
    bool active;            /**< True if stream slot is in use */
    /** @} */

    /**
     * @name State Machine
     * @{
     */
    h2_stream_state_t state; /**< Current stream state */
    /** @} */

    /**
     * @name Request Information
     * Populated from HEADERS frame pseudo-headers (:method, :path, etc.)
     * @{
     */
    char method[MAX_METHOD_LEN];      /**< HTTP method (GET, POST, etc.) */
    char path[MAX_PATH_LEN];          /**< Request path */
    char authority[MAX_HEADER_VALUE]; /**< :authority pseudo-header (host) */
    char scheme[16];                  /**< :scheme (http or https) */
    uint64_t request_time_ns;         /**< Request timestamp (nanoseconds) */
    bool request_headers_done;        /**< Request headers fully received */
    bool request_complete;            /**< Request body complete (END_STREAM seen) */
    /** @} */

    /**
     * @name Response Information
     * Populated from response HEADERS frame
     * @{
     */
    int status_code;                  /**< HTTP status code (200, 404, etc.) */
    char content_type[256];           /**< Content-Type header value */
    char content_encoding[64];        /**< Content-Encoding header value */
    size_t content_length;            /**< Content-Length (if specified) */
    uint64_t response_time_ns;        /**< Response timestamp (nanoseconds) */
    bool response_headers_done;       /**< Response headers fully received */
    bool response_complete;           /**< Response body complete (END_STREAM seen) */
    bool hpack_decode_failed;         /**< HPACK decode failed (mid-stream join) */
    /** @} */

    /**
     * @name Header Storage
     * @{
     */
    http_header_t headers[MAX_HEADERS]; /**< Parsed header name/value pairs */
    int header_count;                   /**< Number of headers stored */
    bool headers_displayed;             /**< Headers already output to console */
    /** @} */

    /**
     * @name Body Accumulation
     * @{
     */
    uint8_t *body_buf;      /**< Dynamically allocated body buffer */
    size_t body_buf_size;   /**< Allocated buffer capacity */
    size_t body_len;        /**< Current body length */
    /** @} */

    /**
     * @name Display Metadata
     * @{
     */
    uint64_t delta_ns;              /**< Latency (response_time - request_time) */
    char comm[TASK_COMM_LEN];       /**< Process command name */
    /** @} */
} h2_stream_t;

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
 * @brief Process HTTP/2 data from BPF event
 *
 * Main entry point for HTTP/2 frame processing. Feeds data into
 * the nghttp2 session for the connection identified by the event's
 * (pid, ssl_ctx) tuple.
 *
 * @param[in] data  Raw HTTP/2 frame data
 * @param[in] len   Length of frame data
 * @param[in] event BPF event with connection context (pid, ssl_ctx, etc.)
 *
 * @note Creates session if needed; handles mid-stream joins
 */
void http2_process_frame(const uint8_t *data, int len, const ssl_data_event_t *event);

/* Forward declaration for flow_context_t */
struct flow_context;

/**
 * @brief Process HTTP/2 data with flow context (Phase 3.6)
 *
 * Flow-aware version that uses flow_context_t for stream storage.
 * Populates both the legacy global pools AND flow_transaction_t
 * for gradual migration.
 *
 * @param[in] data     Raw HTTP/2 frame data
 * @param[in] len      Length of frame data
 * @param[in] event    BPF event with connection context
 * @param[in] flow_ctx Flow context with embedded stream storage (may be NULL)
 *
 * @note When flow_ctx is NULL, behaves identically to http2_process_frame()
 */
void http2_process_frame_flow(const uint8_t *data, int len,
                              const ssl_data_event_t *event,
                              struct flow_context *flow_ctx);

/**
 * @brief Check if connection has active HTTP/2 session
 *
 * @param[in] pid     Process ID
 * @param[in] ssl_ctx SSL context pointer
 *
 * @return true if an HTTP/2 session exists for this connection
 */
bool http2_has_session(uint32_t pid, uint64_t ssl_ctx);

/**
 * @brief Set ALPN protocol for a connection
 *
 * Records the negotiated ALPN protocol (e.g., "h2", "http/1.1")
 * for display purposes.
 *
 * @param[in] pid     Process ID
 * @param[in] ssl_ctx SSL context pointer
 * @param[in] alpn    Protocol string (copied internally)
 *
 * @see http2_get_alpn()
 */
void http2_set_alpn(uint32_t pid, uint64_t ssl_ctx, const char *alpn);

/**
 * @brief Set XDP flow correlation info for an HTTP/2 connection
 *
 * Stores network-layer metadata from XDP packet capture, enabling
 * "Golden Thread" double-view correlation between network and
 * application layers.
 *
 * @param[in] pid       Process ID
 * @param[in] ssl_ctx   SSL context pointer
 * @param[in] src_ip    Source IP address (network byte order)
 * @param[in] dst_ip    Destination IP address (network byte order)
 * @param[in] src_port  Source port (network byte order)
 * @param[in] dst_port  Destination port (network byte order)
 * @param[in] ip_ver    IP version (4 or 6)
 * @param[in] direction Flow direction (0=outbound, 1=inbound)
 * @param[in] category  Traffic category (1=TLS, 2=QUIC, 3=HTTP, 4=H2)
 * @param[in] ifname    Interface name (may be NULL)
 */
void http2_set_flow_info(uint32_t pid, uint64_t ssl_ctx,
                         uint32_t src_ip, uint32_t dst_ip,
                         uint16_t src_port, uint16_t dst_port,
                         uint8_t ip_ver, uint8_t direction,
                         uint8_t category, const char *ifname);

/**
 * @brief Get ALPN protocol for a connection
 *
 * @param[in] pid     Process ID
 * @param[in] ssl_ctx SSL context pointer
 *
 * @return ALPN protocol string, or empty string if not set
 */
const char *http2_get_alpn(uint32_t pid, uint64_t ssl_ctx);

/**
 * @brief Get or create stream state structure
 *
 * Looks up an existing stream or optionally creates a new one.
 *
 * @param[in] pid       Process ID
 * @param[in] ssl_ctx   SSL context pointer
 * @param[in] stream_id HTTP/2 stream identifier
 * @param[in] create    If true, create stream if not found
 *
 * @return Pointer to stream structure, or NULL if not found/create failed
 *
 * @note Stream IDs: odd numbers are client-initiated, even are server push
 */
h2_stream_t *http2_get_stream(uint32_t pid, uint64_t ssl_ctx, int32_t stream_id, bool create);

/**
 * @brief Free stream resources
 *
 * Releases body buffer and marks stream slot as available.
 *
 * @param[in] pid       Process ID
 * @param[in] ssl_ctx   SSL context pointer
 * @param[in] stream_id HTTP/2 stream identifier
 */
void http2_free_stream(uint32_t pid, uint64_t ssl_ctx, int32_t stream_id);

/**
 * @brief Cleanup all HTTP/2 resources for a process
 *
 * Called when a process exits to release all sessions and
 * streams associated with that PID.
 *
 * @param[in] pid Process ID to clean up
 */
void http2_cleanup_pid(uint32_t pid);

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

/** @} */ /* End of http2 group */

#endif /* HTTP2_H */
