/**
 * @file http1.h
 * @brief HTTP/1.1 protocol parser using llhttp
 *
 * @details This module provides HTTP/1.1 parsing capabilities using the
 * llhttp library (Node.js HTTP parser). It handles:
 *
 * - **Request parsing**: Method, path, headers
 * - **Response parsing**: Status code, headers
 * - **Body handling**: Content-Length and chunked transfer encoding
 * - **Auto-detection**: Distinguishes requests from responses
 *
 * @par Architecture:
 * @code
 * SSL data → http1_is_request() / http1_is_response()
 *               │
 *               ▼
 *         http1_parse()
 *               │
 *               ├── llhttp callbacks → headers
 *               └── body accumulation → optional body buffer
 * @endcode
 *
 * @par llhttp Integration:
 * The parser uses llhttp in HTTP_BOTH mode which automatically detects
 * whether data is a request or response. Callbacks populate the
 * http_message_t structure with parsed data.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef HTTP1_H
#define HTTP1_H

#include "../include/spliff.h"
#include <stdbool.h>

/**
 * @defgroup http1 HTTP/1.1 Parser
 * @brief llhttp-based HTTP/1.1 protocol parsing
 * @{
 */

/**
 * @brief Initialize HTTP/1.1 parser system
 *
 * Prepares the llhttp-based parser for use. Must be called
 * before using other http1_* functions.
 *
 * @return 0 on success, negative on error
 *
 * @see http1_cleanup()
 */
int http1_init(void);

/**
 * @brief Get the global llhttp settings with callbacks
 *
 * Returns a pointer to the shared llhttp_settings_t structure
 * that contains all configured callbacks. This allows flow-based
 * HTTP/1 parsers to use the same callback functions.
 *
 * @note http1_init() must be called first
 *
 * @return Pointer to settings, or NULL if not initialized
 */
struct llhttp_settings_s *http1_get_settings(void);

/**
 * @brief Clean up HTTP/1.1 parser resources
 *
 * Releases any resources allocated by the parser system.
 * Call at program shutdown.
 *
 * @see http1_init()
 */
void http1_cleanup(void);

/**
 * @brief Check if data looks like HTTP/1.1 request
 *
 * Performs a quick heuristic check for HTTP request patterns
 * (e.g., "GET ", "POST ", "HTTP/1.").
 *
 * @param[in] data Data buffer to analyze
 * @param[in] len  Length of data buffer
 *
 * @return true if data appears to be an HTTP request
 *
 * @note This is a fast heuristic, not a full parse
 */
bool http1_is_request(const uint8_t *data, size_t len);

/**
 * @brief Check if data looks like HTTP/1.1 response
 *
 * Performs a quick heuristic check for HTTP response patterns
 * (e.g., "HTTP/1.1 200").
 *
 * @param[in] data Data buffer to analyze
 * @param[in] len  Length of data buffer
 *
 * @return true if data appears to be an HTTP response
 *
 * @note This is a fast heuristic, not a full parse
 */
bool http1_is_response(const uint8_t *data, size_t len);

/**
 * @brief Parse HTTP/1.1 message using llhttp
 *
 * Full HTTP/1.1 parser that extracts headers and optionally
 * accumulates body data. Uses HTTP_BOTH mode for automatic
 * request/response detection.
 *
 * @par Features:
 * - Automatic request vs response detection
 * - Chunked transfer encoding decoding
 * - Header extraction with name/value pairs
 * - Optional body accumulation
 *
 * @param[in]  data          Input data buffer
 * @param[in]  len           Length of input data
 * @param[out] msg           Output message structure (zeroed before parsing)
 * @param[out] body_buf      Optional buffer for body data (NULL to skip body)
 * @param[in]  body_buf_size Size of body buffer
 * @param[out] body_len_out  Output: actual body length written (NULL to ignore)
 *
 * @return Number of bytes successfully parsed, or -1 on error
 *
 * @note The msg structure is zeroed before parsing begins
 * @note Partial parses return bytes consumed; caller should buffer remaining
 */
int http1_parse(const uint8_t *data, size_t len, http_message_t *msg,
                uint8_t *body_buf, size_t body_buf_size, size_t *body_len_out);

/**
 * @defgroup http1_flow Flow-Based HTTP/1 Parsing
 * @brief Persistent parser for fragmented TCP streams
 * @{
 */

/* Forward declarations */
struct flow_context;
struct ssl_data_event;

/**
 * @brief Get flow-based llhttp settings
 *
 * Returns settings configured for flow_transaction_t population.
 * These settings use persistent state in flow_ctx->parser.h1.
 *
 * @return Pointer to flow-based llhttp settings
 */
struct llhttp_settings_s *http1_get_flow_settings(void);

/**
 * @brief Parse HTTP/1 data using persistent flow-based parser
 *
 * Uses the parser stored in flow_ctx->parser.h1 to maintain state
 * across TCP segments. Handles:
 * - Headers split across multiple SSL_read calls
 * - Chunked transfer encoding (automatic via llhttp)
 * - Partial body accumulation
 *
 * @param flow_ctx  Flow context with proto == FLOW_PROTO_HTTP1
 * @param data      HTTP data to parse
 * @param len       Data length
 * @param event     SSL event being processed (for timestamps)
 *
 * @return Number of bytes parsed, or -1 on error
 *
 * @note Parser is auto-initialized on first call using http1_get_flow_settings()
 * @note Message is displayed when headers complete (before body finishes)
 */
int http1_parse_flow(struct flow_context *flow_ctx, const uint8_t *data, size_t len,
                     const struct ssl_data_event *event);

/**
 * @brief Unified HTTP/1 event processing entry point
 *
 * Single entry point for all HTTP/1 processing from main.c.
 * Handles detection, parser initialization, and parsing.
 * Keeps all HTTP/1 logic in http1.c.
 *
 * @param[in] data       Raw data buffer
 * @param[in] len        Data length
 * @param[in] event      Worker event with full context
 * @param[in] worker     Worker context for output
 *
 * @return true if data was processed as HTTP/1, false to try other protocols
 */
struct worker_event;
struct worker_ctx;
bool http1_try_process_event(const uint8_t *data, size_t len,
                             struct worker_event *event,
                             struct worker_ctx *worker);

/** @} */ /* End of http1_flow group */

/** @} */ /* End of http1 group */

#endif /* HTTP1_H */
