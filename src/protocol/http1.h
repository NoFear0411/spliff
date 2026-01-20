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
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
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
 *
 * @see http1_parse_headers() for header-only parsing
 */
int http1_parse(const uint8_t *data, size_t len, http_message_t *msg,
                uint8_t *body_buf, size_t body_buf_size, size_t *body_len_out);

/**
 * @brief Parse HTTP/1.1 headers only (compatibility wrapper)
 *
 * Simplified API for parsing only the header section of an HTTP message.
 * Body data is not accumulated.
 *
 * @param[in]  data Data buffer containing HTTP message
 * @param[in]  len  Length of data buffer
 * @param[out] msg  Output message structure
 * @param[in]  dir  Direction hint (ignored - llhttp auto-detects)
 *
 * @note The direction parameter is ignored; llhttp automatically
 *       detects whether data is a request or response
 *
 * @deprecated Use http1_parse() for new code
 */
void http1_parse_headers(const uint8_t *data, size_t len, http_message_t *msg, direction_t dir);

/**
 * @brief Find the body start position in HTTP/1.1 message
 *
 * Locates the position after the header terminator (\\r\\n\\r\\n)
 * where the body content begins.
 *
 * @param[in] data Data buffer containing HTTP message
 * @param[in] len  Length of data buffer
 *
 * @return Byte offset of body start, or -1 if not found
 *
 * @note With llhttp, prefer http1_parse() which handles body via callbacks
 *
 * @par Example:
 * @code
 * int body_start = http1_find_body_start(data, len);
 * if (body_start > 0) {
 *     uint8_t *body = data + body_start;
 *     size_t body_len = len - body_start;
 * }
 * @endcode
 */
int http1_find_body_start(const uint8_t *data, size_t len);

/**
 * @brief Decode chunked transfer encoding
 *
 * Decodes HTTP/1.1 chunked transfer encoding, reassembling
 * the original content from chunk-encoded data.
 *
 * @par Chunked Format:
 * @code
 * <size-hex>\r\n
 * <chunk-data>\r\n
 * ...
 * 0\r\n
 * \r\n
 * @endcode
 *
 * @param[in]  in       Input buffer with chunked data
 * @param[in]  in_len   Length of input data
 * @param[out] out      Output buffer for decoded data
 * @param[in]  out_size Size of output buffer
 *
 * @return Number of bytes written to out, or -1 on error
 *
 * @note llhttp handles this automatically in http1_parse();
 *       this function is provided for direct data processing
 */
int http1_decode_chunked(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_size);

/** @} */ /* End of http1 group */

#endif /* HTTP1_H */
