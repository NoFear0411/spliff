/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * sslsniff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 sslsniff authors
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

#ifndef HTTP1_H
#define HTTP1_H

#include "../include/sslsniff.h"
#include <stdbool.h>

/* Initialize HTTP/1.1 parser (llhttp-based) */
int http1_init(void);

/* Cleanup */
void http1_cleanup(void);

/* Check if data looks like HTTP/1.1 request */
bool http1_is_request(const uint8_t *data, size_t len);

/* Check if data looks like HTTP/1.1 response */
bool http1_is_response(const uint8_t *data, size_t len);

/*
 * Parse HTTP/1.1 message using llhttp (preferred API)
 *
 * Parses headers and optionally accumulates body data.
 * Uses HTTP_BOTH mode to auto-detect request vs response.
 * Chunked transfer encoding is automatically decoded.
 *
 * @param data         Input data buffer
 * @param len          Length of input data
 * @param msg          Output message structure (will be zeroed)
 * @param body_buf     Optional buffer for body data (NULL to skip body)
 * @param body_buf_size Size of body buffer
 * @param body_len_out  Output: actual body length written (NULL to ignore)
 *
 * @return Number of bytes parsed, or -1 on error
 */
int http1_parse(const uint8_t *data, size_t len, http_message_t *msg,
                uint8_t *body_buf, size_t body_buf_size, size_t *body_len_out);

/* Parse HTTP/1.1 headers only (compatibility wrapper)
 * Note: direction parameter is ignored - llhttp auto-detects
 */
void http1_parse_headers(const uint8_t *data, size_t len, http_message_t *msg, direction_t dir);

/* Find the body start position in HTTP/1.1 message (after \r\n\r\n)
 * Note: With llhttp, prefer using http1_parse() which handles body via callback
 */
int http1_find_body_start(const uint8_t *data, size_t len);

/* Decode chunked transfer encoding
 * Note: llhttp handles this automatically in http1_parse().
 * Kept for compatibility with code that processes raw body data.
 *
 * @return Number of bytes written to out, or -1 on error
 */
int http1_decode_chunked(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_size);

#endif /* HTTP1_H */
