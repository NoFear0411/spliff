/**
 * @file decompressor.h
 * @brief HTTP body decompression for gzip, deflate, zstd, and brotli
 *
 * @details This module handles decompression of HTTP response bodies
 * based on the Content-Encoding header. Supports:
 *
 * - **gzip**: Most common web compression (RFC 1952)
 * - **deflate**: Raw deflate compression (RFC 1951)
 * - **zstd**: Zstandard compression (RFC 8878) - optional at compile time
 * - **br** (Brotli): Google's compression algorithm - optional at compile time
 *
 * The module automatically detects compression type from both Content-Encoding
 * headers and data magic bytes, providing graceful fallback when headers are
 * missing or incorrect.
 *
 * @par Compile-time Dependencies:
 * - zlib: Required for gzip/deflate (always available)
 * - libzstd: Optional for zstd support (HAVE_ZSTD)
 * - libbrotli: Optional for brotli support (HAVE_BROTLI)
 *
 * @par Usage Example:
 * @code
 * uint8_t decomp_buf[MAX_BODY_BUFFER];
 * int decomp_len = decompress_body(
 *     response_data, response_len,
 *     "gzip",  // Content-Encoding header
 *     decomp_buf, sizeof(decomp_buf)
 * );
 *
 * if (decomp_len > 0) {
 *     // Use decompressed data
 *     process_body(decomp_buf, decomp_len);
 * } else {
 *     // Decompression failed or not needed
 *     process_body(response_data, response_len);
 * }
 * @endcode
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef DECOMPRESSOR_H
#define DECOMPRESSOR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * @defgroup decompressor HTTP Body Decompression
 * @brief Content-Encoding based decompression
 * @{
 */

/**
 * @brief Supported compression types
 *
 * Enumeration of compression algorithms that can be detected and decoded.
 */
typedef enum {
    COMPRESS_NONE = 0,  /**< No compression / unknown */
    COMPRESS_GZIP,      /**< gzip (RFC 1952) - deflate with gzip wrapper */
    COMPRESS_DEFLATE,   /**< deflate (RFC 1951) - raw deflate stream */
    COMPRESS_ZSTD,      /**< Zstandard (RFC 8878) - requires HAVE_ZSTD */
    COMPRESS_BROTLI     /**< Brotli (RFC 7932) - requires HAVE_BROTLI */
} compress_type_t;

/**
 * @brief Initialize the decompression system
 *
 * Currently a no-op but provided for API consistency.
 * Call once at program startup.
 *
 * @return Always returns 0
 */
int decompressor_init(void);

/**
 * @brief Clean up decompression resources
 *
 * Currently a no-op but provided for API consistency.
 * Call at program shutdown.
 */
void decompressor_cleanup(void);

/**
 * @brief Decompress gzip/deflate data
 *
 * Uses zlib to decompress gzip-wrapped or raw deflate data.
 * Automatically detects and handles both formats.
 *
 * @param[in]  in      Compressed input data
 * @param[in]  in_len  Length of compressed data
 * @param[out] out     Output buffer for decompressed data
 * @param[in]  out_len Size of output buffer
 *
 * @return Number of decompressed bytes, or negative on error
 *
 * @retval -1 Decompression failed
 * @retval -2 Output buffer too small
 *
 * @note This function handles both gzip (magic 1f 8b) and raw deflate.
 *       The zlib windowBits parameter is set to detect automatically.
 */
int decompress_gzip(const uint8_t *in, int in_len, uint8_t *out, int out_len);

/**
 * @brief Decompress zstd data
 *
 * Uses libzstd to decompress Zstandard-encoded data.
 *
 * @param[in]  in      Compressed input data
 * @param[in]  in_len  Length of compressed data
 * @param[out] out     Output buffer for decompressed data
 * @param[in]  out_len Size of output buffer
 *
 * @return Number of decompressed bytes, or negative on error
 *
 * @retval -1 Decompression failed or zstd not available
 * @retval -2 Output buffer too small
 *
 * @note Returns -1 if compiled without HAVE_ZSTD
 */
int decompress_zstd(const uint8_t *in, int in_len, uint8_t *out, int out_len);

/**
 * @brief Decompress brotli data
 *
 * Uses libbrotli to decompress Brotli-encoded data.
 *
 * @param[in]  in      Compressed input data
 * @param[in]  in_len  Length of compressed data
 * @param[out] out     Output buffer for decompressed data
 * @param[in]  out_len Size of output buffer
 *
 * @return Number of decompressed bytes, or negative on error
 *
 * @retval -1 Decompression failed or brotli not available
 * @retval -2 Output buffer too small
 *
 * @note Returns -1 if compiled without HAVE_BROTLI
 */
int decompress_brotli(const uint8_t *in, int in_len, uint8_t *out, int out_len);

/**
 * @brief Check if zstd decompression is available
 *
 * @return true if compiled with HAVE_ZSTD, false otherwise
 */
bool have_zstd_support(void);

/**
 * @brief Check if brotli decompression is available
 *
 * @return true if compiled with HAVE_BROTLI, false otherwise
 */
bool have_brotli_support(void);

/**
 * @brief Detect compression type from data magic bytes
 *
 * Inspects the first few bytes of data to identify compression format,
 * useful when Content-Encoding header is missing or unreliable.
 *
 * Detection signatures:
 * - gzip: 0x1f 0x8b
 * - zstd: 0x28 0xb5 0x2f 0xfd
 * - brotli: Heuristic based on stream format
 *
 * @param[in] data Data buffer to analyze
 * @param[in] len  Length of data buffer
 *
 * @return Detected compression type, or COMPRESS_NONE if unknown
 */
compress_type_t detect_compression(const uint8_t *data, int len);

/**
 * @brief Get human-readable name for compression type
 *
 * @param[in] type Compression type to name
 *
 * @return String name (e.g., "gzip", "zstd", "brotli", "none")
 */
const char *compress_type_name(compress_type_t type);

/**
 * @brief Decompress HTTP body based on Content-Encoding
 *
 * High-level function that selects the appropriate decompressor
 * based on the Content-Encoding header value. Handles:
 * - "gzip" / "x-gzip"
 * - "deflate"
 * - "zstd"
 * - "br" (brotli)
 *
 * @param[in]  data           Compressed body data
 * @param[in]  len            Length of compressed data
 * @param[in]  encoding       Content-Encoding header value (may be NULL)
 * @param[out] decomp_buf     Output buffer for decompressed data
 * @param[in]  decomp_buf_size Size of output buffer
 *
 * @return Number of decompressed bytes, or -1 if no decompression
 *         was needed or decompression failed
 *
 * @note If encoding is NULL or empty, returns -1 (no decompression)
 * @note If the encoding is not recognized, returns -1
 *
 * @par Example:
 * @code
 * uint8_t buf[65536];
 * int len = decompress_body(data, data_len, "gzip", buf, sizeof(buf));
 * if (len > 0) {
 *     // buf contains decompressed data
 * }
 * @endcode
 */
int decompress_body(const uint8_t *data, int len, const char *encoding,
                   uint8_t *decomp_buf, int decomp_buf_size);

/** @} */ /* end of decompressor group */

#endif /* DECOMPRESSOR_H */
