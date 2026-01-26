/**
 * @file decompressor.c
 * @brief Implementation of HTTP body decompression
 *
 * @details This module implements decompression of HTTP response bodies
 * based on Content-Encoding headers. It provides a unified API that
 * abstracts the underlying compression libraries.
 *
 * @par Supported Compression Methods:
 * | Method   | Library   | Compile Flag | Header Magic        |
 * |----------|-----------|--------------|---------------------|
 * | gzip     | zlib      | (required)   | 1f 8b               |
 * | deflate  | zlib      | (required)   | 78 xx               |
 * | zstd     | libzstd   | HAVE_ZSTD    | 28 b5 2f fd         |
 * | brotli   | libbrotli | HAVE_BROTLI  | (stream-dependent)  |
 *
 * @par Architecture:
 * @code
 * decompress_body(data, encoding)
 *    │
 *    ├── Parse Content-Encoding header
 *    ├── Auto-detect if no header (detect_compression)
 *    │
 *    └── dispatch to:
 *        ├── decompress_gzip()   ← zlib (gzip/deflate)
 *        ├── decompress_zstd()   ← libzstd (if HAVE_ZSTD)
 *        └── decompress_brotli() ← libbrotli (if HAVE_BROTLI)
 * @endcode
 *
 * @par Memory Safety:
 * - All functions reserve 1 byte for null termination
 * - Output buffers are always null-terminated on success
 * - Input validation prevents buffer overflows
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "decompressor.h"
#include <string.h>
#include <strings.h>

/*----------------------------------------------------------------------------
 * zlib-ng Native API Support
 *
 * zlib-ng in native mode uses zng_ prefixed functions to avoid symbol
 * collisions with system zlib. These macros provide a unified interface.
 *----------------------------------------------------------------------------*/
#ifdef HAVE_ZLIB_NG
#include <zlib-ng.h>
/* Native zlib-ng API uses zng_ prefix */
#define z_stream        zng_stream
#define inflateInit2    zng_inflateInit2
#define inflate         zng_inflate
#define inflateEnd      zng_inflateEnd
#else
#include <zlib.h>
#endif

#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

#ifdef HAVE_BROTLI
#include <brotli/decode.h>
#endif

/**
 * @brief Initialize the decompression system
 *
 * Currently a no-op as the underlying libraries (zlib, zstd, brotli)
 * don't require global initialization. Provided for API consistency
 * and future extensibility.
 *
 * @return Always returns 0
 *
 * @see decompressor_cleanup()
 */
int decompressor_init(void) {
    /* No initialization needed for now */
    return 0;
}

/**
 * @brief Clean up decompression resources
 *
 * Currently a no-op. Provided for API consistency and to allow
 * future resource management without API changes.
 *
 * @see decompressor_init()
 */
void decompressor_cleanup(void) {
    /* No cleanup needed for now */
}

/**
 * @brief Decompress gzip/deflate data using zlib
 *
 * Uses zlib's inflate functions to decompress both gzip-wrapped
 * (RFC 1952) and raw deflate (RFC 1951) streams. The windowBits
 * parameter (15 + 32) enables automatic format detection.
 *
 * @par zlib windowBits Values:
 * - 15: Raw deflate
 * - 15 + 16: gzip only
 * - 15 + 32: Auto-detect gzip or zlib header
 *
 * @param[in]  in      Compressed input data
 * @param[in]  in_len  Length of compressed data
 * @param[out] out     Output buffer for decompressed data
 * @param[in]  out_len Size of output buffer
 *
 * @return Number of decompressed bytes on success, -1 on failure
 *
 * @note Returns partial data if buffer fills (Z_BUF_ERROR with output)
 * @note The output is NOT null-terminated; caller must handle this
 *
 * @see decompress_body() for high-level API with null termination
 */
int decompress_gzip(const uint8_t *in, int in_len, uint8_t *out, int out_len) {
    z_stream strm = {0};

    /* 15 + 32 = auto-detect gzip/zlib */
    int ret = inflateInit2(&strm, 15 + 32);
    if (ret != Z_OK) return -1;

    strm.avail_in = in_len;
    strm.next_in = (Bytef *)in;
    strm.avail_out = out_len;
    strm.next_out = out;

    ret = inflate(&strm, Z_FINISH);
    int decompressed = out_len - strm.avail_out;
    inflateEnd(&strm);

    if (ret == Z_STREAM_END || ret == Z_OK || (ret == Z_BUF_ERROR && decompressed > 0)) {
        return decompressed;
    }
    return -1;
}

/**
 * @brief Decompress zstd data using libzstd
 *
 * Uses the Zstandard library to decompress data encoded with
 * the zstd algorithm (RFC 8878). This is a single-call API that
 * handles complete frames.
 *
 * @param[in]  in      Compressed input data (zstd frame)
 * @param[in]  in_len  Length of compressed data
 * @param[out] out     Output buffer for decompressed data
 * @param[in]  out_len Size of output buffer
 *
 * @return Number of decompressed bytes on success, -1 on failure
 *
 * @retval -1 Decompression error or HAVE_ZSTD not defined
 *
 * @note Returns -1 if compiled without HAVE_ZSTD
 * @note Zstd magic bytes: 28 b5 2f fd
 *
 * @see have_zstd_support() to check availability at runtime
 */
int decompress_zstd(const uint8_t *in, int in_len, uint8_t *out, int out_len) {
#ifdef HAVE_ZSTD
    size_t result = ZSTD_decompress(out, out_len, in, in_len);
    if (ZSTD_isError(result)) {
        return -1;
    }
    return (int)result;
#else
    (void)in; (void)in_len; (void)out; (void)out_len;
    return -1;
#endif
}

/**
 * @brief Decompress brotli data using libbrotli
 *
 * Uses Google's Brotli library to decompress data encoded with
 * the Brotli algorithm (RFC 7932). This is the compression
 * indicated by "Content-Encoding: br" in HTTP responses.
 *
 * @param[in]  in      Compressed input data (brotli stream)
 * @param[in]  in_len  Length of compressed data
 * @param[out] out     Output buffer for decompressed data
 * @param[in]  out_len Size of output buffer
 *
 * @return Number of decompressed bytes on success, -1 on failure
 *
 * @retval -1 Decompression error or HAVE_BROTLI not defined
 *
 * @note Returns -1 if compiled without HAVE_BROTLI
 * @note Brotli has no fixed magic bytes; detection relies on headers
 *
 * @see have_brotli_support() to check availability at runtime
 */
int decompress_brotli(const uint8_t *in, int in_len, uint8_t *out, int out_len) {
#ifdef HAVE_BROTLI
    size_t decoded_size = out_len;
    BrotliDecoderResult result = BrotliDecoderDecompress(
        in_len, in, &decoded_size, out);
    if (result == BROTLI_DECODER_RESULT_SUCCESS) {
        return (int)decoded_size;
    }
    return -1;
#else
    (void)in; (void)in_len; (void)out; (void)out_len;
    return -1;
#endif
}

/**
 * @defgroup decomp_support Compression Support Queries
 * @brief Runtime checks for optional compression library availability
 * @ingroup decompressor
 * @{
 */

/**
 * @brief Check if zstd decompression is available
 *
 * Returns whether libzstd was linked at compile time.
 * Use this before attempting zstd decompression to provide
 * meaningful error messages or fallback behavior.
 *
 * @return true if HAVE_ZSTD was defined at compile time
 *
 * @see decompress_zstd()
 */
bool have_zstd_support(void) {
#ifdef HAVE_ZSTD
    return true;
#else
    return false;
#endif
}

/**
 * @brief Check if brotli decompression is available
 *
 * Returns whether libbrotli was linked at compile time.
 * Use this before attempting brotli decompression to provide
 * meaningful error messages or fallback behavior.
 *
 * @return true if HAVE_BROTLI was defined at compile time
 *
 * @see decompress_brotli()
 */
bool have_brotli_support(void) {
#ifdef HAVE_BROTLI
    return true;
#else
    return false;
#endif
}

/** @} */ /* End of decomp_support group */

/**
 * @brief Detect compression type from data magic bytes
 *
 * Inspects the first few bytes of data to identify compression
 * format when Content-Encoding header is missing or unreliable.
 *
 * @par Magic Byte Patterns:
 * | Compression | Bytes          | Notes                    |
 * |-------------|----------------|--------------------------|
 * | gzip        | 1f 8b          | RFC 1952 header          |
 * | zstd        | 28 b5 2f fd    | Frame magic number       |
 * | deflate     | 78 xx          | zlib header (CMF=78)     |
 *
 * @par Deflate CMF/FLG Values:
 * - 78 01: No compression (level 0)
 * - 78 5e: Fast compression (level 1)
 * - 78 9c: Default compression (level 6)
 * - 78 da: Best compression (level 9)
 *
 * @param[in] data Data buffer to analyze
 * @param[in] len  Length of data buffer
 *
 * @return Detected compression type, or COMPRESS_NONE if unknown
 *
 * @note Brotli cannot be detected by magic bytes alone
 */
compress_type_t detect_compression(const uint8_t *data, int len) {
    if (len < 2) return COMPRESS_NONE;

    /* gzip: 1f 8b */
    if (data[0] == 0x1f && data[1] == 0x8b) return COMPRESS_GZIP;

    /* zstd: 28 b5 2f fd */
    if (len >= 4 && data[0] == 0x28 && data[1] == 0xb5 &&
        data[2] == 0x2f && data[3] == 0xfd) return COMPRESS_ZSTD;

    /* zlib/deflate: 78 9c, 78 da, 78 01, 78 5e */
    if (data[0] == 0x78 && (data[1] == 0x9c || data[1] == 0xda ||
                            data[1] == 0x01 || data[1] == 0x5e)) return COMPRESS_DEFLATE;

    return COMPRESS_NONE;
}

/**
 * @brief Get human-readable name for compression type
 *
 * Converts a compress_type_t enum value to the corresponding
 * Content-Encoding header value string.
 *
 * @param[in] type Compression type to name
 *
 * @return Static string with compression name:
 *         - COMPRESS_GZIP → "gzip"
 *         - COMPRESS_DEFLATE → "deflate"
 *         - COMPRESS_ZSTD → "zstd"
 *         - COMPRESS_BROTLI → "brotli"
 *         - COMPRESS_NONE/other → NULL
 */
const char *compress_type_name(compress_type_t type) {
    switch (type) {
        case COMPRESS_GZIP: return "gzip";
        case COMPRESS_DEFLATE: return "deflate";
        case COMPRESS_ZSTD: return "zstd";
        case COMPRESS_BROTLI: return "brotli";
        default: return NULL;
    }
}

/**
 * @brief Decompress HTTP body based on Content-Encoding header
 *
 * High-level decompression API that:
 * 1. Parses the Content-Encoding header to determine compression type
 * 2. Falls back to magic byte detection if no header provided
 * 3. Dispatches to the appropriate decompression function
 * 4. Null-terminates the output for safe string handling
 *
 * @par Content-Encoding Mapping:
 * | Header Value      | Compression Type |
 * |-------------------|------------------|
 * | gzip, x-gzip      | COMPRESS_GZIP    |
 * | deflate           | COMPRESS_DEFLATE |
 * | zstd              | COMPRESS_ZSTD    |
 * | br                | COMPRESS_BROTLI  |
 *
 * @param[in]  data            Compressed body data
 * @param[in]  len             Length of compressed data
 * @param[in]  encoding        Content-Encoding header value (may be NULL)
 * @param[out] decomp_buf      Output buffer for decompressed data
 * @param[in]  decomp_buf_size Size of output buffer
 *
 * @return Number of decompressed bytes on success, -1 if:
 *         - No compression detected (data is already uncompressed)
 *         - Decompression failed
 *         - Required library not available
 *
 * @note Reserves 1 byte for null termination; effective buffer is size-1
 * @note Output is always null-terminated when decomp_len > 0
 * @note Case-insensitive header matching via strcasestr()
 *
 * @par Example:
 * @code
 * uint8_t buf[65536];
 * int len = decompress_body(body, body_len, "gzip", buf, sizeof(buf));
 * if (len > 0) {
 *     printf("Decompressed: %s\n", buf);  // Safe: null-terminated
 * }
 * @endcode
 */
int decompress_body(const uint8_t *data, int len, const char *encoding,
                   uint8_t *decomp_buf, int decomp_buf_size) {
    compress_type_t ctype = COMPRESS_NONE;

    /* Determine compression from header */
    if (encoding && encoding[0]) {
        if (strcasestr(encoding, "gzip")) ctype = COMPRESS_GZIP;
        else if (strcasestr(encoding, "deflate")) ctype = COMPRESS_DEFLATE;
        else if (strcasestr(encoding, "zstd")) ctype = COMPRESS_ZSTD;
        else if (strcasestr(encoding, "br")) ctype = COMPRESS_BROTLI;
    }

    /* If no encoding header, try auto-detection */
    if (ctype == COMPRESS_NONE) {
        ctype = detect_compression(data, len);
    }

    if (ctype == COMPRESS_NONE) {
        return -1;  /* No decompression needed */
    }

    int decomp_len = -1;
    switch (ctype) {
        case COMPRESS_GZIP:
        case COMPRESS_DEFLATE:
            decomp_len = decompress_gzip(data, len, decomp_buf, decomp_buf_size - 1);
            break;
        case COMPRESS_ZSTD:
            decomp_len = decompress_zstd(data, len, decomp_buf, decomp_buf_size - 1);
            break;
        case COMPRESS_BROTLI:
            decomp_len = decompress_brotli(data, len, decomp_buf, decomp_buf_size - 1);
            break;
        default:
            break;
    }

    if (decomp_len > 0) {
        decomp_buf[decomp_len] = '\0';
    }
    return decomp_len;
}
