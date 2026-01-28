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
#include <zlib-ng.h>
/* Native zlib-ng API uses zng_ prefix */
#define z_stream        zng_stream
#define inflateInit2    zng_inflateInit2
#define inflate         zng_inflate
#define inflateEnd      zng_inflateEnd

#include <zstd.h>
#include <brotli/decode.h>

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

int decompress_zstd(const uint8_t *in, int in_len, uint8_t *out, int out_len) {
    size_t result = ZSTD_decompress(out, out_len, in, in_len);
    if (ZSTD_isError(result)) {
        return -1;
    }
    return (int)result;
}

int decompress_brotli(const uint8_t *in, int in_len, uint8_t *out, int out_len) {
    size_t decoded_size = out_len;
    BrotliDecoderResult result = BrotliDecoderDecompress(
        in_len, in, &decoded_size, out);
    if (result == BROTLI_DECODER_RESULT_SUCCESS) {
        return (int)decoded_size;
    }
    return -1;
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
    return true;
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
    return true;
}

/** @} */ /* End of decomp_support group */

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

const char *compress_type_name(compress_type_t type) {
    switch (type) {
        case COMPRESS_GZIP: return "gzip";
        case COMPRESS_DEFLATE: return "deflate";
        case COMPRESS_ZSTD: return "zstd";
        case COMPRESS_BROTLI: return "brotli";
        default: return NULL;
    }
}

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
