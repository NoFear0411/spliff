/**
 * @file stream_decompressor.h
 * @brief Per-flow streaming decompression for HTTP body chunks
 *
 * @details Provides a unified streaming API over zlib-ng, libzstd, and
 * libbrotli. Each flow_context_t embeds a stream_decomp_t that processes
 * body chunks incrementally as they arrive from the network.
 *
 * @par Decompression Bomb Protection
 * Two limits prevent resource exhaustion from malicious payloads:
 * - **Ratio limit**: If output/input exceeds STREAM_DECOMP_MAX_RATIO,
 *   the stream is flagged and further input rejected.
 * - **Size limit**: If total output exceeds STREAM_DECOMP_MAX_OUTPUT,
 *   the stream is flagged and further input rejected.
 *
 * @par ZSTD Window Size
 * ZSTD decompression window is capped at STREAM_DECOMP_ZSTD_WINDOW_LOG
 * (8 MB) to prevent excessive memory usage from crafted frames.
 *
 * @par Lifecycle
 * @code
 * stream_decomp_t sd = {0};
 * stream_decomp_init(&sd, COMPRESS_GZIP);    // Once per response
 * while (chunk = next_chunk()) {
 *     int n = stream_decomp_feed(&sd, chunk, len, out, out_sz);
 *     if (n == -2) handle_bomb();
 *     if (n >= 0) process(out, n);
 * }
 * stream_decomp_reset(&sd);                  // Reuse for next response
 * stream_decomp_cleanup(&sd);                // On flow destruction
 * @endcode
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef STREAM_DECOMPRESSOR_H
#define STREAM_DECOMPRESSOR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "decompressor.h"  /* compress_type_t */

/**
 * @defgroup stream_decomp Streaming Decompression
 * @brief Per-flow streaming decompression with bomb protection
 * @{
 */

/*============================================================================
 * Bomb Protection Limits
 *============================================================================*/

/** Maximum total decompressed output per stream (100 MB) */
#define STREAM_DECOMP_MAX_OUTPUT   (100ULL * 1024 * 1024)

/** Maximum decompression ratio (output:input) before flagging as bomb */
#define STREAM_DECOMP_MAX_RATIO    1000

/** ZSTD decompression window log limit (23 = 8 MB) */
#define STREAM_DECOMP_ZSTD_WINDOW_LOG  23

/*============================================================================
 * Stream State
 *============================================================================*/

/**
 * @brief Per-flow streaming decompression state
 *
 * Embeds the library-specific context in a union to share memory.
 * Only one decompressor is active per flow at a time.
 *
 * @par Size
 * ~128 bytes (dominated by zlib-ng's zng_stream at ~112 bytes).
 * Lazy-initialized on first chunk, so idle flows pay 0 cost.
 */
typedef struct {
    compress_type_t type;       /**< Active compression type (NONE if idle) */
    bool initialized;           /**< Stream context allocated and ready */
    bool bomb_detected;         /**< Bomb limit exceeded — reject further input */
    bool finished;              /**< Stream reached end-of-data marker */

    uint64_t bytes_in;          /**< Total compressed bytes consumed */
    uint64_t bytes_out;         /**< Total decompressed bytes produced */

    /** @brief Library-specific stream context (union, one active at a time) */
    union {
        void *zlib_stream;      /**< zng_stream* (allocated on heap) */
        void *zstd_dstream;     /**< ZSTD_DStream* */
        void *brotli_state;     /**< BrotliDecoderState* */
    } ctx;
} stream_decomp_t;

/*============================================================================
 * API
 *============================================================================*/

/**
 * @brief Initialize a streaming decompressor for a given type.
 *
 * Allocates library-specific resources. Can be called multiple times
 * if reset() was called in between (e.g., for a new HTTP response on
 * the same connection).
 *
 * @param sd    Stream state (must be zeroed or previously reset)
 * @param type  Compression type to decompress
 * @return 0 on success, -1 on allocation failure or unsupported type
 */
int stream_decomp_init(stream_decomp_t *sd, compress_type_t type);

/**
 * @brief Feed a chunk of compressed data and produce decompressed output.
 *
 * Processes up to @p in_len bytes from @p in and writes decompressed data
 * to @p out (up to @p out_len bytes). May consume less than in_len if the
 * output buffer fills or the stream finishes.
 *
 * @param sd       Initialized stream state
 * @param in       Compressed input chunk
 * @param in_len   Length of compressed input
 * @param out      Output buffer for decompressed data
 * @param out_len  Size of output buffer
 *
 * @return Number of decompressed bytes written to @p out (>= 0), or:
 * @retval -1  Decompression error (corrupt data, library error)
 * @retval -2  Decompression bomb detected (ratio or size limit exceeded)
 *
 * @note After returning -2, the stream is flagged and all subsequent
 *       calls return -2 without processing data.
 */
int stream_decomp_feed(stream_decomp_t *sd,
                       const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t out_len);

/**
 * @brief Reset stream for reuse (e.g., new HTTP response on same connection).
 *
 * Frees library-specific resources but keeps the struct valid for
 * a subsequent stream_decomp_init() call. More efficient than
 * cleanup + memset + init for connection reuse.
 *
 * @param sd  Stream state (NULL-safe, uninitialized-safe)
 */
void stream_decomp_reset(stream_decomp_t *sd);

/**
 * @brief Free all resources held by the stream decompressor.
 *
 * Called during flow destruction. NULL-safe and idempotent.
 *
 * @param sd  Stream state (NULL-safe, uninitialized-safe)
 */
void stream_decomp_cleanup(stream_decomp_t *sd);

/** @} */

#endif /* STREAM_DECOMPRESSOR_H */
