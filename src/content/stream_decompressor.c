/**
 * @file stream_decompressor.c
 * @brief Per-flow streaming decompression implementation
 *
 * @details Implements streaming decompression for gzip/deflate (zlib-ng),
 * zstd (libzstd), and brotli (libbrotli). Each stream is lazily initialized
 * on the first chunk and can be reset for connection reuse.
 *
 * @par Bomb Protection
 * After each feed, both ratio (output/input) and total output size are
 * checked. Once flagged, the stream permanently rejects further input
 * until reset or cleanup.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "stream_decompressor.h"
#include <stdlib.h>
#include <string.h>

/*----------------------------------------------------------------------------
 * zlib-ng Native API (same macros as decompressor.c)
 *----------------------------------------------------------------------------*/
#include <zlib-ng.h>
#define z_stream        zng_stream
#define inflateInit2    zng_inflateInit2
#define inflate         zng_inflate
#define inflateEnd      zng_inflateEnd
#include <zstd.h>
#include <brotli/decode.h>

/*============================================================================
 * Internal Helpers
 *============================================================================*/

/**
 * @brief Check decompression bomb limits after a feed.
 *
 * @param sd  Stream state with updated bytes_in/bytes_out
 * @return true if bomb detected (ratio or size exceeded)
 */
static bool check_bomb(stream_decomp_t *sd) {
    if (sd->bytes_out > STREAM_DECOMP_MAX_OUTPUT) {
        sd->bomb_detected = true;
        return true;
    }
    /* Ratio check uses multiplication (not division) so bytes_in == 0 is
     * safe — the product is zero, making the comparison always false.
     * Guard bytes_in > 0 is purely defensive against the impossible case
     * where a decompressor produces output without consuming any input. */
    if (sd->bytes_in > 0 &&
        sd->bytes_out > sd->bytes_in * STREAM_DECOMP_MAX_RATIO) {
        sd->bomb_detected = true;
        return true;
    }
    return false;
}

/*============================================================================
 * Init
 *============================================================================*/

/**
 * @brief Initialize gzip/deflate streaming context.
 */
static int init_gzip(stream_decomp_t *sd) {
    z_stream *strm = calloc(1, sizeof(z_stream));
    if (!strm) {
        return -1;
    }
    /* 15 + 32 = auto-detect gzip/zlib wrapper */
    int ret = inflateInit2(strm, 15 + 32);
    if (ret != Z_OK) {
        free(strm);
        return -1;
    }
    sd->ctx.zlib_stream = strm;
    return 0;
}

/**
 * @brief Initialize ZSTD streaming context with window limit.
 */
static int init_zstd(stream_decomp_t *sd) {
    ZSTD_DStream *dstream = ZSTD_createDStream();
    if (!dstream) {
        return -1;
    }
    /* Cap window size to prevent memory exhaustion from crafted frames */
    size_t err = ZSTD_DCtx_setParameter(dstream, ZSTD_d_windowLogMax,
                                         STREAM_DECOMP_ZSTD_WINDOW_LOG);
    if (ZSTD_isError(err)) {
        ZSTD_freeDStream(dstream);
        return -1;
    }
    sd->ctx.zstd_dstream = dstream;
    return 0;
}

/**
 * @brief Initialize brotli streaming context.
 */
static int init_brotli(stream_decomp_t *sd) {
    BrotliDecoderState *state = BrotliDecoderCreateInstance(NULL, NULL, NULL);
    if (!state) {
        return -1;
    }
    sd->ctx.brotli_state = state;
    return 0;
}

int stream_decomp_init(stream_decomp_t *sd, compress_type_t type) {
    if (!sd) {
        return -1;
    }
    if (sd->initialized) {
        return -1;  /* Already initialized — call reset first */
    }
    if (type == COMPRESS_NONE) {
        return -1;
    }

    int ret;
    switch (type) {
        case COMPRESS_GZIP:
        case COMPRESS_DEFLATE:
            ret = init_gzip(sd);
            break;
        case COMPRESS_ZSTD:
            ret = init_zstd(sd);
            break;
        case COMPRESS_BROTLI:
            ret = init_brotli(sd);
            break;
        default:
            return -1;
    }

    if (ret == 0) {
        sd->type = type;
        sd->initialized = true;
        sd->bomb_detected = false;
        sd->finished = false;
        sd->bytes_in = 0;
        sd->bytes_out = 0;
    }
    return ret;
}

/*============================================================================
 * Feed
 *============================================================================*/

/**
 * @brief Feed chunk through gzip/deflate stream.
 */
static int feed_gzip(stream_decomp_t *sd,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t out_len) {
    z_stream *strm = (z_stream *)sd->ctx.zlib_stream;
    strm->next_in = (const uint8_t *)in;
    strm->avail_in = (uint32_t)in_len;
    strm->next_out = out;
    strm->avail_out = (uint32_t)out_len;

    int ret = inflate(strm, Z_SYNC_FLUSH);
    if (ret == Z_STREAM_END) {
        sd->finished = true;
    } else if (ret != Z_OK && ret != Z_BUF_ERROR) {
        return -1;
    }

    size_t produced = out_len - strm->avail_out;
    sd->bytes_in += in_len - strm->avail_in;
    sd->bytes_out += produced;
    return (int)produced;
}

/**
 * @brief Feed chunk through ZSTD stream.
 */
static int feed_zstd(stream_decomp_t *sd,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t out_len) {
    ZSTD_inBuffer input = { .src = in, .size = in_len, .pos = 0 };
    ZSTD_outBuffer output = { .dst = out, .size = out_len, .pos = 0 };

    size_t ret = ZSTD_decompressStream(
        (ZSTD_DStream *)sd->ctx.zstd_dstream, &output, &input);

    if (ZSTD_isError(ret)) {
        return -1;
    }
    if (ret == 0) {
        sd->finished = true;
    }

    sd->bytes_in += input.pos;
    sd->bytes_out += output.pos;
    return (int)output.pos;
}

/**
 * @brief Feed chunk through brotli stream.
 */
static int feed_brotli(stream_decomp_t *sd,
                       const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t out_len) {
    size_t avail_in = in_len;
    const uint8_t *next_in = in;
    size_t avail_out = out_len;
    uint8_t *next_out = out;

    BrotliDecoderResult res = BrotliDecoderDecompressStream(
        (BrotliDecoderState *)sd->ctx.brotli_state,
        &avail_in, &next_in,
        &avail_out, &next_out,
        NULL);

    if (res == BROTLI_DECODER_RESULT_ERROR) {
        return -1;
    }
    if (res == BROTLI_DECODER_RESULT_SUCCESS) {
        sd->finished = true;
    }

    size_t consumed = in_len - avail_in;
    size_t produced = out_len - avail_out;
    sd->bytes_in += consumed;
    sd->bytes_out += produced;
    return (int)produced;
}

int stream_decomp_feed(stream_decomp_t *sd,
                       const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t out_len) {
    if (!sd || !sd->initialized) {
        return -1;
    }
    if (sd->bomb_detected) {
        return -2;
    }
    if (sd->finished || in_len == 0 || out_len == 0) {
        return 0;
    }

    int produced;
    switch (sd->type) {
        case COMPRESS_GZIP:
        case COMPRESS_DEFLATE:
            produced = feed_gzip(sd, in, in_len, out, out_len);
            break;
        case COMPRESS_ZSTD:
            produced = feed_zstd(sd, in, in_len, out, out_len);
            break;
        case COMPRESS_BROTLI:
            produced = feed_brotli(sd, in, in_len, out, out_len);
            break;
        default:
            return -1;
    }

    if (produced < 0) {
        return produced;
    }

    /* Check bomb limits after successful decompression */
    if (check_bomb(sd)) {
        return -2;
    }

    return produced;
}

/*============================================================================
 * Reset / Cleanup
 *============================================================================*/

/**
 * @brief Free library-specific resources without zeroing the struct.
 */
static void free_ctx(stream_decomp_t *sd) {
    if (!sd->initialized) {
        return;
    }

    switch (sd->type) {
        case COMPRESS_GZIP:
        case COMPRESS_DEFLATE:
            if (sd->ctx.zlib_stream) {
                inflateEnd((z_stream *)sd->ctx.zlib_stream);
                free(sd->ctx.zlib_stream);
                sd->ctx.zlib_stream = NULL;
            }
            break;
        case COMPRESS_ZSTD:
            if (sd->ctx.zstd_dstream) {
                ZSTD_freeDStream((ZSTD_DStream *)sd->ctx.zstd_dstream);
                sd->ctx.zstd_dstream = NULL;
            }
            break;
        case COMPRESS_BROTLI:
            if (sd->ctx.brotli_state) {
                BrotliDecoderDestroyInstance(
                    (BrotliDecoderState *)sd->ctx.brotli_state);
                sd->ctx.brotli_state = NULL;
            }
            break;
        default:
            break;
    }

    sd->initialized = false;
}

void stream_decomp_reset(stream_decomp_t *sd) {
    if (!sd) {
        return;
    }
    free_ctx(sd);
    sd->type = COMPRESS_NONE;
    sd->bomb_detected = false;
    sd->finished = false;
    sd->bytes_in = 0;
    sd->bytes_out = 0;
}

void stream_decomp_cleanup(stream_decomp_t *sd) {
    if (!sd) {
        return;
    }
    free_ctx(sd);
    memset(sd, 0, sizeof(*sd));
}
