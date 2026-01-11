/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
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

#include "decompressor.h"
#include <string.h>
#include <strings.h>
#include <zlib.h>

#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

#ifdef HAVE_BROTLI
#include <brotli/decode.h>
#endif

/* Initialize decompressor */
int decompressor_init(void) {
    /* No initialization needed for now */
    return 0;
}

/* Cleanup */
void decompressor_cleanup(void) {
    /* No cleanup needed for now */
}

/* Decompress gzip/deflate data */
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

/* Decompress zstd data */
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

/* Decompress brotli data */
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

/* Check if compression libraries are available */
bool have_zstd_support(void) {
#ifdef HAVE_ZSTD
    return true;
#else
    return false;
#endif
}

bool have_brotli_support(void) {
#ifdef HAVE_BROTLI
    return true;
#else
    return false;
#endif
}

/* Detect compression type from data */
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

/* Get compression type name */
const char *compress_type_name(compress_type_t type) {
    switch (type) {
        case COMPRESS_GZIP: return "gzip";
        case COMPRESS_DEFLATE: return "deflate";
        case COMPRESS_ZSTD: return "zstd";
        case COMPRESS_BROTLI: return "brotli";
        default: return NULL;
    }
}

/* Decompress body data based on Content-Encoding header */
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
