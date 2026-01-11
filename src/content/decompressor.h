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

#ifndef DECOMPRESSOR_H
#define DECOMPRESSOR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Compression types */
typedef enum {
    COMPRESS_NONE = 0,
    COMPRESS_GZIP,
    COMPRESS_DEFLATE,
    COMPRESS_ZSTD,
    COMPRESS_BROTLI
} compress_type_t;

/* Initialize decompressor */
int decompressor_init(void);

/* Cleanup */
void decompressor_cleanup(void);

/* Decompress gzip/deflate data */
int decompress_gzip(const uint8_t *in, int in_len, uint8_t *out, int out_len);

/* Decompress zstd data */
int decompress_zstd(const uint8_t *in, int in_len, uint8_t *out, int out_len);

/* Decompress brotli data */
int decompress_brotli(const uint8_t *in, int in_len, uint8_t *out, int out_len);

/* Check if compression libraries are available */
bool have_zstd_support(void);
bool have_brotli_support(void);

/* Detect compression type from data */
compress_type_t detect_compression(const uint8_t *data, int len);

/* Get compression type name */
const char *compress_type_name(compress_type_t type);

/* Decompress body data based on Content-Encoding header
 * Returns: decompressed length, or -1 if no decompression needed/failed */
int decompress_body(const uint8_t *data, int len, const char *encoding,
                   uint8_t *decomp_buf, int decomp_buf_size);

#endif /* DECOMPRESSOR_H */
