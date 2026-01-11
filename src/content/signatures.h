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

#ifndef SIGNATURES_H
#define SIGNATURES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * File class categories for display grouping.
 * These categorize detected file types for user-friendly output.
 */
typedef enum {
    FILE_CLASS_UNKNOWN = 0,
    FILE_CLASS_IMAGE,       /* JPEG, PNG, GIF, WebP, etc. */
    FILE_CLASS_VIDEO,       /* MP4, WebM, AVI, etc. */
    FILE_CLASS_AUDIO,       /* MP3, OGG, FLAC, WAV, etc. */
    FILE_CLASS_ARCHIVE,     /* ZIP, GZIP, ZSTD, TAR, etc. */
    FILE_CLASS_DOCUMENT,    /* PDF */
    FILE_CLASS_FONT,        /* WOFF, WOFF2, TTF, OTF */
    FILE_CLASS_EXECUTABLE,  /* WASM, ELF, Mach-O */
    FILE_CLASS_DATABASE,    /* SQLite */
    FILE_CLASS_CONTAINER,   /* Generic container formats */
} file_class_t;

/*
 * Signature detection result with full metadata.
 * Returned by signature_detect_full() for detailed information.
 */
typedef struct {
    const char *description;    /* Human-readable description (e.g., "PNG image") */
    file_class_t file_class;    /* Category for display grouping */
    bool is_binary;             /* True if binary (don't display as text) */
    bool trailer_valid;         /* True if trailer bytes matched (when validated) */
    int confidence;             /* Match confidence: magic_len (higher = more specific) */
} signature_result_t;

/* File signature structure (internal, but exposed for documentation) */
typedef struct {
    const uint8_t *magic;       /* Magic bytes to match */
    int magic_len;              /* Length of magic bytes */
    int offset;                 /* Offset from start (0, 4, 8, or 257 for TAR) */
    const char *description;    /* Human-readable description */
    file_class_t file_class;    /* Category for display */
    bool is_binary;             /* True if binary content */
    const uint8_t *trailer;     /* Optional trailer bytes (NULL if none) */
    int trailer_len;            /* Length of trailer bytes */
} file_signature_t;

/* Initialize signature detection (builds sorted index) */
int signatures_init(void);

/* Cleanup */
void signatures_cleanup(void);

/* Detect file type from data - returns description or NULL (legacy API) */
const char *signature_detect(const uint8_t *data, size_t len);

/* Full detection with metadata - fills result struct, returns true if found */
bool signature_detect_full(const uint8_t *data, size_t len,
                           bool validate_trailer,
                           signature_result_t *result);

/* Get human-readable class name */
const char *signature_class_name(file_class_t file_class);

/* Check if content should be treated as binary based on description */
bool signature_is_binary(const char *description);

/* Check if content is local file I/O (not HTTP traffic) */
bool signature_is_local_file(const char *description);

/*
 * Adding new signatures:
 * 1. Define magic bytes as static const uint8_t array
 * 2. Add entry to signatures[] table with appropriate file_class
 * 3. Table is auto-sorted by magic_len (longest first) at init
 * 4. For container formats (ISOBMFF, RIFF), add to special handlers
 */

#endif /* SIGNATURES_H */
