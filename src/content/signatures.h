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

#ifndef SIGNATURES_H
#define SIGNATURES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* File signature structure */
typedef struct {
    const uint8_t *magic;       /* Magic bytes to match */
    int magic_len;              /* Length of magic bytes */
    int offset;                 /* Offset from start (usually 0) */
    const char *description;    /* Human-readable description */
    bool is_binary;             /* True if binary (don't display content) */
} file_signature_t;

/* Initialize signature detection */
int signatures_init(void);

/* Cleanup */
void signatures_cleanup(void);

/* Detect file type from data - returns description or NULL */
const char *signature_detect(const uint8_t *data, size_t len);

/* Check if content should be displayed as text */
bool signature_is_binary(const char *description);

/* Check if content is local file I/O (not HTTP traffic) */
bool signature_is_local_file(const char *description);

#endif /* SIGNATURES_H */
