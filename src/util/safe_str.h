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
 *
 * safe_str.h - Memory-safe string and buffer operations (C23)
 */

#ifndef SAFE_STR_H
#define SAFE_STR_H

#include <stddef.h>
#include <stdint.h>

/*
 * Safe string copy - always null terminates.
 * Uses memccpy (C23/POSIX) for efficient copying with bounds checking.
 *
 * Returns the number of characters copied (excluding null terminator),
 * or dst_size-1 if truncated. Return value can be ignored if truncation
 * detection is not needed.
 */
size_t safe_strcpy(char *dst, size_t dst_size, const char *src);

/*
 * Safe string copy with explicit length - always null terminates.
 * Copies at most src_len bytes from src, always null terminates.
 *
 * Returns the number of characters copied (excluding null terminator).
 */
size_t safe_strncpy(char *dst, size_t dst_size, const char *src, size_t src_len);

/*
 * Safe memory copy with bounds checking.
 * Returns the number of bytes actually copied.
 */
size_t safe_memcpy(void *dst, size_t dst_size, const void *src, size_t src_len);

/*
 * Safe string concatenation - always null terminates.
 * Appends src to dst without exceeding dst_size total.
 *
 * Returns total length of concatenated string (may exceed dst_size if truncated).
 */
size_t safe_strcat(char *dst, size_t dst_size, const char *src);

/*
 * Secure memory clear - prevents compiler optimization from removing the clear.
 * Should be used for clearing sensitive data (passwords, keys, etc.).
 *
 * Uses C23 memset_explicit when available, with volatile fallback.
 */
void safe_memclear(void *ptr, size_t len);

/*
 * Safe memmove with bounds checking.
 * Handles overlapping regions correctly.
 * Returns the number of bytes actually moved.
 */
size_t safe_memmove(void *dst, size_t dst_size, const void *src, size_t src_len);

#endif /* SAFE_STR_H */
