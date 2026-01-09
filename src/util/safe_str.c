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
 * safe_str.c - Memory-safe string and buffer operations (C23)
 */

#include "safe_str.h"
#include <string.h>
#include <stdint.h>

/*
 * Safe string copy - always null terminates.
 * Uses memccpy (C23/POSIX) for efficient copying with bounds checking.
 *
 * Returns the number of characters copied (excluding null terminator),
 * or dst_size-1 if truncated.
 */
size_t safe_strcpy(char *dst, size_t dst_size, const char *src) {
    if (dst_size == 0) return 0;
    if (!dst || !src) {
        if (dst) dst[0] = '\0';
        return 0;
    }

    /* memccpy copies up to n bytes, stopping at char c (here '\0') */
    char *end = memccpy(dst, src, '\0', dst_size);

    if (end) {
        /* Source fit entirely - return actual length copied */
        return (size_t)(end - dst - 1);
    } else {
        /* Truncated - ensure null termination */
        dst[dst_size - 1] = '\0';
        return dst_size - 1;
    }
}

/*
 * Safe string copy with explicit length - always null terminates.
 * Copies at most src_len bytes from src, always null terminates.
 */
size_t safe_strncpy(char *dst, size_t dst_size, const char *src, size_t src_len) {
    if (dst_size == 0) return 0;
    if (!dst || !src) {
        if (dst) dst[0] = '\0';
        return 0;
    }

    /* Determine actual copy length */
    size_t copy_len = (src_len < dst_size - 1) ? src_len : dst_size - 1;

    /* memccpy stops at null byte if found within copy_len */
    char *end = memccpy(dst, src, '\0', copy_len);

    if (end) {
        /* Null byte found - string was shorter than src_len */
        return (size_t)(end - dst - 1);
    } else {
        /* Copied copy_len bytes without finding null - terminate */
        dst[copy_len] = '\0';
        return copy_len;
    }
}

/*
 * Safe memory copy with bounds checking.
 * Returns the number of bytes actually copied.
 */
size_t safe_memcpy(void *dst, size_t dst_size, const void *src, size_t src_len) {
    if (dst_size == 0 || !dst || !src) return 0;

    size_t copy_len = (src_len < dst_size) ? src_len : dst_size;
    memcpy(dst, src, copy_len);
    return copy_len;
}

/*
 * Safe string concatenation - always null terminates.
 * Appends src to dst without exceeding dst_size total.
 * Returns total length of concatenated string (may exceed dst_size if truncated).
 */
size_t safe_strcat(char *dst, size_t dst_size, const char *src) {
    if (dst_size == 0 || !dst || !src) return 0;

    size_t dst_len = strnlen(dst, dst_size);
    if (dst_len >= dst_size - 1) {
        /* No room for additional characters */
        dst[dst_size - 1] = '\0';
        return dst_len + strlen(src);
    }

    size_t src_len = strlen(src);
    size_t space = dst_size - dst_len - 1;
    size_t copy_len = (src_len < space) ? src_len : space;

    memcpy(dst + dst_len, src, copy_len);
    dst[dst_len + copy_len] = '\0';

    return dst_len + src_len;
}

/*
 * Secure memory clear - prevents compiler optimization from removing the clear.
 * Should be used for clearing sensitive data (passwords, keys, etc.).
 *
 * Note: C23 adds memset_explicit for this purpose. We provide a fallback
 * using volatile for compilers that don't support it yet.
 */
void safe_memclear(void *ptr, size_t len) {
    if (!ptr || len == 0) return;

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L && defined(__STDC_LIB_EXT1__)
    /* C23 with Annex K support - use memset_explicit */
    memset_explicit(ptr, 0, len);
#else
    /* Fallback: use volatile to prevent optimization */
    volatile unsigned char *volatile p = (volatile unsigned char *volatile)ptr;
    while (len--) {
        *p++ = 0;
    }
#endif
}

/*
 * Safe memmove with bounds checking.
 * Handles overlapping regions correctly.
 * Returns the number of bytes actually moved.
 */
size_t safe_memmove(void *dst, size_t dst_size, const void *src, size_t src_len) {
    if (dst_size == 0 || !dst || !src) return 0;

    size_t move_len = (src_len < dst_size) ? src_len : dst_size;
    memmove(dst, src, move_len);
    return move_len;
}
