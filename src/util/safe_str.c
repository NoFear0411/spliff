/**
 * @file safe_str.c
 * @brief Implementation of memory-safe string and buffer operations
 *
 * @details This file implements the safe string functions declared in safe_str.h.
 * The implementation prioritizes:
 *
 * - **Safety**: All operations check bounds and handle edge cases
 * - **Performance**: Uses efficient C library functions (memccpy, memcpy, memmove)
 * - **Compatibility**: Works with C11+ compilers, uses C23 features when available
 *
 * @see safe_str.h for function documentation and usage examples
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "safe_str.h"
#include <string.h>
#include <stdint.h>

/**
 * Implementation uses memccpy for efficient single-pass copying that
 * stops at the null terminator. This is more efficient than strlen+memcpy
 * as it avoids scanning the string twice.
 *
 * @note memccpy copies up to n bytes, stopping at char c ('\0' here).
 * Returns pointer to byte after copied char, or NULL if not found.
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

/**
 * Combines length limiting with null-termination guarantee.
 * Uses memccpy to efficiently handle embedded null bytes in the source.
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

/**
 * Simple wrapper around memcpy that enforces destination size limits.
 * Does not handle overlapping regions - use safe_memmove() for that.
 */
size_t safe_memcpy(void *dst, size_t dst_size, const void *src, size_t src_len) {
    if (dst_size == 0 || !dst || !src) return 0;

    size_t copy_len = (src_len < dst_size) ? src_len : dst_size;
    memcpy(dst, src, copy_len);
    return copy_len;
}

/**
 * First finds the current string length using strnlen (bounded to prevent
 * scanning past dst_size), then appends as much of src as will fit.
 *
 * @note Return value semantics match BSD strlcat: returns total length
 * that would result from concatenation, even if truncation occurred.
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

/**
 * Ensures memory is actually zeroed, even when the compiler might otherwise
 * optimize away the clearing.
 *
 * Implementation:
 * - **C23 with Annex K**: Uses memset_explicit() (guaranteed not optimized away)
 * - **Fallback**: Uses volatile pointer to prevent optimization
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

/**
 * Wrapper around memmove that enforces destination size limits.
 * Unlike memcpy, memmove correctly handles overlapping source and
 * destination regions.
 */
size_t safe_memmove(void *dst, size_t dst_size, const void *src, size_t src_len) {
    if (dst_size == 0 || !dst || !src) return 0;

    size_t move_len = (src_len < dst_size) ? src_len : dst_size;
    memmove(dst, src, move_len);
    return move_len;
}
