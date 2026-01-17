/**
 * @file safe_str.h
 * @brief Memory-safe string and buffer operations (C23)
 *
 * @details This module provides safe alternatives to standard C string and
 * memory functions that can cause buffer overflows. All functions:
 *
 * - Accept explicit buffer sizes to prevent overflows
 * - Always null-terminate string results
 * - Handle NULL pointers gracefully
 * - Return meaningful values for detecting truncation
 *
 * The implementation uses C23 features (memccpy) when available, with
 * portable fallbacks for older compilers.
 *
 * @par Example Usage:
 * @code
 * char dest[64];
 *
 * // Safe string copy
 * safe_strcpy(dest, sizeof(dest), source_string);
 *
 * // Safe concatenation
 * safe_strcat(dest, sizeof(dest), " appended text");
 *
 * // Clear sensitive data
 * safe_memclear(password_buffer, sizeof(password_buffer));
 * @endcode
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef SAFE_STR_H
#define SAFE_STR_H

#include <stddef.h>
#include <stdint.h>

/**
 * @defgroup safe_string Safe String Operations
 * @brief Memory-safe string manipulation functions
 * @{
 */

/**
 * @brief Safely copy a null-terminated string
 *
 * Copies the source string to the destination buffer, ensuring null
 * termination even if the source is larger than the destination.
 * Uses memccpy (C23/POSIX) for efficient copying with bounds checking.
 *
 * @param[out] dst      Destination buffer
 * @param[in]  dst_size Size of destination buffer in bytes
 * @param[in]  src      Source null-terminated string
 *
 * @return Number of characters copied (excluding null terminator),
 *         or dst_size-1 if truncated. Return value can be compared
 *         with dst_size-1 to detect truncation.
 *
 * @retval 0 If dst_size is 0 or either pointer is NULL
 *
 * @note Always null-terminates the destination if dst_size > 0
 * @note If src is NULL, dst[0] is set to '\0' and 0 is returned
 *
 * @par Example:
 * @code
 * char buf[10];
 * size_t len = safe_strcpy(buf, sizeof(buf), "hello world");
 * // len == 9 (truncated), buf == "hello wor"
 * @endcode
 */
size_t safe_strcpy(char *dst, size_t dst_size, const char *src);

/**
 * @brief Safely copy a string with explicit length limit
 *
 * Copies at most src_len bytes from src to dst, always null-terminating
 * the result. Useful when the source may not be null-terminated or when
 * only a prefix of the source is needed.
 *
 * @param[out] dst      Destination buffer
 * @param[in]  dst_size Size of destination buffer in bytes
 * @param[in]  src      Source string (may not be null-terminated)
 * @param[in]  src_len  Maximum bytes to copy from source
 *
 * @return Number of characters copied (excluding null terminator)
 *
 * @retval 0 If dst_size is 0 or either pointer is NULL
 *
 * @note Stops early if a null byte is found within src_len bytes
 * @note Always null-terminates the destination if dst_size > 0
 *
 * @par Example:
 * @code
 * char buf[32];
 * // Copy first 5 characters of a longer string
 * safe_strncpy(buf, sizeof(buf), "hello world", 5);
 * // buf == "hello"
 * @endcode
 */
size_t safe_strncpy(char *dst, size_t dst_size, const char *src, size_t src_len);

/**
 * @brief Safely copy memory with bounds checking
 *
 * Copies src_len bytes from src to dst, but never more than dst_size.
 * Unlike string functions, this does not null-terminate.
 *
 * @param[out] dst      Destination buffer
 * @param[in]  dst_size Size of destination buffer in bytes
 * @param[in]  src      Source buffer
 * @param[in]  src_len  Number of bytes to copy from source
 *
 * @return Number of bytes actually copied (min of src_len, dst_size)
 *
 * @retval 0 If dst_size is 0 or either pointer is NULL
 *
 * @warning Does not handle overlapping memory regions; use safe_memmove()
 *          for overlapping buffers
 *
 * @par Example:
 * @code
 * uint8_t dest[100];
 * size_t copied = safe_memcpy(dest, sizeof(dest), large_buffer, 1000);
 * // copied == 100, only first 100 bytes copied
 * @endcode
 */
size_t safe_memcpy(void *dst, size_t dst_size, const void *src, size_t src_len);

/**
 * @brief Safely concatenate strings
 *
 * Appends src to the end of dst, ensuring the total length does not
 * exceed dst_size and the result is null-terminated.
 *
 * @param[in,out] dst      Destination buffer containing a null-terminated string
 * @param[in]     dst_size Total size of destination buffer in bytes
 * @param[in]     src      Source null-terminated string to append
 *
 * @return Total length of the concatenated string (dst_len + src_len).
 *         If this exceeds dst_size, the result was truncated.
 *
 * @retval 0 If dst_size is 0 or either pointer is NULL
 *
 * @note Compare return value with dst_size to detect truncation
 * @note If dst is already full, no characters are appended but the
 *       return value still indicates what the full length would be
 *
 * @par Example:
 * @code
 * char buf[20] = "Hello";
 * size_t total = safe_strcat(buf, sizeof(buf), " World!");
 * // total == 12, buf == "Hello World!"
 *
 * total = safe_strcat(buf, sizeof(buf), " This is too long");
 * // total > 20 (truncated), buf == "Hello World! This i"
 * @endcode
 */
size_t safe_strcat(char *dst, size_t dst_size, const char *src);

/**
 * @brief Securely clear memory (cannot be optimized away)
 *
 * Clears memory in a way that cannot be removed by compiler optimization.
 * Essential for clearing sensitive data like passwords, cryptographic keys,
 * or session tokens before freeing memory.
 *
 * Uses C23 memset_explicit when available, with a volatile pointer
 * fallback for older compilers.
 *
 * @param[out] ptr Pointer to memory to clear
 * @param[in]  len Number of bytes to clear
 *
 * @warning Regular memset() calls may be optimized away if the compiler
 *          determines the memory is not read after clearing. Always use
 *          this function for security-sensitive data.
 *
 * @note Safe to call with NULL ptr or zero len (no-op)
 *
 * @par Example:
 * @code
 * char password[64];
 * // ... use password ...
 *
 * // Securely clear before function return
 * safe_memclear(password, sizeof(password));
 * @endcode
 */
void safe_memclear(void *ptr, size_t len);

/**
 * @brief Safely move memory with bounds checking
 *
 * Moves src_len bytes from src to dst, handling overlapping regions
 * correctly. Never moves more than dst_size bytes.
 *
 * @param[out] dst      Destination buffer
 * @param[in]  dst_size Size of destination buffer in bytes
 * @param[in]  src      Source buffer (may overlap with dst)
 * @param[in]  src_len  Number of bytes to move from source
 *
 * @return Number of bytes actually moved (min of src_len, dst_size)
 *
 * @retval 0 If dst_size is 0 or either pointer is NULL
 *
 * @note Unlike safe_memcpy(), this correctly handles overlapping regions
 *
 * @par Example:
 * @code
 * char buf[] = "Hello World";
 * // Shift content left, overlapping regions
 * safe_memmove(buf, sizeof(buf), buf + 6, 5);
 * // buf == "World World" (first 5 bytes overwritten)
 * @endcode
 */
size_t safe_memmove(void *dst, size_t dst_size, const void *src, size_t src_len);

/** @} */ /* end of safe_string group */

#endif /* SAFE_STR_H */
