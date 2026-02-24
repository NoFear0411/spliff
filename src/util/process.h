/**
 * @file process.h
 * @brief Process information utilities
 *
 * @details Provides portable functions for querying process metadata
 * from the /proc filesystem. All functions are thread-safe and perform
 * defensive input validation.
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license LGPL-3.0-only
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

#ifndef SPLIFF_PROCESS_H
#define SPLIFF_PROCESS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Get process name from /proc/PID/comm
 *
 * Reads the actual process name (not thread name) from procfs.
 * This is important for multi-threaded applications like Firefox
 * where worker threads have names like "Socket Thread" but we
 * want the actual process name "firefox".
 *
 * @param[in]  pid      Process ID to query (must be > 0)
 * @param[out] buf      Buffer to store null-terminated name
 * @param[in]  bufsize  Size of buffer (should be >= 16 for TASK_COMM_LEN)
 *
 * @return true if name was successfully read, false on error
 *
 * @note Thread-safe. Does not modify global state.
 * @note On failure, buf[0] is set to '\0' if buf is valid.
 *
 * @par Example:
 * @code
 *     char name[64];
 *     if (proc_get_name(1234, name, sizeof(name))) {
 *         printf("Process: %s\n", name);
 *     }
 * @endcode
 */
[[nodiscard]] bool proc_get_name(uint32_t pid, char *buf, size_t bufsize);

/**
 * @brief Check if a process exists
 *
 * @param[in] pid  Process ID to check
 * @return true if process exists, false otherwise
 */
[[nodiscard]] bool proc_exists(uint32_t pid);

#endif /* SPLIFF_PROCESS_H */
