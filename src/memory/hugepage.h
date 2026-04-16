/**
 * @file hugepage.h
 * @brief Hugepage availability checking and allocation utilities
 *
 * @details Provides standalone utilities for hugepage management, separate
 * from the mirrored buffer implementation. This module enables:
 *
 * - **Pre-flight checks**: Verify hugepage availability before allocation
 * - **Observability**: Log status for troubleshooting performance issues
 * - **Future expansion**: Ready for EDR components like pattern matching engines
 *
 * @par Why a Separate Module:
 * While mirrored_buffer.c handles its own hugepage allocation, isolating
 * the availability checks provides:
 *
 * 1. Graceful fallback decisions before memfd_create() can fail
 * 2. Diagnostic logging when hugepages are exhausted by other services
 * 3. Reusable allocator for future large-memory components (Hyperscan scratch, etc.)
 *
 * @par Integration Pattern:
 * @code
 * // During initialization
 * hugepage_log_status();  // Log what we're working with
 *
 * size_t needed = 128;    // 128 × 2MB = 256MB
 * bool use_huge = (hugepage_free_count() >= needed);
 *
 * // Create mirrored buffer with informed decision
 * mirrored_buffer_t *buf = mirrored_buffer_create_ex(size, use_huge);
 * @endcode
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef SPLIFF_HUGEPAGE_H
#define SPLIFF_HUGEPAGE_H

#include <stddef.h>
#include <stdbool.h>

/**
 * @defgroup hugepage Hugepage Utilities
 * @brief Availability checking and allocation for 2MB hugepages
 * @{
 */

/**
 * @brief Standard hugepage size (2MB)
 *
 * Linux x86_64 supports 2MB and 1GB hugepages.
 * 2MB is the "sweet spot" - provides 99% TLB reduction while remaining
 * reliable across server fleets (1GB pages are brittle due to fragmentation).
 */
#define HUGEPAGE_SIZE_2MB (2UL * 1024 * 1024)

/**
 * @brief Get count of free 2MB hugepages available
 *
 * Parses /proc/meminfo to read HugePages_Free value. Uses direct buffer
 * read and pointer-walk to stay fast and avoid allocations.
 *
 * @return Number of free hugepages, or 0 if unavailable/error
 *
 * @note This is a point-in-time check. Other processes may allocate
 *       hugepages between this check and your allocation attempt.
 *
 * @par Performance:
 * Uses O(1) stack buffer and simple strstr() - no heap allocation,
 * suitable for calling from hot paths if needed.
 */
size_t hugepage_free_count(void);

/**
 * @brief Get total configured hugepages
 *
 * Parses /proc/meminfo to read HugePages_Total value.
 *
 * @return Total configured hugepages, or 0 if not configured
 */
size_t hugepage_total_count(void);

/**
 * @brief Log current hugepage status for diagnostics
 *
 * Logs hugepage availability to aid troubleshooting. If hugepages are
 * exhausted (common when databases grab them all), this log entry
 * explains why the agent lost "line speed" performance.
 *
 * @note Uses DEBUG_LOG for normal status, LOG_ERR when unavailable.
 *
 * @par Example Output:
 * @code
 * [DEBUG] HUGEPAGE_STATUS: 128/256 free pages. Ready for high-speed mirroring.
 * [ERROR] HUGEPAGE_STATUS: 0/0 available. Performance will be degraded (4KB pages).
 * @endcode
 */
void hugepage_log_status(void);

/**
 * @brief Check if hugepages are available for a given size
 *
 * Convenience function to check if enough hugepages exist for an allocation.
 *
 * @param size_bytes Size in bytes to check (will be rounded to 2MB pages)
 * @return true if enough free hugepages exist, false otherwise
 *
 * @par Example:
 * @code
 * if (hugepage_check_available(256 * 1024 * 1024)) {
 *     // 256MB of hugepages available
 *     use_hugepages = true;
 * }
 * @endcode
 */
bool hugepage_check_available(size_t size_bytes);

/**
 * @brief Calculate number of 2MB pages needed for a size
 *
 * @param size_bytes Size in bytes
 * @return Number of 2MB pages (rounded up)
 */
static inline size_t hugepage_pages_needed(size_t size_bytes) {
    return (size_bytes + HUGEPAGE_SIZE_2MB - 1) / HUGEPAGE_SIZE_2MB;
}

/**
 * @brief Allocate memory using hugepages (general purpose)
 *
 * Allocates memory using MAP_HUGETLB for non-mirrored use cases
 * (e.g., Hyperscan scratch space, signature databases).
 *
 * @param size Size in bytes (will be rounded up to 2MB boundary)
 * @return Pointer to allocated memory, or NULL on failure
 *
 * @warning Caller must use hugepage_free() to release the memory.
 * @note Falls back to regular mmap if hugepages unavailable.
 */
void *hugepage_alloc(size_t size);

/**
 * @brief Allocate hugepage memory with explicit fallback control
 *
 * @param size            Size in bytes
 * @param allow_fallback  If true, fall back to regular pages on failure
 * @param used_hugepages  Output: true if hugepages were actually used (may be NULL)
 *
 * @return Pointer to allocated memory, or NULL on failure
 */
void *hugepage_alloc_ex(size_t size, bool allow_fallback, bool *used_hugepages);

/**
 * @brief Free memory allocated with hugepage_alloc()
 *
 * @param ptr  Pointer returned by hugepage_alloc()
 * @param size Size that was requested (needed for munmap)
 *
 * @note Safe to call with NULL ptr (no-op).
 */
void hugepage_free(void *ptr, size_t size);

/**
 * @brief Align size up to 2MB hugepage boundary
 *
 * @param size Size to align
 * @return Size rounded up to next 2MB boundary
 */
static inline size_t hugepage_align(size_t size) {
    return (size + HUGEPAGE_SIZE_2MB - 1) & ~(HUGEPAGE_SIZE_2MB - 1);
}

/** @} */ /* end of hugepage group */

#endif /* SPLIFF_HUGEPAGE_H */
