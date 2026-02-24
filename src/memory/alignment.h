/**
 * @file alignment.h
 * @brief Cache-line alignment and memory layout infrastructure
 *
 * @details This header provides macros and utilities for cache-line aligned
 * memory allocation and structure padding. Proper alignment is critical for:
 *
 * - **Avoiding false sharing**: When multiple threads access different fields
 *   of the same cache line, the CPU must invalidate the line across all cores,
 *   causing severe performance degradation.
 *
 * - **Optimizing prefetcher behavior**: Intel's spatial prefetcher fetches
 *   adjacent cache lines. Using 128-byte alignment (2 cache lines) prevents
 *   unintended prefetch-induced sharing.
 *
 * - **SIMD alignment**: AVX-512 requires 64-byte alignment; 128-byte alignment
 *   satisfies this and provides headroom for future instruction sets.
 *
 * @par Usage Example:
 * @code
 * // Align a structure to prevent false sharing
 * typedef struct {
 *     _Atomic uint64_t head;
 *     CACHELINE_PAD(head);  // Pad to next cache line
 *     _Atomic uint64_t tail;
 *     CACHELINE_PAD(tail);
 * } CACHE_ALIGNED ring_indices_t;
 *
 * // Validate buffer sizes at compile time
 * static_assert(IS_POWER_OF_TWO(BUFFER_SIZE), "Buffer must be power of 2");
 * @endcode
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license AGPL-3.0-only
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef SPLIFF_ALIGNMENT_H
#define SPLIFF_ALIGNMENT_H

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @defgroup alignment Cache-Line Alignment
 * @brief Macros for cache-aware memory layout
 * @{
 */

/**
 * @brief Cache line size in bytes
 *
 * Set to 128 bytes (2x hardware cache line) to account for:
 * - Intel spatial prefetcher fetching adjacent lines
 * - AMD's 64-byte lines with 128-byte sector prefetch
 * - Future-proofing for larger cache line sizes
 *
 * @note Hardware cache lines are typically 64 bytes, but using 128 bytes
 *       prevents prefetcher-induced false sharing between adjacent lines.
 */
#define CACHELINE_SIZE 128

/**
 * @brief Align a variable or structure to cache line boundary
 *
 * Use this attribute on structures or variables that will be accessed
 * by multiple threads to prevent false sharing.
 *
 * @par Example:
 * @code
 * typedef struct {
 *     _Atomic uint64_t counter;
 * } CACHE_ALIGNED per_cpu_counter_t;
 * @endcode
 */
#define CACHE_ALIGNED alignas(CACHELINE_SIZE)

/**
 * @brief Pad a structure field to the next cache line boundary
 *
 * Insert after a field to ensure the next field starts on a new cache line.
 * The macro creates an anonymous padding array sized to fill the remainder
 * of the current cache line.
 *
 * @param field The field name to pad after (used to calculate current offset)
 *
 * @par Example:
 * @code
 * typedef struct {
 *     _Atomic uint64_t producer_head;
 *     CACHELINE_PAD(producer_head);  // consumer_tail on separate line
 *     _Atomic uint64_t consumer_tail;
 *     CACHELINE_PAD(consumer_tail);
 * } ring_state_t;
 * @endcode
 *
 * @note The padding is placed in an anonymous union to avoid affecting
 *       the sizeof the previous field when using sizeof in the calculation.
 */
#define CACHELINE_PAD(field) \
    char _pad_##field[CACHELINE_SIZE - sizeof(field) % CACHELINE_SIZE]

/** @} */ /* end of alignment group */

/**
 * @defgroup power_of_two Power-of-Two Utilities
 * @brief Compile-time and runtime checks for power-of-two values
 *
 * Power-of-two buffer sizes enable fast wrap-around using bitwise AND:
 * @code
 * // Fast: offset & (size - 1)
 * // Slow: offset % size
 * @endcode
 * @{
 */

/**
 * @brief Check if a value is a power of two (compile-time safe)
 *
 * Uses the classic bit manipulation trick: a power of two has exactly
 * one bit set, so (n & (n-1)) clears that bit, leaving zero.
 *
 * @param n Value to check (must be > 0 for meaningful result)
 * @return true if n is a power of two, false otherwise
 *
 * @note Returns true for n=0 due to (0 & -1) == 0, but 0 is not
 *       a valid power of two. Callers should check n > 0 separately.
 */
#define IS_POWER_OF_TWO(n) (((n) != 0) && (((n) & ((n) - 1)) == 0))

/**
 * @brief Round up to the next power of two (compile-time for constants)
 *
 * Uses bit manipulation to set all bits below the highest set bit,
 * then adds 1. For values already a power of two, returns the same value.
 *
 * @param n Value to round up (must be <= 2^63 for 64-bit)
 * @return Next power of two >= n
 *
 * @warning Returns 0 for n=0. Callers should validate n > 0.
 */
#define NEXT_POWER_OF_TWO_64(n) \
    ((n) <= 1 ? 1 : \
     (1ULL << (64 - __builtin_clzll((n) - 1))))

/**
 * @brief Calculate wrap-around mask for power-of-two buffer
 *
 * For a power-of-two size, (size - 1) creates a bitmask that can be
 * used with bitwise AND for fast modulo operations.
 *
 * @param size Buffer size (must be power of two)
 * @return Bitmask for wrap-around: offset & WRAP_MASK(size)
 *
 * @par Example:
 * @code
 * #define BUF_SIZE (256 * 1024)  // 256KB
 * #define BUF_MASK WRAP_MASK(BUF_SIZE)
 *
 * size_t wrapped_offset = raw_offset & BUF_MASK;
 * @endcode
 */
#define WRAP_MASK(size) ((size) - 1)

/**
 * @brief Default buffer size for per-flow mirrored buffers
 *
 * 256KB provides good balance between memory usage and payload capture depth.
 * Under memory pressure, the system may downscale to MIN_BUFFER_SIZE.
 */
#define DEFAULT_BUFFER_SIZE (256 * 1024)

/**
 * @brief Minimum buffer size under memory pressure
 *
 * 64KB allows monitoring more flows at reduced capture depth.
 * This supports "breadth over depth" under resource constraints.
 */
#define MIN_BUFFER_SIZE (64 * 1024)

/**
 * @brief Maximum buffer size for per-flow buffers
 *
 * 512KB is the upper limit to prevent single flows from consuming
 * excessive memory. Larger captures should use multiple buffers.
 */
#define MAX_BUFFER_SIZE (512 * 1024)

/** @} */ /* end of power_of_two group */

/**
 * @defgroup ratelimit Rate-Limited Logging
 * @brief Infrastructure for preventing log storms in high-throughput paths
 *
 * Even in debug mode, logging every event at line speed can overflow
 * kernel trace buffers and crash the system. These utilities provide
 * rate-limited logging that samples events rather than logging all.
 * @{
 */

/**
 * @brief Rate limiter state for a single log site
 *
 * Place one instance per log site that needs rate limiting.
 * The structure is designed to be lock-free using atomic operations.
 *
 * @note Uses plain uint64_t with GCC builtins rather than _Atomic types
 *       for compatibility with both userspace and shared memory scenarios.
 *       GCC builtins map directly to hardware atomic instructions.
 */
typedef struct {
    uint64_t count;       /**< Total events since last log (atomic access) */
    uint64_t last_log_ns; /**< Timestamp of last logged event (atomic access) */
    uint64_t suppressed;  /**< Events suppressed since last log (atomic access) */
} ratelimit_state_t;

/**
 * @brief Initialize a rate limiter state
 */
#define RATELIMIT_STATE_INIT { .count = 0, .last_log_ns = 0, .suppressed = 0 }

/**
 * @brief Default rate limit interval (100ms)
 *
 * At most one log message per 100ms per log site.
 */
#define RATELIMIT_INTERVAL_NS (100 * 1000 * 1000)

/**
 * @brief Default burst allowance
 *
 * Allow first N events to log immediately before rate limiting kicks in.
 */
#define RATELIMIT_BURST 5

/**
 * @brief Check if logging should proceed (rate-limited)
 *
 * Call this before logging in hot paths. Returns true if the event
 * should be logged, false if it should be suppressed.
 *
 * @param state     Pointer to rate limiter state for this log site
 * @param now_ns    Current timestamp in nanoseconds
 * @param interval  Minimum interval between logs in nanoseconds
 * @param burst     Number of initial events to allow before limiting
 * @return true if event should be logged, false if suppressed
 *
 * @note Thread-safe via atomic operations, but may allow slight over-logging
 *       under extreme contention (acceptable for debug logging).
 */
static inline bool ratelimit_allow(ratelimit_state_t *state,
                                   uint64_t now_ns,
                                   uint64_t interval,
                                   uint64_t burst) {
    uint64_t count = __atomic_fetch_add(&state->count, 1, __ATOMIC_RELAXED);

    /* Allow initial burst unconditionally */
    if (count < burst) {
        return true;
    }

    uint64_t last = __atomic_load_n(&state->last_log_ns, __ATOMIC_RELAXED);

    /* Check if interval has elapsed */
    if (now_ns - last >= interval) {
        /* Try to claim this log slot */
        if (__atomic_compare_exchange_n(&state->last_log_ns, &last, now_ns,
                                        false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            /* Reset suppressed counter and return count */
            __atomic_store_n(&state->suppressed, 0, __ATOMIC_RELAXED);
            return true;
        }
    }

    /* Suppressed - increment counter */
    __atomic_fetch_add(&state->suppressed, 1, __ATOMIC_RELAXED);
    return false;
}

/**
 * @brief Get count of suppressed events since last log
 *
 * Call after ratelimit_allow() returns true to report how many
 * events were suppressed in the log message.
 *
 * @param state Pointer to rate limiter state
 * @return Number of events suppressed since last log
 */
static inline uint64_t ratelimit_get_suppressed(const ratelimit_state_t *state) {
    return __atomic_load_n(&state->suppressed, __ATOMIC_RELAXED);
}

/** @} */ /* end of ratelimit group */

/**
 * @defgroup memory_pressure Memory Pressure Detection
 * @brief Utilities for adaptive buffer sizing under memory constraints
 * @{
 */

/**
 * @brief Memory pressure levels for adaptive buffer sizing
 */
typedef enum {
    MEM_PRESSURE_NONE = 0,  /**< Normal operation, use DEFAULT_BUFFER_SIZE */
    MEM_PRESSURE_LOW,       /**< Some pressure, consider smaller buffers */
    MEM_PRESSURE_MEDIUM,    /**< Moderate pressure, use MIN_BUFFER_SIZE for new flows */
    MEM_PRESSURE_HIGH       /**< Severe pressure, reject new flow allocations */
} mem_pressure_t;

/** @} */ /* end of memory_pressure group */

#endif /* SPLIFF_ALIGNMENT_H */
