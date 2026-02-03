/**
 * @file xdp_ring.h
 * @brief Per-worker SPSC ring buffer for XDP event delivery
 *
 * @details Implements a lock-free Single-Producer Single-Consumer ring buffer
 * for routing XDP events from the dispatcher to worker threads. This fixes
 * the timing race where workers check FLOW_FLAG_HAS_XDP before XDP events
 * are processed by the dispatcher.
 *
 * @par Problem (Event-Loop Starvation)
 * Workers wait on 100ms epoll timeout while XDP events are handled by the
 * dispatcher thread. Workers check HAS_XDP BEFORE the dispatcher has polled
 * XDP, resulting in missing XDP correlation in HTTP output.
 *
 * @par Solution
 * Route XDP events TO workers (like SSL events) via per-worker SPSC rings
 * with instant eventfd signaling. Workers process XDP events FIRST in their
 * loop, ensuring HAS_XDP is set before HTTP parsing.
 *
 * @par Processing Order in Worker Loop
 * @code
 *   1. FIRST: Process XDP events (sets HAS_XDP)
 *   2. THEN: Process SSL events (checks HAS_XDP)
 *   3. FINALLY: Drain deferred (fallback for edge cases)
 * @endcode
 *
 * @par Thread Safety
 * - Dispatcher is the single producer (pushes events)
 * - Worker is the single consumer (pops events)
 * - Head/tail are cache-line aligned to prevent false sharing
 * - Shares worker's existing eventfd for instant wakeup
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef SPLIFF_XDP_RING_H
#define SPLIFF_XDP_RING_H

#include <stdatomic.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../include/spliff.h"

/**
 * @defgroup xdp_ring_config XDP Ring Configuration
 * @brief Compile-time configuration for XDP SPSC ring
 * @{
 */

/** Ring buffer size - must be power of 2. ~256KB memory per worker. */
#define XDP_RING_SIZE 4096

/** Bitmask for fast modulo on power-of-2 size */
#define XDP_RING_MASK (XDP_RING_SIZE - 1)

/** @} */

/**
 * @defgroup xdp_ring_types XDP Ring Types
 * @brief Data structures for XDP event delivery
 * @{
 */

/* Forward declaration for flow_context_t */
struct flow_context;

/**
 * @brief XDP event for SPSC ring transfer
 *
 * Compact structure containing XDP metadata to be delivered to workers.
 * Workers use this to set FLOW_FLAG_HAS_XDP on flow contexts before
 * processing SSL events.
 *
 * @par Single-Writer Architecture (Thread Safety Fix)
 * The flow_ctx pointer is pre-resolved by the dispatcher (single writer)
 * before routing to workers. This ensures all hash table writes happen
 * in the dispatcher thread, making the CK hs SPMC mode safe.
 */
typedef struct xdp_ring_event {
    uint64_t socket_cookie;     /**< Socket cookie for flow lookup */
    flow_key_t flow;            /**< 5-tuple from XDP (28 bytes) */
    uint64_t timestamp_ns;      /**< Kernel timestamp */
    uint32_t ifindex;           /**< Network interface index */
    uint16_t pkt_len;           /**< Packet length */
    uint8_t category;           /**< XDP category (xdp_category_t) */
    uint8_t direction;          /**< 1=ingress, 2=egress */

    /*=== Single-Writer Architecture Fields ===*/
    struct flow_context *flow_ctx;  /**< Pre-resolved by dispatcher (NULL if not found) */
    uint32_t expected_gen;          /**< Flow generation for stale pointer detection */
    uint32_t _pad;                  /**< Padding for alignment */
} xdp_ring_event_t;

/**
 * @brief Per-worker SPSC ring buffer for XDP events
 *
 * Lock-free ring buffer with cache-line aligned head/tail to prevent
 * false sharing between dispatcher (producer) and worker (consumer).
 * Shares the worker's existing eventfd for instant wakeup signaling.
 *
 * @par Memory Layout
 * - buffer: Fixed array of events (inline, no allocation)
 * - head: Written only by dispatcher (producer)
 * - tail: Written only by worker (consumer)
 * - Both aligned to 64-byte cache lines
 */
typedef struct xdp_ring {
    /** Event buffer - inline for cache efficiency */
    xdp_ring_event_t buffer[XDP_RING_SIZE];

    /** Producer head - cache-line aligned, written by dispatcher */
    alignas(64) _Atomic size_t head;

    /** Consumer tail - cache-line aligned, written by worker */
    alignas(64) _Atomic size_t tail;

    /** Shared eventfd for wakeup (same as worker's wakeup_fd) */
    int wakeup_fd;

    /** @name Statistics (atomic for thread-safe reads) */
    /** @{ */
    _Atomic uint64_t push_count;    /**< Events successfully pushed */
    _Atomic uint64_t drop_count;    /**< Events dropped (ring full) */
    /** @} */
} xdp_ring_t;

/** @} */

/**
 * @defgroup xdp_ring_api XDP Ring API
 * @brief Functions for XDP SPSC ring operations
 * @{
 */

/**
 * @brief Initialize XDP SPSC ring
 *
 * Zeroes the ring buffer and stores the shared wakeup eventfd.
 *
 * @param[out] ring      Ring to initialize
 * @param[in]  wakeup_fd Worker's eventfd (shared for wakeup signaling)
 * @return 0 on success
 */
int xdp_ring_init(xdp_ring_t *ring, int wakeup_fd);

/**
 * @brief Cleanup XDP SPSC ring
 *
 * Currently a no-op since buffer is inline, but provided for
 * future extensibility and API symmetry.
 *
 * @param[in] ring Ring to cleanup
 */
void xdp_ring_cleanup(xdp_ring_t *ring);

/**
 * @brief Push XDP event to ring (dispatcher calls this)
 *
 * Copies event into ring buffer and signals worker via eventfd.
 * Lock-free, single-producer safe.
 *
 * @param[in] ring  Target ring
 * @param[in] event Event to push (copied)
 * @return true on success, false if ring is full (event dropped)
 */
[[nodiscard]]
bool xdp_ring_push(xdp_ring_t *ring, const xdp_ring_event_t *event);

/**
 * @brief Pop all available events from ring (worker calls this)
 *
 * Processes all events currently in the ring by calling the handler
 * function for each. Lock-free, single-consumer safe.
 *
 * @param[in] ring    Source ring
 * @param[in] handler Callback for each event
 * @param[in] ctx     Opaque context passed to handler
 * @return Number of events processed
 */
size_t xdp_ring_pop_all(xdp_ring_t *ring,
                        void (*handler)(const xdp_ring_event_t *, void *),
                        void *ctx);

/**
 * @brief Check if ring is empty
 *
 * @param[in] ring Ring to check
 * @return true if no events in ring
 */
static inline bool xdp_ring_empty(const xdp_ring_t *ring) {
    size_t h = atomic_load_explicit(&ring->head, memory_order_acquire);
    size_t t = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    return h == t;
}

/**
 * @brief Get current ring depth
 *
 * @param[in] ring Ring to check
 * @return Number of events currently in ring
 */
static inline size_t xdp_ring_depth(const xdp_ring_t *ring) {
    size_t h = atomic_load_explicit(&ring->head, memory_order_acquire);
    size_t t = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    return (h - t) & XDP_RING_MASK;
}

/** @} */

#endif /* SPLIFF_XDP_RING_H */
