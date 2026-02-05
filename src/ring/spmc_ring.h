/**
 * @file spmc_ring.h
 * @brief Lock-free SPMC ring buffer using Vyukov sequences and CK primitives
 *
 * @details Bounded Single-Producer Multi-Consumer ring using per-slot sequence
 * numbers for torn-read safety on 56-byte events. The dispatcher (single
 * producer) enqueues tagged events; worker threads (multiple consumers)
 * CAS-compete on a shared tail to claim slots.
 *
 * @par Performance Design
 * - Seq-first slots: consumer checks readiness before touching event data
 * - 128-byte cache-line isolation between head (producer) and tail (consumers)
 * - Duplicated mask on head/tail lines: no cross-line reads on hot path
 * - Three-stage batch enqueue: data copy → fence → publish
 * - CAS backoff via ck_pr_stall() prevents coherency storms
 * - Software prefetching on predictable ring access patterns
 * - FAM allocation: header + slots in one contiguous hugepage-friendly block
 *
 * @par Atomics
 * All atomic operations use Concurrency Kit (ck_pr_*) primitives, not GCC
 * builtins or C11 stdatomic. CK provides architecture-specific optimizations
 * (PAUSE on x86, yield on ARM) and is already a project dependency.
 *
 * @par RCU Integration (Phase 3)
 * The ring pointer can be wrapped in rcu_dereference() for hot-swap:
 * @code
 *   rcu_read_lock();
 *   spmc_ring_t *ring = rcu_dereference(global_ring_ptr);
 *   spmc_ring_dequeue(ring, &ev);
 *   rcu_read_unlock();
 * @endcode
 *
 * @see src/ring/ring_event.h Event structure definition
 * @see docs/ARCHITECTURE-DECISIONS.md ADR-001
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef SPLIFF_SPMC_RING_H
#define SPLIFF_SPMC_RING_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <ck_pr.h>

#include "../memory/alignment.h"
#include "ring_event.h"

/**
 * @defgroup spmc_ring SPMC Ring Buffer
 * @brief Lock-free single-producer multi-consumer ring for event dispatch
 * @{
 */

/*============================================================================
 * Configuration
 *============================================================================*/

/** Default ring capacity (power of 2, consolidates N per-worker SPSC rings) */
#define SPMC_RING_DEFAULT_CAPACITY  8192

/** Default batch size for worker dequeue */
#define SPMC_BATCH_DEFAULT          16

/** Maximum batch size (limits CAS retry scope) */
#define SPMC_BATCH_MAX              32

/** Maximum CAS retries for batch dequeue before giving up */
#ifndef SPMC_BATCH_MAX_RETRIES
#define SPMC_BATCH_MAX_RETRIES      3
#endif

/*============================================================================
 * Ring Slot (64 bytes = 1 hardware cache line)
 *============================================================================*/

/**
 * @brief SPMC ring slot with Vyukov sequence
 *
 * Sequence is FIRST so the consumer's initial cache-line fetch loads
 * the readiness indicator before the event data. If the slot isn't ready,
 * the consumer skips without using the remaining 56 bytes.
 *
 * @par Vyukov Sequence Protocol
 * @code
 *   seq == pos              Slot empty, producer may write at position pos
 *   seq == pos + 1          Data ready, consumers may claim position pos
 *   seq == pos + capacity   Slot freed, available for producer's next cycle
 * @endcode
 */
typedef struct spmc_slot {
    uint64_t seq;              /**< Vyukov turn indicator (ck_pr atomic) */
    ring_event_t event;        /**< 56-byte event payload */
} spmc_slot_t;

_Static_assert(sizeof(spmc_slot_t) == 64,
               "spmc_slot_t must be exactly 64 bytes (1 hardware cache line)");

/*============================================================================
 * Ring Buffer Structure (FAM, cache-line isolated)
 *============================================================================*/

/**
 * @brief SPMC ring with cache-line-isolated hot fields
 *
 * @par Memory Layout (3 × 128-byte project cache lines + FAM slots)
 * @code
 *   [0x000..0x07F]  Producer: head, head_mask, cached_tail
 *   [0x080..0x0FF]  Consumer: tail, tail_mask
 *   [0x100..0x17F]  Config:   capacity, drops, dequeues, cas_retries
 *   [0x180...]      Slots:    FAM, contiguous with header
 * @endcode
 *
 * @warning Allocate via spmc_ring_create() which handles alignment.
 * @warning All threads must stop before spmc_ring_destroy().
 */
typedef struct spmc_ring {

    /*--- Producer cache line (128 bytes, only dispatcher writes) -----------*/

    /** Next write position (monotonically increasing, producer-private) */
    CACHE_ALIGNED uint64_t head;

    /** Capacity mask duplicated on producer line (avoids cross-line load) */
    uint64_t head_mask;

    /**
     * @brief Cached consumer tail for fast full-check in batch enqueue
     *
     * Refreshed via ck_pr_load_64(&tail) only when the fast check fails.
     * Avoids touching the contended tail cache line on the common path.
     */
    uint64_t cached_tail;

    /*--- Consumer cache line (128 bytes, workers CAS here) ----------------*/

    /** Next claim position (workers CAS-compete on this) */
    CACHE_ALIGNED uint64_t tail;

    /** Capacity mask duplicated on consumer line */
    uint64_t tail_mask;

    /*--- Config + Stats cache line (128 bytes, mostly read-only) ----------*/

    CACHE_ALIGNED uint64_t capacity;    /**< Number of slots (power of 2) */
    uint64_t drops;                     /**< Enqueue failures (ring full) */
    uint64_t dequeues;                  /**< Successful dequeues */
    uint64_t cas_retries;               /**< Consumer CAS failures */

    /** Explicit padding so FAM slots[] starts at next 128-byte boundary */
    char _stats_pad[CACHELINE_SIZE - 4 * sizeof(uint64_t)];

    /*--- Slot array (FAM, contiguous with header) -------------------------*/

    /** Ring slots - flexible array member, allocated in single block */
    spmc_slot_t slots[];

} spmc_ring_t;

/*============================================================================
 * Lifecycle
 *============================================================================*/

/**
 * @brief Create an SPMC ring buffer
 *
 * Single contiguous allocation (header + slots) for hugepage friendliness.
 * Initializes Vyukov slot sequences: slots[i].seq = i.
 *
 * @param capacity Number of slots (must be power of 2, >= 4)
 * @return Ring pointer on success, NULL on failure
 */
spmc_ring_t *spmc_ring_create(uint32_t capacity);

/**
 * @brief Destroy an SPMC ring buffer
 *
 * @param ring Ring to destroy (NULL is safe no-op)
 * @warning All threads must have stopped using the ring.
 */
void spmc_ring_destroy(spmc_ring_t *ring);

/*============================================================================
 * Producer Operations (Single Thread — Dispatcher)
 *============================================================================*/

/**
 * @brief Enqueue a single event (single producer)
 *
 * Non-blocking. Checks slot sequence to detect full ring.
 * Uses ck_pr_fence_release() before publishing the sequence.
 *
 * @param ring  Target ring
 * @param event Event to enqueue (copied into slot)
 * @return true on success, false if ring full (event dropped)
 *
 * @warning Single-thread only (the dispatcher).
 */
bool spmc_ring_enqueue(spmc_ring_t *ring, const ring_event_t *event);

/**
 * @brief Batch enqueue up to @p count events (single producer)
 *
 * Three-stage pipeline for write-combining efficiency:
 * 1. DATA: Copy N events into slots (with prefetching)
 * 2. BARRIER: Single ck_pr_fence_release() for all writes
 * 3. PUBLISH: Update N slot sequences in tight loop
 *
 * @param ring   Target ring
 * @param events Array of events to enqueue
 * @param count  Number of events (may be trimmed if ring lacks capacity)
 * @return Number of events actually enqueued
 *
 * @warning Single-thread only (the dispatcher).
 */
uint32_t spmc_ring_enqueue_batch(spmc_ring_t *ring,
                                 const ring_event_t *events,
                                 uint32_t count);

/*============================================================================
 * Consumer Operations (Multiple Threads — Workers)
 *============================================================================*/

/**
 * @brief Dequeue a single event (multi-consumer safe)
 *
 * Workers CAS-compete on the shared tail. On CAS failure,
 * ck_pr_stall() prevents coherency storms before retry.
 *
 * @param ring Ring to dequeue from
 * @param out  Output event (valid only if return is true)
 * @return true if event dequeued, false if ring empty
 */
bool spmc_ring_dequeue(spmc_ring_t *ring, ring_event_t *out);

/**
 * @brief Batch dequeue up to @p max_count events (multi-consumer safe)
 *
 * Claims a contiguous range with a single CAS, amortizing overhead.
 * Retries up to SPMC_BATCH_MAX_RETRIES on CAS failure.
 *
 * @param ring      Ring to dequeue from
 * @param out       Output array (must hold max_count events)
 * @param max_count Maximum events (clamped to SPMC_BATCH_MAX)
 * @return Number of events dequeued (0 if empty or retries exhausted)
 */
uint32_t spmc_ring_dequeue_batch(spmc_ring_t *ring,
                                 ring_event_t *out,
                                 uint32_t max_count);

/*============================================================================
 * Diagnostics (Inline)
 *============================================================================*/

/** Approximate number of events in the ring */
static inline uint64_t spmc_ring_depth(const spmc_ring_t *ring) {
    if (!ring) return 0;
    uint64_t h = ck_pr_load_64(&((spmc_ring_t *)ring)->head);
    uint64_t t = ck_pr_load_64(&((spmc_ring_t *)ring)->tail);
    return h - t;
}

/** Check if ring appears empty */
static inline bool spmc_ring_empty(const spmc_ring_t *ring) {
    return spmc_ring_depth(ring) == 0;
}

/** Check if ring appears full */
static inline bool spmc_ring_full(const spmc_ring_t *ring) {
    if (!ring) return true;
    return spmc_ring_depth(ring) >= ring->capacity;
}

/** Get ring capacity */
static inline uint64_t spmc_ring_get_capacity(const spmc_ring_t *ring) {
    return ring ? ring->capacity : 0;
}

/**
 * @brief Fill ratio (0.0 = empty, 1.0 = full)
 *
 * Useful for backpressure level calculation:
 * @code
 *   0.0 - 0.50  NORMAL
 *   0.50 - 0.75 ELEVATED
 *   0.75 - 0.90 HIGH
 *   0.90 - 1.0  CRITICAL → signal eBPF via backpressure_map
 * @endcode
 */
static inline double spmc_ring_fill_ratio(const spmc_ring_t *ring) {
    if (!ring || ring->capacity == 0) return 1.0;
    uint64_t depth = spmc_ring_depth(ring);
    if (depth >= ring->capacity) return 1.0;
    return (double)depth / (double)ring->capacity;
}

/** Total enqueue failures (ring full) */
static inline uint64_t spmc_ring_stat_drops(const spmc_ring_t *ring) {
    return ring ? ck_pr_load_64(&((spmc_ring_t *)ring)->drops) : 0;
}

/** Total successful dequeues */
static inline uint64_t spmc_ring_stat_dequeues(const spmc_ring_t *ring) {
    return ring ? ck_pr_load_64(&((spmc_ring_t *)ring)->dequeues) : 0;
}

/** Total consumer CAS failures (contention indicator) */
static inline uint64_t spmc_ring_stat_cas_retries(const spmc_ring_t *ring) {
    return ring ? ck_pr_load_64(&((spmc_ring_t *)ring)->cas_retries) : 0;
}

/** @} */ /* end of spmc_ring group */

#endif /* SPLIFF_SPMC_RING_H */
