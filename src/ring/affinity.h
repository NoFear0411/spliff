/**
 * @file affinity.h
 * @brief Worker affinity check and per-worker MPSC overflow queue
 *
 * @details When workers dequeue from the shared SPMC ring, stateful events
 * (HTTP/2, WebSocket) may land on the wrong worker. This module provides:
 *
 * 1. **Affinity check**: Inline routing decision — process locally or defer.
 *
 * 2. **Overflow queue**: Per-worker MPSC (Multiple-Producer Single-Consumer)
 *    ring where other workers push misrouted stateful events. The home worker
 *    drains this "priority inbox" before polling the main SPMC ring.
 *
 * @par MPSC / SPMC Symmetry
 * @code
 *   SPMC Ring (main transport):
 *     Producer: single (dispatcher)  -> plain head advance
 *     Consumer: multiple (workers)   -> CAS tail advance
 *
 *   MPSC Overflow (per-worker inbox):
 *     Producer: multiple (workers)   -> CAS head advance (TTAS)
 *     Consumer: single (home worker) -> plain tail advance (zero CAS!)
 * @endcode
 *
 * Both use Vyukov bounded-queue sequences for torn-read safety on 56-byte
 * events. The MPSC push uses TTAS (Test and Test-and-Set): loads the slot
 * sequence in Shared MESI state before attempting the CAS, preventing
 * coherency storms on the head cache line.
 *
 * @par Cache Isolation (MESI Protocol)
 * Producer stats (push_fails) are co-located with the producer's head on
 * the same 128-byte cache line. Consumer stats (drains) are on the
 * consumer's tail line. Neither side ever touches the other's line.
 *
 * The consumer uses @c tail+mask+1 to release slots (equivalent to
 * @c tail+capacity) to avoid loading @c capacity from the producer's
 * line — preventing an RFO (Request For Ownership) stall.
 *
 * @par Acquire Fence in Drain
 * After confirming a slot is ready (seq == tail + 1), the consumer issues
 * @c ck_pr_fence_load() before reading event data. This pairs with the
 * producer's @c ck_pr_fence_release() before publishing, ensuring the
 * consumer sees the producer's complete memcpy on weakly-ordered
 * architectures (ARM). On x86 TSO, this compiles to a compiler barrier
 * (zero instructions).
 *
 * @par Future Worker Integration (Phase 2.3)
 * @code
 *   while (running) {
 *       // Priority 1: Drain overflow inbox (zero CAS, highest priority)
 *       n = affinity_overflow_drain(&my_overflow, events, batch);
 *       process_events(events, n);
 *
 *       // Priority 2: Dequeue from shared SPMC ring
 *       n = spmc_ring_dequeue_batch(ring, events, batch);
 *       for (i = 0; i < n; i++) {
 *           switch (affinity_check(&events[i], my_id)) {
 *           case AFFINITY_LOCAL:
 *               process_event(&events[i]);
 *               break;
 *           case AFFINITY_DEFER:
 *               target = ring_event_preferred_worker(&events[i]);
 *               if (!affinity_overflow_push(&workers[target].overflow,
 *                                           &events[i])) {
 *                   process_event_slow_path(&events[i]);
 *                   misrouted_local_hits++;
 *               }
 *               break;
 *           }
 *       }
 *   }
 * @endcode
 *
 * @par Monitoring: misrouted_local_hits
 * When affinity_overflow_push() fails, the caller should increment a
 * per-worker @c misrouted_local_hits counter and process locally. If this
 * counter spikes, it indicates either:
 * - Overflow queues too small (increase AFFINITY_OVERFLOW_CAPACITY)
 * - Poor hash distribution (socket_cookie % num_workers is skewed)
 *
 * @see src/ring/spmc_ring.h Main event transport
 * @see src/ring/ring_event.h Event structure with routing word
 * @see docs/ARCHITECTURE-DECISIONS.md ADR-001
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef SPLIFF_AFFINITY_H
#define SPLIFF_AFFINITY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <ck_pr.h>

#include "../memory/alignment.h"
#include "ring_event.h"

/**
 * @defgroup affinity Worker Affinity
 * @brief Affinity check and MPSC overflow queue for SPMC dispatch
 * @{
 */

/*============================================================================
 * Configuration
 *============================================================================*/

/**
 * @brief Overflow queue capacity per worker (power of 2)
 *
 * Sized for burst misrouting under load. At 4 workers with 8192-slot SPMC,
 * a worker might grab ~2048 events per poll, of which ~10-20% are stateful
 * and misrouted. 64 slots handles burst without blocking.
 *
 * If full, the caller processes locally (slow path) rather than dropping.
 */
#define AFFINITY_OVERFLOW_CAPACITY  64

/** Mask for overflow capacity (avoids division on hot path) */
#define AFFINITY_OVERFLOW_MASK      (AFFINITY_OVERFLOW_CAPACITY - 1)

/*============================================================================
 * Affinity Decision
 *============================================================================*/

/**
 * @brief Routing decision for a dequeued event
 */
typedef enum {
    /** Process on current worker (stateless, or I am the preferred worker) */
    AFFINITY_LOCAL,

    /** Defer to preferred worker's overflow queue (stateful, wrong worker) */
    AFFINITY_DEFER,
} affinity_decision_t;

/**
 * @brief Check if event should be processed locally or deferred
 *
 * Fast inline check on the routing word. Stateless events (H1, XDP meta)
 * always return AFFINITY_LOCAL. Stateful events (H2, WebSocket) compare
 * preferred_worker against my_worker_id.
 *
 * Branch hints: most traffic is stateless H1 (first branch taken), and
 * the dispatcher usually routes stateful events correctly (second branch).
 *
 * @param event         Event dequeued from SPMC ring
 * @param my_worker_id  This worker's ID (0-based)
 * @return AFFINITY_LOCAL or AFFINITY_DEFER
 */
static inline affinity_decision_t
affinity_check(const ring_event_t *event, uint8_t my_worker_id)
{
    /* Most traffic is stateless H1 — any worker can process */
    if (__builtin_expect(!ring_event_is_stateful(event), 1))
        return AFFINITY_LOCAL;

    /* Stateful — dispatcher usually routes correctly */
    if (__builtin_expect(
            ring_event_preferred_worker(event) == my_worker_id, 1))
        return AFFINITY_LOCAL;

    /* Not my event — defer to preferred worker's overflow queue */
    return AFFINITY_DEFER;
}

/*============================================================================
 * MPSC Overflow Slot (64 bytes = 1 hardware cache line)
 *============================================================================*/

/**
 * @brief Overflow slot with Vyukov sequence (same layout as spmc_slot_t)
 *
 * @par Vyukov Sequence Protocol (MPSC variant)
 * @code
 *   seq == pos              Slot free, producers may claim via CAS
 *   seq == pos + 1          Data ready, consumer may read
 *   seq == pos + mask + 1   Slot released by consumer (next producer lap)
 * @endcode
 */
typedef struct mpsc_slot {
    uint64_t seq;           /**< Vyukov turn indicator (ck_pr atomic) */
    ring_event_t event;     /**< 56-byte event payload */
} mpsc_slot_t;

static_assert(sizeof(mpsc_slot_t) == 64);

/*============================================================================
 * MPSC Overflow Queue Structure (Per-Worker)
 *============================================================================*/

/**
 * @brief Per-worker MPSC overflow queue for misrouted stateful events
 *
 * @par Memory Layout (2 x 128-byte cache lines + inline slots)
 * @code
 *   [0x000..0x07F]  Producer: head, head_mask, push_fails
 *   [0x080..0x0FF]  Consumer: tail, tail_mask, drains
 *   [0x100...]      Slots: mpsc_slot_t[AFFINITY_OVERFLOW_CAPACITY]
 * @endcode
 *
 * @par Cache Isolation
 * Producer stats (push_fails) share the producer line — producers already
 * own this line via CAS on head. Consumer stats (drains) share the consumer
 * line — only the home worker touches it. Neither side ever causes an RFO
 * stall on the other's line. Total pushes can be derived: drains + depth.
 */
typedef struct affinity_overflow {

    /*--- Producer cache line (CAS-contended by N-1 workers) -------------*/

    CACHE_ALIGNED uint64_t head;        /**< Next write position (CAS) */
    uint64_t head_mask;                 /**< capacity - 1 (local copy) */
    uint64_t push_fails;               /**< Push rejected (queue full) */

    /*--- Consumer cache line (home worker only, zero CAS) ---------------*/

    CACHE_ALIGNED uint64_t tail;        /**< Next read position (plain) */
    uint64_t tail_mask;                 /**< capacity - 1 (local copy) */
    uint64_t drains;                   /**< Total events drained */

    /** Pad consumer line so slots start at next 128-byte boundary */
    char _consumer_pad[CACHELINE_SIZE - 3 * sizeof(uint64_t)];

    /*--- Slot array (inline, fixed capacity) ----------------------------*/

    mpsc_slot_t slots[AFFINITY_OVERFLOW_CAPACITY];

} affinity_overflow_t;

static_assert(offsetof(affinity_overflow_t, tail) == 128);
static_assert(offsetof(affinity_overflow_t, slots) == 256);

/*============================================================================
 * Lifecycle
 *============================================================================*/

/**
 * @brief Initialize an overflow queue
 *
 * Zeroes structure, sets masks on both producer and consumer lines,
 * initializes Vyukov sequences: @c slots[i].seq = i (all slots free).
 *
 * Must be called before any push/drain.
 *
 * @param queue  Overflow queue to initialize
 */
void affinity_overflow_init(affinity_overflow_t *queue);

/*============================================================================
 * MPSC Operations
 *============================================================================*/

/**
 * @brief Push a misrouted event to a worker's overflow queue
 *
 * MPSC producer (CAS on head). Uses TTAS (Test and Test-and-Set):
 * loads slot sequence in Shared MESI state before CAS to prevent
 * coherency storms.
 *
 * The 56-byte event is hot in the pusher's L1 (just dequeued from SPMC
 * ring). The __builtin_memcpy transfers it to the target worker's L2/L3.
 *
 * @par Non-Temporal Optimization (Future)
 * If misrouted throughput becomes significant, the 56-byte copy can use
 * @c _mm256_stream_si256 (AVX) to bypass the pusher's cache and write
 * directly to RAM, preventing cache pollution.
 *
 * @par Batch Optimization (Future)
 * If a worker needs to defer multiple events to the same target, batch
 * them locally and push in a tight loop to reduce CAS contention.
 *
 * @param queue  Target worker's overflow queue
 * @param event  Event to defer (copied into queue slot)
 * @return true on success, false if queue full
 *
 * @note On failure, caller should process locally (slow path) and
 *       increment its per-worker @c misrouted_local_hits counter.
 */
bool affinity_overflow_push(affinity_overflow_t *queue,
                            const ring_event_t *event);

/**
 * @brief Drain overflow queue (home worker only)
 *
 * Single-consumer drain with zero CAS overhead. Called at the start of
 * each worker iteration, before polling the SPMC ring.
 *
 * Uses @c ck_pr_fence_load() (acquire) after sequence check to prevent
 * speculative reads of event data on weakly-ordered architectures.
 * Uses @c tail+mask+1 to release slots, avoiding cross-line loads.
 * Prefetches the next slot while processing the current one.
 *
 * @param queue      This worker's overflow queue
 * @param out        Output array (must hold max_count events)
 * @param max_count  Maximum events to drain
 * @return Number of events drained (0 if empty)
 *
 * @warning NOT thread-safe on the consumer side. Only the home worker
 *          (owner of this overflow queue) may call this function.
 */
uint32_t affinity_overflow_drain(affinity_overflow_t *queue,
                                 ring_event_t *out,
                                 uint32_t max_count);

/*============================================================================
 * Diagnostics (Inline)
 *============================================================================*/

/** Approximate number of events pending in overflow queue */
static inline uint64_t
affinity_overflow_depth(const affinity_overflow_t *queue)
{
    if (!queue) return 0;
    uint64_t h = ck_pr_load_64(
        &((affinity_overflow_t *)queue)->head);
    uint64_t t = queue->tail;
    return h - t;
}

/** Check if overflow queue is empty */
static inline bool
affinity_overflow_empty(const affinity_overflow_t *queue)
{
    return affinity_overflow_depth(queue) == 0;
}

/** Total push failures (queue full, caller processed locally) */
static inline uint64_t
affinity_overflow_stat_push_fails(const affinity_overflow_t *queue)
{
    return queue ? ck_pr_load_64(
        &((affinity_overflow_t *)queue)->push_fails) : 0;
}

/** Total events drained by home worker */
static inline uint64_t
affinity_overflow_stat_drains(const affinity_overflow_t *queue)
{
    return queue ? ck_pr_load_64(
        &((affinity_overflow_t *)queue)->drains) : 0;
}

/** @} */ /* end of affinity group */

#endif /* SPLIFF_AFFINITY_H */
