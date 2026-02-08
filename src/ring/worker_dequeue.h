/**
 * @file worker_dequeue.h
 * @brief Three-phase worker event consumption from SPMC ring with affinity routing
 *
 * @details Orchestrates the per-worker dequeue pattern:
 *
 * @par Three-Phase Consumption
 * @code
 *   Phase 1: Drain MPSC overflow inbox    (zero CAS, highest priority)
 *   Phase 2: Batch dequeue from SPMC ring (single CAS for N slots)
 *   Phase 3: Affinity-route SPMC events   (local → output, defer → overflow)
 * @endcode
 *
 * The caller receives a flat array of events that are all safe to process
 * locally. Deferred events are pushed to target workers' overflow queues
 * internally — the caller never sees them.
 *
 * @par BP_CRITICAL Fast Path
 * When backpressure reaches CRITICAL, affinity routing is skipped entirely.
 * All events are processed locally regardless of preferred_worker. This
 * prevents overflow queue pressure from compounding ring pressure.
 * A @c forced_local counter tracks how many stateful events were affected.
 *
 * @par Hop-Limit Guard
 * Events arriving from the overflow inbox have EVENT_FLAG_ROUTED set.
 * These are always processed locally (Phase 1 output goes straight to
 * the caller). During Phase 3, events deferred to overflow are marked
 * ROUTED before push — the receiving worker will process them locally
 * on next drain, preventing ping-pong oscillation.
 *
 * @par Performance Notes
 * - Scratch buffer for SPMC batch lives on the stack (32 × 56B = 1.75KB)
 * - Affinity decision is a single branch on the routing word
 * - __builtin_expect hints on the defer path (rare for H1 traffic)
 * - Prefetch of routing words 2 events ahead during affinity scan
 * - Skip-affinity flag hoisted outside the per-event loop
 *
 * @par Re-Check Before Sleep
 * After poll returns 0, the caller should use worker_dequeue_has_work()
 * before entering epoll_wait. This catches events that arrived between
 * the empty SPMC dequeue and the sleep decision.
 *
 * @see src/ring/spmc_ring.h       SPMC ring transport
 * @see src/ring/affinity.h        Affinity check and MPSC overflow
 * @see src/ring/backpressure.h    Backpressure levels
 * @see src/ring/adaptive_poll.h   Polling timeout computation (Task #15)
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef SPLIFF_WORKER_DEQUEUE_H
#define SPLIFF_WORKER_DEQUEUE_H

#include <stdint.h>
#include <stdbool.h>

#include "../memory/alignment.h"
#include "ring_event.h"
#include "spmc_ring.h"
#include "affinity.h"
#include "backpressure.h"

/**
 * @defgroup worker_dequeue Worker Dequeue
 * @brief Three-phase event consumption with affinity routing
 * @{
 */

/*============================================================================
 * Configuration
 *============================================================================*/

/**
 * @brief Default SPMC batch size per poll iteration
 *
 * Trades latency (smaller → lower tail latency) against throughput
 * (larger → fewer CAS operations per event). 16 is the sweet spot
 * for 4-worker configurations.
 */
#define WORKER_DEQUEUE_BATCH_DEFAULT    SPMC_BATCH_DEFAULT  /* 16 */

/**
 * @brief Maximum events a single poll can return
 *
 * Overflow drain (up to AFFINITY_OVERFLOW_CAPACITY) + SPMC batch
 * (up to SPMC_BATCH_MAX). Caller's output buffer must be at least
 * this large.
 */
#define WORKER_DEQUEUE_MAX_EVENTS \
    (AFFINITY_OVERFLOW_CAPACITY + SPMC_BATCH_MAX)  /* 64 + 32 = 96 */

/*============================================================================
 * Statistics
 *============================================================================*/

/**
 * @brief Per-worker dequeue statistics
 *
 * All fields are worker-private (no cross-thread access needed).
 * Updated on every poll iteration. Provides operational visibility
 * into event routing and backpressure behavior.
 */
typedef struct worker_dequeue_stats {
    uint64_t processed;         /**< Events returned for local processing */
    uint64_t deferred;          /**< Events pushed to other workers' overflow */
    uint64_t from_overflow;     /**< Events received from own overflow inbox */
    uint64_t misrouted_local;   /**< Wrong-affinity events, overflow full */
    uint64_t forced_local;      /**< Stateful events forced local (BP_CRITICAL) */
    uint64_t polls;             /**< Total worker_dequeue_poll() calls */
    uint64_t empty_polls;       /**< Polls that returned 0 events */
} worker_dequeue_stats_t;

/*============================================================================
 * Context
 *============================================================================*/

/**
 * @brief Per-worker dequeue context
 *
 * Initialized once per worker thread, passed to every poll call.
 * Contains pointers to shared infrastructure (ring, overflow queues)
 * and worker-private statistics.
 *
 * @par Cache Layout
 * @code
 *   [0x000..0x003]  worker_id, num_workers, batch_size, pad
 *   [0x004..0x00F]  ring ptr, overflows ptr
 *   [0x080..0x0BF]  stats (worker-private, separate cache line)
 * @endcode
 */
typedef struct worker_dequeue_ctx {
    uint8_t     worker_id;      /**< This worker's ID (0-based) */
    uint8_t     num_workers;    /**< Total worker count */
    uint16_t    batch_size;     /**< SPMC batch size to request */
    uint8_t     _pad[4];        /**< Alignment padding */

    spmc_ring_t             *ring;      /**< Shared SPMC ring (read-only ptr) */
    affinity_overflow_t     *overflows; /**< Overflow queues array [num_workers] */

    /** Worker-private stats on separate cache line */
    CACHE_ALIGNED worker_dequeue_stats_t stats;
} worker_dequeue_ctx_t;

/*============================================================================
 * Lifecycle
 *============================================================================*/

/**
 * @brief Initialize worker dequeue context
 *
 * Must be called once per worker thread before any poll calls.
 * Does not allocate memory — all storage is provided by the caller.
 *
 * @param ctx         Context to initialize (must not be NULL)
 * @param worker_id   This worker's ID (0-based, must be < num_workers)
 * @param num_workers Total worker count (must be >= 1)
 * @param ring        Shared SPMC ring (must not be NULL)
 * @param overflows   Array of overflow queues, one per worker (must not be NULL)
 * @return true on success, false on invalid args
 */
bool worker_dequeue_init(worker_dequeue_ctx_t *ctx,
                         uint8_t worker_id,
                         uint8_t num_workers,
                         spmc_ring_t *ring,
                         affinity_overflow_t *overflows);

/*============================================================================
 * Main Poll Operation
 *============================================================================*/

/**
 * @brief Poll for events using three-phase consumption
 *
 * Returns events that this worker should process locally. Internally
 * routes misrouted stateful events to the correct worker's overflow queue.
 *
 * @par Phase 1: Overflow Drain
 * Drains this worker's MPSC overflow inbox. These events were deferred
 * by other workers and have EVENT_FLAG_ROUTED set. Zero CAS overhead.
 * Up to (max_count) events from overflow.
 *
 * @par Phase 2: SPMC Batch Dequeue
 * Claims a batch of events from the shared ring via single CAS.
 * Batch size is min(ctx->batch_size, remaining capacity in output).
 *
 * @par Phase 3: Affinity Route
 * Scans SPMC batch events. Stateless events and correctly-routed
 * stateful events go to the output array. Misrouted stateful events
 * are marked ROUTED and pushed to the target worker's overflow.
 * Under BP_CRITICAL, all events go to output (affinity skipped).
 *
 * @param ctx        Worker dequeue context
 * @param out        Output array (must hold WORKER_DEQUEUE_MAX_EVENTS)
 * @param max_count  Maximum events to return (clamped to MAX_EVENTS)
 * @param bp_level   Current backpressure level from dispatcher
 * @return Number of events in @p out ready for local processing
 */
uint32_t worker_dequeue_poll(worker_dequeue_ctx_t *ctx,
                             ring_event_t *out,
                             uint32_t max_count,
                             bp_level_t bp_level);

/*============================================================================
 * Re-Check Helper
 *============================================================================*/

/**
 * @brief Check if this worker has pending work
 *
 * Returns true if either the overflow inbox or the SPMC ring has events.
 * Call this between an empty poll result and epoll_wait to catch events
 * that arrived after the empty dequeue but before the sleep decision.
 *
 * @param ctx  Worker dequeue context
 * @return true if overflow or ring has events, false if safe to sleep
 */
static inline bool
worker_dequeue_has_work(const worker_dequeue_ctx_t *ctx)
{
    if (!ctx) return false;

    /* Check overflow inbox first (cheaper, no cross-line read) */
    if (!affinity_overflow_empty(&ctx->overflows[ctx->worker_id]))
        return true;

    /* Check SPMC ring (reads shared tail, one cross-line load) */
    return !spmc_ring_empty(ctx->ring);
}

/*============================================================================
 * Statistics Accessors (Inline)
 *============================================================================*/

/** Total events returned for local processing */
static inline uint64_t
worker_dequeue_stat_processed(const worker_dequeue_ctx_t *ctx) {
    return ctx ? ctx->stats.processed : 0;
}

/** Total events deferred to other workers */
static inline uint64_t
worker_dequeue_stat_deferred(const worker_dequeue_ctx_t *ctx) {
    return ctx ? ctx->stats.deferred : 0;
}

/** Events received from own overflow inbox */
static inline uint64_t
worker_dequeue_stat_from_overflow(const worker_dequeue_ctx_t *ctx) {
    return ctx ? ctx->stats.from_overflow : 0;
}

/** Wrong-affinity events processed locally (overflow was full) */
static inline uint64_t
worker_dequeue_stat_misrouted_local(const worker_dequeue_ctx_t *ctx) {
    return ctx ? ctx->stats.misrouted_local : 0;
}

/** Stateful events forced local under BP_CRITICAL */
static inline uint64_t
worker_dequeue_stat_forced_local(const worker_dequeue_ctx_t *ctx) {
    return ctx ? ctx->stats.forced_local : 0;
}

/** Total poll iterations */
static inline uint64_t
worker_dequeue_stat_polls(const worker_dequeue_ctx_t *ctx) {
    return ctx ? ctx->stats.polls : 0;
}

/** Polls that returned 0 events */
static inline uint64_t
worker_dequeue_stat_empty_polls(const worker_dequeue_ctx_t *ctx) {
    return ctx ? ctx->stats.empty_polls : 0;
}

/** @} */ /* end of worker_dequeue group */

#endif /* SPLIFF_WORKER_DEQUEUE_H */
