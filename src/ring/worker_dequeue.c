/**
 * @file worker_dequeue.c
 * @brief Three-phase worker event consumption from SPMC ring with affinity routing
 *
 * @details Implementation of the worker dequeue pattern:
 *
 *   Phase 1: Drain MPSC overflow inbox    (zero CAS, highest priority)
 *   Phase 2: Batch dequeue from SPMC ring (single CAS for N slots)
 *   Phase 3: Affinity-route SPMC events   (local → output, defer → overflow)
 *
 * The caller receives a flat array of events safe for local processing.
 * Deferred events are pushed to target workers' overflow queues internally.
 *
 * @see worker_dequeue.h for API documentation and design rationale
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license LGPL-3.0-only
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

#include "worker_dequeue.h"

#include <string.h>

/*============================================================================
 * Lifecycle
 *============================================================================*/

bool
worker_dequeue_init(worker_dequeue_ctx_t *ctx,
                    uint8_t worker_id,
                    uint8_t num_workers,
                    spmc_ring_t *ring,
                    affinity_overflow_t *overflows)
{
    if (!ctx || !ring || !overflows)
        return false;

    if (num_workers == 0 || worker_id >= num_workers)
        return false;

    memset(ctx, 0, sizeof(*ctx));

    ctx->worker_id   = worker_id;
    ctx->num_workers = num_workers;
    ctx->batch_size  = WORKER_DEQUEUE_BATCH_DEFAULT;
    ctx->ring        = ring;
    ctx->overflows   = overflows;

    return true;
}

/*============================================================================
 * Phase 3: Affinity Routing (internal helper)
 *============================================================================*/

/**
 * @brief Route SPMC batch events by affinity, appending local events to output
 *
 * For each event in the scratch batch:
 * - Stateless events → append to output (most traffic, predicted path)
 * - Correctly-routed stateful events → append to output
 * - Misrouted stateful events → mark ROUTED, push to target overflow
 *   If push fails (overflow full) → process locally, count as misrouted_local
 *
 * Under BP_CRITICAL, affinity is skipped entirely: all events go to output.
 * Stateful events forced local are tracked in forced_local.
 *
 * @param ctx         Worker context (for worker_id, overflows, stats)
 * @param scratch     SPMC batch events to route
 * @param n_scratch   Number of events in scratch
 * @param out         Output array to append to
 * @param out_pos     Current position in output array (updated in place)
 * @param skip_aff    True if BP_CRITICAL (skip all affinity routing)
 */
static void
route_batch(worker_dequeue_ctx_t *ctx,
            ring_event_t *scratch,
            uint32_t n_scratch,
            ring_event_t *out,
            uint32_t *out_pos,
            bool skip_aff)
{
    uint32_t pos = *out_pos;

    /*
     * BP_CRITICAL fast path: skip affinity entirely.
     * Copy all events to output. Track stateful events forced local.
     */
    if (__builtin_expect(skip_aff, 0)) {
        for (uint32_t i = 0; i < n_scratch; i++) {
            if (__builtin_expect(ring_event_is_stateful(&scratch[i]), 0)) {
                uint8_t pref = ring_event_preferred_worker(&scratch[i]);
                if (pref != ctx->worker_id)
                    ctx->stats.forced_local++;
            }
            out[pos++] = scratch[i];
        }
        *out_pos = pos;
        return;
    }

    /*
     * Normal affinity routing.
     * Prefetch routing words 2 events ahead for the affinity decision.
     */
    for (uint32_t i = 0; i < n_scratch; i++) {
        /* Prefetch routing word 2 ahead */
        if (i + 2 < n_scratch)
            __builtin_prefetch(&scratch[i + 2].routing, 0, 1);

        affinity_decision_t decision = affinity_check(&scratch[i],
                                                      ctx->worker_id);

        if (__builtin_expect(decision == AFFINITY_LOCAL, 1)) {
            out[pos++] = scratch[i];
            continue;
        }

        /*
         * AFFINITY_DEFER: push to target worker's overflow queue.
         * Mark ROUTED before push so the receiving worker won't
         * attempt to defer it again (hop-limit guard).
         */
        uint8_t target = ring_event_preferred_worker(&scratch[i]);

        /*
         * Bounds check: if preferred_worker >= num_workers,
         * process locally rather than corrupting memory.
         */
        if (__builtin_expect(target >= ctx->num_workers, 0)) {
            out[pos++] = scratch[i];
            ctx->stats.misrouted_local++;
            continue;
        }

        ring_event_mark_routed(&scratch[i]);

        if (__builtin_expect(
                affinity_overflow_push(&ctx->overflows[target],
                                       &scratch[i]), 1)) {
            ctx->stats.deferred++;
        } else {
            /* Overflow full — process locally (slow path) */
            out[pos++] = scratch[i];
            ctx->stats.misrouted_local++;
        }
    }

    *out_pos = pos;
}

/*============================================================================
 * Main Poll Operation
 *============================================================================*/

uint32_t
worker_dequeue_poll(worker_dequeue_ctx_t *ctx,
                    ring_event_t *out,
                    uint32_t max_count,
                    bp_level_t bp_level)
{
    if (!ctx || !out)
        return 0;

    if (max_count > WORKER_DEQUEUE_MAX_EVENTS)
        max_count = WORKER_DEQUEUE_MAX_EVENTS;

    ctx->stats.polls++;

    uint32_t total = 0;

    /*
     * ── Phase 1: Drain MPSC overflow inbox ──────────────────────────
     *
     * Zero CAS overhead — this worker is the sole consumer.
     * Events here already have EVENT_FLAG_ROUTED set, so they go
     * straight to the output (no further affinity routing needed).
     */
    uint32_t overflow_budget = max_count;
    if (overflow_budget > AFFINITY_OVERFLOW_CAPACITY)
        overflow_budget = AFFINITY_OVERFLOW_CAPACITY;

    uint32_t n_overflow = affinity_overflow_drain(
        &ctx->overflows[ctx->worker_id], out, overflow_budget);

    total += n_overflow;
    ctx->stats.from_overflow += n_overflow;

    /*
     * ── Phase 2: Batch dequeue from SPMC ring ───────────────────────
     *
     * Single CAS claims up to batch_size slots. Use a stack-local
     * scratch buffer to avoid polluting the output during routing.
     *
     * Batch size clamped to remaining output capacity.
     */
    uint32_t remaining = max_count - total;
    if (remaining == 0)
        goto done;

    uint32_t batch = ctx->batch_size;
    if (batch > remaining)
        batch = remaining;

    ring_event_t scratch[SPMC_BATCH_MAX];
    uint32_t n_ring = spmc_ring_dequeue_batch(ctx->ring, scratch, batch);

    if (n_ring == 0)
        goto done;

    /*
     * ── Phase 3: Affinity-route SPMC events ─────────────────────────
     *
     * Hoist the BP_CRITICAL check outside the per-event loop.
     * Under critical backpressure, all events are processed locally
     * to prevent overflow queue pressure from compounding ring pressure.
     */
    bool skip_affinity = (bp_level >= BP_CRITICAL);

    route_batch(ctx, scratch, n_ring, out, &total, skip_affinity);

done:
    ctx->stats.processed += total;
    if (__builtin_expect(total == 0, 0))
        ctx->stats.empty_polls++;

    return total;
}
