/**
 * @file adaptive_poll.h
 * @brief Adaptive polling timeout state machine for worker threads
 *
 * @details Computes epoll_wait timeout based on recent event throughput
 * and backpressure level. Four states trade latency against CPU:
 *
 * @par State Machine
 * @code
 *   State    Timeout     Trigger
 *   ──────── ────────── ─────────────────────────
 *   IDLE     100 ms     No events for 8+ empty polls
 *   LIGHT      1 ms     Events present, not saturated
 *   MEDIUM     0 ms     Elevated backpressure or moderate load
 *   BUSY     skip       Full batch or high/critical backpressure
 * @endcode
 *
 * @par Transition Rules
 * - **Events received** → move toward BUSY (never skip toward IDLE)
 * - **Empty poll** → move toward IDLE (one state per empty poll)
 * - **BP_HIGH/BP_CRITICAL** → force BUSY (override event count)
 * - **BP_ELEVATED** → force at least MEDIUM
 * - **Full batch** (n >= batch_max) → force BUSY (producer faster)
 *
 * @par Full Batch Override
 * When n >= batch_max, the worker likely left events in the ring.
 * Setting timeout=0 ensures immediate re-poll without epoll_wait,
 * preventing latency spikes during burst traffic. This is the
 * "busy-poll inversion" optimization: never yield when the
 * producer is faster than the consumer.
 *
 * @par BUSY State — Skip epoll_wait
 * When poll returns ADAPTIVE_POLL_SKIP (-1), the caller should
 * skip epoll_wait entirely and re-enter the dequeue loop:
 * @code
 *   int timeout = adaptive_poll_timeout(&poll_state, n, batch_max, bp);
 *   if (timeout == ADAPTIVE_POLL_SKIP)
 *       continue;  // skip epoll_wait, immediate re-poll
 *   epoll_wait(epfd, events, max, timeout);
 * @endcode
 *
 * @par Re-Check Integration
 * The caller should use worker_dequeue_has_work() between an empty
 * poll and epoll_wait. If work arrived after the empty dequeue,
 * override timeout to 0 (or skip epoll entirely).
 *
 * @see src/ring/worker_dequeue.h  Three-phase consumption
 * @see src/ring/backpressure.h    Backpressure levels
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef SPLIFF_ADAPTIVE_POLL_H
#define SPLIFF_ADAPTIVE_POLL_H

#include <stdint.h>
#include <stdbool.h>

#include "backpressure.h"

/**
 * @defgroup adaptive_poll Adaptive Polling
 * @brief Timeout state machine for worker event loops
 * @{
 */

/*============================================================================
 * Configuration
 *============================================================================*/

/** Timeout for IDLE state (ms) — deep sleep, minimum CPU */
#define ADAPTIVE_POLL_IDLE_MS       100

/** Timeout for LIGHT state (ms) — responsive, low CPU */
#define ADAPTIVE_POLL_LIGHT_MS      1

/** Timeout for MEDIUM state (ms) — zero wait, still calls epoll */
#define ADAPTIVE_POLL_MEDIUM_MS     0

/** Sentinel: skip epoll_wait entirely (BUSY state) */
#define ADAPTIVE_POLL_SKIP          (-1)

/** Empty polls before downgrading one level toward IDLE */
#define ADAPTIVE_POLL_COOLDOWN      2

/** Empty polls at LIGHT before transitioning to IDLE */
#define ADAPTIVE_POLL_IDLE_THRESHOLD  8

/*============================================================================
 * Poll State
 *============================================================================*/

/**
 * @brief Polling intensity levels
 */
typedef enum {
    POLL_IDLE   = 0,    /**< Deep sleep (100ms timeout) */
    POLL_LIGHT  = 1,    /**< Light polling (1ms timeout) */
    POLL_MEDIUM = 2,    /**< Busy polling via epoll (0ms timeout) */
    POLL_BUSY   = 3,    /**< Skip epoll entirely */
} poll_level_t;

/** Number of poll levels (for array sizing) */
#define POLL_LEVEL_COUNT  4

/**
 * @brief Per-worker adaptive polling state
 *
 * Small, worker-private. No atomics needed — only accessed
 * by the owning worker thread.
 */
typedef struct adaptive_poll_state {
    poll_level_t level;         /**< Current polling intensity */
    uint32_t     empty_streak;  /**< Consecutive empty polls */
    uint64_t     transitions;   /**< Total state changes */
} adaptive_poll_state_t;

/*============================================================================
 * Lifecycle
 *============================================================================*/

/**
 * @brief Initialize adaptive poll state
 *
 * Starts at POLL_LIGHT — assumes the worker is being created because
 * there's work to do. Transitions to IDLE after sustained inactivity.
 *
 * @param state  Poll state to initialize (must not be NULL)
 */
static inline void
adaptive_poll_init(adaptive_poll_state_t *state)
{
    if (!state) return;
    state->level        = POLL_LIGHT;
    state->empty_streak = 0;
    state->transitions  = 0;
}

/*============================================================================
 * Timeout Computation
 *============================================================================*/

/**
 * @brief Compute epoll_wait timeout based on throughput and backpressure
 *
 * Call after worker_dequeue_poll() with the event count and batch max.
 * Returns the recommended epoll_wait timeout in milliseconds, or
 * ADAPTIVE_POLL_SKIP (-1) to skip epoll_wait entirely.
 *
 * @par Decision Table
 * @code
 *   Condition                  Result
 *   ────────────────────────── ─────────────────────
 *   BP >= HIGH                 BUSY → skip epoll
 *   n >= batch_max             BUSY → skip epoll
 *   BP >= ELEVATED             at least MEDIUM (0ms)
 *   n > 0, streak resets       LIGHT → 1ms
 *   n == 0, streak < cooldown  hold current level
 *   n == 0, streak >= cooldown step down one level
 *   streak >= idle_threshold   IDLE → 100ms
 * @endcode
 *
 * @param state      Per-worker poll state (updated in place)
 * @param n_events   Events returned by last worker_dequeue_poll()
 * @param batch_max  Maximum batch size configured for this worker
 * @param bp_level   Current backpressure level
 * @return Timeout in ms for epoll_wait, or ADAPTIVE_POLL_SKIP
 */
static inline int
adaptive_poll_timeout(adaptive_poll_state_t *state,
                      uint32_t n_events,
                      uint32_t batch_max,
                      bp_level_t bp_level)
{
    static const int timeouts[POLL_LEVEL_COUNT] = {
        ADAPTIVE_POLL_IDLE_MS,      /* POLL_IDLE   */
        ADAPTIVE_POLL_LIGHT_MS,     /* POLL_LIGHT  */
        ADAPTIVE_POLL_MEDIUM_MS,    /* POLL_MEDIUM */
        ADAPTIVE_POLL_SKIP,         /* POLL_BUSY   */
    };

    if (!state) return ADAPTIVE_POLL_LIGHT_MS;

    poll_level_t prev = state->level;
    poll_level_t next;

    /*
     * Priority 1: Backpressure override
     * HIGH/CRITICAL → always BUSY (skip epoll)
     * ELEVATED → at least MEDIUM (0ms epoll)
     */
    if (__builtin_expect(bp_level >= BP_HIGH, 0)) {
        next = POLL_BUSY;
        state->empty_streak = 0;
        goto commit;
    }

    /*
     * Priority 2: Full batch override
     * If we got batch_max events, the ring likely has more.
     * Skip epoll to drain immediately.
     */
    if (n_events >= batch_max && batch_max > 0) {
        next = POLL_BUSY;
        state->empty_streak = 0;
        goto commit;
    }

    /*
     * Priority 3: Event-driven transitions
     */
    if (n_events > 0) {
        state->empty_streak = 0;
        next = POLL_LIGHT;

        /* ELEVATED backpressure floor */
        if (__builtin_expect(bp_level >= BP_ELEVATED, 0))
            next = POLL_MEDIUM;

        goto commit;
    }

    /*
     * Priority 4: Empty poll — step down toward IDLE
     */
    state->empty_streak++;

    if (state->empty_streak >= ADAPTIVE_POLL_IDLE_THRESHOLD) {
        next = POLL_IDLE;
    } else if (state->empty_streak >= ADAPTIVE_POLL_COOLDOWN && prev > POLL_IDLE) {
        next = (poll_level_t)(prev - 1);
    } else {
        next = prev;
    }

commit:
    if (next != prev)
        state->transitions++;
    state->level = next;

    return timeouts[next];
}

/*============================================================================
 * Diagnostics
 *============================================================================*/

/** Current polling level */
static inline poll_level_t
adaptive_poll_current(const adaptive_poll_state_t *state) {
    return state ? state->level : POLL_LIGHT;
}

/** Total state transitions */
static inline uint64_t
adaptive_poll_stat_transitions(const adaptive_poll_state_t *state) {
    return state ? state->transitions : 0;
}

/** Current empty poll streak */
static inline uint32_t
adaptive_poll_stat_empty_streak(const adaptive_poll_state_t *state) {
    return state ? state->empty_streak : 0;
}

/** Human-readable poll level name */
static inline const char *
adaptive_poll_level_name(poll_level_t level) {
    static const char *names[POLL_LEVEL_COUNT] = {
        "IDLE", "LIGHT", "MEDIUM", "BUSY"
    };
    return (level < POLL_LEVEL_COUNT) ? names[level] : "UNKNOWN";
}

/** @} */ /* end of adaptive_poll group */

#endif /* SPLIFF_ADAPTIVE_POLL_H */
