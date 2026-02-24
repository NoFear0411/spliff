/**
 * @file backpressure.h
 * @brief Ring depth backpressure state machine with hysteresis
 *
 * @details Pure state machine that evaluates ring fill depth against
 * precomputed integer thresholds to produce a backpressure level.
 * Designed for the dispatcher hot path: all evaluation is integer
 * comparison with zero floating-point operations.
 *
 * @par Design Principles
 * - **Integer only**: Thresholds precomputed at init as absolute counts
 * - **Immediate bidirectional**: Level jumps up or down in one step
 * - **Deadband hysteresis**: Separate enter/leave thresholds prevent oscillation
 * - **Producer-local**: Evaluates dispatcher-private depth (head - cached_tail)
 *   with zero cross-cache-line reads
 * - **Action-agnostic**: Returns level; caller decides what to signal
 * - **Cross-thread visible**: Level uses __atomic store/load for safe reads
 *   from other threads (e.g. ingress controller checking pressure)
 *
 * @par Threshold Layout
 * Four pressure levels with deadbands between enter and leave:
 * @code
 *                    leave   enter
 *   NORMAL     ──────────── 0%
 *   ELEVATED   ─── 40% ─── 50%    (10% deadband)
 *   HIGH       ─── 65% ─── 75%    (10% deadband)
 *   CRITICAL   ─── 80% ─── 90%    (10% deadband)
 * @endcode
 *
 * @par Two-Phase Evaluation (Stale Tail Mitigation)
 * The dispatcher uses @c cached_tail to avoid cross-cache-line reads,
 * making depth pessimistic (higher than actual). To prevent dwelling
 * in elevated states due to stale data, the caller should force-refresh
 * the tail when the level rises above NORMAL:
 * @code
 *   // Phase 1: cheap evaluation with cached depth (zero cross-line reads)
 *   uint64_t depth = ring->head - ring->cached_tail;
 *   bp_level_t level = bp_evaluate(&bp, depth);
 *
 *   // Phase 2: verify with fresh tail if non-NORMAL (one cross-line read)
 *   if (level > BP_NORMAL) {
 *       ring->cached_tail = ck_pr_load_64(&ring->tail);
 *       depth = ring->head - ring->cached_tail;
 *       level = bp_evaluate(&bp, depth);
 *   }
 * @endcode
 * This keeps the common case (NORMAL) at zero cost, and only pays for
 * the cross-cache-line load when pressure is actually detected.
 *
 * @par Immediate Bidirectional Transitions
 * If the ring drains from 95% to 30% in one batch, the level jumps
 * directly from CRITICAL to NORMAL — no stepping through intermediate
 * levels. Deadbands only prevent oscillation near boundaries, they
 * never delay recovery.
 *
 * @par Struct Layout: Hot/Cold Cache-Line Separation
 * @code
 *   [0x000..0x07F]  Hot:  current level + thresholds (read every evaluation)
 *   [0x080..0x0FF]  Cold: transition stats + matrix (written only on changes)
 * @endcode
 * Transitions (~0.01% of evaluations) never evict thresholds from L1.
 *
 * @par Future Integration (Phase 3+)
 * - RCU-protected threshold hot-swap for runtime tuning
 * - eventfd edge-triggered signaling on upward transitions (EFD_NONBLOCK)
 * - BPF skeleton level update before eventfd write
 * - Batch-end evaluation (once per batch, after head advance)
 *
 * @see src/ring/spmc_ring.h Ring whose depth drives this state machine
 * @see docs/ARCHITECTURE-DECISIONS.md ADR-001
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license AGPL-3.0-only
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef SPLIFF_BACKPRESSURE_H
#define SPLIFF_BACKPRESSURE_H

#include <stdint.h>
#include <stdbool.h>

#include "../memory/alignment.h"

/**
 * @defgroup backpressure Backpressure Detection
 * @brief Ring depth state machine with hysteresis for flow control
 * @{
 */

/*============================================================================
 * Configuration — Threshold Percentages
 *============================================================================*/

/** @name Entry thresholds (rising: depth >= enter → transition up)
 *  @{ */
#define BP_ENTER_ELEVATED_PCT   50
#define BP_ENTER_HIGH_PCT       75
#define BP_ENTER_CRITICAL_PCT   90
/** @} */

/** @name Exit thresholds (falling: depth < leave → transition down)
 *  @{ */
#define BP_LEAVE_ELEVATED_PCT   40
#define BP_LEAVE_HIGH_PCT       65
#define BP_LEAVE_CRITICAL_PCT   80
/** @} */

/*--- Compile-time invariant: leave must always be less than enter ----------*/

_Static_assert(BP_LEAVE_ELEVATED_PCT < BP_ENTER_ELEVATED_PCT,
               "ELEVATED leave threshold must be below enter threshold");
_Static_assert(BP_LEAVE_HIGH_PCT < BP_ENTER_HIGH_PCT,
               "HIGH leave threshold must be below enter threshold");
_Static_assert(BP_LEAVE_CRITICAL_PCT < BP_ENTER_CRITICAL_PCT,
               "CRITICAL leave threshold must be below enter threshold");

/*--- Compile-time invariant: levels must be monotonically increasing ------*/

_Static_assert(BP_ENTER_ELEVATED_PCT < BP_ENTER_HIGH_PCT,
               "ELEVATED enter must be below HIGH enter");
_Static_assert(BP_ENTER_HIGH_PCT < BP_ENTER_CRITICAL_PCT,
               "HIGH enter must be below CRITICAL enter");

/*============================================================================
 * Backpressure Level
 *============================================================================*/

/** Number of backpressure levels (for array sizing) */
#define BP_LEVEL_COUNT  4

/**
 * @brief Backpressure severity levels
 *
 * Ordered by severity: NORMAL < ELEVATED < HIGH < CRITICAL.
 * Numeric values double as indices into threshold arrays and
 * the transition matrix.
 */
typedef enum {
    BP_NORMAL   = 0,    /**< Ring < 50% — no pressure */
    BP_ELEVATED = 1,    /**< Ring 50-75% — consumers lagging */
    BP_HIGH     = 2,    /**< Ring 75-90% — approaching capacity */
    BP_CRITICAL = 3,    /**< Ring > 90% — imminent drops */
} bp_level_t;

/*============================================================================
 * Backpressure State (256 bytes — 2 × 128-byte cache lines)
 *============================================================================*/

/**
 * @brief Backpressure evaluator state with hot/cold cache-line separation
 *
 * Embeddable in the dispatcher's per-ring state. The hot line contains
 * evaluation data (thresholds + current level), read on every call to
 * bp_evaluate(). The cold line contains transition statistics, written
 * only when the level actually changes (~0.01% of evaluations).
 *
 * @par Hot Cache Line [0x000..0x07F] — Read every evaluation
 * @code
 *   [0..3]    current     bp_level_t  (atomic: cross-thread visible)
 *   [4..7]    capacity    uint32_t    (for depth clamping)
 *   [8..23]   enter[4]    uint32_t×4  (precomputed entry thresholds)
 *   [24..39]  leave[4]    uint32_t×4  (precomputed exit thresholds)
 *   [40..127] padding
 * @endcode
 *
 * @par Cold Cache Line [0x080..0x0FF] — Written only on transitions
 * @code
 *   [128..131]  transitions            uint32_t
 *   [132..135]  critical_entries       uint32_t
 *   [136..143]  last_transition_ns     uint64_t
 *   [144..151]  depth_at_transition    uint64_t
 *   [152..183]  time_in_level_ns[4]    uint64_t×4
 *   [184..247]  transition_matrix[4×4] uint32_t×16
 * @endcode
 *
 * @par Cross-Thread Visibility
 * The @c current field uses GCC @c __atomic builtins (relaxed load on
 * hot path, release store on transitions). Other threads can read the
 * level with acquire semantics without affecting the dispatcher's L1.
 */
typedef struct bp_state {

    /*--- Hot cache line: evaluation data (read-heavy, rarely written) ------*/

    /**
     * @brief Current backpressure level (atomic for cross-thread visibility)
     *
     * Written by the dispatcher via __atomic_store_n(..., __ATOMIC_RELEASE)
     * on transitions. Other threads read with __atomic_load_n(..., __ATOMIC_ACQUIRE).
     * On x86 (TSO), both compile to plain MOV — zero overhead.
     */
    CACHE_ALIGNED bp_level_t current;

    /** Ring capacity for depth clamping (set once at init) */
    uint32_t    capacity;

    /** Precomputed entry thresholds: enter level L when depth >= enter[L] */
    uint32_t    enter[BP_LEVEL_COUNT];

    /** Precomputed exit thresholds: leave level L when depth < leave[L] */
    uint32_t    leave[BP_LEVEL_COUNT];

    /*--- Cold cache line: transition statistics (written on changes only) --*/

    /** Total level changes since init */
    CACHE_ALIGNED uint32_t transitions;

    /** Times entered CRITICAL specifically */
    uint32_t    critical_entries;

    /** CLOCK_MONOTONIC ns at last transition (baseline for time-in-level) */
    uint64_t    last_transition_ns;

    /**
     * @brief Ring depth that triggered the last transition
     *
     * Diagnostic: if this is much higher than enter[CRITICAL], the
     * cached_tail is getting too stale (consider more frequent refresh).
     */
    uint64_t    depth_at_transition;

    /**
     * @brief Accumulated nanoseconds spent in each level
     *
     * Updated on every transition: time_in_level_ns[prev] += now - last.
     * Provides SLA metrics ("time in CRITICAL") and tuning data.
     */
    uint64_t    time_in_level_ns[BP_LEVEL_COUNT];

    /**
     * @brief Transition count matrix: transition_matrix[from][to]
     *
     * Records how many times each level-to-level transition occurred.
     * Skip-level jumps (e.g., NORMAL → CRITICAL) indicate batches
     * are too large or thresholds are too close.
     */
    uint32_t    transition_matrix[BP_LEVEL_COUNT][BP_LEVEL_COUNT];

} bp_state_t;

_Static_assert(offsetof(bp_state_t, transitions) == CACHELINE_SIZE,
               "Cold stats must start at second cache line");

/*============================================================================
 * Lifecycle
 *============================================================================*/

/**
 * @brief Initialize backpressure state for a ring of given capacity
 *
 * Precomputes integer thresholds from capacity × percentage / 100.
 * Validates that every deadband gap is at least 1 slot (adjusts leave
 * thresholds down if integer rounding produces enter == leave).
 * Records initial CLOCK_MONOTONIC timestamp for time-in-level tracking.
 *
 * @param state     State to initialize (must not be NULL)
 * @param capacity  Ring capacity (must be power of 2, >= 4)
 * @return true on success, false if capacity is invalid
 */
bool bp_init(bp_state_t *state, uint32_t capacity);

/*============================================================================
 * Transition Recorder (Cold Path — defined in backpressure.c)
 *============================================================================*/

/**
 * @brief Record a backpressure level transition (cold path)
 *
 * Updates transition_matrix[prev][level], accumulates time_in_level_ns
 * for the previous level, records depth_at_transition, and increments
 * critical_entries when entering CRITICAL.
 *
 * Uses clock_gettime(CLOCK_MONOTONIC) for timing — acceptable on the
 * cold path (~20ns via vDSO, called ~0.01% of evaluations).
 *
 * @param state  Backpressure state
 * @param prev   Previous level (before transition)
 * @param level  New level (after transition)
 * @param depth  Ring depth that triggered this transition
 *
 * @internal Called by bp_evaluate(); not part of the public API.
 */
__attribute__((cold))
void bp_record_transition(bp_state_t *state, bp_level_t prev,
                          bp_level_t level, uint64_t depth);

/*============================================================================
 * Evaluation (Hot Path — Inline)
 *============================================================================*/

/**
 * @brief Evaluate ring depth and return backpressure level
 *
 * Pure integer comparison against precomputed thresholds. The hot path
 * (no level change) executes at most 6 integer comparisons and a single
 * branch-not-taken. Transitions are recorded via bp_record_transition()
 * (cold, out-of-line).
 *
 * @par Hysteresis Algorithm
 * For each level L (highest to lowest):
 * - **Enter**: depth >= enter[L] → enter level L (fresh crossing)
 * - **Sustain**: current >= L AND depth >= leave[L] → remain at L (deadband)
 * - **Drop**: depth < leave[L] → fall below L, check next lower level
 *
 * First matching level wins. This gives immediate transitions in both
 * directions: a single evaluation can jump from CRITICAL to NORMAL
 * if the ring drains past all deadbands.
 *
 * @par Depth Clamping
 * If depth exceeds capacity (possible when cached_tail is very stale),
 * it is clamped to capacity before evaluation. This prevents ghost
 * CRITICAL states during initialization or extreme staleness. The
 * branch is predicted not-taken (zero cost on the common path).
 *
 * @param state  Backpressure state (updated in place on transition)
 * @param depth  Current ring depth (head - cached_tail, unsigned)
 * @return Current backpressure level after evaluation
 */
[[nodiscard]]
static inline bp_level_t
bp_evaluate(bp_state_t *state, uint64_t depth)
{
    /* Clamp stale-tail depth to capacity (predicted not-taken) */
    if (__builtin_expect(depth > state->capacity, 0))
        depth = state->capacity;

    bp_level_t prev = __atomic_load_n(&state->current, __ATOMIC_RELAXED);
    bp_level_t level;

    /*
     * Check from highest to lowest: first matching level wins.
     * Each level has two paths to match:
     *   1. Fresh entry:  depth crossed the enter threshold
     *   2. Sustained:    already at/above this level, still in deadband
     *
     * The NORMAL fast-path (all conditions false) is the predicted outcome.
     */
    if (depth >= state->enter[BP_CRITICAL] ||
        (prev >= BP_CRITICAL && depth >= state->leave[BP_CRITICAL])) {
        level = BP_CRITICAL;

    } else if (depth >= state->enter[BP_HIGH] ||
               (prev >= BP_HIGH && depth >= state->leave[BP_HIGH])) {
        level = BP_HIGH;

    } else if (depth >= state->enter[BP_ELEVATED] ||
               (prev >= BP_ELEVATED && depth >= state->leave[BP_ELEVATED])) {
        level = BP_ELEVATED;

    } else {
        level = BP_NORMAL;
    }

    /* Cold path: record transition (rare, ~0.01% of evaluations) */
    if (__builtin_expect(level != prev, 0)) {
        __atomic_store_n(&state->current, level, __ATOMIC_RELEASE);
        bp_record_transition(state, prev, level, depth);
    }

    return level;
}

/*============================================================================
 * Diagnostics
 *============================================================================*/

/**
 * @brief Get human-readable name for a backpressure level
 *
 * @param level  Backpressure level
 * @return Static string ("NORMAL", "ELEVATED", "HIGH", "CRITICAL")
 */
static inline const char *
bp_level_name(bp_level_t level)
{
    static const char *names[BP_LEVEL_COUNT] = {
        "NORMAL", "ELEVATED", "HIGH", "CRITICAL"
    };
    return (level < BP_LEVEL_COUNT) ? names[level] : "UNKNOWN";
}

/**
 * @brief Read current level from any thread (acquire semantics)
 *
 * Safe to call from threads other than the dispatcher (e.g., ingress
 * controller checking whether to throttle). On x86 (TSO), this compiles
 * to a plain MOV — zero overhead.
 */
static inline bp_level_t bp_current_level(const bp_state_t *s) {
    if (!s) return BP_NORMAL;
    return __atomic_load_n(&((bp_state_t *)s)->current, __ATOMIC_ACQUIRE);
}

/** Total number of level transitions */
static inline uint32_t bp_stat_transitions(const bp_state_t *s) {
    return s ? s->transitions : 0;
}

/** Number of times CRITICAL was entered */
static inline uint32_t bp_stat_critical_entries(const bp_state_t *s) {
    return s ? s->critical_entries : 0;
}

/** Accumulated nanoseconds spent in a specific level */
static inline uint64_t bp_stat_time_in_level(const bp_state_t *s,
                                              bp_level_t level) {
    if (!s || level >= BP_LEVEL_COUNT) return 0;
    return s->time_in_level_ns[level];
}

/** Ring depth that triggered the most recent transition */
static inline uint64_t bp_stat_depth_at_transition(const bp_state_t *s) {
    return s ? s->depth_at_transition : 0;
}

/** Transition count from one level to another */
static inline uint32_t bp_stat_matrix(const bp_state_t *s,
                                       bp_level_t from, bp_level_t to) {
    if (!s || from >= BP_LEVEL_COUNT || to >= BP_LEVEL_COUNT) return 0;
    return s->transition_matrix[from][to];
}

/** @} */ /* end of backpressure group */

#endif /* SPLIFF_BACKPRESSURE_H */
