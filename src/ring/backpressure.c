/**
 * @file backpressure.c
 * @brief Backpressure state machine — lifecycle and cold-path transitions
 *
 * @details Contains initialization (threshold precomputation with gap
 * validation) and the cold-path transition recorder (matrix, timing,
 * depth capture). The hot-path evaluator is inline in backpressure.h.
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license AGPL-3.0-only
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "backpressure.h"

#include <string.h>
#include <time.h>

/*============================================================================
 * Internal: Timestamp Helper
 *============================================================================*/

static inline uint64_t
now_monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*============================================================================
 * Lifecycle
 *============================================================================*/

bool
bp_init(bp_state_t *state, uint32_t capacity)
{
    if (!state)
        return false;

    if (capacity < 4 || !IS_POWER_OF_TWO(capacity))
        return false;

    memset(state, 0, sizeof(*state));

    state->capacity = capacity;
    __atomic_store_n(&state->current, BP_NORMAL, __ATOMIC_RELEASE);

    /*
     * Precompute absolute thresholds from percentages.
     * Integer arithmetic: capacity * pct / 100.
     * No overflow risk: uint32_t * 100 < UINT32_MAX for capacity <= 42M.
     */
    state->enter[BP_NORMAL]   = 0;
    state->enter[BP_ELEVATED] = capacity * BP_ENTER_ELEVATED_PCT / 100;
    state->enter[BP_HIGH]     = capacity * BP_ENTER_HIGH_PCT / 100;
    state->enter[BP_CRITICAL] = capacity * BP_ENTER_CRITICAL_PCT / 100;

    state->leave[BP_NORMAL]   = 0;
    state->leave[BP_ELEVATED] = capacity * BP_LEAVE_ELEVATED_PCT / 100;
    state->leave[BP_HIGH]     = capacity * BP_LEAVE_HIGH_PCT / 100;
    state->leave[BP_CRITICAL] = capacity * BP_LEAVE_CRITICAL_PCT / 100;

    /*
     * Gap validation: ensure enter[L] > leave[L] for every level.
     * Integer rounding on small rings (e.g., capacity=4) can produce
     * enter == leave, which defeats hysteresis. Force a minimum gap of 1.
     */
    for (int l = BP_ELEVATED; l <= BP_CRITICAL; l++) {
        if (state->enter[l] <= state->leave[l])
            state->leave[l] = state->enter[l] - 1;
    }

    /* Record init timestamp as baseline for time-in-level accounting */
    state->last_transition_ns = now_monotonic_ns();

    return true;
}

/*============================================================================
 * Transition Recorder (Cold Path)
 *============================================================================*/

void
bp_record_transition(bp_state_t *state, bp_level_t prev,
                     bp_level_t level, uint64_t depth)
{
    uint64_t now = now_monotonic_ns();

    /* Increment total transition counter */
    state->transitions++;

    /* Record which transition occurred (skip-level detection) */
    state->transition_matrix[prev][level]++;

    /* Accumulate time spent in the previous level */
    if (state->last_transition_ns > 0)
        state->time_in_level_ns[prev] += now - state->last_transition_ns;

    state->last_transition_ns = now;

    /* Record the depth that triggered this change (stale-tail diagnostic) */
    state->depth_at_transition = depth;

    /* Track CRITICAL entries separately (high-value SLA metric) */
    if (level == BP_CRITICAL)
        state->critical_entries++;
}
