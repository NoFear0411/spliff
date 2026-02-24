/**
 * @file test_backpressure.c
 * @brief Unit tests for backpressure state machine (Phase 2)
 *
 * Tests cover:
 * - Structure layout verification (sizes, offsets, cache-line isolation)
 * - Threshold precomputation and gap validation
 * - Rising transitions through all four levels
 * - Immediate downward jumps (CRITICAL → NORMAL in one call)
 * - Deadband hysteresis (oscillation prevention)
 * - Depth clamping (stale-tail safety)
 * - Transition matrix (skip-level detection)
 * - Time-in-level tracking
 * - Two-phase evaluation pattern (stale tail mitigation)
 * - Diagnostic accessors and level names
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include "../src/ring/backpressure.h"

/*============================================================================
 * Test Framework (minimal, same style as other Phase 2 tests)
 *============================================================================*/

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { \
        tests_run++; \
        printf("  [%02d] %-55s ", tests_run, name); \
    } while (0)

#define PASS() \
    do { \
        tests_passed++; \
        printf("PASS\n"); \
    } while (0)

#define FAIL(msg) \
    do { \
        tests_failed++; \
        printf("FAIL: %s\n", msg); \
    } while (0)

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { FAIL(msg); return; } \
    } while (0)

/*============================================================================
 * 1. Structure Layout Tests
 *============================================================================*/

static void test_level_enum_values(void) {
    TEST("bp_level_t values: 0, 1, 2, 3");
    CHECK(BP_NORMAL == 0, "NORMAL != 0");
    CHECK(BP_ELEVATED == 1, "ELEVATED != 1");
    CHECK(BP_HIGH == 2, "HIGH != 2");
    CHECK(BP_CRITICAL == 3, "CRITICAL != 3");
    CHECK(BP_LEVEL_COUNT == 4, "LEVEL_COUNT != 4");
    PASS();
}

static void test_state_cold_offset(void) {
    TEST("Cold stats at cache-line boundary (offset 128)");
    CHECK(offsetof(bp_state_t, transitions) == CACHELINE_SIZE,
          "transitions not at CACHELINE_SIZE offset");
    PASS();
}

static void test_state_hot_fields_fit(void) {
    TEST("Hot fields fit within first cache line");
    size_t hot_end = offsetof(bp_state_t, leave) +
                     sizeof(((bp_state_t *)0)->leave);
    CHECK(hot_end <= CACHELINE_SIZE,
          "hot fields exceed cache line boundary");
    PASS();
}

/*============================================================================
 * 2. Initialization Tests
 *============================================================================*/

static void test_init_valid_1024(void) {
    TEST("bp_init(1024): thresholds correct");
    bp_state_t bp;
    CHECK(bp_init(&bp, 1024), "init failed");
    CHECK(bp.capacity == 1024, "capacity wrong");
    CHECK(bp_current_level(&bp) == BP_NORMAL, "initial level not NORMAL");

    /* entry thresholds */
    CHECK(bp.enter[BP_NORMAL] == 0, "enter[NORMAL] != 0");
    CHECK(bp.enter[BP_ELEVATED] == 512, "enter[ELEVATED] != 512");
    CHECK(bp.enter[BP_HIGH] == 768, "enter[HIGH] != 768");
    CHECK(bp.enter[BP_CRITICAL] == 921, "enter[CRITICAL] != 921");

    /* exit thresholds */
    CHECK(bp.leave[BP_NORMAL] == 0, "leave[NORMAL] != 0");
    CHECK(bp.leave[BP_ELEVATED] == 409, "leave[ELEVATED] != 409");
    CHECK(bp.leave[BP_HIGH] == 665, "leave[HIGH] != 665");
    CHECK(bp.leave[BP_CRITICAL] == 819, "leave[CRITICAL] != 819");
    PASS();
}

static void test_init_valid_small_ring(void) {
    TEST("bp_init(4): small ring gap validation");
    bp_state_t bp;
    CHECK(bp_init(&bp, 4), "init failed for cap=4");
    CHECK(bp.capacity == 4, "capacity wrong");

    /* With cap=4: enter[ELEVATED] = 4*50/100 = 2, leave = 4*40/100 = 1 */
    CHECK(bp.enter[BP_ELEVATED] == 2, "enter[ELEVATED] wrong for cap=4");

    /* Gap validation: enter > leave for all levels */
    for (int l = BP_ELEVATED; l <= BP_CRITICAL; l++) {
        CHECK(bp.enter[l] > bp.leave[l], "enter <= leave after gap validation");
    }
    PASS();
}

static void test_init_gap_enforcement(void) {
    TEST("bp_init: gap >= 1 enforced for all levels");
    /* Test with several power-of-2 capacities */
    uint32_t caps[] = { 4, 8, 16, 32, 64, 128, 256, 1024, 8192 };
    for (size_t i = 0; i < sizeof(caps) / sizeof(caps[0]); i++) {
        bp_state_t bp;
        CHECK(bp_init(&bp, caps[i]), "init failed");
        for (int l = BP_ELEVATED; l <= BP_CRITICAL; l++) {
            CHECK(bp.enter[l] > bp.leave[l],
                  "enter <= leave for some capacity");
        }
    }
    PASS();
}

static void test_init_invalid_inputs(void) {
    TEST("bp_init rejects invalid inputs");
    bp_state_t bp;
    CHECK(!bp_init(NULL, 1024), "NULL state accepted");
    CHECK(!bp_init(&bp, 0), "capacity 0 accepted");
    CHECK(!bp_init(&bp, 3), "capacity 3 accepted");
    CHECK(!bp_init(&bp, 5), "capacity 5 accepted");
    CHECK(!bp_init(&bp, 6), "capacity 6 accepted");
    CHECK(!bp_init(&bp, 2), "capacity 2 accepted (< 4)");
    PASS();
}

static void test_init_timestamps(void) {
    TEST("bp_init sets baseline timestamp");
    bp_state_t bp;
    CHECK(bp_init(&bp, 1024), "init failed");
    CHECK(bp.last_transition_ns > 0, "baseline timestamp not set");
    CHECK(bp.transitions == 0, "transitions not zero at init");
    CHECK(bp.critical_entries == 0, "critical_entries not zero at init");
    PASS();
}

/*============================================================================
 * 3. Rising Transition Tests
 *============================================================================*/

static void test_rising_normal_to_elevated(void) {
    TEST("Rising: NORMAL → ELEVATED at 50%");
    bp_state_t bp;
    bp_init(&bp, 1024);

    /* Below threshold */
    bp_level_t l = bp_evaluate(&bp, 500);
    CHECK(l == BP_NORMAL, "should be NORMAL at depth 500");

    /* At threshold */
    l = bp_evaluate(&bp, 512);
    CHECK(l == BP_ELEVATED, "should be ELEVATED at depth 512");
    CHECK(bp.transitions == 1, "expected 1 transition");
    PASS();
}

static void test_rising_elevated_to_high(void) {
    TEST("Rising: ELEVATED → HIGH at 75%");
    bp_state_t bp;
    bp_init(&bp, 1024);

    (void)bp_evaluate(&bp, 512);  /* enter ELEVATED */
    bp_level_t l = bp_evaluate(&bp, 768);
    CHECK(l == BP_HIGH, "should be HIGH at depth 768");
    CHECK(bp.transitions == 2, "expected 2 transitions");
    PASS();
}

static void test_rising_high_to_critical(void) {
    TEST("Rising: HIGH → CRITICAL at 90%");
    bp_state_t bp;
    bp_init(&bp, 1024);

    (void)bp_evaluate(&bp, 512);  /* ELEVATED */
    (void)bp_evaluate(&bp, 768);  /* HIGH */
    bp_level_t l = bp_evaluate(&bp, 921);
    CHECK(l == BP_CRITICAL, "should be CRITICAL at depth 921");
    CHECK(bp.transitions == 3, "expected 3 transitions");
    CHECK(bp.critical_entries == 1, "expected 1 critical entry");
    PASS();
}

static void test_rising_skip_to_critical(void) {
    TEST("Rising: NORMAL → CRITICAL (skip-level jump)");
    bp_state_t bp;
    bp_init(&bp, 1024);

    bp_level_t l = bp_evaluate(&bp, 950);
    CHECK(l == BP_CRITICAL, "should be CRITICAL at depth 950");
    CHECK(bp.transitions == 1, "expected 1 transition");
    CHECK(bp.transition_matrix[BP_NORMAL][BP_CRITICAL] == 1,
          "matrix[NORMAL][CRITICAL] should be 1");
    PASS();
}

/*============================================================================
 * 4. Falling Transition Tests
 *============================================================================*/

static void test_falling_immediate_to_normal(void) {
    TEST("Falling: CRITICAL → NORMAL immediate jump");
    bp_state_t bp;
    bp_init(&bp, 1024);

    (void)bp_evaluate(&bp, 950);  /* enter CRITICAL */
    CHECK(bp_current_level(&bp) == BP_CRITICAL, "not at CRITICAL");

    /* Drop well below all leave thresholds */
    bp_level_t l = bp_evaluate(&bp, 100);
    CHECK(l == BP_NORMAL, "should jump to NORMAL at depth 100");
    CHECK(bp.transitions == 2, "expected 2 transitions (up + down)");
    CHECK(bp.transition_matrix[BP_CRITICAL][BP_NORMAL] == 1,
          "matrix[CRITICAL][NORMAL] should be 1");
    PASS();
}

static void test_falling_critical_to_high(void) {
    TEST("Falling: CRITICAL → HIGH (in HIGH deadband)");
    bp_state_t bp;
    bp_init(&bp, 1024);

    (void)bp_evaluate(&bp, 512);  /* ELEVATED */
    (void)bp_evaluate(&bp, 768);  /* HIGH */
    (void)bp_evaluate(&bp, 950);  /* CRITICAL */

    /* Drop into HIGH deadband (below leave[CRITICAL]=819, above leave[HIGH]=665) */
    bp_level_t l = bp_evaluate(&bp, 700);
    CHECK(l == BP_HIGH, "should drop to HIGH at depth 700");
    PASS();
}

/*============================================================================
 * 5. Deadband Hysteresis Tests
 *============================================================================*/

static void test_deadband_elevated_sustain(void) {
    TEST("Deadband: ELEVATED sustained in [leave, enter) range");
    bp_state_t bp;
    bp_init(&bp, 1024);

    (void)bp_evaluate(&bp, 512);  /* enter ELEVATED */
    uint32_t transitions_before = bp.transitions;

    /* Drop within deadband — should stay ELEVATED */
    bp_level_t l = bp_evaluate(&bp, 450);
    CHECK(l == BP_ELEVATED, "should sustain ELEVATED at 450 (deadband)");
    CHECK(bp.transitions == transitions_before, "no transition in deadband");

    /* Still in deadband at boundary */
    l = bp_evaluate(&bp, 409);
    CHECK(l == BP_ELEVATED, "should sustain at leave boundary 409");

    /* Drop below leave — should exit to NORMAL */
    l = bp_evaluate(&bp, 408);
    CHECK(l == BP_NORMAL, "should exit ELEVATED at 408 (below leave)");
    PASS();
}

static void test_deadband_prevents_oscillation(void) {
    TEST("Deadband: no oscillation near ELEVATED boundary");
    bp_state_t bp;
    bp_init(&bp, 1024);

    /* Cross above enter threshold */
    (void)bp_evaluate(&bp, 520);
    CHECK(bp_current_level(&bp) == BP_ELEVATED, "should enter ELEVATED");
    uint32_t t1 = bp.transitions;

    /* Oscillate near boundary without crossing deadband */
    for (int i = 0; i < 100; i++) {
        uint64_t depth = (i % 2 == 0) ? 505 : 480;
        (void)bp_evaluate(&bp, depth);
    }
    CHECK(bp.transitions == t1, "oscillation caused transitions");
    CHECK(bp_current_level(&bp) == BP_ELEVATED, "left ELEVATED during oscillation");
    PASS();
}

/*============================================================================
 * 6. Depth Clamping Tests
 *============================================================================*/

static void test_depth_clamping(void) {
    TEST("Depth clamping: depth > capacity → clamped to capacity");
    bp_state_t bp;
    bp_init(&bp, 1024);

    /* Pass depth much larger than capacity (stale tail scenario) */
    bp_level_t l = bp_evaluate(&bp, 999999);
    CHECK(l == BP_CRITICAL, "clamped depth should yield CRITICAL");
    PASS();
}

static void test_depth_clamping_at_capacity(void) {
    TEST("Depth at exactly capacity → CRITICAL");
    bp_state_t bp;
    bp_init(&bp, 1024);

    bp_level_t l = bp_evaluate(&bp, 1024);
    CHECK(l == BP_CRITICAL, "depth=capacity should be CRITICAL");
    PASS();
}

/*============================================================================
 * 7. Transition Matrix Tests
 *============================================================================*/

static void test_transition_matrix_full_cycle(void) {
    TEST("Transition matrix: full up-down cycle recorded");
    bp_state_t bp;
    bp_init(&bp, 1024);

    /* Rise through all levels */
    (void)bp_evaluate(&bp, 512);   /* N→E */
    (void)bp_evaluate(&bp, 768);   /* E→H */
    (void)bp_evaluate(&bp, 950);   /* H→C */

    /* Fall back to NORMAL */
    (void)bp_evaluate(&bp, 100);   /* C→N */

    CHECK(bp.transition_matrix[BP_NORMAL][BP_ELEVATED] == 1, "N→E != 1");
    CHECK(bp.transition_matrix[BP_ELEVATED][BP_HIGH] == 1, "E→H != 1");
    CHECK(bp.transition_matrix[BP_HIGH][BP_CRITICAL] == 1, "H→C != 1");
    CHECK(bp.transition_matrix[BP_CRITICAL][BP_NORMAL] == 1, "C→N != 1");
    CHECK(bp.transitions == 4, "expected 4 transitions");

    /* Self-transitions should be zero */
    for (int i = 0; i < BP_LEVEL_COUNT; i++)
        CHECK(bp.transition_matrix[i][i] == 0, "self-transition recorded");
    PASS();
}

/*============================================================================
 * 8. Time-in-Level Tests
 *============================================================================*/

static void test_time_in_level_tracking(void) {
    TEST("Time-in-level: accumulates per-level durations");
    bp_state_t bp;
    bp_init(&bp, 1024);

    /* Spend some time in NORMAL */
    usleep(1000);  /* ~1ms */
    (void)bp_evaluate(&bp, 512);  /* N→E */

    /* Spend some time in ELEVATED */
    usleep(1000);
    (void)bp_evaluate(&bp, 950);  /* E→C */

    /* Spend some time in CRITICAL */
    usleep(1000);
    (void)bp_evaluate(&bp, 100);  /* C→N */

    /* All visited levels should have > 0 time */
    CHECK(bp.time_in_level_ns[BP_NORMAL] > 0,
          "no time recorded for NORMAL");
    CHECK(bp.time_in_level_ns[BP_ELEVATED] > 0,
          "no time recorded for ELEVATED");
    CHECK(bp.time_in_level_ns[BP_CRITICAL] > 0,
          "no time recorded for CRITICAL");

    /* HIGH was never entered */
    CHECK(bp.time_in_level_ns[BP_HIGH] == 0,
          "time recorded for HIGH (never entered)");
    PASS();
}

/*============================================================================
 * 9. Depth-at-Transition Tests
 *============================================================================*/

static void test_depth_at_transition(void) {
    TEST("Depth at transition: records triggering depth");
    bp_state_t bp;
    bp_init(&bp, 1024);

    (void)bp_evaluate(&bp, 600);
    CHECK(bp.depth_at_transition == 600, "depth should be 600 after N→E");

    (void)bp_evaluate(&bp, 800);
    CHECK(bp.depth_at_transition == 800, "depth should be 800 after E→H");

    (void)bp_evaluate(&bp, 200);
    CHECK(bp.depth_at_transition == 200, "depth should be 200 after H→E");
    PASS();
}

/*============================================================================
 * 10. Two-Phase Evaluation Pattern
 *============================================================================*/

static void test_two_phase_evaluation(void) {
    TEST("Two-phase: stale depth → refresh → correct level");
    bp_state_t bp;
    bp_init(&bp, 1024);

    /*
     * Simulate stale tail: first evaluation thinks ring is 95% full,
     * but after refreshing the "actual" depth is only 30%.
     */
    bp_level_t level = bp_evaluate(&bp, 970);  /* stale: CRITICAL */
    CHECK(level == BP_CRITICAL, "stale depth should yield CRITICAL");

    /* Phase 2: refresh reveals ring is actually near-empty */
    level = bp_evaluate(&bp, 300);
    CHECK(level == BP_NORMAL, "refreshed depth should yield NORMAL");
    PASS();
}

/*============================================================================
 * 11. Level Name Tests
 *============================================================================*/

static void test_level_names(void) {
    TEST("bp_level_name: returns correct strings");
    CHECK(strcmp(bp_level_name(BP_NORMAL), "NORMAL") == 0, "NORMAL wrong");
    CHECK(strcmp(bp_level_name(BP_ELEVATED), "ELEVATED") == 0, "ELEVATED wrong");
    CHECK(strcmp(bp_level_name(BP_HIGH), "HIGH") == 0, "HIGH wrong");
    CHECK(strcmp(bp_level_name(BP_CRITICAL), "CRITICAL") == 0, "CRITICAL wrong");
    CHECK(strcmp(bp_level_name(99), "UNKNOWN") == 0, "out-of-range wrong");
    PASS();
}

/*============================================================================
 * 12. Diagnostic Accessor Tests
 *============================================================================*/

static void test_accessors_null_safety(void) {
    TEST("Accessors: NULL state returns defaults");
    CHECK(bp_current_level(NULL) == BP_NORMAL, "NULL current != NORMAL");
    CHECK(bp_stat_transitions(NULL) == 0, "NULL transitions != 0");
    CHECK(bp_stat_critical_entries(NULL) == 0, "NULL critical_entries != 0");
    CHECK(bp_stat_time_in_level(NULL, BP_NORMAL) == 0, "NULL time != 0");
    CHECK(bp_stat_depth_at_transition(NULL) == 0, "NULL depth != 0");
    CHECK(bp_stat_matrix(NULL, BP_NORMAL, BP_CRITICAL) == 0, "NULL matrix != 0");
    PASS();
}

static void test_accessors_values(void) {
    TEST("Accessors: return correct values after operations");
    bp_state_t bp;
    bp_init(&bp, 1024);

    (void)bp_evaluate(&bp, 950);  /* CRITICAL */
    (void)bp_evaluate(&bp, 100);  /* NORMAL */

    CHECK(bp_stat_transitions(&bp) == 2, "transitions != 2");
    CHECK(bp_stat_critical_entries(&bp) == 1, "critical_entries != 1");
    CHECK(bp_stat_depth_at_transition(&bp) == 100, "depth_at_transition wrong");
    CHECK(bp_stat_matrix(&bp, BP_NORMAL, BP_CRITICAL) == 1, "matrix N→C != 1");
    CHECK(bp_stat_matrix(&bp, BP_CRITICAL, BP_NORMAL) == 1, "matrix C→N != 1");
    PASS();
}

static void test_accessor_out_of_range(void) {
    TEST("Accessors: out-of-range level returns 0");
    bp_state_t bp;
    bp_init(&bp, 1024);
    CHECK(bp_stat_time_in_level(&bp, 99) == 0, "out-of-range time != 0");
    CHECK(bp_stat_matrix(&bp, 99, 0) == 0, "out-of-range from != 0");
    CHECK(bp_stat_matrix(&bp, 0, 99) == 0, "out-of-range to != 0");
    PASS();
}

/*============================================================================
 * 13. Steady-State Performance (No Transitions)
 *============================================================================*/

static void test_steady_state_no_transitions(void) {
    TEST("Steady state: 1M evaluations at NORMAL, zero transitions");
    bp_state_t bp;
    bp_init(&bp, 8192);

    for (int i = 0; i < 1000000; i++) {
        bp_level_t l = bp_evaluate(&bp, 100);
        (void)l;
    }
    CHECK(bp.transitions == 0, "transitions during steady state");
    PASS();
}

/*============================================================================
 * Main
 *============================================================================*/

int main(void) {
    printf("\n=== Backpressure State Machine Tests ===\n\n");

    printf("--- Layout ---\n");
    test_level_enum_values();
    test_state_cold_offset();
    test_state_hot_fields_fit();

    printf("\n--- Initialization ---\n");
    test_init_valid_1024();
    test_init_valid_small_ring();
    test_init_gap_enforcement();
    test_init_invalid_inputs();
    test_init_timestamps();

    printf("\n--- Rising Transitions ---\n");
    test_rising_normal_to_elevated();
    test_rising_elevated_to_high();
    test_rising_high_to_critical();
    test_rising_skip_to_critical();

    printf("\n--- Falling Transitions ---\n");
    test_falling_immediate_to_normal();
    test_falling_critical_to_high();

    printf("\n--- Deadband Hysteresis ---\n");
    test_deadband_elevated_sustain();
    test_deadband_prevents_oscillation();

    printf("\n--- Depth Clamping ---\n");
    test_depth_clamping();
    test_depth_clamping_at_capacity();

    printf("\n--- Transition Matrix ---\n");
    test_transition_matrix_full_cycle();

    printf("\n--- Time-in-Level ---\n");
    test_time_in_level_tracking();

    printf("\n--- Depth at Transition ---\n");
    test_depth_at_transition();

    printf("\n--- Two-Phase Evaluation ---\n");
    test_two_phase_evaluation();

    printf("\n--- Level Names ---\n");
    test_level_names();

    printf("\n--- Diagnostic Accessors ---\n");
    test_accessors_null_safety();
    test_accessors_values();
    test_accessor_out_of_range();

    printf("\n--- Steady State ---\n");
    test_steady_state_no_transitions();

    printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf(" (%d FAILED)", tests_failed);
    printf(" ===\n\n");

    return tests_failed > 0 ? 1 : 0;
}
