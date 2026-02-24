/**
 * @file test_worker_dequeue.c
 * @brief Unit tests for worker dequeue module and adaptive polling
 *
 * Tests cover:
 * - Worker dequeue init validation
 * - Phase 1: overflow drain priority
 * - Phase 2: SPMC batch dequeue
 * - Phase 3: affinity routing (local, defer, forced local)
 * - BP_CRITICAL skip-affinity fast path
 * - Hop-limit guard (EVENT_FLAG_ROUTED)
 * - Out-of-bounds preferred_worker safety
 * - Statistics tracking
 * - Re-check helper (worker_dequeue_has_work)
 * - Adaptive poll state machine transitions
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "../src/ring/worker_dequeue.h"
#include "../src/ring/adaptive_poll.h"

/*============================================================================
 * Test Framework (minimal, same style as other test files)
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
 * Test Helpers
 *============================================================================*/

/**
 * @brief Create a test event with specified routing
 */
static ring_event_t make_event(uint64_t cookie, uint8_t flags,
                                uint8_t worker, uint8_t type)
{
    ring_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.socket_cookie = cookie;
    ev.routing = route_pack(flags, worker, type, 0);
    return ev;
}

/** Create a stateless event (any worker can process) */
static ring_event_t make_stateless(uint64_t cookie)
{
    return make_event(cookie, 0, 0, EVENT_TYPE_PLAIN_DATA);
}

/** Create a stateful event routed to a specific worker */
static ring_event_t make_stateful(uint64_t cookie, uint8_t worker)
{
    return make_event(cookie, EVENT_FLAG_STATEFUL, worker,
                      EVENT_TYPE_TLS_DATA);
}

/** Shared test ring and overflow queues */
static spmc_ring_t *test_ring = NULL;
static affinity_overflow_t test_overflows[4];

static void setup_test_infra(void)
{
    test_ring = spmc_ring_create(64);  /* Small ring for tests */
    for (int i = 0; i < 4; i++)
        affinity_overflow_init(&test_overflows[i]);
}

static void teardown_test_infra(void)
{
    if (test_ring) {
        spmc_ring_destroy(test_ring);
        test_ring = NULL;
    }
}

/*============================================================================
 * 1. Init Validation Tests
 *============================================================================*/

static void test_init_null_ctx(void)
{
    TEST("init: NULL ctx returns false");
    CHECK(!worker_dequeue_init(NULL, 0, 4, test_ring, test_overflows),
          "should reject NULL ctx");
    PASS();
}

static void test_init_null_ring(void)
{
    TEST("init: NULL ring returns false");
    worker_dequeue_ctx_t ctx;
    CHECK(!worker_dequeue_init(&ctx, 0, 4, NULL, test_overflows),
          "should reject NULL ring");
    PASS();
}

static void test_init_null_overflows(void)
{
    TEST("init: NULL overflows returns false");
    worker_dequeue_ctx_t ctx;
    CHECK(!worker_dequeue_init(&ctx, 0, 4, test_ring, NULL),
          "should reject NULL overflows");
    PASS();
}

static void test_init_zero_workers(void)
{
    TEST("init: zero workers returns false");
    worker_dequeue_ctx_t ctx;
    CHECK(!worker_dequeue_init(&ctx, 0, 0, test_ring, test_overflows),
          "should reject zero workers");
    PASS();
}

static void test_init_worker_id_out_of_range(void)
{
    TEST("init: worker_id >= num_workers returns false");
    worker_dequeue_ctx_t ctx;
    CHECK(!worker_dequeue_init(&ctx, 4, 4, test_ring, test_overflows),
          "should reject worker_id == num_workers");
    CHECK(!worker_dequeue_init(&ctx, 5, 4, test_ring, test_overflows),
          "should reject worker_id > num_workers");
    PASS();
}

static void test_init_valid(void)
{
    TEST("init: valid params succeed");
    worker_dequeue_ctx_t ctx;
    CHECK(worker_dequeue_init(&ctx, 2, 4, test_ring, test_overflows),
          "valid init should succeed");
    CHECK(ctx.worker_id == 2, "worker_id should be 2");
    CHECK(ctx.num_workers == 4, "num_workers should be 4");
    CHECK(ctx.batch_size == WORKER_DEQUEUE_BATCH_DEFAULT, "batch_size default");
    CHECK(ctx.ring == test_ring, "ring pointer");
    CHECK(ctx.overflows == test_overflows, "overflows pointer");
    CHECK(ctx.stats.processed == 0, "stats zeroed");
    PASS();
}

/*============================================================================
 * 2. Empty Poll Tests
 *============================================================================*/

static void test_poll_empty_ring(void)
{
    TEST("poll: empty ring returns 0 events");
    worker_dequeue_ctx_t ctx;
    worker_dequeue_init(&ctx, 0, 4, test_ring, test_overflows);

    ring_event_t out[WORKER_DEQUEUE_MAX_EVENTS];
    uint32_t n = worker_dequeue_poll(&ctx, out, WORKER_DEQUEUE_MAX_EVENTS,
                                      BP_NORMAL);
    CHECK(n == 0, "should return 0");
    CHECK(ctx.stats.polls == 1, "poll count should be 1");
    CHECK(ctx.stats.empty_polls == 1, "empty poll count should be 1");
    PASS();
}

static void test_poll_null_args(void)
{
    TEST("poll: NULL args return 0");
    worker_dequeue_ctx_t ctx;
    worker_dequeue_init(&ctx, 0, 4, test_ring, test_overflows);

    ring_event_t out[WORKER_DEQUEUE_MAX_EVENTS];
    CHECK(worker_dequeue_poll(NULL, out, 16, BP_NORMAL) == 0, "null ctx");
    CHECK(worker_dequeue_poll(&ctx, NULL, 16, BP_NORMAL) == 0, "null out");
    PASS();
}

/*============================================================================
 * 3. Phase 1: Overflow Drain Tests
 *============================================================================*/

static void test_overflow_drain_priority(void)
{
    TEST("poll: overflow events drained before SPMC ring");
    setup_test_infra();
    worker_dequeue_ctx_t ctx;
    worker_dequeue_init(&ctx, 1, 4, test_ring, test_overflows);

    /* Push 3 events to worker 1's overflow */
    ring_event_t ev1 = make_stateless(100);
    ring_event_mark_routed(&ev1);
    ring_event_t ev2 = make_stateless(200);
    ring_event_mark_routed(&ev2);
    ring_event_t ev3 = make_stateless(300);
    ring_event_mark_routed(&ev3);

    affinity_overflow_push(&test_overflows[1], &ev1);
    affinity_overflow_push(&test_overflows[1], &ev2);
    affinity_overflow_push(&test_overflows[1], &ev3);

    /* Also enqueue 2 stateless events to SPMC ring */
    ring_event_t rev1 = make_stateless(400);
    ring_event_t rev2 = make_stateless(500);
    spmc_ring_enqueue(test_ring, &rev1);
    spmc_ring_enqueue(test_ring, &rev2);

    ring_event_t out[WORKER_DEQUEUE_MAX_EVENTS];
    uint32_t n = worker_dequeue_poll(&ctx, out, WORKER_DEQUEUE_MAX_EVENTS,
                                      BP_NORMAL);

    /* Should get overflow events first (100, 200, 300) then ring (400, 500) */
    CHECK(n == 5, "should get 5 events total");
    CHECK(out[0].socket_cookie == 100, "overflow first: cookie 100");
    CHECK(out[1].socket_cookie == 200, "overflow second: cookie 200");
    CHECK(out[2].socket_cookie == 300, "overflow third: cookie 300");
    CHECK(out[3].socket_cookie == 400, "ring first: cookie 400");
    CHECK(out[4].socket_cookie == 500, "ring second: cookie 500");
    CHECK(ctx.stats.from_overflow == 3, "from_overflow should be 3");
    CHECK(ctx.stats.processed == 5, "processed should be 5");
    teardown_test_infra();
    PASS();
}

/*============================================================================
 * 4. Phase 3: Affinity Routing Tests
 *============================================================================*/

static void test_stateless_events_local(void)
{
    TEST("routing: stateless events always processed locally");
    setup_test_infra();
    worker_dequeue_ctx_t ctx;
    worker_dequeue_init(&ctx, 0, 4, test_ring, test_overflows);

    /* Enqueue 4 stateless events */
    for (uint64_t i = 1; i <= 4; i++) {
        ring_event_t ev = make_stateless(i);
        spmc_ring_enqueue(test_ring, &ev);
    }

    ring_event_t out[WORKER_DEQUEUE_MAX_EVENTS];
    uint32_t n = worker_dequeue_poll(&ctx, out, WORKER_DEQUEUE_MAX_EVENTS,
                                      BP_NORMAL);

    CHECK(n == 4, "should get all 4 events");
    CHECK(ctx.stats.deferred == 0, "no events deferred");
    teardown_test_infra();
    PASS();
}

static void test_stateful_correct_worker(void)
{
    TEST("routing: stateful event on correct worker → local");
    setup_test_infra();
    worker_dequeue_ctx_t ctx;
    worker_dequeue_init(&ctx, 2, 4, test_ring, test_overflows);

    /* Stateful event for worker 2 (us) */
    ring_event_t ev = make_stateful(42, 2);
    spmc_ring_enqueue(test_ring, &ev);

    ring_event_t out[WORKER_DEQUEUE_MAX_EVENTS];
    uint32_t n = worker_dequeue_poll(&ctx, out, WORKER_DEQUEUE_MAX_EVENTS,
                                      BP_NORMAL);

    CHECK(n == 1, "should get 1 event");
    CHECK(out[0].socket_cookie == 42, "correct cookie");
    CHECK(ctx.stats.deferred == 0, "no defers");
    teardown_test_infra();
    PASS();
}

static void test_stateful_wrong_worker_defers(void)
{
    TEST("routing: stateful event on wrong worker → defer");
    setup_test_infra();
    worker_dequeue_ctx_t ctx;
    worker_dequeue_init(&ctx, 0, 4, test_ring, test_overflows);

    /* Stateful event for worker 3 (not us) */
    ring_event_t ev = make_stateful(99, 3);
    spmc_ring_enqueue(test_ring, &ev);

    ring_event_t out[WORKER_DEQUEUE_MAX_EVENTS];
    uint32_t n = worker_dequeue_poll(&ctx, out, WORKER_DEQUEUE_MAX_EVENTS,
                                      BP_NORMAL);

    CHECK(n == 0, "no local events (deferred)");
    CHECK(ctx.stats.deferred == 1, "one event deferred");

    /* Verify it arrived in worker 3's overflow */
    CHECK(!affinity_overflow_empty(&test_overflows[3]),
          "worker 3 overflow should have event");

    /* Drain worker 3's overflow and verify ROUTED flag */
    ring_event_t drain[AFFINITY_OVERFLOW_CAPACITY];
    uint32_t nd = affinity_overflow_drain(&test_overflows[3], drain, 64);
    CHECK(nd == 1, "should drain 1 event");
    CHECK(drain[0].socket_cookie == 99, "correct cookie in overflow");
    CHECK(ring_event_is_routed(&drain[0]), "event should be marked ROUTED");

    teardown_test_infra();
    PASS();
}

static void test_stateful_overflow_full_processes_local(void)
{
    TEST("routing: overflow full → process locally (misrouted_local)");
    setup_test_infra();
    worker_dequeue_ctx_t ctx;
    worker_dequeue_init(&ctx, 0, 4, test_ring, test_overflows);

    /* Fill worker 2's overflow queue completely */
    for (int i = 0; i < AFFINITY_OVERFLOW_CAPACITY; i++) {
        ring_event_t fill = make_stateless((uint64_t)(1000 + i));
        affinity_overflow_push(&test_overflows[2], &fill);
    }

    /* Now enqueue a stateful event for worker 2 */
    ring_event_t ev = make_stateful(777, 2);
    spmc_ring_enqueue(test_ring, &ev);

    ring_event_t out[WORKER_DEQUEUE_MAX_EVENTS];
    uint32_t n = worker_dequeue_poll(&ctx, out, WORKER_DEQUEUE_MAX_EVENTS,
                                      BP_NORMAL);

    CHECK(n == 1, "should process locally when overflow full");
    CHECK(out[0].socket_cookie == 777, "correct cookie");
    CHECK(ctx.stats.misrouted_local == 1, "misrouted_local should be 1");
    CHECK(ctx.stats.deferred == 0, "no successful defers");

    teardown_test_infra();
    PASS();
}

/*============================================================================
 * 5. BP_CRITICAL Fast Path Tests
 *============================================================================*/

static void test_bp_critical_skips_affinity(void)
{
    TEST("BP_CRITICAL: all events processed locally");
    setup_test_infra();
    worker_dequeue_ctx_t ctx;
    worker_dequeue_init(&ctx, 0, 4, test_ring, test_overflows);

    /* Enqueue stateful event for worker 3 (not us) */
    ring_event_t ev1 = make_stateful(10, 3);
    /* And a stateless event */
    ring_event_t ev2 = make_stateless(20);
    spmc_ring_enqueue(test_ring, &ev1);
    spmc_ring_enqueue(test_ring, &ev2);

    ring_event_t out[WORKER_DEQUEUE_MAX_EVENTS];
    uint32_t n = worker_dequeue_poll(&ctx, out, WORKER_DEQUEUE_MAX_EVENTS,
                                      BP_CRITICAL);

    CHECK(n == 2, "both events processed locally");
    CHECK(ctx.stats.deferred == 0, "no defers under CRITICAL");
    CHECK(ctx.stats.forced_local == 1, "one stateful event forced local");
    CHECK(affinity_overflow_empty(&test_overflows[3]),
          "worker 3 overflow should be empty");

    teardown_test_infra();
    PASS();
}

static void test_bp_critical_tracks_forced_local(void)
{
    TEST("BP_CRITICAL: forced_local counts misrouted stateful only");
    setup_test_infra();
    worker_dequeue_ctx_t ctx;
    worker_dequeue_init(&ctx, 1, 4, test_ring, test_overflows);

    /* Stateful for us (worker 1) — not forced */
    ring_event_t ev1 = make_stateful(10, 1);
    /* Stateful for worker 2 — forced local */
    ring_event_t ev2 = make_stateful(20, 2);
    /* Stateless — not counted */
    ring_event_t ev3 = make_stateless(30);

    spmc_ring_enqueue(test_ring, &ev1);
    spmc_ring_enqueue(test_ring, &ev2);
    spmc_ring_enqueue(test_ring, &ev3);

    ring_event_t out[WORKER_DEQUEUE_MAX_EVENTS];
    uint32_t n = worker_dequeue_poll(&ctx, out, WORKER_DEQUEUE_MAX_EVENTS,
                                      BP_CRITICAL);

    CHECK(n == 3, "all 3 processed locally");
    CHECK(ctx.stats.forced_local == 1, "only 1 forced local (ev2)");

    teardown_test_infra();
    PASS();
}

/*============================================================================
 * 6. Hop-Limit Guard Tests
 *============================================================================*/

static void test_routed_events_from_overflow(void)
{
    TEST("hop-limit: overflow events have ROUTED flag");
    setup_test_infra();
    worker_dequeue_ctx_t ctx;
    worker_dequeue_init(&ctx, 0, 4, test_ring, test_overflows);

    /* Simulate another worker deferring to us with ROUTED set */
    ring_event_t ev = make_stateful(55, 0);
    ring_event_mark_routed(&ev);
    affinity_overflow_push(&test_overflows[0], &ev);

    ring_event_t out[WORKER_DEQUEUE_MAX_EVENTS];
    uint32_t n = worker_dequeue_poll(&ctx, out, WORKER_DEQUEUE_MAX_EVENTS,
                                      BP_NORMAL);

    CHECK(n == 1, "should get 1 event");
    CHECK(out[0].socket_cookie == 55, "correct cookie");
    CHECK(ring_event_is_routed(&out[0]), "event should have ROUTED flag");
    CHECK(ctx.stats.from_overflow == 1, "from_overflow should be 1");

    teardown_test_infra();
    PASS();
}

/*============================================================================
 * 7. Out-of-Bounds Worker Safety Tests
 *============================================================================*/

static void test_oob_preferred_worker(void)
{
    TEST("safety: preferred_worker >= num_workers → local");
    setup_test_infra();
    worker_dequeue_ctx_t ctx;
    worker_dequeue_init(&ctx, 0, 4, test_ring, test_overflows);

    /* Stateful event pointing to worker 200 (way out of bounds) */
    ring_event_t ev = make_event(88, EVENT_FLAG_STATEFUL, 200,
                                  EVENT_TYPE_TLS_DATA);
    spmc_ring_enqueue(test_ring, &ev);

    ring_event_t out[WORKER_DEQUEUE_MAX_EVENTS];
    uint32_t n = worker_dequeue_poll(&ctx, out, WORKER_DEQUEUE_MAX_EVENTS,
                                      BP_NORMAL);

    CHECK(n == 1, "should process locally");
    CHECK(ctx.stats.misrouted_local == 1, "counted as misrouted_local");

    teardown_test_infra();
    PASS();
}

/*============================================================================
 * 8. Statistics Tests
 *============================================================================*/

static void test_stats_accessors(void)
{
    TEST("stats: inline accessors return correct values");
    worker_dequeue_ctx_t ctx;
    worker_dequeue_init(&ctx, 0, 4, test_ring, test_overflows);

    /* Set some stats manually */
    ctx.stats.processed = 100;
    ctx.stats.deferred = 20;
    ctx.stats.from_overflow = 15;
    ctx.stats.misrouted_local = 3;
    ctx.stats.forced_local = 7;
    ctx.stats.polls = 50;
    ctx.stats.empty_polls = 10;

    CHECK(worker_dequeue_stat_processed(&ctx) == 100, "processed");
    CHECK(worker_dequeue_stat_deferred(&ctx) == 20, "deferred");
    CHECK(worker_dequeue_stat_from_overflow(&ctx) == 15, "from_overflow");
    CHECK(worker_dequeue_stat_misrouted_local(&ctx) == 3, "misrouted_local");
    CHECK(worker_dequeue_stat_forced_local(&ctx) == 7, "forced_local");
    CHECK(worker_dequeue_stat_polls(&ctx) == 50, "polls");
    CHECK(worker_dequeue_stat_empty_polls(&ctx) == 10, "empty_polls");

    /* NULL safety */
    CHECK(worker_dequeue_stat_processed(NULL) == 0, "null processed");
    CHECK(worker_dequeue_stat_polls(NULL) == 0, "null polls");

    PASS();
}

/*============================================================================
 * 9. Re-Check Helper Tests
 *============================================================================*/

static void test_has_work_empty(void)
{
    TEST("has_work: false when overflow and ring empty");
    setup_test_infra();
    worker_dequeue_ctx_t ctx;
    worker_dequeue_init(&ctx, 0, 4, test_ring, test_overflows);

    CHECK(!worker_dequeue_has_work(&ctx), "should be false");
    teardown_test_infra();
    PASS();
}

static void test_has_work_overflow(void)
{
    TEST("has_work: true when overflow has events");
    setup_test_infra();
    worker_dequeue_ctx_t ctx;
    worker_dequeue_init(&ctx, 1, 4, test_ring, test_overflows);

    ring_event_t ev = make_stateless(42);
    affinity_overflow_push(&test_overflows[1], &ev);

    CHECK(worker_dequeue_has_work(&ctx), "should be true");
    teardown_test_infra();
    PASS();
}

static void test_has_work_ring(void)
{
    TEST("has_work: true when ring has events");
    setup_test_infra();
    worker_dequeue_ctx_t ctx;
    worker_dequeue_init(&ctx, 0, 4, test_ring, test_overflows);

    ring_event_t ev = make_stateless(42);
    spmc_ring_enqueue(test_ring, &ev);

    CHECK(worker_dequeue_has_work(&ctx), "should be true");
    teardown_test_infra();
    PASS();
}

static void test_has_work_null(void)
{
    TEST("has_work: false on NULL ctx");
    CHECK(!worker_dequeue_has_work(NULL), "should be false");
    PASS();
}

/*============================================================================
 * 10. Max Count Clamping Tests
 *============================================================================*/

static void test_max_count_clamped(void)
{
    TEST("poll: max_count clamped to MAX_EVENTS");
    setup_test_infra();
    worker_dequeue_ctx_t ctx;
    worker_dequeue_init(&ctx, 0, 4, test_ring, test_overflows);

    ring_event_t out[WORKER_DEQUEUE_MAX_EVENTS];
    /* Should not crash with very large max_count */
    uint32_t n = worker_dequeue_poll(&ctx, out, 9999, BP_NORMAL);
    CHECK(n == 0, "empty ring, 0 events regardless of max");
    teardown_test_infra();
    PASS();
}

/*============================================================================
 * 11. Adaptive Poll State Machine Tests
 *============================================================================*/

static void test_adaptive_init(void)
{
    TEST("adaptive: init starts at POLL_LIGHT");
    adaptive_poll_state_t state;
    adaptive_poll_init(&state);
    CHECK(state.level == POLL_LIGHT, "initial level");
    CHECK(state.empty_streak == 0, "initial streak");
    CHECK(state.transitions == 0, "initial transitions");
    PASS();
}

static void test_adaptive_full_batch_goes_busy(void)
{
    TEST("adaptive: full batch → BUSY (skip epoll)");
    adaptive_poll_state_t state;
    adaptive_poll_init(&state);

    int timeout = adaptive_poll_timeout(&state, 16, 16, BP_NORMAL);
    CHECK(timeout == ADAPTIVE_POLL_SKIP, "should skip epoll");
    CHECK(state.level == POLL_BUSY, "should be BUSY");
    PASS();
}

static void test_adaptive_bp_high_goes_busy(void)
{
    TEST("adaptive: BP_HIGH → BUSY regardless of events");
    adaptive_poll_state_t state;
    adaptive_poll_init(&state);

    int timeout = adaptive_poll_timeout(&state, 0, 16, BP_HIGH);
    CHECK(timeout == ADAPTIVE_POLL_SKIP, "should skip epoll");
    CHECK(state.level == POLL_BUSY, "should be BUSY");
    PASS();
}

static void test_adaptive_bp_critical_goes_busy(void)
{
    TEST("adaptive: BP_CRITICAL → BUSY");
    adaptive_poll_state_t state;
    adaptive_poll_init(&state);

    int timeout = adaptive_poll_timeout(&state, 0, 16, BP_CRITICAL);
    CHECK(timeout == ADAPTIVE_POLL_SKIP, "should skip epoll");
    CHECK(state.level == POLL_BUSY, "should be BUSY");
    PASS();
}

static void test_adaptive_events_go_light(void)
{
    TEST("adaptive: events received → LIGHT (1ms)");
    adaptive_poll_state_t state;
    adaptive_poll_init(&state);

    /* Force to IDLE first */
    for (int i = 0; i < 10; i++)
        adaptive_poll_timeout(&state, 0, 16, BP_NORMAL);
    CHECK(state.level == POLL_IDLE, "should be IDLE");

    /* Events should bring us back to LIGHT */
    int timeout = adaptive_poll_timeout(&state, 5, 16, BP_NORMAL);
    CHECK(timeout == ADAPTIVE_POLL_LIGHT_MS, "should be 1ms");
    CHECK(state.level == POLL_LIGHT, "should be LIGHT");
    PASS();
}

static void test_adaptive_bp_elevated_floor(void)
{
    TEST("adaptive: BP_ELEVATED with events → at least MEDIUM");
    adaptive_poll_state_t state;
    adaptive_poll_init(&state);

    int timeout = adaptive_poll_timeout(&state, 3, 16, BP_ELEVATED);
    CHECK(timeout == ADAPTIVE_POLL_MEDIUM_MS, "should be 0ms");
    CHECK(state.level == POLL_MEDIUM, "should be MEDIUM");
    PASS();
}

static void test_adaptive_empty_polls_step_down(void)
{
    TEST("adaptive: empty polls step down toward IDLE");
    adaptive_poll_state_t state;
    adaptive_poll_init(&state);

    /* Start at LIGHT, send enough empty polls to step down */
    for (int i = 0; i < ADAPTIVE_POLL_COOLDOWN; i++)
        adaptive_poll_timeout(&state, 0, 16, BP_NORMAL);

    /* After cooldown empty polls at LIGHT, should step to IDLE */
    /* (LIGHT - 1 = IDLE) */
    CHECK(state.level == POLL_IDLE, "should step to IDLE");
    PASS();
}

static void test_adaptive_idle_stays_idle(void)
{
    TEST("adaptive: IDLE stays IDLE on continued empty polls");
    adaptive_poll_state_t state;
    adaptive_poll_init(&state);

    /* Force to IDLE */
    for (int i = 0; i < 10; i++)
        adaptive_poll_timeout(&state, 0, 16, BP_NORMAL);
    CHECK(state.level == POLL_IDLE, "should be IDLE");

    /* More empty polls should stay IDLE */
    int timeout = adaptive_poll_timeout(&state, 0, 16, BP_NORMAL);
    CHECK(timeout == ADAPTIVE_POLL_IDLE_MS, "should be 100ms");
    CHECK(state.level == POLL_IDLE, "should stay IDLE");
    PASS();
}

static void test_adaptive_transition_counter(void)
{
    TEST("adaptive: transition counter increments on changes");
    adaptive_poll_state_t state;
    adaptive_poll_init(&state);

    uint64_t initial = state.transitions;

    /* LIGHT → BUSY (full batch) */
    adaptive_poll_timeout(&state, 16, 16, BP_NORMAL);
    CHECK(state.transitions == initial + 1, "one transition");

    /* BUSY → LIGHT (some events, not full) */
    adaptive_poll_timeout(&state, 5, 16, BP_NORMAL);
    CHECK(state.transitions == initial + 2, "two transitions");

    PASS();
}

static void test_adaptive_level_name(void)
{
    TEST("adaptive: level names correct");
    CHECK(strcmp(adaptive_poll_level_name(POLL_IDLE), "IDLE") == 0, "IDLE");
    CHECK(strcmp(adaptive_poll_level_name(POLL_LIGHT), "LIGHT") == 0, "LIGHT");
    CHECK(strcmp(adaptive_poll_level_name(POLL_MEDIUM), "MEDIUM") == 0, "MEDIUM");
    CHECK(strcmp(adaptive_poll_level_name(POLL_BUSY), "BUSY") == 0, "BUSY");
    CHECK(strcmp(adaptive_poll_level_name(99), "UNKNOWN") == 0, "invalid");
    PASS();
}

static void test_adaptive_null_state(void)
{
    TEST("adaptive: NULL state returns defaults");
    int timeout = adaptive_poll_timeout(NULL, 5, 16, BP_NORMAL);
    CHECK(timeout == ADAPTIVE_POLL_LIGHT_MS, "default 1ms");
    CHECK(adaptive_poll_current(NULL) == POLL_LIGHT, "default level");
    CHECK(adaptive_poll_stat_transitions(NULL) == 0, "default transitions");
    CHECK(adaptive_poll_stat_empty_streak(NULL) == 0, "default streak");
    PASS();
}

/*============================================================================
 * 12. Mixed Scenario Tests
 *============================================================================*/

static void test_mixed_overflow_and_ring(void)
{
    TEST("mixed: overflow + ring with affinity routing");
    setup_test_infra();
    worker_dequeue_ctx_t ctx;
    worker_dequeue_init(&ctx, 0, 4, test_ring, test_overflows);

    /* 2 overflow events */
    ring_event_t ov1 = make_stateless(1);
    ring_event_mark_routed(&ov1);
    ring_event_t ov2 = make_stateless(2);
    ring_event_mark_routed(&ov2);
    affinity_overflow_push(&test_overflows[0], &ov1);
    affinity_overflow_push(&test_overflows[0], &ov2);

    /* 3 ring events: 2 local (stateless + correct worker), 1 defer */
    ring_event_t r1 = make_stateless(10);
    ring_event_t r2 = make_stateful(20, 0);  /* us */
    ring_event_t r3 = make_stateful(30, 2);  /* not us */
    spmc_ring_enqueue(test_ring, &r1);
    spmc_ring_enqueue(test_ring, &r2);
    spmc_ring_enqueue(test_ring, &r3);

    ring_event_t out[WORKER_DEQUEUE_MAX_EVENTS];
    uint32_t n = worker_dequeue_poll(&ctx, out, WORKER_DEQUEUE_MAX_EVENTS,
                                      BP_NORMAL);

    /* 2 overflow + 2 local from ring = 4 (1 deferred) */
    CHECK(n == 4, "should get 4 events");
    CHECK(ctx.stats.from_overflow == 2, "2 from overflow");
    CHECK(ctx.stats.deferred == 1, "1 deferred");
    CHECK(ctx.stats.processed == 4, "4 processed");

    teardown_test_infra();
    PASS();
}

/*============================================================================
 * Main
 *============================================================================*/

int main(void)
{
    printf("\n=== Worker Dequeue & Adaptive Poll Tests ===\n\n");

    /* Create shared test infrastructure */
    setup_test_infra();

    /* 1. Init validation */
    printf("  --- Init Validation ---\n");
    test_init_null_ctx();
    test_init_null_ring();
    test_init_null_overflows();
    test_init_zero_workers();
    test_init_worker_id_out_of_range();
    test_init_valid();

    /* 2. Empty poll */
    printf("\n  --- Empty Poll ---\n");
    test_poll_empty_ring();
    test_poll_null_args();

    teardown_test_infra();

    /* 3. Phase 1: Overflow drain */
    printf("\n  --- Phase 1: Overflow Drain ---\n");
    test_overflow_drain_priority();

    /* 4. Phase 3: Affinity routing */
    printf("\n  --- Phase 3: Affinity Routing ---\n");
    test_stateless_events_local();
    test_stateful_correct_worker();
    test_stateful_wrong_worker_defers();
    test_stateful_overflow_full_processes_local();

    /* 5. BP_CRITICAL */
    printf("\n  --- BP_CRITICAL Fast Path ---\n");
    test_bp_critical_skips_affinity();
    test_bp_critical_tracks_forced_local();

    /* 6. Hop-limit guard */
    printf("\n  --- Hop-Limit Guard ---\n");
    test_routed_events_from_overflow();

    /* 7. OOB safety */
    printf("\n  --- Out-of-Bounds Safety ---\n");
    test_oob_preferred_worker();

    /* 8. Stats */
    printf("\n  --- Statistics ---\n");
    setup_test_infra();
    test_stats_accessors();
    teardown_test_infra();

    /* 9. Re-check helper */
    printf("\n  --- Re-Check Helper ---\n");
    test_has_work_empty();
    test_has_work_overflow();
    test_has_work_ring();
    test_has_work_null();

    /* 10. Max count */
    printf("\n  --- Max Count Clamping ---\n");
    test_max_count_clamped();

    /* 11. Adaptive poll */
    printf("\n  --- Adaptive Poll State Machine ---\n");
    test_adaptive_init();
    test_adaptive_full_batch_goes_busy();
    test_adaptive_bp_high_goes_busy();
    test_adaptive_bp_critical_goes_busy();
    test_adaptive_events_go_light();
    test_adaptive_bp_elevated_floor();
    test_adaptive_empty_polls_step_down();
    test_adaptive_idle_stays_idle();
    test_adaptive_transition_counter();
    test_adaptive_level_name();
    test_adaptive_null_state();

    /* 12. Mixed scenarios */
    printf("\n  --- Mixed Scenarios ---\n");
    test_mixed_overflow_and_ring();

    /* Summary */
    printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf(", %d FAILED", tests_failed);
    printf(" ===\n\n");

    return tests_failed > 0 ? 1 : 0;
}
