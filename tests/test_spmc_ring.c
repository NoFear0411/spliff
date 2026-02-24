/**
 * @file test_spmc_ring.c
 * @brief Unit tests for SPMC ring buffer (Phase 2 - lock-free transport)
 *
 * Tests cover:
 * - Structure layout verification (sizes, offsets, cache-line isolation)
 * - Routing word pack/unpack round-trip
 * - Single enqueue/dequeue correctness
 * - Batch enqueue/dequeue correctness
 * - Ring full/empty boundary conditions
 * - Capacity validation (power-of-2 enforcement)
 * - Diagnostics (depth, fill ratio, stats)
 *
 * Concurrent tests (multi-consumer) are in Task #16.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "../src/ring/spmc_ring.h"

/*============================================================================
 * Test Framework (minimal, same style as test_mirrored_buffer.c)
 *============================================================================*/

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { \
        tests_run++; \
        printf("  [%02d] %-50s ", tests_run, name); \
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

static void test_ring_event_size(void) {
    TEST("ring_event_t is 56 bytes");
    CHECK(sizeof(ring_event_t) == 56, "expected 56 bytes");
    PASS();
}

static void test_spmc_slot_size(void) {
    TEST("spmc_slot_t is 64 bytes (1 cache line)");
    CHECK(sizeof(spmc_slot_t) == 64, "expected 64 bytes");
    PASS();
}

static void test_slot_seq_first(void) {
    TEST("Slot: seq at offset 0 (readiness-first)");
    CHECK(offsetof(spmc_slot_t, seq) == 0, "seq must be at offset 0");
    PASS();
}

static void test_slot_event_offset(void) {
    TEST("Slot: event at offset 8");
    CHECK(offsetof(spmc_slot_t, event) == 8, "event must be at offset 8");
    PASS();
}

static void test_ring_head_offset(void) {
    TEST("Ring: head at offset 0 (producer line)");
    CHECK(offsetof(spmc_ring_t, head) == 0, "head must be at offset 0");
    PASS();
}

static void test_ring_tail_isolation(void) {
    TEST("Ring: tail at offset 128 (consumer line)");
    CHECK(offsetof(spmc_ring_t, tail) == 128, "tail must be at offset 128");
    PASS();
}

static void test_ring_capacity_isolation(void) {
    TEST("Ring: capacity at offset 256 (config line)");
    CHECK(offsetof(spmc_ring_t, capacity) == 256, "capacity must be at offset 256");
    PASS();
}

static void test_ring_slots_offset(void) {
    TEST("Ring: slots ptr on config line (offset 288)");
    CHECK(offsetof(spmc_ring_t, slots) == 288, "slots ptr must be at offset 288");
    PASS();
}

static void test_ring_slot_buf_offset(void) {
    TEST("Ring: slot_buf ptr on config line (offset 296)");
    CHECK(offsetof(spmc_ring_t, slot_buf) == 296, "slot_buf must be at offset 296");
    PASS();
}

static void test_ring_header_size(void) {
    TEST("Ring: header is 384 bytes (3 cache lines)");
    CHECK(sizeof(spmc_ring_t) == 384, "ring header must be 384 bytes");
    PASS();
}

/*============================================================================
 * 2. Routing Word Tests
 *============================================================================*/

static void test_route_pack_unpack(void) {
    TEST("Routing word round-trip (flags/worker/type/gen)");
    uint64_t r = route_pack(EVENT_FLAG_STATEFUL | EVENT_FLAG_URGENT,
                            7, EVENT_TYPE_SSL_DATA, 0xDEADBEEF);
    CHECK(route_flags(r) == 0x03, "flags mismatch");
    CHECK(route_worker(r) == 7, "worker mismatch");
    CHECK(route_type(r) == 0, "type mismatch");
    CHECK(route_generation(r) == 0xDEADBEEF, "generation mismatch");
    PASS();
}

static void test_route_max_values(void) {
    TEST("Routing word max values (255/255/255/0xFFFFFFFF)");
    uint64_t r = route_pack(0xFF, 0xFF, 0xFF, 0xFFFFFFFF);
    CHECK(route_flags(r) == 0xFF, "max flags");
    CHECK(route_worker(r) == 0xFF, "max worker");
    CHECK(route_type(r) == 0xFF, "max type");
    CHECK(route_generation(r) == 0xFFFFFFFF, "max gen");
    PASS();
}

static void test_route_zero(void) {
    TEST("Routing word all zeros");
    uint64_t r = route_pack(0, 0, 0, 0);
    CHECK(r == 0, "all-zero should be 0");
    CHECK(route_flags(r) == 0, "zero flags");
    CHECK(route_worker(r) == 0, "zero worker");
    PASS();
}

/*============================================================================
 * 3. Event Helper Tests
 *============================================================================*/

static void test_event_stateful_check(void) {
    TEST("ring_event_is_stateful() flag check");
    ring_event_t ev = { .routing = route_pack(EVENT_FLAG_STATEFUL, 0, 0, 0) };
    CHECK(ring_event_is_stateful(&ev), "should be stateful");

    ring_event_t ev2 = { .routing = route_pack(0, 0, 0, 0) };
    CHECK(!ring_event_is_stateful(&ev2), "should not be stateful");
    PASS();
}

static void test_event_urgent_check(void) {
    TEST("ring_event_is_urgent() flag check");
    ring_event_t ev = { .routing = route_pack(EVENT_FLAG_URGENT, 0, 0, 0) };
    CHECK(ring_event_is_urgent(&ev), "should be urgent");
    PASS();
}

static void test_event_preferred_worker(void) {
    TEST("ring_event_preferred_worker() extraction");
    ring_event_t ev = { .routing = route_pack(0, 42, 0, 0) };
    CHECK(ring_event_preferred_worker(&ev) == 42, "worker should be 42");
    PASS();
}

/*============================================================================
 * 4. Lifecycle Tests
 *============================================================================*/

static void test_create_destroy(void) {
    TEST("Create and destroy ring (capacity=64)");
    spmc_ring_t *ring = spmc_ring_create(64);
    CHECK(ring != NULL, "create failed");
    CHECK(spmc_ring_get_capacity(ring) == 64, "capacity mismatch");
    CHECK(spmc_ring_empty(ring), "new ring should be empty");
    CHECK(!spmc_ring_full(ring), "new ring should not be full");
    spmc_ring_destroy(ring);
    PASS();
}

static void test_create_minimum(void) {
    TEST("Create ring with minimum capacity (4)");
    spmc_ring_t *ring = spmc_ring_create(4);
    CHECK(ring != NULL, "create with cap=4 failed");
    CHECK(spmc_ring_get_capacity(ring) == 4, "capacity should be 4");
    spmc_ring_destroy(ring);
    PASS();
}

static void test_create_reject_non_power2(void) {
    TEST("Reject non-power-of-2 capacity");
    CHECK(spmc_ring_create(3) == NULL, "cap=3 should fail");
    CHECK(spmc_ring_create(5) == NULL, "cap=5 should fail");
    CHECK(spmc_ring_create(100) == NULL, "cap=100 should fail");
    PASS();
}

static void test_create_reject_too_small(void) {
    TEST("Reject capacity < 4");
    CHECK(spmc_ring_create(0) == NULL, "cap=0 should fail");
    CHECK(spmc_ring_create(1) == NULL, "cap=1 should fail");
    CHECK(spmc_ring_create(2) == NULL, "cap=2 should fail");
    PASS();
}

static void test_destroy_null_safe(void) {
    TEST("Destroy NULL is safe no-op");
    spmc_ring_destroy(NULL); /* Should not crash */
    PASS();
}

static void test_create_mirrored_path(void) {
    TEST("Create ring with mirrored buffer (capacity=1024)");
    /* 1024 slots × 64 bytes = 64KB = MIN_BUFFER_SIZE → mirrored path */
    spmc_ring_t *ring = spmc_ring_create(1024);
    CHECK(ring != NULL, "create with cap=1024 failed");
    CHECK(spmc_ring_get_capacity(ring) == 1024, "capacity should be 1024");
    CHECK(spmc_ring_is_mirrored(ring), "should use mirrored buffer");
    CHECK(ring->slots != NULL, "slots pointer must be set");
    CHECK(ring->slot_buf != NULL, "slot_buf must be set");

    /* Verify basic operation through mirrored buffer */
    ring_event_t ev = { .socket_cookie = 0xBEEF };
    CHECK(spmc_ring_enqueue(ring, &ev), "enqueue failed");
    ring_event_t out = {0};
    CHECK(spmc_ring_dequeue(ring, &out), "dequeue failed");
    CHECK(out.socket_cookie == 0xBEEF, "data mismatch");

    spmc_ring_destroy(ring);
    PASS();
}

static void test_create_heap_fallback(void) {
    TEST("Create small ring uses heap fallback (capacity=4)");
    /* 4 slots × 64 bytes = 256 bytes < MIN_BUFFER_SIZE → heap path */
    spmc_ring_t *ring = spmc_ring_create(4);
    CHECK(ring != NULL, "create with cap=4 failed");
    CHECK(!spmc_ring_is_mirrored(ring), "small ring should NOT be mirrored");
    CHECK(ring->slots != NULL, "slots pointer must be set");
    CHECK(ring->slot_buf == NULL, "slot_buf must be NULL for heap path");
    spmc_ring_destroy(ring);
    PASS();
}

static void test_mirrored_wraparound(void) {
    TEST("Mirrored ring wrap-around correctness");
    spmc_ring_t *ring = spmc_ring_create(1024);
    CHECK(ring != NULL, "create failed");
    CHECK(spmc_ring_is_mirrored(ring), "should be mirrored");

    /* Fill and drain 3 full cycles (3072 enqueue/dequeue on 1024-slot ring) */
    ring_event_t ev, out;
    for (int cycle = 0; cycle < 3; cycle++) {
        for (int i = 0; i < 1024; i++) {
            ev = (ring_event_t){ .socket_cookie = (uint64_t)(cycle * 1024 + i) };
            CHECK(spmc_ring_enqueue(ring, &ev), "enqueue failed at wrap");
        }
        for (int i = 0; i < 1024; i++) {
            CHECK(spmc_ring_dequeue(ring, &out), "dequeue failed at wrap");
            CHECK(out.socket_cookie == (uint64_t)(cycle * 1024 + i),
                  "data wrong at wrap");
        }
    }

    CHECK(spmc_ring_empty(ring), "should be empty after cycles");
    spmc_ring_destroy(ring);
    PASS();
}

/*============================================================================
 * 5. Single Enqueue/Dequeue Tests
 *============================================================================*/

static void test_single_enqueue_dequeue(void) {
    TEST("Single enqueue → dequeue round-trip");
    spmc_ring_t *ring = spmc_ring_create(8);
    CHECK(ring != NULL, "create failed");

    ring_event_t ev = {
        .socket_cookie = 12345,
        .routing = route_pack(EVENT_FLAG_STATEFUL, 3, EVENT_TYPE_SSL_DATA, 42),
        .data_len = 100,
        .flow_key_hash = 0xCAFEBABE,
    };

    CHECK(spmc_ring_enqueue(ring, &ev), "enqueue failed");
    CHECK(spmc_ring_depth(ring) == 1, "depth should be 1");

    ring_event_t out = {0};
    CHECK(spmc_ring_dequeue(ring, &out), "dequeue failed");
    CHECK(out.socket_cookie == 12345, "cookie mismatch");
    CHECK(route_worker(out.routing) == 3, "worker mismatch");
    CHECK(route_generation(out.routing) == 42, "gen mismatch");
    CHECK(out.data_len == 100, "data_len mismatch");
    CHECK(out.flow_key_hash == 0xCAFEBABE, "hash mismatch");
    CHECK(spmc_ring_depth(ring) == 0, "depth should be 0");

    spmc_ring_destroy(ring);
    PASS();
}

static void test_dequeue_empty(void) {
    TEST("Dequeue from empty ring returns false");
    spmc_ring_t *ring = spmc_ring_create(8);
    CHECK(ring != NULL, "create failed");

    ring_event_t out = {0};
    CHECK(!spmc_ring_dequeue(ring, &out), "should return false");

    spmc_ring_destroy(ring);
    PASS();
}

static void test_enqueue_null_guard(void) {
    TEST("Enqueue with NULL args returns false");
    spmc_ring_t *ring = spmc_ring_create(8);
    ring_event_t ev = {0};

    CHECK(!spmc_ring_enqueue(NULL, &ev), "NULL ring should fail");
    CHECK(!spmc_ring_enqueue(ring, NULL), "NULL event should fail");

    spmc_ring_destroy(ring);
    PASS();
}

static void test_fill_and_overflow(void) {
    TEST("Fill ring to capacity, verify overflow drops");
    spmc_ring_t *ring = spmc_ring_create(4);
    CHECK(ring != NULL, "create failed");

    ring_event_t ev = { .socket_cookie = 1 };
    /* Fill all 4 slots */
    for (int i = 0; i < 4; i++) {
        ev.socket_cookie = (uint64_t)(i + 1);
        CHECK(spmc_ring_enqueue(ring, &ev), "enqueue should succeed");
    }

    CHECK(spmc_ring_full(ring), "ring should be full");

    /* 5th enqueue should fail */
    ev.socket_cookie = 999;
    CHECK(!spmc_ring_enqueue(ring, &ev), "enqueue to full ring should fail");
    CHECK(spmc_ring_stat_drops(ring) == 1, "drops should be 1");

    /* Drain and verify order */
    ring_event_t out;
    for (int i = 0; i < 4; i++) {
        CHECK(spmc_ring_dequeue(ring, &out), "dequeue should succeed");
        CHECK(out.socket_cookie == (uint64_t)(i + 1), "order mismatch");
    }

    CHECK(spmc_ring_empty(ring), "ring should be empty after drain");

    spmc_ring_destroy(ring);
    PASS();
}

/*============================================================================
 * 6. Batch Enqueue/Dequeue Tests
 *============================================================================*/

static void test_batch_enqueue_dequeue(void) {
    TEST("Batch enqueue 8 → batch dequeue 8");
    spmc_ring_t *ring = spmc_ring_create(64);
    CHECK(ring != NULL, "create failed");

    ring_event_t batch[8];
    for (int i = 0; i < 8; i++) {
        batch[i] = (ring_event_t){
            .socket_cookie = 100 + (uint64_t)i,
            .routing = route_pack(0, (uint8_t)i, EVENT_TYPE_XDP_META, (uint32_t)i),
        };
    }

    uint32_t enqueued = spmc_ring_enqueue_batch(ring, batch, 8);
    CHECK(enqueued == 8, "should enqueue all 8");
    CHECK(spmc_ring_depth(ring) == 8, "depth should be 8");

    ring_event_t out[8];
    uint32_t dequeued = spmc_ring_dequeue_batch(ring, out, 8);
    CHECK(dequeued == 8, "should dequeue all 8");

    for (uint32_t i = 0; i < 8; i++) {
        CHECK(out[i].socket_cookie == 100 + i, "cookie mismatch in batch");
        CHECK(route_worker(out[i].routing) == (uint8_t)i, "worker mismatch in batch");
    }

    CHECK(spmc_ring_empty(ring), "ring should be empty");
    spmc_ring_destroy(ring);
    PASS();
}

static void test_batch_partial_enqueue(void) {
    TEST("Batch enqueue trimmed to available capacity");
    spmc_ring_t *ring = spmc_ring_create(4);
    CHECK(ring != NULL, "create failed");

    ring_event_t batch[8];
    for (int i = 0; i < 8; i++) {
        batch[i] = (ring_event_t){ .socket_cookie = (uint64_t)i };
    }

    uint32_t enqueued = spmc_ring_enqueue_batch(ring, batch, 8);
    CHECK(enqueued == 4, "should only enqueue 4 (capacity limit)");
    CHECK(spmc_ring_full(ring), "ring should be full");

    spmc_ring_destroy(ring);
    PASS();
}

static void test_batch_dequeue_empty(void) {
    TEST("Batch dequeue from empty ring returns 0");
    spmc_ring_t *ring = spmc_ring_create(8);
    ring_event_t out[4];
    uint32_t n = spmc_ring_dequeue_batch(ring, out, 4);
    CHECK(n == 0, "should return 0");
    spmc_ring_destroy(ring);
    PASS();
}

static void test_batch_null_guard(void) {
    TEST("Batch operations with NULL args return 0");
    spmc_ring_t *ring = spmc_ring_create(8);
    ring_event_t batch[4] = {0};

    CHECK(spmc_ring_enqueue_batch(NULL, batch, 4) == 0, "NULL ring");
    CHECK(spmc_ring_enqueue_batch(ring, NULL, 4) == 0, "NULL events");
    CHECK(spmc_ring_enqueue_batch(ring, batch, 0) == 0, "zero count");
    CHECK(spmc_ring_dequeue_batch(NULL, batch, 4) == 0, "NULL ring dequeue");
    CHECK(spmc_ring_dequeue_batch(ring, NULL, 4) == 0, "NULL out dequeue");

    spmc_ring_destroy(ring);
    PASS();
}

/*============================================================================
 * 7. Wrap-Around Tests
 *============================================================================*/

static void test_wraparound(void) {
    TEST("Ring operates correctly across wrap boundary");
    spmc_ring_t *ring = spmc_ring_create(4);
    CHECK(ring != NULL, "create failed");

    ring_event_t ev, out;
    /* Do 3 full cycles (12 enqueue/dequeue on 4-slot ring) */
    for (int cycle = 0; cycle < 3; cycle++) {
        for (int i = 0; i < 4; i++) {
            ev = (ring_event_t){ .socket_cookie = (uint64_t)(cycle * 4 + i) };
            CHECK(spmc_ring_enqueue(ring, &ev), "enqueue failed at wrap");
        }
        for (int i = 0; i < 4; i++) {
            CHECK(spmc_ring_dequeue(ring, &out), "dequeue failed at wrap");
            CHECK(out.socket_cookie == (uint64_t)(cycle * 4 + i), "data wrong at wrap");
        }
    }

    CHECK(spmc_ring_empty(ring), "should be empty after cycles");
    spmc_ring_destroy(ring);
    PASS();
}

/*============================================================================
 * 8. Diagnostics Tests
 *============================================================================*/

static void test_fill_ratio(void) {
    TEST("Fill ratio reports correct percentages");
    spmc_ring_t *ring = spmc_ring_create(4);
    CHECK(ring != NULL, "create failed");

    double ratio = spmc_ring_fill_ratio(ring);
    CHECK(ratio == 0.0, "empty ring should be 0.0");

    ring_event_t ev = {0};
    spmc_ring_enqueue(ring, &ev);
    ratio = spmc_ring_fill_ratio(ring);
    CHECK(ratio > 0.24 && ratio < 0.26, "1/4 should be ~0.25");

    spmc_ring_enqueue(ring, &ev);
    spmc_ring_enqueue(ring, &ev);
    spmc_ring_enqueue(ring, &ev);
    ratio = spmc_ring_fill_ratio(ring);
    CHECK(ratio == 1.0, "full ring should be 1.0");

    spmc_ring_destroy(ring);
    PASS();
}

static void test_stats_tracking(void) {
    TEST("Stats: drops, dequeues, cas_retries tracked");
    spmc_ring_t *ring = spmc_ring_create(4);
    CHECK(ring != NULL, "create failed");

    /* Fill ring */
    ring_event_t ev = {0};
    for (int i = 0; i < 4; i++)
        spmc_ring_enqueue(ring, &ev);

    /* Overflow → drops */
    spmc_ring_enqueue(ring, &ev);
    spmc_ring_enqueue(ring, &ev);
    CHECK(spmc_ring_stat_drops(ring) == 2, "drops should be 2");

    /* Drain → dequeues */
    ring_event_t out;
    for (int i = 0; i < 4; i++)
        spmc_ring_dequeue(ring, &out);
    CHECK(spmc_ring_stat_dequeues(ring) == 4, "dequeues should be 4");

    /* CAS retries require contention (multi-threaded), skip here */
    CHECK(spmc_ring_stat_cas_retries(ring) == 0, "no retries in single-threaded");

    spmc_ring_destroy(ring);
    PASS();
}

/*============================================================================
 * Main
 *============================================================================*/

int main(void) {
    printf("=== SPMC Ring Buffer Tests (Phase 2) ===\n\n");

    printf("--- Structure Layout ---\n");
    test_ring_event_size();
    test_spmc_slot_size();
    test_slot_seq_first();
    test_slot_event_offset();
    test_ring_head_offset();
    test_ring_tail_isolation();
    test_ring_capacity_isolation();
    test_ring_slots_offset();
    test_ring_slot_buf_offset();
    test_ring_header_size();

    printf("\n--- Routing Word ---\n");
    test_route_pack_unpack();
    test_route_max_values();
    test_route_zero();

    printf("\n--- Event Helpers ---\n");
    test_event_stateful_check();
    test_event_urgent_check();
    test_event_preferred_worker();

    printf("\n--- Lifecycle ---\n");
    test_create_destroy();
    test_create_minimum();
    test_create_reject_non_power2();
    test_create_reject_too_small();
    test_destroy_null_safe();
    test_create_mirrored_path();
    test_create_heap_fallback();
    test_mirrored_wraparound();

    printf("\n--- Single Enqueue/Dequeue ---\n");
    test_single_enqueue_dequeue();
    test_dequeue_empty();
    test_enqueue_null_guard();
    test_fill_and_overflow();

    printf("\n--- Batch Enqueue/Dequeue ---\n");
    test_batch_enqueue_dequeue();
    test_batch_partial_enqueue();
    test_batch_dequeue_empty();
    test_batch_null_guard();

    printf("\n--- Wrap-Around ---\n");
    test_wraparound();

    printf("\n--- Diagnostics ---\n");
    test_fill_ratio();
    test_stats_tracking();

    printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf(", %d FAILED", tests_failed);
    printf(" ===\n");

    return tests_failed > 0 ? 1 : 0;
}
