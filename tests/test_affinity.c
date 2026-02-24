/**
 * @file test_affinity.c
 * @brief Unit tests for affinity check and MPSC overflow queue
 *
 * Tests cover:
 * - Structure layout verification (cache-line isolation, slot size)
 * - Affinity check routing decisions (stateful/stateless/worker match)
 * - Overflow queue init, push, drain round-trip
 * - Queue full behavior (push_fails counter)
 * - Wrap-around correctness (multiple laps)
 * - Vyukov sequence verification (tail + mask + 1 release)
 * - Drain prefetch path (batch drain)
 *
 * Concurrent MPSC tests (multi-producer stress) are in Task #16.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "../src/ring/affinity.h"

/*============================================================================
 * Test Framework
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

static void test_mpsc_slot_size(void) {
    TEST("mpsc_slot_t is 64 bytes");
    CHECK(sizeof(mpsc_slot_t) == 64, "expected 64 bytes");
    PASS();
}

static void test_overflow_head_offset(void) {
    TEST("Overflow: head at offset 0 (producer line)");
    CHECK(offsetof(affinity_overflow_t, head) == 0, "head must be 0");
    PASS();
}

static void test_overflow_tail_isolation(void) {
    TEST("Overflow: tail at offset 128 (consumer line)");
    CHECK(offsetof(affinity_overflow_t, tail) == 128, "tail must be 128");
    PASS();
}

static void test_overflow_slots_offset(void) {
    TEST("Overflow: slots at offset 256");
    CHECK(offsetof(affinity_overflow_t, slots) == 256, "slots must be 256");
    PASS();
}

static void test_overflow_push_fails_on_producer_line(void) {
    TEST("push_fails on producer cache line (< 128)");
    CHECK(offsetof(affinity_overflow_t, push_fails) < 128,
          "push_fails must be on producer line");
    PASS();
}

static void test_overflow_drains_on_consumer_line(void) {
    TEST("drains on consumer cache line (>= 128, < 256)");
    size_t off = offsetof(affinity_overflow_t, drains);
    CHECK(off >= 128 && off < 256,
          "drains must be on consumer line");
    PASS();
}

/*============================================================================
 * 2. Affinity Check Tests
 *============================================================================*/

static void test_affinity_stateless_local(void) {
    TEST("Stateless event -> AFFINITY_LOCAL (any worker)");
    ring_event_t ev = {
        .routing = route_pack(0, 5, EVENT_TYPE_SSL_DATA, 0),
    };
    /* Stateless (no EVENT_FLAG_STATEFUL), worker 5 */
    CHECK(affinity_check(&ev, 0) == AFFINITY_LOCAL,
          "stateless should be LOCAL for worker 0");
    CHECK(affinity_check(&ev, 5) == AFFINITY_LOCAL,
          "stateless should be LOCAL for worker 5");
    CHECK(affinity_check(&ev, 99) == AFFINITY_LOCAL,
          "stateless should be LOCAL for any worker");
    PASS();
}

static void test_affinity_stateful_match(void) {
    TEST("Stateful + preferred_worker match -> AFFINITY_LOCAL");
    ring_event_t ev = {
        .routing = route_pack(EVENT_FLAG_STATEFUL, 3, EVENT_TYPE_SSL_DATA, 0),
    };
    CHECK(affinity_check(&ev, 3) == AFFINITY_LOCAL,
          "should be LOCAL when worker matches");
    PASS();
}

static void test_affinity_stateful_mismatch(void) {
    TEST("Stateful + preferred_worker mismatch -> AFFINITY_DEFER");
    ring_event_t ev = {
        .routing = route_pack(EVENT_FLAG_STATEFUL, 3, EVENT_TYPE_SSL_DATA, 0),
    };
    CHECK(affinity_check(&ev, 0) == AFFINITY_DEFER,
          "should DEFER when worker 0 != preferred 3");
    CHECK(affinity_check(&ev, 7) == AFFINITY_DEFER,
          "should DEFER when worker 7 != preferred 3");
    PASS();
}

static void test_affinity_stateful_xdp(void) {
    TEST("Stateful + XDP flag -> still checks worker");
    ring_event_t ev = {
        .routing = route_pack(
            EVENT_FLAG_STATEFUL | EVENT_FLAG_XDP, 2,
            EVENT_TYPE_XDP_META, 0),
    };
    CHECK(affinity_check(&ev, 2) == AFFINITY_LOCAL, "match");
    CHECK(affinity_check(&ev, 0) == AFFINITY_DEFER, "mismatch");
    PASS();
}

/*============================================================================
 * 3. Overflow Queue Lifecycle Tests
 *============================================================================*/

static affinity_overflow_t queue;

static void test_init(void) {
    TEST("Init: masks set, sequences initialized");
    affinity_overflow_init(&queue);

    CHECK(queue.head == 0, "head should be 0");
    CHECK(queue.tail == 0, "tail should be 0");
    CHECK(queue.head_mask == AFFINITY_OVERFLOW_MASK, "head_mask");
    CHECK(queue.tail_mask == AFFINITY_OVERFLOW_MASK, "tail_mask");
    CHECK(queue.push_fails == 0, "push_fails should be 0");
    CHECK(queue.drains == 0, "drains should be 0");

    /* Verify Vyukov sequences */
    for (uint32_t i = 0; i < AFFINITY_OVERFLOW_CAPACITY; i++) {
        CHECK(queue.slots[i].seq == i, "slot seq should be i");
    }
    PASS();
}

static void test_init_null_safe(void) {
    TEST("Init: NULL is safe no-op");
    affinity_overflow_init(NULL); /* Should not crash */
    PASS();
}

/*============================================================================
 * 4. Push/Drain Round-Trip Tests
 *============================================================================*/

static void test_single_push_drain(void) {
    TEST("Single push -> drain round-trip");
    affinity_overflow_init(&queue);

    ring_event_t ev = {
        .socket_cookie = 42,
        .routing = route_pack(EVENT_FLAG_STATEFUL, 3,
                              EVENT_TYPE_SSL_DATA, 100),
        .data_len = 512,
        .flow_key_hash = 0xCAFE,
    };

    CHECK(affinity_overflow_push(&queue, &ev), "push failed");
    CHECK(affinity_overflow_depth(&queue) == 1, "depth should be 1");

    ring_event_t out = {0};
    uint32_t n = affinity_overflow_drain(&queue, &out, 1);
    CHECK(n == 1, "should drain 1");
    CHECK(out.socket_cookie == 42, "cookie mismatch");
    CHECK(route_worker(out.routing) == 3, "worker mismatch");
    CHECK(route_generation(out.routing) == 100, "gen mismatch");
    CHECK(out.data_len == 512, "data_len mismatch");
    CHECK(out.flow_key_hash == 0xCAFE, "hash mismatch");
    CHECK(affinity_overflow_empty(&queue), "should be empty");
    PASS();
}

static void test_drain_empty(void) {
    TEST("Drain from empty queue returns 0");
    affinity_overflow_init(&queue);

    ring_event_t out;
    uint32_t n = affinity_overflow_drain(&queue, &out, 1);
    CHECK(n == 0, "should return 0");
    PASS();
}

static void test_push_null_guards(void) {
    TEST("Push with NULL args returns false");
    affinity_overflow_init(&queue);
    ring_event_t ev = {0};

    CHECK(!affinity_overflow_push(NULL, &ev), "NULL queue");
    CHECK(!affinity_overflow_push(&queue, NULL), "NULL event");
    PASS();
}

static void test_drain_null_guards(void) {
    TEST("Drain with NULL/zero args returns 0");
    affinity_overflow_init(&queue);
    ring_event_t out;

    CHECK(affinity_overflow_drain(NULL, &out, 1) == 0, "NULL queue");
    CHECK(affinity_overflow_drain(&queue, NULL, 1) == 0, "NULL out");
    CHECK(affinity_overflow_drain(&queue, &out, 0) == 0, "zero count");
    PASS();
}

/*============================================================================
 * 5. Batch Push/Drain Tests
 *============================================================================*/

static void test_batch_push_drain(void) {
    TEST("Batch push 16 -> batch drain 16");
    affinity_overflow_init(&queue);

    for (int i = 0; i < 16; i++) {
        ring_event_t ev = {
            .socket_cookie = 100 + (uint64_t)i,
            .routing = route_pack(EVENT_FLAG_STATEFUL, (uint8_t)i,
                                  EVENT_TYPE_SSL_DATA, (uint32_t)i),
        };
        CHECK(affinity_overflow_push(&queue, &ev), "push failed");
    }
    CHECK(affinity_overflow_depth(&queue) == 16, "depth should be 16");

    ring_event_t out[16];
    uint32_t n = affinity_overflow_drain(&queue, out, 16);
    CHECK(n == 16, "should drain 16");

    for (uint32_t i = 0; i < 16; i++) {
        CHECK(out[i].socket_cookie == 100 + i, "cookie order");
        CHECK(route_worker(out[i].routing) == (uint8_t)i, "worker order");
    }

    CHECK(affinity_overflow_empty(&queue), "should be empty");
    CHECK(affinity_overflow_stat_drains(&queue) == 16, "drains stat");
    PASS();
}

/*============================================================================
 * 6. Queue Full / Push Fails Tests
 *============================================================================*/

static void test_queue_full(void) {
    TEST("Push to full queue returns false, increments push_fails");
    affinity_overflow_init(&queue);

    /* Fill all 64 slots */
    ring_event_t ev = { .socket_cookie = 1 };
    for (int i = 0; i < AFFINITY_OVERFLOW_CAPACITY; i++) {
        ev.socket_cookie = (uint64_t)(i + 1);
        CHECK(affinity_overflow_push(&queue, &ev), "push should succeed");
    }

    /* 65th push should fail */
    ev.socket_cookie = 999;
    CHECK(!affinity_overflow_push(&queue, &ev), "push to full should fail");
    CHECK(affinity_overflow_stat_push_fails(&queue) == 1, "push_fails = 1");

    /* Another fail */
    CHECK(!affinity_overflow_push(&queue, &ev), "second push should fail");
    CHECK(affinity_overflow_stat_push_fails(&queue) == 2, "push_fails = 2");

    /* Drain all and verify order */
    ring_event_t out[AFFINITY_OVERFLOW_CAPACITY];
    uint32_t n = affinity_overflow_drain(&queue, out,
                                          AFFINITY_OVERFLOW_CAPACITY);
    CHECK(n == AFFINITY_OVERFLOW_CAPACITY, "should drain all");
    for (uint32_t i = 0; i < n; i++) {
        CHECK(out[i].socket_cookie == (uint64_t)(i + 1), "order check");
    }

    PASS();
}

/*============================================================================
 * 7. Wrap-Around Tests (Multiple Laps)
 *============================================================================*/

static void test_wraparound(void) {
    TEST("Queue operates correctly across multiple laps");
    affinity_overflow_init(&queue);

    ring_event_t ev, out;

    /*
     * Do 3 full laps (3 * 64 = 192 push/drain on a 64-slot queue).
     * This exercises the Vyukov sequence wrap: after draining,
     * consumer sets seq = tail + mask + 1, which producers on the
     * next lap check as diff == 0.
     */
    for (int lap = 0; lap < 3; lap++) {
        for (int i = 0; i < AFFINITY_OVERFLOW_CAPACITY; i++) {
            ev = (ring_event_t){
                .socket_cookie = (uint64_t)(lap * 64 + i),
            };
            CHECK(affinity_overflow_push(&queue, &ev),
                  "push failed at wrap");
        }
        for (int i = 0; i < AFFINITY_OVERFLOW_CAPACITY; i++) {
            uint32_t n = affinity_overflow_drain(&queue, &out, 1);
            CHECK(n == 1, "drain failed at wrap");
            CHECK(out.socket_cookie == (uint64_t)(lap * 64 + i),
                  "data wrong at wrap");
        }
    }

    CHECK(affinity_overflow_empty(&queue), "should be empty after laps");
    CHECK(affinity_overflow_stat_drains(&queue) == 192, "drains = 192");
    PASS();
}

/*============================================================================
 * 8. Vyukov Sequence Verification
 *============================================================================*/

static void test_vyukov_seq_after_drain(void) {
    TEST("Vyukov seq after drain = tail + mask + 1");
    affinity_overflow_init(&queue);

    ring_event_t ev = { .socket_cookie = 1 };
    affinity_overflow_push(&queue, &ev);

    ring_event_t out;
    affinity_overflow_drain(&queue, &out, 1);

    /*
     * After draining slot 0 with tail=0, mask=63:
     * seq should be 0 + 63 + 1 = 64
     * This tells the next producer at head=64 that the slot is free.
     */
    uint64_t seq = queue.slots[0].seq;
    CHECK(seq == AFFINITY_OVERFLOW_CAPACITY,
          "seq should be capacity (64) after release");
    PASS();
}

static void test_vyukov_seq_second_lap(void) {
    TEST("Vyukov seq correct on second lap");
    affinity_overflow_init(&queue);

    ring_event_t ev = { .socket_cookie = 1 }, out;

    /* Fill and drain (first lap) */
    for (int i = 0; i < AFFINITY_OVERFLOW_CAPACITY; i++)
        affinity_overflow_push(&queue, &ev);
    for (int i = 0; i < AFFINITY_OVERFLOW_CAPACITY; i++)
        affinity_overflow_drain(&queue, &out, 1);

    /* After first full lap: slot[0].seq = 0 + 63 + 1 = 64 */
    /* Second lap starts at head=64. Push should succeed. */
    ev.socket_cookie = 999;
    CHECK(affinity_overflow_push(&queue, &ev), "second lap push");

    uint32_t n = affinity_overflow_drain(&queue, &out, 1);
    CHECK(n == 1 && out.socket_cookie == 999, "second lap data");
    PASS();
}

/*============================================================================
 * 9. Derived Metrics Test
 *============================================================================*/

static void test_derived_total_pushes(void) {
    TEST("Total pushes = drains + depth (derived metric)");
    affinity_overflow_init(&queue);

    ring_event_t ev = { .socket_cookie = 1 };

    /* Push 10 events */
    for (int i = 0; i < 10; i++)
        affinity_overflow_push(&queue, &ev);

    /* Drain 7 */
    ring_event_t batch[7];
    uint32_t drained = affinity_overflow_drain(&queue, batch, 7);

    /* total_pushes = drains(7) + depth(3) = 10 */
    uint64_t total = affinity_overflow_stat_drains(&queue)
                   + affinity_overflow_depth(&queue);
    CHECK(drained == 7, "should drain 7");
    CHECK(total == 10, "derived total pushes should be 10");
    PASS();
}

/*============================================================================
 * Main
 *============================================================================*/

int main(void) {
    printf("=== Affinity + MPSC Overflow Tests (Phase 2) ===\n\n");

    printf("--- Structure Layout ---\n");
    test_mpsc_slot_size();
    test_overflow_head_offset();
    test_overflow_tail_isolation();
    test_overflow_slots_offset();
    test_overflow_push_fails_on_producer_line();
    test_overflow_drains_on_consumer_line();

    printf("\n--- Affinity Check ---\n");
    test_affinity_stateless_local();
    test_affinity_stateful_match();
    test_affinity_stateful_mismatch();
    test_affinity_stateful_xdp();

    printf("\n--- Lifecycle ---\n");
    test_init();
    test_init_null_safe();

    printf("\n--- Push/Drain Round-Trip ---\n");
    test_single_push_drain();
    test_drain_empty();
    test_push_null_guards();
    test_drain_null_guards();

    printf("\n--- Batch Push/Drain ---\n");
    test_batch_push_drain();

    printf("\n--- Queue Full ---\n");
    test_queue_full();

    printf("\n--- Wrap-Around ---\n");
    test_wraparound();

    printf("\n--- Vyukov Sequence ---\n");
    test_vyukov_seq_after_drain();
    test_vyukov_seq_second_lap();

    printf("\n--- Derived Metrics ---\n");
    test_derived_total_pushes();

    printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf(", %d FAILED", tests_failed);
    printf(" ===\n");

    return tests_failed > 0 ? 1 : 0;
}
