/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * test_flow_refcount.c - Unit tests for flow reference counting and plaintext
 *
 * Tests:
 * - Reference count initialization
 * - Acquire/release lifecycle
 * - Last-release detection
 * - Deferred drain blocked while refs held
 * - Deferred drain proceeds at ref_count == 0
 * - Plaintext flag set on cookie-only flows
 * - Plaintext state transition to ACTIVE on XDP
 * - Flow manager integration (get_or_create + terminate)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <time.h>
#include "../src/include/spliff.h"
#include "../src/correlation/flow_context.h"

/* Global config required by linked source files */
config_t g_config = {0};

#define TEST(name) printf("TEST: %s... ", name)
#define PASS() printf("\033[32mPASS\033[0m\n")
#define FAIL(msg) do { printf("\033[31mFAIL: %s\033[0m\n", msg); failures++; } while(0)

static int failures = 0;

/* Helper to get current time in nanoseconds */
static uint64_t test_get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/*============================================================================
 * Reference Count Tests
 *============================================================================*/

/**
 * @brief ref_count starts at 1 after flow_pool_alloc
 */
static void test_refcount_init(void) {
    TEST("refcount_init: starts at 1 after alloc");

    flow_pool_t pool;
    flow_pool_init(&pool);

    flow_context_t *ctx = flow_pool_alloc(&pool);
    if (!ctx) { FAIL("alloc returned NULL"); goto cleanup; }

    uint32_t rc = flow_ref_count(ctx);
    if (rc != 1) {
        char buf[64];
        snprintf(buf, sizeof(buf), "ref_count=%u, expected 1", rc);
        FAIL(buf);
    } else {
        PASS();
    }

cleanup:
    flow_pool_cleanup(&pool);
}

/**
 * @brief Acquire increments, release decrements
 */
static void test_refcount_acquire_release(void) {
    TEST("refcount_acquire_release: increment and decrement");

    flow_pool_t pool;
    flow_pool_init(&pool);

    flow_context_t *ctx = flow_pool_alloc(&pool);
    if (!ctx) { FAIL("alloc returned NULL"); goto cleanup; }

    /* Acquire: 1 → 2 */
    uint32_t prev = flow_ref_acquire(ctx);
    if (prev != 1) { FAIL("acquire prev != 1"); goto cleanup; }
    if (flow_ref_count(ctx) != 2) { FAIL("count != 2 after acquire"); goto cleanup; }

    /* Acquire again: 2 → 3 */
    prev = flow_ref_acquire(ctx);
    if (prev != 2) { FAIL("second acquire prev != 2"); goto cleanup; }
    if (flow_ref_count(ctx) != 3) { FAIL("count != 3 after second acquire"); goto cleanup; }

    /* Release: 3 → 2, not last */
    bool last = flow_ref_release(ctx);
    if (last) { FAIL("release should not be last (3→2)"); goto cleanup; }
    if (flow_ref_count(ctx) != 2) { FAIL("count != 2 after release"); goto cleanup; }

    /* Release: 2 → 1, not last */
    last = flow_ref_release(ctx);
    if (last) { FAIL("release should not be last (2→1)"); goto cleanup; }
    if (flow_ref_count(ctx) != 1) { FAIL("count != 1 after release"); goto cleanup; }

    PASS();

cleanup:
    flow_pool_cleanup(&pool);
}

/**
 * @brief Last release (1 → 0) returns true
 */
static void test_refcount_last_release(void) {
    TEST("refcount_last_release: returns true at zero");

    flow_pool_t pool;
    flow_pool_init(&pool);

    flow_context_t *ctx = flow_pool_alloc(&pool);
    if (!ctx) { FAIL("alloc returned NULL"); goto cleanup; }

    /* Release creator's ref: 1 → 0 */
    bool last = flow_ref_release(ctx);
    if (!last) { FAIL("expected last=true for 1→0"); goto cleanup; }
    if (flow_ref_count(ctx) != 0) { FAIL("count != 0 after last release"); goto cleanup; }

    PASS();

cleanup:
    flow_pool_cleanup(&pool);
}

/**
 * @brief Deferred drain does NOT free while ref_count > 0
 */
static void test_drain_blocked_by_refs(void) {
    TEST("drain_blocked_by_refs: refs > 0 blocks drain");

    flow_pool_t pool;
    flow_pool_init(&pool);

    flow_context_t *ctx = flow_pool_alloc(&pool);
    if (!ctx) { FAIL("alloc returned NULL"); goto cleanup; }

    /* Simulate dispatcher acquiring a ref (as if dispatching an event) */
    flow_ref_acquire(ctx);  /* 1 → 2 */

    /* Move to deferred queue (simulates flow_pool_free) */
    atomic_store_explicit(&ctx->active, false, memory_order_release);
    /* Manually move to deferred list */
    pool.active_head = ctx->list_next;  /* remove from active */
    ctx->list_prev = NULL;
    ctx->list_next = NULL;
    ctx->last_seen_ns = 0;  /* Expired grace period (timestamp=0, now>>0) */
    pool.deferred_head = ctx;
    pool.deferred_tail = ctx;

    /* Release creator's ref: 2 → 1 (still held by "worker") */
    flow_ref_release(ctx);

    /* Attempt drain with well-expired timestamp — should NOT free (ref_count=1) */
    uint64_t now = test_get_time_ns();
    flow_pool_drain_deferred(&pool, now);

    if (pool.deferred_head == NULL) {
        FAIL("drain freed flow despite ref_count > 0");
        return;  /* ctx was freed, can't cleanup normally */
    }

    /* Now release the "worker" ref: 1 → 0 */
    flow_ref_release(ctx);

    /* Drain again — should now succeed */
    flow_pool_drain_deferred(&pool, test_get_time_ns());

    if (pool.deferred_head != NULL) {
        FAIL("drain did NOT free flow after ref_count reached 0");
        goto cleanup;
    }

    PASS();
    return;  /* ctx was freed by drain, don't double-free */

cleanup:
    flow_pool_cleanup(&pool);
}

/**
 * @brief Deferred drain proceeds when ref_count == 0 and grace expired
 */
static void test_drain_allowed_at_zero(void) {
    TEST("drain_allowed_at_zero: proceeds when ref_count == 0");

    flow_pool_t pool;
    flow_pool_init(&pool);

    flow_context_t *ctx = flow_pool_alloc(&pool);
    if (!ctx) { FAIL("alloc returned NULL"); goto cleanup; }

    /* Release creator's ref immediately: 1 → 0 */
    flow_ref_release(ctx);

    /* Move to deferred queue */
    atomic_store_explicit(&ctx->active, false, memory_order_release);
    pool.active_head = ctx->list_next;
    ctx->list_prev = NULL;
    ctx->list_next = NULL;
    ctx->last_seen_ns = 0;  /* Expired */
    pool.deferred_head = ctx;
    pool.deferred_tail = ctx;

    /* Drain — grace expired and ref_count == 0, should free */
    flow_pool_drain_deferred(&pool, test_get_time_ns());

    if (pool.deferred_head != NULL) {
        FAIL("drain did NOT free flow with ref_count == 0");
        goto cleanup;
    }

    PASS();
    return;  /* freed by drain */

cleanup:
    flow_pool_cleanup(&pool);
}

/*============================================================================
 * Plaintext Flow Tests
 *============================================================================*/

/**
 * @brief FLOW_FLAG_PLAINTEXT set when ssl_ctx == 0 and cookie != 0
 */
static void test_plaintext_flag_set(void) {
    TEST("plaintext_flag_set: ssl_ctx=0 + cookie!=0 → PLAINTEXT");

    flow_manager_t mgr;
    flow_manager_init(&mgr);

    /* Create a flow with cookie but no ssl_ctx (plaintext) */
    flow_context_t *ctx = flow_get_or_create(&mgr, 12345, 100, 0);
    if (!ctx) { FAIL("get_or_create returned NULL"); goto cleanup; }

    uint8_t flags = atomic_load(&ctx->flags);
    if (!(flags & FLOW_FLAG_PLAINTEXT)) {
        char buf[64];
        snprintf(buf, sizeof(buf), "PLAINTEXT not set (flags=0x%02x)", flags);
        FAIL(buf);
        goto cleanup;
    }

    PASS();

cleanup:
    flow_manager_cleanup(&mgr);
}

/**
 * @brief FLOW_FLAG_PLAINTEXT NOT set for TLS flows (ssl_ctx != 0)
 */
static void test_plaintext_not_set_for_tls(void) {
    TEST("plaintext_not_set_for_tls: ssl_ctx!=0 → no PLAINTEXT");

    flow_manager_t mgr;
    flow_manager_init(&mgr);

    /* Create a TLS flow (has ssl_ctx) */
    flow_context_t *ctx = flow_get_or_create(&mgr, 12345, 100, 0xDEAD);
    if (!ctx) { FAIL("get_or_create returned NULL"); goto cleanup; }

    uint8_t flags = atomic_load(&ctx->flags);
    if (flags & FLOW_FLAG_PLAINTEXT) {
        FAIL("PLAINTEXT set for TLS flow");
        goto cleanup;
    }

    PASS();

cleanup:
    flow_manager_cleanup(&mgr);
}

/**
 * @brief Plaintext flow transitions to ACTIVE on XDP update
 */
static void test_plaintext_state_active(void) {
    TEST("plaintext_state_active: XDP makes plaintext flow ACTIVE");

    flow_manager_t mgr;
    flow_manager_init(&mgr);

    /* Create plaintext flow */
    flow_context_t *ctx = flow_get_or_create(&mgr, 12345, 100, 0);
    if (!ctx) { FAIL("get_or_create returned NULL"); goto cleanup; }

    if (ctx->state != FLOW_STATE_INIT) {
        FAIL("initial state not INIT");
        goto cleanup;
    }

    /* Simulate XDP packet event */
    xdp_packet_event_t xdp_evt = {0};
    xdp_evt.timestamp_ns = test_get_time_ns();
    xdp_evt.socket_cookie = 12345;
    xdp_evt.ifindex = 1;
    xdp_evt.direction = 1;  /* ingress */
    xdp_evt.pkt_len = 100;
    /* 5-tuple */
    xdp_evt.flow.saddr = 0x0100007F;  /* 127.0.0.1 */
    xdp_evt.flow.daddr = 0x0100007F;
    xdp_evt.flow.sport = 8080;
    xdp_evt.flow.dport = 443;
    xdp_evt.flow.protocol = 6;  /* TCP */

    flow_update_xdp(ctx, &xdp_evt);

    /* Should be ACTIVE now (plaintext + HAS_XDP, no SSL needed) */
    if (ctx->state != FLOW_STATE_ACTIVE) {
        char buf[64];
        snprintf(buf, sizeof(buf), "state=%d, expected ACTIVE(%d)",
                ctx->state, FLOW_STATE_ACTIVE);
        FAIL(buf);
        goto cleanup;
    }

    /* Verify HAS_XDP flag is also set */
    uint8_t flags = atomic_load(&ctx->flags);
    if (!(flags & FLOW_FLAG_HAS_XDP)) {
        FAIL("HAS_XDP not set after flow_update_xdp");
        goto cleanup;
    }

    PASS();

cleanup:
    flow_manager_cleanup(&mgr);
}

/**
 * @brief TLS flow does NOT go ACTIVE on XDP alone
 */
static void test_tls_flow_not_active_on_xdp_alone(void) {
    TEST("tls_flow_not_active: XDP alone insufficient for TLS flow");

    flow_manager_t mgr;
    flow_manager_init(&mgr);

    /* Create TLS flow (has ssl_ctx, not plaintext) */
    flow_context_t *ctx = flow_get_or_create(&mgr, 12345, 100, 0xDEAD);
    if (!ctx) { FAIL("get_or_create returned NULL"); goto cleanup; }

    /* Send XDP event */
    xdp_packet_event_t xdp_evt = {0};
    xdp_evt.timestamp_ns = test_get_time_ns();
    xdp_evt.socket_cookie = 12345;
    xdp_evt.ifindex = 1;
    xdp_evt.direction = 1;
    xdp_evt.pkt_len = 100;
    xdp_evt.flow.saddr = 0x0100007F;
    xdp_evt.flow.daddr = 0x0100007F;
    xdp_evt.flow.sport = 8080;
    xdp_evt.flow.dport = 443;
    xdp_evt.flow.protocol = 6;

    flow_update_xdp(ctx, &xdp_evt);

    /* Should still be INIT (TLS flows need HAS_SSL to go ACTIVE) */
    if (ctx->state != FLOW_STATE_INIT) {
        FAIL("TLS flow went ACTIVE on XDP alone — should need HAS_SSL");
        goto cleanup;
    }

    PASS();

cleanup:
    flow_manager_cleanup(&mgr);
}

/*============================================================================
 * Integration Tests
 *============================================================================*/

/**
 * @brief flow_terminate releases creator's ref
 */
static void test_terminate_releases_ref(void) {
    TEST("terminate_releases_ref: ref_count decremented by terminate");

    flow_manager_t mgr;
    flow_manager_init(&mgr);

    flow_context_t *ctx = flow_get_or_create(&mgr, 12345, 100, 0);
    if (!ctx) { FAIL("get_or_create returned NULL"); goto cleanup; }

    /* Simulate dispatcher acquiring (as if dispatching an event) */
    flow_ref_acquire(ctx);  /* 1 → 2 */

    /* Terminate — releases creator's ref: 2 → 1 */
    flow_terminate(&mgr, ctx);

    /* ctx is now in deferred queue with ref_count == 1.
     * We can still read it because deferred free hasn't run yet. */
    uint32_t rc = flow_ref_count(ctx);
    if (rc != 1) {
        char buf[64];
        snprintf(buf, sizeof(buf), "ref_count=%u after terminate, expected 1", rc);
        FAIL(buf);
        goto cleanup;
    }

    /* Release the "worker" ref: 1 → 0 */
    flow_ref_release(ctx);
    rc = flow_ref_count(ctx);
    if (rc != 0) {
        char buf[64];
        snprintf(buf, sizeof(buf), "ref_count=%u after worker release, expected 0", rc);
        FAIL(buf);
        goto cleanup;
    }

    PASS();

cleanup:
    flow_manager_cleanup(&mgr);
}

/**
 * @brief flow_is_plaintext() helper works correctly
 */
static void test_flow_is_plaintext_helper(void) {
    TEST("flow_is_plaintext: inline helper returns correct value");

    flow_manager_t mgr;
    flow_manager_init(&mgr);

    /* Plaintext flow */
    flow_context_t *pt = flow_get_or_create(&mgr, 12345, 100, 0);
    if (!pt) { FAIL("get_or_create returned NULL for plaintext"); goto cleanup; }

    if (!flow_is_plaintext(pt)) {
        FAIL("flow_is_plaintext() returned false for plaintext flow");
        goto cleanup;
    }

    /* TLS flow */
    flow_context_t *tls = flow_get_or_create(&mgr, 54321, 200, 0xBEEF);
    if (!tls) { FAIL("get_or_create returned NULL for TLS"); goto cleanup; }

    if (flow_is_plaintext(tls)) {
        FAIL("flow_is_plaintext() returned true for TLS flow");
        goto cleanup;
    }

    PASS();

cleanup:
    flow_manager_cleanup(&mgr);
}

/*============================================================================
 * Main
 *============================================================================*/

int main(void) {
    printf("=== Flow Reference Count & Plaintext Tests ===\n\n");

    /* Reference count tests */
    test_refcount_init();
    test_refcount_acquire_release();
    test_refcount_last_release();
    test_drain_blocked_by_refs();
    test_drain_allowed_at_zero();

    /* Plaintext flow tests */
    test_plaintext_flag_set();
    test_plaintext_not_set_for_tls();
    test_plaintext_state_active();
    test_tls_flow_not_active_on_xdp_alone();

    /* Integration tests */
    test_terminate_releases_ref();
    test_flow_is_plaintext_helper();

    printf("\n=== Results: %d failures ===\n", failures);
    return failures ? 1 : 0;
}
