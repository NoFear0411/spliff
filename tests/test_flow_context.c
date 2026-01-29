/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * test_flow_context.c - Unit tests for dynamic flow pool and dual index
 *
 * Tests:
 * - Flow pool allocation/free lifecycle
 * - Cookie index insert/lookup/remove
 * - Shadow index insert/lookup/remove
 * - Cookie promotion (shadow → cookie)
 * - Generation counter validation
 * - Deferred free mechanism
 * - Hash table operations
 * - Flow manager high-level operations
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "../src/include/spliff.h"
#include "../src/correlation/flow_context.h"

#define TEST(name) printf("TEST: %s... ", name)
#define PASS() printf("\033[32mPASS\033[0m\n")
#define FAIL(msg) do { printf("\033[31mFAIL: %s\033[0m\n", msg); failures++; } while(0)

static int failures = 0;

/* Helper to get current time in nanoseconds */
static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/*============================================================================
 * Flow Pool Tests
 *============================================================================*/

static void test_pool_init(void) {
    TEST("flow_pool_init");

    flow_pool_t pool;
    int ret = flow_pool_init(&pool);

    if (ret != 0) {
        FAIL("init returned error");
        return;
    }
    if (pool.active_head != NULL) {
        FAIL("active_head not NULL");
        return;
    }
    if (atomic_load(&pool.allocated) != 0) {
        FAIL("allocated not zero");
        return;
    }
    if (atomic_load(&pool.next_id) != 0) {
        FAIL("next_id not 0");
        return;
    }

    flow_pool_cleanup(&pool);
    PASS();
}

static void test_pool_alloc_single(void) {
    TEST("flow_pool_alloc single");

    flow_pool_t pool;
    flow_pool_init(&pool);

    flow_context_t *ctx = flow_pool_alloc(&pool);
    if (ctx == NULL) {
        FAIL("alloc returned NULL");
        flow_pool_cleanup(&pool);
        return;
    }

    /* Verify context is initialized - first ID is 0 */
    if (ctx->self_id != 0) {
        FAIL("wrong self_id");
        flow_pool_cleanup(&pool);
        return;
    }
    if (ctx->generation == 0) {
        FAIL("generation is zero");
        flow_pool_cleanup(&pool);
        return;
    }
    if (!atomic_load(&ctx->active)) {
        FAIL("not marked active");
        flow_pool_cleanup(&pool);
        return;
    }
    if (atomic_load(&pool.allocated) != 1) {
        FAIL("allocated count wrong");
        flow_pool_cleanup(&pool);
        return;
    }

    /* Verify alignment (64-byte) */
    if (((uintptr_t)ctx & 63) != 0) {
        FAIL("not 64-byte aligned");
        flow_pool_cleanup(&pool);
        return;
    }

    flow_pool_cleanup(&pool);
    PASS();
}

static void test_pool_alloc_multiple(void) {
    TEST("flow_pool_alloc multiple");

    flow_pool_t pool;
    flow_pool_init(&pool);

    flow_context_t *ctx1 = flow_pool_alloc(&pool);
    flow_context_t *ctx2 = flow_pool_alloc(&pool);
    flow_context_t *ctx3 = flow_pool_alloc(&pool);

    if (!ctx1 || !ctx2 || !ctx3) {
        FAIL("alloc returned NULL");
        flow_pool_cleanup(&pool);
        return;
    }

    /* Each should have unique ID */
    if (ctx1->self_id == ctx2->self_id || ctx2->self_id == ctx3->self_id) {
        FAIL("duplicate IDs");
        flow_pool_cleanup(&pool);
        return;
    }

    /* Allocated count should be 3 */
    if (atomic_load(&pool.allocated) != 3) {
        FAIL("wrong allocated count");
        flow_pool_cleanup(&pool);
        return;
    }

    /* Peak should be 3 */
    if (atomic_load(&pool.peak) != 3) {
        FAIL("wrong peak");
        flow_pool_cleanup(&pool);
        return;
    }

    flow_pool_cleanup(&pool);
    PASS();
}

static void test_pool_free_deferred(void) {
    TEST("flow_pool_free deferred");

    flow_pool_t pool;
    flow_pool_init(&pool);

    flow_context_t *ctx = flow_pool_alloc(&pool);
    uint32_t original_gen = ctx->generation;

    /* Free the context (deferred) */
    flow_pool_free(&pool, ctx);

    /* Should be marked inactive */
    if (atomic_load(&ctx->active)) {
        FAIL("still marked active after free");
        flow_pool_cleanup(&pool);
        return;
    }

    /* Should be in deferred queue */
    if (pool.deferred_head != ctx) {
        FAIL("not in deferred queue");
        flow_pool_cleanup(&pool);
        return;
    }

    /* Allocated count should be 0 */
    if (atomic_load(&pool.allocated) != 0) {
        FAIL("allocated not decremented");
        flow_pool_cleanup(&pool);
        return;
    }

    flow_pool_cleanup(&pool);
    PASS();
}

static void test_pool_drain_deferred(void) {
    TEST("flow_pool_drain_deferred");

    flow_pool_t pool;
    flow_pool_init(&pool);

    flow_context_t *ctx = flow_pool_alloc(&pool);
    flow_pool_free(&pool, ctx);

    /* Drain with current time - should NOT free (grace period) */
    uint64_t now = get_time_ns();
    flow_pool_drain_deferred(&pool, now);

    /* Should still be in deferred queue */
    if (pool.deferred_head == NULL) {
        FAIL("freed too early (grace period not respected)");
        flow_pool_cleanup(&pool);
        return;
    }

    /* Drain with time far in future - should free */
    flow_pool_drain_deferred(&pool, now + FLOW_DEFERRED_FREE_GRACE_NS + 1000000000ULL);

    /* Should be empty now */
    if (pool.deferred_head != NULL) {
        FAIL("not freed after grace period");
        flow_pool_cleanup(&pool);
        return;
    }

    flow_pool_cleanup(&pool);
    PASS();
}

static void test_pool_active_list(void) {
    TEST("flow_pool active list");

    flow_pool_t pool;
    flow_pool_init(&pool);

    flow_context_t *ctx1 = flow_pool_alloc(&pool);
    flow_context_t *ctx2 = flow_pool_alloc(&pool);
    flow_context_t *ctx3 = flow_pool_alloc(&pool);

    /* Walk active list - should find all 3 */
    int count = 0;
    flow_context_t *curr = pool.active_head;
    while (curr) {
        count++;
        curr = curr->list_next;
        if (count > 100) {
            FAIL("infinite loop in active list");
            flow_pool_cleanup(&pool);
            return;
        }
    }

    if (count != 3) {
        FAIL("wrong count in active list");
        flow_pool_cleanup(&pool);
        return;
    }

    /* Free middle one and verify list is still valid */
    flow_pool_free(&pool, ctx2);

    count = 0;
    curr = pool.active_head;
    while (curr) {
        count++;
        curr = curr->list_next;
        if (count > 100) {
            FAIL("infinite loop after free");
            flow_pool_cleanup(&pool);
            return;
        }
    }

    if (count != 2) {
        FAIL("wrong count after free");
        flow_pool_cleanup(&pool);
        return;
    }

    flow_pool_cleanup(&pool);
    PASS();
}

/*============================================================================
 * Cookie Index Tests
 *============================================================================*/

static void test_cookie_index_init(void) {
    TEST("cookie_index_init");

    cookie_index_t idx;
    int ret = cookie_index_init(&idx, 64);

    if (ret != 0) {
        FAIL("init returned error");
        return;
    }
    if (idx.capacity != 64) {
        FAIL("wrong capacity");
        cookie_index_cleanup(&idx);
        return;
    }
    if (idx.buckets == NULL) {
        FAIL("buckets is NULL");
        return;
    }
    if (atomic_load(&idx.count) != 0) {
        FAIL("count not zero");
        cookie_index_cleanup(&idx);
        return;
    }

    cookie_index_cleanup(&idx);
    PASS();
}

static void test_cookie_index_insert_lookup(void) {
    TEST("cookie_index insert/lookup");

    cookie_index_t idx;
    cookie_index_init(&idx, 64);

    /* Create a dummy flow context */
    flow_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.socket_cookie = 12345;

    int ret = cookie_index_insert(&idx, 12345, &ctx);
    if (ret != 0) {
        FAIL("insert failed");
        cookie_index_cleanup(&idx);
        return;
    }

    /* Lookup */
    flow_context_t *found = cookie_index_lookup(&idx, 12345);
    if (found != &ctx) {
        FAIL("lookup returned wrong pointer");
        cookie_index_cleanup(&idx);
        return;
    }

    /* Lookup non-existent */
    found = cookie_index_lookup(&idx, 99999);
    if (found != NULL) {
        FAIL("found non-existent cookie");
        cookie_index_cleanup(&idx);
        return;
    }

    cookie_index_cleanup(&idx);
    PASS();
}

static void test_cookie_index_remove(void) {
    TEST("cookie_index remove");

    cookie_index_t idx;
    cookie_index_init(&idx, 64);

    flow_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.socket_cookie = 12345;

    cookie_index_insert(&idx, 12345, &ctx);

    /* Remove */
    cookie_index_remove(&idx, 12345);

    /* Should not find it anymore */
    flow_context_t *found = cookie_index_lookup(&idx, 12345);
    if (found != NULL) {
        FAIL("still found after remove");
        cookie_index_cleanup(&idx);
        return;
    }

    if (atomic_load(&idx.count) != 0) {
        FAIL("count not zero after remove");
        cookie_index_cleanup(&idx);
        return;
    }

    cookie_index_cleanup(&idx);
    PASS();
}

static void test_cookie_index_collision(void) {
    TEST("cookie_index collision handling");

    cookie_index_t idx;
    cookie_index_init(&idx, 8);  /* Small table to force collisions */

    flow_context_t ctx1, ctx2, ctx3;
    memset(&ctx1, 0, sizeof(ctx1));
    memset(&ctx2, 0, sizeof(ctx2));
    memset(&ctx3, 0, sizeof(ctx3));

    /* Insert multiple entries that may collide */
    cookie_index_insert(&idx, 1, &ctx1);
    cookie_index_insert(&idx, 9, &ctx2);   /* 9 % 8 = 1, same bucket as 1 */
    cookie_index_insert(&idx, 17, &ctx3);  /* 17 % 8 = 1, same bucket */

    /* All should be findable */
    if (cookie_index_lookup(&idx, 1) != &ctx1) {
        FAIL("can't find cookie 1");
        cookie_index_cleanup(&idx);
        return;
    }
    if (cookie_index_lookup(&idx, 9) != &ctx2) {
        FAIL("can't find cookie 9");
        cookie_index_cleanup(&idx);
        return;
    }
    if (cookie_index_lookup(&idx, 17) != &ctx3) {
        FAIL("can't find cookie 17");
        cookie_index_cleanup(&idx);
        return;
    }

    cookie_index_cleanup(&idx);
    PASS();
}

static void test_cookie_index_many_entries(void) {
    TEST("cookie_index many entries (resize)");

    cookie_index_t idx;
    cookie_index_init(&idx, 16);

    /* Insert enough to trigger resize (75% load = 12 entries) */
    flow_context_t contexts[20];
    memset(contexts, 0, sizeof(contexts));

    for (int i = 0; i < 20; i++) {
        contexts[i].socket_cookie = 1000 + i;
        if (cookie_index_insert(&idx, 1000 + i, &contexts[i]) != 0) {
            FAIL("insert failed during resize");
            cookie_index_cleanup(&idx);
            return;
        }
    }

    /* Verify all are findable */
    for (int i = 0; i < 20; i++) {
        flow_context_t *found = cookie_index_lookup(&idx, 1000 + i);
        if (found != &contexts[i]) {
            FAIL("can't find entry after resize");
            cookie_index_cleanup(&idx);
            return;
        }
    }

    /* Capacity should have grown */
    if (idx.capacity <= 16) {
        FAIL("capacity didn't grow");
        cookie_index_cleanup(&idx);
        return;
    }

    cookie_index_cleanup(&idx);
    PASS();
}

/*============================================================================
 * Shadow Index Tests
 *============================================================================*/

static void test_shadow_index_init(void) {
    TEST("shadow_index_init");

    shadow_index_t idx;
    int ret = shadow_index_init(&idx, 64);

    if (ret != 0) {
        FAIL("init returned error");
        return;
    }
    if (idx.capacity != 64) {
        FAIL("wrong capacity");
        shadow_index_cleanup(&idx);
        return;
    }

    shadow_index_cleanup(&idx);
    PASS();
}

static void test_shadow_index_insert_lookup(void) {
    TEST("shadow_index insert/lookup");

    shadow_index_t idx;
    shadow_index_init(&idx, 64);

    flow_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pid = 1234;
    ctx.ssl_ctx = 0xDEADBEEF;

    int ret = shadow_index_insert(&idx, 1234, 0xDEADBEEF, &ctx);
    if (ret != 0) {
        FAIL("insert failed");
        shadow_index_cleanup(&idx);
        return;
    }

    /* Lookup */
    flow_context_t *found = shadow_index_lookup(&idx, 1234, 0xDEADBEEF);
    if (found != &ctx) {
        FAIL("lookup returned wrong pointer");
        shadow_index_cleanup(&idx);
        return;
    }

    /* Lookup with wrong pid */
    found = shadow_index_lookup(&idx, 9999, 0xDEADBEEF);
    if (found != NULL) {
        FAIL("found with wrong pid");
        shadow_index_cleanup(&idx);
        return;
    }

    /* Lookup with wrong ssl_ctx */
    found = shadow_index_lookup(&idx, 1234, 0x11111111);
    if (found != NULL) {
        FAIL("found with wrong ssl_ctx");
        shadow_index_cleanup(&idx);
        return;
    }

    shadow_index_cleanup(&idx);
    PASS();
}

static void test_shadow_index_remove(void) {
    TEST("shadow_index remove");

    shadow_index_t idx;
    shadow_index_init(&idx, 64);

    flow_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    shadow_index_insert(&idx, 1234, 0xDEADBEEF, &ctx);
    shadow_index_remove(&idx, 1234, 0xDEADBEEF);

    flow_context_t *found = shadow_index_lookup(&idx, 1234, 0xDEADBEEF);
    if (found != NULL) {
        FAIL("still found after remove");
        shadow_index_cleanup(&idx);
        return;
    }

    shadow_index_cleanup(&idx);
    PASS();
}

/*============================================================================
 * Flow Manager Tests
 *============================================================================*/

static void test_manager_init(void) {
    TEST("flow_manager_init");

    flow_manager_t mgr;
    int ret = flow_manager_init(&mgr);

    if (ret != 0) {
        FAIL("init returned error");
        return;
    }

    /* Verify all components initialized */
    if (mgr.cookie_idx.buckets == NULL) {
        FAIL("cookie_idx not initialized");
        flow_manager_cleanup(&mgr);
        return;
    }
    if (mgr.shadow_idx.buckets == NULL) {
        FAIL("shadow_idx not initialized");
        flow_manager_cleanup(&mgr);
        return;
    }

    flow_manager_cleanup(&mgr);
    PASS();
}

static void test_manager_get_or_create(void) {
    TEST("flow_get_or_create");

    flow_manager_t mgr;
    flow_manager_init(&mgr);

    /* Create new flow */
    flow_context_t *ctx = flow_get_or_create(&mgr, 0, 1234, 0xBEEF);
    if (ctx == NULL) {
        FAIL("get_or_create returned NULL");
        flow_manager_cleanup(&mgr);
        return;
    }

    /* Verify it's in shadow index */
    flow_context_t *found = shadow_index_lookup(&mgr.shadow_idx, 1234, 0xBEEF);
    if (found != ctx) {
        FAIL("not in shadow index");
        flow_manager_cleanup(&mgr);
        return;
    }

    /* Get same flow again - should return same pointer */
    flow_context_t *ctx2 = flow_get_or_create(&mgr, 0, 1234, 0xBEEF);
    if (ctx2 != ctx) {
        FAIL("didn't return same flow");
        flow_manager_cleanup(&mgr);
        return;
    }

    flow_manager_cleanup(&mgr);
    PASS();
}

static void test_manager_get_or_create_with_cookie(void) {
    TEST("flow_get_or_create with cookie");

    flow_manager_t mgr;
    flow_manager_init(&mgr);

    /* Create with cookie known */
    flow_context_t *ctx = flow_get_or_create(&mgr, 99999, 1234, 0xBEEF);
    if (ctx == NULL) {
        FAIL("get_or_create returned NULL");
        flow_manager_cleanup(&mgr);
        return;
    }

    /* Should be in both indexes */
    if (cookie_index_lookup(&mgr.cookie_idx, 99999) != ctx) {
        FAIL("not in cookie index");
        flow_manager_cleanup(&mgr);
        return;
    }
    if (shadow_index_lookup(&mgr.shadow_idx, 1234, 0xBEEF) != ctx) {
        FAIL("not in shadow index");
        flow_manager_cleanup(&mgr);
        return;
    }

    flow_manager_cleanup(&mgr);
    PASS();
}

static void test_manager_lookup(void) {
    TEST("flow_lookup paths");

    flow_manager_t mgr;
    flow_manager_init(&mgr);

    /* Create flow without cookie */
    flow_context_t *ctx = flow_get_or_create(&mgr, 0, 1234, 0xBEEF);

    /* Lookup via shadow (cookie=0) */
    flow_lookup_path_t path;
    flow_context_t *found = flow_lookup_ex(&mgr, 0, 1234, 0xBEEF, &path);
    if (found != ctx) {
        FAIL("shadow lookup failed");
        flow_manager_cleanup(&mgr);
        return;
    }
    if (path != FLOW_PATH_SHADOW) {
        FAIL("wrong path for shadow lookup");
        flow_manager_cleanup(&mgr);
        return;
    }

    /* Promote to cookie index */
    flow_promote_cookie(&mgr, 1234, 0xBEEF, 99999);

    /* Lookup via cookie */
    found = flow_lookup_ex(&mgr, 99999, 1234, 0xBEEF, &path);
    if (found != ctx) {
        FAIL("cookie lookup failed");
        flow_manager_cleanup(&mgr);
        return;
    }
    if (path != FLOW_PATH_COOKIE) {
        FAIL("wrong path for cookie lookup");
        flow_manager_cleanup(&mgr);
        return;
    }

    flow_manager_cleanup(&mgr);
    PASS();
}

static void test_manager_promote_cookie(void) {
    TEST("flow_promote_cookie");

    flow_manager_t mgr;
    flow_manager_init(&mgr);

    /* Create without cookie */
    flow_context_t *ctx = flow_get_or_create(&mgr, 0, 1234, 0xBEEF);

    /* Should not be in cookie index */
    if (cookie_index_lookup(&mgr.cookie_idx, 99999) != NULL) {
        FAIL("shouldn't be in cookie index yet");
        flow_manager_cleanup(&mgr);
        return;
    }

    /* Promote */
    int ret = flow_promote_cookie(&mgr, 1234, 0xBEEF, 99999);
    if (ret != 0) {
        FAIL("promote failed");
        flow_manager_cleanup(&mgr);
        return;
    }

    /* Now should be in cookie index */
    if (cookie_index_lookup(&mgr.cookie_idx, 99999) != ctx) {
        FAIL("not in cookie index after promote");
        flow_manager_cleanup(&mgr);
        return;
    }

    /* socket_cookie field should be updated */
    if (ctx->socket_cookie != 99999) {
        FAIL("socket_cookie not updated");
        flow_manager_cleanup(&mgr);
        return;
    }

    flow_manager_cleanup(&mgr);
    PASS();
}

static void test_manager_terminate(void) {
    TEST("flow_terminate");

    flow_manager_t mgr;
    flow_manager_init(&mgr);

    /* Create flow with cookie */
    flow_context_t *ctx = flow_get_or_create(&mgr, 99999, 1234, 0xBEEF);

    /* Terminate */
    flow_terminate(&mgr, ctx);

    /* Should be removed from both indexes */
    if (cookie_index_lookup(&mgr.cookie_idx, 99999) != NULL) {
        FAIL("still in cookie index");
        flow_manager_cleanup(&mgr);
        return;
    }
    if (shadow_index_lookup(&mgr.shadow_idx, 1234, 0xBEEF) != NULL) {
        FAIL("still in shadow index");
        flow_manager_cleanup(&mgr);
        return;
    }

    /* Should be in deferred free queue */
    if (mgr.pool.deferred_head == NULL) {
        FAIL("not in deferred queue");
        flow_manager_cleanup(&mgr);
        return;
    }

    flow_manager_cleanup(&mgr);
    PASS();
}

static void test_manager_evict_stale(void) {
    TEST("flow_evict_stale");

    flow_manager_t mgr;
    flow_manager_init(&mgr);

    /* Create a flow */
    flow_context_t *ctx = flow_get_or_create(&mgr, 99999, 1234, 0xBEEF);

    /* Set last_seen to old time */
    ctx->last_seen_ns = 1000;  /* Very old */

    /* Evict with current time */
    uint64_t now = get_time_ns();
    int evicted = flow_evict_stale(&mgr, now);

    if (evicted != 1) {
        FAIL("didn't evict stale flow");
        flow_manager_cleanup(&mgr);
        return;
    }

    /* Flow should be removed from indexes */
    if (cookie_index_lookup(&mgr.cookie_idx, 99999) != NULL) {
        FAIL("stale flow still in cookie index");
        flow_manager_cleanup(&mgr);
        return;
    }

    flow_manager_cleanup(&mgr);
    PASS();
}

static void test_manager_stats(void) {
    TEST("flow_manager_get_stats");

    flow_manager_t mgr;
    flow_manager_init(&mgr);

    /* Create some flows */
    flow_get_or_create(&mgr, 11111, 1001, 0xA);
    flow_get_or_create(&mgr, 22222, 1002, 0xB);
    flow_get_or_create(&mgr, 33333, 1003, 0xC);

    flow_pool_stats_t stats;
    flow_manager_get_stats(&mgr, &stats);

    if (stats.pool_allocated != 3) {
        FAIL("wrong pool_allocated");
        flow_manager_cleanup(&mgr);
        return;
    }
    if (stats.cookie_count != 3) {
        FAIL("wrong cookie_count");
        flow_manager_cleanup(&mgr);
        return;
    }
    if (stats.shadow_count != 3) {
        FAIL("wrong shadow_count");
        flow_manager_cleanup(&mgr);
        return;
    }

    flow_manager_cleanup(&mgr);
    PASS();
}

/*============================================================================
 * Transaction/Stream Tests
 *============================================================================*/

static void test_h2_stream_pool(void) {
    TEST("flow_h2 stream pool");

    flow_pool_t pool;
    flow_pool_init(&pool);

    flow_context_t *ctx = flow_pool_alloc(&pool);
    ctx->proto = FLOW_PROTO_HTTP2;

    /* Initialize stream pool */
    flow_h2_init_stream_pool(ctx);

    /* Allocate streams */
    flow_transaction_t *s1 = flow_h2_alloc_stream(ctx, 1);
    flow_transaction_t *s3 = flow_h2_alloc_stream(ctx, 3);
    flow_transaction_t *s5 = flow_h2_alloc_stream(ctx, 5);

    if (!s1 || !s3 || !s5) {
        FAIL("stream alloc returned NULL");
        flow_pool_cleanup(&pool);
        return;
    }

    if (s1->stream_id != 1 || s3->stream_id != 3 || s5->stream_id != 5) {
        FAIL("wrong stream IDs");
        flow_pool_cleanup(&pool);
        return;
    }

    /* Set streams to active state (find excludes IDLE streams) */
    s1->state = TXN_STATE_OPEN;
    s3->state = TXN_STATE_OPEN;
    s5->state = TXN_STATE_OPEN;

    /* Find streams */
    if (flow_h2_find_stream(ctx, 1) != s1) {
        FAIL("can't find stream 1");
        flow_pool_cleanup(&pool);
        return;
    }
    if (flow_h2_find_stream(ctx, 3) != s3) {
        FAIL("can't find stream 3");
        flow_pool_cleanup(&pool);
        return;
    }
    if (flow_h2_find_stream(ctx, 999) != NULL) {
        FAIL("found non-existent stream");
        flow_pool_cleanup(&pool);
        return;
    }

    /* Free a stream */
    flow_h2_free_stream(ctx, s3);

    if (flow_h2_find_stream(ctx, 3) != NULL) {
        FAIL("still found freed stream");
        flow_pool_cleanup(&pool);
        return;
    }

    flow_pool_cleanup(&pool);
    PASS();
}

static void test_txn_body_buffer(void) {
    TEST("flow_txn body buffer");

    flow_transaction_t txn;
    memset(&txn, 0, sizeof(txn));

    /* Allocate body buffer (min capacity is 4096) */
    int ret = flow_txn_alloc_body(&txn, 1024);
    if (ret != 0) {
        FAIL("body alloc failed");
        return;
    }

    /* Capacity is clamped to minimum of 4096 */
    if (txn.body_buf == NULL || txn.body_capacity != 4096) {
        FAIL("body buffer not allocated");
        flow_txn_free_body(&txn);
        return;
    }

    /* Append data */
    uint8_t data[] = "Hello World";
    ret = flow_txn_append_body(&txn, data, sizeof(data) - 1);
    if (ret != 0) {
        FAIL("body append failed");
        flow_txn_free_body(&txn);
        return;
    }

    if (txn.body_len != 11) {
        FAIL("wrong body length");
        flow_txn_free_body(&txn);
        return;
    }

    if (memcmp(txn.body_buf, "Hello World", 11) != 0) {
        FAIL("wrong body content");
        flow_txn_free_body(&txn);
        return;
    }

    flow_txn_free_body(&txn);

    if (txn.body_buf != NULL || txn.body_len != 0) {
        FAIL("body not freed properly");
        return;
    }

    PASS();
}

/*============================================================================
 * Main
 *============================================================================*/

int main(void) {
    printf("\n=== Flow Context Tests ===\n\n");

    /* Pool tests */
    test_pool_init();
    test_pool_alloc_single();
    test_pool_alloc_multiple();
    test_pool_free_deferred();
    test_pool_drain_deferred();
    test_pool_active_list();

    /* Cookie index tests */
    test_cookie_index_init();
    test_cookie_index_insert_lookup();
    test_cookie_index_remove();
    test_cookie_index_collision();
    test_cookie_index_many_entries();

    /* Shadow index tests */
    test_shadow_index_init();
    test_shadow_index_insert_lookup();
    test_shadow_index_remove();

    /* Flow manager tests */
    test_manager_init();
    test_manager_get_or_create();
    test_manager_get_or_create_with_cookie();
    test_manager_lookup();
    test_manager_promote_cookie();
    test_manager_terminate();
    test_manager_evict_stale();
    test_manager_stats();

    /* Transaction/stream tests */
    test_h2_stream_pool();
    test_txn_body_buffer();

    printf("\n=== Results: %d failures ===\n\n", failures);
    return failures > 0 ? 1 : 0;
}
