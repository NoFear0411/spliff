/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * flow_context.c - Dynamic Flow Pool with Incremental Resize
 *
 * Implements on-demand flow allocation (via jemalloc), incrementally-resizing
 * hash tables for dual indexing, and a deferred-free queue for safe pointer
 * invalidation.
 *
 * @par Memory Alignment Requirements (FIX M4)
 * This module uses aligned_alloc(64, ...) for cache-line aligned allocations.
 * Proper alignment requires jemalloc or glibc >= 2.16. The _Static_assert
 * below verifies minimum alignment support at compile time.
 *
 * @par Architecture Coupling Note (M8 - Deferred)
 * This module intentionally couples with the Protocol layer (http2.h) for
 * embedded parser state. This coupling is a deliberate performance optimization
 * that avoids indirection overhead (~2-3ns per access). Decoupling via opaque
 * parser state (void*) was considered but deferred because:
 * 1. Current coupling has zero impact on correctness
 * 2. No new protocols are planned that require different state layout
 * 3. Refactoring ~500+ lines carries regression risk for minimal benefit
 * Future work may revisit if protocol extensibility becomes a requirement.
 *
 * @see flow_context.h for API documentation
 */

#include "flow_context.h"
#include "../protocol/http2.h"
#include "../util/safe_str.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <net/if.h>  /* For if_indextoname() */
#include <stdalign.h>

/*============================================================================
 * Compile-Time Alignment Verification (FIX M4)
 *============================================================================*/

/**
 * @brief Verify cache-line alignment support
 *
 * aligned_alloc(64, size) requires malloc to support at least 16-byte alignment.
 * jemalloc provides guaranteed 64-byte alignment; glibc >= 2.16 provides 16-byte.
 * This static assertion catches builds on systems with inadequate alignment.
 */
_Static_assert(alignof(max_align_t) >= 16,
    "System malloc alignment too small for cache-line alignment; "
    "jemalloc is required for proper 64-byte cache-line aligned allocations");

/*============================================================================
 * Hash Functions
 *============================================================================*/

/** FNV-1a hash for socket_cookie */
static inline uint64_t hash_cookie(uint64_t cookie) {
    uint64_t hash = 14695981039346656037ULL;  /* FNV offset basis */
    hash ^= cookie;
    hash *= 1099511628211ULL;                  /* FNV prime */
    hash ^= (cookie >> 32);
    hash *= 1099511628211ULL;
    return hash;
}

/** FNV-1a hash for (pid, ssl_ctx) pair */
static inline uint64_t hash_shadow_key(uint32_t pid, uint64_t ssl_ctx) {
    uint64_t hash = 14695981039346656037ULL;
    hash ^= pid;
    hash *= 1099511628211ULL;
    hash ^= ssl_ctx;
    hash *= 1099511628211ULL;
    hash ^= (ssl_ctx >> 32);
    hash *= 1099511628211ULL;
    return hash;
}

/* Use extern get_time_ns() from threading/state.c to avoid duplication */
extern uint64_t get_time_ns(void);

/*============================================================================
 * Flow Pool Implementation
 *============================================================================*/

int flow_pool_init(flow_pool_t *pool) {
    if (!pool) {
        return -1;
    }

    memset(pool, 0, sizeof(*pool));
    atomic_store(&pool->allocated, 0);
    atomic_store(&pool->peak, 0);
    atomic_store(&pool->total_allocs, 0);
    atomic_store(&pool->total_frees, 0);
    atomic_store(&pool->alloc_failures, 0);
    atomic_store(&pool->next_id, 0);

    return 0;
}

void flow_pool_cleanup(flow_pool_t *pool) {
    if (!pool) {
        return;
    }

    /* Free all active flows */
    flow_context_t *ctx = pool->active_head;
    while (ctx) {
        flow_context_t *next = ctx->list_next;
        flow_free_resources(ctx);
        free(ctx);
        ctx = next;
    }
    pool->active_head = NULL;

    /* Free all deferred flows */
    ctx = pool->deferred_head;
    while (ctx) {
        flow_context_t *next = ctx->list_next;
        flow_free_resources(ctx);
        free(ctx);
        ctx = next;
    }
    pool->deferred_head = NULL;
    pool->deferred_tail = NULL;
}

flow_context_t *flow_pool_alloc(flow_pool_t *pool) {
    if (!pool) {
        return NULL;
    }

    flow_context_t *ctx = aligned_alloc(64, sizeof(flow_context_t));
    if (!ctx) {
        atomic_fetch_add(&pool->alloc_failures, 1);
        return NULL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->self_id = (flow_id_t)atomic_fetch_add(&pool->next_id, 1);
    ctx->generation = (uint32_t)(ctx->self_id + 1);  /* Never 0 */
    ctx->state = FLOW_STATE_INIT;
    ctx->proto = FLOW_PROTO_UNKNOWN;
    atomic_store_explicit(&ctx->home_worker_id, WORKER_ID_NONE,
                          memory_order_relaxed);
    atomic_store_explicit(&ctx->active, true, memory_order_release);

    /* Insert at head of active list */
    ctx->list_prev = NULL;
    ctx->list_next = pool->active_head;
    if (pool->active_head) {
        pool->active_head->list_prev = ctx;
    }
    pool->active_head = ctx;

    /* Update statistics */
    uint64_t count = atomic_fetch_add(&pool->allocated, 1) + 1;
    uint64_t peak = atomic_load(&pool->peak);
    while (count > peak) {
        if (atomic_compare_exchange_weak(&pool->peak, &peak, count)) {
            break;
        }
    }
    atomic_fetch_add(&pool->total_allocs, 1);

    return ctx;
}

void flow_pool_free(flow_pool_t *pool, flow_context_t *ctx) {
    if (!pool || !ctx) {
        return;
    }

    if (!atomic_load_explicit(&ctx->active, memory_order_acquire)) {
        return;  /* Already freed */
    }

    /* Do NOT free resources here. Workers may still hold a pointer to this
     * flow_ctx and be actively using the nghttp2 session / body buffer.
     * Resources are freed by flow_pool_drain_deferred() only after:
     *   1. The 2s grace period has expired, AND
     *   2. No in-flight events reference this flow (inflight_events == 0)
     * The struct and all its resources remain valid in the deferred queue. */

    /* Mark as inactive */
    atomic_store_explicit(&ctx->active, false, memory_order_release);

    /* Remove from active list */
    if (ctx->list_prev) {
        ctx->list_prev->list_next = ctx->list_next;
    } else {
        pool->active_head = ctx->list_next;
    }
    if (ctx->list_next) {
        ctx->list_next->list_prev = ctx->list_prev;
    }

    /* Add to deferred free FIFO (reuse list_next for singly-linked chain) */
    ctx->list_prev = NULL;
    ctx->list_next = NULL;
    ctx->last_seen_ns = get_time_ns();

    if (pool->deferred_tail) {
        pool->deferred_tail->list_next = ctx;
    } else {
        pool->deferred_head = ctx;
    }
    pool->deferred_tail = ctx;

    /* Update statistics */
    atomic_fetch_sub(&pool->allocated, 1);
    atomic_fetch_add(&pool->total_frees, 1);
}

void flow_pool_drain_deferred(flow_pool_t *pool, uint64_t now) {
    if (!pool) {
        return;
    }

    while (pool->deferred_head) {
        flow_context_t *ctx = pool->deferred_head;
        if (now - ctx->last_seen_ns < FLOW_DEFERRED_FREE_GRACE_NS) {
            break;  /* Not yet expired */
        }
        /* Don't free if workers still have in-flight events referencing this flow */
        if (atomic_load_explicit(&ctx->inflight_events, memory_order_acquire) > 0) {
            break;  /* Workers still processing — retry next janitor cycle */
        }
        pool->deferred_head = ctx->list_next;
        if (!pool->deferred_head) {
            pool->deferred_tail = NULL;
        }
        flow_free_resources(ctx);
        free(ctx);
    }
}

void flow_pool_force_drain(flow_pool_t *pool) {
    if (!pool) {
        return;
    }

    /* Free all active flows immediately (no grace period) */
    flow_context_t *ctx = pool->active_head;
    while (ctx) {
        flow_context_t *next = ctx->list_next;
        flow_free_resources(ctx);
        free(ctx);
        ctx = next;
    }
    pool->active_head = NULL;

    /* Free all deferred flows immediately (no grace period) */
    ctx = pool->deferred_head;
    while (ctx) {
        flow_context_t *next = ctx->list_next;
        flow_free_resources(ctx);
        free(ctx);
        ctx = next;
    }
    pool->deferred_head = NULL;
    pool->deferred_tail = NULL;
}

/*============================================================================
 * CK Hash Set Index Operations
 *
 * The custom hash table implementations have been replaced with thread-safe
 * CK hs wrappers. See ck_cookie_index.c and ck_shadow_index.c.
 *
 * Old code removed (lines 244-820 of original):
 * - cookie_insert_into(), cookie_lookup_in(), cookie_index_migrate_batch()
 * - cookie_index_grow(), cookie_index_init(), cookie_index_cleanup()
 * - cookie_index_insert(), cookie_index_lookup(), cookie_index_remove()
 * - shadow_insert_into(), shadow_lookup_in(), shadow_index_migrate_batch()
 * - shadow_index_grow(), shadow_index_init(), shadow_index_cleanup()
 * - shadow_index_insert(), shadow_index_lookup(), shadow_index_remove()
 * - shadow_find_by_cookie()
 *============================================================================*/

#include "ck_cookie_index.h"
#include "ck_shadow_index.h"

/*============================================================================
 * Flow Manager Implementation
 *============================================================================*/

int flow_manager_init(flow_manager_t *mgr) {
    if (!mgr) {
        return -1;
    }

    memset(mgr, 0, sizeof(*mgr));

    /* Initialize pool (no pre-allocation) */
    if (flow_pool_init(&mgr->pool) != 0) {
        return -1;
    }

    /* Initialize CK cookie index with initial capacity */
    if (ck_cookie_index_init(&mgr->cookie_idx, FLOW_INDEX_INITIAL_CAPACITY) != 0) {
        flow_pool_cleanup(&mgr->pool);
        return -1;
    }

    /* Initialize CK shadow index with initial capacity */
    if (ck_shadow_index_init(&mgr->shadow_idx, FLOW_INDEX_INITIAL_CAPACITY) != 0) {
        ck_cookie_index_cleanup(&mgr->cookie_idx);
        flow_pool_cleanup(&mgr->pool);
        return -1;
    }

    return 0;
}

void flow_manager_cleanup(flow_manager_t *mgr) {
    if (!mgr) {
        return;
    }

    /*
     * COMPREHENSIVE CLEANUP: Collect all unique flow pointers, then free them.
     *
     * With CK hs, we iterate using ck_hs_next() to find all entries.
     * Flows may exist in both indices, so we deduplicate.
     */

    /* Estimate max flows from pool stats */
    uint64_t max_flows = atomic_load(&mgr->pool.total_allocs);
    if (max_flows == 0) {
        max_flows = 256;  /* Default estimate */
    }

    /* Allocate array for unique flow pointers */
    flow_context_t **flows_to_free = calloc((size_t)max_flows, sizeof(flow_context_t *));
    size_t flow_count = 0;

    if (!flows_to_free) {
        /* Fallback: just clean up indices without freeing flows (leak is better than crash) */
        ck_shadow_index_cleanup(&mgr->shadow_idx);
        ck_cookie_index_cleanup(&mgr->cookie_idx);
        return;
    }

    /* Helper macro to add unique flow pointer */
    #define ADD_UNIQUE_FLOW(ctx_ptr) do { \
        if ((ctx_ptr) != NULL) { \
            bool found = false; \
            for (size_t _k = 0; _k < flow_count && !found; _k++) { \
                if (flows_to_free[_k] == (ctx_ptr)) found = true; \
            } \
            if (!found && flow_count < (size_t)max_flows) { \
                flows_to_free[flow_count++] = (ctx_ptr); \
            } \
        } \
    } while (0)

    /* Collect from cookie_index via CK iterator */
    {
        ck_hs_iterator_t iter = CK_HS_ITERATOR_INITIALIZER;
        void *entry_ptr;
        while (ck_hs_next(&mgr->cookie_idx.hs, &iter, &entry_ptr)) {
            ck_cookie_entry_t *entry = entry_ptr;
            ADD_UNIQUE_FLOW(entry->ctx);
        }
    }

    /* Collect from shadow_index via CK iterator */
    {
        ck_hs_iterator_t iter = CK_HS_ITERATOR_INITIALIZER;
        void *entry_ptr;
        while (ck_hs_next(&mgr->shadow_idx.hs, &iter, &entry_ptr)) {
            ck_shadow_entry_t *entry = entry_ptr;
            ADD_UNIQUE_FLOW(entry->ctx);
        }
    }

    /*
     * FIX: Also collect flows from deferred queue.
     * Flows in the deferred queue have been removed from cookie_index/shadow_index
     * but not yet freed. Without this, they leak at shutdown.
     */
    {
        flow_context_t *deferred_ctx = mgr->pool.deferred_head;
        while (deferred_ctx) {
            ADD_UNIQUE_FLOW(deferred_ctx);
            deferred_ctx = deferred_ctx->list_next;
        }
    }

    #undef ADD_UNIQUE_FLOW

    /* Now free all collected flows */
    for (size_t i = 0; i < flow_count; i++) {
        flow_free_resources(flows_to_free[i]);
        free(flows_to_free[i]);
    }
    free(flows_to_free);

    /* Now clean up the index structures (frees entries and ck_hs) */
    ck_shadow_index_cleanup(&mgr->shadow_idx);
    ck_cookie_index_cleanup(&mgr->cookie_idx);

    /* Clear pool lists (flows already freed above) */
    mgr->pool.active_head = NULL;
    mgr->pool.deferred_head = NULL;
    mgr->pool.deferred_tail = NULL;
}

void flow_manager_force_drain(flow_manager_t *mgr) {
    if (!mgr) {
        return;
    }
    flow_pool_force_drain(&mgr->pool);
}

/**
 * @brief Read-only flow lookup (SPMC safe)
 *
 * FIX C4: This function is now purely read-only to maintain SPMC thread safety.
 * Multiple workers can call this concurrently without data races.
 *
 * Write operations (merging SSL info into XDP-created flows) must be done
 * separately via flow_merge_ssl_info() which is only safe from dispatcher.
 */
flow_context_t *flow_lookup_ex(flow_manager_t *mgr, uint64_t cookie,
                               uint32_t pid, uint64_t ssl_ctx,
                               flow_lookup_path_t *path_out) {
    if (path_out) {
        *path_out = FLOW_PATH_NONE;
    }

    if (!mgr) {
        return NULL;
    }

    /* Try cookie_index first (fast path) - uses CK hs (SPMC safe, read-only) */
    if (cookie != 0) {
        flow_context_t *ctx = ck_cookie_index_lookup(&mgr->cookie_idx, cookie);
        if (ctx && atomic_load_explicit(&ctx->active, memory_order_acquire)) {
            /*
             * Verify the cookie-matched flow belongs to this connection.
             * Read-only validation - no writes allowed here for SPMC safety.
             */
            bool cookie_flow_valid = true;

            /* Check for ssl_ctx mismatch (both non-zero and different) */
            if (ssl_ctx != 0 && ctx->ssl_ctx != 0 && ctx->ssl_ctx != ssl_ctx) {
                cookie_flow_valid = false;
            }

            /* Check for pid mismatch (both non-zero and different) */
            if (pid != 0 && ctx->pid != 0 && ctx->pid != pid) {
                cookie_flow_valid = false;
            }

            if (cookie_flow_valid) {
                if (path_out) {
                    *path_out = FLOW_PATH_COOKIE;
                }
                return ctx;
            }
        }
    }

    /* Fall back to shadow_index - uses CK hs (SPMC safe, read-only) */
    if (pid != 0) {
        flow_context_t *ctx = ck_shadow_index_lookup(&mgr->shadow_idx, pid, ssl_ctx);
        if (ctx && atomic_load_explicit(&ctx->active, memory_order_acquire)) {
            if (path_out) {
                *path_out = FLOW_PATH_SHADOW;
            }
            return ctx;
        }
    }

    return NULL;
}

/**
 * @brief Merge SSL info into XDP-created flow (single-writer only)
 *
 * FIX C4: This function performs write operations and MUST only be called
 * from the dispatcher thread (single-writer context).
 *
 * XDP-SSL Correlation: XDP events create flows with ssl_ctx=0.
 * When SSL events arrive with the same cookie, call this to merge
 * the SSL context and PID into the XDP-created flow.
 *
 * @param mgr      Flow manager
 * @param ctx      Flow context to update (must be active)
 * @param pid      Process ID to merge (0 = don't update)
 * @param ssl_ctx  SSL context to merge (0 = don't update)
 * @return 0 on success, -1 on error
 *
 * @par Thread Safety: Single-writer only (dispatcher thread)
 */
int flow_merge_ssl_info(flow_manager_t *mgr, flow_context_t *ctx,
                        uint32_t pid, uint64_t ssl_ctx) {
    if (!mgr || !ctx) {
        return -1;
    }

    /* Verify flow is still active */
    if (!atomic_load_explicit(&ctx->active, memory_order_acquire)) {
        return -1;
    }

    bool updated = false;

    /* Merge ssl_ctx if flow doesn't have one */
    if (ctx->ssl_ctx == 0 && ssl_ctx != 0) {
        ctx->ssl_ctx = ssl_ctx;
        atomic_fetch_or(&ctx->flags, FLOW_FLAG_HAS_SSL);
        updated = true;

        /* Add to shadow_index for future SSL lookups */
        if (pid != 0 && !(atomic_load(&ctx->flags) & FLOW_FLAG_IN_SHADOW)) {
            if (ck_shadow_index_insert(&mgr->shadow_idx, pid, ssl_ctx, ctx) == 0) {
                atomic_fetch_or(&ctx->flags, FLOW_FLAG_IN_SHADOW);
            }
        }
    }

    /* Merge pid if flow doesn't have one */
    if (ctx->pid == 0 && pid != 0) {
        ctx->pid = pid;
        updated = true;
    }

    (void)updated;  /* Suppress unused warning - useful for debugging */
    return 0;
}

flow_context_t *flow_lookup(flow_manager_t *mgr, uint64_t cookie,
                            uint32_t pid, uint64_t ssl_ctx) {
    return flow_lookup_ex(mgr, cookie, pid, ssl_ctx, NULL);
}

flow_context_t *flow_get_or_create(flow_manager_t *mgr, uint64_t cookie,
                                    uint32_t pid, uint64_t ssl_ctx) {
    if (!mgr) {
        return NULL;
    }

    /* Try to find existing flow */
    flow_context_t *ctx = flow_lookup(mgr, cookie, pid, ssl_ctx);
    if (ctx) {
        return ctx;
    }

    /* Allocate new context */
    ctx = flow_pool_alloc(&mgr->pool);
    if (!ctx) {
        return NULL;  /* OOM */
    }

    /* Initialize identity fields */
    ctx->socket_cookie = cookie;
    ctx->pid = pid;
    ctx->ssl_ctx = ssl_ctx;

    /* Add to shadow_index (always) - uses CK hs (single-writer safe) */
    if (pid != 0) {
        if (ck_shadow_index_insert(&mgr->shadow_idx, pid, ssl_ctx, ctx) == 0) {
            atomic_fetch_or(&ctx->flags, FLOW_FLAG_IN_SHADOW);
        }
    }

    /* Add to cookie_index if cookie known - uses CK hs (single-writer safe) */
    if (cookie != 0) {
        int insert_result = ck_cookie_index_insert(&mgr->cookie_idx, cookie, ctx);
        if (insert_result == 0) {
            atomic_fetch_or(&ctx->flags, FLOW_FLAG_IN_COOKIE);
        } else {
            /* CK hs handles growth automatically, but log failures */
            if (g_config.debug_mode) {
                fprintf(stderr, "[WARN] ck_cookie_index_insert failed for cookie=%llu (count=%lu)\n",
                        (unsigned long long)cookie,
                        (unsigned long)atomic_load(&mgr->cookie_idx.count));
            }
        }
    }

    return ctx;
}

/*
 * Promote flow to cookie index - see flow_context.h for API documentation.
 * Implementation handles Two-Source Race where XDP arrives before SSL has cookie.
 */
int flow_promote_cookie(flow_manager_t *mgr, uint32_t pid,
                        uint64_t ssl_ctx, uint64_t cookie) {
    if (!mgr || cookie == 0) {
        return -1;
    }

    /* Find SSL flow by shadow key - uses CK hs (SPMC safe) */
    flow_context_t *ssl_flow = ck_shadow_index_lookup(&mgr->shadow_idx, pid, ssl_ctx);
    if (!ssl_flow || !atomic_load_explicit(&ssl_flow->active, memory_order_acquire)) {
        return -1;
    }

    /* Check if already promoted */
    if (ssl_flow->socket_cookie != 0) {
        return 0;
    }

    /* Check if an XDP-only flow already has this cookie (Two-Source Race) */
    flow_context_t *xdp_flow = ck_cookie_index_lookup(&mgr->cookie_idx, cookie);

    /* Debug: log promotion attempt and cookie_index state */
    if (g_config.debug_mode) {
        fprintf(stderr, "[DEBUG] SSL PROMOTE: pid=%u ssl_ctx=%llx promoting to cookie=%llu\n",
                pid, (unsigned long long)ssl_ctx, (unsigned long long)cookie);
        if (xdp_flow) {
            fprintf(stderr, "[DEBUG] SSL PROMOTE: FOUND XDP flow_id=%u (flags=%u)\n",
                    xdp_flow->self_id, atomic_load(&xdp_flow->flags));
        } else {
            /* CK hs doesn't expose bucket iteration - just log count */
            fprintf(stderr, "[DEBUG] SSL PROMOTE: NO XDP flow for cookie=%llu. Index has %lu entries\n",
                    (unsigned long long)cookie,
                    (unsigned long)atomic_load(&mgr->cookie_idx.count));
        }
    }

    if (xdp_flow && xdp_flow != ssl_flow &&
        atomic_load_explicit(&xdp_flow->active, memory_order_acquire)) {
        /*
         * MERGE: XDP created a flow before SSL got the cookie.
         * Copy XDP metadata (5-tuple, counters) into SSL flow.
         */
        if (atomic_load(&xdp_flow->flags) & FLOW_FLAG_HAS_XDP) {
            /* Copy 5-tuple */
            memcpy(&ssl_flow->flow, &xdp_flow->flow, sizeof(flow_key_t));

            /* Copy XDP metadata */
            ssl_flow->ifindex = xdp_flow->ifindex;
            /* Only copy category if XDP flow has classification.
             * Don't overwrite existing classification with UNKNOWN. */
            if (xdp_flow->xdp_category != XDP_CAT_UNKNOWN) {
                ssl_flow->xdp_category = xdp_flow->xdp_category;
            }
            ssl_flow->first_seen_ns = xdp_flow->first_seen_ns;
            if (xdp_flow->last_seen_ns > ssl_flow->last_seen_ns) {
                ssl_flow->last_seen_ns = xdp_flow->last_seen_ns;
            }

            /* Accumulate traffic counters */
            ssl_flow->pkts_in += xdp_flow->pkts_in;
            ssl_flow->pkts_out += xdp_flow->pkts_out;
            ssl_flow->bytes_in += xdp_flow->bytes_in;
            ssl_flow->bytes_out += xdp_flow->bytes_out;

            /* Set XDP flag on merged flow (release semantics for workers) */
            atomic_fetch_or_explicit(&ssl_flow->flags, FLOW_FLAG_HAS_XDP, memory_order_release);

            /* Debug: Log merge event */
            if (g_config.debug_mode) {
                fprintf(stderr, "[DEBUG] SSL: MERGE flow_id=%u absorbed XDP flow_id=%u (cookie=%llu)\n",
                        ssl_flow->self_id, xdp_flow->self_id, (unsigned long long)cookie);
            }
        }

        /* Remove orphaned XDP flow from cookie_index - uses CK hs (single-writer safe) */
        ck_cookie_index_remove(&mgr->cookie_idx, cookie);

        /* Mark XDP flow for deferred free (2-second grace period) */
        flow_pool_free(&mgr->pool, xdp_flow);

        /* Track merges for statistics */
        atomic_fetch_add(&mgr->shadow_idx.merges, 1);
    }

    /* Promote SSL flow to cookie_index - uses CK hs (single-writer safe) */
    ssl_flow->socket_cookie = cookie;
    if (ck_cookie_index_insert(&mgr->cookie_idx, cookie, ssl_flow) == 0) {
        atomic_fetch_or(&ssl_flow->flags, FLOW_FLAG_IN_COOKIE);
        atomic_fetch_add(&mgr->shadow_idx.promotions, 1);
    }

    return 0;
}

void flow_terminate(flow_manager_t *mgr, flow_context_t *ctx) {
    if (!mgr || !ctx) {
        return;
    }

    /* Remove from cookie_index if present - uses CK hs (single-writer safe) */
    if ((atomic_load(&ctx->flags) & FLOW_FLAG_IN_COOKIE) && ctx->socket_cookie != 0) {
        ck_cookie_index_remove(&mgr->cookie_idx, ctx->socket_cookie);
    }

    /* Remove from shadow_index if present - uses CK hs (single-writer safe) */
    if ((atomic_load(&ctx->flags) & FLOW_FLAG_IN_SHADOW) && ctx->pid != 0) {
        ck_shadow_index_remove(&mgr->shadow_idx, ctx->pid, ctx->ssl_ctx);
    }

    /* Free to pool (deferred) */
    flow_pool_free(&mgr->pool, ctx);
}

int flow_evict_stale(flow_manager_t *mgr, uint64_t current_ns) {
    if (!mgr) {
        return 0;
    }

    int evicted = 0;

    /* Walk active list (O(active) instead of O(capacity)) */
    flow_context_t *ctx = mgr->pool.active_head;
    while (ctx) {
        flow_context_t *next = ctx->list_next;

        if (current_ns - ctx->last_seen_ns > FLOW_TIMEOUT_NS) {
            flow_terminate(mgr, ctx);
            evicted++;
        }

        ctx = next;
    }

    /* Drain deferred free queue */
    flow_pool_drain_deferred(&mgr->pool, current_ns);

    return evicted;
}

/*============================================================================
 * Flow Context Helpers
 *============================================================================*/

void flow_update_xdp(flow_context_t *ctx, const xdp_packet_event_t *evt) {
    if (!ctx || !evt) {
        return;
    }

    /* Copy flow key (5-tuple) from event */
    memcpy(&ctx->flow, &evt->flow, sizeof(flow_key_t));

    /* Update timestamps */
    if (ctx->first_seen_ns == 0) {
        ctx->first_seen_ns = evt->timestamp_ns;
    }
    ctx->last_seen_ns = evt->timestamp_ns;

    /* Update counters based on direction
     * FIX H6: Use atomic operations to prevent lost updates from concurrent access.
     * relaxed memory order is sufficient - we only care about eventual consistency. */
    if (evt->direction == 1) {  /* Ingress */
        atomic_fetch_add_explicit(&ctx->pkts_in, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&ctx->bytes_in, evt->pkt_len, memory_order_relaxed);
    } else {  /* Egress */
        atomic_fetch_add_explicit(&ctx->pkts_out, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&ctx->bytes_out, evt->pkt_len, memory_order_relaxed);
    }

    /* Interface info */
    ctx->ifindex = evt->ifindex;
    /* Only update category if this event has a classification.
     * Don't overwrite existing classification with UNKNOWN (e.g., from ACK packets). */
    if (evt->category != XDP_CAT_UNKNOWN) {
        ctx->xdp_category = evt->category;
    }
    ctx->xdp_direction = evt->direction;  /* Store direction (1=ingress, 2=egress) */

    /* Convert ifindex to interface name if not already done */
    if (evt->ifindex > 0 && ctx->ifname[0] == '\0') {
        if_indextoname(evt->ifindex, ctx->ifname);
    }

    /*
     * CRITICAL: Set HAS_XDP flag with release semantics.
     * Workers use acquire semantics when reading this flag.
     * This ensures XDP metadata writes above are visible to workers.
     */
    atomic_fetch_or_explicit(&ctx->flags, FLOW_FLAG_HAS_XDP, memory_order_release);

    /* Update state if we have both views */
    if ((atomic_load(&ctx->flags) & FLOW_FLAG_HAS_SSL) && ctx->state == FLOW_STATE_INIT) {
        ctx->state = FLOW_STATE_ACTIVE;
    }
}

int flow_h2_session_init(flow_context_t *ctx, nghttp2_session_callbacks *cbs,
                          void *user) {
    if (!ctx || ctx->proto != FLOW_PROTO_HTTP2) {
        return -1;
    }

    if (ctx->parser.h2.session != NULL) {
        return 0;
    }

    int rv;
    nghttp2_option *opt = NULL;

    rv = nghttp2_option_new(&opt);
    if (rv != 0) {
        return -1;
    }

    nghttp2_option_set_no_recv_client_magic(opt, 1);
    nghttp2_option_set_no_auto_window_update(opt, 1);

    rv = nghttp2_session_server_new2(&ctx->parser.h2.session, cbs, user, opt);
    nghttp2_option_del(opt);

    if (rv != 0) {
        return -1;
    }

    rv = nghttp2_hd_inflate_new(&ctx->parser.h2.inflater);
    if (rv != 0) {
        nghttp2_session_del(ctx->parser.h2.session);
        ctx->parser.h2.session = NULL;
        return -1;
    }

    ctx->parser.h2.reassembly_capacity = 65536;
    /*
     * FIX: Use cache-line aligned allocation for HTTP/2 reassembly buffer.
     * This improves performance by avoiding false sharing on multi-core systems
     * and ensures proper alignment for SIMD operations in memcpy.
     */
    ctx->parser.h2.reassembly_buf = aligned_alloc(64, ctx->parser.h2.reassembly_capacity);
    if (!ctx->parser.h2.reassembly_buf) {
        nghttp2_hd_inflate_del(ctx->parser.h2.inflater);
        nghttp2_session_del(ctx->parser.h2.session);
        ctx->parser.h2.inflater = NULL;
        ctx->parser.h2.session = NULL;
        return -1;
    }
    ctx->parser.h2.reassembly_len = 0;

    /* Drain initial SETTINGS frame */
    for (;;) {
        const uint8_t *send_data;
        ssize_t send_len = nghttp2_session_mem_send(ctx->parser.h2.session,
                                                     &send_data);
        if (send_len <= 0) break;
    }

    flow_h2_init_stream_pool(ctx);

    return 0;
}

int flow_h1_parser_init(flow_context_t *ctx, llhttp_settings_t *settings) {
    if (!ctx || ctx->proto != FLOW_PROTO_HTTP1) {
        return -1;
    }

    if (ctx->parser.h1.initialized) {
        return 0;
    }

    if (!settings) {
        llhttp_settings_init(&ctx->parser.h1.settings);
    } else {
        memcpy(&ctx->parser.h1.settings, settings, sizeof(llhttp_settings_t));
    }

    llhttp_init(&ctx->parser.h1.parser, HTTP_BOTH, &ctx->parser.h1.settings);

    ctx->parser.h1.initialized = true;
    return 0;
}

int flow_init_parser(flow_context_t *ctx, const char *alpn) {
    if (!ctx || !alpn) {
        return -1;
    }

    if (atomic_load(&ctx->flags) & FLOW_FLAG_PARSER_INIT) {
        return 0;
    }

    safe_strcpy(ctx->alpn, sizeof(ctx->alpn), alpn);

    if (strcmp(alpn, "h2") == 0) {
        ctx->proto = FLOW_PROTO_HTTP2;
        ctx->parser.h2.session = NULL;
        ctx->parser.h2.inflater = NULL;
        ctx->parser.h2.reassembly_buf = NULL;
        ctx->parser.h2.reassembly_len = 0;
        ctx->parser.h2.reassembly_capacity = 0;
        ctx->parser.h2.preface_seen = false;
        ctx->parser.h2.settings_seen = false;

    } else if (strcmp(alpn, "http/1.1") == 0 || strcmp(alpn, "http/1.0") == 0) {
        ctx->proto = FLOW_PROTO_HTTP1;
        memset(&ctx->parser.h1, 0, sizeof(ctx->parser.h1));
        ctx->parser.h1.initialized = false;

    } else {
        ctx->proto = FLOW_PROTO_OTHER;
    }

    atomic_fetch_or(&ctx->flags, FLOW_FLAG_PARSER_INIT);
    return 0;
}

void flow_free_resources(flow_context_t *ctx) {
    if (!ctx) {
        return;
    }

    /*
     * Free protocol-specific resources based on ctx->proto.
     *
     * CRITICAL: The parser field is a UNION - h1 and h2 share memory.
     * We MUST check proto before accessing union members, otherwise
     * we interpret h1 data as h2 pointers (or vice versa) and crash.
     */
    if (ctx->proto == FLOW_PROTO_HTTP2) {
        /* Free HTTP/2 resources */
        if (ctx->parser.h2.session) {
            nghttp2_session_del(ctx->parser.h2.session);
            ctx->parser.h2.session = NULL;
        }
        if (ctx->parser.h2.inflater) {
            nghttp2_hd_inflate_del(ctx->parser.h2.inflater);
            ctx->parser.h2.inflater = NULL;
        }
        if (ctx->parser.h2.reassembly_buf) {
            free(ctx->parser.h2.reassembly_buf);
            ctx->parser.h2.reassembly_buf = NULL;
        }
        if (ctx->parser.h2.callback_ctx) {
            http2_free_callback_ctx(ctx->parser.h2.callback_ctx);
            ctx->parser.h2.callback_ctx = NULL;
        }

        /* Free H2 stream bodies if any were allocated */
        for (int32_t i = 0; i < FLOW_MAX_H2_STREAMS; i++) {
            flow_txn_free_body(&ctx->parser.h2.streams[i]);
        }
    } else if (ctx->proto == FLOW_PROTO_HTTP1) {
        /* Free HTTP/1 transaction body if allocated */
        flow_txn_free_body(&ctx->parser.h1.txn);
    }
    /* FLOW_PROTO_UNKNOWN and FLOW_PROTO_OTHER have no allocated resources */

    if (ctx->body.buffer) {
        free(ctx->body.buffer);
        ctx->body.buffer = NULL;
    }

    ctx->state = FLOW_STATE_CLOSED;
    atomic_store(&ctx->flags, 0);
}

/*============================================================================
 * Transaction/Stream Operations
 *============================================================================*/

uint32_t flow_get_monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

void flow_h2_init_stream_pool(flow_context_t *ctx) {
    if (!ctx || ctx->proto != FLOW_PROTO_HTTP2) {
        return;
    }

    h2_parser_ctx_t *h2 = &ctx->parser.h2;

    for (int32_t i = 0; i < FLOW_MAX_H2_STREAMS - 1; i++) {
        h2->streams[i].stream_id = 0;
        h2->streams[i].state = TXN_STATE_IDLE;
        h2->streams[i].flags = 0;
        h2->streams[i].body_buf = NULL;
        h2->streams[i].body_len = 0;
        h2->streams[i].body_capacity = 0;
        h2->streams[i].next_free = i + 1;
    }
    h2->streams[FLOW_MAX_H2_STREAMS - 1].stream_id = 0;
    h2->streams[FLOW_MAX_H2_STREAMS - 1].state = TXN_STATE_IDLE;
    h2->streams[FLOW_MAX_H2_STREAMS - 1].flags = 0;
    h2->streams[FLOW_MAX_H2_STREAMS - 1].body_buf = NULL;
    h2->streams[FLOW_MAX_H2_STREAMS - 1].next_free = -1;

    h2->free_head = 0;
    h2->active_count = 0;
    h2->hpack_corrupted = false;
}

flow_transaction_t *flow_h2_alloc_stream(flow_context_t *ctx, int32_t stream_id) {
    if (!ctx || ctx->proto != FLOW_PROTO_HTTP2) {
        return NULL;
    }

    h2_parser_ctx_t *h2 = &ctx->parser.h2;

    if (h2->free_head < 0) {
        return NULL;
    }

    int32_t slot = h2->free_head;
    flow_transaction_t *txn = &h2->streams[slot];
    h2->free_head = txn->next_free;
    h2->active_count++;

    memset(txn, 0, sizeof(*txn));
    txn->stream_id = stream_id;
    txn->state = TXN_STATE_IDLE;
    txn->last_active_ms = flow_get_monotonic_ms();
    txn->next_free = -1;

    return txn;
}

flow_transaction_t *flow_h2_find_stream(flow_context_t *ctx, int32_t stream_id) {
    if (!ctx || ctx->proto != FLOW_PROTO_HTTP2 || stream_id <= 0) {
        return NULL;
    }

    h2_parser_ctx_t *h2 = &ctx->parser.h2;

    for (int32_t i = 0; i < FLOW_MAX_H2_STREAMS; i++) {
        flow_transaction_t *txn = &h2->streams[i];
        if (txn->stream_id == stream_id && txn->state != TXN_STATE_IDLE) {
            return txn;
        }
    }

    return NULL;
}

void flow_h2_free_stream(flow_context_t *ctx, flow_transaction_t *txn) {
    if (!ctx || ctx->proto != FLOW_PROTO_HTTP2 || !txn) {
        return;
    }

    h2_parser_ctx_t *h2 = &ctx->parser.h2;

    flow_txn_free_body(txn);

    txn->stream_id = 0;
    txn->state = TXN_STATE_IDLE;
    txn->flags = 0;
    txn->status_code = 0;
    txn->content_length = 0;
    txn->method[0] = '\0';
    txn->path[0] = '\0';
    txn->host[0] = '\0';
    txn->content_type[0] = '\0';

    txn->next_free = h2->free_head;
    h2->free_head = (int32_t)(txn - h2->streams);
    h2->active_count--;
}

int flow_h2_reap_ghosts(flow_context_t *ctx, uint32_t current_ms) {
    if (!ctx || ctx->proto != FLOW_PROTO_HTTP2) {
        return 0;
    }

    h2_parser_ctx_t *h2 = &ctx->parser.h2;
    int reaped = 0;

    for (int32_t i = 0; i < FLOW_MAX_H2_STREAMS; i++) {
        flow_transaction_t *txn = &h2->streams[i];

        if (txn->state == TXN_STATE_IDLE) {
            continue;
        }

        uint32_t age_ms = current_ms - txn->last_active_ms;
        if (age_ms > FLOW_STREAM_TIMEOUT_MS) {
            flow_h2_free_stream(ctx, txn);
            reaped++;
        }
    }

    return reaped;
}

void flow_h1_reset_txn(flow_context_t *ctx) {
    if (!ctx || ctx->proto != FLOW_PROTO_HTTP1) {
        return;
    }

    flow_transaction_t *txn = &ctx->parser.h1.txn;

    flow_txn_free_body(txn);

    txn->state = TXN_STATE_IDLE;
    txn->flags = 0;
    txn->status_code = 0;
    txn->content_length = 0;
    txn->method[0] = '\0';
    txn->path[0] = '\0';
    txn->host[0] = '\0';
    txn->content_type[0] = '\0';
    txn->last_active_ms = flow_get_monotonic_ms();

    if (ctx->parser.h1.initialized) {
        llhttp_reset(&ctx->parser.h1.parser);
    }
}

int flow_txn_alloc_body(flow_transaction_t *txn, size_t capacity) {
    if (!txn) {
        return -1;
    }

    if (txn->body_buf) {
        return 0;
    }

    if (capacity < 4096) {
        capacity = 4096;
    }

    /*
     * FIX: Use cache-line aligned allocation for transaction body buffer.
     * This improves performance by avoiding false sharing and ensures
     * proper alignment for SIMD operations. Round up capacity to be
     * a multiple of 64 for aligned_alloc requirements.
     */
    size_t aligned_capacity = (capacity + 63) & ~(size_t)63;
    txn->body_buf = aligned_alloc(64, aligned_capacity);
    if (!txn->body_buf) {
        return -1;
    }

    txn->body_len = 0;
    txn->body_capacity = capacity;
    txn->flags |= TXN_FLAG_BODY_ALLOCATED;

    return 0;
}

int flow_txn_append_body(flow_transaction_t *txn, const uint8_t *data, size_t len) {
    if (!txn || !data || len == 0) {
        return 0;
    }

    if (!txn->body_buf) {
        if (flow_txn_alloc_body(txn, len * 2) != 0) {
            return -1;
        }
    }

    if (txn->body_len + len > txn->body_capacity) {
        size_t new_capacity = txn->body_capacity * 2;
        if (new_capacity < txn->body_len + len) {
            new_capacity = txn->body_len + len + 4096;
        }

        if (new_capacity > 256 * 1024) {
            new_capacity = 256 * 1024;
            if (txn->body_len + len > new_capacity) {
                len = new_capacity - txn->body_len;
                if (len == 0) {
                    return 0;
                }
            }
        }

        uint8_t *new_buf = realloc(txn->body_buf, new_capacity);
        if (!new_buf) {
            return -1;
        }
        txn->body_buf = new_buf;
        txn->body_capacity = new_capacity;
    }

    memcpy(txn->body_buf + txn->body_len, data, len);
    txn->body_len += len;
    txn->flags |= TXN_FLAG_HAS_BODY;

    return 0;
}

void flow_txn_free_body(flow_transaction_t *txn) {
    if (!txn) {
        return;
    }

    if (txn->body_buf) {
        free(txn->body_buf);
        txn->body_buf = NULL;
    }
    txn->body_len = 0;
    txn->body_capacity = 0;
    txn->flags &= ~(TXN_FLAG_BODY_ALLOCATED | TXN_FLAG_HAS_BODY);
}

/*============================================================================
 * Pool Statistics
 *============================================================================*/

void flow_manager_get_stats(flow_manager_t *mgr, flow_pool_stats_t *stats) {
    if (!mgr || !stats) {
        return;
    }

    memset(stats, 0, sizeof(*stats));

    /* Pool statistics */
    stats->pool_allocated = atomic_load(&mgr->pool.allocated);
    stats->pool_peak = atomic_load(&mgr->pool.peak);
    stats->pool_total_allocs = atomic_load(&mgr->pool.total_allocs);
    stats->pool_total_frees = atomic_load(&mgr->pool.total_frees);
    stats->pool_alloc_failures = atomic_load(&mgr->pool.alloc_failures);

    /* Cookie index statistics */
    stats->cookie_count = atomic_load(&mgr->cookie_idx.count);
    stats->cookie_hits = atomic_load(&mgr->cookie_idx.hits);
    stats->cookie_misses = atomic_load(&mgr->cookie_idx.misses);

    /* Shadow index statistics */
    stats->shadow_count = atomic_load(&mgr->shadow_idx.count);
    stats->shadow_hits = atomic_load(&mgr->shadow_idx.hits);
    stats->shadow_promotions = atomic_load(&mgr->shadow_idx.promotions);
    stats->shadow_merges = atomic_load(&mgr->shadow_idx.merges);
}
