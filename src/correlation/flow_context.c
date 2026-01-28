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
 * @see flow_context.h for API documentation
 */

#include "flow_context.h"
#include "../protocol/http2.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

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

/** Get nanosecond timestamp for deferred free */
static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

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

/*============================================================================
 * Cookie Index Implementation
 *============================================================================*/

/** Empty slot marker (cookie=0 is valid for "unknown") */
#define COOKIE_SLOT_EMPTY   UINT64_MAX
#define COOKIE_SLOT_DELETED (UINT64_MAX - 1)

/** Shadow index empty slot marker */
#define SHADOW_SLOT_EMPTY   0

/*--- Cookie index: internal insert into a specific bucket array ---*/

static int cookie_insert_into(cookie_entry_t *buckets, size_t capacity,
                               uint64_t cookie, flow_context_t *ctx) {
    size_t start = hash_cookie(cookie) % capacity;
    size_t pos = start;

    do {
        cookie_entry_t *entry = &buckets[pos];

        if (entry->cookie == COOKIE_SLOT_EMPTY ||
            entry->cookie == COOKIE_SLOT_DELETED) {
            entry->cookie = cookie;
            entry->ctx = ctx;
            return 1;  /* New entry inserted */
        }

        if (entry->cookie == cookie) {
            entry->ctx = ctx;
            return 0;  /* Updated existing */
        }

        pos = (pos + 1) % capacity;
    } while (pos != start);

    return -1;  /* Table full */
}

/*--- Cookie index: internal lookup in a specific bucket array ---*/

static flow_context_t *cookie_lookup_in(cookie_entry_t *buckets, size_t capacity,
                                         uint64_t cookie) {
    size_t start = hash_cookie(cookie) % capacity;
    size_t pos = start;

    do {
        cookie_entry_t *entry = &buckets[pos];

        if (entry->cookie == COOKIE_SLOT_EMPTY) {
            return NULL;
        }

        if (entry->cookie == cookie) {
            return entry->ctx;
        }

        pos = (pos + 1) % capacity;
    } while (pos != start);

    return NULL;
}

/*--- Cookie index: incremental migration ---*/

static void cookie_index_migrate_batch(cookie_index_t *idx, size_t batch) {
    if (__builtin_expect(!idx->old_buckets, 1)) {
        return;  /* Fast path: no migration in progress */
    }

    size_t migrated = 0;
    while (migrated < batch && idx->migrate_pos < idx->old_capacity) {
        cookie_entry_t *src = &idx->old_buckets[idx->migrate_pos++];
        if (src->cookie != COOKIE_SLOT_EMPTY &&
            src->cookie != COOKIE_SLOT_DELETED) {
            cookie_insert_into(idx->buckets, idx->capacity,
                               src->cookie, src->ctx);
            migrated++;
        }
    }

    if (idx->migrate_pos >= idx->old_capacity) {
        free(idx->old_buckets);
        idx->old_buckets = NULL;
        idx->old_capacity = 0;
        idx->migrate_pos = 0;
    }
}

/*--- Cookie index: grow (start migration) ---*/

static int cookie_index_grow(cookie_index_t *idx) {
    size_t new_capacity = idx->capacity * 2;

    cookie_entry_t *new_buckets = calloc(new_capacity, sizeof(cookie_entry_t));
    if (!new_buckets) {
        return -1;
    }

    /* Mark all new slots as empty */
    for (size_t i = 0; i < new_capacity; i++) {
        new_buckets[i].cookie = COOKIE_SLOT_EMPTY;
        new_buckets[i].ctx = NULL;
    }

    /* Old table becomes migration source */
    idx->old_buckets = idx->buckets;
    idx->old_capacity = idx->capacity;
    idx->migrate_pos = 0;

    /* New table becomes active */
    idx->buckets = new_buckets;
    idx->capacity = new_capacity;

    return 0;
}

/*--- Cookie index: public API ---*/

int cookie_index_init(cookie_index_t *idx, size_t capacity) {
    if (!idx || capacity == 0) {
        return -1;
    }

    memset(idx, 0, sizeof(*idx));

    idx->buckets = calloc(capacity, sizeof(cookie_entry_t));
    if (!idx->buckets) {
        return -1;
    }

    idx->capacity = capacity;

    for (size_t i = 0; i < capacity; i++) {
        idx->buckets[i].cookie = COOKIE_SLOT_EMPTY;
        idx->buckets[i].ctx = NULL;
    }

    atomic_store(&idx->count, 0);
    atomic_store(&idx->hits, 0);
    atomic_store(&idx->misses, 0);

    return 0;
}

void cookie_index_cleanup(cookie_index_t *idx) {
    if (!idx) {
        return;
    }
    free(idx->buckets);
    idx->buckets = NULL;
    free(idx->old_buckets);
    idx->old_buckets = NULL;
    idx->capacity = 0;
    idx->old_capacity = 0;
}

int cookie_index_insert(cookie_index_t *idx, uint64_t cookie, flow_context_t *ctx) {
    if (!idx || !idx->buckets || cookie == COOKIE_SLOT_EMPTY ||
        cookie == COOKIE_SLOT_DELETED) {
        return -1;
    }

    /* Drive incremental migration forward */
    if (idx->old_buckets) {
        /* Adaptive: under pressure? migrate faster */
        size_t batch = FLOW_INDEX_GROW_BATCH;
        if (atomic_load(&idx->count) * 4 >= idx->capacity * 3) {
            batch = FLOW_INDEX_GROW_BATCH * 4;  /* 32 — urgent */
        }
        cookie_index_migrate_batch(idx, batch);
    }

    /* Check load factor — grow if NOT already migrating */
    if (!idx->old_buckets &&
        atomic_load(&idx->count) * 4 >= idx->capacity * 3) {
        cookie_index_grow(idx);
    }

    /* Insert into active table */
    int result = cookie_insert_into(idx->buckets, idx->capacity, cookie, ctx);
    if (result == 1) {
        atomic_fetch_add(&idx->count, 1);
    }
    return (result >= 0) ? 0 : -1;
}

flow_context_t *cookie_index_lookup(cookie_index_t *idx, uint64_t cookie) {
    if (!idx || !idx->buckets || cookie == COOKIE_SLOT_EMPTY ||
        cookie == COOKIE_SLOT_DELETED) {
        return NULL;
    }

    /* Drive migration (both insert and lookup drive it) */
    if (idx->old_buckets) {
        cookie_index_migrate_batch(idx, FLOW_INDEX_GROW_BATCH);
    }

    /* Search active table first */
    flow_context_t *result = cookie_lookup_in(idx->buckets, idx->capacity, cookie);
    if (result) {
        atomic_fetch_add(&idx->hits, 1);
        return result;
    }

    /* Search old table if migrating */
    if (idx->old_buckets) {
        result = cookie_lookup_in(idx->old_buckets, idx->old_capacity, cookie);
        if (result) {
            atomic_fetch_add(&idx->hits, 1);
            return result;
        }
    }

    atomic_fetch_add(&idx->misses, 1);
    return NULL;
}

void cookie_index_remove(cookie_index_t *idx, uint64_t cookie) {
    if (!idx || !idx->buckets || cookie == COOKIE_SLOT_EMPTY ||
        cookie == COOKIE_SLOT_DELETED) {
        return;
    }

    /* Try active table */
    size_t start = hash_cookie(cookie) % idx->capacity;
    size_t pos = start;
    do {
        cookie_entry_t *entry = &idx->buckets[pos];
        if (entry->cookie == COOKIE_SLOT_EMPTY) {
            break;
        }
        if (entry->cookie == cookie) {
            entry->cookie = COOKIE_SLOT_DELETED;
            entry->ctx = NULL;
            atomic_fetch_sub(&idx->count, 1);
            return;
        }
        pos = (pos + 1) % idx->capacity;
    } while (pos != start);

    /* Try old table if migrating */
    if (idx->old_buckets) {
        start = hash_cookie(cookie) % idx->old_capacity;
        pos = start;
        do {
            cookie_entry_t *entry = &idx->old_buckets[pos];
            if (entry->cookie == COOKIE_SLOT_EMPTY) {
                return;
            }
            if (entry->cookie == cookie) {
                entry->cookie = COOKIE_SLOT_DELETED;
                entry->ctx = NULL;
                atomic_fetch_sub(&idx->count, 1);
                return;
            }
            pos = (pos + 1) % idx->old_capacity;
        } while (pos != start);
    }
}

/*============================================================================
 * Shadow Index Implementation
 *============================================================================*/

/*--- Shadow index: internal insert into a specific bucket array ---*/

static int shadow_insert_into(shadow_entry_t *buckets, size_t capacity,
                               uint32_t pid, uint64_t ssl_ctx,
                               flow_context_t *ctx) {
    size_t start = hash_shadow_key(pid, ssl_ctx) % capacity;
    size_t pos = start;

    do {
        shadow_entry_t *entry = &buckets[pos];

        if (entry->pid == SHADOW_SLOT_EMPTY) {
            entry->pid = pid;
            entry->ssl_ctx = ssl_ctx;
            entry->ctx = ctx;
            return 1;  /* New entry */
        }

        if (entry->pid == pid && entry->ssl_ctx == ssl_ctx) {
            entry->ctx = ctx;
            return 0;  /* Updated */
        }

        pos = (pos + 1) % capacity;
    } while (pos != start);

    return -1;  /* Table full */
}

/*--- Shadow index: internal lookup in a specific bucket array ---*/

static flow_context_t *shadow_lookup_in(shadow_entry_t *buckets, size_t capacity,
                                         uint32_t pid, uint64_t ssl_ctx) {
    size_t start = hash_shadow_key(pid, ssl_ctx) % capacity;
    size_t pos = start;

    do {
        shadow_entry_t *entry = &buckets[pos];

        if (entry->pid == SHADOW_SLOT_EMPTY) {
            return NULL;
        }

        if (entry->pid == pid && entry->ssl_ctx == ssl_ctx) {
            return entry->ctx;
        }

        pos = (pos + 1) % capacity;
    } while (pos != start);

    return NULL;
}

/*--- Shadow index: incremental migration ---*/

static void shadow_index_migrate_batch(shadow_index_t *idx, size_t batch) {
    if (__builtin_expect(!idx->old_buckets, 1)) {
        return;
    }

    size_t migrated = 0;
    while (migrated < batch && idx->migrate_pos < idx->old_capacity) {
        shadow_entry_t *src = &idx->old_buckets[idx->migrate_pos++];
        if (src->pid != SHADOW_SLOT_EMPTY) {
            shadow_insert_into(idx->buckets, idx->capacity,
                               src->pid, src->ssl_ctx, src->ctx);
            migrated++;
        }
    }

    if (idx->migrate_pos >= idx->old_capacity) {
        free(idx->old_buckets);
        idx->old_buckets = NULL;
        idx->old_capacity = 0;
        idx->migrate_pos = 0;
    }
}

/*--- Shadow index: grow (start migration) ---*/

static int shadow_index_grow(shadow_index_t *idx) {
    size_t new_capacity = idx->capacity * 2;

    shadow_entry_t *new_buckets = calloc(new_capacity, sizeof(shadow_entry_t));
    if (!new_buckets) {
        return -1;
    }

    /* pid=0 means empty (calloc already zeroed, SHADOW_SLOT_EMPTY == 0) */

    idx->old_buckets = idx->buckets;
    idx->old_capacity = idx->capacity;
    idx->migrate_pos = 0;

    idx->buckets = new_buckets;
    idx->capacity = new_capacity;

    return 0;
}

/*--- Shadow index: public API ---*/

int shadow_index_init(shadow_index_t *idx, size_t capacity) {
    if (!idx || capacity == 0) {
        return -1;
    }

    memset(idx, 0, sizeof(*idx));

    idx->buckets = calloc(capacity, sizeof(shadow_entry_t));
    if (!idx->buckets) {
        return -1;
    }

    idx->capacity = capacity;
    /* calloc zeroed everything; pid=0 (SHADOW_SLOT_EMPTY) marks empty slots */

    atomic_store(&idx->count, 0);
    atomic_store(&idx->hits, 0);
    atomic_store(&idx->promotions, 0);

    return 0;
}

void shadow_index_cleanup(shadow_index_t *idx) {
    if (!idx) {
        return;
    }
    free(idx->buckets);
    idx->buckets = NULL;
    free(idx->old_buckets);
    idx->old_buckets = NULL;
    idx->capacity = 0;
    idx->old_capacity = 0;
}

int shadow_index_insert(shadow_index_t *idx, uint32_t pid,
                        uint64_t ssl_ctx, flow_context_t *ctx) {
    if (!idx || !idx->buckets || pid == SHADOW_SLOT_EMPTY) {
        return -1;
    }

    /* Drive incremental migration */
    if (idx->old_buckets) {
        size_t batch = FLOW_INDEX_GROW_BATCH;
        if (atomic_load(&idx->count) * 4 >= idx->capacity * 3) {
            batch = FLOW_INDEX_GROW_BATCH * 4;
        }
        shadow_index_migrate_batch(idx, batch);
    }

    /* Check load factor */
    if (!idx->old_buckets &&
        atomic_load(&idx->count) * 4 >= idx->capacity * 3) {
        shadow_index_grow(idx);
    }

    /* Insert into active table */
    int result = shadow_insert_into(idx->buckets, idx->capacity,
                                     pid, ssl_ctx, ctx);
    if (result == 1) {
        atomic_fetch_add(&idx->count, 1);
    }
    return (result >= 0) ? 0 : -1;
}

flow_context_t *shadow_index_lookup(shadow_index_t *idx, uint32_t pid,
                                     uint64_t ssl_ctx) {
    if (!idx || !idx->buckets) {
        return NULL;
    }

    /* Drive migration */
    if (idx->old_buckets) {
        shadow_index_migrate_batch(idx, FLOW_INDEX_GROW_BATCH);
    }

    /* Search active table first */
    flow_context_t *result = shadow_lookup_in(idx->buckets, idx->capacity,
                                               pid, ssl_ctx);
    if (result) {
        atomic_fetch_add(&idx->hits, 1);
        return result;
    }

    /* Search old table if migrating */
    if (idx->old_buckets) {
        result = shadow_lookup_in(idx->old_buckets, idx->old_capacity,
                                   pid, ssl_ctx);
        if (result) {
            atomic_fetch_add(&idx->hits, 1);
            return result;
        }
    }

    return NULL;
}

void shadow_index_remove(shadow_index_t *idx, uint32_t pid, uint64_t ssl_ctx) {
    if (!idx || !idx->buckets) {
        return;
    }

    /* Remove from active table using backward-shift deletion */
    size_t start = hash_shadow_key(pid, ssl_ctx) % idx->capacity;
    size_t pos = start;

    do {
        shadow_entry_t *entry = &idx->buckets[pos];

        if (entry->pid == SHADOW_SLOT_EMPTY) {
            break;
        }

        if (entry->pid == pid && entry->ssl_ctx == ssl_ctx) {
            /* Found - clear slot and rehash subsequent entries */
            entry->pid = SHADOW_SLOT_EMPTY;
            entry->ssl_ctx = 0;
            entry->ctx = NULL;
            atomic_fetch_sub(&idx->count, 1);

            /* Backward-shift: rehash subsequent entries to maintain probe chain */
            size_t rehash_pos = (pos + 1) % idx->capacity;
            while (idx->buckets[rehash_pos].pid != SHADOW_SLOT_EMPTY) {
                shadow_entry_t tmp = idx->buckets[rehash_pos];
                idx->buckets[rehash_pos].pid = SHADOW_SLOT_EMPTY;
                idx->buckets[rehash_pos].ssl_ctx = 0;
                idx->buckets[rehash_pos].ctx = NULL;
                atomic_fetch_sub(&idx->count, 1);

                /* Re-insert (increments count back) */
                shadow_insert_into(idx->buckets, idx->capacity,
                                    tmp.pid, tmp.ssl_ctx, tmp.ctx);
                atomic_fetch_add(&idx->count, 1);

                rehash_pos = (rehash_pos + 1) % idx->capacity;
            }
            return;
        }

        pos = (pos + 1) % idx->capacity;
    } while (pos != start);

    /* Try old table if migrating */
    if (idx->old_buckets) {
        start = hash_shadow_key(pid, ssl_ctx) % idx->old_capacity;
        pos = start;

        do {
            shadow_entry_t *entry = &idx->old_buckets[pos];

            if (entry->pid == SHADOW_SLOT_EMPTY) {
                return;
            }

            if (entry->pid == pid && entry->ssl_ctx == ssl_ctx) {
                entry->pid = SHADOW_SLOT_EMPTY;
                entry->ssl_ctx = 0;
                entry->ctx = NULL;
                atomic_fetch_sub(&idx->count, 1);

                /* Backward-shift in old table */
                size_t rehash_pos = (pos + 1) % idx->old_capacity;
                while (idx->old_buckets[rehash_pos].pid != SHADOW_SLOT_EMPTY) {
                    shadow_entry_t tmp = idx->old_buckets[rehash_pos];
                    idx->old_buckets[rehash_pos].pid = SHADOW_SLOT_EMPTY;
                    idx->old_buckets[rehash_pos].ssl_ctx = 0;
                    idx->old_buckets[rehash_pos].ctx = NULL;
                    atomic_fetch_sub(&idx->count, 1);

                    shadow_insert_into(idx->old_buckets, idx->old_capacity,
                                        tmp.pid, tmp.ssl_ctx, tmp.ctx);
                    atomic_fetch_add(&idx->count, 1);

                    rehash_pos = (rehash_pos + 1) % idx->old_capacity;
                }
                return;
            }

            pos = (pos + 1) % idx->old_capacity;
        } while (pos != start);
    }
}

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

    /* Initialize cookie index with initial capacity */
    if (cookie_index_init(&mgr->cookie_idx, FLOW_INDEX_INITIAL_CAPACITY) != 0) {
        flow_pool_cleanup(&mgr->pool);
        return -1;
    }

    /* Initialize shadow index with initial capacity */
    if (shadow_index_init(&mgr->shadow_idx, FLOW_INDEX_INITIAL_CAPACITY) != 0) {
        cookie_index_cleanup(&mgr->cookie_idx);
        flow_pool_cleanup(&mgr->pool);
        return -1;
    }

    return 0;
}

void flow_manager_cleanup(flow_manager_t *mgr) {
    if (!mgr) {
        return;
    }

    shadow_index_cleanup(&mgr->shadow_idx);
    cookie_index_cleanup(&mgr->cookie_idx);
    flow_pool_cleanup(&mgr->pool);
}

flow_context_t *flow_lookup_ex(flow_manager_t *mgr, uint64_t cookie,
                               uint32_t pid, uint64_t ssl_ctx,
                               flow_lookup_path_t *path_out) {
    if (path_out) {
        *path_out = FLOW_PATH_NONE;
    }

    if (!mgr) {
        return NULL;
    }

    /* Try cookie_index first (fast path) */
    if (cookie != 0) {
        flow_context_t *ctx = cookie_index_lookup(&mgr->cookie_idx, cookie);
        if (ctx && atomic_load_explicit(&ctx->active, memory_order_acquire)) {
            /*
             * Verify the cookie-matched flow belongs to this connection.
             *
             * XDP-SSL Correlation: XDP events create flows with ssl_ctx=0.
             * When SSL events arrive with the same cookie, they should
             * MERGE into the XDP-created flow (filling in ssl_ctx and pid).
             */
            bool cookie_flow_valid = true;

            if (ssl_ctx != 0 && ctx->ssl_ctx != 0 && ctx->ssl_ctx != ssl_ctx) {
                cookie_flow_valid = false;
            }

            if (pid != 0 && ctx->pid != 0 && ctx->pid != pid) {
                cookie_flow_valid = false;
            }

            if (cookie_flow_valid) {
                /* Merge SSL data into XDP-only flow if needed */
                if (ctx->ssl_ctx == 0 && ssl_ctx != 0) {
                    ctx->ssl_ctx = ssl_ctx;
                    ctx->flags |= FLOW_FLAG_HAS_SSL;

                    /* Add to shadow_index for future SSL lookups */
                    if (pid != 0 && !(ctx->flags & FLOW_FLAG_IN_SHADOW)) {
                        if (shadow_index_insert(&mgr->shadow_idx, pid,
                                                ssl_ctx, ctx) == 0) {
                            ctx->flags |= FLOW_FLAG_IN_SHADOW;
                        }
                    }
                }
                if (ctx->pid == 0 && pid != 0) {
                    ctx->pid = pid;
                }
                if (path_out) {
                    *path_out = FLOW_PATH_COOKIE;
                }
                return ctx;
            }
        }
    }

    /* Fall back to shadow_index */
    if (pid != 0) {
        flow_context_t *ctx = shadow_index_lookup(&mgr->shadow_idx, pid, ssl_ctx);
        if (ctx && atomic_load_explicit(&ctx->active, memory_order_acquire)) {
            if (path_out) {
                *path_out = FLOW_PATH_SHADOW;
            }
            return ctx;
        }
    }

    return NULL;
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

    /* Add to shadow_index (always) */
    if (pid != 0) {
        if (shadow_index_insert(&mgr->shadow_idx, pid, ssl_ctx, ctx) == 0) {
            ctx->flags |= FLOW_FLAG_IN_SHADOW;
        }
    }

    /* Add to cookie_index if cookie known */
    if (cookie != 0) {
        if (cookie_index_insert(&mgr->cookie_idx, cookie, ctx) == 0) {
            ctx->flags |= FLOW_FLAG_IN_COOKIE;
        }
    }

    return ctx;
}

int flow_promote_cookie(flow_manager_t *mgr, uint32_t pid,
                        uint64_t ssl_ctx, uint64_t cookie) {
    if (!mgr || cookie == 0) {
        return -1;
    }

    /* Find flow by shadow key */
    flow_context_t *ctx = shadow_index_lookup(&mgr->shadow_idx, pid, ssl_ctx);
    if (!ctx || !atomic_load_explicit(&ctx->active, memory_order_acquire)) {
        return -1;
    }

    /* Check if already promoted */
    if (ctx->socket_cookie != 0) {
        return 0;
    }

    /* Update cookie and add to cookie_index */
    ctx->socket_cookie = cookie;
    if (cookie_index_insert(&mgr->cookie_idx, cookie, ctx) == 0) {
        ctx->flags |= FLOW_FLAG_IN_COOKIE;
        atomic_fetch_add(&mgr->shadow_idx.promotions, 1);
    }

    return 0;
}

void flow_terminate(flow_manager_t *mgr, flow_context_t *ctx) {
    if (!mgr || !ctx) {
        return;
    }

    /* Remove from cookie_index if present */
    if ((ctx->flags & FLOW_FLAG_IN_COOKIE) && ctx->socket_cookie != 0) {
        cookie_index_remove(&mgr->cookie_idx, ctx->socket_cookie);
    }

    /* Remove from shadow_index if present */
    if ((ctx->flags & FLOW_FLAG_IN_SHADOW) && ctx->pid != 0) {
        shadow_index_remove(&mgr->shadow_idx, ctx->pid, ctx->ssl_ctx);
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

    /* Update counters based on direction */
    if (evt->direction == 1) {  /* Ingress */
        ctx->pkts_in++;
        ctx->bytes_in += evt->pkt_len;
    } else {  /* Egress */
        ctx->pkts_out++;
        ctx->bytes_out += evt->pkt_len;
    }

    /* Interface info */
    ctx->ifindex = evt->ifindex;
    ctx->xdp_category = evt->category;
    ctx->flags |= FLOW_FLAG_HAS_XDP;

    /* Update state if we have both views */
    if ((ctx->flags & FLOW_FLAG_HAS_SSL) && ctx->state == FLOW_STATE_INIT) {
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
    ctx->parser.h2.reassembly_buf = malloc(ctx->parser.h2.reassembly_capacity);
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

    if (ctx->flags & FLOW_FLAG_PARSER_INIT) {
        return 0;
    }

    strncpy(ctx->alpn, alpn, sizeof(ctx->alpn) - 1);
    ctx->alpn[sizeof(ctx->alpn) - 1] = '\0';

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

    ctx->flags |= FLOW_FLAG_PARSER_INIT;
    return 0;
}

void flow_free_resources(flow_context_t *ctx) {
    if (!ctx) {
        return;
    }

    if (ctx->proto == FLOW_PROTO_HTTP2) {
        for (int32_t i = 0; i < FLOW_MAX_H2_STREAMS; i++) {
            flow_txn_free_body(&ctx->parser.h2.streams[i]);
        }

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
    } else if (ctx->proto == FLOW_PROTO_HTTP1) {
        flow_txn_free_body(&ctx->parser.h1.txn);
    }

    if (ctx->body.buffer) {
        free(ctx->body.buffer);
        ctx->body.buffer = NULL;
    }

    ctx->state = FLOW_STATE_CLOSED;
    ctx->flags = 0;
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

    txn->body_buf = malloc(capacity);
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
}

void flow_manager_print_stats(flow_manager_t *mgr, bool debug_mode) {
    /* No-op: stats printing is centralized in main.c print_shutdown_stats() */
    (void)mgr;
    (void)debug_mode;
}
