/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * flow_context.c - Shared Pool Architecture Implementation
 *
 * Implements the "Shared Pool with Dual Index" architecture for XDP-SSL
 * correlation. All flow contexts live in a single pre-allocated pool,
 * indexed by two hash tables for O(1) lookup.
 *
 * @see flow_context.h for API documentation
 * @see docs/SHARED_POOL_ARCHITECTURE.md for design details
 */

#include "flow_context.h"
#include "../protocol/http2.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*============================================================================
 * Hash Functions
 *============================================================================*/

/**
 * @brief FNV-1a hash for socket_cookie
 *
 * Fast, well-distributed hash for 64-bit values.
 * FNV-1a chosen for its simplicity and good avalanche properties.
 */
static inline uint64_t hash_cookie(uint64_t cookie) {
    uint64_t hash = 14695981039346656037ULL;  /* FNV offset basis */
    hash ^= cookie;
    hash *= 1099511628211ULL;                  /* FNV prime */
    hash ^= (cookie >> 32);
    hash *= 1099511628211ULL;
    return hash;
}

/**
 * @brief FNV-1a hash for (pid, ssl_ctx) pair
 *
 * Combines both values into a single hash, ensuring different
 * (pid, ssl_ctx) pairs produce different hash values.
 */
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

/*============================================================================
 * Flow Pool Implementation
 *============================================================================*/

int flow_pool_init(flow_pool_t *pool, size_t capacity) {
    if (!pool || capacity == 0 || capacity > FLOW_POOL_CAPACITY) {
        return -1;
    }

    memset(pool, 0, sizeof(*pool));

    /* Allocate cache-aligned slot array */
    size_t alloc_size = capacity * sizeof(flow_context_t);
    pool->slots = aligned_alloc(64, alloc_size);
    if (!pool->slots) {
        return -1;
    }

    memset(pool->slots, 0, alloc_size);
    pool->capacity = capacity;

    /* Initialize free bitmap: all bits = 1 (all slots free) */
    size_t bitmap_words = (capacity + 63) / 64;
    for (size_t i = 0; i < bitmap_words; i++) {
        pool->free_bitmap[i] = ~0ULL;
    }

    /* Clear trailing bits if capacity not multiple of 64 */
    size_t remainder = capacity % 64;
    if (remainder > 0 && bitmap_words > 0) {
        pool->free_bitmap[bitmap_words - 1] = (1ULL << remainder) - 1;
    }

    /* Initialize statistics */
    atomic_store(&pool->allocated, 0);
    atomic_store(&pool->peak, 0);
    atomic_store(&pool->total_allocs, 0);
    atomic_store(&pool->total_frees, 0);

    return 0;
}

void flow_pool_cleanup(flow_pool_t *pool) {
    if (!pool || !pool->slots) {
        return;
    }

    /* Free resources for all active slots */
    for (size_t i = 0; i < pool->capacity; i++) {
        flow_context_t *ctx = &pool->slots[i];
        if (atomic_load_explicit(&ctx->active, memory_order_acquire)) {
            flow_free_resources(ctx);
        }
    }

    free(pool->slots);
    pool->slots = NULL;
    pool->capacity = 0;
}

flow_id_t flow_pool_alloc(flow_pool_t *pool) {
    if (!pool || !pool->slots) {
        return FLOW_ID_INVALID;
    }

    size_t bitmap_words = (pool->capacity + 63) / 64;

    /* Find first word with a free bit using __builtin_ctzll */
    for (size_t word = 0; word < bitmap_words; word++) {
        if (pool->free_bitmap[word] != 0) {
            /* Found a word with free slots */
            int bit = __builtin_ctzll(pool->free_bitmap[word]);
            flow_id_t id = (flow_id_t)(word * 64 + bit);

            /* Bounds check */
            if (id >= pool->capacity) {
                return FLOW_ID_INVALID;
            }

            /* Mark slot as used (clear bit) */
            pool->free_bitmap[word] &= ~(1ULL << bit);

            /* Initialize slot */
            flow_context_t *ctx = &pool->slots[id];
            memset(ctx, 0, sizeof(*ctx));
            ctx->self_id = id;
            ctx->state = FLOW_STATE_INIT;
            ctx->proto = FLOW_PROTO_UNKNOWN;
            atomic_store_explicit(&ctx->home_worker_id, WORKER_ID_NONE,
                                  memory_order_relaxed);
            atomic_store_explicit(&ctx->active, true, memory_order_release);

            /* Update statistics */
            uint64_t count = atomic_fetch_add(&pool->allocated, 1) + 1;
            uint64_t peak = atomic_load(&pool->peak);
            while (count > peak) {
                if (atomic_compare_exchange_weak(&pool->peak, &peak, count)) {
                    break;
                }
            }
            atomic_fetch_add(&pool->total_allocs, 1);

            return id;
        }
    }

    /* Pool is full */
    return FLOW_ID_INVALID;
}

void flow_pool_free(flow_pool_t *pool, flow_id_t id) {
    if (!pool || !pool->slots || id >= pool->capacity) {
        return;
    }

    flow_context_t *ctx = &pool->slots[id];

    /* Check if actually allocated */
    if (!atomic_load_explicit(&ctx->active, memory_order_acquire)) {
        return;  /* Already free */
    }

    /* Free internal resources */
    flow_free_resources(ctx);

    /* Mark as inactive */
    atomic_store_explicit(&ctx->active, false, memory_order_release);

    /* Return to free bitmap */
    size_t word = id / 64;
    int bit = id % 64;
    pool->free_bitmap[word] |= (1ULL << bit);

    /* Update statistics */
    atomic_fetch_sub(&pool->allocated, 1);
    atomic_fetch_add(&pool->total_frees, 1);
}

/*============================================================================
 * Cookie Index Implementation
 *============================================================================*/

/** Empty slot marker (cookie=0 is valid for "unknown") */
#define COOKIE_SLOT_EMPTY   UINT64_MAX
#define COOKIE_SLOT_DELETED (UINT64_MAX - 1)

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

    /* Mark all slots as empty */
    for (size_t i = 0; i < capacity; i++) {
        idx->buckets[i].cookie = COOKIE_SLOT_EMPTY;
        idx->buckets[i].id = FLOW_ID_INVALID;
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
    idx->capacity = 0;
}

int cookie_index_insert(cookie_index_t *idx, uint64_t cookie, flow_id_t id) {
    if (!idx || !idx->buckets || cookie == COOKIE_SLOT_EMPTY ||
        cookie == COOKIE_SLOT_DELETED) {
        return -1;
    }

    size_t start = hash_cookie(cookie) % idx->capacity;
    size_t pos = start;

    /* Linear probing */
    do {
        cookie_entry_t *entry = &idx->buckets[pos];

        if (entry->cookie == COOKIE_SLOT_EMPTY ||
            entry->cookie == COOKIE_SLOT_DELETED) {
            /* Found empty slot */
            entry->cookie = cookie;
            entry->id = id;
            atomic_fetch_add(&idx->count, 1);
            return 0;
        }

        if (entry->cookie == cookie) {
            /* Already exists - update */
            entry->id = id;
            return 0;
        }

        pos = (pos + 1) % idx->capacity;
    } while (pos != start);

    /* Table full */
    return -1;
}

flow_id_t cookie_index_lookup(cookie_index_t *idx, uint64_t cookie) {
    if (!idx || !idx->buckets || cookie == COOKIE_SLOT_EMPTY ||
        cookie == COOKIE_SLOT_DELETED) {
        return FLOW_ID_INVALID;
    }

    size_t start = hash_cookie(cookie) % idx->capacity;
    size_t pos = start;

    /* Linear probing */
    do {
        cookie_entry_t *entry = &idx->buckets[pos];

        if (entry->cookie == COOKIE_SLOT_EMPTY) {
            /* Empty slot = not found */
            atomic_fetch_add(&idx->misses, 1);
            return FLOW_ID_INVALID;
        }

        if (entry->cookie == cookie) {
            /* Found */
            atomic_fetch_add(&idx->hits, 1);
            return entry->id;
        }

        /* Skip deleted slots and continue probing */
        pos = (pos + 1) % idx->capacity;
    } while (pos != start);

    atomic_fetch_add(&idx->misses, 1);
    return FLOW_ID_INVALID;
}

void cookie_index_remove(cookie_index_t *idx, uint64_t cookie) {
    if (!idx || !idx->buckets || cookie == COOKIE_SLOT_EMPTY ||
        cookie == COOKIE_SLOT_DELETED) {
        return;
    }

    size_t start = hash_cookie(cookie) % idx->capacity;
    size_t pos = start;

    /* Linear probing */
    do {
        cookie_entry_t *entry = &idx->buckets[pos];

        if (entry->cookie == COOKIE_SLOT_EMPTY) {
            /* Not found */
            return;
        }

        if (entry->cookie == cookie) {
            /* Found - mark as deleted (tombstone) */
            entry->cookie = COOKIE_SLOT_DELETED;
            entry->id = FLOW_ID_INVALID;
            atomic_fetch_sub(&idx->count, 1);
            return;
        }

        pos = (pos + 1) % idx->capacity;
    } while (pos != start);
}

/*============================================================================
 * Shadow Index Implementation
 *============================================================================*/

/** Empty slot marker for shadow index */
#define SHADOW_SLOT_EMPTY   0

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

    /* Initialize all slots (pid=0 means empty) */
    for (size_t i = 0; i < capacity; i++) {
        idx->buckets[i].pid = SHADOW_SLOT_EMPTY;
        idx->buckets[i].ssl_ctx = 0;
        idx->buckets[i].id = FLOW_ID_INVALID;
    }

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
    idx->capacity = 0;
}

int shadow_index_insert(shadow_index_t *idx, uint32_t pid,
                        uint64_t ssl_ctx, flow_id_t id) {
    if (!idx || !idx->buckets || pid == SHADOW_SLOT_EMPTY) {
        return -1;
    }

    size_t start = hash_shadow_key(pid, ssl_ctx) % idx->capacity;
    size_t pos = start;

    /* Linear probing */
    do {
        shadow_entry_t *entry = &idx->buckets[pos];

        if (entry->pid == SHADOW_SLOT_EMPTY) {
            /* Found empty slot */
            entry->pid = pid;
            entry->ssl_ctx = ssl_ctx;
            entry->id = id;
            atomic_fetch_add(&idx->count, 1);
            return 0;
        }

        if (entry->pid == pid && entry->ssl_ctx == ssl_ctx) {
            /* Already exists - update */
            entry->id = id;
            return 0;
        }

        pos = (pos + 1) % idx->capacity;
    } while (pos != start);

    /* Table full */
    return -1;
}

flow_id_t shadow_index_lookup(shadow_index_t *idx, uint32_t pid,
                              uint64_t ssl_ctx) {
    if (!idx || !idx->buckets) {
        return FLOW_ID_INVALID;
    }

    size_t start = hash_shadow_key(pid, ssl_ctx) % idx->capacity;
    size_t pos = start;

    /* Linear probing */
    do {
        shadow_entry_t *entry = &idx->buckets[pos];

        if (entry->pid == SHADOW_SLOT_EMPTY) {
            /* Empty slot = not found */
            return FLOW_ID_INVALID;
        }

        if (entry->pid == pid && entry->ssl_ctx == ssl_ctx) {
            /* Found */
            atomic_fetch_add(&idx->hits, 1);
            return entry->id;
        }

        pos = (pos + 1) % idx->capacity;
    } while (pos != start);

    return FLOW_ID_INVALID;
}

void shadow_index_remove(shadow_index_t *idx, uint32_t pid, uint64_t ssl_ctx) {
    if (!idx || !idx->buckets) {
        return;
    }

    size_t start = hash_shadow_key(pid, ssl_ctx) % idx->capacity;
    size_t pos = start;

    /* Linear probing with rehashing on delete */
    do {
        shadow_entry_t *entry = &idx->buckets[pos];

        if (entry->pid == SHADOW_SLOT_EMPTY) {
            /* Not found */
            return;
        }

        if (entry->pid == pid && entry->ssl_ctx == ssl_ctx) {
            /* Found - clear slot and rehash subsequent entries */
            entry->pid = SHADOW_SLOT_EMPTY;
            entry->ssl_ctx = 0;
            entry->id = FLOW_ID_INVALID;
            atomic_fetch_sub(&idx->count, 1);

            /* Rehash subsequent entries to maintain probe chain */
            size_t rehash_pos = (pos + 1) % idx->capacity;
            while (idx->buckets[rehash_pos].pid != SHADOW_SLOT_EMPTY) {
                shadow_entry_t tmp = idx->buckets[rehash_pos];
                idx->buckets[rehash_pos].pid = SHADOW_SLOT_EMPTY;
                idx->buckets[rehash_pos].ssl_ctx = 0;
                idx->buckets[rehash_pos].id = FLOW_ID_INVALID;
                atomic_fetch_sub(&idx->count, 1);

                /* Re-insert */
                shadow_index_insert(idx, tmp.pid, tmp.ssl_ctx, tmp.id);

                rehash_pos = (rehash_pos + 1) % idx->capacity;
            }
            return;
        }

        pos = (pos + 1) % idx->capacity;
    } while (pos != start);
}

/*============================================================================
 * Flow Manager Implementation
 *============================================================================*/

int flow_manager_init(flow_manager_t *mgr) {
    if (!mgr) {
        return -1;
    }

    memset(mgr, 0, sizeof(*mgr));

    /* Initialize pool */
    if (flow_pool_init(&mgr->pool, FLOW_POOL_CAPACITY) != 0) {
        return -1;
    }

    /* Initialize cookie index (same capacity as pool) */
    if (cookie_index_init(&mgr->cookie_idx, FLOW_POOL_CAPACITY) != 0) {
        flow_pool_cleanup(&mgr->pool);
        return -1;
    }

    /* Initialize shadow index (same capacity as pool) */
    if (shadow_index_init(&mgr->shadow_idx, FLOW_POOL_CAPACITY) != 0) {
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

    flow_id_t id = FLOW_ID_INVALID;

    /* Try cookie_index first (fast path) */
    if (cookie != 0) {
        id = cookie_index_lookup(&mgr->cookie_idx, cookie);
        if (id != FLOW_ID_INVALID) {
            flow_context_t *ctx = flow_pool_get(&mgr->pool, id);
            if (ctx && atomic_load_explicit(&ctx->active, memory_order_acquire)) {
                /*
                 * Verify the cookie-matched flow belongs to this connection.
                 *
                 * XDP-SSL Correlation: XDP events create flows with ssl_ctx=0.
                 * When SSL events arrive with the same cookie, they should
                 * MERGE into the XDP-created flow (filling in ssl_ctx and pid).
                 *
                 * Validation rules:
                 * - XDP-only flow (ssl_ctx=0): Valid for SSL events (will be merged)
                 * - SSL flow with matching ssl_ctx: Valid
                 * - SSL flow with different ssl_ctx: Invalid (different connection)
                 * - PID mismatch (both non-zero): Invalid (different process)
                 */
                bool cookie_flow_valid = true;

                if (ssl_ctx != 0 && ctx->ssl_ctx != 0 && ctx->ssl_ctx != ssl_ctx) {
                    /* Both have ssl_ctx but they don't match - different connection */
                    cookie_flow_valid = false;
                }

                if (pid != 0 && ctx->pid != 0 && ctx->pid != pid) {
                    /* PID mismatch - this flow belongs to different process */
                    cookie_flow_valid = false;
                }

                if (cookie_flow_valid) {
                    /* Merge SSL data into XDP-only flow if needed */
                    if (ctx->ssl_ctx == 0 && ssl_ctx != 0) {
                        ctx->ssl_ctx = ssl_ctx;
                        ctx->flags |= FLOW_FLAG_HAS_SSL;

                        /* Add to shadow_index for future SSL lookups */
                        if (pid != 0 && !(ctx->flags & FLOW_FLAG_IN_SHADOW)) {
                            if (shadow_index_insert(&mgr->shadow_idx, pid, ssl_ctx, id) == 0) {
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
                /* Cookie matched but flow doesn't belong to us - fall through to shadow */
            }
        }
    }

    /* Fall back to shadow_index */
    if (pid != 0) {
        id = shadow_index_lookup(&mgr->shadow_idx, pid, ssl_ctx);
        if (id != FLOW_ID_INVALID) {
            flow_context_t *ctx = flow_pool_get(&mgr->pool, id);
            if (ctx && atomic_load_explicit(&ctx->active, memory_order_acquire)) {
                if (path_out) {
                    *path_out = FLOW_PATH_SHADOW;
                }
                return ctx;
            }
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

    /* Allocate new slot */
    flow_id_t id = flow_pool_alloc(&mgr->pool);
    if (id == FLOW_ID_INVALID) {
        return NULL;  /* Pool full */
    }

    ctx = flow_pool_get(&mgr->pool, id);
    if (!ctx) {
        return NULL;  /* Should not happen */
    }

    /* Initialize identity fields */
    ctx->socket_cookie = cookie;
    ctx->pid = pid;
    ctx->ssl_ctx = ssl_ctx;

    /* Add to shadow_index (always) */
    if (pid != 0) {
        if (shadow_index_insert(&mgr->shadow_idx, pid, ssl_ctx, id) == 0) {
            ctx->flags |= FLOW_FLAG_IN_SHADOW;
        }
    }

    /* Add to cookie_index if cookie known */
    if (cookie != 0) {
        if (cookie_index_insert(&mgr->cookie_idx, cookie, id) == 0) {
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
    flow_id_t id = shadow_index_lookup(&mgr->shadow_idx, pid, ssl_ctx);
    if (id == FLOW_ID_INVALID) {
        return -1;
    }

    flow_context_t *ctx = flow_pool_get(&mgr->pool, id);
    if (!ctx || !atomic_load_explicit(&ctx->active, memory_order_acquire)) {
        return -1;
    }

    /* Check if already promoted */
    if (ctx->socket_cookie != 0) {
        return 0;  /* Already has cookie */
    }

    /* Update cookie and add to cookie_index */
    ctx->socket_cookie = cookie;
    if (cookie_index_insert(&mgr->cookie_idx, cookie, id) == 0) {
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

    /* Free slot back to pool */
    flow_pool_free(&mgr->pool, ctx->self_id);
}

int flow_evict_stale(flow_manager_t *mgr, uint64_t current_ns) {
    if (!mgr) {
        return 0;
    }

    int evicted = 0;

    for (size_t i = 0; i < mgr->pool.capacity; i++) {
        flow_context_t *ctx = &mgr->pool.slots[i];

        if (!atomic_load_explicit(&ctx->active, memory_order_acquire)) {
            continue;
        }

        /* Check if stale */
        if (current_ns - ctx->last_seen_ns > FLOW_TIMEOUT_NS) {
            flow_terminate(mgr, ctx);
            evicted++;
        }
    }

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

    /* Already initialized? */
    if (ctx->parser.h2.session != NULL) {
        return 0;
    }

    int rv;
    nghttp2_option *opt = NULL;

    /* Create options for passive sniffing */
    rv = nghttp2_option_new(&opt);
    if (rv != 0) {
        return -1;
    }

    /*
     * Critical for passive sniffing:
     * - Skip client magic (24-byte preface) - we detect it separately
     * - Disable auto WINDOW_UPDATE - we're not actual endpoints
     */
    nghttp2_option_set_no_recv_client_magic(opt, 1);
    nghttp2_option_set_no_auto_window_update(opt, 1);

    /* Create server session (parses client requests) */
    rv = nghttp2_session_server_new2(&ctx->parser.h2.session, cbs, user, opt);
    nghttp2_option_del(opt);

    if (rv != 0) {
        return -1;
    }

    /* Create HPACK inflater for response headers */
    rv = nghttp2_hd_inflate_new(&ctx->parser.h2.inflater);
    if (rv != 0) {
        nghttp2_session_del(ctx->parser.h2.session);
        ctx->parser.h2.session = NULL;
        return -1;
    }

    /* Allocate reassembly buffer */
    ctx->parser.h2.reassembly_capacity = 65536;  /* H2_REASSEMBLY_BUF_SIZE */
    ctx->parser.h2.reassembly_buf = malloc(ctx->parser.h2.reassembly_capacity);
    if (!ctx->parser.h2.reassembly_buf) {
        nghttp2_hd_inflate_del(ctx->parser.h2.inflater);
        nghttp2_session_del(ctx->parser.h2.session);
        ctx->parser.h2.inflater = NULL;
        ctx->parser.h2.session = NULL;
        return -1;
    }
    ctx->parser.h2.reassembly_len = 0;

    /*
     * Drain initial SETTINGS frame that nghttp2 queues on session creation.
     * This puts the session in proper state before receiving peer data.
     */
    for (;;) {
        const uint8_t *send_data;
        ssize_t send_len = nghttp2_session_mem_send(ctx->parser.h2.session,
                                                     &send_data);
        if (send_len <= 0) break;
    }

    /* Initialize the stream pool with free list */
    flow_h2_init_stream_pool(ctx);

    return 0;
}

int flow_h1_parser_init(flow_context_t *ctx, llhttp_settings_t *settings) {
    if (!ctx || ctx->proto != FLOW_PROTO_HTTP1) {
        return -1;
    }

    /* Already initialized? */
    if (ctx->parser.h1.initialized) {
        return 0;
    }

    if (!settings) {
        /* No settings provided - initialize with empty settings (no callbacks) */
        llhttp_settings_init(&ctx->parser.h1.settings);
    } else {
        /* Copy the provided settings (contains callback pointers) */
        memcpy(&ctx->parser.h1.settings, settings, sizeof(llhttp_settings_t));
    }

    /* Initialize the parser with HTTP_BOTH for auto-detection */
    llhttp_init(&ctx->parser.h1.parser, HTTP_BOTH, &ctx->parser.h1.settings);

    ctx->parser.h1.initialized = true;
    return 0;
}

int flow_init_parser(flow_context_t *ctx, const char *alpn) {
    if (!ctx || !alpn) {
        return -1;
    }

    /* Don't re-initialize */
    if (ctx->flags & FLOW_FLAG_PARSER_INIT) {
        return 0;
    }

    strncpy(ctx->alpn, alpn, sizeof(ctx->alpn) - 1);
    ctx->alpn[sizeof(ctx->alpn) - 1] = '\0';

    if (strcmp(alpn, "h2") == 0) {
        /*
         * HTTP/2 - defer full session initialization to home worker.
         * Call flow_h2_session_init() when first H2 data arrives.
         */
        ctx->proto = FLOW_PROTO_HTTP2;
        ctx->parser.h2.session = NULL;
        ctx->parser.h2.inflater = NULL;
        ctx->parser.h2.reassembly_buf = NULL;
        ctx->parser.h2.reassembly_len = 0;
        ctx->parser.h2.reassembly_capacity = 0;
        ctx->parser.h2.preface_seen = false;
        ctx->parser.h2.settings_seen = false;

    } else if (strcmp(alpn, "http/1.1") == 0 || strcmp(alpn, "http/1.0") == 0) {
        /*
         * HTTP/1.x - defer full initialization to home worker.
         * Call flow_h1_parser_init() when first H1 data arrives.
         * This ensures the parser uses the global callbacks from http1.c
         * rather than empty settings.
         */
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

    /* Free protocol-specific resources */
    if (ctx->proto == FLOW_PROTO_HTTP2) {
        /* Free all stream body buffers */
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
        /* Free callback context (Phase 3.6 migration) */
        if (ctx->parser.h2.callback_ctx) {
            http2_free_callback_ctx(ctx->parser.h2.callback_ctx);
            ctx->parser.h2.callback_ctx = NULL;
        }
    } else if (ctx->proto == FLOW_PROTO_HTTP1) {
        /* Free HTTP/1 transaction body buffer */
        flow_txn_free_body(&ctx->parser.h1.txn);
    }

    /* Free body assembly buffer (legacy - may be removed) */
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

#include <time.h>  /* For clock_gettime */

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

    /* Link all slots into free list */
    for (int32_t i = 0; i < FLOW_MAX_H2_STREAMS - 1; i++) {
        h2->streams[i].stream_id = 0;
        h2->streams[i].state = TXN_STATE_IDLE;
        h2->streams[i].flags = 0;
        h2->streams[i].body_buf = NULL;
        h2->streams[i].body_len = 0;
        h2->streams[i].body_capacity = 0;
        h2->streams[i].next_free = i + 1;
    }
    /* Last slot points to -1 (end of list) */
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

    /* Check if pool exhausted */
    if (h2->free_head < 0) {
        return NULL;
    }

    /* Pop from free list - O(1) */
    int32_t slot = h2->free_head;
    flow_transaction_t *txn = &h2->streams[slot];
    h2->free_head = txn->next_free;
    h2->active_count++;

    /* Initialize transaction */
    memset(txn, 0, sizeof(*txn));
    txn->stream_id = stream_id;
    txn->state = TXN_STATE_IDLE;
    txn->last_active_ms = flow_get_monotonic_ms();
    txn->next_free = -1;  /* Not in free list */

    return txn;
}

flow_transaction_t *flow_h2_find_stream(flow_context_t *ctx, int32_t stream_id) {
    if (!ctx || ctx->proto != FLOW_PROTO_HTTP2 || stream_id <= 0) {
        return NULL;
    }

    h2_parser_ctx_t *h2 = &ctx->parser.h2;

    /* Linear search - acceptable for 64 slots */
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

    /* Free body buffer if allocated */
    flow_txn_free_body(txn);

    /* Reset state */
    txn->stream_id = 0;
    txn->state = TXN_STATE_IDLE;
    txn->flags = 0;
    txn->status_code = 0;
    txn->content_length = 0;
    txn->method[0] = '\0';
    txn->path[0] = '\0';
    txn->host[0] = '\0';
    txn->content_type[0] = '\0';

    /* Push back to free list - O(1) */
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

        /* Skip free slots */
        if (txn->state == TXN_STATE_IDLE) {
            continue;
        }

        /* Check timeout */
        uint32_t age_ms = current_ms - txn->last_active_ms;
        if (age_ms > FLOW_STREAM_TIMEOUT_MS) {
            /* Ghost stream - free it */
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

    /* Free body buffer if allocated */
    flow_txn_free_body(txn);

    /* Reset transaction state but keep stream_id at 0 */
    txn->state = TXN_STATE_IDLE;
    txn->flags = 0;
    txn->status_code = 0;
    txn->content_length = 0;
    txn->method[0] = '\0';
    txn->path[0] = '\0';
    txn->host[0] = '\0';
    txn->content_type[0] = '\0';
    txn->last_active_ms = flow_get_monotonic_ms();

    /* Reset llhttp parser for next message */
    if (ctx->parser.h1.initialized) {
        llhttp_reset(&ctx->parser.h1.parser);
    }
}

int flow_txn_alloc_body(flow_transaction_t *txn, size_t capacity) {
    if (!txn) {
        return -1;
    }

    /* Already allocated? */
    if (txn->body_buf) {
        return 0;
    }

    /* Use minimum capacity */
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
        return 0;  /* Nothing to do */
    }

    /* Allocate if not already */
    if (!txn->body_buf) {
        if (flow_txn_alloc_body(txn, len * 2) != 0) {
            return -1;
        }
    }

    /* Grow if needed */
    if (txn->body_len + len > txn->body_capacity) {
        size_t new_capacity = txn->body_capacity * 2;
        if (new_capacity < txn->body_len + len) {
            new_capacity = txn->body_len + len + 4096;
        }

        /* Cap at reasonable maximum (256KB per transaction) */
        if (new_capacity > 256 * 1024) {
            new_capacity = 256 * 1024;
            if (txn->body_len + len > new_capacity) {
                /* Truncate - can't grow anymore */
                len = new_capacity - txn->body_len;
                if (len == 0) {
                    return 0;  /* Buffer full */
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
    stats->pool_capacity = mgr->pool.capacity;
    stats->pool_allocated = atomic_load(&mgr->pool.allocated);
    stats->pool_peak = atomic_load(&mgr->pool.peak);
    stats->pool_total_allocs = atomic_load(&mgr->pool.total_allocs);
    stats->pool_total_frees = atomic_load(&mgr->pool.total_frees);

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
    if (!mgr) {
        return;
    }

    flow_pool_stats_t stats;
    flow_manager_get_stats(mgr, &stats);

    fprintf(stderr, "\n=== Flow Pool Statistics ===\n");

    /* Pool utilization */
    double util_pct = stats.pool_capacity > 0
        ? 100.0 * stats.pool_allocated / stats.pool_capacity
        : 0.0;
    double peak_pct = stats.pool_capacity > 0
        ? 100.0 * stats.pool_peak / stats.pool_capacity
        : 0.0;

    fprintf(stderr, "Pool: %lu/%lu active (%.1f%%), peak %lu (%.1f%%)\n",
            stats.pool_allocated, stats.pool_capacity, util_pct,
            stats.pool_peak, peak_pct);

    /* Lifetime stats */
    fprintf(stderr, "Lifetime: %lu allocs, %lu frees\n",
            stats.pool_total_allocs, stats.pool_total_frees);

    /* Index statistics (debug mode) */
    if (debug_mode) {
        fprintf(stderr, "\n--- Index Statistics ---\n");

        /* Cookie index */
        uint64_t cookie_total = stats.cookie_hits + stats.cookie_misses;
        double cookie_hit_rate = cookie_total > 0
            ? 100.0 * stats.cookie_hits / cookie_total
            : 0.0;
        fprintf(stderr, "Cookie index: %lu entries, %lu hits (%.1f%%), %lu misses\n",
                stats.cookie_count, stats.cookie_hits, cookie_hit_rate,
                stats.cookie_misses);

        /* Shadow index */
        fprintf(stderr, "Shadow index: %lu entries, %lu hits, %lu promotions\n",
                stats.shadow_count, stats.shadow_hits, stats.shadow_promotions);

        /* Promotion rate - how often we go from shadow to cookie */
        if (stats.pool_total_allocs > 0) {
            double promo_rate = 100.0 * stats.shadow_promotions / stats.pool_total_allocs;
            fprintf(stderr, "XDP correlation: %.1f%% of flows got socket_cookie\n",
                    promo_rate);
        }
    }
}
