/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * ck_shadow_index.c - Thread-safe SPMC shadow index implementation
 *
 * Uses Concurrency Kit's ck_hs (hash set) for lock-free SPMC access.
 * All entries are cache-line aligned for optimal performance.
 *
 * FIX H5/M9: Integrates liburcu for safe deferred memory reclamation.
 * When CK passes defer=true, we use call_rcu() to delay the free
 * until all readers have completed their critical sections.
 */

#include "ck_shadow_index.h"
#include "flow_context.h"
#include <stdlib.h>
#include <string.h>
#include <stdalign.h>

/*
 * liburcu for safe deferred memory reclamation (FIX H5/M9)
 *
 * We use the urcu-memb flavor (memory barriers) for RCU synchronization.
 * The call_rcu() API requires liburcu-cds library for the call-rcu thread.
 *
 * _LGPL_SOURCE enables static inline optimizations for RCU read-side.
 * We use explicit urcu_memb_call_rcu() to avoid macro expansion issues.
 */
#define _LGPL_SOURCE
#define RCU_MEMBARRIER
#include <urcu/urcu-memb.h>
#include <urcu/call-rcu.h>

/*============================================================================
 * RCU Deferred Free Support (FIX H5/M9)
 *============================================================================*/

/**
 * @brief RCU callback structure for deferred free
 */
typedef struct {
    struct rcu_head rcu_head;  /**< liburcu callback header */
    void *ptr;                 /**< Pointer to free */
} ck_shadow_rcu_free_t;

/**
 * @brief RCU callback to perform deferred free
 */
static void ck_shadow_rcu_free_callback(struct rcu_head *head) {
    ck_shadow_rcu_free_t *rcu_free = caa_container_of(head, ck_shadow_rcu_free_t, rcu_head);
    free(rcu_free->ptr);
    free(rcu_free);
}

/*============================================================================
 * CK Memory Allocator
 *============================================================================*/

/**
 * @brief Cache-line aligned allocation for ck_hs
 */
static void *ck_shadow_malloc(size_t size) {
    /* Round up to cache line boundary */
    size_t aligned_size = (size + 63) & ~(size_t)63;
    return aligned_alloc(64, aligned_size);
}

/**
 * @brief Free for ck_hs allocations with RCU-safe deferred free
 *
 * FIX H5/M9: When defer=true, use liburcu's urcu_memb_call_rcu() to defer free.
 * Using explicit flavor-prefixed name to avoid macro expansion issues.
 */
static void ck_shadow_free(void *ptr, size_t size, bool defer) {
    (void)size;

    if (!defer || ptr == nullptr) {
        free(ptr);
        return;
    }

    /* Deferred free via liburcu urcu_memb_call_rcu() */
    ck_shadow_rcu_free_t *rcu_free = malloc(sizeof(*rcu_free));
    if (rcu_free) {
        rcu_free->ptr = ptr;
        urcu_memb_call_rcu(&rcu_free->rcu_head, ck_shadow_rcu_free_callback);
    } else {
        free(ptr);  /* Fallback: immediate free if OOM */
    }
}

static struct ck_malloc shadow_allocator = {
    .malloc = ck_shadow_malloc,
    .free = ck_shadow_free
};

/*============================================================================
 * Hash and Compare Functions
 *============================================================================*/

/**
 * @brief FNV-1a hash for (pid, ssl_ctx) composite key
 *
 * Combines both parts of the key for good distribution.
 */
static unsigned long shadow_hash(const void *key, unsigned long seed) {
    const ck_shadow_entry_t *entry = key;
    uint64_t h = 14695981039346656037ULL ^ seed;

    /* Hash pid */
    h ^= entry->pid;
    h *= 1099511628211ULL;

    /* Hash ssl_ctx (both halves) */
    h ^= entry->ssl_ctx;
    h *= 1099511628211ULL;
    h ^= (entry->ssl_ctx >> 32);
    h *= 1099511628211ULL;

    return (unsigned long)h;
}

/**
 * @brief Compare two shadow entries for equality
 *
 * Both pid AND ssl_ctx must match for equality.
 */
static bool shadow_compare(const void *a, const void *b) {
    const ck_shadow_entry_t *ea = a;
    const ck_shadow_entry_t *eb = b;
    return ea->pid == eb->pid && ea->ssl_ctx == eb->ssl_ctx;
}

/*============================================================================
 * Secondary Cookie Index Hash/Compare (FIX M7)
 *============================================================================*/

/**
 * @brief FNV-1a hash for socket_cookie
 */
static unsigned long cookie_hash(const void *key, unsigned long seed) {
    const ck_shadow_cookie_entry_t *entry = key;
    uint64_t h = 14695981039346656037ULL ^ seed;

    /* Hash cookie (both halves) */
    h ^= entry->cookie;
    h *= 1099511628211ULL;
    h ^= (entry->cookie >> 32);
    h *= 1099511628211ULL;

    return (unsigned long)h;
}

/**
 * @brief Compare two cookie entries for equality
 */
static bool cookie_compare(const void *a, const void *b) {
    const ck_shadow_cookie_entry_t *ea = a;
    const ck_shadow_cookie_entry_t *eb = b;
    return ea->cookie == eb->cookie;
}

/*============================================================================
 * API Implementation
 *============================================================================*/

int ck_shadow_index_init(ck_shadow_index_t *idx, size_t capacity) {
    if (!idx || capacity == 0) {
        return -1;
    }

    memset(idx, 0, sizeof(*idx));

    /*
     * Initialize primary ck_hs with:
     * - CK_HS_MODE_OBJECT: Store pointers to entry objects
     * - CK_HS_MODE_SPMC: Single-producer multiple-consumer safety
     */
    if (!ck_hs_init(&idx->hs,
                    CK_HS_MODE_OBJECT | CK_HS_MODE_SPMC,
                    shadow_hash,
                    shadow_compare,
                    &shadow_allocator,
                    capacity,
                    0 /* seed */)) {
        return -1;
    }

    /*
     * FIX M7: Initialize secondary cookie index for O(1) lookup by cookie.
     * Uses same capacity as primary index - most flows will eventually get cookies.
     */
    if (!ck_hs_init(&idx->by_cookie,
                    CK_HS_MODE_OBJECT | CK_HS_MODE_SPMC,
                    cookie_hash,
                    cookie_compare,
                    &shadow_allocator,
                    capacity,
                    0 /* seed */)) {
        ck_hs_destroy(&idx->hs);
        return -1;
    }

    atomic_store_explicit(&idx->count, 0, memory_order_relaxed);
    atomic_store_explicit(&idx->hits, 0, memory_order_relaxed);
    atomic_store_explicit(&idx->promotions, 0, memory_order_relaxed);
    atomic_store_explicit(&idx->merges, 0, memory_order_relaxed);
    atomic_store_explicit(&idx->cookie_index_count, 0, memory_order_relaxed);

    return 0;
}

void ck_shadow_index_cleanup(ck_shadow_index_t *idx) {
    if (!idx) {
        return;
    }

    /*
     * Iterate through primary index entries and free them.
     * Note: We do NOT free flow_context_t* - that's the pool's job.
     */
    ck_hs_iterator_t iterator = CK_HS_ITERATOR_INITIALIZER;
    void *entry_ptr;

    while (ck_hs_next(&idx->hs, &iterator, &entry_ptr)) {
        ck_shadow_entry_t *entry = entry_ptr;
        free(entry);
    }

    ck_hs_destroy(&idx->hs);

    /*
     * FIX M7: Cleanup secondary cookie index entries
     */
    iterator = (ck_hs_iterator_t)CK_HS_ITERATOR_INITIALIZER;
    while (ck_hs_next(&idx->by_cookie, &iterator, &entry_ptr)) {
        ck_shadow_cookie_entry_t *entry = entry_ptr;
        free(entry);
    }

    ck_hs_destroy(&idx->by_cookie);
}

int ck_shadow_index_insert(ck_shadow_index_t *idx, uint32_t pid,
                           uint64_t ssl_ctx, flow_context_t *ctx) {
    if (!idx) {
        return -1;
    }

    /* Allocate entry (cache-line aligned, size must be multiple of alignment) */
    size_t alloc_size = (sizeof(ck_shadow_entry_t) + 63) & ~(size_t)63;
    ck_shadow_entry_t *entry = aligned_alloc(64, alloc_size);
    if (!entry) {
        return -1;
    }

    entry->pid = pid;
    entry->_pad = 0;
    entry->ssl_ctx = ssl_ctx;
    entry->ctx = ctx;

    /* Compute hash for this entry */
    unsigned long hash = shadow_hash(entry, 0);

    /*
     * Try to insert uniquely first. ck_hs_put_unique returns:
     * - true if new entry was inserted (no existing key)
     * - false if entry with same key already exists
     */
    if (ck_hs_put_unique(&idx->hs, hash, entry)) {
        /* New entry inserted successfully */
        atomic_fetch_add_explicit(&idx->count, 1, memory_order_relaxed);
        return 0;
    }

    /*
     * Key already exists - use ck_hs_set to replace it.
     * ck_hs_set stores the previous value via the 4th argument.
     */
    void *prev = NULL;
    if (ck_hs_set(&idx->hs, hash, entry, &prev)) {
        if (prev != NULL) {
            /* Free the old entry (not the flow_context, just the wrapper) */
            free(prev);
        }
        /* Replaced existing entry - count stays the same */
        return 0;
    }

    /* ck_hs_set failed (shouldn't happen normally) */
    free(entry);
    return -1;
}

void ck_shadow_index_remove(ck_shadow_index_t *idx, uint32_t pid,
                            uint64_t ssl_ctx) {
    if (!idx) {
        return;
    }

    /* Create a probe entry for lookup */
    ck_shadow_entry_t probe = {
        .pid = pid,
        ._pad = 0,
        .ssl_ctx = ssl_ctx,
        .ctx = NULL
    };
    unsigned long hash = shadow_hash(&probe, 0);

    void *removed = ck_hs_remove(&idx->hs, hash, &probe);
    if (removed) {
        free(removed);
        atomic_fetch_sub_explicit(&idx->count, 1, memory_order_relaxed);
    }
}

flow_context_t *ck_shadow_index_lookup(ck_shadow_index_t *idx, uint32_t pid,
                                       uint64_t ssl_ctx) {
    if (!idx) {
        return NULL;
    }

    /* Create a probe entry for lookup */
    ck_shadow_entry_t probe = {
        .pid = pid,
        ._pad = 0,
        .ssl_ctx = ssl_ctx,
        .ctx = NULL
    };
    unsigned long hash = shadow_hash(&probe, 0);

    void *found = ck_hs_get(&idx->hs, hash, &probe);
    if (found) {
        ck_shadow_entry_t *entry = found;
        atomic_fetch_add_explicit(&idx->hits, 1, memory_order_relaxed);
        return entry->ctx;
    }

    return NULL;
}

flow_context_t *ck_shadow_find_by_cookie(ck_shadow_index_t *idx, uint64_t cookie) {
    if (!idx || cookie == 0) {
        return NULL;
    }

    /*
     * FIX M7: O(1) lookup via secondary cookie index instead of O(n) scan.
     * This dramatically improves performance for XDP-SSL deduplication.
     */
    ck_shadow_cookie_entry_t probe = {
        .cookie = cookie,
        .ctx = NULL
    };
    unsigned long hash = cookie_hash(&probe, 0);

    void *found = ck_hs_get(&idx->by_cookie, hash, &probe);
    if (found) {
        ck_shadow_cookie_entry_t *entry = found;
        atomic_fetch_add_explicit(&idx->hits, 1, memory_order_relaxed);
        return entry->ctx;
    }

    return NULL;
}

int ck_shadow_index_add_cookie(ck_shadow_index_t *idx, uint64_t cookie,
                                flow_context_t *ctx) {
    if (!idx || cookie == 0 || !ctx) {
        return -1;
    }

    /* Allocate cookie entry (cache-line aligned) */
    size_t alloc_size = (sizeof(ck_shadow_cookie_entry_t) + 63) & ~(size_t)63;
    ck_shadow_cookie_entry_t *entry = aligned_alloc(64, alloc_size);
    if (!entry) {
        return -1;
    }

    entry->cookie = cookie;
    entry->ctx = ctx;

    unsigned long hash = cookie_hash(entry, 0);

    /* Try unique insert first */
    if (ck_hs_put_unique(&idx->by_cookie, hash, entry)) {
        atomic_fetch_add_explicit(&idx->cookie_index_count, 1, memory_order_relaxed);
        return 0;
    }

    /* Cookie already exists - replace it */
    void *prev = NULL;
    if (ck_hs_set(&idx->by_cookie, hash, entry, &prev)) {
        if (prev != NULL) {
            free(prev);
        }
        return 0;
    }

    free(entry);
    return -1;
}

void ck_shadow_index_remove_cookie(ck_shadow_index_t *idx, uint64_t cookie) {
    if (!idx || cookie == 0) {
        return;
    }

    ck_shadow_cookie_entry_t probe = {
        .cookie = cookie,
        .ctx = NULL
    };
    unsigned long hash = cookie_hash(&probe, 0);

    void *removed = ck_hs_remove(&idx->by_cookie, hash, &probe);
    if (removed) {
        free(removed);
        atomic_fetch_sub_explicit(&idx->cookie_index_count, 1, memory_order_relaxed);
    }
}
