/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * ck_cookie_index.c - Thread-safe SPMC cookie index implementation
 *
 * Uses Concurrency Kit's ck_hs (hash set) for lock-free SPMC access.
 * All entries are cache-line aligned for optimal performance.
 */

#include "ck_cookie_index.h"
#include <stdlib.h>
#include <string.h>
#include <stdalign.h>

/*============================================================================
 * CK Memory Allocator
 *============================================================================*/

/**
 * @brief Cache-line aligned allocation for ck_hs
 */
static void *ck_cookie_malloc(size_t size) {
    /* Round up to cache line boundary */
    size_t aligned_size = (size + 63) & ~(size_t)63;
    return aligned_alloc(64, aligned_size);
}

/**
 * @brief Free for ck_hs allocations
 */
static void ck_cookie_free(void *ptr, size_t size, bool defer) {
    (void)size;
    (void)defer;
    free(ptr);
}

static struct ck_malloc cookie_allocator = {
    .malloc = ck_cookie_malloc,
    .free = ck_cookie_free
};

/*============================================================================
 * Hash and Compare Functions
 *============================================================================*/

/**
 * @brief FNV-1a hash for socket cookie
 *
 * Uses 64-bit FNV-1a for good distribution across hash table buckets.
 */
static unsigned long cookie_hash(const void *key, unsigned long seed) {
    const ck_cookie_entry_t *entry = key;
    uint64_t h = 14695981039346656037ULL ^ seed;
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
    const ck_cookie_entry_t *ea = a;
    const ck_cookie_entry_t *eb = b;
    return ea->cookie == eb->cookie;
}

/*============================================================================
 * API Implementation
 *============================================================================*/

int ck_cookie_index_init(ck_cookie_index_t *idx, size_t capacity) {
    if (!idx || capacity == 0) {
        return -1;
    }

    memset(idx, 0, sizeof(*idx));

    /*
     * Initialize ck_hs with:
     * - CK_HS_MODE_OBJECT: Store pointers to entry objects
     * - CK_HS_MODE_SPMC: Single-producer multiple-consumer safety
     */
    if (!ck_hs_init(&idx->hs,
                    CK_HS_MODE_OBJECT | CK_HS_MODE_SPMC,
                    cookie_hash,
                    cookie_compare,
                    &cookie_allocator,
                    capacity,
                    0 /* seed */)) {
        return -1;
    }

    atomic_store_explicit(&idx->count, 0, memory_order_relaxed);
    atomic_store_explicit(&idx->hits, 0, memory_order_relaxed);
    atomic_store_explicit(&idx->misses, 0, memory_order_relaxed);

    return 0;
}

void ck_cookie_index_cleanup(ck_cookie_index_t *idx) {
    if (!idx) {
        return;
    }

    /*
     * Iterate through all entries and free them.
     * Note: We do NOT free flow_context_t* - that's the pool's job.
     */
    ck_hs_iterator_t iterator = CK_HS_ITERATOR_INITIALIZER;
    void *entry_ptr;

    while (ck_hs_next(&idx->hs, &iterator, &entry_ptr)) {
        ck_cookie_entry_t *entry = entry_ptr;
        free(entry);
    }

    ck_hs_destroy(&idx->hs);
}

int ck_cookie_index_insert(ck_cookie_index_t *idx, uint64_t cookie,
                           flow_context_t *ctx) {
    if (!idx) {
        return -1;
    }

    /* Allocate entry (cache-line aligned, size must be multiple of alignment) */
    size_t alloc_size = (sizeof(ck_cookie_entry_t) + 63) & ~(size_t)63;
    ck_cookie_entry_t *entry = aligned_alloc(64, alloc_size);
    if (!entry) {
        return -1;
    }

    entry->cookie = cookie;
    entry->ctx = ctx;

    /* Compute hash for this entry */
    unsigned long hash = cookie_hash(entry, 0);

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

void ck_cookie_index_remove(ck_cookie_index_t *idx, uint64_t cookie) {
    if (!idx) {
        return;
    }

    /* Create a probe entry for lookup */
    ck_cookie_entry_t probe = { .cookie = cookie, .ctx = NULL };
    unsigned long hash = cookie_hash(&probe, 0);

    void *removed = ck_hs_remove(&idx->hs, hash, &probe);
    if (removed) {
        free(removed);
        atomic_fetch_sub_explicit(&idx->count, 1, memory_order_relaxed);
    }
}

flow_context_t *ck_cookie_index_lookup(ck_cookie_index_t *idx, uint64_t cookie) {
    if (!idx) {
        return NULL;
    }

    /* Create a probe entry for lookup */
    ck_cookie_entry_t probe = { .cookie = cookie, .ctx = NULL };
    unsigned long hash = cookie_hash(&probe, 0);

    void *found = ck_hs_get(&idx->hs, hash, &probe);
    if (found) {
        ck_cookie_entry_t *entry = found;
        atomic_fetch_add_explicit(&idx->hits, 1, memory_order_relaxed);
        return entry->ctx;
    }

    atomic_fetch_add_explicit(&idx->misses, 1, memory_order_relaxed);
    return NULL;
}
