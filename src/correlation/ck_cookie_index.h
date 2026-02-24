/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * ck_cookie_index.h - Thread-safe SPMC cookie index using CK hs
 *
 * This module provides a lock-free hash set for socket_cookie → flow_context_t*
 * mapping using Concurrency Kit's ck_hs. The data structure supports:
 *
 *   - Single-Producer: Only dispatcher thread performs writes (insert/remove)
 *   - Multiple-Consumer: Workers can safely lookup during writes/resize
 *   - Lock-free: No mutexes, uses atomic operations and memory barriers
 *   - Cache-aligned: 64-byte alignment for optimal cache performance
 *
 * @par Thread Safety Model (SPMC)
 * CK hs only supports Single-Producer Multiple-Consumer access patterns.
 * All write operations (insert, remove) MUST be performed by the dispatcher
 * thread. Worker threads may only call lookup operations.
 *
 * @see flow_context.h for the flow manager that uses this index
 */

#ifndef CK_COOKIE_INDEX_H
#define CK_COOKIE_INDEX_H

#include "../include/spliff.h"  /* For C23 nullptr compatibility */
#include <ck_hs.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

/* Forward declaration */
typedef struct flow_context flow_context_t;

/*============================================================================
 * Types
 *============================================================================*/

/**
 * @brief Cookie index entry stored in ck_hs
 *
 * Each entry maps a socket_cookie to a flow_context_t pointer.
 * The cookie serves as the hash key.
 */
typedef struct {
    uint64_t cookie;            /**< Socket cookie (hash key) */
    flow_context_t *ctx;        /**< Flow context pointer (value) */
} ck_cookie_entry_t;

/**
 * @brief Thread-safe cookie index using CK hs
 *
 * Wraps ck_hs with statistics counters and provides a clean API
 * for the flow manager to use.
 */
typedef struct {
    ck_hs_t hs;                 /**< CK hash set (SPMC safe) */
    _Atomic uint64_t count;     /**< Active entry count */
    _Atomic uint64_t hits;      /**< Successful lookups */
    _Atomic uint64_t misses;    /**< Failed lookups */
} ck_cookie_index_t;

/*============================================================================
 * API Functions
 *============================================================================*/

/**
 * @brief Initialize cookie index
 *
 * Allocates the ck_hs with the given initial capacity.
 *
 * @param[out] idx       Index to initialize
 * @param[in]  capacity  Initial number of buckets (will grow as needed)
 * @return 0 on success, -1 on failure
 */
int ck_cookie_index_init(ck_cookie_index_t *idx, size_t capacity);

/**
 * @brief Cleanup cookie index
 *
 * Frees all entry allocations and the ck_hs.
 * Does NOT free the flow_context_t pointers stored in entries.
 *
 * @param[in] idx  Index to cleanup
 */
void ck_cookie_index_cleanup(ck_cookie_index_t *idx);

/**
 * @brief Insert entry into cookie index (dispatcher only)
 *
 * @warning Single-writer: MUST only be called from dispatcher thread
 *
 * If an entry with the same cookie already exists, it is replaced.
 *
 * @param[in] idx     The index
 * @param[in] cookie  Socket cookie (key)
 * @param[in] ctx     Flow context pointer (value)
 * @return 0 on success, -1 on failure
 */
int ck_cookie_index_insert(ck_cookie_index_t *idx, uint64_t cookie,
                           flow_context_t *ctx);

/**
 * @brief Remove entry from cookie index (dispatcher only)
 *
 * @warning Single-writer: MUST only be called from dispatcher thread
 *
 * @param[in] idx     The index
 * @param[in] cookie  Socket cookie to remove
 */
void ck_cookie_index_remove(ck_cookie_index_t *idx, uint64_t cookie);

/**
 * @brief Lookup entry in cookie index (multi-reader safe)
 *
 * Safe to call from any thread concurrently with other lookups
 * and with single-writer operations.
 *
 * @param[in] idx     The index
 * @param[in] cookie  Socket cookie to find
 * @return flow_context_t pointer, or NULL if not found
 */
flow_context_t *ck_cookie_index_lookup(ck_cookie_index_t *idx, uint64_t cookie);

/**
 * @brief Get entry count
 *
 * @param[in] idx  The index
 * @return Number of entries in the index
 */
static inline uint64_t ck_cookie_index_count(ck_cookie_index_t *idx) {
    return atomic_load_explicit(&idx->count, memory_order_relaxed);
}

/**
 * @brief Get hit count (successful lookups)
 *
 * @param[in] idx  The index
 * @return Number of successful lookups
 */
static inline uint64_t ck_cookie_index_hits(ck_cookie_index_t *idx) {
    return atomic_load_explicit(&idx->hits, memory_order_relaxed);
}

/**
 * @brief Get miss count (failed lookups)
 *
 * @param[in] idx  The index
 * @return Number of failed lookups
 */
static inline uint64_t ck_cookie_index_misses(ck_cookie_index_t *idx) {
    return atomic_load_explicit(&idx->misses, memory_order_relaxed);
}

#endif /* CK_COOKIE_INDEX_H */
