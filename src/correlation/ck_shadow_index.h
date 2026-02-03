/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * ck_shadow_index.h - Thread-safe SPMC shadow index using CK hs
 *
 * This module provides a lock-free hash set for (pid, ssl_ctx) → flow_context_t*
 * mapping using Concurrency Kit's ck_hs. The shadow index is used as a fallback
 * when socket_cookie is not yet known (early SSL events).
 *
 * @par Thread Safety Model (SPMC)
 * CK hs only supports Single-Producer Multiple-Consumer access patterns.
 * All write operations (insert, remove) MUST be performed by the dispatcher
 * thread. Worker threads may only call lookup operations.
 *
 * @see flow_context.h for the flow manager that uses this index
 * @see ck_cookie_index.h for the primary cookie-based index
 */

#ifndef CK_SHADOW_INDEX_H
#define CK_SHADOW_INDEX_H

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
 * @brief Shadow index entry stored in ck_hs
 *
 * Each entry maps a (pid, ssl_ctx) pair to a flow_context_t pointer.
 * The composite key is used when socket_cookie is not yet known.
 */
typedef struct {
    uint32_t pid;               /**< Process ID (key part 1) */
    uint32_t _pad;              /**< Padding for alignment */
    uint64_t ssl_ctx;           /**< SSL context pointer (key part 2) */
    flow_context_t *ctx;        /**< Flow context pointer (value) */
} ck_shadow_entry_t;

/**
 * @brief Secondary index entry for O(1) cookie lookup (FIX M7)
 *
 * Maps socket_cookie → flow_context_t* for fast lookup by cookie.
 * This eliminates the O(n) scan in ck_shadow_find_by_cookie().
 */
typedef struct {
    uint64_t cookie;            /**< Socket cookie (key) */
    flow_context_t *ctx;        /**< Flow context pointer (value) */
} ck_shadow_cookie_entry_t;

/**
 * @brief Thread-safe shadow index using CK hs
 *
 * Wraps ck_hs with statistics counters and provides a clean API
 * for the flow manager to use.
 *
 * @par Dual Indexing (FIX M7)
 * Contains two hash sets:
 * - `hs`: Primary index keyed by (pid, ssl_ctx) composite key
 * - `by_cookie`: Secondary index keyed by socket_cookie for O(1) lookup
 *
 * The secondary index is populated only when a flow has a valid
 * socket_cookie (cookie != 0), enabling fast deduplication during
 * XDP-SSL merge without O(n) scanning.
 */
typedef struct {
    ck_hs_t hs;                     /**< Primary: (pid, ssl_ctx) → flow_context */
    ck_hs_t by_cookie;              /**< Secondary: socket_cookie → flow_context (FIX M7) */
    _Atomic uint64_t count;         /**< Active entry count (primary index) */
    _Atomic uint64_t hits;          /**< Successful lookups */
    _Atomic uint64_t promotions;    /**< Flows promoted to cookie_index */
    _Atomic uint64_t merges;        /**< XDP flows merged into SSL flows */
    _Atomic uint64_t cookie_index_count;  /**< Secondary index entry count */
} ck_shadow_index_t;

/*============================================================================
 * API Functions
 *============================================================================*/

/**
 * @brief Initialize shadow index
 *
 * Allocates the ck_hs with the given initial capacity.
 *
 * @param[out] idx       Index to initialize
 * @param[in]  capacity  Initial number of buckets (will grow as needed)
 * @return 0 on success, -1 on failure
 */
int ck_shadow_index_init(ck_shadow_index_t *idx, size_t capacity);

/**
 * @brief Cleanup shadow index
 *
 * Frees all entry allocations and the ck_hs.
 * Does NOT free the flow_context_t pointers stored in entries.
 *
 * @param[in] idx  Index to cleanup
 */
void ck_shadow_index_cleanup(ck_shadow_index_t *idx);

/**
 * @brief Insert entry into shadow index (dispatcher only)
 *
 * @warning Single-writer: MUST only be called from dispatcher thread
 *
 * If an entry with the same (pid, ssl_ctx) already exists, it is replaced.
 *
 * @param[in] idx      The index
 * @param[in] pid      Process ID (key part 1)
 * @param[in] ssl_ctx  SSL context pointer (key part 2)
 * @param[in] ctx      Flow context pointer (value)
 * @return 0 on success, -1 on failure
 */
int ck_shadow_index_insert(ck_shadow_index_t *idx, uint32_t pid,
                           uint64_t ssl_ctx, flow_context_t *ctx);

/**
 * @brief Remove entry from shadow index (dispatcher only)
 *
 * @warning Single-writer: MUST only be called from dispatcher thread
 *
 * @param[in] idx      The index
 * @param[in] pid      Process ID (key part 1)
 * @param[in] ssl_ctx  SSL context pointer (key part 2)
 */
void ck_shadow_index_remove(ck_shadow_index_t *idx, uint32_t pid,
                            uint64_t ssl_ctx);

/**
 * @brief Lookup entry in shadow index (multi-reader safe)
 *
 * Safe to call from any thread concurrently with other lookups
 * and with single-writer operations.
 *
 * @param[in] idx      The index
 * @param[in] pid      Process ID (key part 1)
 * @param[in] ssl_ctx  SSL context pointer (key part 2)
 * @return flow_context_t pointer, or NULL if not found
 */
flow_context_t *ck_shadow_index_lookup(ck_shadow_index_t *idx, uint32_t pid,
                                       uint64_t ssl_ctx);

/**
 * @brief Find flow in shadow index by socket_cookie (dispatcher only)
 *
 * FIX M7: Now O(1) via secondary cookie index instead of O(n) scan.
 * This handles the race where SSL promoted a flow to cookie_index,
 * but XDP event arrives and would create a duplicate.
 *
 * @param[in] idx     The shadow index
 * @param[in] cookie  Socket cookie to search for
 * @return flow_context_t pointer, or NULL if not found
 */
flow_context_t *ck_shadow_find_by_cookie(ck_shadow_index_t *idx, uint64_t cookie);

/**
 * @brief Update secondary cookie index when flow gets a cookie
 *
 * Called when a flow in the shadow index acquires a socket_cookie
 * (via SSL→XDP correlation). This enables O(1) lookup by cookie.
 *
 * @warning Single-writer: MUST only be called from dispatcher thread
 *
 * @param[in] idx     The shadow index
 * @param[in] cookie  Socket cookie to index
 * @param[in] ctx     Flow context pointer to associate
 * @return 0 on success, -1 on failure
 */
int ck_shadow_index_add_cookie(ck_shadow_index_t *idx, uint64_t cookie,
                                flow_context_t *ctx);

/**
 * @brief Remove entry from secondary cookie index
 *
 * Called when removing a flow from the shadow index to keep both
 * indexes consistent.
 *
 * @warning Single-writer: MUST only be called from dispatcher thread
 *
 * @param[in] idx     The shadow index
 * @param[in] cookie  Socket cookie to remove
 */
void ck_shadow_index_remove_cookie(ck_shadow_index_t *idx, uint64_t cookie);

/**
 * @brief Get entry count
 *
 * @param[in] idx  The index
 * @return Number of entries in the index
 */
static inline uint64_t ck_shadow_index_count(ck_shadow_index_t *idx) {
    return atomic_load_explicit(&idx->count, memory_order_relaxed);
}

/**
 * @brief Get hit count (successful lookups)
 *
 * @param[in] idx  The index
 * @return Number of successful lookups
 */
static inline uint64_t ck_shadow_index_hits(ck_shadow_index_t *idx) {
    return atomic_load_explicit(&idx->hits, memory_order_relaxed);
}

/**
 * @brief Get promotion count (flows promoted to cookie_index)
 *
 * @param[in] idx  The index
 * @return Number of promotions
 */
static inline uint64_t ck_shadow_index_promotions(ck_shadow_index_t *idx) {
    return atomic_load_explicit(&idx->promotions, memory_order_relaxed);
}

/**
 * @brief Get merge count (XDP flows merged into SSL flows)
 *
 * @param[in] idx  The index
 * @return Number of merges
 */
static inline uint64_t ck_shadow_index_merges(ck_shadow_index_t *idx) {
    return atomic_load_explicit(&idx->merges, memory_order_relaxed);
}

/**
 * @brief Increment promotion counter
 *
 * @param[in] idx  The index
 */
static inline void ck_shadow_index_inc_promotions(ck_shadow_index_t *idx) {
    atomic_fetch_add_explicit(&idx->promotions, 1, memory_order_relaxed);
}

/**
 * @brief Increment merge counter
 *
 * @param[in] idx  The index
 */
static inline void ck_shadow_index_inc_merges(ck_shadow_index_t *idx) {
    atomic_fetch_add_explicit(&idx->merges, 1, memory_order_relaxed);
}

#endif /* CK_SHADOW_INDEX_H */
