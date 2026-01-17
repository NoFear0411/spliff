/**
 * @file pool.c
 * @brief Lock-free object pool implementation
 *
 * @details Uses CK ring buffer as a free-list for O(1) alloc/free.
 * Pre-allocates all objects at initialization time to avoid malloc
 * in the hot path during event processing.
 *
 * @par Memory Layout:
 * @code
 *   pool->base ─────────────────────────────────┐
 *                                               │
 *   ┌─────────┬─────────┬─────────┬─────────┐   │
 *   │ Object 0│ Object 1│ Object 2│ Object N│   │ Contiguous allocation
 *   │ 64-byte │ 64-byte │ 64-byte │ 64-byte │   │ (cache-line aligned)
 *   │ aligned │ aligned │ aligned │ aligned │   │
 *   └─────────┴─────────┴─────────┴─────────┘   │
 *                                               │
 *   pool->ring (CK ring buffer) ◄───────────────┘
 *       │
 *       └── Free-list: pointers to available objects
 * @endcode
 *
 * @par Thread Safety:
 * - pool_alloc: SPSC dequeue (single consumer per worker)
 * - pool_free: SPSC enqueue (single producer per worker)
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "threading.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/**
 * @brief Initialize object pool with pre-allocated storage
 *
 * Allocates a contiguous block of cache-line aligned objects and
 * pushes them all onto the free-list ring buffer.
 *
 * @par Capacity Adjustment:
 * The capacity is rounded up to the next power of 2 as required
 * by CK ring buffer. The ring is sized to hold one more element
 * than the actual capacity to avoid the empty/full ambiguity.
 *
 * @par Object Alignment:
 * Objects are aligned to 64-byte cache lines to prevent false
 * sharing when objects from the same pool are accessed by different
 * threads (though our design typically has one pool per worker).
 */
int pool_init(object_pool_t *pool, size_t obj_size, size_t capacity) {
    if (!pool || obj_size == 0 || capacity == 0) {
        return -1;
    }

    memset(pool, 0, sizeof(*pool));

    /* Round capacity to next power of 2 (required by ck_ring)
     * Note: CK ring can hold (capacity - 1) elements, so we need capacity > requested */
    size_t rounded_capacity = 1;
    while (rounded_capacity <= capacity) {  /* Use <= to ensure room for all objects */
        rounded_capacity <<= 1;
    }

    /* Align object size to cache line (64 bytes) */
    size_t aligned_size = (obj_size + 63) & ~63UL;

    pool->obj_size = aligned_size;
    pool->capacity = capacity;  /* Store actual capacity, not ring size */

    /* Allocate ring buffer for free-list
     * CK ring needs (capacity + 1) entries for SPSC
     * Note: aligned_alloc requires size to be a multiple of alignment */
    size_t ring_buf_size = sizeof(ck_ring_buffer_t) * (rounded_capacity + 1);
    ring_buf_size = (ring_buf_size + 63) & ~(size_t)63;  /* Round up to 64-byte boundary */
    pool->ring_buf = aligned_alloc(64, ring_buf_size);
    if (!pool->ring_buf) {
        fprintf(stderr, "pool_init: failed to allocate ring buffer\n");
        return -1;
    }

    /* Initialize CK ring */
    ck_ring_init(&pool->ring, rounded_capacity);

    /* Allocate object storage
     * Note: aligned_alloc requires size to be a multiple of alignment */
    size_t obj_storage_size = aligned_size * capacity;
    obj_storage_size = (obj_storage_size + 63) & ~(size_t)63;  /* Round up to 64-byte boundary */
    pool->base = aligned_alloc(64, obj_storage_size);
    if (!pool->base) {
        fprintf(stderr, "pool_init: failed to allocate object storage\n");
        free(pool->ring_buf);
        pool->ring_buf = NULL;
        return -1;
    }

    /* Zero-initialize all objects */
    memset(pool->base, 0, aligned_size * capacity);

    /* Push all objects onto free-list */
    for (size_t i = 0; i < capacity; i++) {
        void *obj = (char *)pool->base + (i * aligned_size);
        /* Use SPSC enqueue since we're the only producer during init */
        if (!ck_ring_enqueue_spsc(&pool->ring, pool->ring_buf, obj)) {
            fprintf(stderr, "pool_init: failed to enqueue object %zu\n", i);
            free(pool->base);
            free(pool->ring_buf);
            pool->base = NULL;
            pool->ring_buf = NULL;
            return -1;
        }
    }

    atomic_store(&pool->alloc_count, 0);
    atomic_store(&pool->free_count, 0);
    atomic_store(&pool->alloc_failures, 0);

    return 0;
}

/**
 * @brief Destroy object pool and free all memory
 *
 * Frees the ring buffer and object storage. Does not track or
 * complain about unreturned objects (caller's responsibility).
 */
void pool_destroy(object_pool_t *pool) {
    if (!pool) {
        return;
    }

    if (pool->base) {
        free(pool->base);
        pool->base = NULL;
    }

    if (pool->ring_buf) {
        free(pool->ring_buf);
        pool->ring_buf = NULL;
    }

    pool->obj_size = 0;
    pool->capacity = 0;
}

/**
 * @brief Allocate object from pool (lock-free)
 *
 * Dequeues an object pointer from the free-list ring buffer.
 * The object memory was zero-initialized when last freed.
 *
 * @note Uses SPSC (single-producer single-consumer) dequeue since
 *       each worker has its own pool and is the sole consumer.
 *
 * @note On failure (pool empty), increments alloc_failures counter
 *       for diagnostic purposes.
 */
void *pool_alloc(object_pool_t *pool) {
    if (!pool || !pool->ring_buf) {
        return NULL;
    }

    void *obj = NULL;

    /* SPSC dequeue - single consumer per worker */
    if (ck_ring_dequeue_spsc(&pool->ring, pool->ring_buf, &obj)) {
        atomic_fetch_add(&pool->alloc_count, 1);
        return obj;
    }

    /* Pool empty */
    atomic_fetch_add(&pool->alloc_failures, 1);
    return NULL;
}

/**
 * @brief Return object to pool (lock-free)
 *
 * Validates the object belongs to this pool, zero-clears it for
 * security and debugging, then enqueues it back to the free-list.
 *
 * @par Validation Checks:
 * - Object pointer within pool's base allocation
 * - Object pointer properly aligned to obj_size boundary
 *
 * @par Security Note:
 * Zero-clearing prevents sensitive data (like SSL plaintext) from
 * persisting in reused objects. Also helps catch use-after-free bugs.
 *
 * @warning Attempting to free an object not from this pool will
 *          print an error and return without action.
 */
void pool_free(object_pool_t *pool, void *obj) {
    if (!pool || !pool->ring_buf || !obj) {
        return;
    }

    /* Verify object belongs to this pool */
    uintptr_t base = (uintptr_t)pool->base;
    uintptr_t ptr = (uintptr_t)obj;
    uintptr_t end = base + (pool->obj_size * pool->capacity);

    if (ptr < base || ptr >= end) {
        fprintf(stderr, "pool_free: object %p not from this pool [%p, %p)\n",
                obj, pool->base, (void *)end);
        return;
    }

    /* Verify alignment */
    if ((ptr - base) % pool->obj_size != 0) {
        fprintf(stderr, "pool_free: object %p not aligned to obj_size %zu\n",
                obj, pool->obj_size);
        return;
    }

    /* Clear object before returning to pool (security + helps debugging) */
    memset(obj, 0, pool->obj_size);

    /* SPSC enqueue - single producer per worker */
    if (!ck_ring_enqueue_spsc(&pool->ring, pool->ring_buf, obj)) {
        /* This shouldn't happen if pool is used correctly */
        fprintf(stderr, "pool_free: ring buffer full, object leaked\n");
        return;
    }

    atomic_fetch_add(&pool->free_count, 1);
}

/**
 * @brief Get pool statistics (thread-safe)
 *
 * Reads atomic counters for pool usage. All output parameters are
 * optional (pass NULL to skip).
 *
 * @par Diagnostic Use:
 * - allocs - frees = currently allocated objects
 * - failures > 0 indicates pool exhaustion occurred
 */
void pool_get_stats(object_pool_t *pool, uint64_t *allocs, uint64_t *frees,
                    uint64_t *failures) {
    if (!pool) {
        if (allocs) *allocs = 0;
        if (frees) *frees = 0;
        if (failures) *failures = 0;
        return;
    }

    if (allocs) *allocs = atomic_load(&pool->alloc_count);
    if (frees) *frees = atomic_load(&pool->free_count);
    if (failures) *failures = atomic_load(&pool->alloc_failures);
}
