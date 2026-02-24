/**
 * @file xdp_ring.c
 * @brief Per-worker SPSC ring buffer for XDP event delivery
 *
 * @details Implements a lock-free Single-Producer Single-Consumer ring buffer
 * for routing XDP events from the dispatcher to worker threads.
 *
 * @par Memory Ordering
 * - Push: store event with relaxed, then store head with release
 * - Pop: load head with acquire, load event with relaxed, store tail with release
 * This ensures the consumer sees the event data before seeing the updated head.
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license LGPL-3.0-only
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

#include "xdp_ring.h"

#include <string.h>
#include <unistd.h>

int xdp_ring_init(xdp_ring_t *ring, int wakeup_fd) {
    if (!ring) {
        return -1;
    }

    /* Zero the entire structure including buffer */
    memset(ring, 0, sizeof(*ring));

    /* Store shared eventfd - we don't own it, just reference it */
    ring->wakeup_fd = wakeup_fd;

    return 0;
}

void xdp_ring_cleanup(xdp_ring_t *ring) {
    if (!ring) {
        return;
    }

    /*
     * Buffer is inline (not dynamically allocated), so nothing to free.
     * wakeup_fd is owned by worker, not by us.
     */

    /* Clear for safety */
    ring->wakeup_fd = -1;
}

bool xdp_ring_push(xdp_ring_t *ring, const xdp_ring_event_t *event) {
    if (!ring || !event) {
        return false;
    }

    /*
     * Load head with relaxed - we're the only writer.
     * Load tail with acquire - consumer may have updated it.
     */
    size_t h = atomic_load_explicit(&ring->head, memory_order_relaxed);
    size_t t = atomic_load_explicit(&ring->tail, memory_order_acquire);

    /* Check if ring is full */
    size_t next_h = (h + 1) & XDP_RING_MASK;
    if (next_h == t) {
        /* Ring full - drop event */
        atomic_fetch_add_explicit(&ring->drop_count, 1, memory_order_relaxed);
        return false;
    }

    /* Copy event to buffer slot */
    ring->buffer[h] = *event;

    /*
     * Commit with release ordering.
     * This ensures the event data is visible before the head update.
     */
    atomic_store_explicit(&ring->head, next_h, memory_order_release);
    atomic_fetch_add_explicit(&ring->push_count, 1, memory_order_relaxed);

    /*
     * Signal worker via shared eventfd for instant wakeup.
     * The eventfd counter accumulates; worker drains it once.
     * Ignore write errors (non-blocking fd, or worker reading simultaneously).
     */
    if (ring->wakeup_fd >= 0) {
        uint64_t val = 1;
        ssize_t n = write(ring->wakeup_fd, &val, sizeof(val));
        (void)n;  /* Ignore result */
    }

    return true;
}

size_t xdp_ring_pop_all(xdp_ring_t *ring,
                        void (*handler)(const xdp_ring_event_t *, void *),
                        void *ctx) {
    if (!ring || !handler) {
        return 0;
    }

    /*
     * Load tail with relaxed - we're the only writer.
     * Load head with acquire - producer may have updated it.
     */
    size_t t = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    size_t h = atomic_load_explicit(&ring->head, memory_order_acquire);

    size_t count = 0;

    /* Process all available events */
    while (t != h) {
        /* Read event from buffer */
        handler(&ring->buffer[t], ctx);

        /* Advance tail */
        t = (t + 1) & XDP_RING_MASK;
        count++;
    }

    /*
     * Commit tail update with release ordering.
     * This ensures our reads completed before producer sees free slots.
     */
    if (count > 0) {
        atomic_store_explicit(&ring->tail, t, memory_order_release);
    }

    return count;
}
