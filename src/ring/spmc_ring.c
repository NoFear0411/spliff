/**
 * @file spmc_ring.c
 * @brief Lock-free SPMC ring buffer implementation
 *
 * @details Vyukov bounded queue specialized for single producer.
 * All atomic operations use CK primitives (ck_pr_*).
 *
 * @par Memory Ordering Summary
 *
 * Producer (enqueue):
 *   1. ck_pr_load_64(&slot->seq)         — acquire: see consumer's release
 *   2. slot->event = *event              — plain store: slot is "ours"
 *   3. ck_pr_fence_release()             — ensures event visible before seq
 *   4. ck_pr_store_64(&slot->seq, pos+1) — publish to consumers
 *
 * Consumer (dequeue):
 *   1. ck_pr_load_64(&slot->seq)         — acquire: see producer's release
 *   2. ck_pr_cas_64(&tail, pos, pos+1)   — claim slot
 *   3. out = slot->event                 — plain load: slot is "ours"
 *   4. ck_pr_fence_release()             — ensures read done before free
 *   5. ck_pr_store_64(&slot->seq, pos+cap) — release back to producer
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "spmc_ring.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/*============================================================================
 * Lifecycle
 *============================================================================*/

spmc_ring_t *
spmc_ring_create(uint32_t capacity)
{
    /* Require power of 2, minimum 4 (matches CK ring minimum) */
    if (capacity < 4 || !IS_POWER_OF_TWO(capacity))
        return NULL;

    /*
     * Allocate ring header (3 × 128-byte cache lines = 384 bytes).
     * Separate from slot storage so slots can use mirrored buffer.
     */
    size_t hdr_size = sizeof(spmc_ring_t);
    hdr_size = (hdr_size + CACHELINE_SIZE - 1) & ~((size_t)CACHELINE_SIZE - 1);

    spmc_ring_t *ring = aligned_alloc(CACHELINE_SIZE, hdr_size);
    if (!ring)
        return NULL;

    memset(ring, 0, hdr_size);

    /* Config (read-only after init) */
    ring->capacity  = capacity;
    ring->head_mask = capacity - 1;
    ring->tail_mask = capacity - 1;

    /*
     * Allocate slot storage.
     *
     * Mirrored buffer path: capacity × 64 bytes must fall within
     * [MIN_BUFFER_SIZE, MAX_BUFFER_SIZE] (64KB..512KB, i.e. 1024..8192 slots).
     * Mirrored virtual memory makes wrap-around transparent for batch ops.
     *
     * Heap fallback: for small test rings (< 1024 slots) or very large
     * capacities (> 8192 slots) where mirrored buffer constraints don't fit.
     * Also used if mirrored buffer creation fails (e.g., memfd unavailable).
     */
    size_t slot_bytes = (size_t)capacity * sizeof(spmc_slot_t);

    if (slot_bytes >= MIN_BUFFER_SIZE && slot_bytes <= MAX_BUFFER_SIZE) {
        ring->slot_buf = mirrored_buffer_create(slot_bytes);
        if (ring->slot_buf) {
            ring->slots = (spmc_slot_t *)ring->slot_buf->base;
        }
    }

    if (!ring->slots) {
        /* Heap fallback: aligned allocation for cache-friendly slot access */
        ring->slot_buf = NULL;
        size_t aligned_bytes = (slot_bytes + CACHELINE_SIZE - 1)
                             & ~((size_t)CACHELINE_SIZE - 1);
        ring->slots = aligned_alloc(CACHELINE_SIZE, aligned_bytes);
        if (!ring->slots) {
            free(ring);
            return NULL;
        }
        memset(ring->slots, 0, aligned_bytes);
    }

    /* Initialize Vyukov sequences: slot[i].seq = i (empty, ready for producer) */
    for (uint32_t i = 0; i < capacity; i++) {
        ring->slots[i].seq = i;
    }

    /*
     * Lock slot pages against swapping. For an EDR agent, ring memory
     * must never page-fault during the hot path. The seq init loop above
     * already pre-faulted every page; mlock prevents later eviction.
     *
     * Best-effort: fails without CAP_IPC_LOCK or when RLIMIT_MEMLOCK
     * is exceeded. Non-fatal — accept swap risk in unprivileged mode.
     */
    (void)mlock(ring->slots, slot_bytes);

    return ring;
}

void
spmc_ring_destroy(spmc_ring_t *ring)
{
    if (!ring)
        return;

    if (ring->slot_buf) {
        /* Mirrored buffer: unmaps double-mapped pages and closes memfd */
        mirrored_buffer_destroy(ring->slot_buf);
    } else if (ring->slots) {
        /* Heap-allocated slots */
        free(ring->slots);
    }

    ring->slots    = NULL;
    ring->slot_buf = NULL;

    free(ring);
}

/*============================================================================
 * Producer — Single Enqueue
 *============================================================================*/

bool
spmc_ring_enqueue(spmc_ring_t *ring, const ring_event_t *event)
{
    if (!ring || !event)
        return false;

    uint64_t pos  = ring->head;       /* Only writer, plain load */
    uint64_t mask = ring->head_mask;  /* Local copy, same cache line */

    spmc_slot_t *slot = &ring->slots[pos & mask];

    /* Check if slot is free (Vyukov: seq == pos means consumer released it) */
    uint64_t seq = ck_pr_load_64(&slot->seq);
    if (seq != pos) {
        /* Ring full — slot not yet freed by consumer */
        ck_pr_faa_64(&ring->drops, 1);
        return false;
    }

    /*
     * Acquire fence: pairs with consumer's ck_pr_fence_release() before
     * releasing the slot. Ensures we see the consumer's completed read
     * before we overwrite the slot data. On x86 TSO this is a compiler
     * barrier only (zero instructions). On ARM this emits dmb ishld.
     */
    ck_pr_fence_load();

    /* Write event data (plain store — slot is exclusively ours) */
    slot->event = *event;

    /* Prefetch next slot while current write drains to cache */
    __builtin_prefetch(&ring->slots[(pos + 1) & mask], 1, 3);

    /* Publish: fence ensures event is visible before sequence update */
    ck_pr_fence_release();
    ck_pr_store_64(&slot->seq, pos + 1);

    /* Advance head (producer-private, plain store) */
    ring->head = pos + 1;

    return true;
}

/*============================================================================
 * Producer — Batch Enqueue (Three-Stage Pipeline)
 *============================================================================*/

uint32_t
spmc_ring_enqueue_batch(spmc_ring_t *ring, const ring_event_t *events,
                        uint32_t count)
{
    if (!ring || !events || count == 0)
        return 0;

    uint64_t pos  = ring->head;
    uint64_t mask = ring->head_mask;
    uint64_t cap  = ring->capacity;

    /*
     * Fast capacity pre-check using cached tail.
     * Avoids touching slot cache lines if we know the ring is full.
     */
    uint64_t avail = cap - (pos - ring->cached_tail);
    if (avail < count) {
        /* Refresh cached tail from the contended consumer line */
        ring->cached_tail = ck_pr_load_64(&ring->tail);
        avail = cap - (pos - ring->cached_tail);
    }
    if (avail == 0)
        return 0;
    if (count > avail)
        count = (uint32_t)avail;

    /*
     * Stage 1: DATA — Copy payloads into slots.
     * Verify each slot's sequence and write event data.
     * Prefetch next slot while copying current.
     */
    uint32_t n = 0;
    for (; n < count; n++) {
        spmc_slot_t *slot = &ring->slots[(pos + n) & mask];
        uint64_t seq = ck_pr_load_64(&slot->seq);
        if (seq != pos + n)
            break; /* Slot not free (consumer lagging) */

        /*
         * Acquire fence: pairs with consumer's ck_pr_fence_release()
         * before releasing the slot. Ensures we see the consumer's
         * completed read before we overwrite. On x86 TSO this is a
         * compiler barrier (zero instructions). On ARM: dmb ishld.
         */
        ck_pr_fence_load();

        /* Prefetch next slot for the data stage */
        if (n + 1 < count)
            __builtin_prefetch(&ring->slots[(pos + n + 1) & mask], 1, 3);

        slot->event = events[n];
    }

    if (n == 0)
        return 0;

    /*
     * Stage 2: BARRIER — One fence covers all data writes.
     * This is the key optimization: N events, 1 fence (not N fences).
     */
    ck_pr_fence_release();

    /*
     * Stage 3: PUBLISH — Update sequences in tight loop.
     * Workers will see seq == pos+i+1 and know data is ready.
     */
    for (uint32_t i = 0; i < n; i++) {
        ck_pr_store_64(&ring->slots[(pos + i) & mask].seq, pos + i + 1);
    }

    /* Advance head past all enqueued events */
    ring->head = pos + n;

    return n;
}

/*============================================================================
 * Consumer — Single Dequeue (CAS + Backoff)
 *============================================================================*/

bool
spmc_ring_dequeue(spmc_ring_t *ring, ring_event_t *out)
{
    if (!ring || !out)
        return false;

    uint64_t pos  = ck_pr_load_64(&ring->tail);
    uint64_t mask = ring->tail_mask;

    for (;;) {
        spmc_slot_t *slot = &ring->slots[pos & mask];
        uint64_t seq = ck_pr_load_64(&slot->seq);

        int64_t diff = (int64_t)(seq - (pos + 1));

        if (diff == 0) {
            /*
             * Data ready — try to claim this slot.
             * CAS: tail from pos to pos+1.
             */
            if (ck_pr_cas_64(&ring->tail, pos, pos + 1)) {
                /* Winner: copy event out (plain load, slot is ours) */
                *out = slot->event;

                /* Prefetch next slot for the next dequeue iteration */
                __builtin_prefetch(&ring->slots[(pos + 1) & mask], 0, 3);

                /* Release slot back to producer for reuse */
                ck_pr_fence_release();
                ck_pr_store_64(&slot->seq, pos + ring->capacity);

                ck_pr_faa_64(&ring->dequeues, 1);
                return true;
            }

            /*
             * CAS failed — another worker claimed it.
             * Backoff: ck_pr_stall() issues PAUSE (x86) or yield (ARM)
             * to prevent coherency storm on the tail cache line.
             */
            ck_pr_stall();
            pos = ck_pr_load_64(&ring->tail);
            ck_pr_faa_64(&ring->cas_retries, 1);

        } else if (diff < 0) {
            /* Ring empty: producer hasn't written to this slot yet */
            return false;

        } else {
            /*
             * diff > 0: Our local pos is stale.
             * Another consumer already claimed AND released this slot.
             * Refresh tail and retry.
             */
            pos = ck_pr_load_64(&ring->tail);
        }
    }
}

/*============================================================================
 * Consumer — Batch Dequeue (Single CAS for N slots)
 *============================================================================*/

uint32_t
spmc_ring_dequeue_batch(spmc_ring_t *ring, ring_event_t *out,
                        uint32_t max_count)
{
    if (!ring || !out || max_count == 0)
        return 0;

    if (max_count > SPMC_BATCH_MAX)
        max_count = SPMC_BATCH_MAX;

    uint64_t mask = ring->tail_mask;
    uint64_t cap  = ring->capacity;

    for (int retry = 0; retry < SPMC_BATCH_MAX_RETRIES; retry++) {
        uint64_t pos = ck_pr_load_64(&ring->tail);

        /* Scan consecutive ready slots */
        uint32_t n = 0;
        while (n < max_count) {
            spmc_slot_t *slot = &ring->slots[(pos + n) & mask];
            uint64_t seq = ck_pr_load_64(&slot->seq);
            if (seq != pos + n + 1)
                break; /* Slot not ready */
            n++;
        }

        if (n == 0)
            return 0; /* Ring empty */

        /* Claim all n slots with a single CAS */
        if (ck_pr_cas_64(&ring->tail, pos, pos + n)) {
            /* Copy events out */
            for (uint32_t i = 0; i < n; i++) {
                out[i] = ring->slots[(pos + i) & mask].event;
            }

            /* Release all slots back to producer */
            ck_pr_fence_release();
            for (uint32_t i = 0; i < n; i++) {
                ck_pr_store_64(&ring->slots[(pos + i) & mask].seq,
                               pos + i + cap);
            }

            ck_pr_faa_64(&ring->dequeues, n);
            return n;
        }

        /* CAS failed — another worker claimed some slots */
        ck_pr_stall();
        ck_pr_faa_64(&ring->cas_retries, 1);
    }

    return 0;
}
