/**
 * @file affinity.c
 * @brief MPSC overflow queue implementation for worker affinity routing
 *
 * @details Vyukov bounded queue specialized for multiple producers
 * (any worker pushing misrouted events) and a single consumer
 * (the home worker draining its priority inbox).
 *
 * @par Memory Ordering Summary
 *
 * Producer (push — multiple workers, TTAS + CAS):
 *   1. ck_pr_load_64(&q->head)            — read current head
 *   2. ck_pr_load_64(&slot->seq)           — TTAS pre-check (Shared state)
 *   3. ck_pr_cas_64(&q->head, h, h+1)     — claim slot (full barrier)
 *   4. __builtin_memcpy(slot, event, 56)   — write payload (CAS barrier
 *                                             ensures prior consumer release
 *                                             is visible)
 *   5. ck_pr_fence_release()               — ensures payload visible
 *   6. ck_pr_store_64(&slot->seq, h+1)     — publish to consumer
 *
 * Consumer (drain — single home worker, zero CAS):
 *   1. plain load q->tail                  — consumer-private
 *   2. ck_pr_load_64(&slot->seq)           — check readiness
 *   3. ck_pr_fence_load()                  — acquire: pairs with producer's
 *                                             release, prevents speculative
 *                                             read of event data on ARM
 *   4. __builtin_memcpy(out, slot, 56)     — read payload (safe after fence)
 *   5. ck_pr_fence_release()               — ensures read completes
 *   6. ck_pr_store_64(&slot->seq,
 *                      tail + mask + 1)    — release slot to producers
 *                                             (avoids loading capacity from
 *                                             producer's cache line)
 *   7. plain store q->tail                 — advance consumer position
 *
 * @par The tail + mask + 1 Trick
 * The consumer releases slots using @c tail+mask+1 instead of
 * @c tail+capacity. Since mask = capacity - 1, the values are identical,
 * but the consumer's @c tail_mask is on its own cache line — avoiding an
 * RFO (Request For Ownership) stall from loading capacity off the
 * producer's line. In a 64-slot queue: consumer at tail=0 sets
 * seq = 0 + 63 + 1 = 64. Next producer at head=64 sees diff = 64 - 64 = 0,
 * confirming the slot is free for the second lap.
 *
 * @par Why CAS Provides Acquire for Push
 * The TTAS sequence check before CAS is speculative — if the check sees
 * stale data, the CAS will fail or succeed correctly regardless. The CAS
 * itself is a full memory barrier: after claiming the slot, the producer
 * is guaranteed to see the consumer's prior release stores (the consumer's
 * fence_release + seq update from the previous lap). No additional acquire
 * fence is needed between CAS and data write.
 *
 * @par ARM Correctness Note
 * The SPMC ring's enqueue (spmc_ring.c) has the same acquire-fence gap:
 * the single producer checks slot seq then writes data without a CAS in
 * between. A ck_pr_fence_load() should be added there for ARM correctness
 * (follow-up fix).
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license LGPL-3.0-only
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

#include "affinity.h"

#include <string.h>

/*============================================================================
 * Lifecycle
 *============================================================================*/

void
affinity_overflow_init(affinity_overflow_t *queue)
{
    if (!queue)
        return;

    memset(queue, 0, sizeof(*queue));

    /* Duplicate masks on both producer and consumer cache lines */
    queue->head_mask = AFFINITY_OVERFLOW_MASK;
    queue->tail_mask = AFFINITY_OVERFLOW_MASK;

    /* Initialize Vyukov sequences: slots[i].seq = i (all free) */
    for (uint32_t i = 0; i < AFFINITY_OVERFLOW_CAPACITY; i++) {
        queue->slots[i].seq = i;
    }
}

/*============================================================================
 * Producer — MPSC Push (TTAS + CAS on head)
 *============================================================================*/

bool
affinity_overflow_push(affinity_overflow_t *queue, const ring_event_t *event)
{
    if (!queue || !event)
        return false;

    uint64_t head = ck_pr_load_64(&queue->head);
    uint64_t mask = queue->head_mask;
    mpsc_slot_t *slot;

    for (;;) {
        slot = &queue->slots[head & mask];

        /*
         * TTAS (Test and Test-and-Set): Load sequence in Shared MESI
         * state before attempting the expensive CAS. Only if the slot
         * looks free (diff == 0) do we request Exclusive ownership
         * via CAS. This keeps the interconnect quiet when the queue
         * is full or other workers are racing.
         */
        uint64_t seq = ck_pr_load_64(&slot->seq);
        int64_t diff = (int64_t)(seq - head);

        if (diff == 0) {
            /* Slot appears free — CAS to claim it */
            if (ck_pr_cas_64(&queue->head, head, head + 1))
                break;

            /* CAS failed — another worker claimed it, reload */
            head = ck_pr_load_64(&queue->head);

        } else if (diff < 0) {
            /*
             * Queue full: sequence is from a previous lap.
             * Consumer hasn't drained this slot yet.
             * Caller should process locally (slow path).
             */
            ck_pr_faa_64(&queue->push_fails, 1);
            return false;

        } else {
            /* Stale local head — catch up to current position */
            head = ck_pr_load_64(&queue->head);
        }

        /* PAUSE (x86) / yield (ARM) — reduce bus traffic on retry */
        ck_pr_stall();
    }

    /*
     * Claimed slot [head]. CAS is a full barrier — we are guaranteed
     * to see the consumer's prior release of this slot.
     *
     * Copy 56-byte event. The event is hot in our L1 (just dequeued
     * from SPMC ring). __builtin_memcpy gives the compiler freedom to
     * auto-vectorize (e.g., 2x AVX-256 for 56 bytes on x86).
     *
     * Future: if misrouted throughput is high, use _mm256_stream_si256
     * (non-temporal) to bypass our cache and prevent pollution.
     */
    __builtin_memcpy(&slot->event, event, sizeof(ring_event_t));

    /*
     * Publish: release fence ensures the memcpy is visible to the
     * consumer before the sequence update signals "data ready."
     */
    ck_pr_fence_release();
    ck_pr_store_64(&slot->seq, head + 1);

    return true;
}

/*============================================================================
 * Consumer — Home Worker Drain (Zero CAS, Acquire Fence)
 *============================================================================*/

uint32_t
affinity_overflow_drain(affinity_overflow_t *queue, ring_event_t *out,
                        uint32_t max_count)
{
    if (!queue || !out || max_count == 0)
        return 0;

    uint64_t tail = queue->tail;             /* Plain — consumer-private */
    const uint64_t mask = queue->tail_mask;  /* const: compiler may bake
                                                into immediate/register */
    uint32_t count = 0;

    while (count < max_count) {
        mpsc_slot_t *slot = &queue->slots[tail & mask];
        uint64_t seq = ck_pr_load_64(&slot->seq);

        /* Data ready when seq == tail + 1 */
        if ((int64_t)(seq - (tail + 1)) != 0)
            break; /* No more data — producer hasn't written here yet */

        /*
         * Acquire fence: pairs with producer's ck_pr_fence_release().
         *
         * On ARM (weakly-ordered), without this fence the CPU can
         * speculatively read event data before the sequence load
         * completes, causing a torn read if the producer is mid-write.
         *
         * On x86 (TSO), this compiles to a compiler barrier only —
         * zero instructions emitted, zero cost.
         */
        ck_pr_fence_load();

        /*
         * Prefetch next slot while we memcpy the current one.
         * The next slot's data was written by a different worker,
         * so it's in Shared or Invalid state in our cache hierarchy.
         */
        if (count + 1 < max_count)
            __builtin_prefetch(
                &queue->slots[(tail + 1) & mask].event, 0, 3);

        /* Copy 56-byte event out (safe after acquire fence) */
        __builtin_memcpy(&out[count], &slot->event, sizeof(ring_event_t));

        /*
         * Release slot back to producers.
         *
         * seq = tail + mask + 1 (same as tail + capacity)
         *
         * Uses local mask instead of capacity to avoid loading from
         * the producer's cache line — no RFO stall under MESI.
         *
         * Example: capacity=64, mask=63, tail=0:
         *   seq = 0 + 63 + 1 = 64
         *   Next producer at head=64: diff = 64 - 64 = 0 → slot free
         */
        ck_pr_fence_release();
        ck_pr_store_64(&slot->seq, tail + mask + 1);

        tail++;
        count++;
    }

    /* Update consumer position (plain store — consumer-private) */
    queue->tail = tail;

    if (count > 0)
        ck_pr_faa_64(&queue->drains, count);

    return count;
}
