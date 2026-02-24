/**
 * @file test_concurrent.c
 * @brief Multi-threaded stress tests for SPMC ring and MPSC overflow queue
 *
 * Verifies lock-free correctness under real contention:
 * - No lost events (every produced event is consumed exactly once)
 * - No duplicate events (CAS claims are exclusive)
 * - CAS retries occur (proving contention happened)
 * - Stats are consistent across producer/consumer counters
 * - Full pipeline: SPMC → affinity check → MPSC overflow → drain
 *
 * @par Verification Strategy
 * Each event carries a unique ID in socket_cookie. Per-thread uint8_t
 * bitmaps track which IDs each thread consumed. After joining, bitmaps
 * are merged and checked: every ID must appear exactly once (no loss,
 * no duplicates).
 *
 * @par ThreadSanitizer Note
 * CK primitives use inline assembly (lock cmpxchg on x86, ldxr/stxr
 * on ARM) which TSan cannot instrument. Correctness is verified
 * logically via bitmap checking rather than TSan's race detector.
 *
 * @par Hardware Requirements
 * Tests produce meaningful contention on >= 2 hardware threads. On
 * single-core machines, tests still pass but may not exercise all
 * concurrency paths. The CAS retries check may fail on single-core.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>

#include "../src/ring/spmc_ring.h"
#include "../src/ring/affinity.h"

/*============================================================================
 * Test Framework
 *============================================================================*/

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { \
        tests_run++; \
        printf("  [%02d] %-55s ", tests_run, name); \
        fflush(stdout); \
    } while (0)

#define PASS() \
    do { \
        tests_passed++; \
        printf("PASS\n"); \
    } while (0)

#define FAIL(msg) \
    do { \
        tests_failed++; \
        printf("FAIL: %s\n", msg); \
    } while (0)

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { FAIL(msg); return; } \
    } while (0)

/*============================================================================
 * Configuration
 *============================================================================*/

/** Number of consumer/worker threads */
#define NUM_WORKERS         4

/** Total events for SPMC stress tests */
#define SPMC_TOTAL_EVENTS   100000

/** SPMC ring capacity (power of 2) */
#define SPMC_RING_CAP       4096

/** Events per producer in MPSC test */
#define MPSC_EVENTS_PER     10000

/** Total MPSC events (all producers combined) */
#define MPSC_TOTAL_EVENTS   (MPSC_EVENTS_PER * NUM_WORKERS)

/** Events for full pipeline test */
#define PIPELINE_EVENTS     50000

/*============================================================================
 * Helpers
 *============================================================================*/

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/*============================================================================
 * SPMC Single-Op Stress: 1 Producer + N Consumers
 *
 * Producer enqueues SPMC_TOTAL_EVENTS events (spin-retry on full).
 * N consumers dequeue until producer is done and ring is empty.
 * Per-thread bitmaps verify no loss / no duplicates.
 *============================================================================*/

typedef struct {
    spmc_ring_t *ring;
    pthread_barrier_t *barrier;
    uint32_t *done;
    uint8_t *seen;      /* Per-thread seen bitmap [SPMC_TOTAL_EVENTS] */
    uint64_t count;     /* Events consumed by this thread */
} spmc_consumer_ctx_t;

typedef struct {
    spmc_ring_t *ring;
    pthread_barrier_t *barrier;
    uint32_t *done;
    uint32_t total;
} spmc_producer_ctx_t;

static void *spmc_single_producer(void *arg)
{
    spmc_producer_ctx_t *ctx = arg;
    pthread_barrier_wait(ctx->barrier);

    for (uint32_t i = 0; i < ctx->total; i++) {
        ring_event_t ev = {
            .socket_cookie = i,
            .routing = route_pack(0, 0, EVENT_TYPE_SSL_DATA, 0),
        };
        while (!spmc_ring_enqueue(ctx->ring, &ev))
            ck_pr_stall();
    }

    __atomic_store_n(ctx->done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static void *spmc_single_consumer(void *arg)
{
    spmc_consumer_ctx_t *ctx = arg;
    pthread_barrier_wait(ctx->barrier);

    ring_event_t ev;
    uint64_t count = 0;

    for (;;) {
        if (spmc_ring_dequeue(ctx->ring, &ev)) {
            if (ev.socket_cookie < SPMC_TOTAL_EVENTS)
                ctx->seen[ev.socket_cookie]++;
            count++;
        } else {
            if (__atomic_load_n(ctx->done, __ATOMIC_ACQUIRE)) {
                /* Producer done — final drain */
                while (spmc_ring_dequeue(ctx->ring, &ev)) {
                    if (ev.socket_cookie < SPMC_TOTAL_EVENTS)
                        ctx->seen[ev.socket_cookie]++;
                    count++;
                }
                break;
            }
            ck_pr_stall();
        }
    }

    ctx->count = count;
    return NULL;
}

/* Cached results from single stress run */
static struct {
    bool ran;
    bool has_loss;
    bool has_dups;
    uint64_t total_consumed;
    uint64_t drops;
    uint64_t dequeues_stat;
    uint64_t cas_retries;
    double elapsed_ms;
} spmc_single_results;

static void run_spmc_single_stress(void)
{
    if (spmc_single_results.ran) return;

    spmc_ring_t *ring = spmc_ring_create(SPMC_RING_CAP);
    if (!ring) {
        spmc_single_results.has_loss = true;
        spmc_single_results.ran = true;
        return;
    }

    uint32_t done = 0;
    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, NUM_WORKERS + 1);

    /* Allocate per-thread seen bitmaps */
    uint8_t *seen[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; i++)
        seen[i] = calloc(SPMC_TOTAL_EVENTS, 1);

    spmc_producer_ctx_t pctx = {
        .ring = ring, .barrier = &barrier,
        .done = &done, .total = SPMC_TOTAL_EVENTS,
    };

    spmc_consumer_ctx_t cctx[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; i++) {
        cctx[i] = (spmc_consumer_ctx_t){
            .ring = ring, .barrier = &barrier,
            .done = &done, .seen = seen[i],
        };
    }

    double start = now_ms();

    pthread_t producer;
    pthread_t consumers[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; i++)
        pthread_create(&consumers[i], NULL, spmc_single_consumer, &cctx[i]);
    pthread_create(&producer, NULL, spmc_single_producer, &pctx);

    pthread_join(producer, NULL);
    for (int i = 0; i < NUM_WORKERS; i++)
        pthread_join(consumers[i], NULL);

    spmc_single_results.elapsed_ms = now_ms() - start;

    /* Merge per-thread bitmaps */
    uint8_t *merged = calloc(SPMC_TOTAL_EVENTS, 1);
    uint64_t total = 0;
    for (int w = 0; w < NUM_WORKERS; w++) {
        total += cctx[w].count;
        for (uint32_t i = 0; i < SPMC_TOTAL_EVENTS; i++)
            merged[i] += seen[w][i];
    }

    bool has_loss = false, has_dups = false;
    for (uint32_t i = 0; i < SPMC_TOTAL_EVENTS; i++) {
        if (merged[i] == 0) has_loss = true;
        if (merged[i] > 1)  has_dups = true;
    }

    spmc_single_results.has_loss       = has_loss;
    spmc_single_results.has_dups       = has_dups;
    spmc_single_results.total_consumed = total;
    spmc_single_results.drops          = spmc_ring_stat_drops(ring);
    spmc_single_results.dequeues_stat  = spmc_ring_stat_dequeues(ring);
    spmc_single_results.cas_retries    = spmc_ring_stat_cas_retries(ring);
    spmc_single_results.ran            = true;

    for (int i = 0; i < NUM_WORKERS; i++)
        free(seen[i]);
    free(merged);
    pthread_barrier_destroy(&barrier);
    spmc_ring_destroy(ring);
}

/*============================================================================
 * SPMC Batch Stress: 1 Producer (batch) + N Consumers (batch)
 *
 * Same verification as single-op, but exercises the three-stage
 * batch enqueue pipeline and the single-CAS batch dequeue under
 * real contention.
 *============================================================================*/

static void *spmc_batch_producer(void *arg)
{
    spmc_producer_ctx_t *ctx = arg;
    pthread_barrier_wait(ctx->barrier);

    ring_event_t batch[SPMC_BATCH_DEFAULT];
    uint32_t sent = 0;

    while (sent < ctx->total) {
        uint32_t batch_size = ctx->total - sent;
        if (batch_size > SPMC_BATCH_DEFAULT)
            batch_size = SPMC_BATCH_DEFAULT;

        for (uint32_t i = 0; i < batch_size; i++) {
            batch[i] = (ring_event_t){
                .socket_cookie = sent + i,
                .routing = route_pack(0, 0, EVENT_TYPE_SSL_DATA, 0),
            };
        }

        uint32_t n = spmc_ring_enqueue_batch(ctx->ring, batch, batch_size);
        sent += n;
        if (n < batch_size)
            ck_pr_stall();
    }

    __atomic_store_n(ctx->done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static void *spmc_batch_consumer(void *arg)
{
    spmc_consumer_ctx_t *ctx = arg;
    pthread_barrier_wait(ctx->barrier);

    ring_event_t batch[SPMC_BATCH_DEFAULT];
    uint64_t count = 0;

    for (;;) {
        uint32_t n = spmc_ring_dequeue_batch(
            ctx->ring, batch, SPMC_BATCH_DEFAULT);
        if (n > 0) {
            for (uint32_t i = 0; i < n; i++) {
                if (batch[i].socket_cookie < SPMC_TOTAL_EVENTS)
                    ctx->seen[batch[i].socket_cookie]++;
                count++;
            }
        } else {
            if (__atomic_load_n(ctx->done, __ATOMIC_ACQUIRE)) {
                /* Final drain */
                while ((n = spmc_ring_dequeue_batch(ctx->ring, batch,
                            SPMC_BATCH_DEFAULT)) > 0) {
                    for (uint32_t i = 0; i < n; i++) {
                        if (batch[i].socket_cookie < SPMC_TOTAL_EVENTS)
                            ctx->seen[batch[i].socket_cookie]++;
                        count++;
                    }
                }
                break;
            }
            ck_pr_stall();
        }
    }

    ctx->count = count;
    return NULL;
}

static struct {
    bool ran;
    bool has_loss;
    bool has_dups;
    uint64_t total_consumed;
    double elapsed_ms;
} spmc_batch_results;

static void run_spmc_batch_stress(void)
{
    if (spmc_batch_results.ran) return;

    spmc_ring_t *ring = spmc_ring_create(SPMC_RING_CAP);
    if (!ring) {
        spmc_batch_results.has_loss = true;
        spmc_batch_results.ran = true;
        return;
    }

    uint32_t done = 0;
    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, NUM_WORKERS + 1);

    uint8_t *seen[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; i++)
        seen[i] = calloc(SPMC_TOTAL_EVENTS, 1);

    spmc_producer_ctx_t pctx = {
        .ring = ring, .barrier = &barrier,
        .done = &done, .total = SPMC_TOTAL_EVENTS,
    };

    spmc_consumer_ctx_t cctx[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; i++) {
        cctx[i] = (spmc_consumer_ctx_t){
            .ring = ring, .barrier = &barrier,
            .done = &done, .seen = seen[i],
        };
    }

    double start = now_ms();

    pthread_t producer;
    pthread_t consumers[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; i++)
        pthread_create(&consumers[i], NULL, spmc_batch_consumer, &cctx[i]);
    pthread_create(&producer, NULL, spmc_batch_producer, &pctx);

    pthread_join(producer, NULL);
    for (int i = 0; i < NUM_WORKERS; i++)
        pthread_join(consumers[i], NULL);

    spmc_batch_results.elapsed_ms = now_ms() - start;

    uint8_t *merged = calloc(SPMC_TOTAL_EVENTS, 1);
    uint64_t total = 0;
    for (int w = 0; w < NUM_WORKERS; w++) {
        total += cctx[w].count;
        for (uint32_t i = 0; i < SPMC_TOTAL_EVENTS; i++)
            merged[i] += seen[w][i];
    }

    bool has_loss = false, has_dups = false;
    for (uint32_t i = 0; i < SPMC_TOTAL_EVENTS; i++) {
        if (merged[i] == 0) has_loss = true;
        if (merged[i] > 1)  has_dups = true;
    }

    spmc_batch_results.has_loss       = has_loss;
    spmc_batch_results.has_dups       = has_dups;
    spmc_batch_results.total_consumed = total;
    spmc_batch_results.ran            = true;

    for (int i = 0; i < NUM_WORKERS; i++)
        free(seen[i]);
    free(merged);
    pthread_barrier_destroy(&barrier);
    spmc_ring_destroy(ring);
}

/*============================================================================
 * MPSC Multi-Producer Stress: N Producers + 1 Consumer
 *
 * 4 producers push 10K events each to the same overflow queue.
 * Single consumer drains continuously. Bitmap verifies 40K events
 * delivered exactly once through a 64-slot queue (~625 laps).
 *============================================================================*/

typedef struct {
    affinity_overflow_t *queue;
    pthread_barrier_t *barrier;
    uint32_t producer_id;
    uint32_t events_per;
    uint32_t *producers_done; /* Atomic counter of finished producers */
} mpsc_producer_ctx_t;

typedef struct {
    affinity_overflow_t *queue;
    pthread_barrier_t *barrier;
    uint32_t total_producers;
    uint32_t *producers_done;
    uint8_t *seen;
    uint64_t count;
} mpsc_consumer_ctx_t;

static void *mpsc_producer_thread(void *arg)
{
    mpsc_producer_ctx_t *ctx = arg;
    pthread_barrier_wait(ctx->barrier);

    uint32_t base_id = ctx->producer_id * ctx->events_per;

    for (uint32_t i = 0; i < ctx->events_per; i++) {
        ring_event_t ev = {
            .socket_cookie = base_id + i,
            .routing = route_pack(0, 0, EVENT_TYPE_SSL_DATA, 0),
        };
        /* Spin-retry on full queue (consumer will drain slots) */
        while (!affinity_overflow_push(ctx->queue, &ev))
            ck_pr_stall();
    }

    __atomic_fetch_add(ctx->producers_done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static void *mpsc_consumer_thread(void *arg)
{
    mpsc_consumer_ctx_t *ctx = arg;
    pthread_barrier_wait(ctx->barrier);

    ring_event_t batch[16];
    uint64_t count = 0;

    for (;;) {
        uint32_t n = affinity_overflow_drain(ctx->queue, batch, 16);
        if (n > 0) {
            for (uint32_t i = 0; i < n; i++) {
                if (batch[i].socket_cookie < MPSC_TOTAL_EVENTS)
                    ctx->seen[batch[i].socket_cookie]++;
                count++;
            }
        } else {
            if (__atomic_load_n(ctx->producers_done, __ATOMIC_ACQUIRE)
                == ctx->total_producers) {
                /* All producers done — final drain */
                while ((n = affinity_overflow_drain(ctx->queue, batch, 16)) > 0) {
                    for (uint32_t i = 0; i < n; i++) {
                        if (batch[i].socket_cookie < MPSC_TOTAL_EVENTS)
                            ctx->seen[batch[i].socket_cookie]++;
                        count++;
                    }
                }
                break;
            }
            ck_pr_stall();
        }
    }

    ctx->count = count;
    return NULL;
}

static struct {
    bool ran;
    bool has_loss;
    bool has_dups;
    uint64_t total_consumed;
    uint64_t drains_stat;
    double elapsed_ms;
} mpsc_results;

static affinity_overflow_t mpsc_test_queue;

static void run_mpsc_stress(void)
{
    if (mpsc_results.ran) return;

    affinity_overflow_init(&mpsc_test_queue);

    uint32_t producers_done = 0;
    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, NUM_WORKERS + 1);

    uint8_t *seen = calloc(MPSC_TOTAL_EVENTS, 1);

    mpsc_producer_ctx_t pctx[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; i++) {
        pctx[i] = (mpsc_producer_ctx_t){
            .queue = &mpsc_test_queue,
            .barrier = &barrier,
            .producer_id = (uint32_t)i,
            .events_per = MPSC_EVENTS_PER,
            .producers_done = &producers_done,
        };
    }

    mpsc_consumer_ctx_t cctx = {
        .queue = &mpsc_test_queue,
        .barrier = &barrier,
        .total_producers = NUM_WORKERS,
        .producers_done = &producers_done,
        .seen = seen,
    };

    double start = now_ms();

    pthread_t consumer;
    pthread_t producers[NUM_WORKERS];
    pthread_create(&consumer, NULL, mpsc_consumer_thread, &cctx);
    for (int i = 0; i < NUM_WORKERS; i++)
        pthread_create(&producers[i], NULL, mpsc_producer_thread, &pctx[i]);

    for (int i = 0; i < NUM_WORKERS; i++)
        pthread_join(producers[i], NULL);
    pthread_join(consumer, NULL);

    mpsc_results.elapsed_ms = now_ms() - start;

    bool has_loss = false, has_dups = false;
    for (uint32_t i = 0; i < MPSC_TOTAL_EVENTS; i++) {
        if (seen[i] == 0) has_loss = true;
        if (seen[i] > 1)  has_dups = true;
    }

    mpsc_results.has_loss       = has_loss;
    mpsc_results.has_dups       = has_dups;
    mpsc_results.total_consumed = cctx.count;
    mpsc_results.drains_stat    = affinity_overflow_stat_drains(&mpsc_test_queue);
    mpsc_results.ran            = true;

    free(seen);
    pthread_barrier_destroy(&barrier);
}

/*============================================================================
 * Full Pipeline Stress: Dispatcher → Workers → Overflow → Drain
 *
 * 1 dispatcher pushes PIPELINE_EVENTS events to SPMC ring.
 * Events: 33% stateful (preferred_worker = id % NUM_WORKERS),
 *         67% stateless (any worker).
 *
 * Workers dequeue from SPMC, check affinity:
 *   AFFINITY_LOCAL → process directly
 *   AFFINITY_DEFER → push to target worker's overflow queue
 *
 * Workers drain their own overflow inbox before polling SPMC.
 *
 * Two-phase shutdown:
 *   Phase 1: Workers consume SPMC + process + defer + drain overflow.
 *            Each worker exits when dispatcher done + SPMC empty.
 *   Phase 2: Barrier sync — all workers done with SPMC. Then each
 *            worker drains its own overflow queue (events pushed by
 *            other workers in Phase 1).
 *
 * The barrier ensures no worker checks its overflow for "empty" while
 * another worker might still be pushing to it from SPMC dequeue.
 *============================================================================*/

static affinity_overflow_t pipeline_overflows[NUM_WORKERS];

typedef struct {
    spmc_ring_t *ring;
    affinity_overflow_t *overflows;
    pthread_barrier_t *start_barrier;
    pthread_barrier_t *phase2_barrier;
    uint32_t *dispatcher_done;
    uint8_t worker_id;
    uint8_t *seen;
    uint64_t processed_local;
    uint64_t processed_overflow;
    uint64_t deferred;
    uint64_t misrouted_local_hits;
} pipeline_worker_ctx_t;

typedef struct {
    spmc_ring_t *ring;
    pthread_barrier_t *start_barrier;
    uint32_t *dispatcher_done;
    uint32_t total;
} pipeline_dispatcher_ctx_t;

static void *pipeline_dispatcher(void *arg)
{
    pipeline_dispatcher_ctx_t *ctx = arg;
    pthread_barrier_wait(ctx->start_barrier);

    for (uint32_t i = 0; i < ctx->total; i++) {
        /*
         * 33% stateful (every 3rd event), routed to preferred worker.
         * 67% stateless (any worker can process).
         *
         * Of stateful events, only 1/NUM_WORKERS land on the right
         * worker → ~75% of stateful events are deferred → ~25% of
         * total events exercise the MPSC overflow path.
         */
        uint8_t flags    = (i % 3 == 0) ? EVENT_FLAG_STATEFUL : 0;
        uint8_t preferred = (uint8_t)(i % NUM_WORKERS);

        ring_event_t ev = {
            .socket_cookie = i,
            .routing = route_pack(flags, preferred,
                                  EVENT_TYPE_SSL_DATA, 0),
        };

        while (!spmc_ring_enqueue(ctx->ring, &ev))
            ck_pr_stall();
    }

    __atomic_store_n(ctx->dispatcher_done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static void *pipeline_worker(void *arg)
{
    pipeline_worker_ctx_t *ctx = arg;
    pthread_barrier_wait(ctx->start_barrier);

    ring_event_t ev;
    ring_event_t overflow_batch[16];

    /* Phase 1: Consume SPMC + process + defer + drain overflow */
    for (;;) {
        /* Priority 1: Drain own overflow inbox (zero CAS, fast) */
        uint32_t n = affinity_overflow_drain(
            &ctx->overflows[ctx->worker_id], overflow_batch, 16);
        for (uint32_t i = 0; i < n; i++) {
            /* Events in my overflow are correctly routed — process directly */
            if (overflow_batch[i].socket_cookie < PIPELINE_EVENTS)
                ctx->seen[overflow_batch[i].socket_cookie]++;
            ctx->processed_overflow++;
        }

        /* Priority 2: Dequeue from shared SPMC ring */
        if (spmc_ring_dequeue(ctx->ring, &ev)) {
            switch (affinity_check(&ev, ctx->worker_id)) {
            case AFFINITY_LOCAL:
                if (ev.socket_cookie < PIPELINE_EVENTS)
                    ctx->seen[ev.socket_cookie]++;
                ctx->processed_local++;
                break;

            case AFFINITY_DEFER:
            {
                uint8_t target = ring_event_preferred_worker(&ev);
                if (target < NUM_WORKERS &&
                    affinity_overflow_push(&ctx->overflows[target], &ev)) {
                    ctx->deferred++;
                } else {
                    /* Overflow full or invalid target — slow path */
                    if (ev.socket_cookie < PIPELINE_EVENTS)
                        ctx->seen[ev.socket_cookie]++;
                    ctx->processed_local++;
                    ctx->misrouted_local_hits++;
                }
                break;
            }
            }
        } else {
            /* SPMC empty — check if dispatcher is done */
            if (__atomic_load_n(ctx->dispatcher_done, __ATOMIC_ACQUIRE)) {
                /* Final SPMC drain + process */
                while (spmc_ring_dequeue(ctx->ring, &ev)) {
                    switch (affinity_check(&ev, ctx->worker_id)) {
                    case AFFINITY_LOCAL:
                        if (ev.socket_cookie < PIPELINE_EVENTS)
                            ctx->seen[ev.socket_cookie]++;
                        ctx->processed_local++;
                        break;

                    case AFFINITY_DEFER:
                    {
                        uint8_t target = ring_event_preferred_worker(&ev);
                        if (target < NUM_WORKERS &&
                            affinity_overflow_push(
                                &ctx->overflows[target], &ev)) {
                            ctx->deferred++;
                        } else {
                            if (ev.socket_cookie < PIPELINE_EVENTS)
                                ctx->seen[ev.socket_cookie]++;
                            ctx->processed_local++;
                            ctx->misrouted_local_hits++;
                        }
                        break;
                    }
                    }
                }
                break; /* Exit Phase 1 */
            }
            ck_pr_stall();
        }
    }

    /*
     * Phase 2: Barrier sync — ensures all workers finished their
     * SPMC consumption (and any associated overflow pushes) before
     * any worker starts the final overflow drain.
     */
    pthread_barrier_wait(ctx->phase2_barrier);

    /* Drain own overflow completely (no more pushes possible) */
    for (;;) {
        uint32_t n = affinity_overflow_drain(
            &ctx->overflows[ctx->worker_id], overflow_batch, 16);
        if (n == 0) break;
        for (uint32_t i = 0; i < n; i++) {
            if (overflow_batch[i].socket_cookie < PIPELINE_EVENTS)
                ctx->seen[overflow_batch[i].socket_cookie]++;
            ctx->processed_overflow++;
        }
    }

    return NULL;
}

static struct {
    bool ran;
    bool has_loss;
    bool has_dups;
    uint64_t total_processed;
    uint64_t total_deferred;
    uint64_t total_overflow_processed;
    uint64_t total_misrouted_local;
    bool all_overflow_empty;
    double elapsed_ms;
} pipeline_results;

static void run_pipeline_stress(void)
{
    if (pipeline_results.ran) return;

    spmc_ring_t *ring = spmc_ring_create(SPMC_RING_CAP);
    if (!ring) {
        pipeline_results.has_loss = true;
        pipeline_results.ran = true;
        return;
    }

    for (int i = 0; i < NUM_WORKERS; i++)
        affinity_overflow_init(&pipeline_overflows[i]);

    uint32_t dispatcher_done = 0;
    pthread_barrier_t start_barrier, phase2_barrier;
    pthread_barrier_init(&start_barrier, NULL, NUM_WORKERS + 1);
    pthread_barrier_init(&phase2_barrier, NULL, NUM_WORKERS);

    uint8_t *seen[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; i++)
        seen[i] = calloc(PIPELINE_EVENTS, 1);

    pipeline_dispatcher_ctx_t dctx = {
        .ring = ring, .start_barrier = &start_barrier,
        .dispatcher_done = &dispatcher_done, .total = PIPELINE_EVENTS,
    };

    pipeline_worker_ctx_t wctx[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; i++) {
        wctx[i] = (pipeline_worker_ctx_t){
            .ring = ring, .overflows = pipeline_overflows,
            .start_barrier = &start_barrier,
            .phase2_barrier = &phase2_barrier,
            .dispatcher_done = &dispatcher_done,
            .worker_id = (uint8_t)i, .seen = seen[i],
        };
    }

    double start = now_ms();

    pthread_t dispatcher;
    pthread_t workers[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; i++)
        pthread_create(&workers[i], NULL, pipeline_worker, &wctx[i]);
    pthread_create(&dispatcher, NULL, pipeline_dispatcher, &dctx);

    pthread_join(dispatcher, NULL);
    for (int i = 0; i < NUM_WORKERS; i++)
        pthread_join(workers[i], NULL);

    pipeline_results.elapsed_ms = now_ms() - start;

    /* Merge per-worker bitmaps */
    uint8_t *merged = calloc(PIPELINE_EVENTS, 1);
    uint64_t total = 0, total_deferred = 0;
    uint64_t total_overflow = 0, total_misrouted = 0;
    for (int w = 0; w < NUM_WORKERS; w++) {
        total += wctx[w].processed_local + wctx[w].processed_overflow;
        total_deferred  += wctx[w].deferred;
        total_overflow  += wctx[w].processed_overflow;
        total_misrouted += wctx[w].misrouted_local_hits;
        for (uint32_t i = 0; i < PIPELINE_EVENTS; i++)
            merged[i] += seen[w][i];
    }

    bool has_loss = false, has_dups = false;
    for (uint32_t i = 0; i < PIPELINE_EVENTS; i++) {
        if (merged[i] == 0) has_loss = true;
        if (merged[i] > 1)  has_dups = true;
    }

    bool all_empty = true;
    for (int i = 0; i < NUM_WORKERS; i++) {
        if (!affinity_overflow_empty(&pipeline_overflows[i]))
            all_empty = false;
    }

    pipeline_results.has_loss                = has_loss;
    pipeline_results.has_dups                = has_dups;
    pipeline_results.total_processed         = total;
    pipeline_results.total_deferred          = total_deferred;
    pipeline_results.total_overflow_processed = total_overflow;
    pipeline_results.total_misrouted_local   = total_misrouted;
    pipeline_results.all_overflow_empty      = all_empty;
    pipeline_results.ran                     = true;

    for (int i = 0; i < NUM_WORKERS; i++)
        free(seen[i]);
    free(merged);
    pthread_barrier_destroy(&start_barrier);
    pthread_barrier_destroy(&phase2_barrier);
    spmc_ring_destroy(ring);
}

/*============================================================================
 * Test Functions — SPMC Single-Op
 *============================================================================*/

static void test_spmc_single_no_loss(void) {
    TEST("1P + 4C single ops: no events lost (100K)");
    run_spmc_single_stress();
    CHECK(!spmc_single_results.has_loss, "events were lost");
    CHECK(spmc_single_results.total_consumed == SPMC_TOTAL_EVENTS,
          "consumed count != produced");
    PASS();
}

static void test_spmc_single_no_dups(void) {
    TEST("1P + 4C single ops: no duplicate events");
    run_spmc_single_stress();
    CHECK(!spmc_single_results.has_dups, "duplicate events detected");
    PASS();
}

static void test_spmc_single_contention(void) {
    TEST("1P + 4C single ops: CAS contention observed");
    run_spmc_single_stress();
    CHECK(spmc_single_results.cas_retries > 0,
          "no CAS retries — contention not exercised");
    PASS();
}

static void test_spmc_single_stats(void) {
    TEST("1P + 4C single ops: dequeues stat consistent");
    run_spmc_single_stress();
    CHECK(spmc_single_results.dequeues_stat
          == spmc_single_results.total_consumed,
          "ring dequeues stat != actual consumed count");
    PASS();
}

/*============================================================================
 * Test Functions — SPMC Batch
 *============================================================================*/

static void test_spmc_batch_no_loss(void) {
    TEST("1P + 4C batch ops: no events lost (100K)");
    run_spmc_batch_stress();
    CHECK(!spmc_batch_results.has_loss, "events were lost (batch)");
    CHECK(spmc_batch_results.total_consumed == SPMC_TOTAL_EVENTS,
          "consumed count != produced (batch)");
    PASS();
}

static void test_spmc_batch_no_dups(void) {
    TEST("1P + 4C batch ops: no duplicate events");
    run_spmc_batch_stress();
    CHECK(!spmc_batch_results.has_dups, "duplicate events detected (batch)");
    PASS();
}

/*============================================================================
 * Test Functions — MPSC Multi-Producer
 *============================================================================*/

static void test_mpsc_no_loss(void) {
    TEST("4P + 1C MPSC: no events lost (40K)");
    run_mpsc_stress();
    CHECK(!mpsc_results.has_loss, "events were lost");
    CHECK(mpsc_results.total_consumed == MPSC_TOTAL_EVENTS,
          "consumed count != produced");
    PASS();
}

static void test_mpsc_no_dups(void) {
    TEST("4P + 1C MPSC: no duplicate events");
    run_mpsc_stress();
    CHECK(!mpsc_results.has_dups, "duplicate events detected");
    PASS();
}

static void test_mpsc_stats(void) {
    TEST("4P + 1C MPSC: drains stat matches consumed");
    run_mpsc_stress();
    CHECK(mpsc_results.drains_stat == mpsc_results.total_consumed,
          "drains stat != consumed count");
    PASS();
}

/*============================================================================
 * Test Functions — Full Pipeline
 *============================================================================*/

static void test_pipeline_no_loss(void) {
    TEST("Pipeline: all 50K events processed exactly once");
    run_pipeline_stress();
    CHECK(!pipeline_results.has_loss, "events were lost in pipeline");
    CHECK(!pipeline_results.has_dups, "duplicate events in pipeline");
    CHECK(pipeline_results.total_processed == PIPELINE_EVENTS,
          "processed count != produced");
    PASS();
}

static void test_pipeline_affinity(void) {
    TEST("Pipeline: affinity deferral exercised");
    run_pipeline_stress();
    CHECK(pipeline_results.total_deferred > 0,
          "no events deferred — affinity path not tested");
    PASS();
}

static void test_pipeline_overflow_clean(void) {
    TEST("Pipeline: all overflow queues drained");
    run_pipeline_stress();
    CHECK(pipeline_results.all_overflow_empty,
          "overflow queues not fully drained");
    PASS();
}

/*============================================================================
 * Main
 *============================================================================*/

int main(void)
{
    printf("=== Concurrent Stress Tests (Phase 2) ===\n");
    printf("    Config: %d workers, %dK SPMC, %dK MPSC, %dK pipeline\n\n",
           NUM_WORKERS,
           SPMC_TOTAL_EVENTS / 1000,
           MPSC_TOTAL_EVENTS / 1000,
           PIPELINE_EVENTS / 1000);

    printf("--- SPMC Single-Op (1P + %dC x %dK) ---\n",
           NUM_WORKERS, SPMC_TOTAL_EVENTS / 1000);
    test_spmc_single_no_loss();
    test_spmc_single_no_dups();
    test_spmc_single_contention();
    test_spmc_single_stats();
    if (spmc_single_results.ran)
        printf("    (%.1f ms, %lu CAS retries)\n",
               spmc_single_results.elapsed_ms,
               (unsigned long)spmc_single_results.cas_retries);

    printf("\n--- SPMC Batch (1P + %dC x %dK) ---\n",
           NUM_WORKERS, SPMC_TOTAL_EVENTS / 1000);
    test_spmc_batch_no_loss();
    test_spmc_batch_no_dups();
    if (spmc_batch_results.ran)
        printf("    (%.1f ms)\n", spmc_batch_results.elapsed_ms);

    printf("\n--- MPSC Multi-Producer (%dP + 1C x %dK) ---\n",
           NUM_WORKERS, MPSC_TOTAL_EVENTS / 1000);
    test_mpsc_no_loss();
    test_mpsc_no_dups();
    test_mpsc_stats();
    if (mpsc_results.ran)
        printf("    (%.1f ms)\n", mpsc_results.elapsed_ms);

    printf("\n--- Pipeline (1D + %dW x %dK) ---\n",
           NUM_WORKERS, PIPELINE_EVENTS / 1000);
    test_pipeline_no_loss();
    test_pipeline_affinity();
    test_pipeline_overflow_clean();
    if (pipeline_results.ran)
        printf("    (%.1f ms, %lu deferred, %lu overflow, %lu local fallback)\n",
               pipeline_results.elapsed_ms,
               (unsigned long)pipeline_results.total_deferred,
               (unsigned long)pipeline_results.total_overflow_processed,
               (unsigned long)pipeline_results.total_misrouted_local);

    printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf(", %d FAILED", tests_failed);
    printf(" ===\n");

    return tests_failed > 0 ? 1 : 0;
}
