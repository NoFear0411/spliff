/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * worker.c - Worker thread implementation
 *
 * Each worker thread:
 * - Receives events from dispatcher via lock-free CK ring
 * - Processes events using per-worker isolated state
 * - Sends formatted output to output thread via another CK ring
 * - Uses adaptive wait strategy (spin → yield → sleep on eventfd)
 */

#include "threading.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <errno.h>

/* Forward declaration - will be implemented in main.c integration */
extern void process_worker_event(worker_ctx_t *ctx, worker_event_t *event);

/* ============================================================================
 * Adaptive Wait Strategy
 * ============================================================================ */

/*
 * Phase 1: Spin-wait (lowest latency, highest CPU)
 * Spins for SPIN_ITERATIONS checking the queue.
 * Uses CPU pause instruction to reduce power and help hyperthreading.
 */
static inline bool try_spin_dequeue(worker_ctx_t *ctx, worker_event_t **event) {
    for (int i = 0; i < SPIN_ITERATIONS; i++) {
        if (ck_ring_dequeue_spsc(&ctx->in_ring, ctx->in_buffer, event)) {
            return true;
        }
        /* CPU hint to reduce power and help hyperthreading */
#if defined(__x86_64__) || defined(__i386__)
        __builtin_ia32_pause();
#elif defined(__aarch64__)
        __asm__ volatile("yield" ::: "memory");
#endif
    }
    atomic_fetch_add(&ctx->spin_cycles, SPIN_ITERATIONS);
    return false;
}

/*
 * Phase 2: Yield to other threads
 * Gives up CPU time slice to other threads before sleeping.
 */
static inline bool try_yield_dequeue(worker_ctx_t *ctx, worker_event_t **event) {
    for (int i = 0; i < YIELD_ITERATIONS; i++) {
        sched_yield();
        if (ck_ring_dequeue_spsc(&ctx->in_ring, ctx->in_buffer, event)) {
            return true;
        }
    }
    atomic_fetch_add(&ctx->yield_cycles, YIELD_ITERATIONS);
    return false;
}

/*
 * Phase 3: Sleep on eventfd (minimal CPU)
 * Blocks until dispatcher signals new work via eventfd.
 */
static inline bool try_sleep_dequeue(worker_ctx_t *ctx, worker_event_t **event) {
    struct pollfd pfd = {
        .fd = ctx->wakeup_fd,
        .events = POLLIN
    };

    /* Clear has_work flag before final check and sleep */
    atomic_store(&ctx->has_work, false);

    /* Final check before sleeping (avoid race) */
    if (ck_ring_dequeue_spsc(&ctx->in_ring, ctx->in_buffer, event)) {
        return true;
    }

    /* Sleep until woken or timeout */
    int ret = poll(&pfd, 1, POLL_TIMEOUT_MS);
    if (ret > 0) {
        /* Drain eventfd */
        uint64_t val;
        ssize_t n = read(ctx->wakeup_fd, &val, sizeof(val));
        (void)n;  /* Ignore read result */
    }

    atomic_fetch_add(&ctx->sleep_cycles, 1);
    return ck_ring_dequeue_spsc(&ctx->in_ring, ctx->in_buffer, event);
}

/* ============================================================================
 * Worker Initialization
 * ============================================================================ */

/*
 * Initialize worker context
 */
int worker_init(worker_ctx_t *ctx, int worker_id) {
    if (!ctx) {
        return -1;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->worker_id = worker_id;

    /* Create eventfd for wakeup signaling */
    ctx->wakeup_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (ctx->wakeup_fd < 0) {
        fprintf(stderr, "Worker %d: failed to create eventfd: %s\n",
                worker_id, strerror(errno));
        return -1;
    }

    /* Initialize input ring (dispatcher -> worker)
     * Note: aligned_alloc requires size to be a multiple of alignment */
    size_t in_buf_size = sizeof(ck_ring_buffer_t) * (EVENT_RING_SIZE + 1);
    in_buf_size = (in_buf_size + 63) & ~(size_t)63;  /* Round up to 64-byte boundary */
    ctx->in_buffer = aligned_alloc(64, in_buf_size);
    if (!ctx->in_buffer) {
        fprintf(stderr, "Worker %d: failed to allocate input ring\n", worker_id);
        close(ctx->wakeup_fd);
        return -1;
    }
    ck_ring_init(&ctx->in_ring, EVENT_RING_SIZE);

    /* Initialize output ring (worker -> output thread) */
    size_t out_buf_size = sizeof(ck_ring_buffer_t) * (OUTPUT_RING_SIZE + 1);
    out_buf_size = (out_buf_size + 63) & ~(size_t)63;  /* Round up to 64-byte boundary */
    ctx->out_buffer = aligned_alloc(64, out_buf_size);
    if (!ctx->out_buffer) {
        fprintf(stderr, "Worker %d: failed to allocate output ring\n", worker_id);
        free(ctx->in_buffer);
        close(ctx->wakeup_fd);
        return -1;
    }
    ck_ring_init(&ctx->out_ring, OUTPUT_RING_SIZE);

    /* Initialize event pool */
    if (pool_init(&ctx->event_pool, sizeof(worker_event_t), EVENT_POOL_SIZE) != 0) {
        fprintf(stderr, "Worker %d: failed to init event pool\n", worker_id);
        free(ctx->out_buffer);
        free(ctx->in_buffer);
        close(ctx->wakeup_fd);
        return -1;
    }

    /* Initialize output pool */
    if (pool_init(&ctx->output_pool, sizeof(output_msg_t), OUTPUT_POOL_SIZE) != 0) {
        fprintf(stderr, "Worker %d: failed to init output pool\n", worker_id);
        pool_destroy(&ctx->event_pool);
        free(ctx->out_buffer);
        free(ctx->in_buffer);
        close(ctx->wakeup_fd);
        return -1;
    }

    /* Initialize per-worker state */
    if (worker_state_init(&ctx->state, worker_id) != 0) {
        fprintf(stderr, "Worker %d: failed to init worker state\n", worker_id);
        pool_destroy(&ctx->output_pool);
        pool_destroy(&ctx->event_pool);
        free(ctx->out_buffer);
        free(ctx->in_buffer);
        close(ctx->wakeup_fd);
        return -1;
    }

    /* Initialize atomics */
    atomic_store(&ctx->events_processed, 0);
    atomic_store(&ctx->events_dropped, 0);
    atomic_store(&ctx->spin_cycles, 0);
    atomic_store(&ctx->yield_cycles, 0);
    atomic_store(&ctx->sleep_cycles, 0);
    atomic_store(&ctx->has_work, false);
    atomic_store(&ctx->running, false);

    return 0;
}

/*
 * Cleanup worker context
 */
void worker_cleanup(worker_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    /* Cleanup per-worker state */
    worker_state_cleanup(&ctx->state);

    /* Destroy pools */
    pool_destroy(&ctx->output_pool);
    pool_destroy(&ctx->event_pool);

    /* Free rings */
    if (ctx->out_buffer) {
        free(ctx->out_buffer);
        ctx->out_buffer = NULL;
    }
    if (ctx->in_buffer) {
        free(ctx->in_buffer);
        ctx->in_buffer = NULL;
    }

    /* Close eventfd */
    if (ctx->wakeup_fd >= 0) {
        close(ctx->wakeup_fd);
        ctx->wakeup_fd = -1;
    }
}

/* ============================================================================
 * Worker Thread Main Loop
 * ============================================================================ */

/*
 * Drain remaining events from input queue
 */
static void worker_drain_queues(worker_ctx_t *ctx) {
    worker_event_t *event;
    int drained = 0;

    while (ck_ring_dequeue_spsc(&ctx->in_ring, ctx->in_buffer, &event)) {
        process_worker_event(ctx, event);
        pool_free(&ctx->event_pool, event);
        drained++;
        atomic_fetch_add(&ctx->events_processed, 1);
    }

    if (drained > 0) {
        fprintf(stderr, "  Worker %d drained %d events\n", ctx->worker_id, drained);
    }
}

/*
 * Main worker processing loop
 */
static void worker_loop(worker_ctx_t *ctx) {
    while (atomic_load(&ctx->running)) {
        worker_event_t *event = NULL;

        /* Adaptive wait: spin -> yield -> sleep */
        if (!try_spin_dequeue(ctx, &event)) {
            if (!try_yield_dequeue(ctx, &event)) {
                if (!try_sleep_dequeue(ctx, &event)) {
                    continue;
                }
            }
        }

        /* Process event and batch more if available */
        int processed = 0;
        do {
            process_worker_event(ctx, event);
            pool_free(&ctx->event_pool, event);
            processed++;
            atomic_fetch_add(&ctx->events_processed, 1);
        } while (processed < BATCH_SIZE &&
                 ck_ring_dequeue_spsc(&ctx->in_ring, ctx->in_buffer, &event));
    }
}

/*
 * Worker thread entry point
 */
void *worker_thread_main(void *arg) {
    worker_ctx_t *ctx = (worker_ctx_t *)arg;
    if (!ctx) {
        return NULL;
    }

    /* Set thread name for debugging */
    char name[16];
    snprintf(name, sizeof(name), "spliff-w%d", ctx->worker_id);
#ifdef _GNU_SOURCE
    pthread_setname_np(pthread_self(), name);
#endif

    /* Set thread-local worker state */
    set_current_worker_state(&ctx->state);

    /* Mark as running */
    atomic_store(&ctx->running, true);

    /* Optional: pin to CPU for better cache locality */
    /* This is controlled by threading_mgr and done before thread creation */

    /* Main processing loop */
    worker_loop(ctx);

    /* Drain remaining events before exit */
    worker_drain_queues(ctx);

    /* Clear thread-local state */
    set_current_worker_state(NULL);

    return NULL;
}

/* ============================================================================
 * Event Processing Stub
 * ============================================================================ */

/*
 * Default event processor - will be replaced by integration with main.c
 *
 * This is a weak symbol that can be overridden by the real implementation
 * in main.c when the threading module is integrated.
 */
__attribute__((weak))
void process_worker_event(worker_ctx_t *ctx, worker_event_t *event) {
    if (!ctx || !event) {
        return;
    }

    /* Default: just count the event
     * Real implementation will:
     * 1. Parse HTTP/1 or HTTP/2 data
     * 2. Format output message
     * 3. Enqueue to output ring
     */
    (void)ctx;
    (void)event;
}
