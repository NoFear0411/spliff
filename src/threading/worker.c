/**
 * @file worker.c
 * @brief Worker thread implementation
 *
 * @details Each worker thread operates independently with isolated state:
 * - Receives events from dispatcher via lock-free CK ring
 * - Processes events (HTTP/1, HTTP/2 parsing) using per-worker state
 * - Sends formatted output to output thread via another CK ring
 * - Uses adaptive wait strategy for efficient CPU utilization
 *
 * @par Adaptive Wait Strategy:
 * @code
 *   ┌─────────┐    not found     ┌─────────┐    not found     ┌─────────┐
 *   │  Spin   │────────────────► │  Yield  │────────────────► │  Sleep  │
 *   │ ~1-2 μs │                  │ ~10-100 │                  │ ~1-10 ms│
 *   └────┬────┘                  │    μs   │                  └────┬────┘
 *        │ found                 └────┬────┘                       │ timeout
 *        ▼                            │ found                      │ or wake
 *   ┌─────────┐                       ▼                            ▼
 *   │ Process │◄──────────────────────┴────────────────────────────┘
 *   │  Event  │
 *   └─────────┘
 * @endcode
 *
 * @par Thread-Local State:
 * Workers use get_current_worker_state() to access per-worker state
 * without function parameter passing throughout the protocol parsers.
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
#include <unistd.h>
#include <sched.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <errno.h>

/** Forward declaration - implemented in main.c integration */
extern void process_worker_event(worker_ctx_t *ctx, worker_event_t *event);

/**
 * @defgroup worker_wait Adaptive Wait Strategy
 * @brief Three-phase wait with increasing latency and decreasing CPU usage
 * @{
 */

/**
 * @brief Phase 1: Spin-wait (lowest latency, highest CPU)
 *
 * Spins for SPIN_ITERATIONS checking the queue. Uses architecture-specific
 * pause instructions to reduce power consumption and improve hyperthreading
 * efficiency on shared cores.
 *
 * @param[in]  ctx   Worker context
 * @param[out] event Dequeued event if successful
 *
 * @return true if event dequeued, false if spin iterations exhausted
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

/**
 * @brief Phase 2: Yield to other threads
 *
 * Gives up CPU time slice via sched_yield() for YIELD_ITERATIONS,
 * checking the queue after each yield. More efficient than spinning
 * when queue is likely empty for a longer period.
 *
 * @param[in]  ctx   Worker context
 * @param[out] event Dequeued event if successful
 *
 * @return true if event dequeued, false if yield iterations exhausted
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

/**
 * @brief Phase 3: Sleep on eventfd (minimal CPU)
 *
 * Blocks on poll() until dispatcher signals new work via eventfd write,
 * or POLL_TIMEOUT_MS expires. This is the most CPU-efficient wait but
 * has highest latency (~1-10ms depending on kernel scheduling).
 *
 * @par Race Condition Prevention:
 * Clears has_work flag before final queue check to ensure:
 * 1. If dispatcher enqueues after our check but before sleep, it will
 *    write to eventfd (because has_work is false)
 * 2. We wake up and find the event
 *
 * @param[in]  ctx   Worker context
 * @param[out] event Dequeued event if successful
 *
 * @return true if event dequeued, false if timeout with empty queue
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

/** @} */ /* end worker_wait */

/**
 * @defgroup worker_init Worker Initialization
 * @brief Setup and teardown for worker threads
 * @{
 */

/**
 * @brief Initialize worker context
 *
 * Allocates and initializes all resources for a worker thread:
 * - eventfd for wakeup signaling
 * - Input ring buffer (dispatcher -> worker)
 * - Output ring buffer (worker -> output thread)
 * - Event object pool
 * - Output message object pool
 * - Per-worker protocol state
 *
 * @par Memory Alignment:
 * Ring buffers are 64-byte aligned for cache efficiency.
 *
 * @param[out] ctx       Worker context to initialize
 * @param[in]  worker_id Worker index (0 to num_workers-1)
 *
 * @return 0 on success, -1 on failure (partial cleanup performed)
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

/**
 * @brief Cleanup worker context and free all resources
 *
 * Frees per-worker state, pools, ring buffers, and eventfd.
 * Should only be called after worker thread has exited.
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

/** @} */ /* end worker_init */

/**
 * @defgroup worker_loop Worker Main Loop
 * @brief Event processing loop implementation
 * @{
 */

/**
 * @brief Drain remaining events from input queue
 *
 * Called during shutdown to process any events queued after the
 * running flag was cleared. Ensures no events are lost.
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

/**
 * @brief Main worker processing loop
 *
 * Continuously dequeues and processes events until running flag is cleared.
 * Uses adaptive wait strategy and batch processing for efficiency.
 *
 * @par Batch Processing:
 * After successfully dequeuing one event (potentially after wait), attempts
 * to dequeue up to BATCH_SIZE additional events without waiting. This
 * amortizes wait overhead when events arrive in bursts.
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

/**
 * @brief Worker thread entry point
 *
 * Thread entry point passed to pthread_create(). Sets up thread-local
 * state, runs the main loop, and drains remaining events on shutdown.
 *
 * @param[in] arg Pointer to worker_ctx_t
 *
 * @return NULL
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

/** @} */ /* end worker_loop */

/**
 * @defgroup worker_stub Event Processing Stub
 * @brief Default event processor (weak symbol)
 * @{
 */

/**
 * @brief Default event processor (weak symbol)
 *
 * Placeholder implementation that can be overridden by the real
 * implementation in main.c. When linked with main.c, that implementation
 * takes precedence due to weak symbol semantics.
 *
 * @par Real Implementation Responsibilities:
 * 1. Determine protocol (HTTP/1.1 or HTTP/2 via ALPN cache)
 * 2. Parse SSL plaintext data
 * 3. Format output (JSON or human-readable)
 * 4. Enqueue to output ring via output_write()
 *
 * @param[in] ctx   Worker context
 * @param[in] event Event to process
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

/** @} */ /* end worker_stub */
