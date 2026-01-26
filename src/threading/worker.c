/**
 * @file worker.c
 * @brief Worker thread implementation with NAPI-style adaptive polling
 *
 * @details Each worker thread operates independently with isolated state:
 * - Receives events from dispatcher via lock-free CK ring
 * - Processes events (HTTP/1, HTTP/2 parsing) using per-worker state
 * - Sends formatted output to output thread via another CK ring
 * - Uses NAPI-style budget-based polling for efficient CPU utilization
 *
 * @par NAPI-Style Adaptive Polling:
 * @code
 *   while (running) {
 *       work_done = 0;
 *
 *       // Process events up to budget
 *       while (work_done < NAPI_BUDGET && can_dequeue()) {
 *           process_event();
 *           work_done++;
 *       }
 *
 *       // Process deferred cookie retries
 *       work_done += process_deferred_batch();
 *
 *       if (work_done < NAPI_BUDGET) {
 *           // Caught up with traffic - sleep efficiently
 *           epoll_wait(epoll_fd, events, 4, timeout);
 *       }
 *       // else: heavy traffic - loop immediately without sleeping
 *   }
 * @endcode
 *
 * @par Benefits:
 * - Zero CPU when idle (epoll blocks)
 * - Zero syscall overhead under heavy load (never reaches epoll_wait)
 * - Naturally adapts to traffic patterns
 *
 * @par Cookie Retry Queue:
 * Handles SSL-sockops timing race where SSL events arrive before XDP events
 * populate the flow_cache. Uses bitmask for O(1) slot operations:
 * - __builtin_ctzll() finds first set/free bit in one CPU cycle
 * - __builtin_popcountll() counts pending in one cycle
 * - Fixed array with no pointer chasing, excellent cache locality
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "threading.h"
#include "../protocol/http1.h"
#include "../protocol/http2.h"
#include "../protocol/detector.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <errno.h>

/** Forward declaration - implemented in main.c integration */
extern void process_worker_event(worker_ctx_t *ctx, worker_event_t *event);

/**
 * @defgroup worker_epoll Epoll Setup
 * @brief NAPI-style efficient blocking with epoll
 * @{
 */

/**
 * @brief Initialize epoll for efficient blocking
 *
 * Creates epoll instance and registers the wakeup eventfd.
 * Workers block on epoll_wait when caught up with traffic.
 *
 * @param[in] ctx Worker context with wakeup_fd already initialized
 *
 * @return 0 on success, -1 on failure
 */
static int worker_init_epoll(worker_ctx_t *ctx) {
    ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (ctx->epoll_fd < 0) {
        fprintf(stderr, "Worker %d: failed to create epoll: %s\n",
                ctx->worker_id, strerror(errno));
        return -1;
    }

    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.fd = ctx->wakeup_fd
    };

    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->wakeup_fd, &ev) < 0) {
        fprintf(stderr, "Worker %d: failed to add eventfd to epoll: %s\n",
                ctx->worker_id, strerror(errno));
        close(ctx->epoll_fd);
        ctx->epoll_fd = -1;
        return -1;
    }

    return 0;
}

/**
 * @brief Cleanup epoll resources
 *
 * @param[in] ctx Worker context
 */
static void worker_cleanup_epoll(worker_ctx_t *ctx) {
    if (ctx->epoll_fd >= 0) {
        close(ctx->epoll_fd);
        ctx->epoll_fd = -1;
    }
}

/**
 * @brief Drain eventfd to clear pending wakeup
 *
 * @param[in] fd eventfd file descriptor
 */
static inline void drain_eventfd(int fd) {
    uint64_t val;
    ssize_t n = read(fd, &val, sizeof(val));
    (void)n;  /* Ignore read result */
}

/** @} */ /* end worker_epoll */

/**
 * @defgroup worker_retry Cookie Retry Queue
 * @brief Bitmask-based deferred event queue for timing race handling
 * @{
 */

/**
 * @brief Defer event for cookie retry
 *
 * When an SSL event has a valid socket_cookie but flow_cache_lookup returns
 * NULL (XDP event not yet processed), defer the event for later retry.
 *
 * Uses bitmask for O(1) slot allocation:
 * - __builtin_ctzll() finds first zero bit (free slot) in one cycle
 *
 * @param[in] ctx   Worker context
 * @param[in] event Event to defer (ownership transferred to queue)
 *
 * @return 0 on success, -1 if all 64 slots are full
 */
static int defer_event_for_retry(worker_ctx_t *ctx, worker_event_t *event) {
    uint64_t free_mask = ~ctx->deferred_busy_mask;
    if (free_mask == 0) {
        /* All 64 slots full - process without flow_info */
        atomic_fetch_add(&ctx->deferred_failures, 1);
        return -1;
    }

    /* Find first free slot - O(1) with compiler intrinsic */
    int slot = __builtin_ctzll(free_mask);
    ctx->deferred_busy_mask |= (1ULL << slot);

    /* Store event with identity for cache thrashing detection */
    ctx->deferred_slots[slot].event = event;
    ctx->deferred_slots[slot].original_cookie = event->socket_cookie;
    ctx->deferred_slots[slot].defer_time_ns = get_time_ns();
    ctx->deferred_slots[slot].retry_count = 0;

    atomic_fetch_add(&ctx->deferred_count, 1);
    return 0;
}

/**
 * @brief Process all pending retries in one batch
 *
 * Called once per NAPI loop iteration. Better cache locality than
 * individual timers per event. Processes events with tick-based interval
 * to allow flow_cache to be populated by XDP events.
 *
 * @par Identity Check:
 * Before correlating, verifies the flow_cache entry still belongs to
 * the same socket_cookie. This detects cache thrashing where a slot
 * was evicted and reused by a different flow.
 *
 * @param[in] ctx Worker context
 *
 * @return Number of events processed (completed or gave up)
 */
static int process_deferred_batch(worker_ctx_t *ctx) {
    ctx->retry_tick++;

    /* Only retry every N ticks (controls retry interval ~500μs under load) */
    if ((ctx->retry_tick % RETRY_TICK_INTERVAL) != 0) {
        return 0;
    }

    int processed = 0;
    uint64_t mask = ctx->deferred_busy_mask;

    while (mask) {
        /* Find first set bit (occupied slot) - O(1) */
        int slot = __builtin_ctzll(mask);
        mask &= ~(1ULL << slot);  /* Clear bit for iteration */

        deferred_event_t *def = &ctx->deferred_slots[slot];
        worker_event_t *event = def->event;

        /* Retry lookup in Shared Pool */
        threading_mgr_t *mgr = threading_get_manager();
        if (mgr && event->socket_cookie != 0) {
            /* Shared Pool: lookup by cookie or (pid, ssl_ctx) */
            flow_context_t *flow_ctx = flow_lookup(&mgr->dispatcher.flow_mgr,
                                                    event->socket_cookie,
                                                    event->pid,
                                                    event->ssl_ctx);
            if (flow_ctx) {
                event->flow_id = flow_ctx->self_id;
                event->flow_ctx = flow_ctx;
            }
        }

        def->retry_count++;

        /* Success if flow_ctx found */
        bool correlation_success = (event->flow_ctx != NULL);

        if (correlation_success) {
            /* Success! Clear slot and process */
            ctx->deferred_busy_mask &= ~(1ULL << slot);
            atomic_fetch_sub(&ctx->deferred_count, 1);
            atomic_fetch_add(&ctx->deferred_successes, 1);
            process_worker_event(ctx, event);
            pool_free(&ctx->event_pool, event);
            processed++;
        } else if (def->retry_count >= MAX_COOKIE_RETRIES) {
            /* Give up - clear slot and process without flow_info */
            ctx->deferred_busy_mask &= ~(1ULL << slot);
            atomic_fetch_sub(&ctx->deferred_count, 1);
            atomic_fetch_add(&ctx->deferred_failures, 1);
            process_worker_event(ctx, event);  /* Process without network metadata */
            pool_free(&ctx->event_pool, event);
            processed++;
        }
        /* else: stays in queue for next batch */
    }

    return processed;
}

/** @} */ /* end worker_retry */

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
 * - epoll for efficient blocking
 * - Input ring buffer (dispatcher -> worker)
 * - Output ring buffer (worker -> output thread)
 * - Event object pool
 * - Output message object pool
 * - Per-worker protocol state
 * - Deferred event queue (cookie retry)
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
    ctx->epoll_fd = -1;

    /* Create eventfd for wakeup signaling */
    ctx->wakeup_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (ctx->wakeup_fd < 0) {
        fprintf(stderr, "Worker %d: failed to create eventfd: %s\n",
                worker_id, strerror(errno));
        return -1;
    }

    /* Initialize epoll for NAPI-style blocking */
    if (worker_init_epoll(ctx) != 0) {
        close(ctx->wakeup_fd);
        return -1;
    }

    /* Initialize input ring (dispatcher -> worker)
     * Note: aligned_alloc requires size to be a multiple of alignment */
    size_t in_buf_size = sizeof(ck_ring_buffer_t) * (EVENT_RING_SIZE + 1);
    in_buf_size = (in_buf_size + 63) & ~(size_t)63;  /* Round up to 64-byte boundary */
    ctx->in_buffer = aligned_alloc(64, in_buf_size);
    if (!ctx->in_buffer) {
        fprintf(stderr, "Worker %d: failed to allocate input ring\n", worker_id);
        worker_cleanup_epoll(ctx);
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
        worker_cleanup_epoll(ctx);
        close(ctx->wakeup_fd);
        return -1;
    }
    ck_ring_init(&ctx->out_ring, OUTPUT_RING_SIZE);

    /* Initialize event pool */
    if (pool_init(&ctx->event_pool, sizeof(worker_event_t), EVENT_POOL_SIZE) != 0) {
        fprintf(stderr, "Worker %d: failed to init event pool\n", worker_id);
        free(ctx->out_buffer);
        free(ctx->in_buffer);
        worker_cleanup_epoll(ctx);
        close(ctx->wakeup_fd);
        return -1;
    }

    /* Initialize output pool */
    if (pool_init(&ctx->output_pool, sizeof(output_msg_t), OUTPUT_POOL_SIZE) != 0) {
        fprintf(stderr, "Worker %d: failed to init output pool\n", worker_id);
        pool_destroy(&ctx->event_pool);
        free(ctx->out_buffer);
        free(ctx->in_buffer);
        worker_cleanup_epoll(ctx);
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
        worker_cleanup_epoll(ctx);
        close(ctx->wakeup_fd);
        return -1;
    }

    /* Initialize deferred event queue (cookie retry) */
    ctx->deferred_busy_mask = 0;
    ctx->retry_tick = 0;
    memset(ctx->deferred_slots, 0, sizeof(ctx->deferred_slots));

    /* Initialize atomics */
    atomic_store(&ctx->events_processed, 0);
    atomic_store(&ctx->events_dropped, 0);
    atomic_store(&ctx->spin_cycles, 0);    /* Unused in NAPI mode, kept for stats compat */
    atomic_store(&ctx->yield_cycles, 0);   /* Unused in NAPI mode, kept for stats compat */
    atomic_store(&ctx->sleep_cycles, 0);
    atomic_store(&ctx->has_work, false);
    atomic_store(&ctx->running, false);
    atomic_store(&ctx->deferred_count, 0);
    atomic_store(&ctx->deferred_successes, 0);
    atomic_store(&ctx->deferred_failures, 0);

    return 0;
}

/**
 * @brief Cleanup worker context and free all resources
 *
 * Frees per-worker state, pools, ring buffers, epoll, and eventfd.
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

    /* Cleanup epoll */
    worker_cleanup_epoll(ctx);

    /* Close eventfd */
    if (ctx->wakeup_fd >= 0) {
        close(ctx->wakeup_fd);
        ctx->wakeup_fd = -1;
    }
}

/** @} */ /* end worker_init */

/**
 * @defgroup worker_loop Worker Main Loop
 * @brief NAPI-style event processing loop implementation
 * @{
 */

/**
 * @brief Drain remaining events from input queue
 *
 * Called during shutdown to process any events queued after the
 * running flag was cleared. Ensures no events are lost.
 *
 * @param[in] ctx Worker context
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

    /* Also drain deferred events */
    uint64_t mask = ctx->deferred_busy_mask;
    while (mask) {
        int slot = __builtin_ctzll(mask);
        mask &= ~(1ULL << slot);
        ctx->deferred_busy_mask &= ~(1ULL << slot);

        deferred_event_t *def = &ctx->deferred_slots[slot];
        process_worker_event(ctx, def->event);
        pool_free(&ctx->event_pool, def->event);
        drained++;
        atomic_fetch_add(&ctx->events_processed, 1);
    }

    if (drained > 0) {
        fprintf(stderr, "  Worker %d drained %d events\n", ctx->worker_id, drained);
    }
}

/**
 * @brief NAPI-style main worker processing loop
 *
 * Uses budget-based polling similar to Linux NAPI:
 * - Process up to NAPI_BUDGET events per iteration
 * - If work_done < budget: caught up, sleep via epoll_wait
 * - If work_done == budget: heavy traffic, loop immediately
 *
 * @par CPU Efficiency:
 * - Zero CPU when idle (epoll_wait blocks)
 * - Zero syscall overhead under heavy load (never reaches epoll_wait)
 *
 * @par Cookie Retry Integration:
 * Events with valid socket_cookie but NULL flow_info are deferred
 * to the retry queue. The queue is processed on each iteration.
 *
 * @param[in] ctx Worker context
 */
static void worker_loop(worker_ctx_t *ctx) {
    struct epoll_event events[4];

    while (atomic_load(&ctx->running)) {
        int work_done = 0;
        worker_event_t *event;

        /* Process events up to NAPI budget */
        while (work_done < NAPI_BUDGET &&
               ck_ring_dequeue_spsc(&ctx->in_ring, ctx->in_buffer, &event)) {

            /* Check if cookie retry needed */
            if (event->needs_cookie_retry && event->flow_ctx == NULL) {
                if (defer_event_for_retry(ctx, event) == 0) {
                    /* Successfully deferred - don't count against budget */
                    continue;
                }
                /* Queue full - fall through to process immediately */
            }

            /*
             * === Worker Affinity: Claim or Route ===
             *
             * Implements "Hybrid Sticky" architecture for thread-safe
             * HTTP/2 state without locking. First worker to process
             * an event claims ownership via atomic CAS.
             */
            if (event->flow_ctx) {
                uint32_t expected = WORKER_ID_NONE;
                uint32_t my_id = ctx->worker_id;

                /* Try to claim ownership */
                if (atomic_compare_exchange_strong(&event->flow_ctx->home_worker_id,
                                                    &expected, my_id)) {
                    /*
                     * Successfully claimed - we are the home worker.
                     * Initialize protocol-specific state that requires
                     * single-writer ownership (e.g., HTTP/2 nghttp2 session).
                     */
                    if (g_config.debug_mode) {
                        fprintf(stderr, "[Worker %u] Claimed flow_id=%u proto=%d\n",
                                my_id, event->flow_ctx->self_id,
                                event->flow_ctx->proto);
                    }

                    /*
                     * Protocol Parser Initialization
                     *
                     * Initialize protocol-specific parser state when home worker
                     * first claims the flow. This ensures single-writer ownership
                     * of parser state.
                     */
                    switch (event->flow_ctx->proto) {
                    case FLOW_PROTO_HTTP2:
                        /*
                         * HTTP/2: Create nghttp2 session with proper callback context
                         *
                         * Creates callback context for flow-based processing, then
                         * initializes the nghttp2 session. This enables direct use of
                         * flow_ctx->parser.h2.session without global pool dependency.
                         */
                        if (event->flow_ctx->parser.h2.session == NULL) {
                            nghttp2_session_callbacks *cbs = http2_get_callbacks();
                            if (cbs) {
                                /* Create callback context for this flow */
                                void *cb_ctx = http2_create_callback_ctx(event->flow_ctx);
                                if (cb_ctx) {
                                    event->flow_ctx->parser.h2.callback_ctx = cb_ctx;
                                    int rv = flow_h2_session_init(event->flow_ctx, cbs, cb_ctx);
                                    if (rv == 0 && g_config.debug_mode) {
                                        fprintf(stderr, "[Worker %u] Initialized H2 session for flow_id=%u\n",
                                                my_id, event->flow_ctx->self_id);
                                    }
                                }
                            }
                        }
                        break;

                    case FLOW_PROTO_HTTP1:
                        /*
                         * HTTP/1: Initialize llhttp parser with flow-based callbacks
                         *
                         * The flow-based parser uses persistent state in flow_ctx->parser.h1
                         * to handle headers/body split across TCP segments. Callbacks store
                         * data in flow_transaction_t and display via on_headers_complete.
                         */
                        if (!event->flow_ctx->parser.h1.initialized) {
                            llhttp_settings_t *settings = http1_get_flow_settings();
                            int rv = flow_h1_parser_init(event->flow_ctx, settings);
                            if (rv == 0 && g_config.debug_mode) {
                                fprintf(stderr, "[Worker %u] Initialized H1 parser for flow_id=%u\n",
                                        my_id, event->flow_ctx->self_id);
                            }
                        }
                        break;

                    default:
                        /* FLOW_PROTO_UNKNOWN or FLOW_PROTO_OTHER - no parser to init */
                        break;
                    }
                } else {
                    /* Flow already owned - check if we are the owner */
                    uint32_t home = atomic_load(&event->flow_ctx->home_worker_id);
                    if (home == my_id) {
                        /*
                         * We own this flow - check for late parser initialization.
                         *
                         * This handles the case where:
                         * 1. SSL data arrived first → claimed flow with proto=UNKNOWN
                         * 2. ALPN event arrived later → set proto but CAS failed
                         * 3. Parser needs initialization now that proto is known
                         *
                         * This is the "Golden Thread" fix for ALPN timing issues.
                         */
                        if (event->flow_ctx->proto == FLOW_PROTO_HTTP2 &&
                            event->flow_ctx->parser.h2.session == NULL) {
                            nghttp2_session_callbacks *cbs = http2_get_callbacks();
                            if (cbs) {
                                void *cb_ctx = http2_create_callback_ctx(event->flow_ctx);
                                if (cb_ctx) {
                                    event->flow_ctx->parser.h2.callback_ctx = cb_ctx;
                                    int rv = flow_h2_session_init(event->flow_ctx, cbs, cb_ctx);
                                    if (rv == 0 && g_config.debug_mode) {
                                        fprintf(stderr, "[Worker %u] Late H2 init for flow_id=%u\n",
                                                my_id, event->flow_ctx->self_id);
                                    }
                                }
                            }
                        } else if (event->flow_ctx->proto == FLOW_PROTO_HTTP1 &&
                                   !event->flow_ctx->parser.h1.initialized) {
                            llhttp_settings_t *settings = http1_get_flow_settings();
                            int rv = flow_h1_parser_init(event->flow_ctx, settings);
                            if (rv == 0 && g_config.debug_mode) {
                                fprintf(stderr, "[Worker %u] Late H1 init for flow_id=%u\n",
                                        my_id, event->flow_ctx->self_id);
                            }
                        }
                    } else if (home != WORKER_ID_NONE) {
                        /*
                         * Misrouted event: we are not the home worker.
                         *
                         * nghttp2 sessions are NOT thread-safe, so we cannot have
                         * multiple workers accessing the same session. If parser
                         * initialization is needed, we must atomically re-home the
                         * flow to this worker before initializing.
                         *
                         * Re-homing strategy:
                         * 1. If proto is known but parser not initialized, try to
                         *    atomically claim ownership (CAS home_worker_id)
                         * 2. If CAS succeeds: we own the flow now, initialize parser
                         * 3. If CAS fails: another worker beat us, defer event
                         */
                        atomic_fetch_add(&ctx->events_misrouted, 1);

                        bool needs_parser_init = false;
                        if (event->flow_ctx->proto == FLOW_PROTO_HTTP2 &&
                            event->flow_ctx->parser.h2.session == NULL) {
                            needs_parser_init = true;
                        } else if (event->flow_ctx->proto == FLOW_PROTO_HTTP1 &&
                                   !event->flow_ctx->parser.h1.initialized) {
                            needs_parser_init = true;
                        }

                        if (needs_parser_init) {
                            /*
                             * Atomically try to re-home this flow to current worker.
                             * This ensures single-writer ownership of parser state.
                             */
                            uint32_t expected = home;
                            if (atomic_compare_exchange_strong(&event->flow_ctx->home_worker_id,
                                                               &expected, my_id)) {
                                /* Successfully re-homed - we now own this flow */
                                if (g_config.debug_mode) {
                                    fprintf(stderr, "[Worker %u] Re-homed flow_id=%u from worker %u\n",
                                            my_id, event->flow_ctx->self_id, home);
                                }

                                /* Initialize parser as the new owner */
                                if (event->flow_ctx->proto == FLOW_PROTO_HTTP2) {
                                    nghttp2_session_callbacks *cbs = http2_get_callbacks();
                                    if (cbs) {
                                        void *cb_ctx = http2_create_callback_ctx(event->flow_ctx);
                                        if (cb_ctx) {
                                            event->flow_ctx->parser.h2.callback_ctx = cb_ctx;
                                            int rv = flow_h2_session_init(event->flow_ctx, cbs, cb_ctx);
                                            if (rv == 0 && g_config.debug_mode) {
                                                fprintf(stderr, "[Worker %u] Initialized H2 session after re-home for flow_id=%u\n",
                                                        my_id, event->flow_ctx->self_id);
                                            }
                                        }
                                    }
                                } else if (event->flow_ctx->proto == FLOW_PROTO_HTTP1) {
                                    llhttp_settings_t *settings = http1_get_flow_settings();
                                    int rv = flow_h1_parser_init(event->flow_ctx, settings);
                                    if (rv == 0 && g_config.debug_mode) {
                                        fprintf(stderr, "[Worker %u] Initialized H1 parser after re-home for flow_id=%u\n",
                                                my_id, event->flow_ctx->self_id);
                                    }
                                }
                            } else {
                                /*
                                 * CAS failed - another worker changed ownership.
                                 * Defer this event for retry.
                                 */
                                if (g_config.debug_mode) {
                                    fprintf(stderr, "[Worker %u] Re-home CAS failed for flow_id=%u, deferring\n",
                                            my_id, event->flow_ctx->self_id);
                                }
                                if (defer_event_for_retry(ctx, event) == 0) {
                                    continue; /* Skip process_worker_event, will retry later */
                                }
                                /* Defer failed (queue full), process anyway */
                            }
                        } else {
                            /*
                             * Parser already initialized - misrouted but can process.
                             * This should be rare (transient routing during setup).
                             */
                            if (g_config.debug_mode) {
                                fprintf(stderr, "[Worker %u] Misrouted event for flow_id=%u "
                                        "(home=%u) - processing locally\n",
                                        my_id, event->flow_ctx->self_id, home);
                            }
                        }
                    }
                }
            }

            process_worker_event(ctx, event);
            pool_free(&ctx->event_pool, event);
            work_done++;
        }

        /* Process deferred events ready for retry */
        work_done += process_deferred_batch(ctx);

        /* Update events processed counter */
        if (work_done > 0) {
            atomic_fetch_add(&ctx->events_processed, work_done);
        }

        /* NAPI decision: sleep only if caught up with traffic */
        if (work_done < NAPI_BUDGET) {
            /* Select timeout based on queue state */
            int timeout = (atomic_load(&ctx->deferred_count) > 0)
                         ? EPOLL_RETRY_TIMEOUT_MS   /* Short timeout for fast retry */
                         : EPOLL_TIMEOUT_MS;        /* Normal timeout when idle */

            int n = epoll_wait(ctx->epoll_fd, events, 4, timeout);
            if (n > 0) {
                drain_eventfd(ctx->wakeup_fd);
                atomic_store(&ctx->has_work, false);
            }
            atomic_fetch_add(&ctx->sleep_cycles, 1);
        }
        /* else: heavy traffic - loop immediately without sleeping */
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
