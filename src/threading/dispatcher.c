/**
 * @file dispatcher.c
 * @brief Dispatcher thread implementation
 *
 * @details The dispatcher is the single consumer of the BPF ring buffer.
 * It receives SSL events from kernel eBPF probes and routes them to
 * worker threads using flow affinity hashing.
 *
 * @par Responsibilities:
 * - Poll BPF ring buffer for SSL events
 * - Route events to workers using socket_cookie (preferred) or flow_hash(pid, ssl_ctx)
 * - Handle process lifecycle events (exec, exit) directly
 * - Handle XDP flow discovery events
 * - Manage backpressure when worker queues are full
 *
 * @par Event Flow:
 * @code
 *   eBPF Probes                          Dispatcher                     Workers
 *       │                                     │                            │
 *       │ SSL_read/write event                │                            │
 *       ├────────────────────────────────────►│                            │
 *       │                                     │ socket_cookie % workers    │
 *       │                                     ├───────────────────────────►│
 *       │                                     │                            │
 *       │ Process exit event                  │                            │
 *       ├────────────────────────────────────►│                            │
 *       │                                     │ cleanup_pid() (direct)     │
 *       │                                     ├───────────────────────────►│
 * @endcode
 *
 * @par Flow Affinity:
 * Events with the same socket_cookie always go to the same worker.
 * This ensures XDP packets and SSL uprobe data for a connection
 * land on the same worker, enabling correlation without locking.
 * Falls back to (pid, ssl_ctx) hash when socket_cookie unavailable.
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "threading.h"
#include "xdp_ring.h"
#include "../util/safe_str.h"
#include "../util/process.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>  /* For ntohl/ntohs */

/**
 * @def RCU_MEMBARRIER
 * @brief Enable membarrier-based RCU synchronization
 *
 * Must be defined before including urcu headers. Uses sys_membarrier()
 * for efficient cross-CPU memory barriers instead of signal-based IPI.
 * Required for FIX M9: RCU-safe memory reclamation in flow indexes.
 */
#define RCU_MEMBARRIER
#include <urcu/urcu-memb.h>

/** Global dispatcher context for BPF callback access */
static dispatcher_ctx_t *g_dispatcher = NULL;

/** Flow janitor interval - evict stale flows every 30 seconds */
#define FLOW_JANITOR_INTERVAL_NS (30ULL * 1000000000ULL)

/**
 * @defgroup dispatcher_routing Event Routing
 * @brief Flow affinity routing to workers
 * @{
 */

/**
 * @brief Dispatch event to appropriate worker based on flow affinity
 *
 * Copies BPF event data into a worker_event_t, computes routing info,
 * and enqueues to the target worker's input ring.
 *
 * @par Backpressure Handling:
 * If worker's event pool is empty or input ring is full, the event
 * is dropped and drop counters are incremented. This prevents the
 * dispatcher from blocking.
 *
 * @par Wake-up Signaling:
 * If has_work flag was false (worker might be sleeping), writes to
 * worker's eventfd to wake it up.
 *
 * @param[in] ctx       Dispatcher context
 * @param[in] bpf_event BPF ring buffer event
 *
 * @return 0 on success, -1 if event was dropped
 */
static int dispatch_event_to_worker(dispatcher_ctx_t *ctx,
                                     const ssl_data_event_t *bpf_event) {
    if (!ctx || !bpf_event || ctx->num_workers <= 0) {
        return -1;
    }

    /*
     * === Shared Pool: Dual-Index Correlation ===
     *
     * Do flow lookup FIRST to determine proper routing.
     * If flow exists, route to its home_worker_id for cache locality.
     * This prevents misrouted events caused by cookie vs hash routing mismatch.
     *
     * Flow lifecycle:
     * 1. First SSL event (cookie=0): create via shadow_index
     * 2. XDP event arrives: flow already exists via cookie_index (or creates new)
     * 3. Later SSL event with cookie: finds flow via cookie_index
     *
     * Cookie promotion happens when we learn the cookie for an existing flow.
     */
    flow_lookup_path_t lookup_path = FLOW_PATH_NONE;
    flow_context_t *flow_ctx = flow_lookup_ex(&ctx->flow_mgr,
                                               bpf_event->socket_cookie,
                                               bpf_event->pid,
                                               bpf_event->ssl_ctx,
                                               &lookup_path);

    if (!flow_ctx) {
        /* First SSL event for this flow - create with shadow_index */
        flow_ctx = flow_get_or_create(&ctx->flow_mgr,
                                       bpf_event->socket_cookie,
                                       bpf_event->pid,
                                       bpf_event->ssl_ctx);
        lookup_path = FLOW_PATH_CREATED;
        if (flow_ctx && g_config.debug_mode) {
            fprintf(stderr, "[DEBUG] SSL: CREATED flow_id=%u (pid=%u ssl_ctx=%llx cookie=%llu)\n",
                    flow_ctx->self_id, bpf_event->pid,
                    (unsigned long long)bpf_event->ssl_ctx,
                    (unsigned long long)bpf_event->socket_cookie);
        }
    } else {
        /*
         * FIX C4: Merge SSL info into existing flow (single-writer context).
         * flow_lookup_ex() is now read-only for SPMC safety.
         * We must explicitly merge ssl_ctx/pid from SSL events into XDP-created flows.
         */
        flow_merge_ssl_info(&ctx->flow_mgr, flow_ctx,
                            bpf_event->pid, bpf_event->ssl_ctx);

        /* Show correlation path in debug mode */
        if (g_config.debug_mode) {
            const char *path_name = (lookup_path == FLOW_PATH_COOKIE) ? "COOKIE" : "SHADOW";
            fprintf(stderr, "[DEBUG] SSL: %s lookup → flow_id=%u\n",
                    path_name, flow_ctx->self_id);
        }
    }

    /*
     * Determine worker ID for routing with sticky affinity.
     *
     * CRITICAL: Once a flow is assigned to a worker, ALL events (SSL, XDP, etc.)
     * must go to that same worker. This is enforced by:
     * 1. Checking home_worker_id first (sticky routing)
     * 2. If unclaimed, compute worker_id and SET home_worker_id immediately
     *    This prevents race where XDP and SSL use different routing algorithms
     *
     * The dispatcher owns setting home_worker_id (single-writer), ensuring
     * all events for a flow are routed consistently.
     */
    int worker_id;
    if (flow_ctx) {
        /*
         * FIX: Use memory_order_acquire to ensure we see any writes
         * performed by the worker that claimed ownership.
         */
        uint32_t home = atomic_load_explicit(&flow_ctx->home_worker_id, memory_order_acquire);
        if (home != WORKER_ID_NONE && home < (uint32_t)ctx->num_workers) {
            /* Route to flow's home worker for sticky affinity */
            worker_id = (int)home;
        } else {
            /* Flow exists but unclaimed - compute and SET home_worker_id now */
            worker_id = get_worker_id_ex(bpf_event->socket_cookie,
                                          bpf_event->pid, bpf_event->ssl_ctx,
                                          ctx->num_workers);
            /* CAS to claim - if another event already claimed, use their choice */
            uint32_t expected = WORKER_ID_NONE;
            if (atomic_compare_exchange_strong(&flow_ctx->home_worker_id,
                                                &expected, (uint32_t)worker_id)) {
                if (g_config.debug_mode) {
                    fprintf(stderr, "[DEBUG] SSL: flow_id=%u claimed by worker %d\n",
                            flow_ctx->self_id, worker_id);
                }
            } else {
                /* Another event claimed first - use their worker for consistency */
                worker_id = (int)expected;
            }
        }
    } else {
        /* No flow context - use hash routing */
        worker_id = get_worker_id_ex(bpf_event->socket_cookie,
                                      bpf_event->pid, bpf_event->ssl_ctx,
                                      ctx->num_workers);
    }

    worker_ctx_t *worker = &ctx->workers[worker_id];

    /* Allocate event from worker's pool */
    worker_event_t *event = pool_alloc(&worker->event_pool);
    if (!event) {
        /* Pool empty - drop event
         * FIX L1: Use relaxed ordering for non-synchronizing stats counters */
        atomic_fetch_add_explicit(&ctx->events_dropped, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&worker->events_dropped, 1, memory_order_relaxed);
        return -1;
    }

    /* Copy BPF event data */
    event->timestamp_ns = bpf_event->timestamp_ns;
    event->delta_ns = bpf_event->delta_ns;
    event->ssl_ctx = bpf_event->ssl_ctx;
    event->socket_cookie = bpf_event->socket_cookie;
    event->pid = bpf_event->pid;
    event->tid = bpf_event->tid;
    event->uid = bpf_event->uid;
    event->event_type = bpf_event->event_type;
    event->buf_filled = bpf_event->buf_filled;
    memcpy(event->comm, bpf_event->comm, TASK_COMM_LEN);

    /* Pre-compute routing info */
    event->worker_id = worker_id;
    event->flow_hash = flow_hash(bpf_event->pid, bpf_event->ssl_ctx);

    /* Flow context already looked up above - continue with existing logic */
    if (flow_ctx && lookup_path != FLOW_PATH_CREATED) {

        /*
         * Flow exists. If this event has a cookie but the flow doesn't,
         * this is a cookie promotion opportunity.
         */
        if (bpf_event->socket_cookie != 0 && flow_ctx->socket_cookie == 0) {
            /* Cookie promotion: SSL event brings cookie to shadow-only flow */
            int prom_result = flow_promote_cookie(&ctx->flow_mgr,
                                                   bpf_event->pid,
                                                   bpf_event->ssl_ctx,
                                                   bpf_event->socket_cookie);
            if (prom_result == 0 && g_config.debug_mode) {
                fprintf(stderr, "[DEBUG] SSL: PROMOTED flow_id=%u to cookie=%llu\n",
                        flow_ctx->self_id,
                        (unsigned long long)bpf_event->socket_cookie);
            }

            /*
             * Note: xdp_poll_urgent flag removed - now that SSL and XDP are both
             * polled in the dispatcher thread, XDP events are processed in the
             * same iteration, eliminating the timing race.
             */
        }
    }

    /* Update flow context with SSL metadata */
    if (flow_ctx) {
        atomic_fetch_or(&flow_ctx->flags, FLOW_FLAG_HAS_SSL);
        if (flow_ctx->pid == 0) {
            flow_ctx->pid = bpf_event->pid;
        }
        if (flow_ctx->ssl_ctx == 0) {
            flow_ctx->ssl_ctx = bpf_event->ssl_ctx;
        }
        /*
         * Process name resolution: Get actual process name from /proc/PID/comm
         * instead of using thread name from BPF (which can be "Socket Thread"
         * for Firefox worker threads, etc.)
         */
        if (flow_ctx->comm[0] == '\0' && bpf_event->pid != 0) {
            (void)proc_get_name(bpf_event->pid, flow_ctx->comm, sizeof(flow_ctx->comm));
        }
        /* Fallback to BPF comm if /proc lookup failed */
        if (flow_ctx->comm[0] == '\0' && bpf_event->comm[0] != '\0') {
            safe_strcpy(flow_ctx->comm, sizeof(flow_ctx->comm), bpf_event->comm);
        }
        flow_ctx->uid = bpf_event->uid;
        flow_ctx->last_seen_ns = bpf_event->timestamp_ns;

        /* Transition to ACTIVE if we have both XDP and SSL data */
        if ((atomic_load(&flow_ctx->flags) & FLOW_FLAG_HAS_XDP) && flow_ctx->state == FLOW_STATE_INIT) {
            flow_ctx->state = FLOW_STATE_ACTIVE;
        }
    }

    /* Populate Shared Pool correlation fields for worker */
    event->flow_id = flow_ctx ? flow_ctx->self_id : FLOW_ID_INVALID;
    event->flow_ctx = flow_ctx;  /* Worker will validate via generation check */
    event->expected_gen = flow_ctx ? flow_ctx->generation : 0;

    /*
     * Set retry flag if we have a cookie but XDP data hasn't arrived yet.
     * Worker's deferred queue can retry later when XDP event populates the flow.
     */
    event->needs_cookie_retry = (bpf_event->socket_cookie != 0) &&
                                 (!flow_ctx || !(atomic_load(&flow_ctx->flags) & FLOW_FLAG_HAS_XDP));

    /* Copy payload */
    event->data_len = (bpf_event->buf_filled > 0) ?
                       (uint32_t)bpf_event->buf_filled : 0;
    if (event->data_len > 0 && event->data_len <= MAX_BUF_SIZE) {
        memcpy(event->data, bpf_event->data, event->data_len);
    }

    /* Acquire reference for the event we're about to dispatch */
    if (flow_ctx) {
        flow_ref_acquire(flow_ctx);
    }

    /* Enqueue to worker's input ring */
    if (!ck_ring_enqueue_spsc(&worker->in_ring, worker->in_buffer, event)) {
        /* Queue full - return event to pool and drop */
        if (flow_ctx) {
            flow_ref_release(flow_ctx);
        }
        pool_free(&worker->event_pool, event);
        /* FIX L1: Use relaxed ordering for non-synchronizing stats counters */
        atomic_fetch_add_explicit(&ctx->events_dropped, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&worker->events_dropped, 1, memory_order_relaxed);
        return -1;
    }

    /* Signal worker if it might be sleeping */
    if (!atomic_exchange(&worker->has_work, true)) {
        uint64_t val = 1;
        ssize_t n = write(worker->wakeup_fd, &val, sizeof(val));
        (void)n;  /* Ignore write result */
    }

    /* FIX L1: Use relaxed ordering for non-synchronizing stats counters */
    atomic_fetch_add_explicit(&ctx->events_dispatched, 1, memory_order_relaxed);
    return 0;
}

/**
 * @brief BPF ring buffer callback
 *
 * Called by probe_handler_poll() for each event in the BPF ring buffer.
 * Routes SSL data events to workers, handles lifecycle events directly.
 *
 * @par Event Routing:
 * - EVENT_SSL_READ/WRITE: Dispatched to worker via flow affinity
 * - EVENT_PROCESS_EXEC: Calls lifecycle callback (dynamic SSL detection)
 * - EVENT_PROCESS_EXIT: Calls dispatcher_cleanup_pid() directly
 * - EVENT_NSS_SSL_FD: Handled by probe_handler (not dispatched)
 *
 * @param[in] event   BPF event data
 * @param[in] ctx_arg Dispatcher context
 *
 * @return 0 to continue processing
 */
static int dispatcher_bpf_callback(const ssl_data_event_t *event, void *ctx_arg) {
    dispatcher_ctx_t *ctx = (dispatcher_ctx_t *)ctx_arg;

    if (!ctx || !event) {
        return 0;
    }

    /* Handle special event types that don't need dispatching to workers */
    if (event->event_type == EVENT_NSS_SSL_FD) {
        /* NSS SSL FD tracking is handled by probe_handler */
        return 0;
    }

    /* Process lifecycle events - handle directly (not dispatched to workers) */
    if (event->event_type == EVENT_PROCESS_EXIT) {
        /*
         * Flow cleanup is now handled by:
         * 1. BPF FLOW_END on FIN/RST → dispatcher_xdp_event_handler()
         * 2. flow_terminate() removes from indexes
         * 3. flow_evict_stale() janitor for timeout
         */
        return 0;
    }

    if (event->event_type == EVENT_PROCESS_EXEC) {
        /* Dynamic SSL library detection via callback */
        if (ctx->lifecycle_cb) {
            ctx->lifecycle_cb(event, ctx->lifecycle_ctx);
        }
        return 0;
    }

    /* Dispatch SSL data events to worker */
    dispatch_event_to_worker(ctx, event);
    return 0;
}

/**
 * @brief Wrapper callback matching probe_handler's expected signature
 *
 * Adapts void return type to int return type expected by BPF ring buffer.
 */
static void dispatcher_event_callback(const ssl_data_event_t *event, void *ctx) {
    dispatcher_bpf_callback(event, ctx);
}

/** @} */ /* end dispatcher_routing */

/**
 * @defgroup dispatcher_init Dispatcher Initialization
 * @brief Setup and teardown for dispatcher thread
 * @{
 */

int dispatcher_init(dispatcher_ctx_t *ctx, probe_handler_t *handler,
                    bpf_loader_t *loader, worker_ctx_t *workers, int num_workers) {
    if (!ctx || !handler || !workers || num_workers <= 0) {
        return -1;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->handler = handler;
    ctx->loader = loader;  /* May be NULL if XDP not initialized */
    ctx->workers = workers;
    ctx->num_workers = num_workers;

    atomic_store(&ctx->events_dispatched, 0);
    atomic_store(&ctx->events_dropped, 0);
    atomic_store(&ctx->running, false);

    /* Initialize Shared Pool flow manager */
    if (flow_manager_init(&ctx->flow_mgr) != 0) {
        return -1;
    }

    /* Set global for BPF callback */
    g_dispatcher = ctx;

    return 0;
}

/**
 * @brief Cleanup dispatcher context
 *
 * Clears references and global state. Should be called after
 * dispatcher thread has exited.
 */
void dispatcher_cleanup(dispatcher_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    /*
     * DO NOT call flow_manager_cleanup() here.
     * It's already handled by flow_manager_force_drain() in threading_cleanup().
     * Calling both would cause double-free of pool and index resources.
     */

    g_dispatcher = NULL;
    ctx->handler = NULL;
    ctx->workers = NULL;
    ctx->num_workers = 0;
    ctx->lifecycle_cb = NULL;
    ctx->lifecycle_ctx = NULL;
}

void dispatcher_set_lifecycle_callback(dispatcher_ctx_t *ctx, process_lifecycle_cb_t cb, void *user_ctx) {
    if (!ctx) return;
    ctx->lifecycle_cb = cb;
    ctx->lifecycle_ctx = user_ctx;
}

/** @} */ /* end dispatcher_init */

/**
 * @defgroup dispatcher_thread Dispatcher Thread Loop
 * @brief Main dispatcher thread implementation
 * @{
 */

void *dispatcher_thread_main(void *arg) {
    dispatcher_ctx_t *ctx = (dispatcher_ctx_t *)arg;
    if (!ctx || !ctx->handler) {
        return NULL;
    }

    /* Set thread name */
#ifdef _GNU_SOURCE
    pthread_setname_np(pthread_self(), "spliff-disp");
#endif

    /* FIX M9: Register this thread with liburcu.
     * Dispatcher is the single-writer for CK hash tables. It needs RCU registration
     * so call_rcu() callbacks know when the dispatcher has passed quiescent states. */
    urcu_memb_register_thread();

    /* Register our callback with probe handler */
    probe_handler_set_callback(ctx->handler, dispatcher_event_callback, ctx);

    /* Mark as running */
    atomic_store(&ctx->running, true);

    /* Flow janitor state */
    uint64_t last_janitor_run = get_time_ns();

    /* Main poll loop */
    while (atomic_load(&ctx->running)) {
        /* Poll SSL events (50ms timeout for responsive XDP polling) */
        int err = probe_handler_poll(ctx->handler, 50);
        if (err == -EINTR) {
            continue;
        }
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Dispatcher: poll error %d\n", err);
            break;
        }

        /*
         * Poll XDP events - SINGLE-WRITER: all hash table writes now on this thread.
         * This fixes the multi-writer race condition by ensuring both SSL and XDP
         * events are processed in the dispatcher thread, making CK hs SPMC mode safe.
         */
        if (ctx->loader && bpf_loader_xdp_is_active(ctx->loader)) {
            int xdp_err = bpf_loader_xdp_poll(ctx->loader, 0);  /* Non-blocking */
            if (xdp_err < 0 && xdp_err != -EINTR && g_config.debug_mode) {
                fprintf(stderr, "Dispatcher: XDP poll error %d\n", xdp_err);
            }
        }

        /* Flow janitor: evict stale flows periodically */
        uint64_t now = get_time_ns();
        if (now - last_janitor_run > FLOW_JANITOR_INTERVAL_NS) {
            /* Evict stale flows from Shared Pool */
            int evicted_pool = flow_evict_stale(&ctx->flow_mgr, now);

            if (evicted_pool > 0 && g_config.debug_mode) {
                fprintf(stderr, "[Janitor] Evicted %d flows\n", evicted_pool);
            }
            last_janitor_run = now;
        }
    }

    /* Drain any remaining XDP events before shutdown to prevent event loss */
    if (ctx->loader && bpf_loader_xdp_is_active(ctx->loader)) {
        int drained = 0;
        int remaining;
        while ((remaining = bpf_loader_xdp_poll(ctx->loader, 0)) > 0) {
            drained += remaining;
        }
        if (drained > 0 && g_config.debug_mode) {
            fprintf(stderr, "Dispatcher: drained %d XDP events on shutdown\n", drained);
        }
    }

    /* FIX M9: Unregister from liburcu before thread exit */
    urcu_memb_unregister_thread();

    return NULL;
}

/** @} */ /* end dispatcher_thread */

/**
 * @defgroup dispatcher_stats Dispatcher Statistics
 * @brief Statistics accessors for dispatcher
 * @{
 */

/**
 * @brief Get dispatcher statistics
 *
 * Returns atomic counters for events dispatched and dropped.
 * All output parameters are optional (pass NULL to skip).
 */
void dispatcher_get_stats(dispatcher_ctx_t *ctx, uint64_t *dispatched,
                          uint64_t *dropped) {
    if (!ctx) {
        if (dispatched) *dispatched = 0;
        if (dropped) *dropped = 0;
        return;
    }

    if (dispatched) *dispatched = atomic_load(&ctx->events_dispatched);
    if (dropped) *dropped = atomic_load(&ctx->events_dropped);
}

/**
 * @brief Get XDP event statistics
 *
 * Returns atomic counters for XDP flow discovery events.
 * All output parameters are optional (pass NULL to skip).
 */
void dispatcher_get_xdp_stats(dispatcher_ctx_t *ctx, uint64_t *flows_discovered,
                               uint64_t *flows_terminated, uint64_t *ambiguous,
                               uint64_t *dropped) {
    if (!ctx) {
        if (flows_discovered) *flows_discovered = 0;
        if (flows_terminated) *flows_terminated = 0;
        if (ambiguous) *ambiguous = 0;
        if (dropped) *dropped = 0;
        return;
    }

    if (flows_discovered) *flows_discovered = atomic_load(&ctx->xdp_flows_discovered);
    if (flows_terminated) *flows_terminated = atomic_load(&ctx->xdp_flows_terminated);
    if (ambiguous) *ambiguous = atomic_load(&ctx->xdp_ambiguous_events);
    if (dropped) *dropped = atomic_load(&ctx->xdp_events_dropped);
}

/**
 * @brief Get total XDP events received by dispatcher
 *
 * @param[in] ctx Dispatcher context
 * @return Total events received from ring buffer, 0 if ctx is NULL
 */
uint64_t dispatcher_get_xdp_events_received(dispatcher_ctx_t *ctx) {
    if (!ctx) return 0;
    return atomic_load(&ctx->xdp_events_received);
}

/** @} */ /* end dispatcher_stats */

/**
 * @defgroup dispatcher_xdp XDP Event Handling
 * @brief XDP flow discovery event processing
 *
 * Event type is inferred from struct size + tcp_flags:
 * - 172 bytes = xdp_payload_event_t → AMBIGUOUS (needs PCRE2-JIT)
 * - 56 bytes + FIN/RST = xdp_packet_event_t → FLOW_END
 * - 56 bytes otherwise = xdp_packet_event_t → FLOW_NEW
 * @{
 */

/** Debug sampling rate - print 1 in N events to avoid performance issues */
#define XDP_DEBUG_SAMPLE_RATE 1000

/**
 * @brief Route XDP event to appropriate worker via SPSC ring
 *
 * Single-Writer Architecture: The dispatcher creates/looks up the flow
 * BEFORE routing to workers. This ensures all hash table writes happen
 * in the dispatcher thread, making CK hs SPMC mode safe.
 *
 * @param[in] dispatcher Dispatcher context
 * @param[in] pkt        XDP packet event
 * @return true if event was routed, false if dropped (ring full)
 */
static bool dispatcher_route_xdp_to_worker(dispatcher_ctx_t *dispatcher,
                                            const xdp_packet_event_t *pkt) {
    if (!dispatcher || !pkt || dispatcher->num_workers <= 0) {
        return false;
    }

    /*
     * SINGLE-WRITER: Create/lookup flow in dispatcher (not worker).
     * This is the key architectural change for thread safety.
     * All hash table writes happen here in the single dispatcher thread.
     */
    flow_context_t *flow_ctx = flow_get_or_create(&dispatcher->flow_mgr,
                                                   pkt->socket_cookie, 0, 0);

    if (flow_ctx) {
        /* Populate XDP metadata in dispatcher (single-writer) */
        flow_update_xdp(flow_ctx, pkt);

        if (g_config.debug_mode) {
            fprintf(stderr, "[DEBUG] XDP DISPATCHER: flow_id=%u cookie=%llu HAS_XDP set\n",
                    flow_ctx->self_id, (unsigned long long)pkt->socket_cookie);
        }
    }

    /* Build ring event from packet event with pre-resolved flow */
    xdp_ring_event_t ring_evt = {
        .socket_cookie = pkt->socket_cookie,
        .flow = pkt->flow,
        .timestamp_ns = pkt->timestamp_ns,
        .ifindex = pkt->ifindex,
        .pkt_len = pkt->pkt_len,
        .category = pkt->category,
        .direction = pkt->direction,
        .flow_ctx = flow_ctx,
        .expected_gen = flow_ctx ? flow_ctx->generation : 0,
        ._pad = 0,
    };

    /*
     * Route to worker with sticky affinity - CRITICAL for thread safety.
     * Once a flow is assigned to a worker, ALL events must go there.
     * The dispatcher sets home_worker_id on first routing to prevent races.
     */
    int worker_id;
    if (flow_ctx) {
        /*
         * FIX: Use memory_order_acquire to ensure we see any writes
         * performed by the worker that claimed ownership.
         */
        uint32_t home = atomic_load_explicit(&flow_ctx->home_worker_id, memory_order_acquire);
        if (home != WORKER_ID_NONE && home < (uint32_t)dispatcher->num_workers) {
            /* Route to flow's home worker for sticky affinity */
            worker_id = (int)home;
        } else {
            /* Flow unclaimed - compute and SET home_worker_id now */
            worker_id = (int)(pkt->socket_cookie % (uint64_t)dispatcher->num_workers);
            /* CAS to claim - if another event already claimed, use their choice */
            uint32_t expected = WORKER_ID_NONE;
            if (atomic_compare_exchange_strong(&flow_ctx->home_worker_id,
                                                &expected, (uint32_t)worker_id)) {
                if (g_config.debug_mode) {
                    fprintf(stderr, "[DEBUG] XDP: flow_id=%u claimed by worker %d\n",
                            flow_ctx->self_id, worker_id);
                }
            } else {
                /* Another event claimed first - use their worker for consistency */
                worker_id = (int)expected;
            }
        }
    } else {
        worker_id = (int)(pkt->socket_cookie % (uint64_t)dispatcher->num_workers);
    }
    worker_ctx_t *worker = &dispatcher->workers[worker_id];

    /* Acquire reference for the event we're about to dispatch */
    if (flow_ctx) {
        flow_ref_acquire(flow_ctx);
    }

    /* Push to worker's SPSC ring (includes eventfd signal) */
    if (!worker->xdp_ring) {
        if (flow_ctx) {
            flow_ref_release(flow_ctx);
        }
        /* FIX L1: Use relaxed ordering for non-synchronizing stats counters */
        atomic_fetch_add_explicit(&dispatcher->xdp_events_dropped, 1, memory_order_relaxed);
        return false;
    }

    if (!xdp_ring_push(worker->xdp_ring, &ring_evt)) {
        if (flow_ctx) {
            flow_ref_release(flow_ctx);
        }
        /* FIX L1: Use relaxed ordering for non-synchronizing stats counters */
        atomic_fetch_add_explicit(&dispatcher->xdp_events_dropped, 1, memory_order_relaxed);
        return false;
    }

    return true;
}

/**
 * @brief Route AMBIGUOUS XDP event to worker via SPSC ring
 *
 * Single-Writer Architecture: The dispatcher creates/looks up the flow
 * BEFORE routing to workers. Similar to dispatcher_route_xdp_to_worker
 * but handles xdp_payload_event_t.
 *
 * @param[in] dispatcher Dispatcher context
 * @param[in] evt        XDP payload event
 * @return true if event was routed, false if dropped
 */
static bool dispatcher_route_ambiguous_to_worker(dispatcher_ctx_t *dispatcher,
                                                  const xdp_payload_event_t *evt) {
    if (!dispatcher || !evt || dispatcher->num_workers <= 0) {
        return false;
    }

    /*
     * SINGLE-WRITER: Create/lookup flow in dispatcher (not worker).
     * All hash table writes happen here in the single dispatcher thread.
     */
    flow_context_t *flow_ctx = flow_get_or_create(&dispatcher->flow_mgr,
                                                   evt->socket_cookie, 0, 0);

    if (flow_ctx) {
        /* Build a temporary packet event for flow_update_xdp */
        xdp_packet_event_t tmp_pkt = {
            .socket_cookie = evt->socket_cookie,
            .flow = evt->flow,
            .timestamp_ns = evt->timestamp_ns,
            .ifindex = 0,
            .pkt_len = (uint16_t)evt->payload_len,
            .category = evt->category,
            .direction = 0,
            .tcp_flags = 0,
        };
        flow_update_xdp(flow_ctx, &tmp_pkt);
    }

    /* Build ring event with pre-resolved flow */
    xdp_ring_event_t ring_evt = {
        .socket_cookie = evt->socket_cookie,
        .flow = evt->flow,
        .timestamp_ns = evt->timestamp_ns,
        .ifindex = 0,  /* Not available in payload event */
        .pkt_len = (uint16_t)evt->payload_len,
        .category = evt->category,
        .direction = 0,  /* Not available in payload event */
        .flow_ctx = flow_ctx,
        .expected_gen = flow_ctx ? flow_ctx->generation : 0,
        ._pad = 0,
    };

    /*
     * Route to worker with sticky affinity - CRITICAL for thread safety.
     * Once a flow is assigned to a worker, ALL events must go there.
     * The dispatcher sets home_worker_id on first routing to prevent races.
     */
    int worker_id;
    if (flow_ctx) {
        /*
         * FIX: Use memory_order_acquire to ensure we see any writes
         * performed by the worker that claimed ownership.
         */
        uint32_t home = atomic_load_explicit(&flow_ctx->home_worker_id, memory_order_acquire);
        if (home != WORKER_ID_NONE && home < (uint32_t)dispatcher->num_workers) {
            /* Route to flow's home worker for sticky affinity */
            worker_id = (int)home;
        } else {
            /* Flow unclaimed - compute and SET home_worker_id now */
            worker_id = (int)(evt->socket_cookie % (uint64_t)dispatcher->num_workers);
            /* CAS to claim - if another event already claimed, use their choice */
            uint32_t expected = WORKER_ID_NONE;
            if (atomic_compare_exchange_strong(&flow_ctx->home_worker_id,
                                                &expected, (uint32_t)worker_id)) {
                if (g_config.debug_mode) {
                    fprintf(stderr, "[DEBUG] AMBIGUOUS: flow_id=%u claimed by worker %d\n",
                            flow_ctx->self_id, worker_id);
                }
            } else {
                /* Another event claimed first - use their worker for consistency */
                worker_id = (int)expected;
            }
        }
    } else {
        worker_id = (int)(evt->socket_cookie % (uint64_t)dispatcher->num_workers);
    }
    worker_ctx_t *worker = &dispatcher->workers[worker_id];

    /* Acquire reference for the event we're about to dispatch */
    if (flow_ctx) {
        flow_ref_acquire(flow_ctx);
    }

    if (!worker->xdp_ring) {
        if (flow_ctx) {
            flow_ref_release(flow_ctx);
        }
        /* FIX L1: Use relaxed ordering for non-synchronizing stats counters */
        atomic_fetch_add_explicit(&dispatcher->xdp_events_dropped, 1, memory_order_relaxed);
        return false;
    }

    if (!xdp_ring_push(worker->xdp_ring, &ring_evt)) {
        if (flow_ctx) {
            flow_ref_release(flow_ctx);
        }
        /* FIX L1: Use relaxed ordering for non-synchronizing stats counters */
        atomic_fetch_add_explicit(&dispatcher->xdp_events_dropped, 1, memory_order_relaxed);
        return false;
    }

    return true;
}

/**
 * @brief Get human-readable category name for display
 */
static const char *xdp_category_name(uint8_t category) {
    switch (category) {
        case XDP_CAT_TLS_TCP:     return "TLS/TCP";
        case XDP_CAT_QUIC:        return "QUIC";
        case XDP_CAT_PLAIN_HTTP:  return "HTTP";
        case XDP_CAT_H2_PREFACE:  return "H2-Preface";
        case XDP_CAT_OTHER:       return "Other";
        case XDP_CAT_UNKNOWN:     return "Unknown";
        default:                   return "?";
    }
}

/**
 * @brief Format IPv4 address for display
 *
 * Converts network-byte-order IP to dotted-decimal string.
 */
static void format_ipv4(uint32_t ip_net, char *buf, size_t buf_size) {
    uint32_t ip = ntohl(ip_net);
    snprintf(buf, buf_size, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF,
             (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF,
             ip & 0xFF);
}

int dispatcher_xdp_event_handler(void *ctx, void *data, size_t data_sz) {
    dispatcher_ctx_t *dispatcher = (dispatcher_ctx_t *)ctx;

    if (!dispatcher || !data) {
        return 0;  /* Continue processing */
    }

    /* Track total events received for debugging ring buffer consumption
     * FIX L1: Use relaxed ordering for non-synchronizing stats counters */
    atomic_fetch_add_explicit(&dispatcher->xdp_events_received, 1, memory_order_relaxed);

    /* Sampling counter for debug output
     * FIX L1: Use relaxed ordering for non-synchronizing stats counters */
    uint64_t sample_count = atomic_fetch_add_explicit(&dispatcher->xdp_debug_samples, 1, memory_order_relaxed);
    bool should_debug = g_config.debug_mode &&
                        (sample_count % XDP_DEBUG_SAMPLE_RATE == 0);

    /* === Event Type Inference from Struct Size === */

    if (data_sz == sizeof(xdp_payload_event_t)) {
        /* ==================== AMBIGUOUS EVENT ====================
         * 172-byte payload event - needs PCRE2-JIT classification
         */
        const xdp_payload_event_t *payload_evt = (const xdp_payload_event_t *)data;

        /* FIX L1: Use relaxed ordering for non-synchronizing stats counters */
        atomic_fetch_add_explicit(&dispatcher->xdp_ambiguous_events, 1, memory_order_relaxed);

        if (should_debug) {
            char src_ip[16], dst_ip[16];
            format_ipv4(payload_evt->flow.saddr, src_ip, sizeof(src_ip));
            format_ipv4(payload_evt->flow.daddr, dst_ip, sizeof(dst_ip));

            fprintf(stderr,
                "[XDP] AMBIGUOUS: %s:%u -> %s:%u [%s] cookie=%lu len=%u\n",
                src_ip, ntohs(payload_evt->flow.sport),
                dst_ip, ntohs(payload_evt->flow.dport),
                xdp_category_name(payload_evt->category),
                (unsigned long)payload_evt->socket_cookie,
                payload_evt->payload_len);

            /* Show payload hex dump (first 32 bytes) */
            if (payload_evt->payload_len > 0) {
                fprintf(stderr, "  Payload: ");
                uint32_t dump_len = payload_evt->payload_len;
                if (dump_len > 32) dump_len = 32;
                for (uint32_t i = 0; i < dump_len; i++) {
                    fprintf(stderr, "%02x ", payload_evt->payload[i]);
                }
                if (payload_evt->payload_len > 32) {
                    fprintf(stderr, "...");
                }
                fprintf(stderr, "\n");
            }
        }

        /*
         * PHASE 3 FIX: Route AMBIGUOUS events to workers via SPSC ring.
         * Workers will set FLOW_FLAG_HAS_XDP before processing SSL events.
         */
        if (payload_evt->socket_cookie != 0) {
            dispatcher_route_ambiguous_to_worker(dispatcher, payload_evt);

            if (should_debug) {
                fprintf(stderr, "[DEBUG] AMBIGUOUS: routed to worker (cookie=%llu)\n",
                        (unsigned long long)payload_evt->socket_cookie);
            }
        }

        /* TODO: Queue for PCRE2-JIT classification
         * dispatcher_queue_ambiguous_event(dispatcher, payload_evt);
         */

    } else if (data_sz == sizeof(xdp_packet_event_t)) {
        /* ==================== PACKET EVENT (metadata-only) ====================
         * 56-byte metadata event - infer sub-type from tcp_flags
         */
        const xdp_packet_event_t *packet_evt = (const xdp_packet_event_t *)data;

        if (packet_evt->tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST)) {
            /* ==================== FLOW_END ====================
             * Flow terminated (FIN or RST)
             */
            /* FIX L1: Use relaxed ordering for non-synchronizing stats counters */
            atomic_fetch_add_explicit(&dispatcher->xdp_flows_terminated, 1, memory_order_relaxed);

            /* Terminate flow from Shared Pool if present */
            flow_context_t *flow_ctx = flow_lookup(&dispatcher->flow_mgr,
                                                    packet_evt->socket_cookie,
                                                    0, 0);
            if (flow_ctx) {
                flow_terminate(&dispatcher->flow_mgr, flow_ctx);
            }

            if (should_debug) {
                char src_ip[16], dst_ip[16];
                format_ipv4(packet_evt->flow.saddr, src_ip, sizeof(src_ip));
                format_ipv4(packet_evt->flow.daddr, dst_ip, sizeof(dst_ip));

                const char *flag_name = (packet_evt->tcp_flags & TCP_FLAG_FIN)
                    ? "FIN" : "RST";

                fprintf(stderr,
                    "[XDP] FLOW_END (%s): %s:%u -> %s:%u [%s] cookie=%lu\n",
                    flag_name,
                    src_ip, ntohs(packet_evt->flow.sport),
                    dst_ip, ntohs(packet_evt->flow.dport),
                    xdp_category_name(packet_evt->category),
                    (unsigned long)packet_evt->socket_cookie);
            }

        } else {
            /* ==================== FLOW_NEW ====================
             * New flow discovered (category != UNKNOWN)
             *
             * PHASE 3 FIX: Route XDP events to workers via SPSC ring.
             * Workers set FLOW_FLAG_HAS_XDP before processing SSL events,
             * ensuring proper correlation timing.
             */
            /* FIX L1: Use relaxed ordering for non-synchronizing stats counters */
            atomic_fetch_add_explicit(&dispatcher->xdp_flows_discovered, 1, memory_order_relaxed);

            /*
             * Route to worker for HAS_XDP flag setting.
             * Worker will handle flow lookup/creation and set the flag
             * BEFORE processing any SSL events in the same iteration.
             */
            if (packet_evt->socket_cookie != 0) {
                dispatcher_route_xdp_to_worker(dispatcher, packet_evt);
            }

            if (should_debug) {
                char src_ip[16], dst_ip[16];
                format_ipv4(packet_evt->flow.saddr, src_ip, sizeof(src_ip));
                format_ipv4(packet_evt->flow.daddr, dst_ip, sizeof(dst_ip));

                fprintf(stderr,
                    "[XDP] FLOW_NEW: %s:%u -> %s:%u [%s] cookie=%lu if=%u → worker\n",
                    src_ip, ntohs(packet_evt->flow.sport),
                    dst_ip, ntohs(packet_evt->flow.dport),
                    xdp_category_name(packet_evt->category),
                    (unsigned long)packet_evt->socket_cookie,
                    packet_evt->ifindex);
            }
        }

    } else {
        /* Unknown struct size - should not happen
         * FIX L1: Use relaxed ordering for non-synchronizing stats counters */
        atomic_fetch_add_explicit(&dispatcher->xdp_events_dropped, 1, memory_order_relaxed);

        if (should_debug) {
            fprintf(stderr, "[XDP] WARNING: Unknown event size %zu "
                    "(expected %zu or %zu)\n",
                    data_sz,
                    sizeof(xdp_packet_event_t),
                    sizeof(xdp_payload_event_t));
        }
    }

    return 0;  /* Continue processing */
}

/** @} */ /* end dispatcher_xdp */
