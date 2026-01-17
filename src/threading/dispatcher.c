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
 * - Route events to workers using flow_hash(pid, ssl_ctx)
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
 *       │                                     │ flow_hash(pid,ssl_ctx)     │
 *       │                                     ├───────────────────────────►│
 *       │                                     │                            │
 *       │ Process exit event                  │                            │
 *       ├────────────────────────────────────►│                            │
 *       │                                     │ cleanup_pid() (direct)     │
 *       │                                     ├───────────────────────────►│
 * @endcode
 *
 * @par Flow Affinity:
 * Events with the same (pid, ssl_ctx) always go to the same worker.
 * This ensures connection state (HTTP/2 sessions, HPACK contexts)
 * is only accessed by a single thread, eliminating locking.
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
#include <errno.h>
#include <arpa/inet.h>  /* For ntohl/ntohs */

/** Global dispatcher context for BPF callback access */
static dispatcher_ctx_t *g_dispatcher = NULL;

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

    /* Calculate worker ID using flow affinity */
    int worker_id = get_worker_id(bpf_event->pid, bpf_event->ssl_ctx,
                                   ctx->num_workers);
    worker_ctx_t *worker = &ctx->workers[worker_id];

    /* Allocate event from worker's pool */
    worker_event_t *event = pool_alloc(&worker->event_pool);
    if (!event) {
        /* Pool empty - drop event */
        atomic_fetch_add(&ctx->events_dropped, 1);
        atomic_fetch_add(&worker->events_dropped, 1);
        return -1;
    }

    /* Copy BPF event data */
    event->timestamp_ns = bpf_event->timestamp_ns;
    event->delta_ns = bpf_event->delta_ns;
    event->ssl_ctx = bpf_event->ssl_ctx;
    event->pid = bpf_event->pid;
    event->tid = bpf_event->tid;
    event->uid = bpf_event->uid;
    event->event_type = bpf_event->event_type;
    event->buf_filled = bpf_event->buf_filled;
    memcpy(event->comm, bpf_event->comm, TASK_COMM_LEN);

    /* Pre-compute routing info */
    event->worker_id = worker_id;
    event->flow_hash = flow_hash(bpf_event->pid, bpf_event->ssl_ctx);

    /* Copy payload */
    event->data_len = (bpf_event->buf_filled > 0) ?
                       (uint32_t)bpf_event->buf_filled : 0;
    if (event->data_len > 0 && event->data_len <= MAX_BUF_SIZE) {
        memcpy(event->data, bpf_event->data, event->data_len);
    }

    /* Enqueue to worker's input ring */
    if (!ck_ring_enqueue_spsc(&worker->in_ring, worker->in_buffer, event)) {
        /* Queue full - return event to pool and drop */
        pool_free(&worker->event_pool, event);
        atomic_fetch_add(&ctx->events_dropped, 1);
        atomic_fetch_add(&worker->events_dropped, 1);
        return -1;
    }

    /* Signal worker if it might be sleeping */
    if (!atomic_exchange(&worker->has_work, true)) {
        uint64_t val = 1;
        ssize_t n = write(worker->wakeup_fd, &val, sizeof(val));
        (void)n;  /* Ignore write result */
    }

    atomic_fetch_add(&ctx->events_dispatched, 1);
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
        /* Cleanup all worker resources for this PID */
        dispatcher_cleanup_pid(ctx, event->pid);
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

/**
 * @brief Initialize dispatcher context
 *
 * Sets up dispatcher with references to BPF ring buffer and worker array.
 * Does not start the dispatcher thread.
 *
 * @param[out] ctx         Dispatcher context to initialize
 * @param[in]  handler     BPF probe handler with ring buffer
 * @param[in]  workers     Array of worker contexts
 * @param[in]  num_workers Number of workers
 *
 * @return 0 on success, -1 on invalid arguments
 */
int dispatcher_init(dispatcher_ctx_t *ctx, probe_handler_t *handler,
                    worker_ctx_t *workers, int num_workers) {
    if (!ctx || !handler || !workers || num_workers <= 0) {
        return -1;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->handler = handler;
    ctx->workers = workers;
    ctx->num_workers = num_workers;

    atomic_store(&ctx->events_dispatched, 0);
    atomic_store(&ctx->events_dropped, 0);
    atomic_store(&ctx->running, false);

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

    g_dispatcher = NULL;
    ctx->handler = NULL;
    ctx->workers = NULL;
    ctx->num_workers = 0;
    ctx->lifecycle_cb = NULL;
    ctx->lifecycle_ctx = NULL;
}

/**
 * @brief Set process lifecycle callback for dynamic SSL detection
 *
 * Called when EVENT_PROCESS_EXEC is received. The callback can scan
 * the new process for SSL libraries and attach probes dynamically.
 *
 * @param[in] ctx      Dispatcher context
 * @param[in] cb       Callback function
 * @param[in] user_ctx User context passed to callback
 */
void dispatcher_set_lifecycle_callback(dispatcher_ctx_t *ctx, process_lifecycle_cb_t cb, void *user_ctx) {
    if (!ctx) return;
    ctx->lifecycle_cb = cb;
    ctx->lifecycle_ctx = user_ctx;
}

/**
 * @brief Cleanup all resources for a PID across all workers
 *
 * Called when a process exits (EVENT_PROCESS_EXIT). Iterates through
 * all workers and cleans up:
 * - HTTP/2 connections and streams
 * - Pending body buffers
 * - ALPN cache entries
 * - HTTP/1.1 request cache entries
 *
 * @param[in] ctx Dispatcher context
 * @param[in] pid Process ID that exited
 *
 * @note This accesses worker state directly, which is safe because
 *       the exit event means no more events will arrive for this PID.
 */
void dispatcher_cleanup_pid(dispatcher_ctx_t *ctx, uint32_t pid) {
    if (!ctx || !ctx->workers) return;

    for (int i = 0; i < ctx->num_workers; i++) {
        worker_state_t *state = &ctx->workers[i].state;

        /* Cleanup HTTP/2 connections and streams for this PID */
        for (int j = 0; j < MAX_H2_SESSIONS_PER_WORKER; j++) {
            h2_connection_local_t *conn = &state->h2_connections[j];
            if (conn->active && conn->pid == pid) {
                worker_cleanup_h2_connection(state, conn);
            }
        }

        /* Cleanup pending bodies for this PID */
        worker_cleanup_pending_bodies_pid(state, pid);

        /* Cleanup ALPN cache entries for this PID */
        for (int j = 0; j < MAX_ALPN_CACHE_PER_WORKER; j++) {
            if (state->alpn_cache[j].pid == pid) {
                state->alpn_cache[j].pid = 0;
                state->alpn_cache[j].ssl_ctx = 0;
                state->alpn_cache[j].alpn_proto[0] = '\0';
            }
        }

        /* Cleanup HTTP/1 request cache for this PID */
        for (int j = 0; j < MAX_H1_REQUEST_CACHE_PER_WORKER; j++) {
            if (state->h1_request_cache[j].pid == pid) {
                state->h1_request_cache[j].pid = 0;
                state->h1_request_cache[j].ssl_ctx = 0;
            }
        }
    }
}

/** @} */ /* end dispatcher_init */

/**
 * @defgroup dispatcher_thread Dispatcher Thread Loop
 * @brief Main dispatcher thread implementation
 * @{
 */

/**
 * @brief Dispatcher thread entry point
 *
 * Main loop that polls the BPF ring buffer and dispatches events.
 * Runs until running flag is cleared.
 *
 * @param[in] arg Pointer to dispatcher_ctx_t
 *
 * @return NULL
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

    /* Register our callback with probe handler */
    probe_handler_set_callback(ctx->handler, dispatcher_event_callback, ctx);

    /* Mark as running */
    atomic_store(&ctx->running, true);

    /* Main poll loop */
    while (atomic_load(&ctx->running)) {
        int err = probe_handler_poll(ctx->handler, 100);  /* 100ms timeout */
        if (err == -EINTR) {
            continue;
        }
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Dispatcher: poll error %d\n", err);
            break;
        }
    }

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

/**
 * @brief XDP event handler callback
 *
 * Called by ring_buffer__poll() for each XDP event. Event type is
 * inferred from struct size since BPF ring buffers don't carry type info.
 *
 * @par Event Types:
 * - 172 bytes (xdp_payload_event_t): AMBIGUOUS - needs PCRE2-JIT
 * - 56 bytes (xdp_packet_event_t) + FIN/RST: FLOW_END
 * - 56 bytes (xdp_packet_event_t) otherwise: FLOW_NEW
 *
 * @param[in] ctx     User context (dispatcher_ctx_t*)
 * @param[in] data    Event data
 * @param[in] data_sz Event data size
 *
 * @return 0 to continue processing
 */
int dispatcher_xdp_event_handler(void *ctx, void *data, size_t data_sz) {
    dispatcher_ctx_t *dispatcher = (dispatcher_ctx_t *)ctx;

    if (!dispatcher || !data) {
        return 0;  /* Continue processing */
    }

    /* Sampling counter for debug output */
    uint64_t sample_count = atomic_fetch_add(&dispatcher->xdp_debug_samples, 1);
    bool should_debug = g_config.debug_mode &&
                        (sample_count % XDP_DEBUG_SAMPLE_RATE == 0);

    /* === Event Type Inference from Struct Size === */

    if (data_sz == sizeof(xdp_payload_event_t)) {
        /* ==================== AMBIGUOUS EVENT ====================
         * 172-byte payload event - needs PCRE2-JIT classification
         */
        const xdp_payload_event_t *payload_evt = (const xdp_payload_event_t *)data;

        atomic_fetch_add(&dispatcher->xdp_ambiguous_events, 1);

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
            atomic_fetch_add(&dispatcher->xdp_flows_terminated, 1);

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
             */
            atomic_fetch_add(&dispatcher->xdp_flows_discovered, 1);

            if (should_debug) {
                char src_ip[16], dst_ip[16];
                format_ipv4(packet_evt->flow.saddr, src_ip, sizeof(src_ip));
                format_ipv4(packet_evt->flow.daddr, dst_ip, sizeof(dst_ip));

                fprintf(stderr,
                    "[XDP] FLOW_NEW: %s:%u -> %s:%u [%s] cookie=%lu if=%u\n",
                    src_ip, ntohs(packet_evt->flow.sport),
                    dst_ip, ntohs(packet_evt->flow.dport),
                    xdp_category_name(packet_evt->category),
                    (unsigned long)packet_evt->socket_cookie,
                    packet_evt->ifindex);
            }
        }

    } else {
        /* Unknown struct size - should not happen */
        atomic_fetch_add(&dispatcher->xdp_events_dropped, 1);

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
