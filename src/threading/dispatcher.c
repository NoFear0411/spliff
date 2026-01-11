/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * dispatcher.c - Dispatcher thread implementation
 *
 * The dispatcher thread:
 * - Polls the BPF ring buffer for SSL events
 * - Routes events to workers using flow affinity (same connection → same worker)
 * - Handles backpressure when worker queues are full
 */

#include "threading.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

/* Global dispatcher context (for BPF callback) */
static dispatcher_ctx_t *g_dispatcher = NULL;

/* ============================================================================
 * Event Dispatch
 * ============================================================================ */

/*
 * Dispatch event to appropriate worker based on flow affinity
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

/*
 * BPF ring buffer callback
 * Called by libbpf for each event in the ring buffer
 */
static int dispatcher_bpf_callback(const ssl_data_event_t *event, void *ctx_arg) {
    dispatcher_ctx_t *ctx = (dispatcher_ctx_t *)ctx_arg;

    if (!ctx || !event) {
        return 0;
    }

    /* Handle special event types that don't need dispatching */
    if (event->event_type == EVENT_NSS_SSL_FD) {
        /* NSS SSL FD tracking is handled by probe_handler */
        return 0;
    }

    /* Dispatch to worker */
    dispatch_event_to_worker(ctx, event);
    return 0;
}

/*
 * Wrapper callback that matches probe_handler's expected signature
 */
static void dispatcher_event_callback(const ssl_data_event_t *event, void *ctx) {
    dispatcher_bpf_callback(event, ctx);
}

/* ============================================================================
 * Dispatcher Initialization
 * ============================================================================ */

/*
 * Initialize dispatcher context
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

/*
 * Cleanup dispatcher context
 */
void dispatcher_cleanup(dispatcher_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    g_dispatcher = NULL;
    ctx->handler = NULL;
    ctx->workers = NULL;
    ctx->num_workers = 0;
}

/* ============================================================================
 * Dispatcher Thread
 * ============================================================================ */

/*
 * Dispatcher thread entry point
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

/* ============================================================================
 * Statistics
 * ============================================================================ */

/*
 * Get dispatcher statistics
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
