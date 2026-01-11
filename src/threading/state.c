/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * state.c - Per-worker state management
 *
 * Each worker thread has isolated state for:
 * - HTTP/2 connections and streams
 * - ALPN cache
 * - Pending body buffers
 * - Decompression scratch buffers
 *
 * Connection affinity (same pid+ssl_ctx → same worker) eliminates
 * the need for any locking on this state.
 */

#include "threading.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifdef HAVE_NGHTTP2
#include <nghttp2/nghttp2.h>
#endif

/* Thread-local storage for current worker state */
static __thread worker_state_t *tls_worker_state = NULL;

/*
 * Get current worker's state from thread-local storage
 */
worker_state_t *get_current_worker_state(void) {
    return tls_worker_state;
}

/*
 * Set current worker's state in thread-local storage
 */
void set_current_worker_state(worker_state_t *state) {
    tls_worker_state = state;
}

/*
 * Get current time in nanoseconds
 */
uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/*
 * Initialize per-worker state
 *
 * Allocates all buffers and initializes data structures for a worker.
 * This is called once per worker thread during startup.
 *
 * @param state      Worker state to initialize
 * @param worker_id  Worker ID (0 to num_workers-1)
 *
 * @return 0 on success, -1 on failure
 */
int worker_state_init(worker_state_t *state, int worker_id) {
    if (!state) {
        return -1;
    }

    memset(state, 0, sizeof(*state));
    state->worker_id = worker_id;

    /* Allocate HTTP/2 connection pool */
    state->h2_connection_capacity = MAX_H2_SESSIONS_PER_WORKER;
    size_t conn_size = state->h2_connection_capacity * sizeof(h2_connection_local_t);
    state->h2_connections = aligned_alloc(64, conn_size);
    if (!state->h2_connections) {
        fprintf(stderr, "Worker %d: failed to allocate H2 connections\n", worker_id);
        goto cleanup;
    }
    memset(state->h2_connections, 0, conn_size);

    /* Allocate HTTP/2 stream pool */
    state->h2_stream_capacity = MAX_H2_STREAMS_PER_WORKER;
    size_t stream_size = state->h2_stream_capacity * sizeof(h2_stream_local_t);
    state->h2_streams = aligned_alloc(64, stream_size);
    if (!state->h2_streams) {
        fprintf(stderr, "Worker %d: failed to allocate H2 streams\n", worker_id);
        goto cleanup;
    }
    memset(state->h2_streams, 0, stream_size);

    /* Allocate body buffers for each stream slot */
    h2_stream_local_t *streams = (h2_stream_local_t *)state->h2_streams;
    for (int i = 0; i < state->h2_stream_capacity; i++) {
        streams[i].body_buf = aligned_alloc(64, H2_BODY_BUFFER_SIZE);
        if (!streams[i].body_buf) {
            fprintf(stderr, "Worker %d: failed to allocate stream %d body buffer\n",
                    worker_id, i);
            /* Clean up already allocated buffers */
            for (int j = 0; j < i; j++) {
                free(streams[j].body_buf);
                streams[j].body_buf = NULL;
            }
            goto cleanup;
        }
        streams[i].body_buf_size = H2_BODY_BUFFER_SIZE;
    }

    /* Allocate decompression buffer */
    state->decomp_buf_size = MAX_BODY_BUFFER;
    state->decomp_buf = aligned_alloc(64, state->decomp_buf_size);
    if (!state->decomp_buf) {
        fprintf(stderr, "Worker %d: failed to allocate decompression buffer\n", worker_id);
        goto cleanup;
    }

    /* Allocate HTTP/1 body buffer */
    state->body_buf_size = MAX_BODY_BUFFER;
    state->body_buf = aligned_alloc(64, state->body_buf_size);
    if (!state->body_buf) {
        fprintf(stderr, "Worker %d: failed to allocate body buffer\n", worker_id);
        goto cleanup;
    }

    /* Allocate pending body accumulation buffers */
    for (int i = 0; i < MAX_PENDING_BODIES_PER_WORKER; i++) {
        state->pending_bodies[i].accum_buf = NULL;  /* Allocated on demand */
        state->pending_bodies[i].accum_capacity = 0;
    }

#ifdef HAVE_NGHTTP2
    /* Create nghttp2 session callbacks (thread-local copy) */
    if (nghttp2_session_callbacks_new(&state->h2_callbacks) != 0) {
        fprintf(stderr, "Worker %d: failed to create nghttp2 callbacks\n", worker_id);
        goto cleanup;
    }

    /* Note: The actual callback setup will be done by http2 module
     * when it's updated to use per-worker state. For now, we just
     * create the callback object. */
#endif

    state->initialized = true;
    return 0;

cleanup:
    worker_state_cleanup(state);
    return -1;
}

/*
 * Cleanup per-worker state
 *
 * Frees all allocated resources for a worker.
 */
void worker_state_cleanup(worker_state_t *state) {
    if (!state) {
        return;
    }

    /* Free HTTP/2 stream body buffers */
    if (state->h2_streams) {
        h2_stream_local_t *streams = (h2_stream_local_t *)state->h2_streams;
        for (int i = 0; i < state->h2_stream_capacity; i++) {
            if (streams[i].body_buf) {
                free(streams[i].body_buf);
                streams[i].body_buf = NULL;
            }
        }
    }

    /* Free HTTP/2 connection resources */
    if (state->h2_connections) {
        h2_connection_local_t *conns = (h2_connection_local_t *)state->h2_connections;
        for (int i = 0; i < state->h2_connection_capacity; i++) {
            if (conns[i].active) {
#ifdef HAVE_NGHTTP2
                if (conns[i].server_session) {
                    nghttp2_session_del(conns[i].server_session);
                    conns[i].server_session = NULL;
                }
                if (conns[i].response_inflater) {
                    nghttp2_hd_inflate_del(conns[i].response_inflater);
                    conns[i].response_inflater = NULL;
                }
#endif
                if (conns[i].response_buf) {
                    free(conns[i].response_buf);
                    conns[i].response_buf = NULL;
                }
            }
        }
        free(state->h2_connections);
        state->h2_connections = NULL;
    }

    /* Free HTTP/2 stream pool */
    if (state->h2_streams) {
        free(state->h2_streams);
        state->h2_streams = NULL;
    }

    /* Free pending body accumulation buffers */
    for (int i = 0; i < MAX_PENDING_BODIES_PER_WORKER; i++) {
        if (state->pending_bodies[i].accum_buf) {
            free(state->pending_bodies[i].accum_buf);
            state->pending_bodies[i].accum_buf = NULL;
        }
    }

    /* Free buffers */
    if (state->decomp_buf) {
        free(state->decomp_buf);
        state->decomp_buf = NULL;
    }

    if (state->body_buf) {
        free(state->body_buf);
        state->body_buf = NULL;
    }

#ifdef HAVE_NGHTTP2
    /* Free nghttp2 callbacks */
    if (state->h2_callbacks) {
        nghttp2_session_callbacks_del(state->h2_callbacks);
        state->h2_callbacks = NULL;
    }
#endif

    state->initialized = false;
}

/* ============================================================================
 * Per-Worker HTTP/2 Connection Management
 * ============================================================================ */

/*
 * Find or create HTTP/2 connection for (pid, ssl_ctx) in worker's pool
 */
h2_connection_local_t *worker_get_h2_connection(worker_state_t *state,
                                                  uint32_t pid, uint64_t ssl_ctx,
                                                  bool create) {
    if (!state || !state->h2_connections) {
        return NULL;
    }

    h2_connection_local_t *conns = (h2_connection_local_t *)state->h2_connections;

    /* Find existing */
    for (int i = 0; i < state->h2_connection_capacity; i++) {
        if (conns[i].active &&
            conns[i].pid == pid &&
            conns[i].ssl_ctx == ssl_ctx) {
            conns[i].last_activity_ns = get_time_ns();
            return &conns[i];
        }
    }

    if (!create) {
        return NULL;
    }

    /* Find empty slot */
    h2_connection_local_t *slot = NULL;
    for (int i = 0; i < state->h2_connection_capacity; i++) {
        if (!conns[i].active) {
            slot = &conns[i];
            break;
        }
    }

    /* If no empty slot, evict LRU */
    if (!slot) {
        uint64_t oldest_time = UINT64_MAX;
        int oldest_idx = 0;
        for (int i = 0; i < state->h2_connection_capacity; i++) {
            if (conns[i].last_activity_ns < oldest_time) {
                oldest_time = conns[i].last_activity_ns;
                oldest_idx = i;
            }
        }
        /* Cleanup old connection */
        worker_cleanup_h2_connection(state, &conns[oldest_idx]);
        slot = &conns[oldest_idx];
    }

    /* Initialize new connection */
    memset(slot, 0, sizeof(*slot));
    slot->pid = pid;
    slot->ssl_ctx = ssl_ctx;
    slot->active = true;
    slot->last_activity_ns = get_time_ns();

    /* Allocate response buffer */
    slot->response_buf = malloc(H2_REASSEMBLY_BUF_SIZE);
    if (!slot->response_buf) {
        slot->active = false;
        return NULL;
    }
    slot->response_buf_len = 0;

#ifdef HAVE_NGHTTP2
    /* Create HPACK inflater */
    if (nghttp2_hd_inflate_new(&slot->response_inflater) != 0) {
        free(slot->response_buf);
        slot->active = false;
        return NULL;
    }
#endif

    state->h2_connection_count++;
    return slot;
}

/*
 * Cleanup HTTP/2 connection
 */
void worker_cleanup_h2_connection(worker_state_t *state, h2_connection_local_t *conn) {
    if (!state || !conn || !conn->active) {
        return;
    }

#ifdef HAVE_NGHTTP2
    if (conn->server_session) {
        nghttp2_session_del(conn->server_session);
        conn->server_session = NULL;
    }
    if (conn->response_inflater) {
        nghttp2_hd_inflate_del(conn->response_inflater);
        conn->response_inflater = NULL;
    }
#endif

    if (conn->response_buf) {
        free(conn->response_buf);
        conn->response_buf = NULL;
    }

    /* Cleanup associated streams */
    worker_cleanup_h2_streams_for_connection(state, conn->pid, conn->ssl_ctx);

    conn->active = false;
    state->h2_connection_count--;
}

/* ============================================================================
 * Per-Worker HTTP/2 Stream Management
 * ============================================================================ */

/*
 * Find or create HTTP/2 stream for (pid, ssl_ctx, stream_id) in worker's pool
 */
h2_stream_local_t *worker_get_h2_stream(worker_state_t *state,
                                          uint32_t pid, uint64_t ssl_ctx,
                                          int32_t stream_id, bool create) {
    if (!state || !state->h2_streams) {
        return NULL;
    }

    h2_stream_local_t *streams = (h2_stream_local_t *)state->h2_streams;

    /* Find existing */
    for (int i = 0; i < state->h2_stream_capacity; i++) {
        if (streams[i].active &&
            streams[i].pid == pid &&
            streams[i].ssl_ctx == ssl_ctx &&
            streams[i].stream_id == stream_id) {
            return &streams[i];
        }
    }

    if (!create) {
        return NULL;
    }

    /* Find empty slot */
    h2_stream_local_t *slot = NULL;
    for (int i = 0; i < state->h2_stream_capacity; i++) {
        if (!streams[i].active) {
            slot = &streams[i];
            break;
        }
    }

    /* If no empty slot, evict closed stream */
    if (!slot) {
        for (int i = 0; i < state->h2_stream_capacity; i++) {
            if (streams[i].state == H2_STREAM_CLOSED) {
                worker_free_h2_stream(state, &streams[i]);
                slot = &streams[i];
                break;
            }
        }
    }

    if (!slot) {
        return NULL;
    }

    /* Initialize stream (body_buf already allocated in state_init) */
    uint8_t *saved_body_buf = slot->body_buf;
    size_t saved_body_buf_size = slot->body_buf_size;

    memset(slot, 0, sizeof(*slot));
    slot->pid = pid;
    slot->ssl_ctx = ssl_ctx;
    slot->stream_id = stream_id;
    slot->active = true;
    slot->state = H2_STREAM_OPEN;
    slot->body_buf = saved_body_buf;
    slot->body_buf_size = saved_body_buf_size;
    slot->body_len = 0;

    state->h2_stream_count++;
    return slot;
}

/*
 * Free HTTP/2 stream (clear but keep body_buf allocated)
 */
void worker_free_h2_stream(worker_state_t *state, h2_stream_local_t *stream) {
    if (!state || !stream || !stream->active) {
        return;
    }

    /* Preserve body_buf - it's pre-allocated */
    uint8_t *saved_body_buf = stream->body_buf;
    size_t saved_body_buf_size = stream->body_buf_size;

    memset(stream, 0, sizeof(*stream));
    stream->body_buf = saved_body_buf;
    stream->body_buf_size = saved_body_buf_size;

    state->h2_stream_count--;
}

/*
 * Cleanup all streams for a connection
 */
void worker_cleanup_h2_streams_for_connection(worker_state_t *state,
                                                uint32_t pid, uint64_t ssl_ctx) {
    if (!state || !state->h2_streams) {
        return;
    }

    h2_stream_local_t *streams = (h2_stream_local_t *)state->h2_streams;
    for (int i = 0; i < state->h2_stream_capacity; i++) {
        if (streams[i].active &&
            streams[i].pid == pid &&
            streams[i].ssl_ctx == ssl_ctx) {
            worker_free_h2_stream(state, &streams[i]);
        }
    }
}

/* ============================================================================
 * Per-Worker ALPN Cache
 * ============================================================================ */

/*
 * Get ALPN protocol for (pid, ssl_ctx)
 */
const char *worker_get_alpn(worker_state_t *state, uint32_t pid, uint64_t ssl_ctx) {
    if (!state) {
        return "";
    }

    for (int i = 0; i < MAX_ALPN_CACHE_PER_WORKER; i++) {
        if (state->alpn_cache[i].active &&
            state->alpn_cache[i].pid == pid &&
            state->alpn_cache[i].ssl_ctx == ssl_ctx) {
            return state->alpn_cache[i].alpn_proto;
        }
    }
    return "";
}

/*
 * Set ALPN protocol for (pid, ssl_ctx)
 */
void worker_set_alpn(worker_state_t *state, uint32_t pid, uint64_t ssl_ctx,
                       const char *alpn) {
    if (!state || !alpn) {
        return;
    }

    /* Check if already exists */
    for (int i = 0; i < MAX_ALPN_CACHE_PER_WORKER; i++) {
        if (state->alpn_cache[i].active &&
            state->alpn_cache[i].pid == pid &&
            state->alpn_cache[i].ssl_ctx == ssl_ctx) {
            strncpy(state->alpn_cache[i].alpn_proto, alpn,
                    sizeof(state->alpn_cache[i].alpn_proto) - 1);
            return;
        }
    }

    /* Find empty slot */
    for (int i = 0; i < MAX_ALPN_CACHE_PER_WORKER; i++) {
        if (!state->alpn_cache[i].active) {
            state->alpn_cache[i].pid = pid;
            state->alpn_cache[i].ssl_ctx = ssl_ctx;
            strncpy(state->alpn_cache[i].alpn_proto, alpn,
                    sizeof(state->alpn_cache[i].alpn_proto) - 1);
            state->alpn_cache[i].active = true;
            state->alpn_cache_count++;
            return;
        }
    }

    /* Evict first entry (simple LRU approximation) */
    state->alpn_cache[0].pid = pid;
    state->alpn_cache[0].ssl_ctx = ssl_ctx;
    strncpy(state->alpn_cache[0].alpn_proto, alpn,
            sizeof(state->alpn_cache[0].alpn_proto) - 1);
    state->alpn_cache[0].active = true;
}

/* ============================================================================
 * Per-Worker Pending Body Management
 * ============================================================================ */

/*
 * Find pending body for (pid, ssl_ctx)
 */
pending_body_entry_t *worker_find_pending_body(worker_state_t *state,
                                                  uint32_t pid, uint64_t ssl_ctx) {
    if (!state) {
        return NULL;
    }

    for (int i = 0; i < MAX_PENDING_BODIES_PER_WORKER; i++) {
        if (state->pending_bodies[i].active &&
            state->pending_bodies[i].pid == pid &&
            state->pending_bodies[i].ssl_ctx == ssl_ctx) {
            return &state->pending_bodies[i];
        }
    }
    return NULL;
}

/*
 * Create pending body entry
 */
pending_body_entry_t *worker_create_pending_body(worker_state_t *state,
                                                    uint32_t pid, uint64_t ssl_ctx,
                                                    size_t expected_len,
                                                    const char *content_type,
                                                    const char *content_encoding) {
    if (!state) {
        return NULL;
    }

    /* Find empty slot */
    pending_body_entry_t *slot = NULL;
    for (int i = 0; i < MAX_PENDING_BODIES_PER_WORKER; i++) {
        if (!state->pending_bodies[i].active) {
            slot = &state->pending_bodies[i];
            break;
        }
    }

    if (!slot) {
        /* Evict first entry */
        worker_clear_pending_body(state, &state->pending_bodies[0]);
        slot = &state->pending_bodies[0];
    }

    slot->pid = pid;
    slot->ssl_ctx = ssl_ctx;
    slot->expected_len = expected_len;
    slot->received_len = 0;
    slot->active = true;
    slot->header_printed = false;
    slot->needs_decompression = (content_encoding && content_encoding[0]);

    if (content_type) {
        strncpy(slot->content_type, content_type, sizeof(slot->content_type) - 1);
    }
    if (content_encoding) {
        strncpy(slot->content_encoding, content_encoding, sizeof(slot->content_encoding) - 1);
    }

    /* Allocate accumulation buffer on demand */
    if (!slot->accum_buf) {
        slot->accum_capacity = MAX_BODY_BUFFER;
        slot->accum_buf = malloc(slot->accum_capacity);
        if (!slot->accum_buf) {
            slot->active = false;
            return NULL;
        }
    }
    slot->accum_len = 0;

    state->pending_body_count++;
    return slot;
}

/*
 * Clear pending body entry
 */
void worker_clear_pending_body(worker_state_t *state, pending_body_entry_t *entry) {
    if (!state || !entry || !entry->active) {
        return;
    }

    /* Keep accum_buf allocated for reuse */
    entry->active = false;
    entry->received_len = 0;
    entry->expected_len = 0;
    entry->accum_len = 0;
    entry->header_printed = false;
    entry->content_type[0] = '\0';
    entry->content_encoding[0] = '\0';

    state->pending_body_count--;
}

/*
 * Cleanup all pending bodies for a PID
 */
void worker_cleanup_pending_bodies_pid(worker_state_t *state, uint32_t pid) {
    if (!state) {
        return;
    }

    for (int i = 0; i < MAX_PENDING_BODIES_PER_WORKER; i++) {
        if (state->pending_bodies[i].active &&
            state->pending_bodies[i].pid == pid) {
            worker_clear_pending_body(state, &state->pending_bodies[i]);
        }
    }
}
