/**
 * @file state.c
 * @brief Per-worker state management
 *
 * @details Each worker thread has isolated state for:
 * - HTTP/2 connections and streams (nghttp2 sessions, HPACK contexts)
 * - ALPN cache (protocol negotiation results)
 * - Pending body buffers (chunked response assembly)
 * - Decompression scratch buffers
 *
 * @par Connection Affinity:
 * The same (pid, ssl_ctx) pair always routes to the same worker via
 * flow_hash(). This eliminates the need for any locking on per-worker
 * state - each worker is the sole accessor of its state.
 *
 * @par Memory Layout (per worker):
 * @code
 *   worker_state_t
 *       │
 *       ├── h2_connections[]      [16 slots, LRU eviction]
 *       │       └── nghttp2_session, HPACK inflater, response_buf
 *       │
 *       ├── h2_streams[]          [128 slots, pre-allocated body_bufs]
 *       │       └── request/response state, headers[], body_buf
 *       │
 *       ├── alpn_cache[]          [32 slots, FIFO eviction]
 *       ├── pending_bodies[]      [4 slots, on-demand accum_buf]
 *       ├── h1_request_cache[]    [16 slots]
 *       ├── decomp_buf            [MAX_BODY_BUFFER, shared scratch]
 *       └── body_buf              [MAX_BODY_BUFFER, HTTP/1 parsing]
 * @endcode
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "threading.h"
#include "../util/safe_str.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include <nghttp2/nghttp2.h>

/**
 * @brief Thread-local storage for current worker state
 *
 * Set during worker thread startup via set_current_worker_state().
 * Allows protocol parsers to access per-worker caches without
 * passing state through every function call.
 */
static __thread worker_state_t *tls_worker_state = NULL;

/**
 * @brief Get current worker's state from thread-local storage
 *
 * @return Worker state pointer, or NULL if not in a worker thread
 */
worker_state_t *get_current_worker_state(void) {
    return tls_worker_state;
}

void set_current_worker_state(worker_state_t *state) {
    tls_worker_state = state;
}

/**
 * @brief Get current time in nanoseconds
 *
 * Uses CLOCK_MONOTONIC for consistent timestamps that don't jump
 * during system time adjustments.
 *
 * @return Nanoseconds since arbitrary epoch (suitable for deltas)
 */
uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

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

    /* Create nghttp2 session callbacks (thread-local copy) */
    if (nghttp2_session_callbacks_new(&state->h2_callbacks) != 0) {
        fprintf(stderr, "Worker %d: failed to create nghttp2 callbacks\n", worker_id);
        goto cleanup;
    }

    /* Note: The actual callback setup will be done by http2 module
     * when it's updated to use per-worker state. For now, we just
     * create the callback object. */

    state->initialized = true;
    return 0;

cleanup:
    worker_state_cleanup(state);
    return -1;
}

/**
 * @brief Cleanup per-worker state
 *
 * Frees all allocated resources for a worker including:
 * - nghttp2 sessions and HPACK inflaters
 * - HTTP/2 connection response buffers
 * - Stream body buffers
 * - Pending body accumulation buffers
 * - Decompression and parsing scratch buffers
 * - nghttp2 callback structure
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
                if (conns[i].server_session) {
                    nghttp2_session_del(conns[i].server_session);
                    conns[i].server_session = NULL;
                }
                if (conns[i].response_inflater) {
                    nghttp2_hd_inflate_del(conns[i].response_inflater);
                    conns[i].response_inflater = NULL;
                }
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

    /* Free buffers */
    if (state->decomp_buf) {
        free(state->decomp_buf);
        state->decomp_buf = NULL;
    }

    if (state->body_buf) {
        free(state->body_buf);
        state->body_buf = NULL;
    }

    /* Free nghttp2 callbacks */
    if (state->h2_callbacks) {
        nghttp2_session_callbacks_del(state->h2_callbacks);
        state->h2_callbacks = NULL;
    }

    state->initialized = false;
}

/**
 * @defgroup state_h2conn HTTP/2 Connection Management
 * @brief Worker-local HTTP/2 connection pool operations
 * @{
 */

/**
 * @brief Find or create HTTP/2 connection for (pid, ssl_ctx)
 *
 * Looks up existing connection in worker's pool. If not found and
 * create=true, allocates a new slot (evicting LRU if pool is full).
 *
 * @par LRU Eviction:
 * When pool is full, the connection with oldest last_activity_ns is
 * evicted. This cleans up associated streams and nghttp2 resources.
 *
 * @par New Connection Setup:
 * - Allocates response reassembly buffer (H2_REASSEMBLY_BUF_SIZE)
 * - Creates HPACK inflater for response header decoding
 * - nghttp2_session is created lazily when first frame is processed
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

    /* Create HPACK inflater */
    if (nghttp2_hd_inflate_new(&slot->response_inflater) != 0) {
        free(slot->response_buf);
        slot->active = false;
        return NULL;
    }

    state->h2_connection_count++;
    return slot;
}

/**
 * @brief Cleanup HTTP/2 connection and associated resources
 *
 * Destroys nghttp2 session, HPACK inflater, response buffer, and
 * all streams associated with this connection.
 */
void worker_cleanup_h2_connection(worker_state_t *state, h2_connection_local_t *conn) {
    if (!state || !conn || !conn->active) {
        return;
    }

    if (conn->server_session) {
        nghttp2_session_del(conn->server_session);
        conn->server_session = NULL;
    }
    if (conn->response_inflater) {
        nghttp2_hd_inflate_del(conn->response_inflater);
        conn->response_inflater = NULL;
    }

    if (conn->response_buf) {
        free(conn->response_buf);
        conn->response_buf = NULL;
    }

    /* Cleanup associated streams */
    worker_cleanup_h2_streams_for_connection(state, conn->pid, conn->ssl_ctx);

    conn->active = false;
    state->h2_connection_count--;
}

/** @} */ /* end state_h2conn */

/**
 * @defgroup state_h2stream HTTP/2 Stream Management
 * @brief Worker-local HTTP/2 stream pool operations
 * @{
 */

/**
 * @brief Find or create HTTP/2 stream for (pid, ssl_ctx, stream_id)
 *
 * Looks up existing stream in worker's pool. If not found and create=true,
 * allocates a new slot. Prefers evicting closed streams before failing.
 *
 * @par Body Buffer Preservation:
 * Stream body_bufs are pre-allocated during worker_state_init() and
 * preserved across stream reuse. Only the metadata is cleared.
 *
 * @par Eviction Strategy:
 * 1. First try to find an empty (inactive) slot
 * 2. If none, evict a stream in H2_STREAM_CLOSED state
 * 3. If still none, return NULL (caller should retry later)
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

/**
 * @brief Free HTTP/2 stream (clear metadata but preserve body_buf)
 *
 * Clears all stream state except the pre-allocated body_buf, which
 * is reused for the next stream in this slot.
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

/**
 * @brief Cleanup all streams for a connection
 *
 * Called when connection closes. Frees all streams matching the
 * (pid, ssl_ctx) pair.
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

/** @} */ /* end state_h2stream */
