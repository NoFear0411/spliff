/**
 * @file state.c
 * @brief Per-worker state management
 *
 * @details Each worker thread has isolated state for:
 * - Decompression scratch buffers
 * - HTTP/1 body parsing buffers
 * - nghttp2 session callbacks
 *
 * @par Connection Affinity:
 * The same (pid, ssl_ctx) pair always routes to the same worker via
 * flow_hash(). This eliminates the need for any locking on per-worker
 * state - each worker is the sole accessor of its state.
 *
 * HTTP/2 sessions are managed per-flow in flow_ctx->parser.h2.
 * - Race conditions between dispatcher and worker
 * - Shadow queue complexity for deferred cleanup
 *
 * @par Memory Layout (per worker):
 * @code
 *   worker_state_t
 *       │
 *       ├── decomp_buf            [MAX_BODY_BUFFER, shared scratch]
 *       ├── body_buf              [MAX_BODY_BUFFER, HTTP/1 parsing]
 *       └── h2_callbacks          [nghttp2 session callbacks]
 * @endcode
 *
 * SPDX-License-Identifier: AGPL-3.0-only
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
 * - Decompression and parsing scratch buffers
 * - nghttp2 callback structure
 *
 * HTTP/2 sessions are now managed per-flow and cleaned up by
 * flow_terminate() on FIN/RST events. See flow_context.c.
 */
void worker_state_cleanup(worker_state_t *state) {
    if (!state) {
        return;
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

