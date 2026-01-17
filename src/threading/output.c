/**
 * @file output.c
 * @brief Output thread implementation
 *
 * @details The output thread centralizes all formatted output from worker
 * threads to prevent interleaved output to stdout/file.
 *
 * @par Responsibilities:
 * - Collect formatted messages from all worker output queues
 * - Serialize writes to prevent interleaving
 * - Periodic and idle-triggered flushing
 * - Clean drain on shutdown
 *
 * @par Collection Strategy:
 * @code
 *   Worker 0 ──┬── out_ring ──┐
 *   Worker 1 ──┼── out_ring ──┼──► Output Thread ──► stdout/file
 *   Worker N ──┴── out_ring ──┘
 *              round-robin poll
 * @endcode
 *
 * @par Flow:
 * 1. Round-robin poll each worker's out_ring
 * 2. Dequeue up to BATCH_SIZE messages per worker per iteration
 * 3. Write to output file
 * 4. Return message to worker's output pool
 * 5. Flush periodically or when idle
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
#include <stdarg.h>
#include <unistd.h>
#include <time.h>

/**
 * @defgroup output_init Output Initialization
 * @brief Setup and teardown for output thread
 * @{
 */

/**
 * @brief Initialize output context
 *
 * Sets up the output thread context with references to worker queues
 * and output destination.
 */
int output_init(output_ctx_t *ctx, worker_ctx_t *workers, int num_workers,
                FILE *output_file) {
    if (!ctx || !workers || num_workers <= 0) {
        return -1;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->workers = workers;
    ctx->num_workers = num_workers;
    ctx->output_file = output_file ? output_file : stdout;

    atomic_store(&ctx->messages_written, 0);
    atomic_store(&ctx->bytes_written, 0);
    atomic_store(&ctx->running, false);

    return 0;
}

/**
 * @brief Cleanup output context
 *
 * Flushes output file and clears context. Does not close the file
 * (caller's responsibility if not stdout).
 */
void output_cleanup(output_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    /* Flush output file before cleanup */
    if (ctx->output_file) {
        fflush(ctx->output_file);
    }

    ctx->workers = NULL;
    ctx->num_workers = 0;
}

/** @} */ /* end output_init */

/**
 * @defgroup output_thread Output Thread Loop
 * @brief Main output thread implementation
 * @{
 */

/**
 * @brief Collect and write output messages from all workers
 *
 * Performs one round-robin pass through all worker output queues,
 * dequeueing up to BATCH_SIZE messages per worker.
 *
 * @param[in] ctx Output context
 *
 * @return Number of messages written this iteration
 *
 * @note Messages are returned to worker's output_pool after writing
 */
static int collect_and_write_output(output_ctx_t *ctx) {
    int written = 0;

    /* Round-robin poll each worker's output ring */
    for (int w = 0; w < ctx->num_workers; w++) {
        worker_ctx_t *worker = &ctx->workers[w];
        output_msg_t *msg;

        /* Dequeue up to BATCH_SIZE messages per worker per iteration */
        int batch = 0;
        while (batch < BATCH_SIZE &&
               ck_ring_dequeue_spsc(&worker->out_ring, worker->out_buffer, &msg)) {

            /* Write to output file */
            if (msg->len > 0) {
                size_t n = fwrite(msg->data, 1, msg->len, ctx->output_file);
                if (n > 0) {
                    atomic_fetch_add(&ctx->bytes_written, n);
                }
            }

            /* Return message to worker's output pool */
            pool_free(&worker->output_pool, msg);

            atomic_fetch_add(&ctx->messages_written, 1);
            written++;
            batch++;
        }
    }

    return written;
}

/**
 * @brief Output thread entry point
 *
 * Main loop for the output thread:
 * 1. Collect messages from all worker output queues
 * 2. Write to output file
 * 3. Flush periodically (every 100 iterations or when idle)
 * 4. Sleep 1ms when idle to avoid busy-spinning
 * 5. On shutdown, drain remaining messages before exiting
 *
 * @param[in] arg Pointer to output_ctx_t
 *
 * @return NULL
 */
void *output_thread_main(void *arg) {
    output_ctx_t *ctx = (output_ctx_t *)arg;
    if (!ctx) {
        return NULL;
    }

    /* Set thread name */
#ifdef _GNU_SOURCE
    pthread_setname_np(pthread_self(), "spliff-out");
#endif

    /* Mark as running */
    atomic_store(&ctx->running, true);

    int flush_counter = 0;

    /* Main output loop */
    while (atomic_load(&ctx->running)) {
        int written = collect_and_write_output(ctx);

        /* Flush periodically or when idle */
        flush_counter++;
        if (written == 0 || flush_counter >= 100) {
            fflush(ctx->output_file);
            flush_counter = 0;
        }

        /* If no work, sleep briefly */
        if (written == 0) {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };  /* 1ms */
            nanosleep(&ts, NULL);
        }
    }

    /* Final drain - collect any remaining messages */
    int total_drained = 0;
    int drained;
    do {
        drained = collect_and_write_output(ctx);
        total_drained += drained;
    } while (drained > 0);

    if (total_drained > 0) {
        fprintf(stderr, "  Output thread drained %d messages\n", total_drained);
    }

    /* Final flush */
    fflush(ctx->output_file);

    return NULL;
}

/** @} */ /* end output_thread */

/**
 * @defgroup output_helpers Output Helpers
 * @brief Worker functions for enqueueing formatted output
 * @{
 */

/**
 * @brief Allocate output message from worker's pool
 *
 * Allocates a message and initializes timestamp and worker_id.
 * Caller should fill in msg->data and msg->len, then call output_enqueue().
 *
 * @param[in] worker Worker context
 *
 * @return Message pointer, or NULL if pool exhausted
 */
output_msg_t *output_alloc(worker_ctx_t *worker) {
    if (!worker) {
        return NULL;
    }

    output_msg_t *msg = pool_alloc(&worker->output_pool);
    if (msg) {
        msg->timestamp_ns = get_time_ns();
        msg->worker_id = worker->worker_id;
        msg->sequence = 0;
        msg->len = 0;
        msg->data[0] = '\0';
    }
    return msg;
}

/**
 * @brief Enqueue output message to output thread
 *
 * Transfers ownership of the message to the output thread.
 * On failure (queue full), the message is freed back to the pool.
 *
 * @param[in] worker Worker context
 * @param[in] msg    Message to enqueue (ownership transferred)
 *
 * @return 0 on success, -1 if queue full
 */
int output_enqueue(worker_ctx_t *worker, output_msg_t *msg) {
    if (!worker || !msg) {
        return -1;
    }

    if (!ck_ring_enqueue_spsc(&worker->out_ring, worker->out_buffer, msg)) {
        /* Queue full - free message and report failure */
        pool_free(&worker->output_pool, msg);
        return -1;
    }

    return 0;
}

/**
 * @brief Format and enqueue output message (printf-style)
 *
 * Convenience function that combines output_alloc(), vsnprintf(),
 * and output_enqueue(). Suitable for simple formatted output.
 *
 * @param[in] worker Worker context
 * @param[in] fmt    printf format string
 * @param[in] ...    Format arguments
 *
 * @return 0 on success, -1 on allocation or enqueue failure
 */
int output_write(worker_ctx_t *worker, const char *fmt, ...) {
    if (!worker || !fmt) {
        return -1;
    }

    output_msg_t *msg = output_alloc(worker);
    if (!msg) {
        return -1;
    }

    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(msg->data, OUTPUT_MSG_MAX_SIZE, fmt, args);
    va_end(args);

    if (n < 0) {
        pool_free(&worker->output_pool, msg);
        return -1;
    }

    msg->len = (n < OUTPUT_MSG_MAX_SIZE) ? n : OUTPUT_MSG_MAX_SIZE - 1;
    return output_enqueue(worker, msg);
}

/** @} */ /* end output_helpers */

/**
 * @defgroup output_stats Output Statistics
 * @brief Output thread statistics accessors
 * @{
 */

/**
 * @brief Get output statistics
 *
 * Returns atomic counters for messages and bytes written.
 * All output parameters are optional (pass NULL to skip).
 */
void output_get_stats(output_ctx_t *ctx, uint64_t *messages, uint64_t *bytes) {
    if (!ctx) {
        if (messages) *messages = 0;
        if (bytes) *bytes = 0;
        return;
    }

    if (messages) *messages = atomic_load(&ctx->messages_written);
    if (bytes) *bytes = atomic_load(&ctx->bytes_written);
}

/** @} */ /* end output_stats */
