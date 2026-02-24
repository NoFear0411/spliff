/**
 * @file deferred.h
 * @brief Per-worker deferred display queue API
 *
 * Public interface for the deferred display queue used to synchronize
 * XDP correlation with HTTP message display.
 *
 * @par Problem
 * XDP events and SSL uprobe events arrive asynchronously. HTTP data from
 * SSL often arrives before XDP metadata, resulting in missing network
 * correlation (source IP, dest IP, ports) in output.
 *
 * @par Solution
 * HTTP messages without XDP info are queued with an adaptive timeout:
 * - 100ms normal timeout
 * - 20ms under load (backpressure valve)
 * - Force flush oldest 10% when queue exceeds max
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license LGPL-3.0-only
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

#ifndef SPLIFF_DEFERRED_H
#define SPLIFF_DEFERRED_H

#include "threading.h"

/**
 * @brief Initialize deferred queue with pre-allocated entries
 *
 * Pre-allocates a free list to avoid malloc in the hot path.
 *
 * @param[out] q        Queue to initialize
 * @param[in]  prealloc Number of entries to pre-allocate
 * @return 0 on success, -1 on error
 */
int deferred_queue_init(deferred_queue_t *q, size_t prealloc);

/**
 * @brief Enqueue message for deferred display
 *
 * Copies the HTTP message and queues it for later display when XDP
 * correlation data arrives or timeout expires.
 *
 * @param[in] q        Deferred queue
 * @param[in] msg      HTTP message (copied)
 * @param[in] flow_ctx Flow context for XDP checking
 * @param[in] now_ns   Current timestamp
 * @return 0 on success, -1 on error
 */
int deferred_enqueue(deferred_queue_t *q, const http_message_t *msg,
                     flow_context_t *flow_ctx, uint64_t now_ns);

/**
 * @brief Drain queue - display messages with XDP or timeout
 *
 * Called each worker loop iteration. Checks each queued message:
 * - If XDP flag set: display with XDP_MATCHED status
 * - If timeout exceeded: display with XDP_NOT_FOUND status
 * - Otherwise: keep in queue for next iteration
 *
 * Uses adaptive timeout based on queue fullness.
 *
 * @param[in] q      Deferred queue
 * @param[in] now_ns Current timestamp
 * @return Number of messages displayed
 */
size_t deferred_drain(deferred_queue_t *q, uint64_t now_ns);

/**
 * @brief Force flush oldest entries when queue is full
 *
 * Called when queue depth exceeds DEFERRED_QUEUE_MAX_ENTRIES.
 * Flushes DEFERRED_FLUSH_BATCH oldest entries immediately.
 *
 * @param[in] q Deferred queue
 * @return Number of messages flushed
 */
size_t deferred_force_flush(deferred_queue_t *q);

/**
 * @brief Aggregate stats from all workers
 *
 * Collects deferred queue statistics from all worker threads
 * for shutdown summary.
 *
 * @param[in]  workers     Worker array
 * @param[in]  num_workers Number of workers
 * @param[out] out         Output statistics
 */
void deferred_get_stats(const worker_ctx_t *workers, int num_workers,
                        deferred_stats_t *out);

/**
 * @brief Cleanup deferred queue and free all memory
 *
 * Frees all queued messages, free list entries, and resets the queue.
 *
 * @param[in] q Queue to cleanup
 */
void deferred_queue_cleanup(deferred_queue_t *q);

/**
 * @brief Get current worker's deferred queue
 *
 * Uses thread-local storage to find the worker context and return
 * its deferred queue. Returns NULL if not called from a worker thread.
 *
 * @return Deferred queue pointer, or NULL if not in worker thread
 */
deferred_queue_t *deferred_get_current_queue(void);

/**
 * @brief Display or defer HTTP message based on XDP status
 *
 * Helper for protocol handlers. If FLOW_FLAG_HAS_XDP is set on the
 * flow context, displays the message immediately. Otherwise, enqueues
 * it to the current worker's deferred display queue.
 *
 * @param[in] msg      HTTP message to display/defer
 * @param[in] flow_ctx Flow context for XDP checking (may be NULL)
 * @return 0 on success, -1 on error
 */
int deferred_display_or_enqueue(const http_message_t *msg,
                                flow_context_t *flow_ctx);

#endif /* SPLIFF_DEFERRED_H */
