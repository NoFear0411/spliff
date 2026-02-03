/**
 * @file logger.h
 * @brief Async MPSC logging pipeline for lock-free output serialization
 *
 * This module provides a global MPSC (Multiple Producer, Single Consumer) ring buffer
 * for async logging. All worker threads enqueue formatted messages to a single ring,
 * and a dedicated logger thread drains with writev() for atomic batch writes.
 *
 * Key features:
 * - Lock-free MPSC ring using ck_ring
 * - Pre-allocated entry pool (zero malloc in hot path)
 * - eventfd notification (edge-triggered, empty→non-empty only)
 * - writev() batching for atomic output
 * - 64-byte cache-line aligned entries
 *
 * @copyright Copyright (c) 2026
 */

#ifndef SPLIFF_LOGGER_H
#define SPLIFF_LOGGER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdio.h>
#include <pthread.h>
#include <ck_ring.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Constants
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Ring buffer size (must be power of 2 for CK ring) */
#define LOG_RING_SIZE       8192

/* Batch 5.1: Compile-time verification of ring size invariant */
_Static_assert((LOG_RING_SIZE & (LOG_RING_SIZE - 1)) == 0,
               "LOG_RING_SIZE must be power of 2 for CK ring");

/** Maximum messages per writev() batch */
#define LOG_BATCH_SIZE      64

/** Maximum size of a single log message */
#define LOG_MSG_MAX_SIZE    (64 * 1024)

/** Cache line size for alignment */
#define LOG_CACHE_LINE      64

/* ═══════════════════════════════════════════════════════════════════════════
 * Structures
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Log entry structure - cache-line aligned
 *
 * Each entry is pre-allocated in the entry pool. Workers acquire from
 * free-list, format into data[], enqueue to main ring. Logger thread
 * dequeues, writes, returns to free-list.
 */
typedef struct log_entry {
    uint64_t timestamp_ns;          /**< Monotonic timestamp for ordering */
    uint32_t len;                   /**< Length of data (excluding NUL) */
    uint32_t _pad;                  /**< Padding for alignment */
    char data[LOG_MSG_MAX_SIZE];    /**< Message buffer */
} __attribute__((aligned(LOG_CACHE_LINE))) log_entry_t;

/**
 * @brief Logger context - global async logging state
 *
 * Single instance manages the MPSC ring, free-list, logger thread,
 * and statistics. Initialized by log_init(), cleaned up by log_cleanup().
 */
typedef struct logger_ctx {
    /* MPSC ring for pending messages */
    ck_ring_t ring;                         /**< Main message ring */
    ck_ring_buffer_t *ring_buffer;          /**< Ring buffer storage */

    /* Free-list for entry recycling */
    ck_ring_t free_ring;                    /**< Free entry ring */
    ck_ring_buffer_t *free_ring_buffer;     /**< Free ring buffer storage */

    /* Pre-allocated entry pool */
    log_entry_t *entry_pool;                /**< Pool of entries */
    size_t pool_size;                       /**< Number of entries in pool */

    /* Wake-up mechanism */
    int eventfd;                            /**< Event notification fd */
    int epoll_fd;                           /**< epoll instance for eventfd */
    _Atomic bool ring_was_empty;            /**< Edge-trigger state */

    /* Logger thread */
    pthread_t thread;                       /**< Logger thread handle */
    _Atomic bool running;                   /**< Thread running flag */
    _Atomic bool shutdown_requested;        /**< Graceful shutdown flag */

    /* Output destination */
    int output_fd;                          /**< Output file descriptor */

    /* Statistics */
    _Atomic uint64_t messages_logged;       /**< Total messages written */
    _Atomic uint64_t bytes_written;         /**< Total bytes written */
    _Atomic uint64_t batches_written;       /**< Number of writev() calls */
    _Atomic uint64_t drops;                 /**< Messages dropped (ring full) */
    _Atomic uint64_t alloc_failures;        /**< Free-list exhaustion count */
} logger_ctx_t;

/**
 * @brief Logger statistics snapshot
 */
typedef struct logger_stats {
    uint64_t messages;      /**< Total messages written */
    uint64_t bytes;         /**< Total bytes written */
    uint64_t batches;       /**< Number of writev() batches */
    uint64_t drops;         /**< Messages dropped (ring full) */
    uint64_t alloc_failures;/**< Entry allocation failures */
} logger_stats_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * API Functions
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Initialize the async logger
 *
 * Creates the MPSC ring, entry pool, eventfd, and starts the logger thread.
 * Must be called before any log_enqueue() or log_printf() calls.
 *
 * @param output_file Output FILE* (NULL for stdout)
 * @return 0 on success, -1 on error (check errno)
 */
int log_init(FILE *output_file);

/**
 * @brief Shutdown and cleanup the async logger
 *
 * Signals shutdown, drains remaining messages, joins the logger thread,
 * and frees all resources.
 */
void log_cleanup(void);

/**
 * @brief Enqueue a pre-formatted message
 *
 * Acquires an entry from free-list, copies message, enqueues to ring.
 * Signals logger thread if ring was empty (edge-triggered).
 *
 * @param msg Message buffer
 * @param len Message length (must be <= LOG_MSG_MAX_SIZE)
 * @return 0 on success, -1 on drop (ring full or alloc failure)
 */
int log_enqueue(const char *msg, size_t len);

/**
 * @brief Printf-style logging
 *
 * Formats message and enqueues to async logger. Thread-safe.
 *
 * @param fmt Printf format string
 * @param ... Format arguments
 * @return Number of characters written, or -1 on error
 */
int log_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/**
 * @brief Signal the logger thread to wake up
 *
 * Called at end of NAPI budget cycle for coalesced wake-up.
 * Only signals if ring transitioned from empty to non-empty.
 */
void log_signal(void);

/**
 * @brief Get logger statistics
 *
 * @param stats Output statistics structure
 */
void log_get_stats(logger_stats_t *stats);

/**
 * @brief Check if logger is initialized and running
 *
 * @return true if logger is active
 */
bool log_is_running(void);

#ifdef __cplusplus
}
#endif

#endif /* SPLIFF_LOGGER_H */
