/**
 * @file logger.c
 * @brief Async MPSC logging pipeline implementation
 *
 * Implements lock-free async logging with:
 * - MPSC ring buffer (ck_ring)
 * - Pre-allocated entry pool with free-list recycling
 * - eventfd edge-triggered wake-up
 * - writev() batch writes for atomic output
 *
 * @copyright Copyright (c) 2026
 */

#include "logger.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/uio.h>

#include <ck_ring.h>

/* C23 static assertions for alignment validation */
_Static_assert(sizeof(log_entry_t) % LOG_CACHE_LINE == 0,
               "log_entry_t must be cache-line multiple");
_Static_assert(_Alignof(log_entry_t) == LOG_CACHE_LINE,
               "log_entry_t must be cache-line aligned");

/* ═══════════════════════════════════════════════════════════════════════════
 * Global State
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Global logger context */
static logger_ctx_t g_logger = {
    .eventfd = -1,
    .epoll_fd = -1,
    .output_fd = STDOUT_FILENO,
    .running = false,
    .shutdown_requested = false,
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Get monotonic timestamp in nanoseconds
 */
static inline uint64_t get_timestamp_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/**
 * @brief Allocate an entry from the free-list
 *
 * @return Entry pointer or NULL if free-list exhausted
 */
static log_entry_t *entry_alloc(void)
{
    log_entry_t *entry = NULL;

    if (!ck_ring_dequeue_mpsc(&g_logger.free_ring,
                               g_logger.free_ring_buffer,
                               &entry)) {
        atomic_fetch_add_explicit(&g_logger.alloc_failures, 1,
                                  memory_order_relaxed);
        return NULL;
    }

    return entry;
}

/**
 * @brief Return an entry to the free-list
 */
static void entry_free(log_entry_t *entry)
{
    if (entry) {
        /* MPSC enqueue back to free ring - always succeeds if balanced */
        ck_ring_enqueue_mpsc(&g_logger.free_ring,
                             g_logger.free_ring_buffer,
                             entry);
    }
}

/**
 * @brief Signal the logger thread via eventfd
 *
 * Only signals on empty→non-empty transition (edge-triggered).
 */
static void signal_logger(void)
{
    /*
     * FIX: Use memory_order_release instead of memory_order_acq_rel.
     * We only need release semantics here - we're publishing the fact
     * that the ring is no longer empty. The acquire is unnecessary since
     * we don't read any data that depends on the previous value.
     */
    bool was_empty = atomic_exchange_explicit(&g_logger.ring_was_empty,
                                               false,
                                               memory_order_release);
    if (was_empty) {
        uint64_t val = 1;
        ssize_t ret = write(g_logger.eventfd, &val, sizeof(val));
        (void)ret; /* Ignore errors - logger will poll eventually */
    }
}

/**
 * @brief Drain the ring buffer and write with writev()
 *
 * @return Number of messages written
 */
static size_t drain_and_write(void)
{
    log_entry_t *entries[LOG_BATCH_SIZE];
    struct iovec iov[LOG_BATCH_SIZE];
    size_t count = 0;
    size_t total_bytes = 0;

    /* Dequeue up to batch size */
    while (count < LOG_BATCH_SIZE) {
        log_entry_t *entry = NULL;
        if (!ck_ring_dequeue_mpsc(&g_logger.ring,
                                   g_logger.ring_buffer,
                                   &entry)) {
            break;
        }
        entries[count] = entry;
        iov[count].iov_base = entry->data;
        iov[count].iov_len = entry->len;
        total_bytes += entry->len;
        count++;
    }

    if (count == 0) {
        /* Ring is empty - set edge-trigger flag */
        atomic_store_explicit(&g_logger.ring_was_empty, true,
                              memory_order_release);
        return 0;
    }

    /* Write all messages atomically with writev */
    ssize_t written = writev(g_logger.output_fd, iov, (int)count);
    if (written < 0) {
        /* Write error - still return entries to free-list */
        written = 0;
    }

    /* Update statistics */
    atomic_fetch_add_explicit(&g_logger.messages_logged, count,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(&g_logger.bytes_written, (uint64_t)written,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(&g_logger.batches_written, 1,
                              memory_order_relaxed);

    /* Return entries to free-list */
    for (size_t i = 0; i < count; i++) {
        entry_free(entries[i]);
    }

    return count;
}

/**
 * @brief Logger thread main function
 */
static void *logger_thread_main(void *arg)
{
    (void)arg;

    struct epoll_event events[1];
    const int timeout_ms = 100; /* Fallback timeout for robustness */

    atomic_store_explicit(&g_logger.running, true, memory_order_release);

    while (!atomic_load_explicit(&g_logger.shutdown_requested,
                                  memory_order_acquire)) {
        /* Wait for eventfd signal or timeout */
        int nfds = epoll_wait(g_logger.epoll_fd, events, 1, timeout_ms);

        if (nfds > 0) {
            /* Consume eventfd counter */
            uint64_t val;
            ssize_t ret = read(g_logger.eventfd, &val, sizeof(val));
            (void)ret;
        }

        /* Drain until empty */
        while (drain_and_write() > 0) {
            /* Keep draining */
        }
    }

    /* Final drain on shutdown */
    while (drain_and_write() > 0) {
        /* Drain remaining messages */
    }

    atomic_store_explicit(&g_logger.running, false, memory_order_release);
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API
 * ═══════════════════════════════════════════════════════════════════════════ */

int log_init(FILE *output_file)
{
    int ret = -1;

    /* Set output file descriptor */
    if (output_file) {
        g_logger.output_fd = fileno(output_file);
    } else {
        g_logger.output_fd = STDOUT_FILENO;
    }

    /* Allocate ring buffer storage (power of 2 required) */
    g_logger.ring_buffer = calloc(LOG_RING_SIZE, sizeof(ck_ring_buffer_t));
    if (!g_logger.ring_buffer) {
        goto err_ring_buffer;
    }
    ck_ring_init(&g_logger.ring, LOG_RING_SIZE);

    /* Allocate free ring buffer storage */
    g_logger.free_ring_buffer = calloc(LOG_RING_SIZE, sizeof(ck_ring_buffer_t));
    if (!g_logger.free_ring_buffer) {
        goto err_free_ring_buffer;
    }
    ck_ring_init(&g_logger.free_ring, LOG_RING_SIZE);

    /* Allocate entry pool with alignment */
    g_logger.pool_size = LOG_RING_SIZE;
    size_t pool_bytes = g_logger.pool_size * sizeof(log_entry_t);
    g_logger.entry_pool = aligned_alloc(LOG_CACHE_LINE, pool_bytes);
    if (!g_logger.entry_pool) {
        goto err_entry_pool;
    }
    memset(g_logger.entry_pool, 0, pool_bytes);

    /* Populate free-list with all entries */
    for (size_t i = 0; i < g_logger.pool_size; i++) {
        log_entry_t *entry = &g_logger.entry_pool[i];
        ck_ring_enqueue_spsc(&g_logger.free_ring,
                             g_logger.free_ring_buffer,
                             entry);
    }

    /* Create eventfd for wake-up signaling */
    g_logger.eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (g_logger.eventfd < 0) {
        goto err_eventfd;
    }

    /* Create epoll instance */
    g_logger.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (g_logger.epoll_fd < 0) {
        goto err_epoll;
    }

    /* Add eventfd to epoll */
    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.fd = g_logger.eventfd,
    };
    if (epoll_ctl(g_logger.epoll_fd, EPOLL_CTL_ADD, g_logger.eventfd, &ev) < 0) {
        goto err_epoll_add;
    }

    /* Initialize state */
    atomic_store_explicit(&g_logger.ring_was_empty, true, memory_order_release);
    atomic_store_explicit(&g_logger.shutdown_requested, false, memory_order_release);
    atomic_store_explicit(&g_logger.messages_logged, 0, memory_order_relaxed);
    atomic_store_explicit(&g_logger.bytes_written, 0, memory_order_relaxed);
    atomic_store_explicit(&g_logger.batches_written, 0, memory_order_relaxed);
    atomic_store_explicit(&g_logger.drops, 0, memory_order_relaxed);
    atomic_store_explicit(&g_logger.alloc_failures, 0, memory_order_relaxed);

    /* Start logger thread */
    if (pthread_create(&g_logger.thread, NULL, logger_thread_main, NULL) != 0) {
        goto err_thread;
    }

    return 0;

err_thread:
err_epoll_add:
    close(g_logger.epoll_fd);
    g_logger.epoll_fd = -1;
err_epoll:
    close(g_logger.eventfd);
    g_logger.eventfd = -1;
err_eventfd:
    free(g_logger.entry_pool);
    g_logger.entry_pool = NULL;
err_entry_pool:
    free(g_logger.free_ring_buffer);
    g_logger.free_ring_buffer = NULL;
err_free_ring_buffer:
    free(g_logger.ring_buffer);
    g_logger.ring_buffer = NULL;
err_ring_buffer:
    return ret;
}

void log_cleanup(void)
{
    /* Signal shutdown */
    atomic_store_explicit(&g_logger.shutdown_requested, true,
                          memory_order_release);

    /* Wake up logger thread */
    if (g_logger.eventfd >= 0) {
        uint64_t val = 1;
        ssize_t ret = write(g_logger.eventfd, &val, sizeof(val));
        (void)ret;
    }

    /* Wait for logger thread */
    if (g_logger.thread) {
        pthread_join(g_logger.thread, NULL);
        g_logger.thread = 0;
    }

    /* Close file descriptors */
    if (g_logger.epoll_fd >= 0) {
        close(g_logger.epoll_fd);
        g_logger.epoll_fd = -1;
    }
    if (g_logger.eventfd >= 0) {
        close(g_logger.eventfd);
        g_logger.eventfd = -1;
    }

    /* Free memory */
    free(g_logger.entry_pool);
    g_logger.entry_pool = NULL;

    free(g_logger.free_ring_buffer);
    g_logger.free_ring_buffer = NULL;

    free(g_logger.ring_buffer);
    g_logger.ring_buffer = NULL;
}

int log_enqueue(const char *msg, size_t len)
{
    if (!msg || len == 0) {
        return 0;
    }

    /* Truncate if too long */
    if (len > LOG_MSG_MAX_SIZE) {
        len = LOG_MSG_MAX_SIZE;
    }

    /* Allocate entry from free-list */
    log_entry_t *entry = entry_alloc();
    if (!entry) {
        atomic_fetch_add_explicit(&g_logger.drops, 1, memory_order_relaxed);
        return -1;
    }

    /* Fill entry */
    entry->timestamp_ns = get_timestamp_ns();
    entry->len = (uint32_t)len;
    memcpy(entry->data, msg, len);

    /* Enqueue to main ring */
    if (!ck_ring_enqueue_mpsc(&g_logger.ring, g_logger.ring_buffer, entry)) {
        /* Ring full - return entry and count as drop */
        entry_free(entry);
        atomic_fetch_add_explicit(&g_logger.drops, 1, memory_order_relaxed);
        return -1;
    }

    /* Signal logger (edge-triggered) */
    signal_logger();

    return 0;
}

int log_printf(const char *fmt, ...)
{
    if (!fmt) {
        return -1;
    }

    /* Allocate entry from free-list */
    log_entry_t *entry = entry_alloc();
    if (!entry) {
        atomic_fetch_add_explicit(&g_logger.drops, 1, memory_order_relaxed);
        return -1;
    }

    /* Format message directly into entry */
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(entry->data, LOG_MSG_MAX_SIZE, fmt, args);
    va_end(args);

    if (len < 0) {
        entry_free(entry);
        return -1;
    }

    /* Truncate if necessary */
    if ((size_t)len >= LOG_MSG_MAX_SIZE) {
        len = LOG_MSG_MAX_SIZE - 1;
    }

    entry->timestamp_ns = get_timestamp_ns();
    entry->len = (uint32_t)len;

    /* Enqueue to main ring */
    if (!ck_ring_enqueue_mpsc(&g_logger.ring, g_logger.ring_buffer, entry)) {
        entry_free(entry);
        atomic_fetch_add_explicit(&g_logger.drops, 1, memory_order_relaxed);
        return -1;
    }

    /* Signal logger (edge-triggered) */
    signal_logger();

    return len;
}

void log_signal(void)
{
    signal_logger();
}

void log_get_stats(logger_stats_t *stats)
{
    if (!stats) {
        return;
    }

    stats->messages = atomic_load_explicit(&g_logger.messages_logged,
                                            memory_order_relaxed);
    stats->bytes = atomic_load_explicit(&g_logger.bytes_written,
                                         memory_order_relaxed);
    stats->batches = atomic_load_explicit(&g_logger.batches_written,
                                           memory_order_relaxed);
    stats->drops = atomic_load_explicit(&g_logger.drops,
                                         memory_order_relaxed);
    stats->alloc_failures = atomic_load_explicit(&g_logger.alloc_failures,
                                                  memory_order_relaxed);
}

bool log_is_running(void)
{
    return atomic_load_explicit(&g_logger.running, memory_order_acquire);
}
