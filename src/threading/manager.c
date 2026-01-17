/**
 * @file manager.c
 * @brief Threading manager implementation
 *
 * @details The threading manager is the top-level coordinator for the
 * multi-threaded event processing pipeline. It handles:
 * - Auto-detection of optimal worker count based on CPU cores
 * - Initialization of all thread contexts
 * - Thread creation with optional CPU affinity
 * - Ordered graceful shutdown
 * - Statistics collection and reporting
 *
 * @par Startup Sequence:
 * @code
 *   threading_init()
 *       │
 *       └── Initialize worker contexts
 *
 *   threading_start()
 *       │
 *       ├── Initialize dispatcher context
 *       ├── Initialize output context
 *       ├── Create worker threads
 *       ├── Create output thread
 *       └── Create dispatcher thread
 * @endcode
 *
 * @par Shutdown Sequence:
 * @code
 *   threading_shutdown()
 *       │
 *       ├── 1. Stop dispatcher (no new events)
 *       ├── 2. Stop workers (drain input queues)
 *       └── 3. Stop output (drain output queues)
 *
 *   threading_cleanup()
 *       │
 *       └── Free all resources
 * @endcode
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
#include <sched.h>
#include <sys/sysinfo.h>
#include <signal.h>

/** Global manager for signal handler access */
static threading_mgr_t *g_threading_mgr = NULL;

/**
 * @defgroup manager_cpu CPU Detection
 * @brief Auto-detection of optimal worker count
 * @{
 */

/**
 * @brief Calculate default worker count based on available CPU cores
 *
 * Uses get_nprocs() to determine available cores and reserves 3 for
 * system threads (main, dispatcher, output).
 *
 * @par Formula:
 * workers = max(1, nprocs - 3) capped at MAX_WORKERS
 *
 * @return Recommended number of worker threads
 */
int threading_default_workers(void) {
    int nproc = get_nprocs();

    /* Reserve 3 cores for main/dispatcher/output threads */
    int workers = nproc - 3;

    /* Ensure at least 1 worker */
    if (workers < 1) {
        workers = 1;
    }

    /* Cap at maximum */
    if (workers > MAX_WORKERS) {
        workers = MAX_WORKERS;
    }

    return workers;
}

/** @} */ /* end manager_cpu */

/**
 * @defgroup manager_init Manager Initialization
 * @brief Setup and teardown for threading manager
 * @{
 */

/**
 * @brief Initialize threading manager
 *
 * Allocates and initializes all worker contexts but does not start
 * any threads. Call threading_start() to begin processing.
 *
 * @param[out] mgr         Manager structure to initialize
 * @param[in]  num_workers Number of worker threads (0 = auto-detect)
 * @param[in]  pin_cores   Whether to pin threads to CPU cores
 *
 * @return 0 on success, -1 on failure
 *
 * @note On failure, partially initialized workers are cleaned up
 */
int threading_init(threading_mgr_t *mgr, int num_workers, bool pin_cores) {
    if (!mgr) {
        return -1;
    }

    memset(mgr, 0, sizeof(*mgr));

    /* Auto-detect worker count if not specified */
    if (num_workers <= 0) {
        num_workers = threading_default_workers();
    }
    if (num_workers > MAX_WORKERS) {
        num_workers = MAX_WORKERS;
    }

    mgr->num_workers = num_workers;
    mgr->pin_cores = pin_cores;

    fprintf(stderr, "Threading: initializing with %d workers\n", num_workers);

    /* Initialize workers */
    for (int i = 0; i < num_workers; i++) {
        if (worker_init(&mgr->workers[i], i) != 0) {
            fprintf(stderr, "Threading: failed to init worker %d\n", i);
            /* Cleanup already initialized workers */
            for (int j = 0; j < i; j++) {
                worker_cleanup(&mgr->workers[j]);
            }
            return -1;
        }
    }

    /* Set global for signal handler */
    g_threading_mgr = mgr;

    mgr->initialized = true;
    atomic_store(&mgr->shutdown_requested, false);

    return 0;
}

/**
 * @brief Start all threads
 *
 * Creates and starts all threads in order:
 * 1. Worker threads (with optional CPU affinity)
 * 2. Output thread
 * 3. Dispatcher thread
 *
 * @par CPU Pinning:
 * If pin_cores is enabled, workers are pinned to cores 3+ to avoid
 * contention with main/dispatcher/output threads on cores 0-2.
 *
 * @param[in] mgr     Initialized manager
 * @param[in] handler BPF probe handler for dispatcher
 *
 * @return 0 on success, -1 on failure (threads cleaned up)
 */
int threading_start(threading_mgr_t *mgr, probe_handler_t *handler) {
    if (!mgr || !mgr->initialized || !handler) {
        return -1;
    }

    fprintf(stderr, "Threading: starting threads...\n");

    /* Initialize dispatcher */
    if (dispatcher_init(&mgr->dispatcher, handler, mgr->workers, mgr->num_workers) != 0) {
        fprintf(stderr, "Threading: failed to init dispatcher\n");
        return -1;
    }

    /* Initialize output thread */
    if (output_init(&mgr->output, mgr->workers, mgr->num_workers, NULL) != 0) {
        fprintf(stderr, "Threading: failed to init output\n");
        dispatcher_cleanup(&mgr->dispatcher);
        return -1;
    }

    /* Start worker threads */
    for (int i = 0; i < mgr->num_workers; i++) {
        pthread_attr_t attr;
        pthread_attr_init(&attr);

        /* Optional: pin to CPU core */
        if (mgr->pin_cores) {
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            /* Pin workers to cores 3+ (skip 0-2 for main/dispatcher/output) */
            CPU_SET((i + 3) % get_nprocs(), &cpuset);
            pthread_attr_setaffinity_np(&attr, sizeof(cpuset), &cpuset);
        }

        if (pthread_create(&mgr->workers[i].thread, &attr,
                           worker_thread_main, &mgr->workers[i]) != 0) {
            fprintf(stderr, "Threading: failed to create worker %d thread\n", i);
            pthread_attr_destroy(&attr);
            /* Signal already-started workers to stop */
            for (int j = 0; j < i; j++) {
                atomic_store(&mgr->workers[j].running, false);
                pthread_join(mgr->workers[j].thread, NULL);
            }
            output_cleanup(&mgr->output);
            dispatcher_cleanup(&mgr->dispatcher);
            return -1;
        }
        pthread_attr_destroy(&attr);
    }

    /* Start output thread */
    if (pthread_create(&mgr->output.thread, NULL,
                       output_thread_main, &mgr->output) != 0) {
        fprintf(stderr, "Threading: failed to create output thread\n");
        for (int i = 0; i < mgr->num_workers; i++) {
            atomic_store(&mgr->workers[i].running, false);
            pthread_join(mgr->workers[i].thread, NULL);
        }
        output_cleanup(&mgr->output);
        dispatcher_cleanup(&mgr->dispatcher);
        return -1;
    }

    /* Start dispatcher thread */
    if (pthread_create(&mgr->dispatcher.thread, NULL,
                       dispatcher_thread_main, &mgr->dispatcher) != 0) {
        fprintf(stderr, "Threading: failed to create dispatcher thread\n");
        atomic_store(&mgr->output.running, false);
        pthread_join(mgr->output.thread, NULL);
        for (int i = 0; i < mgr->num_workers; i++) {
            atomic_store(&mgr->workers[i].running, false);
            pthread_join(mgr->workers[i].thread, NULL);
        }
        output_cleanup(&mgr->output);
        dispatcher_cleanup(&mgr->dispatcher);
        return -1;
    }

    fprintf(stderr, "Threading: all threads started\n");
    return 0;
}

/** @} */ /* end manager_init */

/**
 * @defgroup manager_shutdown Shutdown
 * @brief Graceful shutdown coordination
 * @{
 */

/**
 * @brief Request graceful shutdown
 *
 * Stops threads in order to ensure all events are processed:
 * 1. Dispatcher stops (no new events accepted)
 * 2. Workers drain input queues and stop
 * 3. Output thread drains output queues and stops
 *
 * @note This function blocks until all threads have exited.
 */
void threading_shutdown(threading_mgr_t *mgr) {
    if (!mgr || !mgr->initialized) {
        return;
    }

    if (atomic_exchange(&mgr->shutdown_requested, true)) {
        /* Already shutting down */
        return;
    }

    fprintf(stderr, "\nShutdown requested...\n");

    /* 1. Stop dispatcher first (stop accepting new events) */
    atomic_store(&mgr->dispatcher.running, false);
    pthread_join(mgr->dispatcher.thread, NULL);
    fprintf(stderr, "  Dispatcher stopped\n");

    /* 2. Stop workers (they will drain their queues) */
    for (int i = 0; i < mgr->num_workers; i++) {
        atomic_store(&mgr->workers[i].running, false);
        /* Wake if sleeping */
        uint64_t val = 1;
        ssize_t n = write(mgr->workers[i].wakeup_fd, &val, sizeof(val));
        (void)n;
    }

    /* 3. Wait for workers */
    for (int i = 0; i < mgr->num_workers; i++) {
        pthread_join(mgr->workers[i].thread, NULL);
    }
    fprintf(stderr, "  Workers stopped\n");

    /* 4. Stop output thread (it will drain output queues) */
    atomic_store(&mgr->output.running, false);
    pthread_join(mgr->output.thread, NULL);
    fprintf(stderr, "  Output thread stopped\n");
}

/**
 * @brief Cleanup all resources
 *
 * Frees all allocated memory for workers, dispatcher, and output.
 * Must be called after threading_shutdown().
 */
void threading_cleanup(threading_mgr_t *mgr) {
    if (!mgr) {
        return;
    }

    /* Cleanup components */
    output_cleanup(&mgr->output);
    dispatcher_cleanup(&mgr->dispatcher);

    for (int i = 0; i < mgr->num_workers; i++) {
        worker_cleanup(&mgr->workers[i]);
    }

    g_threading_mgr = NULL;
    mgr->initialized = false;

    fprintf(stderr, "Threading: cleanup complete\n");
}

/** @} */ /* end manager_shutdown */

/**
 * @defgroup manager_stats Statistics
 * @brief Threading statistics collection and display
 * @{
 */

/**
 * @brief Print threading statistics to stderr
 *
 * Outputs comprehensive statistics including:
 * - Dispatcher events dispatched/dropped
 * - Per-worker events processed/dropped and wait cycle distribution
 * - Output thread messages/bytes written
 */
void threading_print_stats(threading_mgr_t *mgr) {
    if (!mgr || !mgr->initialized) {
        return;
    }

    fprintf(stderr, "\n=== Threading Statistics ===\n");
    fprintf(stderr, "Workers: %d\n\n", mgr->num_workers);

    /* Dispatcher stats */
    uint64_t dispatched, dropped;
    dispatcher_get_stats(&mgr->dispatcher, &dispatched, &dropped);
    fprintf(stderr, "Dispatcher:\n");
    fprintf(stderr, "  Events dispatched: %lu\n", dispatched);
    fprintf(stderr, "  Events dropped: %lu\n", dropped);

    /* Worker stats */
    uint64_t total_processed = 0;
    uint64_t total_dropped = 0;
    uint64_t total_spin = 0;
    uint64_t total_yield = 0;
    uint64_t total_sleep = 0;

    fprintf(stderr, "\nWorkers:\n");
    for (int i = 0; i < mgr->num_workers; i++) {
        worker_ctx_t *w = &mgr->workers[i];
        uint64_t processed = atomic_load(&w->events_processed);
        uint64_t w_dropped = atomic_load(&w->events_dropped);
        uint64_t spin = atomic_load(&w->spin_cycles);
        uint64_t yield = atomic_load(&w->yield_cycles);
        uint64_t sleep = atomic_load(&w->sleep_cycles);

        fprintf(stderr, "  Worker %d: processed=%lu dropped=%lu "
                        "spin=%lu yield=%lu sleep=%lu\n",
                i, processed, w_dropped, spin, yield, sleep);

        total_processed += processed;
        total_dropped += w_dropped;
        total_spin += spin;
        total_yield += yield;
        total_sleep += sleep;
    }

    fprintf(stderr, "\n  Total: processed=%lu dropped=%lu\n",
            total_processed, total_dropped);

    /* Calculate wait distribution */
    uint64_t total_wait = total_spin + total_yield + total_sleep;
    if (total_wait > 0) {
        fprintf(stderr, "  Wait distribution: spin=%.1f%% yield=%.1f%% sleep=%.1f%%\n",
                100.0 * total_spin / total_wait,
                100.0 * total_yield / total_wait,
                100.0 * total_sleep / total_wait);
    }

    /* Output stats */
    uint64_t messages, bytes;
    output_get_stats(&mgr->output, &messages, &bytes);
    fprintf(stderr, "\nOutput:\n");
    fprintf(stderr, "  Messages written: %lu\n", messages);
    fprintf(stderr, "  Bytes written: %lu\n", bytes);

    fprintf(stderr, "\n");
}

/** @} */ /* end manager_stats */

/**
 * @defgroup manager_helpers Helper Functions
 * @brief Global manager access utilities
 * @{
 */

/**
 * @brief Check if threading is enabled and running
 *
 * @param[in] mgr Manager to check
 *
 * @return true if manager is initialized and not shutting down
 */
bool threading_is_running(threading_mgr_t *mgr) {
    return mgr && mgr->initialized && !atomic_load(&mgr->shutdown_requested);
}

/**
 * @brief Get global threading manager instance
 *
 * Returns the singleton manager set during threading_init().
 * Useful for signal handlers that need manager access.
 *
 * @return Manager pointer, or NULL if not initialized
 */
threading_mgr_t *threading_get_manager(void) {
    return g_threading_mgr;
}

/** @} */ /* end manager_helpers */
