/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * manager.c - Threading manager implementation
 *
 * Coordinates all threading components:
 * - Auto-detects optimal worker count based on CPU cores
 * - Initializes and starts all threads
 * - Handles graceful shutdown
 * - Collects and prints statistics
 */

#include "threading.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <sys/sysinfo.h>
#include <signal.h>

/* Global manager for signal handler access */
static threading_mgr_t *g_threading_mgr = NULL;

/* ============================================================================
 * CPU Detection
 * ============================================================================ */

/*
 * Calculate default worker count based on available CPU cores
 *
 * Formula: max(1, nprocs - 3) capped at MAX_WORKERS
 * Reserves cores for: main thread, dispatcher, output thread
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

/* ============================================================================
 * Threading Manager Initialization
 * ============================================================================ */

/*
 * Initialize threading manager
 *
 * @param mgr         Manager structure to initialize
 * @param num_workers Number of worker threads (0 = auto-detect)
 * @param pin_cores   Whether to pin threads to CPU cores
 *
 * @return 0 on success, -1 on failure
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

/*
 * Start all threads
 *
 * @param mgr      Initialized manager
 * @param handler  BPF probe handler to use for dispatcher
 *
 * @return 0 on success, -1 on failure
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

/* ============================================================================
 * Shutdown
 * ============================================================================ */

/*
 * Request graceful shutdown
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

/*
 * Cleanup all resources
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

/* ============================================================================
 * Statistics
 * ============================================================================ */

/*
 * Print threading statistics
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

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/*
 * Check if threading is enabled and running
 */
bool threading_is_running(threading_mgr_t *mgr) {
    return mgr && mgr->initialized && !atomic_load(&mgr->shutdown_requested);
}

/*
 * Get global threading manager (for signal handlers)
 */
threading_mgr_t *threading_get_manager(void) {
    return g_threading_mgr;
}
