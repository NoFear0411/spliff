/**
 * @file stats.c
 * @brief Session statistics output implementation
 *
 * Handles formatted output of session statistics to stderr.
 * Uses fprintf(stderr,...) directly since stats go to stderr,
 * separate from the async stdout logger.
 *
 * @copyright Copyright (c) 2026
 */

#include "stats.h"
#include "display.h"
#include "logger.h"
#include "../threading/threading.h"
#include "../bpf/bpf_loader.h"

#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

char *stats_format_bytes(uint64_t bytes, char *buf, size_t size)
{
    if (bytes >= 1024ULL * 1024 * 1024) {
        snprintf(buf, size, "%.1f GB", bytes / (1024.0 * 1024 * 1024));
    } else if (bytes >= 1024 * 1024) {
        snprintf(buf, size, "%.1f MB", bytes / (1024.0 * 1024));
    } else if (bytes >= 1024) {
        snprintf(buf, size, "%.1f KB", bytes / 1024.0);
    } else {
        snprintf(buf, size, "%lu B", (unsigned long)bytes);
    }
    return buf;
}

void stats_print_session(const threading_stats_t *ts,
                         const xdp_stats_t *xdp,
                         bpf_loader_t *loader,
                         const logger_stats_t *log_stats,
                         bool use_colors)
{
    /* Color codes - either real ANSI or empty strings */
    const char *dim   = use_colors ? C_DIM : "";
    const char *bold  = use_colors ? C_BOLD : "";
    const char *cyan  = use_colors ? C_CYAN : "";
    const char *green = use_colors ? C_GREEN : "";
    const char *yellow = use_colors ? C_YELLOW : "";
    const char *reset = use_colors ? C_RESET : "";

    char bytebuf[32];

    fprintf(stderr, "\n%s", bold);
    fprintf(stderr, "============================================\n");
    fprintf(stderr, "           Session Statistics\n");
    fprintf(stderr, "============================================%s\n", reset);

    /* ── Application Layer (SSL/TLS) ─────────────────────────────────── */
    fprintf(stderr, "\n  %sApplication Layer (SSL/TLS)%s\n", cyan, reset);
    fprintf(stderr, "  %s----------------------------------------------%s\n", dim, reset);

    /* Events pipeline */
    fprintf(stderr, "  Events:      %lu captured", ts->events_dispatched);
    if (ts->total_processed > 0 || ts->events_dispatched > 0) {
        fprintf(stderr, " -> %lu processed", ts->total_processed);
    }
    uint64_t total_drops = ts->events_dropped + ts->total_dropped;
    if (total_drops > 0) {
        fprintf(stderr, " %s(%lu dropped)%s", yellow, total_drops, reset);
    }
    fprintf(stderr, "\n");

    /* Output */
    fprintf(stderr, "  Output:      %lu messages (%s)\n",
            ts->messages_written, stats_format_bytes(ts->bytes_written, bytebuf, sizeof(bytebuf)));

    /* Cookie retry correlation */
    uint64_t total_deferred = ts->total_deferred_ok + ts->total_deferred_fail;
    if (total_deferred > 0) {
        double success_rate = 100.0 * ts->total_deferred_ok / total_deferred;
        fprintf(stderr, "  Correlation: %.1f%% retry success (%lu of %lu deferred)\n",
                success_rate, ts->total_deferred_ok, total_deferred);
    }

    /* ── Async Logger ────────────────────────────────────────────────── */
    if (log_stats) {
        fprintf(stderr, "\n  %sAsync Logger%s\n", cyan, reset);
        fprintf(stderr, "  %s----------------------------------------------%s\n", dim, reset);
        fprintf(stderr, "  Messages: %lu (%s)\n",
                log_stats->messages, stats_format_bytes(log_stats->bytes, bytebuf, sizeof(bytebuf)));
        fprintf(stderr, "  Batches:  %lu", log_stats->batches);
        if (log_stats->batches > 0) {
            fprintf(stderr, " (avg %.1f msgs/batch)", (double)log_stats->messages / log_stats->batches);
        }
        fprintf(stderr, "\n");
        if (log_stats->drops > 0) {
            fprintf(stderr, "  %sDropped:  %lu (ring full)%s\n", yellow, log_stats->drops, reset);
        }
        if (log_stats->alloc_failures > 0) {
            fprintf(stderr, "  %sAlloc fail: %lu (entry pool exhausted)%s\n",
                    yellow, log_stats->alloc_failures, reset);
        }
    }

    /* ── Workers ─────────────────────────────────────────────────────── */
    fprintf(stderr, "\n  %sWorkers (%d)%s\n", cyan, ts->num_workers, reset);
    fprintf(stderr, "  %s----------------------------------------------%s\n", dim, reset);

    for (int i = 0; i < ts->num_workers; i++) {
        if (ts->worker_processed[i] > 0 || ts->worker_dropped[i] > 0) {
            fprintf(stderr, "  Worker %2d: %lu events", i, ts->worker_processed[i]);
            if (ts->worker_dropped[i] > 0) {
                fprintf(stderr, " (%lu dropped)", ts->worker_dropped[i]);
            }
            if (ts->worker_deferred_ok[i] > 0 || ts->worker_deferred_fail[i] > 0) {
                fprintf(stderr, " [retry: %lu ok, %lu fail]",
                        ts->worker_deferred_ok[i], ts->worker_deferred_fail[i]);
            }
            fprintf(stderr, "\n");
        }
    }

    /* CPU efficiency */
    if (ts->total_sleep_cycles > 0) {
        fprintf(stderr, "  CPU: %sGood%s (NAPI-style, %lu sleep cycles)\n",
                green, reset, ts->total_sleep_cycles);
    } else if (ts->total_processed > 0) {
        fprintf(stderr, "  CPU: %sHigh load%s (continuous processing)\n",
                yellow, reset);
    }

    /* ── Deferred Display Queue (XDP Correlation) ─────────────────────── */
    const deferred_stats_t *ds = &ts->deferred;
    uint64_t deferred_total = atomic_load(&ds->total_deferred);

    if (deferred_total > 0) {
        fprintf(stderr, "\n  %sDeferred Display Queue (XDP Correlation)%s\n", cyan, reset);
        fprintf(stderr, "  %s----------------------------------------------%s\n", dim, reset);

        uint64_t matched = atomic_load(&ds->matched_xdp);
        uint64_t timed_out = atomic_load(&ds->timed_out);
        uint64_t forced = atomic_load(&ds->forced_flush);

        double match_rate = 100.0 * matched / deferred_total;
        fprintf(stderr, "  Matched:     %lu (XDP arrived in time)\n", matched);
        fprintf(stderr, "  Timed out:   %lu (no XDP within timeout)\n", timed_out);
        if (forced > 0) {
            fprintf(stderr, "  %sForce flush: %lu (queue overflow)%s\n",
                    yellow, forced, reset);
        }
        fprintf(stderr, "  Match rate:  %.1f%%\n", match_rate);

        /* Health assessment */
        if (match_rate >= 95.0) {
            fprintf(stderr, "  Health:      %sExcellent%s (XDP correlation working well)\n",
                    green, reset);
        } else if (match_rate >= 80.0) {
            fprintf(stderr, "  Health:      %sGood%s (some timing gaps)\n",
                    green, reset);
        } else if (match_rate >= 50.0) {
            fprintf(stderr, "  Health:      %sWarning%s (frequent timing issues)\n",
                    yellow, reset);
        } else {
            fprintf(stderr, "  Health:      %sCritical%s (XDP correlation failing)\n",
                    yellow, reset);
        }
    }

    /* ── Flow Pool ───────────────────────────────────────────────────── */
    const flow_pool_stats_t *fp = &ts->flow_pool;

    fprintf(stderr, "\n  %sFlow Pool%s\n", cyan, reset);
    fprintf(stderr, "  %s----------------------------------------------%s\n", dim, reset);

    fprintf(stderr, "  Active:      %lu flows, peak %lu\n",
            fp->pool_allocated, fp->pool_peak);
    fprintf(stderr, "  Throughput:  %lu allocs, %lu frees\n",
            fp->pool_total_allocs, fp->pool_total_frees);
    if (fp->pool_alloc_failures > 0) {
        fprintf(stderr, "  %sOOM:         %lu allocation failures%s\n",
                yellow, fp->pool_alloc_failures, reset);
    }

    /* Flow index details */
    uint64_t cookie_total = fp->cookie_hits + fp->cookie_misses;
    double cookie_hit_rate = cookie_total > 0
        ? 100.0 * fp->cookie_hits / cookie_total : 0.0;
    fprintf(stderr, "  Cookie index: %lu entries, %lu hits (%.1f%%), %lu misses\n",
            fp->cookie_count, fp->cookie_hits, cookie_hit_rate, fp->cookie_misses);
    fprintf(stderr, "  Shadow index: %lu entries, %lu hits, %lu promotions\n",
            fp->shadow_count, fp->shadow_hits, fp->shadow_promotions);

    /* Show merge statistics if any merges occurred */
    if (fp->shadow_merges > 0) {
        fprintf(stderr, "  Merges:       %lu (XDP flows absorbed into SSL flows)\n",
                fp->shadow_merges);
    }

    if (fp->pool_total_allocs > 0) {
        double promo_rate = 100.0 * fp->shadow_promotions / fp->pool_total_allocs;
        fprintf(stderr, "  Promotion:    %.1f%% of flows got socket_cookie\n", promo_rate);
    }

    /* ── Network Layer (XDP) ─────────────────────────────────────────── */
    if (xdp) {
        fprintf(stderr, "\n  %sNetwork Layer (XDP)%s\n", cyan, reset);
        fprintf(stderr, "  %s----------------------------------------------%s\n", dim, reset);

        fprintf(stderr, "  Packets:     %lu processed (%lu TCP)\n",
                xdp->packets_total, xdp->packets_tcp);
        fprintf(stderr, "  Connections: %lu tracked", xdp->flows_created);
        if (xdp->flows_classified > 0) {
            fprintf(stderr, ", %lu classified", xdp->flows_classified);
        }
        fprintf(stderr, "\n");

        /* Correlation success rate */
        if (xdp->flows_created > 0) {
            uint64_t correlated = xdp->flows_created - xdp->cookie_failures;
            double corr_pct = 100.0 * correlated / xdp->flows_created;
            fprintf(stderr, "  Correlation: %.1f%% socket cookie success\n", corr_pct);
        }

        /* XDP classification details */
        fprintf(stderr, "  Classified:  %lu flows\n", xdp->flows_classified);
        fprintf(stderr, "  Ambiguous:   %lu (deeper inspection needed)\n", xdp->flows_ambiguous);
        fprintf(stderr, "  Terminated:  %lu (FIN/RST)\n", xdp->flows_terminated);
        fprintf(stderr, "  Cache hits:  %lu (fast-path gatekeeper)\n", xdp->gatekeeper_hits);
        fprintf(stderr, "  Cookie miss: %lu (correlation gaps)\n", xdp->cookie_failures);
        if (xdp->ringbuf_drops > 0) {
            fprintf(stderr, "  %sRing drops:  %lu (buffer full)%s\n",
                    yellow, xdp->ringbuf_drops, reset);
        }

        /* Sockops */
        uint64_t sockops_total = xdp->sockops_active + xdp->sockops_passive;
        fprintf(stderr, "\n  %sSockops (cookie caching)%s\n", cyan, reset);
        fprintf(stderr, "  %s----------------------------------------------%s\n", dim, reset);

        if (sockops_total > 0 || xdp->sockops_state > 0) {
            fprintf(stderr, "  Events:  %lu (active: %lu, passive: %lu)\n",
                    sockops_total, xdp->sockops_active, xdp->sockops_passive);
            fprintf(stderr, "  Cleanup: %lu\n", xdp->sockops_state);
        } else {
            fprintf(stderr, "  %sWARNING: No sockops events - cookie caching inactive!%s\n",
                    yellow, reset);
            fprintf(stderr, "  (Check cgroup2 mount and sockops attachment)\n");
        }
    }

    /* ── SSL Probes ──────────────────────────────────────────────────── */
    if (loader) {
        struct bpf_object *obj = bpf_loader_get_object(loader);
        if (obj) {
            struct bpf_map *map = bpf_object__find_map_by_name(obj, "ssl_op_counter");
            if (map) {
                int fd = bpf_map__fd(map);
                uint32_t key = 0;
                uint64_t counter = 0;
                if (bpf_map_lookup_elem(fd, &key, &counter) == 0 && counter > 0) {
                    fprintf(stderr, "\n  %sSSL Probes%s\n", cyan, reset);
                    fprintf(stderr, "  %s----------------------------------------------%s\n",
                            dim, reset);
                    fprintf(stderr, "  SSL_read/SSL_write intercepted: %lu\n", counter);
                }
            }
        }
    }

    fprintf(stderr, "\n%s============================================%s\n\n", dim, reset);
}
