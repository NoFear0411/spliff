/**
 * @file stats.h
 * @brief Session statistics output module
 *
 * This module handles formatted output of session statistics including
 * threading metrics, flow pool status, XDP correlation, and BPF probes.
 *
 * @copyright Copyright (c) 2026
 */

#ifndef SPLIFF_STATS_H
#define SPLIFF_STATS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Forward declarations - use actual types from other modules */
#include "../threading/threading.h"
#include "../bpf/bpf_loader.h"
#include "logger.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Print session shutdown statistics to stderr
 *
 * Formats and outputs all session statistics including:
 * - Application layer (SSL/TLS) events and processing
 * - Worker thread statistics
 * - Flow pool usage and correlation
 * - Network layer (XDP) if enabled
 * - Async logger statistics
 *
 * @param ts Threading stats from threading_get_aggregate_stats()
 * @param xdp XDP stats from bpf_loader_xdp_read_stats() (may be NULL)
 * @param loader BPF loader for SSL probe stats (may be NULL)
 * @param log_stats Async logger stats (may be NULL)
 * @param use_colors Whether to use ANSI color codes
 */
void stats_print_session(const threading_stats_t *ts,
                         const xdp_stats_t *xdp,
                         bpf_loader_t *loader,
                         const logger_stats_t *log_stats,
                         bool use_colors);

/**
 * @brief Format byte count into human-readable string
 *
 * @param bytes Byte count
 * @param buf Output buffer
 * @param size Buffer size
 * @return Pointer to buf
 */
char *stats_format_bytes(uint64_t bytes, char *buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* SPLIFF_STATS_H */
