/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * sslsniff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 sslsniff authors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * probe_handler.h - Ring buffer event handling and filtering
 */

#ifndef PROBE_HANDLER_H
#define PROBE_HANDLER_H

#include <stdint.h>
#include <stdbool.h>
#include <bpf/libbpf.h>
#include "../include/sslsniff.h"

#define MAX_BUF_SIZE 16384
#define PID_CACHE_SIZE 1024

/* Event types */
enum event_type {
    EVENT_SSL_READ = 0,
    EVENT_SSL_WRITE = 1,
    EVENT_HANDSHAKE = 2,
    EVENT_PROCESS_EXIT = 3
};

/* SSL data event from BPF (must match BPF side) */
typedef struct {
    uint64_t timestamp_ns;
    uint64_t delta_ns;       /* Latency (function execution time) */
    uint64_t ssl_ctx;        /* SSL context pointer for connection tracking */
    uint32_t pid;
    uint32_t tid;
    uint32_t uid;
    uint32_t len;
    int32_t buf_filled;
    uint32_t event_type;     /* EVENT_SSL_READ, EVENT_SSL_WRITE, EVENT_HANDSHAKE */
    char comm[TASK_COMM_LEN];
    uint8_t data[MAX_BUF_SIZE];
} ssl_data_event_t;

/* Event callback function type */
typedef void (*event_callback_t)(const ssl_data_event_t *event, void *ctx);

/* Probe handler state */
typedef struct {
    struct ring_buffer *rb;
    event_callback_t callback;
    void *callback_ctx;

    /* Filtering */
    char target_comm[64];
    int *target_pids;
    int num_target_pids;
    int target_ppid;
    int ppid_cache[PID_CACHE_SIZE];
    int ppid_cache_count;
} probe_handler_t;

/* Initialize probe handler - returns 0 on success, -1 on failure */
[[nodiscard]] int probe_handler_init(probe_handler_t *handler);

/* Set event callback */
void probe_handler_set_callback(probe_handler_t *handler, event_callback_t callback, void *ctx);

/* Set filtering options */
void probe_handler_set_filter_comm(probe_handler_t *handler, const char *comm);
void probe_handler_set_filter_pids(probe_handler_t *handler, int *pids, int count);
void probe_handler_set_filter_ppid(probe_handler_t *handler, int ppid);

/* Setup ring buffer from BPF object - returns 0 on success, -1 on failure */
[[nodiscard]] int probe_handler_setup_ringbuf(probe_handler_t *handler, struct bpf_object *obj);

/* Poll ring buffer for events - returns number of events or negative on error */
int probe_handler_poll(probe_handler_t *handler, int timeout_ms);

/* Cleanup */
void probe_handler_cleanup(probe_handler_t *handler);

#endif /* PROBE_HANDLER_H */
