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
 */

#include "probe_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <strings.h>
#include <unistd.h>
#include <limits.h>

/* PPID cache refresh timestamp */
static uint64_t ppid_cache_time = 0;

/* Check if a process's executable matches the target comm */
static bool exe_matches_comm(int pid, const char *target) {
    char exe_path[64];
    char resolved[512];

    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
    ssize_t len = readlink(exe_path, resolved, sizeof(resolved) - 1);
    if (len > 0) {
        resolved[len] = '\0';
        /* Check if executable path contains target (e.g., "firefox") */
        if (strcasestr(resolved, target)) {
            return true;
        }
    }
    return false;
}

/* Get parent PID of a process */
static int get_ppid(int pid) {
    char stat_path[64];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);

    FILE *f = fopen(stat_path, "r");
    if (!f) return -1;

    int ppid = -1;
    char line[512];
    if (fgets(line, sizeof(line), f)) {
        char *paren = strrchr(line, ')');
        if (paren) {
            int scanned_ppid;
            if (sscanf(paren + 2, "%*c %d", &scanned_ppid) == 1) {
                ppid = scanned_ppid;
            }
        }
    }
    fclose(f);
    return ppid;
}

/* Check if pid is descendant of ancestor (up to max_depth levels) */
static bool is_descendant_of(int pid, int ancestor, int max_depth) {
    if (pid <= 1 || ancestor <= 0 || max_depth <= 0) return false;
    if (pid == ancestor) return true;

    int current = pid;
    for (int depth = 0; depth < max_depth && current > 1; depth++) {
        int parent = get_ppid(current);
        if (parent <= 0) break;
        if (parent == ancestor) return true;
        current = parent;
    }
    return false;
}

/* Refresh PPID cache (for --ppid filtering) - builds list of all descendants */
static void refresh_ppid_cache(probe_handler_t *handler) {
    if (handler->target_ppid == 0) return;

    uint64_t now = 0;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        now = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    }

    /* Refresh every 2 seconds */
    if (ppid_cache_time > 0 && now - ppid_cache_time < 2000) return;
    ppid_cache_time = now;

    handler->ppid_cache_count = 0;

    /* Read all PIDs from /proc */
    DIR *proc = opendir("/proc");
    if (!proc) return;

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL && handler->ppid_cache_count < PID_CACHE_SIZE) {
        /* Skip non-numeric entries */
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

        char *endptr;
        long pid_long = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid_long <= 0 || pid_long > INT_MAX) continue;
        int pid = (int)pid_long;

        /* Include if this is the target OR is a descendant (up to 5 levels deep) */
        if (pid == handler->target_ppid || is_descendant_of(pid, handler->target_ppid, 5)) {
            handler->ppid_cache[handler->ppid_cache_count++] = pid;
        }
    }

    closedir(proc);
}

/* Check if event should be displayed */
static bool should_display(probe_handler_t *handler, const ssl_data_event_t *e) {
    bool passes = (handler->target_comm[0] == '\0' &&
                   handler->num_target_pids == 0 &&
                   handler->target_ppid == 0);

    /* Check comm filter - match by comm name OR executable path */
    if (handler->target_comm[0]) {
        /* First check comm name (substring, case-insensitive) */
        if (strcasestr(e->comm, handler->target_comm)) {
            passes = true;
        }
        /* Also check executable path (for multi-process apps like Firefox
         * where child processes have different comm names) */
        else if (exe_matches_comm(e->pid, handler->target_comm)) {
            passes = true;
        }
    }

    /* Check PID filter */
    for (int i = 0; i < handler->num_target_pids; i++) {
        if (e->pid == (uint32_t)handler->target_pids[i]) {
            passes = true;
        }
    }

    /* Check PPID filter (for multi-process apps like Firefox) */
    if (handler->target_ppid > 0) {
        refresh_ppid_cache(handler);
        for (int i = 0; i < handler->ppid_cache_count; i++) {
            if (e->pid == (uint32_t)handler->ppid_cache[i]) {
                passes = true;
                break;
            }
        }
    }

    if (!passes) return false;

    /* Handshake events have no buffer data - always pass through */
    if (e->event_type == EVENT_HANDSHAKE) return true;

    /* Filter truly internal threads (non-HTTP traffic like file cache) */
    if (e->buf_filled <= 1) return false;
    if (strstr(e->comm, "Cache2 I/O") || strstr(e->comm, "Timer") ||
        strstr(e->comm, "LS Thread") || strstr(e->comm, "BgIOThr")) return false;

    return true;
}

/* Ring buffer event callback */
static int handle_event(void *ctx, void *data, size_t sz) {
    (void)sz;
    probe_handler_t *handler = (probe_handler_t *)ctx;
    const ssl_data_event_t *e = (const ssl_data_event_t *)data;

    if (!should_display(handler, e)) return 0;

    if (handler->callback) {
        handler->callback(e, handler->callback_ctx);
    }

    return 0;
}

/* Initialize probe handler */
int probe_handler_init(probe_handler_t *handler) {
    if (!handler) return -1;

    memset(handler, 0, sizeof(*handler));
    handler->rb = NULL;
    handler->callback = NULL;
    handler->callback_ctx = NULL;
    handler->target_comm[0] = '\0';
    handler->target_pids = NULL;
    handler->num_target_pids = 0;
    handler->target_ppid = 0;
    handler->ppid_cache_count = 0;

    return 0;
}

/* Set event callback */
void probe_handler_set_callback(probe_handler_t *handler, event_callback_t callback, void *ctx) {
    if (!handler) return;
    handler->callback = callback;
    handler->callback_ctx = ctx;
}

/* Set filtering options */
void probe_handler_set_filter_comm(probe_handler_t *handler, const char *comm) {
    if (!handler || !comm) return;
    snprintf(handler->target_comm, sizeof(handler->target_comm), "%s", comm);
}

void probe_handler_set_filter_pids(probe_handler_t *handler, int *pids, int count) {
    if (!handler) return;
    handler->target_pids = pids;
    handler->num_target_pids = count;
}

void probe_handler_set_filter_ppid(probe_handler_t *handler, int ppid) {
    if (!handler) return;
    handler->target_ppid = ppid;
}

/* Setup ring buffer from BPF object */
int probe_handler_setup_ringbuf(probe_handler_t *handler, struct bpf_object *obj) {
    if (!handler || !obj) return -1;

    int rb_fd = bpf_object__find_map_fd_by_name(obj, "ssl_events");
    if (rb_fd < 0) {
        return -1;
    }

    handler->rb = ring_buffer__new(rb_fd, handle_event, handler, NULL);
    if (!handler->rb) {
        return -1;
    }

    return 0;
}

/* Poll ring buffer for events */
int probe_handler_poll(probe_handler_t *handler, int timeout_ms) {
    if (!handler || !handler->rb) return -1;
    return ring_buffer__poll(handler->rb, timeout_ms);
}

/* Cleanup */
void probe_handler_cleanup(probe_handler_t *handler) {
    if (!handler) return;

    if (handler->rb) {
        ring_buffer__free(handler->rb);
        handler->rb = NULL;
    }
}
