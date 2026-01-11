/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
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
#include "../protocol/http2.h"
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

/* Known IPC/internal thread patterns
 * NOTE: "Socket Thread" is Firefox's legitimate web traffic thread - DO NOT filter it */
static const char *ipc_thread_patterns[] = {
    "Cache2 I/O",       /* Firefox cache I/O */
    "Timer",            /* Timer threads */
    "LS Thread",        /* Firefox local storage */
    "BgIOThr",          /* Background I/O threads */
    "TaskScheduler",    /* Chromium task scheduler */
    "Chrome_IOThread",  /* Chrome I/O thread */
    "Compositor",       /* Compositor threads */
    "GPU Process",      /* GPU process threads */
    "AudioIPC",         /* Audio IPC threads */
    "PaintThread",      /* Painting threads */
    "DOM Worker",       /* Web workers */
    "JS Helper",        /* JavaScript helpers */
    "StyleThread",      /* Style computation threads */
    NULL
};


/* Check if data looks like IPC/binary protocol rather than HTTP */
static bool is_ipc_traffic(const ssl_data_event_t *e) {
    if (e->buf_filled < 2) return true;  /* Too short to be HTTP */

    const uint8_t *data = e->data;
    size_t len = e->buf_filled;

    /* Check for HTTP/1.x signatures */
    if (len >= 4) {
        /* Request methods */
        if (memcmp(data, "GET ", 4) == 0 ||
            memcmp(data, "POST", 4) == 0 ||
            memcmp(data, "PUT ", 4) == 0 ||
            memcmp(data, "HEAD", 4) == 0 ||
            memcmp(data, "DELE", 4) == 0 ||  /* DELETE */
            memcmp(data, "PATC", 4) == 0 ||  /* PATCH */
            memcmp(data, "OPTI", 4) == 0) {  /* OPTIONS */
            return false;  /* Looks like HTTP request */
        }
        /* Response status line */
        if (memcmp(data, "HTTP", 4) == 0) {
            return false;  /* Looks like HTTP response */
        }
    }

    /* Check for HTTP/2 connection preface (full or partial) */
    if (len >= 24 && memcmp(data, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) {
        return false;  /* HTTP/2 preface */
    }
    /* Also check for partial HTTP/2 preface start (when preface is split across reads) */
    if (len >= 4 && memcmp(data, "PRI ", 4) == 0) {
        return false;  /* HTTP/2 preface start */
    }

    /* Check for HTTP/2 frame header (first byte should be frame length high byte,
     * second and third are length, fourth is type 0x00-0x09) */
    if (len >= 9) {
        uint8_t frame_type = data[3];
        uint32_t frame_len = ((uint32_t)data[0] << 16) | ((uint32_t)data[1] << 8) | data[2];
        /* Accept frame types 0-9, lengths up to 64KB (common max frame size) */
        if (frame_type <= 9 && frame_len <= 65536) {
            /* Looks like a valid HTTP/2 frame */
            return false;
        }
    }

    /* Check for high concentration of non-printable bytes (binary data)
     * Note: HPACK-compressed headers and gzip bodies have many non-printable bytes
     * so we use a high threshold to avoid false positives */
    int non_printable = 0;
    size_t check_len = len > 64 ? 64 : len;  /* Check first 64 bytes */
    for (size_t i = 0; i < check_len; i++) {
        uint8_t c = data[i];
        /* Non-printable and not common whitespace */
        if (c < 0x20 && c != '\r' && c != '\n' && c != '\t') {
            non_printable++;
        }
    }
    /* If more than 50% non-printable, likely binary IPC
     * (increased from 30% to reduce false positives with compressed data) */
    if (non_printable * 100 / check_len > 50) {
        return true;
    }

    return false;  /* Looks like it could be text/HTTP */
}

/* Check if comm name matches known internal thread patterns */
static bool is_internal_thread(const char *comm) {
    for (int i = 0; ipc_thread_patterns[i] != NULL; i++) {
        if (strstr(comm, ipc_thread_patterns[i])) {
            return true;
        }
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

/* Forward declarations for NSS SSL FD tracking (via SSL_ImportFD) */
static void track_nss_ssl_fd(probe_handler_t *handler, const ssl_data_event_t *e);
static void cleanup_nss_ssl_fds_pid(probe_handler_t *handler, uint32_t pid);

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

    /* Handshake and ALPN events have no buffer data - always pass through */
    if (e->event_type == EVENT_HANDSHAKE || e->event_type == EVENT_ALPN) return true;

    /* Filter truly internal threads (non-HTTP traffic like file cache) */
    if (e->buf_filled <= 1) return false;

    /*
     * Enhanced IPC filtering (always on - BPF handles kernel-level socket family
     * filtering, this provides additional userspace heuristics as backup)
     */

    /* Check for known internal thread patterns */
    if (is_internal_thread(e->comm)) return false;

    /* Content-based IPC detection for all traffic.
     * Skip if this connection has an active HTTP/2 session (definitely web traffic) */
    bool has_h2 = http2_has_session(e->pid, e->ssl_ctx);
    if (!has_h2) {
        /* Check if data looks like IPC rather than HTTP */
        if (is_ipc_traffic(e)) return false;
    }

    return true;
}

/* Ring buffer event callback */
static int handle_event(void *ctx, void *data, size_t sz) {
    (void)sz;
    probe_handler_t *handler = (probe_handler_t *)ctx;
    const ssl_data_event_t *e = (const ssl_data_event_t *)data;

    /* Handle NSS SSL_ImportFD tracking events (always process, even if filtered) */
    if (e->event_type == EVENT_NSS_SSL_FD) {
        track_nss_ssl_fd(handler, e);
        /* Don't forward to callback - this is internal tracking */
        return 0;
    }

    /* Handle process exit - cleanup NSS SSL FDs */
    if (e->event_type == EVENT_PROCESS_EXIT) {
        cleanup_nss_ssl_fds_pid(handler, e->pid);
        /* Still forward to callback for other cleanup */
    }

    if (!should_display(handler, e)) return 0;

    if (handler->callback) {
        handler->callback(e, handler->callback_ctx);
    }

    return 0;
}

/* Track an NSS SSL FD from SSL_ImportFD */
static void track_nss_ssl_fd(probe_handler_t *handler, const ssl_data_event_t *e) {
    if (!handler || !e) return;

    /* Check if already tracked */
    for (int i = 0; i < handler->nss_ssl_fd_count; i++) {
        if (handler->nss_ssl_fds[i].active &&
            handler->nss_ssl_fds[i].pid == e->pid &&
            handler->nss_ssl_fds[i].fd == e->ssl_ctx) {
            /* Already tracked */
            return;
        }
    }

    /* Find empty slot or evict oldest */
    int slot = -1;
    for (int i = 0; i < NSS_CONN_CACHE_SIZE; i++) {
        if (!handler->nss_ssl_fds[i].active) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        /* Cache full, evict first entry */
        slot = 0;
        /* Shift all entries */
        for (int i = 1; i < NSS_CONN_CACHE_SIZE; i++) {
            handler->nss_ssl_fds[i-1] = handler->nss_ssl_fds[i];
        }
        slot = NSS_CONN_CACHE_SIZE - 1;
    }

    /* Store the SSL FD info */
    handler->nss_ssl_fds[slot].pid = e->pid;
    handler->nss_ssl_fds[slot].fd = e->ssl_ctx;
    handler->nss_ssl_fds[slot].active = true;

    if (slot >= handler->nss_ssl_fd_count) {
        handler->nss_ssl_fd_count = slot + 1;
    }
}

/* Cleanup NSS SSL FDs for a specific PID */
static void cleanup_nss_ssl_fds_pid(probe_handler_t *handler, uint32_t pid) {
    if (!handler) return;

    for (int i = 0; i < handler->nss_ssl_fd_count; i++) {
        if (handler->nss_ssl_fds[i].active &&
            handler->nss_ssl_fds[i].pid == pid) {
            handler->nss_ssl_fds[i].active = false;
        }
    }
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
    handler->filter_ipc = false;
    handler->nss_ssl_fd_count = 0;

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

void probe_handler_set_filter_ipc(probe_handler_t *handler, bool filter) {
    if (!handler) return;
    handler->filter_ipc = filter;
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
