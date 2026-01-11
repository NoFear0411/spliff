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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include "include/spliff.h"
#include "bpf/bpf_loader.h"
#include "bpf/probe_handler.h"
#include "output/display.h"
#include "content/decompressor.h"
#include "content/signatures.h"
#include "protocol/http1.h"
#include "protocol/http2.h"
#include "util/safe_str.h"

#ifdef HAVE_THREADING
#include "threading/threading.h"
#endif

/* Global state */
static volatile sig_atomic_t g_exiting = 0;
static bpf_loader_t g_loader;
static probe_handler_t g_handler;
static bool g_modules_initialized = false;
static bool g_bpf_initialized = false;
static bool g_probe_initialized = false;

#ifdef HAVE_THREADING
static threading_mgr_t g_threading;
static bool g_threading_initialized = false;
static bool g_threading_enabled = false;  /* Set by CLI or auto-detect */
#endif

/* Configuration - IPC filtering enabled by default (BPF handles kernel-level filtering) */
config_t g_config = {
    .filter_ipc = true,  /* Always on - BPF does socket family filtering */
    .use_colors = true,  /* Colors on by default */
};

/* Forward declarations for cleanup */
static void cleanup_pending_bodies(void);
static void cleanup_all_resources(void);

/* Get real process name from /proc/PID/comm (not thread name) */
static void get_process_name(uint32_t pid, char *buf, size_t bufsize) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/comm", pid);

    FILE *f = fopen(path, "r");
    if (f) {
        if (fgets(buf, bufsize, f)) {
            /* Remove trailing newline */
            size_t len = strlen(buf);
            if (len > 0 && buf[len-1] == '\n') {
                buf[len-1] = '\0';
            }
        }
        fclose(f);
    }
}

/* ALPN cache - tracks negotiated ALPN protocols per connection
 * Used by single-threaded event processing (process_event)
 * Note: In multi-threaded mode, per-worker ALPN cache is used instead
 */
#define ST_MAX_ALPN_CACHE 128

/* Use a different name to avoid conflict with threading.h's alpn_cache_entry_t */
typedef struct st_alpn_cache_entry {
    uint32_t pid;
    uint64_t ssl_ctx;
    char alpn_proto[16];
    bool active;
} st_alpn_cache_entry_t;

static st_alpn_cache_entry_t g_alpn_cache[ST_MAX_ALPN_CACHE];

static const char *get_alpn_proto(uint32_t pid, uint64_t ssl_ctx) {
    /* First check H2 sessions (they store ALPN internally) */
    const char *h2_alpn = http2_get_alpn(pid, ssl_ctx);
    if (h2_alpn && h2_alpn[0]) {
        return h2_alpn;
    }
    /* Then check our cache (for HTTP/1.1 connections) */
    for (int i = 0; i < ST_MAX_ALPN_CACHE; i++) {
        if (g_alpn_cache[i].active &&
            g_alpn_cache[i].pid == pid &&
            g_alpn_cache[i].ssl_ctx == ssl_ctx) {
            return g_alpn_cache[i].alpn_proto;
        }
    }
    return NULL;
}

static void set_alpn_proto(uint32_t pid, uint64_t ssl_ctx, const char *alpn) {
    /* Find existing or empty slot */
    st_alpn_cache_entry_t *slot = NULL;
    int oldest_idx = 0;

    for (int i = 0; i < ST_MAX_ALPN_CACHE; i++) {
        if (g_alpn_cache[i].active &&
            g_alpn_cache[i].pid == pid &&
            g_alpn_cache[i].ssl_ctx == ssl_ctx) {
            slot = &g_alpn_cache[i];
            break;
        }
        if (!g_alpn_cache[i].active) {
            slot = &g_alpn_cache[i];
            break;
        }
    }
    /* If no slot found, evict oldest (first one) */
    if (!slot) {
        slot = &g_alpn_cache[oldest_idx];
    }

    slot->pid = pid;
    slot->ssl_ctx = ssl_ctx;
    slot->active = true;
    safe_strcpy(slot->alpn_proto, sizeof(slot->alpn_proto), alpn ? alpn : "");

    /* Also store in H2 session if it exists */
    http2_set_alpn(pid, ssl_ctx, alpn);
}

/* Pending body state - tracks responses expecting body data */
#define BODY_ACCUM_SIZE (256 * 1024)  /* 256KB accumulation buffer */

typedef struct {
    uint32_t pid;
    uint64_t ssl_ctx;     /* SSL context pointer for connection tracking */
    size_t expected_len;
    size_t received_len;
    char content_type[256];
    char content_encoding[64];
    bool active;
    bool header_printed;  /* Whether we printed the body header */
    bool needs_decompression;
    uint8_t *accum_buf;   /* Accumulation buffer for compressed data */
    size_t accum_len;
} pending_body_t;

#define MAX_PENDING_BODIES 16
static pending_body_t g_pending_bodies[MAX_PENDING_BODIES];

static pending_body_t *find_pending_body(uint32_t pid, uint64_t ssl_ctx) {
    for (int i = 0; i < MAX_PENDING_BODIES; i++) {
        if (g_pending_bodies[i].active &&
            g_pending_bodies[i].pid == pid &&
            g_pending_bodies[i].ssl_ctx == ssl_ctx) {
            return &g_pending_bodies[i];
        }
    }
    return NULL;
}

static void set_pending_body(uint32_t pid, uint64_t ssl_ctx, size_t len, const char *ct, const char *ce) {
    /* Find existing or empty slot */
    pending_body_t *slot = find_pending_body(pid, ssl_ctx);
    if (!slot) {
        for (int i = 0; i < MAX_PENDING_BODIES; i++) {
            if (!g_pending_bodies[i].active) {
                slot = &g_pending_bodies[i];
                break;
            }
        }
    }
    if (slot) {
        /* Free any existing buffer */
        if (slot->accum_buf) {
            free(slot->accum_buf);
            slot->accum_buf = NULL;
        }

        slot->pid = pid;
        slot->ssl_ctx = ssl_ctx;
        slot->expected_len = len;
        slot->received_len = 0;
        slot->accum_len = 0;
        slot->active = true;
        slot->header_printed = false;

        safe_strcpy(slot->content_type, sizeof(slot->content_type), ct ? ct : "");
        safe_strcpy(slot->content_encoding, sizeof(slot->content_encoding), ce ? ce : "");

        /* Check if decompression needed */
        slot->needs_decompression = (ce && ce[0] &&
            (strstr(ce, "gzip") || strstr(ce, "deflate") ||
             strstr(ce, "br") || strstr(ce, "zstd")));

        /* Allocate accumulation buffer for compressed data */
        if (slot->needs_decompression) {
            slot->accum_buf = malloc(BODY_ACCUM_SIZE);
            if (!slot->accum_buf) {
                slot->needs_decompression = false;  /* Fall back to no decompression */
            }
        }
    }
}

static void clear_pending_body(uint32_t pid, uint64_t ssl_ctx) {
    pending_body_t *p = find_pending_body(pid, ssl_ctx);
    if (p) {
        /* If we accumulated compressed data, decompress and display now */
        if (p->accum_buf && p->accum_len > 0) {
            uint8_t *decomp_buf = malloc(BODY_ACCUM_SIZE);
            if (decomp_buf) {
                int decomp_len = decompress_body(p->accum_buf, p->accum_len,
                                                 p->content_encoding,
                                                 decomp_buf, BODY_ACCUM_SIZE);
                if (decomp_len > 0) {
                    if (!p->header_printed) {
                        printf("%s─── Body ───%s\n", display_color(C_DIM), display_color(C_RESET));
                    }
                    fwrite(decomp_buf, 1, decomp_len, stdout);
                    if (decomp_buf[decomp_len-1] != '\n') printf("\n");
                    p->header_printed = true;
                }
                free(decomp_buf);
            }
        }

        if (p->header_printed) {
            printf("%s────────────%s\n\n", display_color(C_DIM), display_color(C_RESET));
        }

        /* Free buffer */
        if (p->accum_buf) {
            free(p->accum_buf);
            p->accum_buf = NULL;
        }
        p->active = false;
    }
}

/* Cleanup all pending body buffers - called at exit */
static void cleanup_pending_bodies(void) {
    for (int i = 0; i < MAX_PENDING_BODIES; i++) {
        if (g_pending_bodies[i].accum_buf) {
            free(g_pending_bodies[i].accum_buf);
            g_pending_bodies[i].accum_buf = NULL;
        }
        g_pending_bodies[i].active = false;
    }
}

/* Cleanup pending body buffers for a specific PID (process exit) */
static void cleanup_pending_bodies_pid(uint32_t pid) {
    for (int i = 0; i < MAX_PENDING_BODIES; i++) {
        if (g_pending_bodies[i].active && g_pending_bodies[i].pid == pid) {
            if (g_pending_bodies[i].accum_buf) {
                free(g_pending_bodies[i].accum_buf);
                g_pending_bodies[i].accum_buf = NULL;
            }
            g_pending_bodies[i].active = false;
        }
    }
}

/* Master cleanup function registered with atexit() */
static void cleanup_all_resources(void) {
#ifdef HAVE_THREADING
    /* Shutdown threading first (waits for workers to drain) */
    if (g_threading_initialized) {
        threading_shutdown(&g_threading);
        threading_print_stats(&g_threading);
        threading_cleanup(&g_threading);
        g_threading_initialized = false;
    }
#endif

    /* Cleanup probe handler (ring buffer) */
    if (g_probe_initialized) {
        probe_handler_cleanup(&g_handler);
        g_probe_initialized = false;
    }

    /* Cleanup BPF loader (detach probes, close object) */
    if (g_bpf_initialized) {
        bpf_loader_cleanup(&g_loader);
        g_bpf_initialized = false;
    }

    /* Cleanup pending body buffers (only in non-threaded mode) */
#ifdef HAVE_THREADING
    if (!g_threading_enabled)
#endif
    {
        cleanup_pending_bodies();
    }

    /* Cleanup modules in reverse order of initialization */
    if (g_modules_initialized) {
        http2_cleanup();
        http1_cleanup();
        decompressor_cleanup();
        signatures_cleanup();
        display_cleanup();
        g_modules_initialized = false;
    }
}

/* Signal handler */
static void sig_handler(int sig) {
    (void)sig;
    g_exiting = 1;
}

/* Setup signal handlers */
static void setup_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

/* Event processing callback */
static void process_event(const ssl_data_event_t *event, void *ctx) {
    (void)ctx;

    /* Handle process exit events - cleanup resources */
    if (event->event_type == EVENT_PROCESS_EXIT) {
        http2_cleanup_pid(event->pid);
        cleanup_pending_bodies_pid(event->pid);
        return;
    }

    /* Handle handshake events (no buffer data)
     * NOTE: Handshake events may arrive out of order relative to HTTP data due to
     * different probe timing. Future improvement: buffer events and sort by timestamp. */
    if (event->event_type == EVENT_HANDSHAKE) {
        if (g_config.show_handshake) {
            char proc_name[TASK_COMM_LEN] = {0};
            get_process_name(event->pid, proc_name, sizeof(proc_name));
            const char *name = proc_name[0] ? proc_name : event->comm;
            display_handshake(event->pid, name, event->delta_ns, (int)event->len);
        }
        return;
    }

    /* Handle ALPN protocol negotiation events */
    if (event->event_type == EVENT_ALPN) {
        if (event->buf_filled > 0 && event->buf_filled <= 255) {
            char alpn_proto[256] = {0};
            memcpy(alpn_proto, event->data, event->buf_filled);
            /* Store ALPN for later inclusion in request/response display */
            set_alpn_proto(event->pid, event->ssl_ctx, alpn_proto);
        }
        return;
    }

    if (event->buf_filled == 0) return;

    const uint8_t *data = event->data;
    size_t len = event->buf_filled;

    /* Try HTTP/1.1 parsing first (using llhttp with HTTP_BOTH) */
    if (http1_is_request(data, len) || http1_is_response(data, len)) {
        /* New HTTP message - clear any pending body from this connection */
        clear_pending_body(event->pid, event->ssl_ctx);

        http_message_t msg = {0};
        static uint8_t body_buf[MAX_BODY_BUFFER];  /* Static to avoid stack overflow */
        size_t body_len = 0;

        /* Parse with llhttp - handles both request/response and chunked decoding */
        int result = http1_parse(data, len, &msg,
                                 g_config.show_body ? body_buf : NULL,
                                 g_config.show_body ? MAX_BODY_BUFFER : 0,
                                 &body_len);

        if (result < 0) {
            /* Parse failed - show raw data info */
            goto show_raw;
        }

        /* Set metadata AFTER parsing (parse function clears the struct) */
        msg.pid = event->pid;
        msg.timestamp_ns = event->timestamp_ns;
        msg.delta_ns = event->delta_ns;

        /* Get real process name (not thread name like "Socket Thread") */
        char proc_name[TASK_COMM_LEN] = {0};
        get_process_name(event->pid, proc_name, sizeof(proc_name));
        if (proc_name[0]) {
            safe_strcpy(msg.comm, sizeof(msg.comm), proc_name);
        } else {
            safe_strcpy(msg.comm, sizeof(msg.comm), event->comm);
        }

        /* Get ALPN protocol if available */
        const char *alpn = get_alpn_proto(event->pid, event->ssl_ctx);
        if (alpn) {
            safe_strcpy(msg.alpn_proto, sizeof(msg.alpn_proto), alpn);
        }

        /* Display based on direction (auto-detected by llhttp) */
        if (msg.direction == DIR_REQUEST) {
            display_http_request(&msg);
        } else {
            display_http_response(&msg);
        }

        /* Show headers unless compact mode */
        if (!g_config.compact_mode && msg.header_count > 0) {
            display_http_headers(&msg);
        }

        /* Show body if requested and present */
        /* Note: llhttp already decoded chunked transfer encoding */
        if (g_config.show_body) {
            if (body_len > 0) {
                const uint8_t *body_data = body_buf;
                size_t display_len = body_len;

                /* Decompress if content-encoding is set */
                static uint8_t decomp_buf[MAX_BODY_BUFFER];  /* Static for large bodies */
                if (msg.content_encoding[0]) {
                    int decomp_len = decompress_body(body_data, body_len,
                                                     msg.content_encoding,
                                                     decomp_buf, MAX_BODY_BUFFER);
                    if (decomp_len > 0) {
                        body_data = decomp_buf;
                        display_len = decomp_len;
                    }
                }

                display_body(body_data, display_len, msg.content_type);
                clear_pending_body(event->pid, event->ssl_ctx);
            } else if (msg.direction == DIR_RESPONSE &&
                       (msg.content_length > 0 || msg.is_chunked)) {
                /* Body will arrive in next event - track it
                 * For chunked encoding, use 0 as expected_len (unknown size) */
                set_pending_body(event->pid, event->ssl_ctx,
                                 msg.content_length > 0 ? msg.content_length : 0,
                                 msg.content_type, msg.content_encoding);
            }
        }

        printf("\n");
        return;
    }

    /* Check if we already have an active HTTP/2 session for this (PID, ssl_ctx) */
    bool has_h2 = http2_has_session(event->pid, event->ssl_ctx);
    DEBUG_MAIN("PID=%u ssl_ctx=0x%llx has_h2_session=%d len=%zu",
               event->pid, (unsigned long long)event->ssl_ctx, has_h2, len);
    if (has_h2) {
        /* Always process data for active H2 sessions */
        http2_process_frame(data, len, event);
        return;
    }

    /* Check for HTTP/2 connection preface (client-side) */
    if (http2_is_preface(data, len)) {
        printf("%s[HTTP/2 connection]%s PID %u (%s)\n",
               display_color(C_YELLOW), display_color(C_RESET),
               event->pid, event->comm);

        /* Process any frames following the preface */
        if (len > 24) {
            http2_process_frame(data + 24, len - 24, event);
        }
        return;
    }

    /* Check for HTTP/2 frames (may attach mid-connection) */
    if (len >= 9) {
        /*
         * HTTP/2 frame header is 9 bytes:
         * - 3 bytes: length (big-endian, max 16384)
         * - 1 byte: type (0x00-0x09 are valid)
         * - 1 byte: flags
         * - 4 bytes: stream ID (with reserved bit)
         */
        uint32_t frame_len = ((uint32_t)data[0] << 16) |
                             ((uint32_t)data[1] << 8) |
                             (uint32_t)data[2];
        uint8_t frame_type = data[3];
        uint32_t stream_id = ((uint32_t)(data[5] & 0x7f) << 24) |
                             ((uint32_t)data[6] << 16) |
                             ((uint32_t)data[7] << 8) |
                             (uint32_t)data[8];

        /* Valid HTTP/2 frame: type 0x00-0x09, reasonable length */
        if (frame_type <= 0x09 && frame_len <= 16384) {
            /*
             * Detect HTTP/2 session from various frame types:
             * - SETTINGS (0x04): Standard connection start
             * - HEADERS (0x01): May see if attached mid-connection
             * - WINDOW_UPDATE (0x08): Common early frame
             *
             * Additional validation:
             * - SETTINGS/WINDOW_UPDATE/PING on stream 0
             * - HEADERS on odd stream IDs (client-initiated)
             * - Frame length + 9 should not exceed total data length
             */
            bool is_valid_h2 = false;

            if (frame_type == H2_FRAME_SETTINGS && stream_id == 0) {
                is_valid_h2 = true;
            } else if (frame_type == H2_FRAME_HEADERS && (stream_id & 1) != 0) {
                /* HEADERS on odd stream ID (client-initiated) */
                is_valid_h2 = true;
            } else if (frame_type == H2_FRAME_WINDOW_UPDATE && stream_id == 0) {
                is_valid_h2 = true;
            } else if (frame_type == H2_FRAME_DATA && (stream_id & 1) != 0 && frame_len > 0) {
                /* DATA frame on odd stream with actual content */
                is_valid_h2 = true;
            }

            /* Verify frame fits in buffer (additional sanity check) */
            if (is_valid_h2 && (9 + frame_len) <= len) {
                printf("%s[HTTP/2 connection]%s PID %u (%s)\n",
                       display_color(C_YELLOW), display_color(C_RESET),
                       event->pid, event->comm);
                http2_process_frame(data, len, event);
                return;
            }
        }
    }

    /* Check if this is body data for a pending response */
    if (g_config.show_body) {
        pending_body_t *pending = find_pending_body(event->pid, event->ssl_ctx);
        if (pending && pending->active) {
            pending->received_len += len;

            /* For compressed content, accumulate raw data for deferred decompression */
            if (pending->needs_decompression && pending->accum_buf) {
                /* Accumulate compressed data */
                if (pending->accum_len + len <= BODY_ACCUM_SIZE) {
                    memcpy(pending->accum_buf + pending->accum_len, data, len);
                    pending->accum_len += len;
                }
                /* Check if complete (Content-Length known) */
                if (pending->expected_len > 0 && pending->received_len >= pending->expected_len) {
                    clear_pending_body(event->pid, event->ssl_ctx);
                }
                /* For chunked (expected_len=0), wait for next HTTP message to trigger clear */
                return;
            }

            /* Non-compressed: stream directly */
            if (!pending->header_printed) {
                printf("%s─── Body ───%s\n", display_color(C_DIM), display_color(C_RESET));
                pending->header_printed = true;
            }

            /* For text content, stream it directly */
            bool is_text = (strstr(pending->content_type, "text/") != NULL ||
                           strstr(pending->content_type, "json") != NULL ||
                           strstr(pending->content_type, "xml") != NULL ||
                           strstr(pending->content_type, "javascript") != NULL);

            if (is_text) {
                fwrite(data, 1, len, stdout);
            } else {
                printf("[binary chunk: %zu bytes]\n", len);
            }

            /* Check if we've received all expected data */
            if (pending->expected_len > 0 && pending->received_len >= pending->expected_len) {
                clear_pending_body(event->pid, event->ssl_ctx);
            }
            fflush(stdout);

            return;
        }
    }

show_raw:
    /* Unknown/binary data - show basic info */
    ;  /* Empty statement after label for C99 compliance */

    /* Try to detect file type early to filter non-HTTP traffic */
    const char *sig = signature_detect(data, len);
    if (signature_is_local_file(sig)) {
        /* Skip local file I/O (ELF, Mach-O, SQLite, etc.) - not HTTP traffic */
        return;
    }

    /* Suppress HTTP/2 control frames in release mode (keep them in debug mode)
     * HTTP/2 frame header is 9 bytes, control frames have small payloads:
     * - SETTINGS ACK: 9 bytes (0 payload)
     * - WINDOW_UPDATE: 13 bytes (4 byte payload)
     * - PING: 17 bytes (8 byte payload)
     * - RST_STREAM: 13 bytes (4 byte payload)
     * - PRIORITY: 14 bytes (5 byte payload)
     */
    if (!g_config.debug_mode) {
        if (len >= 9 && len <= 32) {
            uint8_t frame_type = data[3];
            /* Suppress known control frame types (types 0x02-0x08, excluding DATA and HEADERS) */
            if (frame_type >= 0x02 && frame_type <= 0x08) {
                return;  /* Suppress control frame output */
            }
        }

        /* Also suppress very small writes (< 9 bytes) that can't be valid HTTP/2 frames
         * and are likely partial control data or TCP-level artifacts */
        if (len < 9 && http2_has_session(event->pid, event->ssl_ctx)) {
            return;  /* Suppress tiny writes when HTTP/2 session is active */
        }
    }

    char ts[32];
    display_get_timestamp(ts, sizeof(ts));
    const char *dir = (event->event_type == EVENT_SSL_WRITE) ? "WRITE" : "READ";

    /* Get real process name */
    char raw_proc_name[TASK_COMM_LEN] = {0};
    get_process_name(event->pid, raw_proc_name, sizeof(raw_proc_name));
    const char *display_name = raw_proc_name[0] ? raw_proc_name : event->comm;

    printf("%s%s%s [%s%s%s] %s (PID %u) %d bytes ",
           display_color(C_DIM), ts, display_color(C_RESET),
           display_color(C_CYAN), dir, display_color(C_RESET),
           display_name, event->pid, event->buf_filled);

    if (sig) {
        printf("%s[%s]%s", display_color(C_YELLOW), sig, display_color(C_RESET));
    }
    printf("\n");
}

#ifdef HAVE_THREADING
/* ============================================================================
 * Multi-Threaded Event Processing
 *
 * This section contains the threaded version of event processing.
 * Key differences from single-threaded mode:
 * - Uses per-worker state (ALPN cache, pending bodies, buffers)
 * - HTTP/2 sessions are per-worker (no global state)
 * - Output is serialized through the output thread
 * ============================================================================ */

/*
 * Process an event in worker thread context
 * Uses per-worker state for thread-safe operation
 */
void process_worker_event(worker_ctx_t *worker, worker_event_t *event) {
    if (!worker || !event) {
        return;
    }

    worker_state_t *state = &worker->state;

    /* Handle process exit events - cleanup resources */
    if (event->event_type == EVENT_PROCESS_EXIT) {
        /* Cleanup HTTP/2 sessions for this PID */
        for (int i = 0; i < state->h2_connection_count; i++) {
            if (state->h2_connections[i].active &&
                state->h2_connections[i].pid == event->pid) {
                worker_cleanup_h2_connection(state, &state->h2_connections[i]);
            }
        }
        worker_cleanup_h2_streams_for_connection(state, event->pid, 0);
        worker_cleanup_pending_bodies_pid(state, event->pid);
        return;
    }

    /* Handle handshake events */
    if (event->event_type == EVENT_HANDSHAKE) {
        if (g_config.show_handshake) {
            char proc_name[TASK_COMM_LEN] = {0};
            get_process_name(event->pid, proc_name, sizeof(proc_name));
            const char *name = proc_name[0] ? proc_name : event->comm;

            output_write(worker, "%s[TLS Handshake]%s %s%s%s (PID %u) %.3fms\n",
                        display_color(C_YELLOW), display_color(C_RESET),
                        display_color(C_CYAN), name, display_color(C_RESET),
                        event->pid, event->delta_ns / 1000000.0);
        }
        return;
    }

    /* Handle ALPN protocol negotiation */
    if (event->event_type == EVENT_ALPN) {
        if (event->data_len > 0 && event->data_len <= 255) {
            char alpn_proto[256] = {0};
            memcpy(alpn_proto, event->data, event->data_len);
            worker_set_alpn(state, event->pid, event->ssl_ctx, alpn_proto);
        }
        return;
    }

    if (event->data_len == 0) return;

    const uint8_t *data = event->data;
    size_t len = event->data_len;

    /* Try HTTP/1.1 parsing first */
    if (http1_is_request(data, len) || http1_is_response(data, len)) {
        /* Clear any pending body from this connection */
        pending_body_entry_t *old_pending = worker_find_pending_body(state,
                                                event->pid, event->ssl_ctx);
        if (old_pending) {
            worker_clear_pending_body(state, old_pending);
        }

        http_message_t msg = {0};
        size_t body_len = 0;

        /* Use per-worker body buffer */
        uint8_t *body_buf = g_config.show_body ? state->body_buf : NULL;
        size_t body_buf_size = g_config.show_body ? state->body_buf_size : 0;

        int result = http1_parse(data, len, &msg, body_buf, body_buf_size, &body_len);

        if (result < 0) {
            goto show_raw;
        }

        /* Set metadata */
        msg.pid = event->pid;
        msg.timestamp_ns = event->timestamp_ns;
        msg.delta_ns = event->delta_ns;

        char proc_name[TASK_COMM_LEN] = {0};
        get_process_name(event->pid, proc_name, sizeof(proc_name));
        safe_strcpy(msg.comm, sizeof(msg.comm),
                   proc_name[0] ? proc_name : event->comm);

        /* Get ALPN from per-worker cache */
        const char *alpn = worker_get_alpn(state, event->pid, event->ssl_ctx);
        if (alpn) {
            safe_strcpy(msg.alpn_proto, sizeof(msg.alpn_proto), alpn);
        }

        /* Format output through output thread */
        char ts[32];
        display_get_timestamp(ts, sizeof(ts));
        const char *dir_str = (msg.direction == DIR_REQUEST) ? "REQ" : "RSP";
        const char *dir_color = (msg.direction == DIR_REQUEST) ?
                                display_color(C_GREEN) : display_color(C_CYAN);

        if (msg.direction == DIR_REQUEST) {
            output_write(worker, "%s%s%s %s[%s]%s %s%s%s %s %s%s%s (PID %u)\n",
                        display_color(C_DIM), ts, display_color(C_RESET),
                        dir_color, dir_str, display_color(C_RESET),
                        display_color(C_GREEN), msg.method, display_color(C_RESET),
                        msg.path,
                        display_color(C_DIM), msg.comm, display_color(C_RESET),
                        msg.pid);
        } else {
            const char *status_color = (msg.status_code >= 200 && msg.status_code < 300) ?
                                       display_color(C_GREEN) :
                                       (msg.status_code >= 400) ?
                                       display_color(C_RED) : display_color(C_YELLOW);
            output_write(worker, "%s%s%s %s[%s]%s %s%d %s%s %.3fms\n",
                        display_color(C_DIM), ts, display_color(C_RESET),
                        dir_color, dir_str, display_color(C_RESET),
                        status_color, msg.status_code, msg.status_text,
                        display_color(C_RESET),
                        msg.delta_ns / 1000000.0);
        }

        /* Show headers unless compact mode */
        if (!g_config.compact_mode && msg.header_count > 0) {
            for (int i = 0; i < msg.header_count; i++) {
                output_write(worker, "  %s%s:%s %s\n",
                            display_color(C_DIM),
                            msg.headers[i].name, display_color(C_RESET),
                            msg.headers[i].value);
            }
        }

        /* Show body if present */
        if (g_config.show_body && body_len > 0) {
            const uint8_t *body_data = body_buf;
            size_t display_len = body_len;

            /* Use per-worker decompression buffer */
            if (msg.content_encoding[0]) {
                int decomp_len = decompress_body(body_data, body_len,
                                                msg.content_encoding,
                                                state->decomp_buf,
                                                state->decomp_buf_size);
                if (decomp_len > 0) {
                    body_data = state->decomp_buf;
                    display_len = decomp_len;
                }
            }

            output_write(worker, "%s─── Body (%zu bytes) ───%s\n",
                        display_color(C_DIM), display_len, display_color(C_RESET));

            /* Output body (truncate if too long for output buffer) */
            output_msg_t *body_msg = output_alloc(worker);
            if (body_msg) {
                size_t copy_len = (display_len < OUTPUT_MSG_MAX_SIZE - 1) ?
                                  display_len : OUTPUT_MSG_MAX_SIZE - 1;
                memcpy(body_msg->data, body_data, copy_len);
                body_msg->len = copy_len;
                output_enqueue(worker, body_msg);
            }
            output_write(worker, "\n%s────────────%s\n",
                        display_color(C_DIM), display_color(C_RESET));
        } else if (g_config.show_body && msg.direction == DIR_RESPONSE &&
                   (msg.content_length > 0 || msg.is_chunked)) {
            /* Body will arrive in next event - track with per-worker state */
            worker_create_pending_body(state, event->pid, event->ssl_ctx,
                                       msg.content_length > 0 ? msg.content_length : 0,
                                       msg.content_type, msg.content_encoding);
        }

        output_write(worker, "\n");
        return;
    }

    /* Check for existing HTTP/2 session (per-worker) */
    h2_connection_local_t *h2_conn = worker_get_h2_connection(state,
                                        event->pid, event->ssl_ctx, false);
    if (h2_conn && h2_conn->active) {
        /* Process HTTP/2 frame with per-worker session */
        /* TODO: Integrate with http2_process_frame using worker state */
        /* For now, fall back to global HTTP/2 processing */
        ssl_data_event_t bpf_event = {
            .timestamp_ns = event->timestamp_ns,
            .delta_ns = event->delta_ns,
            .ssl_ctx = event->ssl_ctx,
            .pid = event->pid,
            .tid = event->tid,
            .uid = event->uid,
            .event_type = event->event_type,
            .buf_filled = event->data_len,
        };
        memcpy(bpf_event.comm, event->comm, TASK_COMM_LEN);
        memcpy(bpf_event.data, event->data, event->data_len);

        http2_process_frame(data, len, &bpf_event);
        return;
    }

    /* Check for HTTP/2 connection preface */
    if (http2_is_preface(data, len)) {
        output_write(worker, "%s[HTTP/2 connection]%s PID %u (%s)\n",
                    display_color(C_YELLOW), display_color(C_RESET),
                    event->pid, event->comm);

        /* Create per-worker H2 connection */
        h2_conn = worker_get_h2_connection(state, event->pid, event->ssl_ctx, true);
        if (h2_conn) {
            h2_conn->client_preface_seen = true;
            safe_strcpy(h2_conn->comm, sizeof(h2_conn->comm), event->comm);
        }

        /* Process frames after preface */
        if (len > 24) {
            ssl_data_event_t bpf_event = {
                .timestamp_ns = event->timestamp_ns,
                .delta_ns = event->delta_ns,
                .ssl_ctx = event->ssl_ctx,
                .pid = event->pid,
                .tid = event->tid,
                .uid = event->uid,
                .event_type = event->event_type,
                .buf_filled = len - 24,
            };
            memcpy(bpf_event.comm, event->comm, TASK_COMM_LEN);
            memcpy(bpf_event.data, data + 24, len - 24);
            http2_process_frame(data + 24, len - 24, &bpf_event);
        }
        return;
    }

    /* Check for HTTP/2 frames (mid-connection attach) */
    if (len >= 9) {
        uint32_t frame_len = ((uint32_t)data[0] << 16) |
                             ((uint32_t)data[1] << 8) |
                             (uint32_t)data[2];
        uint8_t frame_type = data[3];
        uint32_t stream_id = ((uint32_t)(data[5] & 0x7f) << 24) |
                             ((uint32_t)data[6] << 16) |
                             ((uint32_t)data[7] << 8) |
                             (uint32_t)data[8];

        if (frame_type <= 0x09 && frame_len <= 16384) {
            bool is_valid_h2 = false;
            if (frame_type == H2_FRAME_SETTINGS && stream_id == 0) is_valid_h2 = true;
            else if (frame_type == H2_FRAME_HEADERS && (stream_id & 1) != 0) is_valid_h2 = true;
            else if (frame_type == H2_FRAME_WINDOW_UPDATE && stream_id == 0) is_valid_h2 = true;
            else if (frame_type == H2_FRAME_DATA && (stream_id & 1) != 0 && frame_len > 0) is_valid_h2 = true;

            if (is_valid_h2 && (9 + frame_len) <= len) {
                output_write(worker, "%s[HTTP/2 connection]%s PID %u (%s)\n",
                            display_color(C_YELLOW), display_color(C_RESET),
                            event->pid, event->comm);

                h2_conn = worker_get_h2_connection(state, event->pid, event->ssl_ctx, true);
                if (h2_conn) {
                    safe_strcpy(h2_conn->comm, sizeof(h2_conn->comm), event->comm);
                }

                ssl_data_event_t bpf_event = {
                    .timestamp_ns = event->timestamp_ns,
                    .delta_ns = event->delta_ns,
                    .ssl_ctx = event->ssl_ctx,
                    .pid = event->pid,
                    .tid = event->tid,
                    .uid = event->uid,
                    .event_type = event->event_type,
                    .buf_filled = len,
                };
                memcpy(bpf_event.comm, event->comm, TASK_COMM_LEN);
                memcpy(bpf_event.data, data, len);
                http2_process_frame(data, len, &bpf_event);
                return;
            }
        }
    }

    /* Check for pending body data (per-worker) */
    if (g_config.show_body) {
        pending_body_entry_t *pending = worker_find_pending_body(state,
                                            event->pid, event->ssl_ctx);
        if (pending && pending->active) {
            pending->received_len += len;

            if (pending->needs_decompression && pending->accum_buf) {
                if (pending->accum_len + len <= pending->accum_capacity) {
                    memcpy(pending->accum_buf + pending->accum_len, data, len);
                    pending->accum_len += len;
                }
                if (pending->expected_len > 0 &&
                    pending->received_len >= pending->expected_len) {
                    /* Decompress and output */
                    int decomp_len = decompress_body(pending->accum_buf,
                                                    pending->accum_len,
                                                    pending->content_encoding,
                                                    state->decomp_buf,
                                                    state->decomp_buf_size);
                    if (decomp_len > 0) {
                        if (!pending->header_printed) {
                            output_write(worker, "%s─── Body ───%s\n",
                                        display_color(C_DIM), display_color(C_RESET));
                        }
                        output_msg_t *body_msg = output_alloc(worker);
                        if (body_msg) {
                            size_t copy_len = (decomp_len < OUTPUT_MSG_MAX_SIZE - 1) ?
                                              decomp_len : OUTPUT_MSG_MAX_SIZE - 1;
                            memcpy(body_msg->data, state->decomp_buf, copy_len);
                            body_msg->len = copy_len;
                            output_enqueue(worker, body_msg);
                        }
                        output_write(worker, "\n%s────────────%s\n\n",
                                    display_color(C_DIM), display_color(C_RESET));
                    }
                    worker_clear_pending_body(state, pending);
                }
                return;
            }

            /* Non-compressed: stream directly */
            if (!pending->header_printed) {
                output_write(worker, "%s─── Body ───%s\n",
                            display_color(C_DIM), display_color(C_RESET));
                pending->header_printed = true;
            }

            bool is_text = (strstr(pending->content_type, "text/") != NULL ||
                           strstr(pending->content_type, "json") != NULL ||
                           strstr(pending->content_type, "xml") != NULL);

            if (is_text) {
                output_msg_t *body_msg = output_alloc(worker);
                if (body_msg) {
                    size_t copy_len = (len < OUTPUT_MSG_MAX_SIZE - 1) ?
                                      len : OUTPUT_MSG_MAX_SIZE - 1;
                    memcpy(body_msg->data, data, copy_len);
                    body_msg->len = copy_len;
                    output_enqueue(worker, body_msg);
                }
            } else {
                output_write(worker, "[binary chunk: %zu bytes]\n", len);
            }

            if (pending->expected_len > 0 &&
                pending->received_len >= pending->expected_len) {
                output_write(worker, "%s────────────%s\n\n",
                            display_color(C_DIM), display_color(C_RESET));
                worker_clear_pending_body(state, pending);
            }
            return;
        }
    }

show_raw:
    /* Unknown/binary data */
    ;

    const char *sig = signature_detect(data, len);
    if (signature_is_local_file(sig)) {
        return;
    }

    /* Suppress HTTP/2 control frames and noise in non-debug mode */
    if (!g_config.debug_mode) {
        /* HTTP/2 control frames (types 0x02-0x08) in small packets */
        if (len >= 9 && len <= 32) {
            uint8_t frame_type = data[3];
            if (frame_type >= 0x02 && frame_type <= 0x08) {
                return;
            }
        }

        /* Small writes (<= 13 bytes) are likely HTTP/2 control frames:
         * - 9 bytes: frame header only (e.g., SETTINGS ACK)
         * - 13 bytes: frame header + 4 byte payload (e.g., WINDOW_UPDATE)
         * - 8 bytes: partial frame or GOAWAY body
         * - 4 bytes: partial WINDOW_UPDATE payload
         * Suppress these when event looks like it could be HTTP/2 traffic */
        if (len <= 13 && event->event_type == EVENT_SSL_WRITE) {
            /* Check if this process has any H2 activity */
            h2_conn = worker_get_h2_connection(state, event->pid, event->ssl_ctx, false);
            if (h2_conn) {
                return;  /* Known H2 connection - suppress noise */
            }
            /* Also suppress small writes that look like H2 frames */
            if (len == 4 || len == 8 || len == 9 || len == 13) {
                return;  /* Common H2 control frame sizes */
            }
        }

        /* Small reads on active H2 connections are partial frames */
        if (len <= 9 && event->event_type == EVENT_SSL_READ) {
            h2_conn = worker_get_h2_connection(state, event->pid, event->ssl_ctx, false);
            if (h2_conn && h2_conn->active) {
                return;
            }
        }

        /* Block-sized reads without signatures are likely file I/O (when IPC filter on) */
        if (g_config.filter_ipc && !sig) {
            /* Common block sizes: 4096, 8192, 16384, 32768 */
            if (len == 4096 || len == 8192 || len == 16384 || len == 32768 ||
                len == 32 || len == 64 || len == 128 || len == 256) {
                return;
            }
        }
    }

    char ts[32];
    display_get_timestamp(ts, sizeof(ts));
    const char *dir = (event->event_type == EVENT_SSL_WRITE) ? "WRITE" : "READ";

    char raw_proc_name[TASK_COMM_LEN] = {0};
    get_process_name(event->pid, raw_proc_name, sizeof(raw_proc_name));
    const char *display_name = raw_proc_name[0] ? raw_proc_name : event->comm;

    if (sig) {
        output_write(worker, "%s%s%s [%s%s%s] %s (PID %u) %u bytes %s[%s]%s\n",
                    display_color(C_DIM), ts, display_color(C_RESET),
                    display_color(C_CYAN), dir, display_color(C_RESET),
                    display_name, event->pid, event->data_len,
                    display_color(C_YELLOW), sig, display_color(C_RESET));
    } else {
        output_write(worker, "%s%s%s [%s%s%s] %s (PID %u) %u bytes\n",
                    display_color(C_DIM), ts, display_color(C_RESET),
                    display_color(C_CYAN), dir, display_color(C_RESET),
                    display_name, event->pid, event->data_len);
    }
}
#endif /* HAVE_THREADING */

/* Print usage */
static void print_usage(const char *prog) {
    printf("spliff v%s - SSL/TLS Traffic Sniffer\n\n", SPLIFF_VERSION);
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -p, --pid PID   Filter by PID(s), comma-separated\n");
    printf("  --ppid PID      Filter by parent PID (captures all children)\n");
    printf("  --comm NAME     Filter by process name or executable path\n");
    printf("  --openssl       Only attach to OpenSSL\n");
    printf("  --gnutls        Only attach to GnuTLS\n");
    printf("  --nss           Only attach to NSS\n");
    printf("  -b              Show response/request bodies\n");
    printf("  -x              Show body as hexdump with file signature detection\n");
    printf("  -c              Compact mode (hide headers)\n");
    printf("  -l              Show latency (SSL operation time)\n");
    printf("  -H              Show TLS handshake events\n");
    printf("  -d              Debug mode (verbose output)\n");
    printf("  --show-libs     Show all discovered SSL libraries\n");
    printf("  -C              Disable colored output\n");
#ifdef HAVE_THREADING
    printf("\nThreading Options:\n");
    printf("  -t, --threads N Worker threads (0=auto, default: auto)\n");
    printf("                  Auto: max(1, CPUs-3), capped at 16\n");
    printf("  --no-threading  Disable multi-threading (single-threaded mode)\n");
#endif
    printf("  -v, --version   Show version\n");
    printf("  -h, --help      Show this help\n");
    printf("\nExamples:\n");
    printf("  %s --comm curl         # Capture traffic from curl\n", prog);
    printf("  %s -p 1234,5678        # Capture PIDs 1234 and 5678\n", prog);
    printf("  %s --nss --ppid 1234   # NSS traffic from Firefox children\n", prog);
}

int main(int argc, char **argv) {
    int err = 0;
    char openssl_path[512] = {0};
    char gnutls_path[512] = {0};
    char nss_path[512] = {0};
    char nss_ssl_path[512] = {0};  /* libssl3.so for NSS handshake */
    char wolfssl_path[512] = {0};  /* WolfSSL support */
    bool use_openssl = true;
    bool use_gnutls = true;
    bool use_nss = true;
    bool use_wolfssl = true;       /* WolfSSL auto-detection */
    bool debug_mode = false;
    bool show_libs = false;        /* Show all discovered libraries */

#ifdef HAVE_THREADING
    int num_threads = 0;           /* 0 = auto-detect based on CPU count */
    bool disable_threading = false;
#endif

    /* Filter options */
    char target_comm[64] = {0};
    int target_pids[64] = {0};
    int num_target_pids = 0;
    int target_ppid = 0;

    /* Default config */
    g_config.use_colors = true;
    g_config.use_openssl = true;
    g_config.use_gnutls = true;
    g_config.use_nss = true;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("spliff version %s\n", SPLIFF_VERSION);
            return 0;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--pid") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires a PID argument\n", argv[i]);
                return 1;
            }
            /* Parse comma-separated PIDs using strtok_r for thread safety */
            char *pidstr = argv[++i];
            char *saveptr = NULL;
            char *token = strtok_r(pidstr, ",", &saveptr);
            while (token && num_target_pids < 64) {
                char *endptr;
                long pid = strtol(token, &endptr, 10);
                if (*endptr != '\0' || pid <= 0 || pid > INT_MAX) {
                    fprintf(stderr, "Error: Invalid PID '%s'\n", token);
                    return 1;
                }
                target_pids[num_target_pids++] = (int)pid;
                token = strtok_r(NULL, ",", &saveptr);
            }
        } else if (strcmp(argv[i], "--ppid") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --ppid requires a PID argument\n");
                return 1;
            }
            char *endptr;
            long ppid = strtol(argv[++i], &endptr, 10);
            if (*endptr != '\0' || ppid <= 0 || ppid > INT_MAX) {
                fprintf(stderr, "Error: Invalid parent PID '%s'\n", argv[i]);
                return 1;
            }
            target_ppid = (int)ppid;
        } else if (strcmp(argv[i], "--comm") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --comm requires a process name\n");
                return 1;
            }
            safe_strcpy(target_comm, sizeof(target_comm), argv[++i]);
        } else if (strcmp(argv[i], "-C") == 0) {
            g_config.use_colors = false;
        } else if (strcmp(argv[i], "-d") == 0) {
            debug_mode = true;
            g_config.debug_mode = true;
        } else if (strcmp(argv[i], "-b") == 0) {
            g_config.show_body = true;
        } else if (strcmp(argv[i], "-x") == 0) {
            g_config.show_body = true;
            g_config.hexdump_body = true;
        } else if (strcmp(argv[i], "-c") == 0) {
            g_config.compact_mode = true;
        } else if (strcmp(argv[i], "-l") == 0) {
            g_config.show_latency = true;
        } else if (strcmp(argv[i], "-H") == 0) {
            g_config.show_handshake = true;
        } else if (strcmp(argv[i], "--openssl") == 0) {
            use_gnutls = use_nss = false;
        } else if (strcmp(argv[i], "--gnutls") == 0) {
            use_openssl = use_nss = false;
        } else if (strcmp(argv[i], "--nss") == 0) {
            use_openssl = use_gnutls = false;
        } else if (strcmp(argv[i], "--show-libs") == 0) {
            show_libs = true;
#ifdef HAVE_THREADING
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--threads") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires a number argument\n", argv[i]);
                return 1;
            }
            char *endptr;
            long threads = strtol(argv[++i], &endptr, 10);
            if (*endptr != '\0' || threads < 0 || threads > MAX_WORKERS) {
                fprintf(stderr, "Error: Invalid thread count '%s' (0=auto, max=%d)\n",
                        argv[i], MAX_WORKERS);
                return 1;
            }
            num_threads = (int)threads;
        } else if (strcmp(argv[i], "--no-threading") == 0) {
            disable_threading = true;
#endif
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Check for root privileges (required for BPF) */
    if (geteuid() != 0) {
        fprintf(stderr, "%sError:%s This program requires root privileges to attach BPF probes.\n",
                "\033[31m", "\033[0m");
        fprintf(stderr, "Please run with: sudo %s\n", argv[0]);
        return 1;
    }

    /* Register cleanup handler for safe exit */
    if (atexit(cleanup_all_resources) != 0) {
        fprintf(stderr, "Warning: Failed to register cleanup handler\n");
    }

    /* Initialize modules */
    display_init(g_config.use_colors);
    if (signatures_init() != 0) {
        fprintf(stderr, "Warning: Failed to initialize signature detection (memory allocation failure)\n");
        /* Continue anyway - detection will work but signatures won't be in priority order */
    }
    decompressor_init();
    http1_init();
    http2_init();
    g_modules_initialized = true;

    printf("\n%s╔════════════════════════════════════════╗%s\n",
           display_color(C_CYAN), display_color(C_RESET));
    printf("%s║      spliff v%-6s                  ║%s\n",
           display_color(C_CYAN), SPLIFF_VERSION, display_color(C_RESET));
    printf("%s╚════════════════════════════════════════╝%s\n\n",
           display_color(C_CYAN), display_color(C_RESET));

    /* Find SSL libraries - use dynamic discovery if PIDs specified */
    int *discovery_pids = (num_target_pids > 0) ? target_pids : NULL;
    int discovery_pid_count = num_target_pids;

    /* Run full discovery to get statistics */
    lib_discovery_result_t discovery_result;
    if (bpf_loader_discover_libraries(discovery_pids, discovery_pid_count, &discovery_result) == 0) {
        if (show_libs || debug_mode) {
            bpf_loader_print_discovery(&discovery_result);
        }

        /* Use discovered paths (primary path for each type) */
        if (use_openssl && discovery_result.libs[LIB_OPENSSL].found) {
            safe_strcpy(openssl_path, sizeof(openssl_path),
                       discovery_result.libs[LIB_OPENSSL].path);
            printf("  %s✓%s OpenSSL: %s\n",
                   display_color(C_GREEN), display_color(C_RESET), openssl_path);
        }

        if (use_gnutls && discovery_result.libs[LIB_GNUTLS].found) {
            safe_strcpy(gnutls_path, sizeof(gnutls_path),
                       discovery_result.libs[LIB_GNUTLS].path);
            printf("  %s✓%s GnuTLS:  %s\n",
                   display_color(C_GREEN), display_color(C_RESET), gnutls_path);
        }

        if (use_nss && discovery_result.libs[LIB_NSS].found) {
            safe_strcpy(nss_path, sizeof(nss_path),
                       discovery_result.libs[LIB_NSS].path);
            printf("  %s✓%s NSS:     %s\n",
                   display_color(C_GREEN), display_color(C_RESET), nss_path);
        }

        if (use_nss && discovery_result.libs[LIB_NSS_SSL].found) {
            safe_strcpy(nss_ssl_path, sizeof(nss_ssl_path),
                       discovery_result.libs[LIB_NSS_SSL].path);
            printf("  %s✓%s NSS SSL: %s\n",
                   display_color(C_GREEN), display_color(C_RESET), nss_ssl_path);
        }

        if (use_wolfssl && discovery_result.libs[LIB_WOLFSSL].found) {
            safe_strcpy(wolfssl_path, sizeof(wolfssl_path),
                       discovery_result.libs[LIB_WOLFSSL].path);
            printf("  %s✓%s WolfSSL: %s\n",
                   display_color(C_GREEN), display_color(C_RESET), wolfssl_path);
        }
    } else {
        /* Fallback to individual lookups if full discovery fails */
        if (use_openssl && bpf_loader_find_library_dynamic("libssl.so", openssl_path,
                                                            sizeof(openssl_path),
                                                            discovery_pids, discovery_pid_count) == 0) {
            printf("  %s✓%s OpenSSL: %s\n",
                   display_color(C_GREEN), display_color(C_RESET), openssl_path);
        }

        if (use_gnutls && bpf_loader_find_library_dynamic("libgnutls.so", gnutls_path,
                                                           sizeof(gnutls_path),
                                                           discovery_pids, discovery_pid_count) == 0) {
            printf("  %s✓%s GnuTLS:  %s\n",
                   display_color(C_GREEN), display_color(C_RESET), gnutls_path);
        }

        if (use_nss && bpf_loader_find_library_dynamic("libnspr4.so", nss_path,
                                                        sizeof(nss_path),
                                                        discovery_pids, discovery_pid_count) == 0) {
            printf("  %s✓%s NSS:     %s\n",
                   display_color(C_GREEN), display_color(C_RESET), nss_path);
            /* Also find libssl3.so for NSS handshake probes */
            if (bpf_loader_find_library_dynamic("libssl3.so", nss_ssl_path,
                                                 sizeof(nss_ssl_path),
                                                 discovery_pids, discovery_pid_count) == 0) {
                printf("  %s✓%s NSS SSL: %s\n",
                       display_color(C_GREEN), display_color(C_RESET), nss_ssl_path);
            }
        }
    }

    printf("\n");

    /* Initialize BPF */
    if (bpf_loader_init(&g_loader) < 0) {
        fprintf(stderr, "Error: Failed to initialize BPF loader\n");
        return 1;
    }
    g_bpf_initialized = true;

    /* Load BPF program - try multiple paths */
    static const char *bpf_paths[] = {
        "build/spliff.bpf.o",           /* CMake build directory */
        "spliff.bpf.o",                 /* Current directory */
        "src/bpf/spliff.bpf.o",         /* Source directory (legacy) */
        "/usr/lib/spliff/spliff.bpf.o", /* Installed path */
        NULL
    };
    int bpf_loaded = 0;
    for (const char **path = bpf_paths; *path; path++) {
        if (bpf_loader_load(&g_loader, *path) == 0) {
            if (debug_mode) {
                printf("  [DEBUG] Loaded BPF program from %s\n", *path);
            }
            bpf_loaded = 1;
            break;
        }
    }
    if (!bpf_loaded) {
        fprintf(stderr, "%sError:%s Cannot load BPF program\n",
                display_color(C_RED), display_color(C_RESET));
        return 1;
    }

    setup_signals();

    /* Attach uprobes */
    if (openssl_path[0]) {
        bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_write",
                                "probe_ssl_rw_enter", false, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_write",
                                "probe_ssl_write_exit", true, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_read",
                                "probe_ssl_rw_enter", false, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_read",
                                "probe_ssl_read_exit", true, debug_mode);

        /* SSL_set_fd - track SSL* → OS fd mapping for socket family filtering
         * This enables kernel-level IPC filtering by checking AF_INET vs AF_UNIX */
        bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_set_fd",
                                "probe_ssl_set_fd_enter", false, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_set_fd",
                                "probe_ssl_set_fd_exit", true, debug_mode);

        /* SSL_free - cleanup session tracking when SSL connection is freed */
        bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_free",
                                "probe_ssl_free", false, debug_mode);
    }

    if (gnutls_path[0]) {
        bpf_loader_attach_uprobe(&g_loader, gnutls_path, "gnutls_record_send",
                                "probe_gnutls_send_enter", false, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, gnutls_path, "gnutls_record_send",
                                "probe_gnutls_send_exit", true, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, gnutls_path, "gnutls_record_recv",
                                "probe_gnutls_recv_enter", false, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, gnutls_path, "gnutls_record_recv",
                                "probe_gnutls_recv_exit", true, debug_mode);

        /* gnutls_deinit - cleanup session tracking when GnuTLS session is freed */
        bpf_loader_attach_uprobe(&g_loader, gnutls_path, "gnutls_deinit",
                                "probe_gnutls_deinit", false, debug_mode);
    }

    if (nss_path[0]) {
        bpf_loader_attach_uprobe(&g_loader, nss_path, "PR_Write",
                                "probe_nss_write_enter", false, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, nss_path, "PR_Write",
                                "probe_nss_write_exit", true, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, nss_path, "PR_Read",
                                "probe_nss_read_enter", false, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, nss_path, "PR_Read",
                                "probe_nss_read_exit", true, debug_mode);
        /* PR_Send/PR_Recv - additional NSPR socket I/O functions */
        bpf_loader_attach_uprobe(&g_loader, nss_path, "PR_Send",
                                "probe_nss_write_enter", false, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, nss_path, "PR_Send",
                                "probe_nss_write_exit", true, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, nss_path, "PR_Recv",
                                "probe_nss_read_enter", false, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, nss_path, "PR_Recv",
                                "probe_nss_read_exit", true, debug_mode);

        /* PR_Close - cleanup session tracking when PRFileDesc is closed */
        bpf_loader_attach_uprobe(&g_loader, nss_path, "PR_Close",
                                "probe_pr_close", false, debug_mode);
    }

    /* SSL_ImportFD - track verified SSL connections for IPC filtering
     * This is called when a socket is promoted to SSL in Firefox.
     * All web traffic must pass through here, but IPC rarely does. */
    if (nss_ssl_path[0]) {
        bpf_loader_attach_uprobe(&g_loader, nss_ssl_path, "SSL_ImportFD",
                                "probe_ssl_import_fd_exit", true, debug_mode);
    }

    /* Attach handshake probes if -H is set */
    if (g_config.show_handshake) {
        if (openssl_path[0]) {
            /* SSL_connect - client-side handshake (most common for curl, wget, etc.) */
            bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_connect",
                                    "probe_ssl_handshake_enter", false, debug_mode);
            bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_connect",
                                    "probe_ssl_handshake_exit", true, debug_mode);
            /* SSL_do_handshake - generic handshake */
            bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_do_handshake",
                                    "probe_ssl_handshake_enter", false, debug_mode);
            bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_do_handshake",
                                    "probe_ssl_handshake_exit", true, debug_mode);
        }
        if (gnutls_path[0]) {
            bpf_loader_attach_uprobe(&g_loader, gnutls_path, "gnutls_handshake",
                                    "probe_ssl_handshake_enter", false, debug_mode);
            bpf_loader_attach_uprobe(&g_loader, gnutls_path, "gnutls_handshake",
                                    "probe_ssl_handshake_exit", true, debug_mode);
        }
        if (nss_ssl_path[0]) {
            /* SSL_ForceHandshake - NSS explicit handshake */
            bpf_loader_attach_uprobe(&g_loader, nss_ssl_path, "SSL_ForceHandshake",
                                    "probe_ssl_handshake_enter", false, debug_mode);
            bpf_loader_attach_uprobe(&g_loader, nss_ssl_path, "SSL_ForceHandshake",
                                    "probe_ssl_handshake_exit", true, debug_mode);
        }
    }

    /* Attach WolfSSL probes (same signature as OpenSSL, reuse probes) */
    if (wolfssl_path[0]) {
        bpf_loader_attach_uprobe(&g_loader, wolfssl_path, "wolfSSL_write",
                                "probe_ssl_rw_enter", false, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, wolfssl_path, "wolfSSL_write",
                                "probe_ssl_write_exit", true, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, wolfssl_path, "wolfSSL_read",
                                "probe_ssl_rw_enter", false, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, wolfssl_path, "wolfSSL_read",
                                "probe_ssl_read_exit", true, debug_mode);
    }

    /* Attach ALPN protocol detection probes */
    if (openssl_path[0]) {
        bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_get0_alpn_selected",
                                "probe_openssl_alpn_enter", false, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_get0_alpn_selected",
                                "probe_openssl_alpn_exit", true, debug_mode);
    }
    if (gnutls_path[0]) {
        bpf_loader_attach_uprobe(&g_loader, gnutls_path, "gnutls_alpn_get_selected_protocol",
                                "probe_gnutls_alpn_enter", false, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, gnutls_path, "gnutls_alpn_get_selected_protocol",
                                "probe_gnutls_alpn_exit", true, debug_mode);
    }
    if (nss_ssl_path[0]) {
        /* SSL_GetNextProto - NSS ALPN negotiation result */
        bpf_loader_attach_uprobe(&g_loader, nss_ssl_path, "SSL_GetNextProto",
                                "probe_nss_alpn_enter", false, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, nss_ssl_path, "SSL_GetNextProto",
                                "probe_nss_alpn_exit", true, debug_mode);
    }
    if (wolfssl_path[0]) {
        /* wolfSSL_ALPN_GetProtocol - WolfSSL ALPN negotiation result */
        bpf_loader_attach_uprobe(&g_loader, wolfssl_path, "wolfSSL_ALPN_GetProtocol",
                                "probe_wolfssl_alpn_enter", false, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, wolfssl_path, "wolfSSL_ALPN_GetProtocol",
                                "probe_wolfssl_alpn_exit", true, debug_mode);
    }

    /* Attach process exit tracepoint for session cleanup */
    if (bpf_loader_attach_tracepoint(&g_loader, "sched", "sched_process_exit",
                                      "handle_process_exit", debug_mode) == 0) {
        if (debug_mode) {
            printf("  [DEBUG] Process exit tracepoint attached\n");
        }
    }

    if (bpf_loader_get_link_count(&g_loader) == 0) {
        fprintf(stderr, "%sError:%s No probes attached\n",
                display_color(C_RED), display_color(C_RESET));
        return 1;  /* atexit handler will cleanup */
    }

    printf("  %s%d probes attached%s\n\n",
           display_color(C_GREEN),
           bpf_loader_get_link_count(&g_loader),
           display_color(C_RESET));

    /* Setup probe handler */
    if (probe_handler_init(&g_handler) < 0) {
        fprintf(stderr, "%sError:%s Failed to initialize probe handler\n",
                display_color(C_RED), display_color(C_RESET));
        return 1;  /* atexit handler will cleanup */
    }

    /* Set filters */
    if (target_comm[0]) {
        probe_handler_set_filter_comm(&g_handler, target_comm);
    }
    if (num_target_pids > 0) {
        probe_handler_set_filter_pids(&g_handler, target_pids, num_target_pids);
    }
    if (target_ppid > 0) {
        probe_handler_set_filter_ppid(&g_handler, target_ppid);
    }
    /* Note: IPC filtering is always on (BPF kernel-level + userspace heuristics) */

#ifdef HAVE_THREADING
    /* Initialize threading if enabled (default: auto-detect unless --no-threading) */
    if (!disable_threading) {
        if (threading_init(&g_threading, num_threads, false) == 0) {
            g_threading_initialized = true;
            g_threading_enabled = true;
            printf("  %sMulti-threading:%s %d workers%s\n",
                   display_color(C_GREEN), display_color(C_RESET),
                   g_threading.num_workers,
                   num_threads == 0 ? " (auto)" : "");
        } else {
            fprintf(stderr, "Warning: Failed to initialize threading, falling back to single-threaded mode\n");
        }
    }

    if (!g_threading_enabled)
#endif
    {
        /* Single-threaded mode: use direct callback */
        probe_handler_set_callback(&g_handler, process_event, NULL);
    }

    if (probe_handler_setup_ringbuf(&g_handler, bpf_loader_get_object(&g_loader)) < 0) {
        fprintf(stderr, "%sError:%s Cannot setup ring buffer\n",
                display_color(C_RED), display_color(C_RESET));
        return 1;  /* atexit handler will cleanup */
    }
    g_probe_initialized = true;

    /* Show active filters (IPC filtering always on via BPF, not shown) */
    if (target_comm[0] || num_target_pids > 0 || target_ppid > 0) {
        printf("  %sFilters:%s", display_color(C_YELLOW), display_color(C_RESET));
        if (target_comm[0]) {
            printf(" comm=%s", target_comm);
        }
        if (num_target_pids > 0) {
            printf(" pid=");
            for (int i = 0; i < num_target_pids; i++) {
                printf("%s%d", i > 0 ? "," : "", target_pids[i]);
            }
        }
        if (target_ppid > 0) {
            printf(" ppid=%d (+children)", target_ppid);
        }
        printf("\n\n");
    }

    printf("%s════════════════════════════════════════════%s\n",
           display_color(C_DIM), display_color(C_RESET));
    printf("  Capturing... Press Ctrl+C to stop\n");
    printf("%s════════════════════════════════════════════%s\n\n",
           display_color(C_DIM), display_color(C_RESET));

#ifdef HAVE_THREADING
    if (g_threading_enabled) {
        /* Multi-threaded mode: start threading and wait */
        if (threading_start(&g_threading, &g_handler) != 0) {
            fprintf(stderr, "%sError:%s Failed to start threading\n",
                    display_color(C_RED), display_color(C_RESET));
            return 1;
        }

        /* Wait for signal (Ctrl+C) */
        while (!g_exiting) {
            usleep(100000);  /* 100ms sleep */
        }

        /* Shutdown handled by cleanup_all_resources via atexit */
    } else
#endif
    {
        /* Single-threaded main event loop */
        while (!g_exiting) {
            err = probe_handler_poll(&g_handler, 100);
            if (err == -EINTR) continue;
            if (err < 0) break;
        }
    }

    printf("\n%sDone.%s\n", display_color(C_GREEN), display_color(C_RESET));

    /* Cleanup is handled by atexit(cleanup_all_resources) */
    return (err < 0 && err != -EINTR) ? 1 : 0;
}
