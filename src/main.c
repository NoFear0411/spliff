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
#include <sys/stat.h>
#include <arpa/inet.h>
#include "include/spliff.h"
#include "bpf/bpf_loader.h"
#include "bpf/binary_scanner.h"
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
static bool g_xdp_initialized = false;
static bool g_debug_mode = false;

#ifdef HAVE_THREADING
static threading_mgr_t g_threading;
static bool g_threading_initialized = false;
static dispatcher_ctx_t g_xdp_dispatcher;  /* XDP event dispatcher context */
#endif

/* Configuration - IPC filtering enabled by default (BPF handles kernel-level filtering) */
config_t g_config = {
    .filter_ipc = true,  /* Always on - BPF does socket family filtering */
    .use_colors = true,  /* Colors on by default */
};

/* Forward declarations for cleanup */
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

/*
 * NOTE: Single-threaded mode has been retired (Phase 3.6 migration).
 * All event processing now uses multi-threaded flow-based architecture.
 * - ALPN tracking: per-worker cache in worker_state_t
 * - Request-response correlation: flow_transaction_t
 * - Body tracking: flow_ctx->body and pending_body_entry_t in worker_state_t
 */

/* ============================================================================
 * Dynamic Probe Attachment - attaches probes to newly discovered SSL libraries
 *
 * When a new process executes (EVENT_PROCESS_EXEC), we scan its /proc/PID/maps
 * for SSL libraries and attach probes dynamically. This enables monitoring
 * processes that start AFTER spliff is running.
 *
 * Supported libraries:
 *   - OpenSSL (libssl.so)
 *   - GnuTLS (libgnutls.so)
 *   - NSS/NSPR (libnspr4.so, libssl3.so)
 *   - WolfSSL (libwolfssl.so)
 *   - BoringSSL (statically linked in Chrome/Chromium/Electron)
 * ============================================================================
 */

/* Track library paths that already have probes attached */
#define MAX_PROBED_PATHS 128

typedef struct {
    char path[512];
    lib_type_t type;
    bool active;
} probed_path_t;

static probed_path_t g_probed_paths[MAX_PROBED_PATHS];
static int g_probed_path_count = 0;

/* Check if probes are already attached to this path */
static bool is_path_already_probed(const char *path) {
    for (int i = 0; i < g_probed_path_count; i++) {
        if (g_probed_paths[i].active &&
            strcmp(g_probed_paths[i].path, path) == 0) {
            return true;
        }
    }
    return false;
}

/* Mark a path as probed */
static void mark_path_probed(const char *path, lib_type_t type) {
    if (g_probed_path_count >= MAX_PROBED_PATHS) return;

    for (int i = 0; i < MAX_PROBED_PATHS; i++) {
        if (!g_probed_paths[i].active) {
            safe_strcpy(g_probed_paths[i].path, sizeof(g_probed_paths[i].path), path);
            g_probed_paths[i].type = type;
            g_probed_paths[i].active = true;
            g_probed_path_count++;
            return;
        }
    }
}

/* Attach probes to an OpenSSL/compatible library (OpenSSL, WolfSSL) */
static int attach_openssl_probes(const char *path, bool is_wolfssl) {
    int attached = 0;
    const char *read_sym = is_wolfssl ? "wolfSSL_read" : "SSL_read";
    const char *write_sym = is_wolfssl ? "wolfSSL_write" : "SSL_write";

    /* Basic SSL_read/SSL_write probes */
    if (bpf_loader_attach_uprobe(&g_loader, path, write_sym,
                                  "probe_ssl_rw_enter", false, g_debug_mode) == 0) attached++;
    if (bpf_loader_attach_uprobe(&g_loader, path, write_sym,
                                  "probe_ssl_write_exit", true, g_debug_mode) == 0) attached++;
    if (bpf_loader_attach_uprobe(&g_loader, path, read_sym,
                                  "probe_ssl_rw_enter", false, g_debug_mode) == 0) attached++;
    if (bpf_loader_attach_uprobe(&g_loader, path, read_sym,
                                  "probe_ssl_read_exit", true, g_debug_mode) == 0) attached++;

    if (!is_wolfssl) {
        /* OpenSSL-specific: SSL_set_fd for socket family tracking */
        bpf_loader_attach_uprobe(&g_loader, path, "SSL_set_fd",
                                  "probe_ssl_set_fd_enter", false, g_debug_mode);
        bpf_loader_attach_uprobe(&g_loader, path, "SSL_set_fd",
                                  "probe_ssl_set_fd_exit", true, g_debug_mode);
        /* SSL_free for cleanup */
        bpf_loader_attach_uprobe(&g_loader, path, "SSL_free",
                                  "probe_ssl_free", false, g_debug_mode);
        /* SSL_read_ex / SSL_write_ex for OpenSSL 3.x */
        bpf_loader_attach_uprobe(&g_loader, path, "SSL_read_ex",
                                  "probe_ssl_rw_ex_enter", false, g_debug_mode);
        bpf_loader_attach_uprobe(&g_loader, path, "SSL_read_ex",
                                  "probe_ssl_read_ex_exit", true, g_debug_mode);
        bpf_loader_attach_uprobe(&g_loader, path, "SSL_write_ex",
                                  "probe_ssl_rw_ex_enter", false, g_debug_mode);
        bpf_loader_attach_uprobe(&g_loader, path, "SSL_write_ex",
                                  "probe_ssl_write_ex_exit", true, g_debug_mode);
        /* ALPN detection */
        bpf_loader_attach_uprobe(&g_loader, path, "SSL_get0_alpn_selected",
                                  "probe_openssl_alpn_enter", false, g_debug_mode);
        bpf_loader_attach_uprobe(&g_loader, path, "SSL_get0_alpn_selected",
                                  "probe_openssl_alpn_exit", true, g_debug_mode);
    } else {
        /* WolfSSL ALPN */
        bpf_loader_attach_uprobe(&g_loader, path, "wolfSSL_ALPN_GetProtocol",
                                  "probe_wolfssl_alpn_enter", false, g_debug_mode);
        bpf_loader_attach_uprobe(&g_loader, path, "wolfSSL_ALPN_GetProtocol",
                                  "probe_wolfssl_alpn_exit", true, g_debug_mode);
    }

    return attached;
}

/* Attach probes to GnuTLS library */
static int attach_gnutls_probes(const char *path) {
    int attached = 0;

    if (bpf_loader_attach_uprobe(&g_loader, path, "gnutls_record_send",
                                  "probe_gnutls_send_enter", false, g_debug_mode) == 0) attached++;
    if (bpf_loader_attach_uprobe(&g_loader, path, "gnutls_record_send",
                                  "probe_gnutls_send_exit", true, g_debug_mode) == 0) attached++;
    if (bpf_loader_attach_uprobe(&g_loader, path, "gnutls_record_recv",
                                  "probe_gnutls_recv_enter", false, g_debug_mode) == 0) attached++;
    if (bpf_loader_attach_uprobe(&g_loader, path, "gnutls_record_recv",
                                  "probe_gnutls_recv_exit", true, g_debug_mode) == 0) attached++;
    /* Cleanup */
    bpf_loader_attach_uprobe(&g_loader, path, "gnutls_deinit",
                              "probe_gnutls_deinit", false, g_debug_mode);
    /* ALPN */
    bpf_loader_attach_uprobe(&g_loader, path, "gnutls_alpn_get_selected_protocol",
                              "probe_gnutls_alpn_enter", false, g_debug_mode);
    bpf_loader_attach_uprobe(&g_loader, path, "gnutls_alpn_get_selected_protocol",
                              "probe_gnutls_alpn_exit", true, g_debug_mode);

    return attached;
}

/* Attach probes to NSS/NSPR library */
static int attach_nss_probes(const char *nspr_path, const char *nss_ssl_path) {
    int attached = 0;

    if (nspr_path && nspr_path[0]) {
        /* NSPR I/O functions */
        if (bpf_loader_attach_uprobe(&g_loader, nspr_path, "PR_Write",
                                      "probe_nss_write_enter", false, g_debug_mode) == 0) attached++;
        if (bpf_loader_attach_uprobe(&g_loader, nspr_path, "PR_Write",
                                      "probe_nss_write_exit", true, g_debug_mode) == 0) attached++;
        if (bpf_loader_attach_uprobe(&g_loader, nspr_path, "PR_Read",
                                      "probe_nss_read_enter", false, g_debug_mode) == 0) attached++;
        if (bpf_loader_attach_uprobe(&g_loader, nspr_path, "PR_Read",
                                      "probe_nss_read_exit", true, g_debug_mode) == 0) attached++;
        bpf_loader_attach_uprobe(&g_loader, nspr_path, "PR_Send",
                                  "probe_nss_write_enter", false, g_debug_mode);
        bpf_loader_attach_uprobe(&g_loader, nspr_path, "PR_Send",
                                  "probe_nss_write_exit", true, g_debug_mode);
        bpf_loader_attach_uprobe(&g_loader, nspr_path, "PR_Recv",
                                  "probe_nss_read_enter", false, g_debug_mode);
        bpf_loader_attach_uprobe(&g_loader, nspr_path, "PR_Recv",
                                  "probe_nss_read_exit", true, g_debug_mode);
        bpf_loader_attach_uprobe(&g_loader, nspr_path, "PR_Close",
                                  "probe_pr_close", false, g_debug_mode);
    }

    if (nss_ssl_path && nss_ssl_path[0]) {
        /* NSS SSL functions */
        bpf_loader_attach_uprobe(&g_loader, nss_ssl_path, "SSL_ImportFD",
                                  "probe_ssl_import_fd_exit", true, g_debug_mode);
        bpf_loader_attach_uprobe(&g_loader, nss_ssl_path, "SSL_GetNextProto",
                                  "probe_nss_alpn_enter", false, g_debug_mode);
        bpf_loader_attach_uprobe(&g_loader, nss_ssl_path, "SSL_GetNextProto",
                                  "probe_nss_alpn_exit", true, g_debug_mode);
    }

    return attached;
}

/* Scan /proc/PID/maps and attach probes to any SSL libraries found */
static int attach_probes_for_pid(uint32_t pid) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%u/maps", pid);

    FILE *f = fopen(maps_path, "r");
    if (!f) return 0;

    int total_attached = 0;
    char line[1024];
    char openssl_path[512] = {0};
    char gnutls_path[512] = {0};
    char nspr_path[512] = {0};
    char nss_ssl_path[512] = {0};
    char wolfssl_path[512] = {0};

    while (fgets(line, sizeof(line), f)) {
        /* Find the pathname (starts with /) */
        char *pathname = strchr(line, '/');
        if (!pathname) continue;

        /* Remove trailing newline */
        char *nl = strchr(pathname, '\n');
        if (nl) *nl = '\0';

        /* Skip if already probed */
        if (is_path_already_probed(pathname)) continue;

        /* Check library types */
        if (strstr(pathname, "libssl.so") && !openssl_path[0]) {
            safe_strcpy(openssl_path, sizeof(openssl_path), pathname);
        } else if (strstr(pathname, "libgnutls.so") && !gnutls_path[0]) {
            safe_strcpy(gnutls_path, sizeof(gnutls_path), pathname);
        } else if (strstr(pathname, "libnspr4.so") && !nspr_path[0]) {
            safe_strcpy(nspr_path, sizeof(nspr_path), pathname);
        } else if (strstr(pathname, "libssl3.so") && !nss_ssl_path[0]) {
            safe_strcpy(nss_ssl_path, sizeof(nss_ssl_path), pathname);
        } else if (strstr(pathname, "libwolfssl.so") && !wolfssl_path[0]) {
            safe_strcpy(wolfssl_path, sizeof(wolfssl_path), pathname);
        }
    }
    fclose(f);

    /* Attach probes to discovered libraries */
    if (openssl_path[0] && !is_path_already_probed(openssl_path)) {
        int attached = attach_openssl_probes(openssl_path, false);
        if (attached > 0) {
            mark_path_probed(openssl_path, LIB_OPENSSL);
            total_attached += attached;
            if (g_debug_mode) {
                printf("  [DYNAMIC] Attached %d probes to OpenSSL: %s (PID %u)\n",
                       attached, openssl_path, pid);
            }
        }
    }

    if (gnutls_path[0] && !is_path_already_probed(gnutls_path)) {
        int attached = attach_gnutls_probes(gnutls_path);
        if (attached > 0) {
            mark_path_probed(gnutls_path, LIB_GNUTLS);
            total_attached += attached;
            if (g_debug_mode) {
                printf("  [DYNAMIC] Attached %d probes to GnuTLS: %s (PID %u)\n",
                       attached, gnutls_path, pid);
            }
        }
    }

    /* NSS requires both NSPR and SSL libraries */
    if ((nspr_path[0] && !is_path_already_probed(nspr_path)) ||
        (nss_ssl_path[0] && !is_path_already_probed(nss_ssl_path))) {
        int attached = attach_nss_probes(
            is_path_already_probed(nspr_path) ? NULL : nspr_path,
            is_path_already_probed(nss_ssl_path) ? NULL : nss_ssl_path
        );
        if (attached > 0) {
            if (nspr_path[0] && !is_path_already_probed(nspr_path)) {
                mark_path_probed(nspr_path, LIB_NSS);
            }
            if (nss_ssl_path[0] && !is_path_already_probed(nss_ssl_path)) {
                mark_path_probed(nss_ssl_path, LIB_NSS_SSL);
            }
            total_attached += attached;
            if (g_debug_mode) {
                printf("  [DYNAMIC] Attached %d probes to NSS (PID %u)\n",
                       attached, pid);
            }
        }
    }

    if (wolfssl_path[0] && !is_path_already_probed(wolfssl_path)) {
        int attached = attach_openssl_probes(wolfssl_path, true);
        if (attached > 0) {
            mark_path_probed(wolfssl_path, LIB_WOLFSSL);
            total_attached += attached;
            if (g_debug_mode) {
                printf("  [DYNAMIC] Attached %d probes to WolfSSL: %s (PID %u)\n",
                       attached, wolfssl_path, pid);
            }
        }
    }

    return total_attached;
}

/* Handle process exec event - scan for SSL libraries and attach probes */
static void handle_process_exec_event(const ssl_data_event_t *event) {
    /* Small delay to allow library loading to complete
     * Libraries are loaded lazily after the process starts */
    usleep(50000);  /* 50ms */

    int attached = attach_probes_for_pid(event->pid);
    if (attached > 0 && g_debug_mode) {
        char proc_name[TASK_COMM_LEN] = {0};
        get_process_name(event->pid, proc_name, sizeof(proc_name));
        printf("  [DYNAMIC] Process %s (PID %u): attached %d probes\n",
               proc_name[0] ? proc_name : event->comm, event->pid, attached);
    }

    /* Also check for BoringSSL binaries (Chrome, Chromium, Electron, etc.)
     * Only if basic library scan found nothing (statically linked BoringSSL) */
    if (attached == 0) {
        /* Get the actual binary path via readlink */
        char proc_exe[64];
        char binary_path[512];
        snprintf(proc_exe, sizeof(proc_exe), "/proc/%u/exe", event->pid);

        ssize_t len = readlink(proc_exe, binary_path, sizeof(binary_path) - 1);
        if (len <= 0) return;
        binary_path[len] = '\0';

        /* Check if already probed (fast path - avoids redundant scanning) */
        if (is_path_already_probed(binary_path)) {
            return;
        }

        /* Check binary size - skip small binaries (< 50MB unlikely to have BoringSSL) */
        struct stat st;
        if (stat(binary_path, &st) != 0 || st.st_size < 50 * 1024 * 1024) {
            return;
        }

        /* Direct build ID lookup - fast path that only reads ELF headers
         * Skip the slow binary_has_boringssl() signature scan since:
         * 1. If build ID is in database, we know it has BoringSSL
         * 2. If not in database, we can't attach probes anyway */
        struct boringssl_offsets offsets = {0};
        int scan_result = scan_binary_for_boringssl(binary_path, &offsets, false);

        if (scan_result == 0 && offsets.found) {
            /* Known BoringSSL binary - attach probes */
            int probes = 0;

            if (offsets.ssl_write_offset) {
                if (bpf_loader_attach_uprobe_offset(&g_loader, binary_path,
                        offsets.ssl_write_offset, "probe_ssl_rw_enter", false, g_debug_mode) == 0)
                    probes++;
                if (bpf_loader_attach_uprobe_offset(&g_loader, binary_path,
                        offsets.ssl_write_offset, "probe_ssl_write_exit", true, g_debug_mode) == 0)
                    probes++;
            }

            if (offsets.ssl_read_offset) {
                if (bpf_loader_attach_uprobe_offset(&g_loader, binary_path,
                        offsets.ssl_read_offset, "probe_ssl_rw_enter", false, g_debug_mode) == 0)
                    probes++;
                if (bpf_loader_attach_uprobe_offset(&g_loader, binary_path,
                        offsets.ssl_read_offset, "probe_ssl_read_exit", true, g_debug_mode) == 0)
                    probes++;
            }

            if (probes > 0) {
                mark_path_probed(binary_path, LIB_BORINGSSL);
                printf("  [DYNAMIC] %s✓%s BoringSSL: %s (%d probes)\n",
                       display_color(C_GREEN), display_color(C_RESET),
                       binary_path, probes);
                if (offsets.version_info) {
                    printf("      %s\n", offsets.version_info);
                }
            }
        } else if (offsets.build_id[0] && g_debug_mode) {
            /* Unknown build ID - log for debugging */
            mark_path_probed(binary_path, LIB_BORINGSSL);  /* Don't rescan */
            printf("  [DYNAMIC] Unknown BoringSSL build: %s (build_id=%s)\n",
                   binary_path, offsets.build_id);
        }
    }
}

#ifdef HAVE_THREADING
/* Process exec callback for threading mode - called directly by dispatcher */
static void threading_process_exec_callback(const ssl_data_event_t *event, void *ctx) {
    (void)ctx;
    handle_process_exec_event(event);
}
#endif

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

    /* Print SSL operation counter (debug: verify probes fire) */
    if (g_bpf_initialized && g_debug_mode) {
        struct bpf_object *obj = bpf_loader_get_object(&g_loader);
        if (obj) {
            struct bpf_map *map = bpf_object__find_map_by_name(obj, "ssl_op_counter");
            if (map) {
                int fd = bpf_map__fd(map);
                uint32_t key = 0;
                uint64_t counter = 0;
                if (bpf_map_lookup_elem(fd, &key, &counter) == 0) {
                    printf("\n=== SSL Probe Statistics ===\n");
                    printf("Total SSL_read/SSL_write calls intercepted: %lu\n", counter);
                }
            }
        }
    }

    /**
     * @brief Print XDP statistics before cleanup
     *
     * XDP (eXpress Data Path) provides network-layer packet visibility.
     * These statistics show how many packets were processed and correlated
     * with application-layer SSL/TLS events.
     */
    if (g_xdp_initialized) {
        xdp_stats_t xdp_stats;
        if (bpf_loader_xdp_read_stats(&g_loader, &xdp_stats) == 0) {
            printf("\n=== Network Layer (XDP) ===\n");
            printf("Packets processed: %lu (TCP: %lu)\n",
                   xdp_stats.packets_total, xdp_stats.packets_tcp);
            printf("Connections tracked: %lu\n", xdp_stats.flows_created);

            if (g_debug_mode) {
                /* Detailed breakdown in debug mode */
                printf("\n  Flows classified: %lu\n", xdp_stats.flows_classified);
                printf("  Flows ambiguous:  %lu (need deeper inspection)\n",
                       xdp_stats.flows_ambiguous);
                printf("  Cache hits:       %lu (fast-path packets)\n",
                       xdp_stats.gatekeeper_hits);
                printf("  Cookie misses:    %lu (correlation gaps)\n",
                       xdp_stats.cookie_failures);
                if (xdp_stats.ringbuf_drops > 0) {
                    printf("  Events dropped:   %lu (ring buffer full)\n",
                           xdp_stats.ringbuf_drops);
                }

                /* Sockops statistics (cookie caching for XDP correlation) */
                uint64_t sockops_total = xdp_stats.sockops_active +
                                         xdp_stats.sockops_passive;
                if (sockops_total > 0 || xdp_stats.sockops_state > 0) {
                    printf("\n  Sockops events:   %lu (active: %lu, passive: %lu)\n",
                           sockops_total,
                           xdp_stats.sockops_active,
                           xdp_stats.sockops_passive);
                    printf("  Sockops cleanup:  %lu\n", xdp_stats.sockops_state);
                } else {
                    printf("\n  %sWARNING%s: No sockops events - cookie caching inactive!\n",
                           display_color(C_YELLOW), display_color(C_RESET));
                    printf("  (Check cgroup2 mount and sockops attachment)\n");
                }
            }
            printf("\n");
        }
    }

    /* Cleanup XDP (detach from all interfaces) - before BPF cleanup */
    if (g_xdp_initialized) {
        bpf_loader_xdp_detach_all(&g_loader, g_debug_mode);
        g_xdp_initialized = false;
    }

    /* Cleanup BPF loader (detach probes, close object) */
    if (g_bpf_initialized) {
        bpf_loader_cleanup(&g_loader);
        g_bpf_initialized = false;
    }

    /* NOTE: Global pending_body cleanup removed - now handled per-worker */

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

/*
 * NOTE: Single-threaded process_event() removed in Phase 3.6 migration.
 * All event processing now uses multi-threaded process_worker_event().
 */

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
            char ts[32];
            display_get_timestamp(ts, sizeof(ts));

            char proc_name[TASK_COMM_LEN] = {0};
            get_process_name(event->pid, proc_name, sizeof(proc_name));
            const char *name = proc_name[0] ? proc_name : event->comm;

            char lat[32];
            display_format_latency(event->delta_ns, lat, sizeof(lat));

            output_write(worker, "%s%s%s %s\xf0\x9f\x94\x92%s TLS handshake %scomplete%s %s[%s]%s %s%s%s %s(%u)%s\n",
                        display_color(C_DIM), ts, display_color(C_RESET),
                        display_color(C_MAGENTA), display_color(C_RESET),
                        display_color(C_GREEN), display_color(C_RESET),
                        display_color(C_YELLOW), lat, display_color(C_RESET),
                        display_color(C_CYAN), name, display_color(C_RESET),
                        display_color(C_DIM), event->pid, display_color(C_RESET));
        }
        return;
    }

    /* Handle ALPN protocol negotiation */
    if (event->event_type == EVENT_ALPN) {
        if (event->data_len > 0 && event->data_len <= 255) {
            char alpn_proto[256] = {0};
            memcpy(alpn_proto, event->data, event->data_len);

            /* Store in per-worker cache (legacy) */
            worker_set_alpn(state, event->pid, event->ssl_ctx, alpn_proto);

            /* Also store in Shared Pool flow_context and initialize parser */
            if (event->flow_ctx) {
                flow_init_parser(event->flow_ctx, alpn_proto);
                event->flow_ctx->flags |= FLOW_FLAG_HAS_SSL;
            }
        }
        return;
    }

    if (event->data_len == 0) return;

    const uint8_t *data = event->data;
    size_t len = event->data_len;

    /* Try HTTP/1.1 parsing first */
    if (http1_is_request(data, len) || http1_is_response(data, len)) {
        /*
         * Flow-based HTTP/1 parsing (Phase 3.6)
         *
         * When flow_ctx is available with HTTP/1 protocol, use the persistent
         * flow-based parser. This handles:
         * - Headers split across TCP segments
         * - HTTP/1.1 keep-alive with on_reset callback
         * - Chunked transfer encoding (automatic via llhttp)
         *
         * The parser displays output via callbacks (on_headers_complete_flow).
         */
        if (event->flow_ctx && event->flow_ctx->proto == FLOW_PROTO_HTTP1) {
            /* Build ssl_data_event_t for flow-based parser */
            ssl_data_event_t bpf_event = {
                .timestamp_ns = event->timestamp_ns,
                .delta_ns = event->delta_ns,
                .ssl_ctx = event->ssl_ctx,
                .pid = event->pid,
                .tid = event->tid,
                .uid = event->uid,
                .event_type = event->event_type,
                .buf_filled = (int32_t)event->data_len,
            };
            memcpy(bpf_event.comm, event->comm, TASK_COMM_LEN);

            /* Parse using persistent flow-based parser */
            int result = http1_parse_flow(event->flow_ctx, data, len, &bpf_event);
            if (result >= 0) {
                return;  /* Successfully parsed - display handled in callbacks */
            }
            /* Fall through to legacy parsing on error */
        }

        /*
         * LEGACY HTTP/1 PARSING - DEPRECATED
         *
         * This fallback path uses worker caches (h1_request_entry_t,
         * pending_body_entry_t) instead of flow_context_t. It's only
         * reached when:
         * 1. flow_ctx is not available (pool exhaustion)
         * 2. flow_ctx->proto != FLOW_PROTO_HTTP1 (protocol not detected)
         * 3. http1_parse_flow() returns an error
         *
         * TODO: Once flow-based parsing is fully validated, this entire
         * block (through the matching closing brace) can be removed along
         * with the worker_*_h1_request and worker_*_pending_body functions.
         */
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

        /* Get ALPN - prefer Shared Pool, fall back to per-worker cache */
        const char *alpn = NULL;
        if (event->flow_ctx && event->flow_ctx->alpn[0]) {
            alpn = event->flow_ctx->alpn;
        } else {
            alpn = worker_get_alpn(state, event->pid, event->ssl_ctx);
        }
        if (alpn && alpn[0]) {
            safe_strcpy(msg.alpn_proto, sizeof(msg.alpn_proto), alpn);
        }

        /* Populate XDP flow correlation info ("Golden Thread" double-view) */
        if (event->flow_info) {
            msg.has_flow_info = true;
            msg.flow_src_ip = event->flow_info->flow.saddr;
            msg.flow_dst_ip = event->flow_info->flow.daddr;
            msg.flow_src_port = event->flow_info->flow.sport;
            msg.flow_dst_port = event->flow_info->flow.dport;
            msg.flow_ip_version = event->flow_info->flow.ip_version;
            msg.flow_direction = event->flow_info->direction;
            msg.flow_category = event->flow_info->category;
            memcpy(msg.flow_ifname, event->flow_info->ifname, sizeof(msg.flow_ifname));
        }

        /* Format output through output thread - unified with display_http_* functions */
        char ts[32];
        display_get_timestamp(ts, sizeof(ts));

        /* Determine ALPN protocol string */
        const char *alpn_str = alpn ? alpn : "http/1.1";

        if (msg.direction == DIR_REQUEST) {
            /* Extract Host header for URL display and store for response correlation */
            const char *host = NULL;
            for (int i = 0; i < msg.header_count; i++) {
                if (strcasecmp(msg.headers[i].name, "Host") == 0) {
                    host = msg.headers[i].value;
                    break;
                }
            }
            /* Store request for response correlation */
            worker_set_h1_request(state, event->pid, event->ssl_ctx,
                                  msg.method, msg.path, host);

            /* Build full URI with safe truncation for display
             * Buffer: 2560, "https://" = 8, null = 1, available = 2551
             * Host max: 500 (domains are short), Path max: 2048 */
            char full_uri[2560];
            if (host && host[0]) {
                snprintf(full_uri, sizeof(full_uri), "https://%.500s%.2048s", host, msg.path);
            } else {
                snprintf(full_uri, sizeof(full_uri), "%.2048s", msg.path);
            }

            /* Format: <timestamp> -> <METHOD> <full URI> ALPN:<protocol> <process> (<PID>) [latency] */
            output_write(worker, "%s%s%s %s\xe2\x86\x92%s %s%s%s %s %sALPN:%s%s %s%s%s %s(%u)%s",
                        display_color(C_DIM), ts, display_color(C_RESET),
                        display_color(C_GREEN), display_color(C_RESET),
                        display_color(C_BOLD), msg.method, display_color(C_RESET),
                        full_uri,
                        display_color(C_DIM), alpn_str, display_color(C_RESET),
                        display_color(C_CYAN), msg.comm, display_color(C_RESET),
                        display_color(C_DIM), msg.pid, display_color(C_RESET));
            if (msg.delta_ns > 0) {
                char lat[32];
                display_format_latency(msg.delta_ns, lat, sizeof(lat));
                output_write(worker, " %s[%s]%s",
                            display_color(C_YELLOW), lat, display_color(C_RESET));
            }
            output_write(worker, "\n");

            /**
             * @brief Show XDP flow correlation info ("Golden Thread" double-view)
             *
             * Normalizes display based on HTTP direction:
             * - Request: local_client:port → remote_server:port
             * - Response: remote_server:port → local_client:port
             */
            if (msg.has_flow_info) {
                char ip1[INET6_ADDRSTRLEN], ip2[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET, &msg.flow_src_ip, ip1, sizeof(ip1));
                inet_ntop(AF_INET, &msg.flow_dst_ip, ip2, sizeof(ip2));
                uint16_t port1 = ntohs(msg.flow_src_port);
                uint16_t port2 = ntohs(msg.flow_dst_port);

                /* Normalize based on flow_direction and HTTP direction */
                const char *left_ip, *right_ip;
                uint16_t left_port, right_port;
                if (msg.flow_direction == 1) {
                    /* Packet was client→server: saddr=client, daddr=server */
                    left_ip = ip1; left_port = port1;
                    right_ip = ip2; right_port = port2;
                } else {
                    /* Packet was server→client: saddr=server, daddr=client */
                    /* For request, swap to show client → server */
                    left_ip = ip2; left_port = port2;
                    right_ip = ip1; right_port = port1;
                }

                const char *cat_name = (msg.flow_category == XDP_CAT_TLS_TCP) ? "TLS" :
                                       (msg.flow_category == XDP_CAT_QUIC) ? "QUIC" :
                                       (msg.flow_category == XDP_CAT_PLAIN_HTTP) ? "HTTP" :
                                       (msg.flow_category == XDP_CAT_H2_PREFACE) ? "H2" :
                                       (msg.flow_category == XDP_CAT_OTHER) ? "Other" : "?";
                output_write(worker, "              %s|-%s %s%s:%u → %s:%u%s %s[%s]%s",
                            display_color(C_DIM), display_color(C_RESET),
                            display_color(C_DIM), left_ip, left_port,
                            right_ip, right_port, display_color(C_RESET),
                            display_color(C_CYAN), cat_name, display_color(C_RESET));
                if (msg.flow_ifname[0]) {
                    output_write(worker, " %s(%s)%s", display_color(C_DIM),
                                msg.flow_ifname, display_color(C_RESET));
                }
                output_write(worker, "\n");
            }
        } else {
            /* Look up cached request for URL correlation */
            h1_request_entry_t *cached_req = worker_find_h1_request(state, event->pid, event->ssl_ctx);

            /* Format: <timestamp> <- <STATUS> <URL> ALPN:<protocol> <content-type> (<size>) <process> (<PID>) [latency] */
            const char *status_color = (msg.status_code >= 200 && msg.status_code < 300) ?
                                       C_GREEN : (msg.status_code >= 400) ? C_RED : C_YELLOW;
            output_write(worker, "%s%s%s %s\xe2\x86\x90%s %s%d%s",
                        display_color(C_DIM), ts, display_color(C_RESET),
                        display_color(C_BLUE), display_color(C_RESET),
                        display_color(status_color), msg.status_code, display_color(C_RESET));
            /* Show URL from cached request for correlation */
            if (cached_req && cached_req->host[0]) {
                output_write(worker, " https://%s%s", cached_req->host, cached_req->path);
            }
            /* Show ALPN after URL */
            output_write(worker, " %sALPN:%s%s",
                        display_color(C_DIM), alpn_str, display_color(C_RESET));
            if (msg.content_type[0]) {
                output_write(worker, " %s%s%s",
                            display_color(C_DIM), msg.content_type, display_color(C_RESET));
            }
            if (msg.content_length > 0) {
                output_write(worker, " %s(%zu bytes)%s",
                            display_color(C_DIM), msg.content_length, display_color(C_RESET));
            }
            output_write(worker, " %s%s%s %s(%u)%s",
                        display_color(C_CYAN), msg.comm, display_color(C_RESET),
                        display_color(C_DIM), msg.pid, display_color(C_RESET));
            if (msg.delta_ns > 0) {
                char lat[32];
                display_format_latency(msg.delta_ns, lat, sizeof(lat));
                output_write(worker, " %s[%s]%s",
                            display_color(C_YELLOW), lat, display_color(C_RESET));
            }
            output_write(worker, "\n");

            /**
             * @brief Show XDP flow correlation info ("Golden Thread" double-view)
             *
             * Normalizes display based on HTTP direction:
             * - Response: remote_server:port → local_client:port
             */
            if (msg.has_flow_info) {
                char ip1[INET6_ADDRSTRLEN], ip2[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET, &msg.flow_src_ip, ip1, sizeof(ip1));
                inet_ntop(AF_INET, &msg.flow_dst_ip, ip2, sizeof(ip2));
                uint16_t port1 = ntohs(msg.flow_src_port);
                uint16_t port2 = ntohs(msg.flow_dst_port);

                /* Normalize: response shows server → client */
                const char *left_ip, *right_ip;
                uint16_t left_port, right_port;
                if (msg.flow_direction == 2) {
                    /* Packet was server→client: saddr=server, daddr=client */
                    left_ip = ip1; left_port = port1;
                    right_ip = ip2; right_port = port2;
                } else {
                    /* Packet was client→server: saddr=client, daddr=server */
                    /* For response, swap to show server → client */
                    left_ip = ip2; left_port = port2;
                    right_ip = ip1; right_port = port1;
                }

                const char *cat_name = (msg.flow_category == XDP_CAT_TLS_TCP) ? "TLS" :
                                       (msg.flow_category == XDP_CAT_QUIC) ? "QUIC" :
                                       (msg.flow_category == XDP_CAT_PLAIN_HTTP) ? "HTTP" :
                                       (msg.flow_category == XDP_CAT_H2_PREFACE) ? "H2" :
                                       (msg.flow_category == XDP_CAT_OTHER) ? "Other" : "?";
                output_write(worker, "              %s|-%s %s%s:%u → %s:%u%s %s[%s]%s",
                            display_color(C_DIM), display_color(C_RESET),
                            display_color(C_DIM), left_ip, left_port,
                            right_ip, right_port, display_color(C_RESET),
                            display_color(C_CYAN), cat_name, display_color(C_RESET));
                if (msg.flow_ifname[0]) {
                    output_write(worker, " %s(%s)%s", display_color(C_DIM),
                                msg.flow_ifname, display_color(C_RESET));
                }
                output_write(worker, "\n");
            }
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
        /* NOTE: XDP flow info is in event->flow_ctx->flow (Phase 3.6) */

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

        /* Use flow-aware processing when flow_ctx available (Phase 3.6) */
        http2_process_frame_flow(data, len, &bpf_event, event->flow_ctx);
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

        /* Set XDP flow correlation info if available ("Golden Thread" double-view) */
        if (event->flow_info) {
            http2_set_flow_info(event->pid, event->ssl_ctx,
                               event->flow_info->flow.saddr,
                               event->flow_info->flow.daddr,
                               event->flow_info->flow.sport,
                               event->flow_info->flow.dport,
                               event->flow_info->flow.ip_version,
                               event->flow_info->direction,
                               event->flow_info->category,
                               event->flow_info->ifname);
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
            /* Use flow-aware processing when flow_ctx available (Phase 3.6) */
            http2_process_frame_flow(data + 24, len - 24, &bpf_event, event->flow_ctx);
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

                /* Set XDP flow correlation info if available */
                if (event->flow_info) {
                    http2_set_flow_info(event->pid, event->ssl_ctx,
                                       event->flow_info->flow.saddr,
                                       event->flow_info->flow.daddr,
                                       event->flow_info->flow.sport,
                                       event->flow_info->flow.dport,
                                       event->flow_info->flow.ip_version,
                                       event->flow_info->direction,
                                       event->flow_info->category,
                                       event->flow_info->ifname);
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
                /* Use flow-aware processing when flow_ctx available (Phase 3.6) */
                http2_process_frame_flow(data, len, &bpf_event, event->flow_ctx);
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
            g_debug_mode = true;
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
    printf("%s║        spliff v%-6s                  ║%s\n",
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
        "build-release/spliff.bpf.o",   /* Makefile release build */
        "build-debug/spliff.bpf.o",     /* Makefile debug build */
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

    /* Initialize XDP subsystem (auto-attach to network interfaces) */
    xdp_error_t xdp_err;
    if (bpf_loader_xdp_init(&g_loader, debug_mode, &xdp_err) == 0) {
        g_xdp_initialized = true;

#ifdef HAVE_THREADING
        /* Initialize XDP dispatcher context for event handling */
        memset(&g_xdp_dispatcher, 0, sizeof(g_xdp_dispatcher));

        /* Register XDP event callback (may fail if ringbuf unavailable) */
        int callback_ret = bpf_loader_xdp_set_event_callback(&g_loader,
                                                              dispatcher_xdp_event_handler,
                                                              &g_xdp_dispatcher);
        if (callback_ret != 0 && debug_mode) {
            printf("  %s[DEBUG]%s XDP event callback not registered (ringbuf unavailable)\n",
                   display_color(C_YELLOW), display_color(C_RESET));
        }
#endif

        /* Auto-attach to all suitable network interfaces
         * Attach regardless of callback status - provides packet visibility */
        int attached = bpf_loader_xdp_attach_all(&g_loader, debug_mode);
        if (attached > 0) {
            printf("  %s✓%s XDP attached to %d interface%s\n",
                   display_color(C_GREEN), display_color(C_RESET),
                   attached, attached > 1 ? "s" : "");

            /* Attach sock_ops for socket cookie caching (the "Golden Thread")
             * sock_ops runs at TCP connection establishment and caches cookies
             * so XDP can correlate packets with SSL sessions */
            if (bpf_loader_sockops_attach(&g_loader, debug_mode) == 0) {
                if (debug_mode) {
                    printf("  %s✓%s sock_ops attached for cookie caching\n",
                           display_color(C_GREEN), display_color(C_RESET));
                }
            } else if (debug_mode) {
                printf("  %s[DEBUG]%s sock_ops attach failed (cookie correlation limited)\n",
                       display_color(C_YELLOW), display_color(C_RESET));
            }

            /* Warm-up: Seed flow_cookie_map with existing TCP connections
             * This enables correlation with connections established before attachment */
            int warmed = bpf_loader_xdp_warmup_cookies(&g_loader, debug_mode);
            if (warmed > 0 && debug_mode) {
                printf("  %s[DEBUG]%s Warmed up %d existing connections\n",
                       display_color(C_GREEN), display_color(C_RESET), warmed);
            }
        } else if (debug_mode) {
            printf("  %s[DEBUG]%s No suitable interfaces for XDP attachment\n",
                   display_color(C_YELLOW), display_color(C_RESET));
        }
    } else if (debug_mode) {
        printf("  %s[DEBUG]%s XDP not available: %s\n",
               display_color(C_YELLOW), display_color(C_RESET),
               xdp_err.message[0] ? xdp_err.message : "unknown error");
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

        /* SSL_read_ex / SSL_write_ex - OpenSSL 3.x extended variants
         * Chrome and other modern applications use these instead of SSL_read/SSL_write */
        bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_read_ex",
                                "probe_ssl_rw_ex_enter", false, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_read_ex",
                                "probe_ssl_read_ex_exit", true, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_write_ex",
                                "probe_ssl_rw_ex_enter", false, debug_mode);
        bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_write_ex",
                                "probe_ssl_write_ex_exit", true, debug_mode);
        /* Mark as probed to prevent dynamic re-attachment */
        mark_path_probed(openssl_path, LIB_OPENSSL);
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
        /* Mark as probed to prevent dynamic re-attachment */
        mark_path_probed(gnutls_path, LIB_GNUTLS);
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
        /* Mark as probed to prevent dynamic re-attachment */
        mark_path_probed(nss_path, LIB_NSS);
    }

    /* SSL_ImportFD - track verified SSL connections for IPC filtering
     * This is called when a socket is promoted to SSL in Firefox.
     * All web traffic must pass through here, but IPC rarely does. */
    if (nss_ssl_path[0]) {
        bpf_loader_attach_uprobe(&g_loader, nss_ssl_path, "SSL_ImportFD",
                                "probe_ssl_import_fd_exit", true, debug_mode);
        /* Mark as probed to prevent dynamic re-attachment */
        mark_path_probed(nss_ssl_path, LIB_NSS_SSL);
    }

    /* Attach handshake probes if -H is set */
    if (g_config.show_handshake) {
        if (openssl_path[0]) {
            /* SSL_connect - client-side handshake (internally calls SSL_do_handshake) */
            bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_connect",
                                    "probe_ssl_handshake_enter", false, debug_mode);
            bpf_loader_attach_uprobe(&g_loader, openssl_path, "SSL_connect",
                                    "probe_ssl_handshake_exit", true, debug_mode);
            /* Note: SSL_do_handshake probes removed - SSL_connect calls it internally,
             * which was causing duplicate handshake events */
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
        /* Mark as probed to prevent dynamic re-attachment */
        mark_path_probed(wolfssl_path, LIB_WOLFSSL);
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

    /* BoringSSL detection (EDR-style)
     * Scan running processes for any binary with statically-linked BoringSSL.
     * This detects Chrome, Chromium, Brave, Edge, Electron apps, or any other
     * binary using BoringSSL - no hardcoded paths or names needed. */
    int boringssl_found = bpf_loader_discover_boringssl(&discovery_result, 50, debug_mode);

    if (discovery_result.boringssl_count > 0) {
        printf("\n  BoringSSL Binaries (%d found, %d with known offsets):\n",
               discovery_result.boringssl_count, boringssl_found);

        for (int i = 0; i < discovery_result.boringssl_count; i++) {
            discovered_boringssl_t *b = &discovery_result.boringssl[i];

            if (!b->offsets_known) {
                printf("  %s?%s %s\n",
                       display_color(C_YELLOW), display_color(C_RESET), b->path);
                printf("      Build ID: %s (unknown - add to offset database)\n", b->build_id);
                continue;
            }

            printf("  %s✓%s %s\n",
                   display_color(C_GREEN), display_color(C_RESET), b->path);
            if (b->version_info) {
                printf("      %s\n", b->version_info);
            }
            if (debug_mode) {
                printf("      SSL_read: 0x%lx, SSL_write: 0x%lx\n",
                       b->ssl_read_offset, b->ssl_write_offset);
            }

            /* Attach probes to internal functions
             *
             * IMPORTANT: From Ghidra decompilation of Chromium 143:
             * - ssl_read_impl(SSL*) only takes SSL pointer - NO buf/len args!
             * - DoPayloadWrite() takes NO args besides 'this' - buffer is internal
             * - DoPayloadRead(this, span.data, span.size) - base::span by value
             * - ReadIfReady(this, IOBuffer*, len, callback) - complex C++ ABI
             *
             * We ONLY use SSL_read/SSL_write as reliable hooks since they have
             * stable 3-arg signatures: (SSL*, buf, len)
             */

            /* ssl_read_impl - DISABLED: only takes SSL*, no buffer args
             * The probe would read garbage from RSI/RDX causing crashes */
#if 0
            if (b->ssl_read_impl_offset) {
                bpf_loader_attach_uprobe_offset(&g_loader, b->path,
                    b->ssl_read_impl_offset, "probe_ssl_read_impl_enter", false, debug_mode);
                bpf_loader_attach_uprobe_offset(&g_loader, b->path,
                    b->ssl_read_impl_offset, "probe_ssl_read_exit", true, debug_mode);
            }
#endif

            /* DoPayloadWrite - DISABLED: no buffer arguments, can't capture data */
#if 0
            if (b->ssl_write_impl_offset) {
                bpf_loader_attach_uprobe_offset(&g_loader, b->path,
                    b->ssl_write_impl_offset, "probe_do_payload_write_enter", false, debug_mode);
                bpf_loader_attach_uprobe_offset(&g_loader, b->path,
                    b->ssl_write_impl_offset, "probe_ssl_write_exit", true, debug_mode);
            }
#endif

            /* Async I/O hooks - DISABLED: complex C++ ABI, need more analysis */
#if 0
            if (b->socket_read_offset) {
                bpf_loader_attach_uprobe_offset(&g_loader, b->path,
                    b->socket_read_offset, "probe_socket_read_enter", false, debug_mode);
            }
            if (b->on_read_ready_offset) {
                bpf_loader_attach_uprobe_offset(&g_loader, b->path,
                    b->on_read_ready_offset, "probe_on_read_ready", false, debug_mode);
            }
#endif

            /* DoPayloadRead - base::span passed by value (RSI=data, RDX=size)
             * This one might work but disabled for safety until verified */
#if 0
            if (b->do_payload_read_offset) {
                bpf_loader_attach_uprobe_offset(&g_loader, b->path,
                    b->do_payload_read_offset, "probe_do_payload_read_enter", false, debug_mode);
            }
#endif

            /* Public API fallback hooks */
            bpf_loader_attach_uprobe_offset(&g_loader, b->path,
                b->ssl_write_offset, "probe_ssl_rw_enter", false, debug_mode);
            bpf_loader_attach_uprobe_offset(&g_loader, b->path,
                b->ssl_write_offset, "probe_ssl_write_exit", true, debug_mode);
            bpf_loader_attach_uprobe_offset(&g_loader, b->path,
                b->ssl_read_offset, "probe_ssl_rw_enter", false, debug_mode);
            bpf_loader_attach_uprobe_offset(&g_loader, b->path,
                b->ssl_read_offset, "probe_ssl_read_exit", true, debug_mode);
        }
        printf("\n");
    }

    /* Attach syscall tracepoints for SSL* → fd correlation
     * This enables FD tracking for Chrome/BoringSSL and other libraries
     * that don't use SSL_set_fd. The correlation works by detecting when
     * a syscall (write/read/sendto/recvfrom) happens during an active
     * SSL_read/SSL_write operation. */
    int syscall_hooks = 0;
    if (bpf_loader_attach_tracepoint(&g_loader, "syscalls", "sys_enter_write",
                                      "trace_sys_enter_write", debug_mode) == 0) {
        syscall_hooks++;
    }
    if (bpf_loader_attach_tracepoint(&g_loader, "syscalls", "sys_enter_read",
                                      "trace_sys_enter_read", debug_mode) == 0) {
        syscall_hooks++;
    }
    if (bpf_loader_attach_tracepoint(&g_loader, "syscalls", "sys_enter_sendto",
                                      "trace_sys_enter_sendto", debug_mode) == 0) {
        syscall_hooks++;
    }
    if (bpf_loader_attach_tracepoint(&g_loader, "syscalls", "sys_enter_recvfrom",
                                      "trace_sys_enter_recvfrom", debug_mode) == 0) {
        syscall_hooks++;
    }
    if (debug_mode && syscall_hooks > 0) {
        printf("  [DEBUG] Attached %d syscall correlation hooks\n", syscall_hooks);
    }

    /* Attach process exit tracepoint for session cleanup */
    if (bpf_loader_attach_tracepoint(&g_loader, "sched", "sched_process_exit",
                                      "handle_process_exit", debug_mode) == 0) {
        if (debug_mode) {
            printf("  [DEBUG] Process exit tracepoint attached\n");
        }
    }

    /* Attach process lifecycle tracepoints for dynamic SSL library detection
     * - sched_process_exec: New process starts → check for SSL libraries
     * - sched_process_fork: Process forks → inherit parent's SSL tracking
     * This enables attaching probes to processes started AFTER spliff loads */
    int lifecycle_hooks = 0;
    if (bpf_loader_attach_tracepoint(&g_loader, "sched", "sched_process_exec",
                                      "handle_process_exec", debug_mode) == 0) {
        lifecycle_hooks++;
        if (debug_mode) {
            printf("  [DEBUG] Process exec tracepoint attached (dynamic SSL detection)\n");
        }
    }
    if (bpf_loader_attach_tracepoint(&g_loader, "sched", "sched_process_fork",
                                      "handle_process_fork", debug_mode) == 0) {
        lifecycle_hooks++;
        if (debug_mode) {
            printf("  [DEBUG] Process fork tracepoint attached\n");
        }
    }
    if (debug_mode && lifecycle_hooks > 0) {
        printf("  [DEBUG] Dynamic process monitoring enabled (%d hooks)\n", lifecycle_hooks);
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
    /* Initialize threading (required for Phase 3.6+ architecture) */
    if (threading_init(&g_threading, num_threads, false) == 0) {
        g_threading_initialized = true;
        printf("  %sMulti-threading:%s %d workers%s\n",
               display_color(C_GREEN), display_color(C_RESET),
               g_threading.num_workers,
               num_threads == 0 ? " (auto)" : "");

        /* Warm-up userspace flow_cache with existing flows from BPF.
         * This fixes correlation for pre-existing connections that don't
         * trigger XDP FLOW_NEW events (already classified in BPF).
         * Uses real socket cookies from BPF flow_states map. */
        int flow_states_fd = bpf_loader_get_flow_states_fd(&g_loader);
        if (flow_states_fd >= 0) {
            int warmed_cache = flow_cache_warmup_from_bpf(
                &g_threading.dispatcher.flow_cache, flow_states_fd, debug_mode);
            if (debug_mode && warmed_cache > 0) {
                printf("  %s[DEBUG]%s Warmed up flow_cache with %d BPF flows\n",
                       display_color(C_DIM), display_color(C_RESET), warmed_cache);
            }
        }
    } else {
        fprintf(stderr, "%sError:%s Failed to initialize threading\n",
                display_color(C_RED), display_color(C_RESET));
        return 1;  /* atexit handler will cleanup */
    }
#else
    fprintf(stderr, "%sError:%s spliff requires HAVE_THREADING support\n",
            display_color(C_RED), display_color(C_RESET));
    return 1;
#endif

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

    /* === Main Event Processing Loop ===
     *
     * This loop integrates two event sources:
     *
     * 1. UPROBE EVENTS (SSL/TLS Decryption)
     *    - Source:  SSL_read/write/set_fd hooks
     *    - Data:    Decrypted payloads, socket cookies
     *    - Handler: uprobe worker threads (if HAVE_THREADING)
     *    - Purpose: Observe encrypted traffic semantics
     *
     * 2. XDP EVENTS (Network Flow Classification)
     *    - Source:  Kernel XDP program
     *    - Data:    5-tuple, protocol category, socket cookies
     *    - Handler: dispatcher_xdp_event_handler
     *    - Purpose: Observe network-layer traffic patterns
     *
     * CORRELATION: Both events carry socket_cookie to enable matching
     *
     *   Uprobe sees: SSL_write(fd=42, data="GET /api/v1/...")
     *   XDP sees:    TCP 192.168.1.1:54321 -> 10.0.0.1:443 [TLS]
     *   Link:        Both have cookie=12345 (same socket)
     *
     * FLOW WITH THREADING:
     *   Main thread:   Polls XDP, updates stats, sleeps 50ms
     *   Worker threads: Handle uprobe events via dispatcher
     *
     * FLOW WITHOUT THREADING:
     *   Main thread:   Sequentially polls uprobe (50ms), then XDP (50ms)
     *   Total latency: ~100ms worst case
     *
     * ERROR HANDLING:
     *   - Uprobe errors: Fatal (break loop)
     *   - XDP errors:    Non-fatal (continue, uprobe unaffected)
     *   - EINTR:         Harmless (continue loop)
     */

#ifdef HAVE_THREADING
    /* Start multi-threaded event processing */
    if (threading_start(&g_threading, &g_handler) != 0) {
        fprintf(stderr, "%sError:%s Failed to start threading\n",
                display_color(C_RED), display_color(C_RESET));
        return 1;
    }

    /* Register callback for dynamic SSL library detection (process exec events) */
    dispatcher_set_lifecycle_callback(&g_threading.dispatcher,
                                      threading_process_exec_callback, NULL);

    /* Re-register XDP callback with the threaded dispatcher's flow_cache.
     * The initial registration (above) used g_xdp_dispatcher which has no
     * flow_cache. Now that threading is started, use the real dispatcher
     * so XDP events populate the same flow_cache that SSL events use. */
    if (g_xdp_initialized) {
        bpf_loader_xdp_set_event_callback(&g_loader,
                                          dispatcher_xdp_event_handler,
                                          &g_threading.dispatcher);
        if (debug_mode) {
            printf("  %s✓%s XDP callback re-registered with threaded dispatcher\n",
                   display_color(C_GREEN), display_color(C_RESET));
        }
    }

    /* Main thread polls XDP ring buffer while workers handle uprobes */
    while (!g_exiting) {
        if (g_xdp_initialized && bpf_loader_xdp_is_active(&g_loader)) {
            /* Poll XDP events (non-blocking with short timeout) */
            int xdp_err = bpf_loader_xdp_poll(&g_loader, 50);
            if (xdp_err < 0 && xdp_err != -EINTR) {
                if (debug_mode) {
                    fprintf(stderr, "[DEBUG] XDP poll error: %d\n", xdp_err);
                }
            }
        }
        usleep(50000);  /* 50ms between XDP polls */
    }
    /* Shutdown handled by cleanup_all_resources via atexit */
#endif

    printf("\n%sDone.%s\n", display_color(C_GREEN), display_color(C_RESET));

    /* Cleanup is handled by atexit(cleanup_all_resources) */
    return (err < 0 && err != -EINTR) ? 1 : 0;
}
