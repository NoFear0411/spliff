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
 *
 * bpf_loader.h - BPF program loading and uprobe attachment
 */

#ifndef BPF_LOADER_H
#define BPF_LOADER_H

#include <stdbool.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define SPLIFF_MAX_LINKS 64   /* Renamed to avoid conflict with linux/netlink.h */
#define MAX_DISCOVERED_LIBS 32   /* Maximum unique library paths to track */
#define MAX_PATHS_PER_TYPE 8     /* Maximum paths per library type */
#define MAX_XDP_INTERFACES 32    /* Maximum network interfaces for XDP */

// =============================================================================
// XDP Types - Forward Declarations
// =============================================================================

/* XDP error information for diagnostics */
typedef struct {
    int code;                /* Error code (-ENOENT, -EACCES, etc.) */
    char message[256];       /* Human-readable error message */
} xdp_error_t;

/* XDP event callback function type
 * Called by ring_buffer__poll() for each event received.
 * @param ctx      User context (passed to set_event_callback)
 * @param data     Event data (xdp_packet_event or xdp_payload_event)
 * @param data_sz  Size of event data
 * @return 0 to continue processing, <0 to stop
 */
typedef int (*xdp_event_callback_t)(void *ctx, void *data, size_t data_sz);

// =============================================================================
// XDP Interface Management
// =============================================================================

/* XDP attachment mode */
typedef enum {
    XDP_MODE_SKB = 0,    /* Generic/SKB mode (fallback, works everywhere) */
    XDP_MODE_NATIVE,     /* Native/driver mode (requires driver support) */
    XDP_MODE_OFFLOAD,    /* Hardware offload (requires NIC support) */
} xdp_mode_t;

/* XDP interface attachment state */
typedef struct {
    char name[32];       /* Interface name (e.g., "eth0") */
    int ifindex;         /* Interface index */
    int prog_fd;         /* XDP program fd attached to this interface */
    xdp_mode_t mode;     /* Attachment mode used */
    bool attached;       /* Whether XDP is attached */
} xdp_interface_t;

/* XDP loader state */
typedef struct {
    struct bpf_program *xdp_prog;           /* XDP program from BPF object */
    xdp_interface_t interfaces[MAX_XDP_INTERFACES];
    int interface_count;                     /* Number of attached interfaces */
    struct ring_buffer *xdp_rb;              /* XDP ring buffer (xdp_events) */
    xdp_event_callback_t event_callback;    /* User event callback */
    void *callback_ctx;                      /* User context for callback */
    int xdp_events_fd;                       /* XDP ring buffer map fd */
    int session_registry_fd;                 /* For userspace policy updates */
    int flow_states_fd;                      /* For debugging/stats */
    int xdp_stats_fd;                        /* XDP statistics map fd */
    int cookie_to_ssl_fd;                   /* Cookie correlation map fd */
    int flow_cookie_map_fd;                 /* Flow→cookie cache map fd */
    xdp_error_t last_error;                 /* Last error for diagnostics */
    bool enabled;                            /* Whether XDP is initialized */
    /* sock_ops for socket cookie caching */
    struct bpf_link *sockops_link;          /* sock_ops program link */
    int cgroup_fd;                          /* Cgroup fd for sock_ops attachment */
} xdp_loader_t;

/* BPF loader state */
typedef struct {
    struct bpf_object *obj;
    struct bpf_link *links[SPLIFF_MAX_LINKS];
    int link_count;
    xdp_loader_t xdp;                        /* XDP-specific state */
} bpf_loader_t;

/* Initialize BPF loader - returns 0 on success, -1 on failure */
[[nodiscard]] int bpf_loader_init(bpf_loader_t *loader);

/* Load BPF object from file - returns 0 on success, negative on failure */
[[nodiscard]] int bpf_loader_load(bpf_loader_t *loader, const char *filename);

/* Set BPF object from skeleton (for embedded BPF via libbpf skeleton)
 * The loader takes ownership of the object - do NOT destroy it separately.
 * Use this with bpftool-generated skeletons for CO-RE and strip-safe builds. */
void bpf_loader_set_object(bpf_loader_t *loader, struct bpf_object *obj);

/* Find a library path by name (static paths) - returns 0 on success, -1 if not found */
int bpf_loader_find_library(const char *name, char *path, size_t size);

/* Library types for dynamic discovery */
typedef enum {
    LIB_OPENSSL = 0,
    LIB_GNUTLS,
    LIB_NSS,
    LIB_NSS_SSL,
    LIB_WOLFSSL,
    LIB_BORINGSSL,
    LIB_TYPE_COUNT
} lib_type_t;

/* Discovered library information */
typedef struct {
    char path[512];
    lib_type_t type;
    bool found;
    int process_count;  /* Number of processes using this path */
} discovered_lib_t;

/* Library paths for a single type (can have multiple paths) */
typedef struct {
    char paths[MAX_PATHS_PER_TYPE][512];
    int path_count;
    bool found;
} lib_paths_t;

/* Maximum BoringSSL binaries to track */
#define MAX_BORINGSSL_BINARIES 16

/* Discovered BoringSSL binary - EDR-style detection result
 * This struct caches everything needed to attach probes, avoiding repeated lookups.
 * The detection is purely behavioral: any binary with BoringSSL signature and
 * known build ID gets probed, regardless of its name or path.
 */
typedef struct {
    char path[512];              /* Full path to binary (from /proc/PID/exe) */
    char build_id[65];           /* ELF build ID hex string */
    uint64_t binary_size;        /* Binary size in bytes */
    int process_count;           /* Number of running processes using this binary */
    bool offsets_known;          /* Build ID found in offset database */
    /* Cached offsets from database lookup (avoids repeated lookups) */
    uint64_t ssl_read_offset;    /* File offset of SSL_read */
    uint64_t ssl_write_offset;   /* File offset of SSL_write */
    uint64_t ssl_read_impl_offset;   /* Internal ssl_read_impl (Golden Hook) */
    uint64_t ssl_write_impl_offset;  /* Internal DoPayloadWrite (Golden Hook) */
    uint64_t do_payload_read_offset; /* DoPayloadRead - best hook point */
    uint64_t socket_read_offset;     /* ReadIfReady - async I/O entry */
    uint64_t on_read_ready_offset;   /* OnReadReady - async I/O completion */
    const char *version_info;    /* Version string from database (or NULL) */
} discovered_boringssl_t;

/* Discovery result - holds multiple library paths per type */
typedef struct {
    /* Quick lookup by type (first path found) - backward compatible */
    discovered_lib_t libs[LIB_TYPE_COUNT];
    int count;

    /* Extended: all unique paths per type */
    lib_paths_t extended[LIB_TYPE_COUNT];

    /* BoringSSL binaries discovered from running processes (EDR-style) */
    discovered_boringssl_t boringssl[MAX_BORINGSSL_BINARIES];
    int boringssl_count;     /* Number of unique BoringSSL binaries found */

    /* Statistics */
    int processes_scanned;
    int processes_with_ssl;
    int total_unique_paths;
} lib_discovery_result_t;

/* Discover SSL libraries from running processes
 * Scans /proc/PID/maps to find actually loaded libraries.
 * @param pids       Array of PIDs to scan (NULL = scan all processes)
 * @param pid_count  Number of PIDs in array
 * @param result     Output: discovered library information
 * @return 0 on success (at least one library found), -1 on failure
 */
int bpf_loader_discover_libraries(const int *pids, int pid_count,
                                   lib_discovery_result_t *result);

/* Find library path with dynamic discovery fallback
 * Tries /proc/PID/maps first, falls back to static paths.
 * @param name       Library name (e.g., "libssl.so")
 * @param path       Output buffer for found path
 * @param size       Size of output buffer
 * @param pids       Optional: specific PIDs to scan
 * @param pid_count  Number of PIDs (0 to scan all processes)
 * @return 0 on success, -1 if not found
 */
int bpf_loader_find_library_dynamic(const char *name, char *path, size_t size,
                                     const int *pids, int pid_count);

/* Attach uprobe to a symbol - returns 0 on success, -1 on failure
 * Note: Failure to attach individual probes is often non-fatal */
int bpf_loader_attach_uprobe(bpf_loader_t *loader, const char *lib,
                             const char *sym, const char *prog_name,
                             bool is_ret, bool debug);

/* Attach uprobe by file offset (for stripped binaries)
 * Used for binaries like Chrome with statically linked BoringSSL
 * where symbols are not available. The offset should be the file offset
 * of the function prologue, not the virtual address.
 *
 * Parameters:
 *   loader     - BPF loader
 *   binary     - Path to binary (e.g., "/opt/google/chrome/chrome")
 *   offset     - File offset of function (from binary scanner)
 *   prog_name  - Name of BPF program to attach
 *   is_ret     - True for uretprobe, false for uprobe
 *   debug      - Enable debug output
 *
 * Returns 0 on success, -1 on failure */
int bpf_loader_attach_uprobe_offset(bpf_loader_t *loader, const char *binary,
                                     uint64_t offset, const char *prog_name,
                                     bool is_ret, bool debug);

/* Attach tracepoint - returns 0 on success, -1 on failure */
int bpf_loader_attach_tracepoint(bpf_loader_t *loader, const char *category,
                                  const char *name, const char *prog_name,
                                  bool debug);

/* Get BPF object (for ring buffer setup) */
struct bpf_object *bpf_loader_get_object(bpf_loader_t *loader);

/* Get number of attached probes */
int bpf_loader_get_link_count(bpf_loader_t *loader);

/* Get library type name for display */
const char *bpf_loader_lib_type_name(lib_type_t type);

/* Print discovered libraries (for verbose output) */
void bpf_loader_print_discovery(const lib_discovery_result_t *result);

/* Discover BoringSSL binaries from running processes (EDR-style detection)
 *
 * Scans /proc for binaries containing BoringSSL signatures, extracts build IDs,
 * and looks up offsets in the database. This is a behavioral detection approach:
 * any binary with BoringSSL signature and known build ID gets discovered,
 * regardless of its name, path, or the application it belongs to.
 *
 * Detection flow:
 *   1. Enumerate unique binary paths from /proc/PID/exe
 *   2. Filter by minimum size (performance optimization)
 *   3. Check for BoringSSL signature in binary
 *   4. Extract ELF build ID
 *   5. Look up offsets in embedded database
 *
 * @param result         Discovery result to populate (boringssl array)
 * @param min_size_mb    Minimum binary size in MB to scan (0 = no filter)
 * @param debug          Enable debug output
 * @return Number of BoringSSL binaries discovered with known offsets
 */
int bpf_loader_discover_boringssl(lib_discovery_result_t *result,
                                   uint64_t min_size_mb, bool debug);

/* Cleanup BPF resources */
void bpf_loader_cleanup(bpf_loader_t *loader);

// =============================================================================
// XDP Functions - Network Interface Discovery and Attachment
// =============================================================================
//
// Initialization Sequence:
//   1. bpf_loader_init() + bpf_loader_load()
//   2. bpf_loader_xdp_init()           - Find XDP program and maps
//   3. bpf_loader_xdp_set_event_callback() - Register event handler
//   4. bpf_loader_xdp_attach_all()     - Attach to interfaces
//   5. ring_buffer__poll() in event loop
//
// Cleanup Sequence (bpf_loader_cleanup handles automatically):
//   1. Stop event loop
//   2. bpf_loader_xdp_detach_all()     - Detach from all interfaces
//   3. ring_buffer__free()             - Free ring buffer
//   4. bpf_object__close()             - Close BPF object
//
// Kernel Requirements:
//   - Linux >= 5.8  (XDP socket lookup, bpf_skc_lookup_tcp)
//   - Linux >= 5.13 (BPF ring buffer)
//   - libbpf >= 0.5.0
// =============================================================================

/* Interface discovery filter flags */
#define XDP_DISCOVER_SKIP_LOOPBACK   (1 << 0)  /* Skip lo interface */
#define XDP_DISCOVER_SKIP_VIRTUAL    (1 << 1)  /* Skip veth, docker, etc. */
#define XDP_DISCOVER_ONLY_UP         (1 << 2)  /* Only interfaces with IFF_UP */
#define XDP_DISCOVER_ONLY_PHYSICAL   (1 << 3)  /* Only physical NICs */
#define XDP_DISCOVER_DEFAULT         (XDP_DISCOVER_SKIP_LOOPBACK | \
                                      XDP_DISCOVER_SKIP_VIRTUAL | \
                                      XDP_DISCOVER_ONLY_UP)

/* Extended interface info from discovery */
typedef struct {
    char name[64];           /* Interface name (supports long VRF names) */
    unsigned int ifindex;    /* Kernel interface index */
    unsigned int mtu;        /* Maximum transmission unit */
    unsigned int flags;      /* IFF_UP, IFF_LOOPBACK, etc. */
    bool is_physical;        /* True if physical NIC (not virtual) */
} xdp_iface_info_t;

/* XDP statistics with field documentation */
typedef struct {
    uint64_t packets_total;      /* All packets processed by XDP */
    uint64_t packets_tcp;        /* TCP packets (passed header parsing) */
    uint64_t flows_created;      /* New flow_state entries created */
    uint64_t flows_classified;   /* Successfully classified (TLS, HTTP, etc.) */
    uint64_t flows_ambiguous;    /* Sent to userspace for PCRE2-JIT */
    uint64_t flows_terminated;   /* FIN/RST seen (connection closed) */
    uint64_t gatekeeper_hits;    /* Fast-path: silenced sessions skipped */
    uint64_t cookie_failures;    /* Socket cookie lookup failed (IPv6, etc.) */
    uint64_t ringbuf_drops;      /* Events dropped due to ringbuf full */
    uint64_t sockops_active;     /* Sockops ACTIVE_ESTABLISHED events */
    uint64_t sockops_passive;    /* Sockops PASSIVE_ESTABLISHED events */
    uint64_t sockops_state;      /* Sockops STATE_CB events (cleanup) */
} xdp_stats_t;

/**
 * Check kernel support for XDP features.
 * Validates kernel version and required BPF features.
 *
 * @param err_out  Optional: error details if check fails
 * @return 0 if supported, -1 if not (check err_out for details)
 */
int bpf_loader_xdp_check_kernel_support(xdp_error_t *err_out);

/**
 * Initialize XDP subsystem within an already-loaded BPF object.
 * Finds the XDP program ("xdp_flow_tracker") and required maps:
 *   - flow_states, session_registry, xdp_events (required)
 *   - cookie_to_ssl, xdp_stats_map, xdp_payload_heap (optional)
 *
 * Must be called after bpf_loader_load().
 *
 * @param loader   BPF loader with loaded object
 * @param debug    Print debug messages
 * @param err_out  Optional: error details if init fails
 * @return 0 on success, -1 if XDP program/maps not found
 */
int bpf_loader_xdp_init(bpf_loader_t *loader, bool debug, xdp_error_t *err_out);

/**
 * Register callback for XDP ring buffer events.
 * Must be called before attach to receive events.
 *
 * Events received:
 *   - xdp_packet_event:  Discovery, termination (FIN/RST)
 *   - xdp_payload_event: Ambiguous traffic needing PCRE2-JIT
 *
 * @param loader   BPF loader with initialized XDP
 * @param callback Event handler function
 * @param ctx      User context passed to callback
 * @return 0 on success, -1 on failure
 */
int bpf_loader_xdp_set_event_callback(bpf_loader_t *loader,
                                       xdp_event_callback_t callback,
                                       void *ctx);

/**
 * Discover active network interfaces suitable for XDP attachment.
 *
 * @param ifaces   Output array (caller provides buffer)
 * @param max      Maximum interfaces to return
 * @param count    Output: actual number found
 * @param flags    Discovery filter flags (XDP_DISCOVER_*)
 * @param debug    Print debug messages
 * @return 0 on success, -1 on failure (e.g., /sys/class/net not readable)
 */
int bpf_loader_xdp_discover_interfaces(xdp_iface_info_t *ifaces, int max,
                                        int *count, int flags, bool debug);

/**
 * Attach XDP program to a specific network interface.
 * Tries preferred mode first, falls back to SKB mode.
 *
 * @param loader   BPF loader with initialized XDP
 * @param ifname   Interface name (e.g., "eth0")
 * @param mode     Preferred XDP mode (XDP_MODE_NATIVE recommended)
 * @param debug    Print debug messages
 * @param err_out  Optional: error details if attach fails
 * @return Actual mode attached (XDP_MODE_*) on success, -1 on failure
 */
int bpf_loader_xdp_attach(bpf_loader_t *loader, const char *ifname,
                          xdp_mode_t mode, bool debug, xdp_error_t *err_out);

/**
 * Attach XDP program to all suitable network interfaces.
 * Auto-discovers interfaces using XDP_DISCOVER_DEFAULT flags.
 *
 * @param loader   BPF loader with initialized XDP
 * @param debug    Print debug messages
 * @return Number of interfaces successfully attached (may be 0)
 */
int bpf_loader_xdp_attach_all(bpf_loader_t *loader, bool debug);

/**
 * Attach sock_ops program for socket cookie caching.
 * This program runs at TCP connection establishment and caches
 * socket cookies so XDP can correlate packets with connections.
 *
 * @param loader   BPF loader with loaded BPF object
 * @param debug    Print debug messages
 * @return 0 on success, -1 on failure
 */
int bpf_loader_sockops_attach(bpf_loader_t *loader, bool debug);

/**
 * Detach sock_ops program.
 * Called automatically by bpf_loader_cleanup().
 *
 * @param loader   BPF loader
 * @param debug    Print debug messages
 */
void bpf_loader_sockops_detach(bpf_loader_t *loader, bool debug);

/**
 * Detach XDP program from a specific interface.
 *
 * @param loader   BPF loader
 * @param ifname   Interface name to detach from
 * @param debug    Print debug messages
 * @return 0 on success, -1 on failure
 */
int bpf_loader_xdp_detach(bpf_loader_t *loader, const char *ifname, bool debug);

/**
 * Detach XDP from all attached interfaces.
 * Called automatically by bpf_loader_cleanup().
 * Safe to call multiple times (idempotent).
 *
 * @param loader   BPF loader
 * @param debug    Print debug messages
 */
void bpf_loader_xdp_detach_all(bpf_loader_t *loader, bool debug);

/**
 * Check if XDP is attached to a specific interface.
 *
 * @param loader   BPF loader
 * @param ifname   Interface name to check
 * @return true if attached, false otherwise
 */
bool bpf_loader_xdp_is_attached(bpf_loader_t *loader, const char *ifname);

/**
 * Get list of currently attached interfaces.
 *
 * @param loader   BPF loader
 * @param ifaces   Output array (caller provides buffer)
 * @param max      Maximum interfaces to return
 * @return Number of attached interfaces (may exceed max if truncated)
 */
int bpf_loader_xdp_get_attached_interfaces(bpf_loader_t *loader,
                                            xdp_interface_t *ifaces, int max);

/**
 * Get the XDP ring buffer for manual polling (advanced).
 * Prefer using set_event_callback() + ring_buffer__poll().
 *
 * @param loader   BPF loader with initialized XDP
 * @return Ring buffer pointer, or NULL if XDP not initialized
 */
struct ring_buffer *bpf_loader_xdp_get_ring_buffer(bpf_loader_t *loader);

/**
 * Poll XDP ring buffer for events.
 * Calls registered callback for each event.
 *
 * @param loader     BPF loader with initialized XDP
 * @param timeout_ms Timeout in milliseconds (-1 for blocking)
 * @return Number of events processed, 0 on timeout, <0 on error
 */
int bpf_loader_xdp_poll(bpf_loader_t *loader, int timeout_ms);

/**
 * Update session registry (the "Gatekeeper" silencing map).
 * Called by userspace dispatcher after PCRE2-JIT classification.
 *
 * Note: Due to concurrent access, updates may have 10-100µs latency
 * before XDP sees them. Not suitable for hard-real-time policies.
 *
 * @param loader       BPF loader with initialized XDP
 * @param cookie       Socket cookie (the "Golden Thread")
 * @param proto_type   Classified protocol (PROTO_HTTP1, PROTO_HTTP2, etc.)
 * @param silenced     Whether to silence future packet notifications
 * @return 0 on success, -1 on failure
 */
int bpf_loader_xdp_update_policy(bpf_loader_t *loader, uint64_t cookie,
                                  uint32_t proto_type, bool silenced);

/**
 * Read XDP statistics (packets processed, flows classified, etc.).
 * Sums per-CPU counters across all CPUs.
 *
 * @param loader   BPF loader with initialized XDP
 * @param stats    Output: aggregated statistics
 * @return 0 on success, -1 on failure
 */
int bpf_loader_xdp_read_stats(bpf_loader_t *loader, xdp_stats_t *stats);

/**
 * Get XDP mode name for display.
 *
 * @param mode   XDP attachment mode
 * @return "native", "skb", "offload", or "unknown"
 */
const char *bpf_loader_xdp_mode_name(xdp_mode_t mode);

/**
 * Check if XDP is enabled and has at least one attached interface.
 *
 * @param loader   BPF loader
 * @return true if XDP active, false otherwise
 */
bool bpf_loader_xdp_is_active(bpf_loader_t *loader);

/**
 * Get last XDP error (for functions that don't have err_out parameter).
 *
 * @param loader   BPF loader
 * @return Pointer to internal error struct (valid until next XDP call)
 */
const xdp_error_t *bpf_loader_xdp_get_last_error(bpf_loader_t *loader);

/**
 * Warm-up flow_cookie_map with existing TCP connections.
 * Parses /proc/net/tcp[6] and seeds the map with socket cookies for
 * connections that existed before sock_ops program was attached.
 * This enables XDP correlation with existing long-lived connections.
 *
 * Should be called after bpf_loader_xdp_init() and before traffic capture.
 *
 * @param loader   BPF loader with initialized XDP
 * @param debug    Print debug messages
 * @return Number of connections seeded (0 if map not available)
 */
int bpf_loader_xdp_warmup_cookies(bpf_loader_t *loader, bool debug);

/**
 * @brief Flow info from BPF map lookup
 *
 * Contains network metadata retrieved from BPF flow_states map.
 */
typedef struct bpf_flow_info {
    uint32_t saddr;           /**< Source IP (network byte order) */
    uint32_t daddr;           /**< Dest IP (network byte order) */
    uint16_t sport;           /**< Source port (network byte order) */
    uint16_t dport;           /**< Dest port (network byte order) */
    uint8_t  category;        /**< XDP protocol category */
    uint8_t  direction;       /**< Traffic direction */
    uint8_t  ip_version;      /**< IP version (4 or 6) */
    uint8_t  _pad;
} bpf_flow_info_t;

/**
 * @brief Lookup flow info from BPF map by socket cookie
 *
 * Iterates the flow_states BPF map to find an entry with matching cookie.
 * This is used as a fallback when the userspace flow_cache misses but
 * we know the connection exists in BPF.
 *
 * @param loader   BPF loader with XDP initialized
 * @param cookie   Socket cookie to search for
 * @param info_out Output structure for flow info
 * @return 0 on success, -1 if not found
 *
 * @note This is O(n) in the number of flows, use sparingly
 */
int bpf_loader_lookup_flow_by_cookie(bpf_loader_t *loader, uint64_t cookie,
                                     bpf_flow_info_t *info_out);

/**
 * @brief Get flow_states map file descriptor
 *
 * Returns the fd for the BPF flow_states map, used for userspace
 * warm-up of the flow_cache.
 *
 * @param loader   BPF loader with XDP initialized
 * @return File descriptor, or -1 if not available
 */
static inline int bpf_loader_get_flow_states_fd(bpf_loader_t *loader) {
    return (loader && loader->xdp.flow_states_fd >= 0) ?
           loader->xdp.flow_states_fd : -1;
}

#endif /* BPF_LOADER_H */
