/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * spliff.bpf.c - eBPF probes for SSL/TLS interception
 * Supports OpenSSL, GnuTLS, and NSS (via NSPR)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_BUF_SIZE 16384
#define TASK_COMM_LEN 16

// Event types
#define EVENT_SSL_READ     0
#define EVENT_SSL_WRITE    1
#define EVENT_HANDSHAKE    2
#define EVENT_PROCESS_EXIT 3
#define EVENT_ALPN         4
#define EVENT_NSS_SSL_FD   5  // NSS SSL_ImportFD tracking (verified TLS connection)

// Address families for socket filtering
#define AF_UNIX     1   // Unix domain socket (IPC - filter out)
#define AF_INET     2   // IPv4 (web traffic - keep)
#define AF_INET6    10  // IPv6 (web traffic - keep)

// Protocol types for session tracking
#define PROTO_UNKNOWN   0
#define PROTO_HTTP1     1   // HTTP/1.x - route to llhttp
#define PROTO_HTTP2     2   // HTTP/2   - route to nghttp2

// Data structure for SSL events
struct ssl_data_event {
    __u64 timestamp_ns;
    __u64 delta_ns;       // Latency (for handshake or request-response)
    __u64 ssl_ctx;        // SSL context pointer for connection tracking
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 len;            // Actual data length
    __u32 buf_filled;     // How much of buf[] is filled
    __u32 event_type;     // EVENT_SSL_READ, EVENT_SSL_WRITE, EVENT_HANDSHAKE
    char comm[TASK_COMM_LEN];
    __u8 buf[MAX_BUF_SIZE];
};

// Arguments saved between entry and exit probes
struct ssl_args {
    __u64 ssl_ctx;        // SSL context pointer
    __u64 buf_ptr;        // Buffer pointer
    __u32 len;            // Requested length
};

// Handshake state saved between entry and exit probes
struct handshake_args {
    __u64 ssl_ctx;        // SSL context pointer
    __u64 start_ns;       // Start timestamp
};

// ALPN query state saved between entry and exit probes
struct alpn_query_args {
    __u64 ssl_ctx;        // SSL context pointer
    __u64 data_ptr;       // Pointer to output data pointer (OpenSSL) or buffer (NSS/GnuTLS)
    __u64 len_ptr;        // Pointer to length output
};

// Session info for tracked web connections
// Only sessions that pass socket family check (AF_INET/AF_INET6) and have valid ALPN
struct session_info {
    __u32 protocol;       // PROTO_HTTP1, PROTO_HTTP2
    __u16 family;         // AF_INET, AF_INET6
    __u16 flags;          // Reserved for future use
    __s32 fd;             // OS file descriptor (for socket family lookup)
};

// SSL_set_fd arguments (for OpenSSL fd tracking)
struct ssl_fd_args {
    __u64 ssl_ctx;        // SSL* pointer
    __s32 fd;             // OS file descriptor
};


// =============================================================================
// BPF Maps
// =============================================================================

// Per-CPU array for event storage (avoids stack size limits)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ssl_data_event);
} ssl_data_heap SEC(".maps");

// Hash map to store arguments between uprobe entry and uretprobe
// Key: tid (thread ID) - SSL operations are per-thread
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);  // tid
    __type(value, struct ssl_args);
} ssl_args_map SEC(".maps");

// Hash map to store SSL read/write start times
// Key: tid (thread ID)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);  // tid
    __type(value, __u64); // start timestamp
} start_ns SEC(".maps");

// Separate map for handshake state (to avoid race with read/write)
// Key: tid (thread ID)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // tid
    __type(value, struct handshake_args);
} handshake_args_map SEC(".maps");

// Separate map for ALPN query state
// Key: tid (thread ID)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // tid
    __type(value, struct alpn_query_args);
} alpn_query_map SEC(".maps");

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ssl_events SEC(".maps");

// Map to track PIDs that have had SSL activity (for process exit filtering)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);    // PID
    __type(value, __u8);   // dummy value (just need existence)
} tracked_pids SEC(".maps");

// =============================================================================
// Session Tracking Maps (for IPC filtering and protocol routing)
// =============================================================================

// Map SSL* (or PRFileDesc*, gnutls_session_t) → session_info
// Populated on successful handshake + ALPN negotiation
// Key: ssl_ctx pointer
// Value: session_info with protocol type and socket family
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);    // SSL* / PRFileDesc* / gnutls_session_t pointer
    __type(value, struct session_info);
} tracked_sessions SEC(".maps");

// Map SSL* → OS file descriptor (for OpenSSL)
// Populated by SSL_set_fd hook
// Key: SSL* pointer
// Value: OS fd number
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);    // SSL* pointer
    __type(value, __s32);  // OS fd
} ssl_to_fd SEC(".maps");

// Map tid → ssl_fd_args (for SSL_set_fd entry/exit probe)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // tid
    __type(value, struct ssl_fd_args);
} ssl_fd_args_map SEC(".maps");

// Map to track SSL-imported file descriptors (NSS layer filtering)
// Populated by SSL_ImportFD hook - marks verified SSL connections
// Key: PRFileDesc pointer (returned by SSL_ImportFD)
// Value: 1 (just marks existence)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);    // PRFileDesc pointer
    __type(value, __u8);
} nss_ssl_fds SEC(".maps");


// =============================================================================
// Helper Functions
// =============================================================================

static __always_inline __u32 get_tid(void) {
    return (__u32)bpf_get_current_pid_tgid();
}

static __always_inline __u32 get_pid(void) {
    return bpf_get_current_pid_tgid() >> 32;
}

static __always_inline __u32 get_uid(void) {
    return (__u32)bpf_get_current_uid_gid();
}

static __always_inline void fill_event_metadata(struct ssl_data_event *event) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->uid = (__u32)uid_gid;
    event->delta_ns = 0;

    // Zero out comm field first to ensure clean data
    #pragma unroll
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        event->comm[i] = 0;
    }
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
}

// Helper to mark a PID as having SSL activity
static __always_inline void track_pid(__u32 pid) {
    __u8 val = 1;
    bpf_map_update_elem(&tracked_pids, &pid, &val, BPF_ANY);
}

// =============================================================================
// Socket Family Lookup (CO-RE)
// Walks: task_struct → files_struct → fdtable → file → socket → sock → skc_family
// Returns AF_INET (2), AF_INET6 (10), AF_UNIX (1), or 0 on error
// =============================================================================

static __always_inline __u16 get_socket_family_from_fd(__s32 fd) {
    if (fd < 0) return 0;

    // Get current task
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    // task → files_struct
    struct files_struct *files = NULL;
    if (bpf_core_read(&files, sizeof(files), &task->files) || !files)
        return 0;

    // files_struct → fdtable
    struct fdtable *fdt = NULL;
    if (bpf_core_read(&fdt, sizeof(fdt), &files->fdt) || !fdt)
        return 0;

    // fdtable → fd array
    struct file **fd_array = NULL;
    if (bpf_core_read(&fd_array, sizeof(fd_array), &fdt->fd) || !fd_array)
        return 0;

    // Bounds check for fd (BPF verifier requirement)
    if (fd >= 8192) return 0;  // Reasonable upper bound

    // fd_array[fd] → file
    struct file *file = NULL;
    if (bpf_core_read(&file, sizeof(file), &fd_array[fd]) || !file)
        return 0;

    // file → private_data (which is struct socket* for sockets)
    void *private_data = NULL;
    if (bpf_core_read(&private_data, sizeof(private_data), &file->private_data) || !private_data)
        return 0;

    // Cast to socket and get sk
    struct socket *sock = (struct socket *)private_data;
    struct sock *sk = NULL;
    if (bpf_core_read(&sk, sizeof(sk), &sock->sk) || !sk)
        return 0;

    // sock → __sk_common → skc_family
    __u16 family = 0;
    bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);

    return family;
}

// Check if a session is tracked and get its info
// Returns: pointer to session_info if tracked, NULL otherwise
static __always_inline struct session_info *get_session_info(__u64 ssl_ctx) {
    return bpf_map_lookup_elem(&tracked_sessions, &ssl_ctx);
}

// Check if SSL* has a known fd mapping and return socket family
// Returns: AF_INET, AF_INET6, AF_UNIX, or 0 if unknown
static __always_inline __u16 get_ssl_socket_family(__u64 ssl_ctx) {
    // First check if we have a tracked session with known family
    struct session_info *info = get_session_info(ssl_ctx);
    if (info && info->family != 0) {
        return info->family;
    }

    // Try to look up fd from ssl_to_fd map (populated by SSL_set_fd)
    __s32 *fd_ptr = bpf_map_lookup_elem(&ssl_to_fd, &ssl_ctx);
    if (!fd_ptr) return 0;

    return get_socket_family_from_fd(*fd_ptr);
}

// Check if socket family indicates web traffic (not IPC)
static __always_inline bool is_web_socket_family(__u16 family) {
    return family == AF_INET || family == AF_INET6;
}

// Check if a PRFileDesc is a verified SSL connection (NSS layer filtering)
static __always_inline bool is_nss_ssl_fd(__u64 fd) {
    return bpf_map_lookup_elem(&nss_ssl_fds, &fd) != NULL;
}

// Parse ALPN string and return protocol type
// "h2" → PROTO_HTTP2, "http/1.1" or "http/1.0" → PROTO_HTTP1
static __always_inline __u32 parse_alpn_protocol(const __u8 *alpn, __u32 len) {
    if (len == 2 && alpn[0] == 'h' && alpn[1] == '2') {
        return PROTO_HTTP2;
    }
    if (len >= 8 && alpn[0] == 'h' && alpn[1] == 't' && alpn[2] == 't' && alpn[3] == 'p' &&
        alpn[4] == '/' && alpn[5] == '1' && alpn[6] == '.') {
        return PROTO_HTTP1;  // http/1.0 or http/1.1
    }
    return PROTO_UNKNOWN;
}

// Update session with protocol type from ALPN negotiation
// Also validates/updates socket family if we have fd mapping
static __always_inline void update_session_protocol(__u64 ssl_ctx, __u32 protocol) {
    struct session_info *info = bpf_map_lookup_elem(&tracked_sessions, &ssl_ctx);
    if (info) {
        // Update protocol in existing session
        info->protocol = protocol;

        // If we don't have family yet, try to get it from fd mapping
        if (info->family == 0) {
            __s32 *fd_ptr = bpf_map_lookup_elem(&ssl_to_fd, &ssl_ctx);
            if (fd_ptr) {
                __u16 family = get_socket_family_from_fd(*fd_ptr);
                info->family = family;
                info->fd = *fd_ptr;
            }
        }
    } else {
        // Create new session entry
        __s32 fd = -1;
        __u16 family = 0;

        // Try to get fd and family from ssl_to_fd map
        __s32 *fd_ptr = bpf_map_lookup_elem(&ssl_to_fd, &ssl_ctx);
        if (fd_ptr) {
            fd = *fd_ptr;
            family = get_socket_family_from_fd(fd);
        }

        // Only track if we have valid ALPN (h1/h2)
        if (protocol != PROTO_UNKNOWN) {
            struct session_info new_info = {
                .protocol = protocol,
                .family = family,
                .flags = 0,
                .fd = fd,
            };
            bpf_map_update_elem(&tracked_sessions, &ssl_ctx, &new_info, BPF_ANY);
        }
    }
}


// =============================================================================
// SSL Read/Write Entry Probe
// Called for: SSL_read, SSL_write, gnutls_record_recv, gnutls_record_send,
//             PR_Read, PR_Write, PR_Recv, PR_Send
// =============================================================================

SEC("uprobe/ssl_rw_enter")
int BPF_UPROBE(probe_ssl_rw_enter, void *ssl_ctx, void *buf, int num) {
    __u32 tid = get_tid();

    // Save SSL context, buffer address and length for the exit probe
    struct ssl_args args = {
        .ssl_ctx = (__u64)ssl_ctx,
        .buf_ptr = (__u64)buf,
        .len = (__u32)num,
    };

    bpf_map_update_elem(&ssl_args_map, &tid, &args, BPF_ANY);

    // Save start timestamp for latency calculation
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);

    return 0;
}

// =============================================================================
// SSL Read Exit Probe
// =============================================================================

SEC("uretprobe/ssl_read_exit")
int BPF_URETPROBE(probe_ssl_read_exit) {
    __u32 tid = get_tid();
    __u32 zero = 0;
    
    // Lookup saved arguments
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_args_map, &tid);
    if (!args) {
        return 0;
    }
    
    // Get return value (bytes read)
    int ret = PT_REGS_RC((struct pt_regs *)ctx);
    if (ret <= 0) {
        // No data or error
        bpf_map_delete_elem(&ssl_args_map, &tid);
        bpf_map_delete_elem(&start_ns, &tid);
        return 0;
    }
    
    // Get event buffer
    struct ssl_data_event *event = bpf_map_lookup_elem(&ssl_data_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&ssl_args_map, &tid);
        bpf_map_delete_elem(&start_ns, &tid);
        return 0;
    }
    
    // Fill metadata
    fill_event_metadata(event);
    event->event_type = EVENT_SSL_READ;
    event->len = (__u32)ret;
    event->ssl_ctx = args->ssl_ctx;

    // Calculate latency
    __u64 *tsp = bpf_map_lookup_elem(&start_ns, &tid);
    if (tsp) {
        event->delta_ns = event->timestamp_ns - *tsp;
    }
    
    // Copy data from userspace buffer
    __u32 buf_copy_size = (__u32)ret;
    if (buf_copy_size > MAX_BUF_SIZE) {
        buf_copy_size = MAX_BUF_SIZE;
    }
    
    event->buf_filled = 0;
    if (args->buf_ptr != 0) {
        int err = bpf_probe_read_user(&event->buf, buf_copy_size & (MAX_BUF_SIZE - 1), (void *)args->buf_ptr);
        if (err == 0) {
            event->buf_filled = buf_copy_size;
        }
    }
    
    // Track this PID for process exit cleanup
    track_pid(event->pid);

    // Submit event - size must be bounded for verifier
    __u64 submit_size = sizeof(struct ssl_data_event) - MAX_BUF_SIZE + event->buf_filled;
    if (submit_size > sizeof(struct ssl_data_event)) {
        submit_size = sizeof(struct ssl_data_event);
    }
    bpf_ringbuf_output(&ssl_events, event, submit_size & 0xFFFF, 0);

    // Cleanup
    bpf_map_delete_elem(&ssl_args_map, &tid);
    bpf_map_delete_elem(&start_ns, &tid);

    return 0;
}

// =============================================================================
// SSL Write Exit Probe
// =============================================================================

SEC("uretprobe/ssl_write_exit")
int BPF_URETPROBE(probe_ssl_write_exit) {
    __u32 tid = get_tid();
    __u32 zero = 0;
    
    // Lookup saved arguments
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_args_map, &tid);
    if (!args) {
        return 0;
    }
    
    // Get return value (bytes written)
    int ret = PT_REGS_RC((struct pt_regs *)ctx);
    if (ret <= 0) {
        // No data or error
        bpf_map_delete_elem(&ssl_args_map, &tid);
        bpf_map_delete_elem(&start_ns, &tid);
        return 0;
    }
    
    // Get event buffer
    struct ssl_data_event *event = bpf_map_lookup_elem(&ssl_data_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&ssl_args_map, &tid);
        bpf_map_delete_elem(&start_ns, &tid);
        return 0;
    }
    
    // Fill metadata
    fill_event_metadata(event);
    event->event_type = EVENT_SSL_WRITE;
    event->len = (__u32)ret;
    event->ssl_ctx = args->ssl_ctx;

    // Calculate latency
    __u64 *tsp = bpf_map_lookup_elem(&start_ns, &tid);
    if (tsp) {
        event->delta_ns = event->timestamp_ns - *tsp;
    }
    
    // Copy data from userspace buffer
    __u32 buf_copy_size = (__u32)ret;
    if (buf_copy_size > MAX_BUF_SIZE) {
        buf_copy_size = MAX_BUF_SIZE;
    }
    
    event->buf_filled = 0;
    if (args->buf_ptr != 0) {
        int err = bpf_probe_read_user(&event->buf, buf_copy_size & (MAX_BUF_SIZE - 1), (void *)args->buf_ptr);
        if (err == 0) {
            event->buf_filled = buf_copy_size;
        }
    }
    
    // Track this PID for process exit cleanup
    track_pid(event->pid);

    // Submit event - size must be bounded for verifier
    __u64 submit_size = sizeof(struct ssl_data_event) - MAX_BUF_SIZE + event->buf_filled;
    if (submit_size > sizeof(struct ssl_data_event)) {
        submit_size = sizeof(struct ssl_data_event);
    }
    bpf_ringbuf_output(&ssl_events, event, submit_size & 0xFFFF, 0);

    // Cleanup
    bpf_map_delete_elem(&ssl_args_map, &tid);
    bpf_map_delete_elem(&start_ns, &tid);

    return 0;
}

// =============================================================================
// SSL Handshake Probes
// For: SSL_do_handshake, SSL_connect, SSL_accept, gnutls_handshake
// =============================================================================

SEC("uprobe/ssl_handshake_enter")
int BPF_UPROBE(probe_ssl_handshake_enter, void *ssl_ctx) {
    __u32 tid = get_tid();

    // Save SSL context and start timestamp
    struct handshake_args args = {
        .ssl_ctx = (__u64)ssl_ctx,
        .start_ns = bpf_ktime_get_ns(),
    };

    // Use separate map to avoid race with SSL_read/SSL_write during handshake
    bpf_map_update_elem(&handshake_args_map, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/ssl_handshake_exit")
int BPF_URETPROBE(probe_ssl_handshake_exit) {
    __u32 tid = get_tid();
    __u32 zero = 0;

    // Lookup handshake state from handshake-specific map
    struct handshake_args *args = bpf_map_lookup_elem(&handshake_args_map, &tid);
    if (!args) {
        return 0;
    }

    // Get return value
    int ret = PT_REGS_RC((struct pt_regs *)ctx);

    // Get event buffer
    struct ssl_data_event *event = bpf_map_lookup_elem(&ssl_data_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&handshake_args_map, &tid);
        return 0;
    }

    // Fill metadata
    fill_event_metadata(event);
    event->event_type = EVENT_HANDSHAKE;
    event->len = (__u32)ret;  // Store return value (1=success, 0/-1=fail)
    event->buf_filled = 0;
    event->ssl_ctx = args->ssl_ctx;
    event->delta_ns = event->timestamp_ns - args->start_ns;

    // Track this PID for process exit cleanup
    track_pid(event->pid);

    // Submit event (small, no buffer data) - use fixed size for verifier
    bpf_ringbuf_output(&ssl_events, event, sizeof(struct ssl_data_event) - MAX_BUF_SIZE, 0);

    // Cleanup
    bpf_map_delete_elem(&handshake_args_map, &tid);

    return 0;
}

// =============================================================================
// SSL_set_fd Hook (OpenSSL)
// int SSL_set_fd(SSL *ssl, int fd)
// Maps SSL* → OS fd for socket family lookup
// =============================================================================

SEC("uprobe/ssl_set_fd_enter")
int BPF_UPROBE(probe_ssl_set_fd_enter, void *ssl, int fd) {
    __u32 tid = get_tid();

    // Save args for exit probe
    struct ssl_fd_args args = {
        .ssl_ctx = (__u64)ssl,
        .fd = fd,
    };

    bpf_map_update_elem(&ssl_fd_args_map, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/ssl_set_fd_exit")
int BPF_URETPROBE(probe_ssl_set_fd_exit) {
    __u32 tid = get_tid();

    struct ssl_fd_args *args = bpf_map_lookup_elem(&ssl_fd_args_map, &tid);
    if (!args) {
        return 0;
    }

    // Check return value (1 = success)
    int ret = PT_REGS_RC((struct pt_regs *)ctx);
    if (ret != 1) {
        bpf_map_delete_elem(&ssl_fd_args_map, &tid);
        return 0;
    }

    // Store SSL* → fd mapping
    __u64 ssl_ctx = args->ssl_ctx;
    __s32 fd = args->fd;
    bpf_map_update_elem(&ssl_to_fd, &ssl_ctx, &fd, BPF_ANY);

    // Also update session_info if it exists, with socket family
    struct session_info *info = bpf_map_lookup_elem(&tracked_sessions, &ssl_ctx);
    if (info) {
        __u16 family = get_socket_family_from_fd(fd);
        if (family != 0) {
            // Update in-place via map lookup (we have the pointer)
            info->family = family;
            info->fd = fd;
        }
    } else {
        // Create new session entry with just fd/family (protocol TBD via ALPN)
        __u16 family = get_socket_family_from_fd(fd);
        if (is_web_socket_family(family)) {
            struct session_info new_info = {
                .protocol = PROTO_UNKNOWN,
                .family = family,
                .flags = 0,
                .fd = fd,
            };
            bpf_map_update_elem(&tracked_sessions, &ssl_ctx, &new_info, BPF_ANY);
        }
    }

    bpf_map_delete_elem(&ssl_fd_args_map, &tid);
    return 0;
}

// =============================================================================
// GnuTLS Probes
// For: gnutls_record_send, gnutls_record_recv
// =============================================================================

SEC("uprobe/gnutls_send_enter")
int BPF_UPROBE(probe_gnutls_send_enter, void *session, void *buf, size_t num) {
    __u32 tid = get_tid();

    // Save session context, buffer address and length for the exit probe
    struct ssl_args args = {
        .ssl_ctx = (__u64)session,
        .buf_ptr = (__u64)buf,
        .len = (__u32)num,
    };

    bpf_map_update_elem(&ssl_args_map, &tid, &args, BPF_ANY);

    // Save start timestamp for latency calculation
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);

    return 0;
}

SEC("uretprobe/gnutls_send_exit")
int BPF_URETPROBE(probe_gnutls_send_exit) {
    __u32 tid = get_tid();
    __u32 zero = 0;

    // Lookup saved arguments
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_args_map, &tid);
    if (!args) {
        return 0;
    }

    // Get return value (bytes sent)
    ssize_t ret = (ssize_t)PT_REGS_RC((struct pt_regs *)ctx);
    if (ret <= 0) {
        bpf_map_delete_elem(&ssl_args_map, &tid);
        bpf_map_delete_elem(&start_ns, &tid);
        return 0;
    }

    // Get event buffer
    struct ssl_data_event *event = bpf_map_lookup_elem(&ssl_data_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&ssl_args_map, &tid);
        bpf_map_delete_elem(&start_ns, &tid);
        return 0;
    }

    // Fill metadata
    fill_event_metadata(event);
    event->event_type = EVENT_SSL_WRITE;
    event->len = (__u32)ret;
    event->ssl_ctx = args->ssl_ctx;

    // Calculate latency
    __u64 *tsp = bpf_map_lookup_elem(&start_ns, &tid);
    if (tsp) {
        event->delta_ns = event->timestamp_ns - *tsp;
    }

    // Copy data from userspace buffer
    __u32 buf_copy_size = (__u32)ret;
    if (buf_copy_size > MAX_BUF_SIZE) {
        buf_copy_size = MAX_BUF_SIZE;
    }

    event->buf_filled = 0;
    if (args->buf_ptr != 0) {
        int err = bpf_probe_read_user(&event->buf, buf_copy_size & (MAX_BUF_SIZE - 1), (void *)args->buf_ptr);
        if (err == 0) {
            event->buf_filled = buf_copy_size;
        }
    }

    // Track this PID for process exit cleanup
    track_pid(event->pid);

    // Submit event
    __u64 submit_size = sizeof(struct ssl_data_event) - MAX_BUF_SIZE + event->buf_filled;
    if (submit_size > sizeof(struct ssl_data_event)) {
        submit_size = sizeof(struct ssl_data_event);
    }
    bpf_ringbuf_output(&ssl_events, event, submit_size & 0xFFFF, 0);

    // Cleanup
    bpf_map_delete_elem(&ssl_args_map, &tid);
    bpf_map_delete_elem(&start_ns, &tid);

    return 0;
}

SEC("uprobe/gnutls_recv_enter")
int BPF_UPROBE(probe_gnutls_recv_enter, void *session, void *buf, size_t num) {
    __u32 tid = get_tid();

    // Save session context, buffer address and length for the exit probe
    struct ssl_args args = {
        .ssl_ctx = (__u64)session,
        .buf_ptr = (__u64)buf,
        .len = (__u32)num,
    };

    bpf_map_update_elem(&ssl_args_map, &tid, &args, BPF_ANY);

    // Save start timestamp for latency calculation
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);

    return 0;
}

SEC("uretprobe/gnutls_recv_exit")
int BPF_URETPROBE(probe_gnutls_recv_exit) {
    __u32 tid = get_tid();
    __u32 zero = 0;

    // Lookup saved arguments
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_args_map, &tid);
    if (!args) {
        return 0;
    }

    // Get return value (bytes received)
    ssize_t ret = (ssize_t)PT_REGS_RC((struct pt_regs *)ctx);
    if (ret <= 0) {
        bpf_map_delete_elem(&ssl_args_map, &tid);
        bpf_map_delete_elem(&start_ns, &tid);
        return 0;
    }

    // Get event buffer
    struct ssl_data_event *event = bpf_map_lookup_elem(&ssl_data_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&ssl_args_map, &tid);
        bpf_map_delete_elem(&start_ns, &tid);
        return 0;
    }

    // Fill metadata
    fill_event_metadata(event);
    event->event_type = EVENT_SSL_READ;
    event->len = (__u32)ret;
    event->ssl_ctx = args->ssl_ctx;

    // Calculate latency
    __u64 *tsp = bpf_map_lookup_elem(&start_ns, &tid);
    if (tsp) {
        event->delta_ns = event->timestamp_ns - *tsp;
    }

    // Copy data from userspace buffer
    __u32 buf_copy_size = (__u32)ret;
    if (buf_copy_size > MAX_BUF_SIZE) {
        buf_copy_size = MAX_BUF_SIZE;
    }

    event->buf_filled = 0;
    if (args->buf_ptr != 0) {
        int err = bpf_probe_read_user(&event->buf, buf_copy_size & (MAX_BUF_SIZE - 1), (void *)args->buf_ptr);
        if (err == 0) {
            event->buf_filled = buf_copy_size;
        }
    }

    // Track this PID for process exit cleanup
    track_pid(event->pid);

    // Submit event
    __u64 submit_size = sizeof(struct ssl_data_event) - MAX_BUF_SIZE + event->buf_filled;
    if (submit_size > sizeof(struct ssl_data_event)) {
        submit_size = sizeof(struct ssl_data_event);
    }
    bpf_ringbuf_output(&ssl_events, event, submit_size & 0xFFFF, 0);

    // Cleanup
    bpf_map_delete_elem(&ssl_args_map, &tid);
    bpf_map_delete_elem(&start_ns, &tid);

    return 0;
}

// =============================================================================
// NSS Probes
// For: PR_Write, PR_Read
// =============================================================================

SEC("uprobe/nss_write_enter")
int BPF_UPROBE(probe_nss_write_enter, void *fd, void *buf, int num) {
    __u32 tid = get_tid();

    // Save file descriptor, buffer address and length for the exit probe
    struct ssl_args args = {
        .ssl_ctx = (__u64)fd,
        .buf_ptr = (__u64)buf,
        .len = (__u32)num,
    };

    bpf_map_update_elem(&ssl_args_map, &tid, &args, BPF_ANY);

    // Save start timestamp for latency calculation
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);

    return 0;
}

SEC("uretprobe/nss_write_exit")
int BPF_URETPROBE(probe_nss_write_exit) {
    __u32 tid = get_tid();
    __u32 zero = 0;

    // Lookup saved arguments
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_args_map, &tid);
    if (!args) {
        return 0;
    }

    // NSS Layer Filtering: Only process verified SSL connections
    // PRFileDesc passed through SSL_ImportFD is tracked in nss_ssl_fds map
    // This filters out IPC, file I/O, and non-SSL NSPR operations
    if (!is_nss_ssl_fd(args->ssl_ctx)) {
        // Not a verified SSL connection - skip
        // Still cleanup to avoid map leaks
        bpf_map_delete_elem(&ssl_args_map, &tid);
        bpf_map_delete_elem(&start_ns, &tid);
        return 0;
    }

    // Get return value (bytes written)
    int ret = (int)PT_REGS_RC((struct pt_regs *)ctx);
    if (ret <= 0) {
        bpf_map_delete_elem(&ssl_args_map, &tid);
        bpf_map_delete_elem(&start_ns, &tid);
        return 0;
    }

    // Get event buffer
    struct ssl_data_event *event = bpf_map_lookup_elem(&ssl_data_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&ssl_args_map, &tid);
        bpf_map_delete_elem(&start_ns, &tid);
        return 0;
    }

    // Fill metadata
    fill_event_metadata(event);
    event->event_type = EVENT_SSL_WRITE;
    event->len = (__u32)ret;
    event->ssl_ctx = args->ssl_ctx;

    // Calculate latency
    __u64 *tsp = bpf_map_lookup_elem(&start_ns, &tid);
    if (tsp) {
        event->delta_ns = event->timestamp_ns - *tsp;
    }

    // Copy data from userspace buffer
    __u32 buf_copy_size = (__u32)ret;
    if (buf_copy_size > MAX_BUF_SIZE) {
        buf_copy_size = MAX_BUF_SIZE;
    }

    event->buf_filled = 0;
    if (args->buf_ptr != 0) {
        int err = bpf_probe_read_user(&event->buf, buf_copy_size & (MAX_BUF_SIZE - 1), (void *)args->buf_ptr);
        if (err == 0) {
            event->buf_filled = buf_copy_size;
        }
    }

    // Track this PID for process exit cleanup
    track_pid(event->pid);

    // Submit event
    __u64 submit_size = sizeof(struct ssl_data_event) - MAX_BUF_SIZE + event->buf_filled;
    if (submit_size > sizeof(struct ssl_data_event)) {
        submit_size = sizeof(struct ssl_data_event);
    }
    bpf_ringbuf_output(&ssl_events, event, submit_size & 0xFFFF, 0);

    // Cleanup
    bpf_map_delete_elem(&ssl_args_map, &tid);
    bpf_map_delete_elem(&start_ns, &tid);

    return 0;
}

SEC("uprobe/nss_read_enter")
int BPF_UPROBE(probe_nss_read_enter, void *fd, void *buf, int num) {
    __u32 tid = get_tid();

    // Save file descriptor, buffer address and length for the exit probe
    struct ssl_args args = {
        .ssl_ctx = (__u64)fd,
        .buf_ptr = (__u64)buf,
        .len = (__u32)num,
    };

    bpf_map_update_elem(&ssl_args_map, &tid, &args, BPF_ANY);

    // Save start timestamp for latency calculation
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);

    return 0;
}

SEC("uretprobe/nss_read_exit")
int BPF_URETPROBE(probe_nss_read_exit) {
    __u32 tid = get_tid();
    __u32 zero = 0;

    // Lookup saved arguments
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_args_map, &tid);
    if (!args) {
        return 0;
    }

    // NSS Layer Filtering: Only process verified SSL connections
    // This filters out non-SSL PRFileDesc layers (IPC, file I/O, etc.)
    if (!is_nss_ssl_fd(args->ssl_ctx)) {
        bpf_map_delete_elem(&ssl_args_map, &tid);
        bpf_map_delete_elem(&start_ns, &tid);
        return 0;
    }

    // Get return value (bytes read)
    int ret = (int)PT_REGS_RC((struct pt_regs *)ctx);
    if (ret <= 0) {
        bpf_map_delete_elem(&ssl_args_map, &tid);
        bpf_map_delete_elem(&start_ns, &tid);
        return 0;
    }

    // Get event buffer
    struct ssl_data_event *event = bpf_map_lookup_elem(&ssl_data_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&ssl_args_map, &tid);
        bpf_map_delete_elem(&start_ns, &tid);
        return 0;
    }

    // Fill metadata
    fill_event_metadata(event);
    event->event_type = EVENT_SSL_READ;
    event->len = (__u32)ret;
    event->ssl_ctx = args->ssl_ctx;

    // Calculate latency
    __u64 *tsp = bpf_map_lookup_elem(&start_ns, &tid);
    if (tsp) {
        event->delta_ns = event->timestamp_ns - *tsp;
    }

    // Copy data from userspace buffer
    __u32 buf_copy_size = (__u32)ret;
    if (buf_copy_size > MAX_BUF_SIZE) {
        buf_copy_size = MAX_BUF_SIZE;
    }

    event->buf_filled = 0;
    if (args->buf_ptr != 0) {
        int err = bpf_probe_read_user(&event->buf, buf_copy_size & (MAX_BUF_SIZE - 1), (void *)args->buf_ptr);
        if (err == 0) {
            event->buf_filled = buf_copy_size;
        }
    }

    // Track this PID for process exit cleanup
    track_pid(event->pid);

    // Submit event
    __u64 submit_size = sizeof(struct ssl_data_event) - MAX_BUF_SIZE + event->buf_filled;
    if (submit_size > sizeof(struct ssl_data_event)) {
        submit_size = sizeof(struct ssl_data_event);
    }
    bpf_ringbuf_output(&ssl_events, event, submit_size & 0xFFFF, 0);

    // Cleanup
    bpf_map_delete_elem(&ssl_args_map, &tid);
    bpf_map_delete_elem(&start_ns, &tid);

    return 0;
}

// =============================================================================
// ALPN Protocol Detection Probes
// For: SSL_get0_alpn_selected (OpenSSL), SSL_GetNextProto (NSS),
//      gnutls_alpn_get_selected_protocol (GnuTLS)
// =============================================================================

// OpenSSL: void SSL_get0_alpn_selected(const SSL *ssl,
//                                       const unsigned char **data,
//                                       unsigned int *len)
SEC("uprobe/openssl_alpn_enter")
int BPF_UPROBE(probe_openssl_alpn_enter, void *ssl, void **data_out, unsigned int *len_out) {
    __u32 tid = get_tid();

    struct alpn_query_args args = {
        .ssl_ctx = (__u64)ssl,
        .data_ptr = (__u64)data_out,   // Pointer to output data pointer
        .len_ptr = (__u64)len_out,     // Pointer to output length
    };

    bpf_map_update_elem(&alpn_query_map, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/openssl_alpn_exit")
int BPF_URETPROBE(probe_openssl_alpn_exit) {
    __u32 tid = get_tid();
    __u32 zero = 0;

    struct alpn_query_args *args = bpf_map_lookup_elem(&alpn_query_map, &tid);
    if (!args) {
        return 0;
    }

    // Read the length from *len_out
    __u32 alpn_len = 0;
    if (args->len_ptr != 0) {
        bpf_probe_read_user(&alpn_len, sizeof(alpn_len), (void *)args->len_ptr);
    }

    // No ALPN selected or invalid length
    if (alpn_len == 0 || alpn_len > 255) {
        bpf_map_delete_elem(&alpn_query_map, &tid);
        return 0;
    }

    // Read the data pointer from *data_out
    __u64 data_ptr = 0;
    if (args->data_ptr != 0) {
        bpf_probe_read_user(&data_ptr, sizeof(data_ptr), (void *)args->data_ptr);
    }

    if (data_ptr == 0) {
        bpf_map_delete_elem(&alpn_query_map, &tid);
        return 0;
    }

    // Get event buffer
    struct ssl_data_event *event = bpf_map_lookup_elem(&ssl_data_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&alpn_query_map, &tid);
        return 0;
    }

    // Fill metadata
    fill_event_metadata(event);
    event->event_type = EVENT_ALPN;
    event->len = alpn_len;
    event->ssl_ctx = args->ssl_ctx;
    event->delta_ns = 0;

    // Read ALPN protocol string
    event->buf_filled = 0;
    int err = bpf_probe_read_user(&event->buf, alpn_len & 0xFF, (void *)data_ptr);
    if (err == 0) {
        event->buf_filled = alpn_len;

        // Update session tracking with protocol type
        __u32 protocol = parse_alpn_protocol(event->buf, alpn_len);
        update_session_protocol(args->ssl_ctx, protocol);
    }

    // Track this PID
    track_pid(event->pid);

    // Submit event (small, ALPN strings are short)
    __u64 submit_size = sizeof(struct ssl_data_event) - MAX_BUF_SIZE + event->buf_filled;
    if (submit_size > sizeof(struct ssl_data_event)) {
        submit_size = sizeof(struct ssl_data_event);
    }
    bpf_ringbuf_output(&ssl_events, event, submit_size & 0xFFFF, 0);

    bpf_map_delete_elem(&alpn_query_map, &tid);
    return 0;
}

// GnuTLS: int gnutls_alpn_get_selected_protocol(gnutls_session_t session,
//                                                gnutls_datum_t *protocol)
// gnutls_datum_t = { unsigned char *data; unsigned int size; }
SEC("uprobe/gnutls_alpn_enter")
int BPF_UPROBE(probe_gnutls_alpn_enter, void *session, void *protocol_out) {
    __u32 tid = get_tid();

    struct alpn_query_args args = {
        .ssl_ctx = (__u64)session,
        .data_ptr = (__u64)protocol_out,  // Pointer to gnutls_datum_t
        .len_ptr = 0,
    };

    bpf_map_update_elem(&alpn_query_map, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/gnutls_alpn_exit")
int BPF_URETPROBE(probe_gnutls_alpn_exit) {
    __u32 tid = get_tid();
    __u32 zero = 0;

    struct alpn_query_args *args = bpf_map_lookup_elem(&alpn_query_map, &tid);
    if (!args) {
        return 0;
    }

    // Check return value (0 = success)
    int ret = PT_REGS_RC((struct pt_regs *)ctx);
    if (ret != 0) {
        bpf_map_delete_elem(&alpn_query_map, &tid);
        return 0;
    }

    // Read gnutls_datum_t structure: { unsigned char *data; unsigned int size; }
    struct {
        __u64 data;
        __u32 size;
    } datum = {0, 0};

    if (args->data_ptr != 0) {
        bpf_probe_read_user(&datum, sizeof(datum), (void *)args->data_ptr);
    }

    if (datum.size == 0 || datum.size > 255 || datum.data == 0) {
        bpf_map_delete_elem(&alpn_query_map, &tid);
        return 0;
    }

    // Get event buffer
    struct ssl_data_event *event = bpf_map_lookup_elem(&ssl_data_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&alpn_query_map, &tid);
        return 0;
    }

    // Fill metadata
    fill_event_metadata(event);
    event->event_type = EVENT_ALPN;
    event->len = datum.size;
    event->ssl_ctx = args->ssl_ctx;
    event->delta_ns = 0;

    // Read ALPN protocol string
    event->buf_filled = 0;
    int err = bpf_probe_read_user(&event->buf, datum.size & 0xFF, (void *)datum.data);
    if (err == 0) {
        event->buf_filled = datum.size;

        // Update session tracking with protocol type
        __u32 protocol = parse_alpn_protocol(event->buf, datum.size);
        update_session_protocol(args->ssl_ctx, protocol);
    }

    // Track this PID
    track_pid(event->pid);

    // Submit event
    __u64 submit_size = sizeof(struct ssl_data_event) - MAX_BUF_SIZE + event->buf_filled;
    if (submit_size > sizeof(struct ssl_data_event)) {
        submit_size = sizeof(struct ssl_data_event);
    }
    bpf_ringbuf_output(&ssl_events, event, submit_size & 0xFFFF, 0);

    bpf_map_delete_elem(&alpn_query_map, &tid);
    return 0;
}

// NSS: SECStatus SSL_GetNextProto(PRFileDesc *fd,
//                                  SSLNextProtoState *state,
//                                  unsigned char *buf,
//                                  unsigned int *bufLen,
//                                  unsigned int bufLenMax)
SEC("uprobe/nss_alpn_enter")
int BPF_UPROBE(probe_nss_alpn_enter, void *fd, void *state, void *buf,
               unsigned int *buf_len, unsigned int buf_len_max) {
    __u32 tid = get_tid();

    struct alpn_query_args args = {
        .ssl_ctx = (__u64)fd,
        .data_ptr = (__u64)buf,        // Output buffer for protocol name
        .len_ptr = (__u64)buf_len,     // Pointer to output length
    };

    bpf_map_update_elem(&alpn_query_map, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/nss_alpn_exit")
int BPF_URETPROBE(probe_nss_alpn_exit) {
    __u32 tid = get_tid();
    __u32 zero = 0;

    struct alpn_query_args *args = bpf_map_lookup_elem(&alpn_query_map, &tid);
    if (!args) {
        return 0;
    }

    // Check return value (SECSuccess = 0)
    int ret = PT_REGS_RC((struct pt_regs *)ctx);
    if (ret != 0) {
        bpf_map_delete_elem(&alpn_query_map, &tid);
        return 0;
    }

    // Read the length from *buf_len
    __u32 alpn_len = 0;
    if (args->len_ptr != 0) {
        bpf_probe_read_user(&alpn_len, sizeof(alpn_len), (void *)args->len_ptr);
    }

    if (alpn_len == 0 || alpn_len > 255) {
        bpf_map_delete_elem(&alpn_query_map, &tid);
        return 0;
    }

    // Get event buffer
    struct ssl_data_event *event = bpf_map_lookup_elem(&ssl_data_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&alpn_query_map, &tid);
        return 0;
    }

    // Fill metadata
    fill_event_metadata(event);
    event->event_type = EVENT_ALPN;
    event->len = alpn_len;
    event->ssl_ctx = args->ssl_ctx;
    event->delta_ns = 0;

    // Read ALPN protocol string from buf
    event->buf_filled = 0;
    if (args->data_ptr != 0) {
        int err = bpf_probe_read_user(&event->buf, alpn_len & 0xFF, (void *)args->data_ptr);
        if (err == 0) {
            event->buf_filled = alpn_len;

            // Update session tracking with protocol type
            __u32 protocol = parse_alpn_protocol(event->buf, alpn_len);
            update_session_protocol(args->ssl_ctx, protocol);
        }
    }

    // Track this PID
    track_pid(event->pid);

    // Submit event
    __u64 submit_size = sizeof(struct ssl_data_event) - MAX_BUF_SIZE + event->buf_filled;
    if (submit_size > sizeof(struct ssl_data_event)) {
        submit_size = sizeof(struct ssl_data_event);
    }
    bpf_ringbuf_output(&ssl_events, event, submit_size & 0xFFFF, 0);

    bpf_map_delete_elem(&alpn_query_map, &tid);
    return 0;
}

// wolfSSL: int wolfSSL_ALPN_GetProtocol(WOLFSSL* ssl, char** protocol, word16* size)
// Returns WOLFSSL_SUCCESS (1) on success, protocol is double pointer
SEC("uprobe/wolfssl_alpn_enter")
int BPF_UPROBE(probe_wolfssl_alpn_enter, void *ssl, char **protocol_out, unsigned short *size_out) {
    __u32 tid = get_tid();

    struct alpn_query_args args = {
        .ssl_ctx = (__u64)ssl,
        .data_ptr = (__u64)protocol_out,  // Double pointer to protocol string
        .len_ptr = (__u64)size_out,       // Pointer to size
    };

    bpf_map_update_elem(&alpn_query_map, &tid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/wolfssl_alpn_exit")
int BPF_URETPROBE(probe_wolfssl_alpn_exit) {
    __u32 tid = get_tid();
    __u32 zero = 0;

    struct alpn_query_args *args = bpf_map_lookup_elem(&alpn_query_map, &tid);
    if (!args) {
        return 0;
    }

    // Check return value (WOLFSSL_SUCCESS = 1)
    int ret = PT_REGS_RC((struct pt_regs *)ctx);
    if (ret != 1) {
        bpf_map_delete_elem(&alpn_query_map, &tid);
        return 0;
    }

    // Read the size from *size_out
    __u16 alpn_len = 0;
    if (args->len_ptr != 0) {
        bpf_probe_read_user(&alpn_len, sizeof(alpn_len), (void *)args->len_ptr);
    }

    if (alpn_len == 0 || alpn_len > 255) {
        bpf_map_delete_elem(&alpn_query_map, &tid);
        return 0;
    }

    // Read the protocol pointer from *protocol_out (double pointer)
    __u64 protocol_ptr = 0;
    if (args->data_ptr != 0) {
        bpf_probe_read_user(&protocol_ptr, sizeof(protocol_ptr), (void *)args->data_ptr);
    }

    if (protocol_ptr == 0) {
        bpf_map_delete_elem(&alpn_query_map, &tid);
        return 0;
    }

    // Get event buffer
    struct ssl_data_event *event = bpf_map_lookup_elem(&ssl_data_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&alpn_query_map, &tid);
        return 0;
    }

    // Fill metadata
    fill_event_metadata(event);
    event->event_type = EVENT_ALPN;
    event->len = alpn_len;
    event->ssl_ctx = args->ssl_ctx;
    event->delta_ns = 0;

    // Read ALPN protocol string
    event->buf_filled = 0;
    int err = bpf_probe_read_user(&event->buf, alpn_len & 0xFF, (void *)protocol_ptr);
    if (err == 0) {
        event->buf_filled = alpn_len;

        // Update session tracking with protocol type
        __u32 protocol = parse_alpn_protocol(event->buf, alpn_len);
        update_session_protocol(args->ssl_ctx, protocol);
    }

    // Track this PID
    track_pid(event->pid);

    // Submit event
    __u64 submit_size = sizeof(struct ssl_data_event) - MAX_BUF_SIZE + event->buf_filled;
    if (submit_size > sizeof(struct ssl_data_event)) {
        submit_size = sizeof(struct ssl_data_event);
    }
    bpf_ringbuf_output(&ssl_events, event, submit_size & 0xFFFF, 0);

    bpf_map_delete_elem(&alpn_query_map, &tid);
    return 0;
}

// =============================================================================
// NSS SSL_ImportFD Probe - Track verified SSL connections
// PRFileDesc* SSL_ImportFD(PRFileDesc *model, PRFileDesc *fd)
//
// This is the bottleneck for all Firefox web traffic - every HTTPS connection
// must pass through here to get its TLS wrapper. IPC almost never does.
// By tracking which file descriptors have been promoted to SSL, we can
// filter out non-SSL IPC traffic.
// =============================================================================

SEC("uretprobe/ssl_import_fd")
int BPF_URETPROBE(probe_ssl_import_fd_exit) {
    __u32 zero = 0;

    // Get returned PRFileDesc* - this is the SSL-wrapped fd
    __u64 ssl_fd = (__u64)PT_REGS_RC((struct pt_regs *)ctx);

    if (ssl_fd == 0) {
        return 0;  // SSL_ImportFD failed
    }

    // Mark this fd as a verified SSL connection
    __u8 val = 1;
    bpf_map_update_elem(&nss_ssl_fds, &ssl_fd, &val, BPF_ANY);

    // Emit event for userspace tracking
    struct ssl_data_event *event = bpf_map_lookup_elem(&ssl_data_heap, &zero);
    if (!event) {
        return 0;
    }

    fill_event_metadata(event);
    event->event_type = EVENT_NSS_SSL_FD;
    event->ssl_ctx = ssl_fd;  // The SSL-wrapped PRFileDesc
    event->len = 0;
    event->buf_filled = 0;
    event->delta_ns = 0;

    track_pid(event->pid);

    bpf_ringbuf_output(&ssl_events, event,
                       sizeof(struct ssl_data_event) - MAX_BUF_SIZE, 0);

    return 0;
}

// =============================================================================
// Session Cleanup Hooks
// Clean up BPF maps when SSL sessions are explicitly freed
// This prevents map exhaustion over time and keeps tracking accurate
// =============================================================================

// OpenSSL: SSL_free(SSL *ssl) - cleanup when SSL connection is freed
SEC("uprobe/ssl_free")
int BPF_UPROBE(probe_ssl_free, void *ssl) {
    __u64 ssl_ctx = (__u64)ssl;

    // Clean up session tracking
    bpf_map_delete_elem(&tracked_sessions, &ssl_ctx);

    // Clean up SSL* → fd mapping
    bpf_map_delete_elem(&ssl_to_fd, &ssl_ctx);

    return 0;
}

// NSS: PR_Close(PRFileDesc *fd) - cleanup when PRFileDesc is closed
// This cleans up both SSL-imported fds and potentially session tracking
SEC("uprobe/pr_close")
int BPF_UPROBE(probe_pr_close, void *fd) {
    __u64 fd_ptr = (__u64)fd;

    // Clean up NSS SSL fd tracking
    bpf_map_delete_elem(&nss_ssl_fds, &fd_ptr);

    // Also try to clean up session tracking (PRFileDesc used as ssl_ctx for NSS)
    bpf_map_delete_elem(&tracked_sessions, &fd_ptr);

    return 0;
}

// GnuTLS: gnutls_deinit(gnutls_session_t session) - cleanup when session is freed
SEC("uprobe/gnutls_deinit")
int BPF_UPROBE(probe_gnutls_deinit, void *session) {
    __u64 ssl_ctx = (__u64)session;

    // Clean up session tracking
    bpf_map_delete_elem(&tracked_sessions, &ssl_ctx);

    return 0;
}

// =============================================================================
// Process Exit Tracepoint
// Notifies userspace when a tracked process exits for session cleanup
// =============================================================================

SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(void *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Only emit event if this PID had SSL activity
    __u8 *tracked = bpf_map_lookup_elem(&tracked_pids, &pid);
    if (!tracked) {
        return 0;  // Not a tracked PID, ignore
    }

    // Remove from tracking map
    bpf_map_delete_elem(&tracked_pids, &pid);

    __u32 zero = 0;

    // Get event buffer from per-CPU heap
    struct ssl_data_event *event = bpf_map_lookup_elem(&ssl_data_heap, &zero);
    if (!event) {
        return 0;
    }

    // Fill basic metadata
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = (__u32)pid_tgid;
    event->uid = (__u32)bpf_get_current_uid_gid();
    event->event_type = EVENT_PROCESS_EXIT;
    event->len = 0;
    event->buf_filled = 0;
    event->delta_ns = 0;
    event->ssl_ctx = 0;

    // Get process name
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Submit event (small, no buffer data)
    bpf_ringbuf_output(&ssl_events, event,
                       sizeof(struct ssl_data_event) - MAX_BUF_SIZE, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
