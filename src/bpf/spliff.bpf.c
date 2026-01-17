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
#include <bpf/bpf_endian.h>

#define MAX_BUF_SIZE 16384
#define TASK_COMM_LEN 16

// Event types
#define EVENT_SSL_READ     0
#define EVENT_SSL_WRITE    1
#define EVENT_HANDSHAKE    2
#define EVENT_PROCESS_EXIT 3
#define EVENT_ALPN         4
#define EVENT_NSS_SSL_FD   5  // NSS SSL_ImportFD tracking (verified TLS connection)
#define EVENT_XDP_PACKET   6  // XDP packet metadata event
#define EVENT_PROCESS_EXEC 7  // New process exec - dynamic probe attachment

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
    __u64 out_len_ptr;    // Output length pointer (for SSL_read_ex/SSL_write_ex)
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
// XDP Structures and Constants
// =============================================================================

// Traffic categories (content-based detection, not port-based)
#define CAT_UNKNOWN       0
#define CAT_TLS_TCP       1   // TLS over TCP (H1/H2)
#define CAT_QUIC          2   // QUIC/H3 over UDP (stub)
#define CAT_PLAIN_HTTP    3   // Unencrypted HTTP/1.x
#define CAT_H2_PREFACE    4   // HTTP/2 connection preface ("PRI * HTTP/2.0...")
#define CAT_OTHER         5

// Ethernet
#define ETH_HLEN          14
#define ETH_P_IP          0x0800
#define ETH_P_IPV6        0x86DD

// IP protocols
#define IPPROTO_TCP_VAL   6
#define IPPROTO_UDP_VAL   17

// TLS record types
#define TLS_CHANGE_CIPHER 0x14
#define TLS_ALERT         0x15
#define TLS_HANDSHAKE     0x16
#define TLS_APP_DATA      0x17

// TCP flags for connection lifecycle
#define TCP_FLAG_FIN      0x01
#define TCP_FLAG_SYN      0x02
#define TCP_FLAG_RST      0x04
#define TCP_FLAG_PSH      0x08
#define TCP_FLAG_ACK      0x10

// Flow key (5-tuple) - packed for memcmp consistency
struct flow_key {
    __u32 saddr;          // [4] Source IP (v4) or hash (v6)
    __u32 daddr;          // [4] Dest IP (v4) or hash (v6)
    __u16 sport;          // [2] Source port
    __u16 dport;          // [2] Dest port
    __u8  protocol;       // [1] TCP or UDP
    __u8  ip_version;     // [1] 4 or 6
    __u8  _pad[2];        // [2] Align to 16 bytes
} __attribute__((packed));

// XDP packet event - optimized for cache efficiency
struct xdp_packet_event {
    __u64 timestamp_ns;   // [8] Absolute time for latency calcs
    __u64 socket_cookie;  // [8] The "Golden Thread" to uprobes/L7
    struct flow_key flow; // [16] Src/Dst IP + Ports

    __u32 pkt_len;        // [4] Wire length
    __u32 ifindex;        // [4] NIC ID
    __u32 event_type;     // [4] EVENT_XDP_PACKET (matches uprobe enum)

    __u16 payload_off;    // [2] L4 payload start
    __u8  category;       // [1] Protocol class
    __u8  tls_type;       // [1] TLS record type (Handshake vs Data)
    __u8  direction;      // [1] 0=unknown, 1=ingress, 2=egress
    __u8  tcp_flags;      // [1] SYN/FIN/RST for flow lifecycle
    __u8  _pad[2];        // [2] Align to 8-byte boundary
} __attribute__((packed));

// Socket cookie correlation - bridges uprobe SSL* to XDP 5-tuple
struct cookie_correlation {
    __u64 ssl_ctx;        // [8] SSL* from uprobe
    __u64 timestamp_ns;   // [8] When established
    __u32 pid;            // [4] Process ID
    __u32 _pad;           // [4] Alignment
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

// Debug counter for SSL operations (to verify probes still fire)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ssl_op_counter SEC(".maps");

// =============================================================================
// Chrome Async I/O Tracking - SSLClientSocketImpl buffer correlation
// =============================================================================
// Chrome uses async I/O: SSLClientSocketImpl::Read() may return immediately
// with ERR_IO_PENDING. When data arrives, OnReadReady() is called.
// We need to track the IOBuffer* where data will eventually be stored.
//
// Map: SSLClientSocketImpl* (this ptr) → socket_read_args
struct socket_read_args {
    __u64 io_buffer;     // IOBuffer* where data will be stored
    __u32 buf_len;       // Requested read length
    __u64 timestamp_ns;  // When Read() was called
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, __u64);    // SSLClientSocketImpl* (this ptr)
    __type(value, struct socket_read_args);
} socket_read_map SEC(".maps");

// =============================================================================
// XDP Maps - Flow Tracking, Socket Cookie Correlation, Session Registry
// =============================================================================
//
// Architecture: 3-Stage State Machine with "Silent Tracking"
//   Stage 1 (PENDING):    SYN seen → entry created, waiting for first data
//   Stage 2 (CLASSIFIED): First data packet → structural DPI classifies protocol
//   Stage 3 (SILENCED):   Userspace PCRE2-JIT confirms → XDP stops sending payloads
//
// Memory Budget (~4 MB total):
//   flow_states:       65K × 36B  = 2.3 MB (5-tuple → state)
//   session_registry: 131K × 8B  = 1.0 MB (cookie → policy)
//   cookie_to_ssl:     8K × 24B  = 0.2 MB (cookie → SSL* correlation)
//   xdp_events:       512 KB ringbuf
//
// Why session_registry is 2x flow_states:
//   Socket cookies persist across TIME_WAIT recycling. A single cookie may
//   correlate with multiple sequential 5-tuples over its lifetime.
// =============================================================================

// Flow state machine stages
#define FLOW_STATE_PENDING     0   // SYN seen, awaiting first data packet
#define FLOW_STATE_CLASSIFIED  1   // Protocol identified by XDP structural DPI
#define FLOW_STATE_AMBIGUOUS   2   // Needs userspace PCRE2-JIT classification

// Flow state flags (bitfield)
#define FLOW_FLAG_NEEDS_PCRE2  0x01  // Ambiguous: send payload to userspace
#define FLOW_FLAG_HAS_UPROBE   0x02  // SSL_set_fd populated cookie_to_ssl
#define FLOW_FLAG_TERMINATED   0x04  // FIN/RST seen, pending cleanup

// Timeout for zombie flow cleanup (userspace sweeper checks last_seen_ns)
#define FLOW_TIMEOUT_NS (30ULL * 1000000000ULL)  // 30 seconds

// Flow state - tracks each 5-tuple through the state machine
// Fields ordered by size (8→4→1) to minimize padding: 36 bytes total
struct flow_state {
    __u64 socket_cookie;      // [8] The "Golden Thread" correlation key
    __u64 first_seen_ns;      // [8] Connection start (SYN timestamp)
    __u64 last_seen_ns;       // [8] Last packet seen (for timeout)
    __u32 pkt_count;          // [4] Packet counter (stats)
    __u32 byte_count;         // [4] Byte counter (stats)
    __u8  category;           // [1] CAT_TLS_TCP, CAT_PLAIN_HTTP, CAT_OTHER
    __u8  state;              // [1] FLOW_STATE_*
    __u8  direction;          // [1] 0=unknown, 1=client→server, 2=server→client
    __u8  flags;              // [1] FLOW_FLAG_* bitfield
} __attribute__((packed));    // 36 bytes, no padding waste

// Flow state map - keyed by 5-tuple
// LRU: Automatic eviction of oldest flows when full (prevents memory exhaustion)
// 65,536 entries supports ~65K concurrent connections per host
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);      // 16-byte 5-tuple (defined above)
    __type(value, struct flow_state);  // 36 bytes
} flow_states SEC(".maps");

// Session policy - the XDP "Gatekeeper" decision cache
// Once userspace PCRE2-JIT classifies a flow, XDP checks this to fast-pass
// Fields ordered by size: 8 bytes total, no padding
struct session_policy {
    __u32 proto_type;         // [4] PROTO_HTTP1, PROTO_HTTP2, PROTO_UNKNOWN
    __u8  silenced;           // [1] 1 = stop sending payloads to ringbuf
    __u8  _pad[3];            // [3] Explicit padding for alignment
};

// Session registry - indexed by socket_cookie (the universal correlator)
// Updated by userspace dispatcher after PCRE2-JIT classification completes
// XDP reads to decide: full processing or fast-pass?
// 131K entries (2x flow_states) because cookies outlive 5-tuples
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u64);                // socket_cookie
    __type(value, struct session_policy);
} session_registry SEC(".maps");

// Socket cookie → SSL* correlation (the "Golden Thread" bridge)
// Populated by USERSPACE after correlating XDP and uprobe events:
//   1. XDP sends event with socket_cookie (from bpf_skc_lookup_tcp)
//   2. Uprobe sends SSL event with SSL* (ssl_to_fd maps SSL* → fd)
//   3. Userspace calls getsockopt(fd, SOL_SOCKET, SO_COOKIE) to get cookie
//   4. Userspace updates this map via bpf_map_update_elem()
// This enables the "Double View": XDP network metadata + uprobe decrypted content
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);                // socket_cookie
    __type(value, struct cookie_correlation);  // 24 bytes (defined above)
} cookie_to_ssl SEC(".maps");

// Per-CPU array for XDP metadata events (avoids 512-byte stack limit)
// XDP programs have strict stack limits; PERCPU_ARRAY provides safe heap
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_packet_event);  // 56 bytes (defined above)
} xdp_event_heap SEC(".maps");

// Ring buffer for XDP events - kernel→userspace channel
// 512 KB sized for ~10K events in flight (event size ~50 bytes avg)
// Only sends: Discovery (new flow), Termination (FIN/RST), Ambiguous (needs PCRE2)
// Silenced flows do NOT write here - that's the whole point of the Gatekeeper
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} xdp_events SEC(".maps");

// Payload capture size for ambiguous traffic classification
// 128 bytes captures: full HTTP request line, TLS ClientHello SNI, H2 preface
// RFC 9112: request-line = method SP request-target SP HTTP-version CRLF
// Typical: "GET /path HTTP/1.1\r\n" = ~20 bytes, plus Host header ~50 bytes
#define XDP_PAYLOAD_MAX 128

// XDP payload event - for ambiguous traffic needing PCRE2-JIT classification
// Sent when XDP structural DPI is uncertain (e.g., non-standard HTTP method)
// Fields ordered by size: 164 bytes total
struct xdp_payload_event {
    __u64 timestamp_ns;                // [8] Event time
    __u64 socket_cookie;               // [8] Correlation key
    struct flow_key flow;              // [16] 5-tuple for map lookup
    __u32 payload_len;                 // [4] Actual bytes captured (≤128)
    __u32 event_type;                  // [4] EVENT_XDP_PACKET
    __u8  category;                    // [1] Best-guess category from XDP
    __u8  _pad[3];                     // [3] Alignment
    __u8  payload[XDP_PAYLOAD_MAX];    // [128] First bytes for PCRE2-JIT
} __attribute__((packed));             // 172 bytes

// Per-CPU heap for payload events (avoids stack overflow)
// 172 bytes exceeds comfortable stack usage; PERCPU_ARRAY is safe
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_payload_event);
} xdp_payload_heap SEC(".maps");

// XDP statistics counters (per-CPU for lock-free updates)
// Userspace sums all CPUs for total; useful for debugging and monitoring
struct xdp_stats {
    __u64 packets_total;      // All packets seen
    __u64 packets_tcp;        // TCP packets processed
    __u64 flows_created;      // New flow_state entries
    __u64 flows_classified;   // Successful protocol classification
    __u64 flows_ambiguous;    // Sent to userspace for PCRE2-JIT
    __u64 flows_terminated;   // FIN/RST seen
    __u64 gatekeeper_hits;    // Silenced flows (fast-pass)
    __u64 cookie_failures;    // Socket cookie lookup failures (IPv6, etc.)
    __u64 ringbuf_drops;      // Ring buffer full (bpf_ringbuf_output failures)
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_stats);
} xdp_stats_map SEC(".maps");

// Flow → Socket Cookie cache (populated by sock_ops, read by XDP)
// sock_ops runs at socket establishment with full task context, allowing
// bpf_get_socket_cookie() which is NOT available in XDP context.
// XDP then looks up the pre-cached cookie for correlation with uprobe data.
// 65K entries matches flow_states capacity.
struct flow_cookie_entry {
    __u64 socket_cookie;      // [8] The "Golden Thread" correlator
    __u64 timestamp_ns;       // [8] When cached (for staleness detection)
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);           // 16-byte 5-tuple
    __type(value, struct flow_cookie_entry); // 16 bytes
} flow_cookie_map SEC(".maps");


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
// Chrome/BoringSSL Internal Probes (Golden Hooks)
// =============================================================================
//
// =============================================================================
// Chrome/BoringSSL Internal Function Probes
// =============================================================================
//
// IMPORTANT: From Ghidra decompilation of Chromium 143:
//
// ssl_read_impl(SSL *ssl) - ONLY takes SSL* pointer!
//   - RDI: SSL* context (ONLY argument)
//   - Returns: int (bytes available or error code)
//   - Buffer is NOT passed - data goes to internal SSL buffers
//   - SSL_read then does memcpy from internal buffer to user buffer
//
// SSL_read(SSL*, void* buf, int len) - Standard 3-arg signature
//   - This is the correct hook point for capturing read data
//   - Entry: save buf/len, Exit: read data using return value
//
// SSL_write(SSL*, void* buf, int len) - Standard 3-arg signature
//   - Entry: capture data immediately from buf
//   - Exit: get bytes written from return value
//
// DoPayloadRead(this, span.data, span.size) - base::span passed by value
//   - RSI contains data pointer, RDX contains size
//
// DoPayloadWrite(this) - NO buffer arguments!
//   - Buffer is at *(this+0x50)+0x10, length at this+0x58
//   - Cannot capture write data from arguments
// =============================================================================

// NOTE: ssl_read_impl only takes SSL* - we use this for correlation only.
// Actual data capture happens via SSL_read (probe_ssl_rw_enter/probe_ssl_read_exit)
SEC("uprobe/ssl_read_impl_enter")
int BPF_UPROBE(probe_ssl_read_impl_enter, void *ssl_ctx) {
    __u32 tid = get_tid();

    bpf_printk("SSL_READ_IMPL_ENTER: ssl=%lx tid=%u (correlation only)",
               (unsigned long)ssl_ctx, tid);

    // Just save SSL* for correlation - no buffer info available here
    struct ssl_args args = {
        .ssl_ctx = (__u64)ssl_ctx,
        .buf_ptr = 0,  // Not available - ssl_read_impl has no buf arg
        .len = 0,      // Not available
    };

    bpf_map_update_elem(&ssl_args_map, &tid, &args, BPF_ANY);

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);

    return 0;
}

// DoPayloadWrite is a C++ method: this pointer in RDI
// The IOBuffer is stored in the object, not passed as argument
SEC("uprobe/do_payload_write_enter")
int BPF_UPROBE(probe_do_payload_write_enter, void *this_ptr) {
    __u32 tid = get_tid();

    // For DoPayloadWrite, 'this' is SSLClientSocketImpl*
    // We store it as ssl_ctx for correlation purposes
    struct ssl_args args = {
        .ssl_ctx = (__u64)this_ptr,
        .buf_ptr = 0,  // IOBuffer is in object state
        .len = 0,
    };

    bpf_map_update_elem(&ssl_args_map, &tid, &args, BPF_ANY);

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);

    return 0;
}

// =============================================================================
// Chrome Async I/O Probes - SSLClientSocketImpl::Read and OnReadReady
// =============================================================================
//
// Chrome's network stack uses async I/O:
//   1. Read(IOBuffer*, int, callback) is called - may return ERR_IO_PENDING
//   2. When data arrives, OnReadReady() is called
//   3. OnReadReady() internally calls SSL_read() to drain data
//
// We save the IOBuffer* on Read() entry, then when SSL_read exits with data,
// we can correlate and capture the actual decrypted content.

// SSLClientSocketImpl::ReadIfReady(net::IOBuffer*, int, base::OnceCallback)
// C++ method: this in RDI, IOBuffer* in RSI, buf_len in RDX
// IOBuffer inherits from RefCounted. Layout: [vtable:8][data_:8]
// From Ghidra analysis: data_ (raw char*) is at offset +8
SEC("uprobe/socket_read_enter")
int BPF_UPROBE(probe_socket_read_enter, void *this_ptr, void *io_buffer, int buf_len) {
    __u64 this_key = (__u64)this_ptr;
    __u32 tid = get_tid();

    // Dereference IOBuffer to get the actual char* data_ pointer
    // IOBuffer layout: data_ is at offset +8 (after vtable)
    void *raw_buffer = NULL;
    if (io_buffer) {
        int ret = bpf_probe_read_user(&raw_buffer, sizeof(raw_buffer),
                                       (void *)((char *)io_buffer + 0x8));
        if (ret != 0) {
            bpf_printk("SOCKET_READ: failed to read IOBuffer data_ ptr");
            return 0;
        }
    }

    // Save the IOBuffer mapping for async completion
    struct socket_read_args args = {
        .io_buffer = (__u64)raw_buffer,
        .buf_len = (__u32)buf_len,
        .timestamp_ns = bpf_ktime_get_ns(),
    };

    bpf_map_update_elem(&socket_read_map, &this_key, &args, BPF_ANY);

    // Also save in ssl_args_map so ssl_read_exit can correlate
    struct ssl_args ssl_args = {
        .ssl_ctx = this_key,
        .buf_ptr = (__u64)raw_buffer,
        .len = (__u32)buf_len,
    };
    bpf_map_update_elem(&ssl_args_map, &tid, &ssl_args, BPF_ANY);

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);

    bpf_printk("SOCKET_READ: this=%lx iobuf=%lx raw=%lx len=%d",
               (unsigned long)this_ptr, (unsigned long)io_buffer,
               (unsigned long)raw_buffer, buf_len);

    return 0;
}

// =============================================================================
// SSLClientSocketImpl::DoPayloadRead - THE BEST HOOK POINT
// =============================================================================
// DoPayloadRead receives the raw char* buffer directly (already extracted from IOBuffer).
// From Chromium disassembly:
//   - arg1 (rdi): this pointer (SSLClientSocketImpl*)
//   - arg2 (rsi): raw char* buffer pointer
//   - arg3 (rdx): buffer length
// This is called before SSL_read and has direct access to the buffer.
SEC("uprobe/do_payload_read_enter")
int BPF_UPROBE(probe_do_payload_read_enter, void *this_ptr, void *buf, int buf_len) {
    __u32 tid = get_tid();

    bpf_printk("DO_PAYLOAD_READ: this=%lx buf=%lx len=%d tid=%u",
               (unsigned long)this_ptr, (unsigned long)buf, buf_len, tid);

    // Save the buffer info - ssl_read_impl_enter/exit will use this
    struct ssl_args ssl_args = {
        .ssl_ctx = (__u64)this_ptr,  // this pointer for correlation
        .buf_ptr = (__u64)buf,       // Raw buffer pointer (char*)
        .len = (__u32)buf_len,
    };
    bpf_map_update_elem(&ssl_args_map, &tid, &ssl_args, BPF_ANY);

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);

    return 0;
}

// SSLClientSocketImpl::OnReadReady() - async completion callback
// C++ method: this in RDI (no other args - it's a void() callback)
// Note: OnReadReady and OnWriteReady share the same address due to ICF optimization
// We use the 'this' pointer to distinguish read vs write context
SEC("uprobe/on_read_ready")
int BPF_UPROBE(probe_on_read_ready, void *this_ptr) {
    __u64 this_key = (__u64)this_ptr;

    // Look up saved IOBuffer from Read() entry
    struct socket_read_args *saved = bpf_map_lookup_elem(&socket_read_map, &this_key);
    if (saved) {
        bpf_printk("ON_READ_READY: this=%lx iobuf=%lx (async completion)",
                   (unsigned long)this_ptr, (unsigned long)saved->io_buffer);

        // The actual SSL_read call will happen next and be captured by ssl_read_exit
        // We just log here for debugging the async flow
    } else {
        bpf_printk("ON_READ_READY: this=%lx (no saved buffer - write ready?)",
                   (unsigned long)this_ptr);
    }

    return 0;
}

// =============================================================================
// SSL Read/Write Entry Probe
// Called for: SSL_read, SSL_write, gnutls_record_recv, gnutls_record_send,
//             PR_Read, PR_Write, PR_Recv, PR_Send
// =============================================================================

SEC("uprobe/ssl_rw_enter")
int BPF_UPROBE(probe_ssl_rw_enter, void *ssl_ctx, void *buf, int num) {
    __u32 tid = get_tid();

    // Debug: print every SSL_read/SSL_write call for Chrome debugging
    bpf_printk("SSL_RW_ENTER: ssl=%lx buf=%lx num=%d tid=%u",
               (unsigned long)ssl_ctx, (unsigned long)buf, num, tid);

    // Debug: count SSL operations
    __u32 zero = 0;
    __u64 *counter = bpf_map_lookup_elem(&ssl_op_counter, &zero);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }

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
// SSL_read_ex / SSL_write_ex Entry Probe (OpenSSL 3.x)
// int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)
// int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)
// Returns 1 on success, 0 on failure. Actual bytes in output pointer.
// =============================================================================

SEC("uprobe/ssl_rw_ex_enter")
int BPF_UPROBE(probe_ssl_rw_ex_enter, void *ssl_ctx, void *buf, size_t num, size_t *out_len) {
    __u32 tid = get_tid();

    // Save SSL context, buffer address, length, and output length pointer
    struct ssl_args args = {
        .ssl_ctx = (__u64)ssl_ctx,
        .buf_ptr = (__u64)buf,
        .len = (__u32)num,
        .out_len_ptr = (__u64)out_len,
    };

    bpf_map_update_elem(&ssl_args_map, &tid, &args, BPF_ANY);

    // Save start timestamp for latency calculation
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);

    return 0;
}

// =============================================================================
// SSL_read_ex Exit Probe
// =============================================================================

SEC("uretprobe/ssl_read_ex_exit")
int BPF_URETPROBE(probe_ssl_read_ex_exit) {
    __u32 tid = get_tid();
    __u32 zero = 0;

    // Lookup saved arguments
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_args_map, &tid);
    if (!args) {
        return 0;
    }

    // Get return value (1=success, 0=failure for _ex variants)
    int ret = PT_REGS_RC((struct pt_regs *)ctx);
    if (ret != 1) {
        // Failure - no data
        bpf_map_delete_elem(&ssl_args_map, &tid);
        bpf_map_delete_elem(&start_ns, &tid);
        return 0;
    }

    // Read actual bytes from output pointer
    size_t bytes_read = 0;
    if (args->out_len_ptr != 0) {
        bpf_probe_read_user(&bytes_read, sizeof(bytes_read), (void *)args->out_len_ptr);
    }

    if (bytes_read == 0) {
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
    event->len = (__u32)bytes_read;
    event->ssl_ctx = args->ssl_ctx;

    // Calculate latency
    __u64 *tsp = bpf_map_lookup_elem(&start_ns, &tid);
    if (tsp) {
        event->delta_ns = event->timestamp_ns - *tsp;
    }

    // Copy data from userspace buffer
    __u32 buf_copy_size = (__u32)bytes_read;
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
// SSL_write_ex Exit Probe
// =============================================================================

SEC("uretprobe/ssl_write_ex_exit")
int BPF_URETPROBE(probe_ssl_write_ex_exit) {
    __u32 tid = get_tid();
    __u32 zero = 0;

    // Lookup saved arguments
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_args_map, &tid);
    if (!args) {
        return 0;
    }

    // Get return value (1=success, 0=failure for _ex variants)
    int ret = PT_REGS_RC((struct pt_regs *)ctx);
    if (ret != 1) {
        // Failure - no data
        bpf_map_delete_elem(&ssl_args_map, &tid);
        bpf_map_delete_elem(&start_ns, &tid);
        return 0;
    }

    // Read actual bytes from output pointer
    size_t bytes_written = 0;
    if (args->out_len_ptr != 0) {
        bpf_probe_read_user(&bytes_written, sizeof(bytes_written), (void *)args->out_len_ptr);
    }

    if (bytes_written == 0) {
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
    event->len = (__u32)bytes_written;
    event->ssl_ctx = args->ssl_ctx;

    // Calculate latency
    __u64 *tsp = bpf_map_lookup_elem(&start_ns, &tid);
    if (tsp) {
        event->delta_ns = event->timestamp_ns - *tsp;
    }

    // Copy data from userspace buffer
    __u32 buf_copy_size = (__u32)bytes_written;
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
// Syscall Correlation Hooks (for Chrome/BoringSSL FD discovery)
// =============================================================================
//
// Chrome's BoringSSL doesn't call SSL_set_fd, so we can't track SSL* → fd
// via that hook. Instead, we use "EDR Proxy" correlation:
//
// 1. When SSL_read/SSL_write is called, ssl_args_map[tid] has the SSL* pointer
// 2. Internally, BoringSSL calls write()/read()/sendto()/recvfrom() syscalls
// 3. These syscall hooks fire WHILE still inside SSL_read/SSL_write (same thread)
// 4. We check if ssl_args_map[tid] exists - if yes, we found the fd!
// 5. We update ssl_to_fd[SSL*] = fd for future lookups
//
// This works because SSL operations are synchronous and single-threaded.
// =============================================================================

// Helper to correlate SSL context with file descriptor
static __always_inline void try_correlate_ssl_fd(__s32 fd) {
    // Only correlate valid fds (skip stdin/stdout/stderr)
    if (fd < 3) return;

    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // Check if this thread is currently inside an SSL_read/SSL_write
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_args_map, &tid);
    if (!args) {
        return;
    }

    __u64 ssl_ctx = args->ssl_ctx;
    if (!ssl_ctx) return;

    // Check if we already have this mapping (avoid redundant updates)
    __s32 *existing = bpf_map_lookup_elem(&ssl_to_fd, &ssl_ctx);
    if (existing) return;

    // Found a new SSL* → fd correlation! Store it.
    bpf_map_update_elem(&ssl_to_fd, &ssl_ctx, &fd, BPF_NOEXIST);
    bpf_printk("CORRELATED: tid=%u ssl=%lx fd=%d", tid, ssl_ctx, fd);
}

// Syscall hook: write(int fd, const void *buf, size_t count)
// Raw tracepoint gives us access to syscall args directly
SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    __s32 fd = (__s32)ctx->args[0];
    try_correlate_ssl_fd(fd);
    return 0;
}

// Syscall hook: read(int fd, void *buf, size_t count)
SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    __s32 fd = (__s32)ctx->args[0];
    try_correlate_ssl_fd(fd);
    return 0;
}

// Syscall hook: sendto(int fd, const void *buf, size_t len, int flags, ...)
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    __s32 fd = (__s32)ctx->args[0];
    try_correlate_ssl_fd(fd);
    return 0;
}

// Syscall hook: recvfrom(int fd, void *buf, size_t len, int flags, ...)
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    __s32 fd = (__s32)ctx->args[0];
    try_correlate_ssl_fd(fd);
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

// =============================================================================
// Process Exec Tracepoint - Dynamic SSL Library Detection
// Notifies userspace when ANY new process starts so it can check for SSL libs
// Supports: OpenSSL, GnuTLS, NSS/NSPR, BoringSSL, WolfSSL
// =============================================================================

SEC("tracepoint/sched/sched_process_exec")
int handle_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
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
    event->event_type = EVENT_PROCESS_EXEC;
    event->len = 0;
    event->delta_ns = 0;
    event->ssl_ctx = 0;

    // Get process name - userspace uses this for quick filtering
    // (e.g., skip known non-SSL processes like "ls", "cat", etc.)
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->buf_filled = 0;

    // Submit event - userspace will check /proc/PID/maps for SSL libraries
    bpf_ringbuf_output(&ssl_events, event,
                       sizeof(struct ssl_data_event) - MAX_BUF_SIZE, 0);

    return 0;
}

// =============================================================================
// Process Fork Tracepoint - Track child processes of SSL-using parents
// Important for multi-process apps (Chrome, Firefox, Electron apps)
// =============================================================================

SEC("tracepoint/sched/sched_process_fork")
int handle_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    // Get parent and child PIDs
    __u32 parent_pid = BPF_CORE_READ(ctx, parent_pid);
    __u32 child_pid = BPF_CORE_READ(ctx, child_pid);

    // Check if parent is tracked (has SSL activity)
    __u8 *parent_tracked = bpf_map_lookup_elem(&tracked_pids, &parent_pid);
    if (!parent_tracked) {
        return 0;  // Parent not tracked, ignore fork
    }

    // Mark child as tracked too (inherits parent's SSL libraries)
    __u8 tracked = 1;
    bpf_map_update_elem(&tracked_pids, &child_pid, &tracked, BPF_ANY);

    return 0;
}

// =============================================================================
// XDP Program - Structural Protocol Detection & Flow Tracking
// =============================================================================
//
// Architecture: 3-Stage State Machine with "Silent Tracking"
//   Stage 1: Lifecycle management (SYN creates PENDING, FIN/RST terminates)
//   Stage 2: Gatekeeper - silenced flows fast-pass with zero processing
//   Stage 3: Classification - structural DPI on first data packet
//   Stage 4: Event emission - discovery/termination/ambiguous only
//
// Protocol Detection (RFC-compliant heuristics):
//   TLS:     5-byte record header (ContentType 0x14-0x17, Version 0x03xx, Length ≤16384)
//   HTTP/2:  Connection preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (check first 8 bytes)
//   HTTP/1:  RFC 9112 request-line: [A-Z]{3,8} SP "/" (method + space + path)
//
// Limitations:
//   - IPv6 socket cookie lookup not implemented (falls back to classification-only)
//   - Stats counters are approximate (no atomic ops, per-CPU summation)
// =============================================================================

// XDP helper: Check if byte is uppercase ASCII [A-Z]
static __always_inline bool xdp_is_uppercase(__u8 c) {
    return c >= 'A' && c <= 'Z';
}

// XDP helper: Detect TLS record structure (5-byte header validation)
// TLS Record: [ContentType:1][Version:2][Length:2][Payload:N]
// Returns: CAT_TLS_TCP if valid TLS record, CAT_UNKNOWN otherwise
static __always_inline __u8 xdp_detect_tls(void *data, void *data_end,
                                            __u8 *out_content_type) {
    *out_content_type = 0;

    // Caller must have validated (data + 5) <= data_end before calling
    __u8 *p = data;
    __u8 content_type = p[0];
    __u8 ver_major = p[1];
    __u8 ver_minor = p[2];
    __u16 record_len = ((__u16)p[3] << 8) | p[4];

    // ContentType: 0x14=ChangeCipherSpec, 0x15=Alert, 0x16=Handshake, 0x17=AppData
    if (content_type < TLS_CHANGE_CIPHER || content_type > TLS_APP_DATA)
        return CAT_UNKNOWN;

    // Version: 0x0300=SSL3.0, 0x0301=TLS1.0, 0x0302=TLS1.1, 0x0303=TLS1.2/1.3
    // Some implementations use 0x0301 in record layer even for TLS 1.3
    if (ver_major != 0x03 || ver_minor > 0x04)
        return CAT_UNKNOWN;

    // Length: TLS records max 16KB (16384 bytes) per RFC 8446
    if (record_len > 16384)
        return CAT_UNKNOWN;

    *out_content_type = content_type;
    return CAT_TLS_TCP;
}

// XDP helper: Detect HTTP/2 connection preface
// The preface is: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (24 bytes)
// We check first 8 bytes: "PRI * HT" for efficiency
// Returns: CAT_H2_PREFACE if detected, CAT_UNKNOWN otherwise
static __always_inline __u8 xdp_detect_http2_preface(void *data, void *data_end) {
    // Caller must have validated (data + 8) <= data_end before calling
    __u8 *p = data;
    // HTTP/2 connection preface: "PRI * HT" (0x50 0x52 0x49 0x20 0x2A 0x20 0x48 0x54)
    if (p[0] == 'P' && p[1] == 'R' && p[2] == 'I' && p[3] == ' ' &&
        p[4] == '*' && p[5] == ' ' && p[6] == 'H' && p[7] == 'T') {
        return CAT_H2_PREFACE;
    }

    return CAT_UNKNOWN;
}

// XDP helper: Detect HTTP/1.x request line using RFC 9112 heuristic
// Pattern: [A-Z]{3,8} SP "/" (method + space + path starting with /)
// Captures: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, CONNECT, PROPFIND, etc.
// Returns: CAT_PLAIN_HTTP if likely HTTP/1.x request, CAT_UNKNOWN otherwise
static __always_inline __u8 xdp_detect_http1_request(void *data, void *data_end) {
    // Caller must have validated (data + 8) <= data_end before calling
    // This gives us enough for "OPTIONS " (8 chars) + path check needs more
    __u8 *p = data;
    __u8 method_len = 0;

    // Count uppercase ASCII characters (HTTP method: 3-8 chars per RFC)
    // We know we have at least 8 bytes from caller validation
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (xdp_is_uppercase(p[i])) {
            method_len++;
        } else {
            break;
        }
    }

    // Valid method length: 3-8 characters
    // GET=3, PUT=3, HEAD=4, POST=4, PATCH=5, DELETE=6, OPTIONS=7, PROPFIND=8
    if (method_len < 3 || method_len > 8) return CAT_UNKNOWN;

    // For methods < 7 chars, we need method_len + 2 bytes which is < 8 (already validated)
    // For 7-8 char methods (OPTIONS, PROPFIND), we need up to 10 bytes
    // Check additional bounds for longer methods using check-pointer-first pattern
    if (method_len >= 7) {
        __u8 *check_extra = p + method_len + 2;
        asm volatile("" : "+r"(check_extra));  // Barrier: lock in the addition
        if ((void *)check_extra > data_end)
            return CAT_UNKNOWN;
    }

    // Check for SP (0x20) after method
    if (p[method_len] != ' ') return CAT_UNKNOWN;

    // Check for "/" (0x2F) as path start (or "*" for OPTIONS)
    __u8 path_start = p[method_len + 1];
    if (path_start != '/' && path_start != '*') return CAT_UNKNOWN;

    return CAT_PLAIN_HTTP;
}

// XDP helper: Structural protocol classification (priority order)
// Caller MUST validate (payload + 8) <= data_end before calling
// Returns: CAT_TLS_TCP, CAT_H2_PREFACE, CAT_PLAIN_HTTP, or CAT_UNKNOWN
static __always_inline __u8 xdp_classify_protocol(void *payload, void *data_end,
                                                   __u8 *out_tls_type) {
    *out_tls_type = 0;

    // Priority 1: TLS (most common for modern web traffic ~90%)
    __u8 cat = xdp_detect_tls(payload, data_end, out_tls_type);
    if (cat == CAT_TLS_TCP)
        return CAT_TLS_TCP;

    // Priority 2: HTTP/2 preface (binary protocol, distinct from HTTP/1)
    cat = xdp_detect_http2_preface(payload, data_end);
    if (cat == CAT_H2_PREFACE)
        return CAT_H2_PREFACE;

    // Priority 3: HTTP/1.x request line (plaintext)
    cat = xdp_detect_http1_request(payload, data_end);
    if (cat == CAT_PLAIN_HTTP)
        return CAT_PLAIN_HTTP;

    return CAT_UNKNOWN;
}

// XDP helper: Build flow key from packet headers
// Parses: Ethernet → IPv4/IPv6 → TCP
// Returns: 0 on success, -1 if not TCP/IP or malformed
// Takes pre-cached data/data_end pointers to avoid ctx access issues
static __always_inline int xdp_parse_packet_cached(void *data, void *data_end,
                                                    struct flow_key *key,
                                                    void **payload_out, __u16 *payload_len_out,
                                                    __u8 *tcp_flags_out) {

    // Ethernet header (14 bytes)
    struct ethhdr_simple {
        __u8 h_dest[6];
        __u8 h_source[6];
        __be16 h_proto;
    } *eth = data;

    if ((void *)(eth + 1) > data_end)
        return -1;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    void *l3_hdr = (void *)(eth + 1);
    __u8 l4_proto = 0;
    void *l4_hdr = NULL;

    // IPv4 header
    if (eth_proto == ETH_P_IP) {
        struct iphdr_simple {
            __u8  ihl_version;
            __u8  tos;
            __be16 tot_len;
            __be16 id;
            __be16 frag_off;
            __u8  ttl;
            __u8  protocol;
            __be16 check;
            __be32 saddr;
            __be32 daddr;
        } *ip = l3_hdr;

        if ((void *)(ip + 1) > data_end)
            return -1;

        __u8 ihl = (ip->ihl_version & 0x0F) * 4;
        if (ihl < 20 || (void *)ip + ihl > data_end)
            return -1;

        key->saddr = ip->saddr;
        key->daddr = ip->daddr;
        key->ip_version = 4;
        l4_proto = ip->protocol;
        l4_hdr = (void *)ip + ihl;
    }
    // IPv6 header (40 bytes, no extension header parsing)
    else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr_simple {
            __be32 flow_lbl_ver;
            __be16 payload_len;
            __u8   nexthdr;
            __u8   hop_limit;
            __u8   saddr[16];
            __u8   daddr[16];
        } *ip6 = l3_hdr;

        if ((void *)(ip6 + 1) > data_end)
            return -1;

        // Hash IPv6 addresses to 32-bit for flow_key (XOR all 4 dwords)
        // Note: This loses precision but fits in flow_key structure
        __u32 *s = (__u32 *)ip6->saddr;
        __u32 *d = (__u32 *)ip6->daddr;
        if ((void *)(s + 4) > data_end || (void *)(d + 4) > data_end)
            return -1;

        key->saddr = s[0] ^ s[1] ^ s[2] ^ s[3];
        key->daddr = d[0] ^ d[1] ^ d[2] ^ d[3];
        key->ip_version = 6;
        l4_proto = ip6->nexthdr;
        l4_hdr = (void *)(ip6 + 1);
    }
    else {
        return -1;  // Not IPv4/IPv6
    }

    // Only process TCP (UDP/QUIC is stub for now)
    if (l4_proto != IPPROTO_TCP_VAL)
        return -1;

    key->protocol = l4_proto;

    // TCP header (20-60 bytes)
    struct tcphdr_simple {
        __be16 source;
        __be16 dest;
        __be32 seq;
        __be32 ack_seq;
        __u8   doff_res;  // data offset (4 bits) + reserved (4 bits)
        __u8   flags;
        __be16 window;
        __be16 check;
        __be16 urg_ptr;
    } *tcp = l4_hdr;

    if ((void *)(tcp + 1) > data_end)
        return -1;

    key->sport = tcp->source;  // Keep network byte order for map key consistency
    key->dport = tcp->dest;
    key->_pad[0] = 0;
    key->_pad[1] = 0;

    *tcp_flags_out = tcp->flags;

    // TCP header length (data offset field × 4, range 20-60 bytes)
    __u8 tcp_hdr_len = ((tcp->doff_res >> 4) & 0x0F) * 4;
    if (tcp_hdr_len < 20 || tcp_hdr_len > 60)
        return -1;

    void *payload = (void *)tcp + tcp_hdr_len;

    // CRITICAL: Do NOT set payload = data_end as fallback!
    // That contaminates payload with pkt_end() type, causing verifier errors
    // when we later do arithmetic on it.
    if (payload > data_end) {
        // TCP header extends beyond packet - malformed
        *payload_out = payload;  // Won't be accessed due to 0 length
        *payload_len_out = 0;
        return 0;  // Still return success so we track the flow
    }

    *payload_out = payload;

    // Calculate payload length (bounded to u16)
    __u64 plen = (__u64)data_end - (__u64)payload;
    *payload_len_out = plen > 0xFFFF ? 0xFFFF : (__u16)plen;

    return 0;
}

// XDP helper: Infer direction from port numbers (heuristic for mid-capture)
// Low port (< 1024) is typically server; high port is typically client
static __always_inline __u8 xdp_infer_direction(__u16 sport_net, __u16 dport_net) {
    __u16 sport = bpf_ntohs(sport_net);
    __u16 dport = bpf_ntohs(dport_net);

    // Well-known ports (< 1024): server side
    if (dport < 1024 && sport >= 1024)
        return 1;  // Client → Server
    if (sport < 1024 && dport >= 1024)
        return 2;  // Server → Client
    // Ephemeral range heuristic: higher port is usually client
    if (sport > dport)
        return 1;  // Client → Server (guessing client has higher port)
    if (dport > sport)
        return 2;  // Server → Client

    return 0;  // Unknown
}

// Main XDP program - Protocol detection and flow tracking
// Attach to network interfaces for packet-level visibility
SEC("xdp")
int xdp_flow_tracker(struct xdp_md *ctx) {
    // =========================================================================
    // CRITICAL: Cache ALL ctx fields at the VERY START - never touch ctx again
    // The BPF verifier forbids accessing ctx through modified pointers.
    // If we re-read ctx later, the compiler may optimize using offset math.
    // =========================================================================
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len = (__u32)(data_end - data);
    __u32 ifindex = ctx->ingress_ifindex;

    __u32 zero = 0;

    // Get stats counter (per-CPU, no lock contention)
    struct xdp_stats *stats = bpf_map_lookup_elem(&xdp_stats_map, &zero);
    if (stats)
        stats->packets_total++;

    // Parse packet headers into flow key
    struct flow_key fkey = {};
    void *payload = NULL;
    __u16 payload_len = 0;
    __u8 tcp_flags = 0;

    if (xdp_parse_packet_cached(data, data_end, &fkey, &payload, &payload_len, &tcp_flags) < 0)
        return XDP_PASS;  // Not TCP/IP, pass through

    if (stats)
        stats->packets_tcp++;

    __u64 now = bpf_ktime_get_ns();

    // Look up existing flow state by 5-tuple
    struct flow_state *fs = bpf_map_lookup_elem(&flow_states, &fkey);

    // =========================================================================
    // Stage 1: Connection Lifecycle (SYN/FIN/RST)
    // =========================================================================

    // New connection: SYN without ACK
    if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
        struct flow_state new_fs = {
            .socket_cookie = 0,       // Not available until data packet
            .first_seen_ns = now,
            .last_seen_ns = now,
            .pkt_count = 1,
            .byte_count = payload_len,
            .category = CAT_UNKNOWN,
            .state = FLOW_STATE_PENDING,
            .direction = 1,           // SYN sender is client
            .flags = 0,
        };
        bpf_map_update_elem(&flow_states, &fkey, &new_fs, BPF_ANY);

        if (stats)
            stats->flows_created++;

        return XDP_PASS;
    }

    // Connection termination: FIN or RST
    if (tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST)) {
        if (fs && fs->socket_cookie != 0) {
            // Emit termination event for userspace cleanup
            struct xdp_packet_event *evt = bpf_map_lookup_elem(&xdp_event_heap, &zero);
            if (evt) {
                evt->timestamp_ns = now;
                evt->socket_cookie = fs->socket_cookie;
                __builtin_memcpy(&evt->flow, &fkey, sizeof(fkey));
                evt->pkt_len = pkt_len;
                evt->ifindex = ifindex;
                evt->event_type = EVENT_XDP_PACKET;
                evt->payload_off = 0;
                evt->category = fs->category;
                evt->tls_type = 0;
                evt->direction = fs->direction;
                evt->tcp_flags = tcp_flags;
                evt->_pad[0] = 0;
                evt->_pad[1] = 0;

                long ret = bpf_ringbuf_output(&xdp_events, evt, sizeof(*evt), 0);
                if (ret < 0 && stats)
                    stats->ringbuf_drops++;
            }

            fs->flags |= FLOW_FLAG_TERMINATED;
            fs->last_seen_ns = now;

            if (stats)
                stats->flows_terminated++;
        }
        return XDP_PASS;
    }

    // =========================================================================
    // Stage 2: Gatekeeper - Silenced Sessions Fast-Pass
    // =========================================================================

    if (fs && fs->socket_cookie != 0) {
        struct session_policy *policy = bpf_map_lookup_elem(&session_registry, &fs->socket_cookie);
        if (policy) {
            // Update stats (approximate, no atomic)
            fs->pkt_count++;
            fs->byte_count += payload_len;
            fs->last_seen_ns = now;

            if (policy->silenced) {
                // FAST PATH: Already classified and silenced
                // Zero-cost processing - just update counters and pass
                if (stats)
                    stats->gatekeeper_hits++;
                return XDP_PASS;
            }
            // Policy exists but not silenced - still in classification window
            // Fall through to check if we need to emit event
        }
    }

    // =========================================================================
    // Stage 3: Protocol Classification (First Data Packet)
    // =========================================================================

    // Skip classification if no payload
    if (payload_len == 0) {
        if (fs) {
            fs->pkt_count++;
            fs->last_seen_ns = now;
        }
        return XDP_PASS;
    }

    // -------------------------------------------------------------------------
    // CRITICAL: Bounds validation BEFORE map lookups (verifier state is clean)
    // The verifier loses pointer tracking across map lookups, so we must
    // validate payload access here while it can still track the bounds.
    // NOTE: Use 'data_end' cached at function start - never re-read ctx
    // -------------------------------------------------------------------------

    // Validate we can access at least 8 bytes (max needed for HTTP/2 preface)
    // CRITICAL: Compute check pointer FIRST, then barrier, then compare.
    // This prevents Clang from inverting "ptr + N <= end" to "end - ptr >= N"
    // which would do arithmetic on pkt_end (prohibited by verifier).
    __u8 tls_type = 0;
    __u8 category = CAT_UNKNOWN;
    __u8 *pld = (__u8 *)payload;

    // Check for 8 bytes (HTTP/2 preface detection)
    __u8 *check8 = pld + 8;
    asm volatile("" : "+r"(check8));  // Barrier: lock in the addition
    if ((void *)check8 <= data_end) {
        // Full classification possible - we have at least 8 bytes
        category = xdp_classify_protocol(pld, data_end, &tls_type);
    } else {
        // Check for 5 bytes (TLS record header)
        __u8 *check5 = pld + 5;
        asm volatile("" : "+r"(check5));  // Barrier: lock in the addition
        if ((void *)check5 <= data_end) {
            // Can check TLS (5 bytes) but not HTTP/2 preface (8 bytes)
            category = xdp_detect_tls(pld, data_end, &tls_type);
        }
    }
    // else: payload too small to classify, leave as CAT_UNKNOWN

    // -------------------------------------------------------------------------
    // Now safe to do map lookups (classification already done above)
    // -------------------------------------------------------------------------

    // Get socket cookie from sock_ops cache (the "Golden Thread")
    // sock_ops program caches cookies when connections are established
    // because bpf_get_socket_cookie() is NOT available in XDP context.
    // Userspace warm-up seeds this map with existing connections at startup.
    __u64 cookie = 0;

    struct flow_cookie_entry *cookie_entry = bpf_map_lookup_elem(&flow_cookie_map, &fkey);
    if (cookie_entry) {
        cookie = cookie_entry->socket_cookie;
    } else {
        // Cookie not cached yet - sock_ops may not have run for this flow
        // This happens for: mid-connection captures, packets before socket setup,
        // or connections established before program attachment.
        // Classification still works, but correlation with uprobes limited.
        if (stats)
            stats->cookie_failures++;
    }

    // Determine if userspace PCRE2-JIT is needed for ambiguous traffic
    bool needs_pcre2 = (category == CAT_UNKNOWN && payload_len >= 4);
    bool is_new_classification = false;

    // Update or create flow state
    if (!fs) {
        // New flow without SYN (mid-connection capture or missed SYN)
        struct flow_state new_fs = {
            .socket_cookie = cookie,
            .first_seen_ns = now,
            .last_seen_ns = now,
            .pkt_count = 1,
            .byte_count = payload_len,
            .category = category,
            .state = (category != CAT_UNKNOWN) ? FLOW_STATE_CLASSIFIED : FLOW_STATE_AMBIGUOUS,
            .direction = xdp_infer_direction(fkey.sport, fkey.dport),
            .flags = needs_pcre2 ? FLOW_FLAG_NEEDS_PCRE2 : 0,
        };
        bpf_map_update_elem(&flow_states, &fkey, &new_fs, BPF_ANY);
        fs = bpf_map_lookup_elem(&flow_states, &fkey);

        if (stats)
            stats->flows_created++;

        is_new_classification = (category != CAT_UNKNOWN);
    } else if (fs->state == FLOW_STATE_PENDING) {
        // First data packet on pending flow - classify now
        fs->socket_cookie = cookie;
        fs->category = category;
        fs->state = (category != CAT_UNKNOWN) ? FLOW_STATE_CLASSIFIED : FLOW_STATE_AMBIGUOUS;
        fs->flags = needs_pcre2 ? FLOW_FLAG_NEEDS_PCRE2 : 0;
        fs->pkt_count++;
        fs->byte_count += payload_len;
        fs->last_seen_ns = now;

        is_new_classification = (category != CAT_UNKNOWN);
    } else {
        // Existing classified/ambiguous flow - update stats only
        fs->pkt_count++;
        fs->byte_count += payload_len;
        fs->last_seen_ns = now;

        // Don't re-emit if already classified and not needing PCRE2
        if (fs->state == FLOW_STATE_CLASSIFIED && !needs_pcre2)
            return XDP_PASS;
    }

    // Update stats
    if (stats) {
        if (is_new_classification)
            stats->flows_classified++;
        if (needs_pcre2)
            stats->flows_ambiguous++;
    }

    // =========================================================================
    // Stage 4: Event Emission (Discovery / Ambiguous)
    // =========================================================================

    // Only emit if: newly classified OR needs PCRE2-JIT analysis
    if (!is_new_classification && !needs_pcre2)
        return XDP_PASS;

    // Use cached 'data_end' from function start - never re-read ctx
    long ret = 0;

    if (needs_pcre2 && payload_len > 0) {
        // Get scratch buffer from heap first
        struct xdp_payload_event *pevt = bpf_map_lookup_elem(&xdp_payload_heap, &zero);
        if (!pevt)
            return XDP_PASS;  // CRITICAL: must check immediately

        // Fill event metadata
        pevt->timestamp_ns = now;
        pevt->socket_cookie = cookie;
        __builtin_memcpy(&pevt->flow, &fkey, sizeof(fkey));
        pevt->event_type = EVENT_XDP_PACKET;
        pevt->category = category;
        pevt->_pad[0] = 0;
        pevt->_pad[1] = 0;
        pevt->_pad[2] = 0;

        // Zero-init destination first
        __builtin_memset(pevt->payload, 0, XDP_PAYLOAD_MAX);

        // Bounds check using the check-pointer-first pattern
        // Compute check pointer, barrier, then compare (no arithmetic on data_end)
        __u8 *src = (__u8 *)payload;
        __u8 *check_max = src + XDP_PAYLOAD_MAX;
        asm volatile("" : "+r"(check_max));  // Barrier: lock in the addition

        if ((void *)check_max <= data_end) {
            // Unrolled copy - verifier tracks each index
            pevt->payload_len = XDP_PAYLOAD_MAX;
            #pragma unroll
            for (int i = 0; i < XDP_PAYLOAD_MAX; i++) {
                pevt->payload[i] = src[i];
            }
        } else {
            // Payload smaller than max - can't copy safely
            // Just report what we have (payload stays zeroed)
            pevt->payload_len = 0;
        }

        ret = bpf_ringbuf_output(&xdp_events, pevt, sizeof(*pevt), 0);
    } else if (is_new_classification) {
        // Send metadata-only discovery event
        struct xdp_packet_event *evt = bpf_map_lookup_elem(&xdp_event_heap, &zero);
        if (evt) {
            evt->timestamp_ns = now;
            evt->socket_cookie = cookie;
            __builtin_memcpy(&evt->flow, &fkey, sizeof(fkey));
            evt->pkt_len = pkt_len;
            evt->ifindex = ifindex;
            evt->event_type = EVENT_XDP_PACKET;
            evt->category = category;
            evt->tls_type = tls_type;
            evt->direction = fs ? fs->direction : 0;
            evt->tcp_flags = tcp_flags;
            evt->_pad[0] = 0;
            evt->_pad[1] = 0;

            // Calculate payload offset (payload ptr was validated during parsing)
            evt->payload_off = (__u8 *)payload - (__u8 *)data;

            ret = bpf_ringbuf_output(&xdp_events, evt, sizeof(*evt), 0);
        }
    }

    if (ret < 0 && stats)
        stats->ringbuf_drops++;

    return XDP_PASS;
}

// =============================================================================
// SOCK_OPS Program - Socket Cookie Caching for XDP Correlation
// =============================================================================
//
// Why SOCK_OPS?
// - bpf_get_socket_cookie() requires socket context (NOT available in XDP)
// - sock_ops runs at TCP connection establishment (socket fully ready)
// - We cache the cookie here so XDP can look it up later
//
// Flow:
//   1. TCP connection established → kernel calls sock_ops
//   2. sock_ops extracts socket_cookie → stores in flow_cookie_map
//   3. Packet arrives → XDP looks up cookie from flow_cookie_map
//   4. XDP correlates with uprobe SSL data via cookie ("Golden Thread")
//
// Operations we handle:
//   - BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB (server accepted connection)
//   - BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB (client initiated connection)
//   - BPF_SOCK_OPS_STATE_CB (connection state change - for cleanup on close)
//
// TCP states for STATE_CB (from include/net/tcp_states.h):
#define TCP_ESTABLISHED  1
#define TCP_CLOSE        7
#define TCP_CLOSE_WAIT   8
#define TCP_LAST_ACK     9
#define TCP_FIN_WAIT1   10
#define TCP_FIN_WAIT2   11
#define TCP_TIME_WAIT   12

SEC("sockops")
int sockops_cache_cookie(struct bpf_sock_ops *skops) {
    bool is_cleanup = false;

    switch (skops->op) {
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:  // Server side: accept() completed
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:   // Client side: connect() completed
        break;
    case BPF_SOCK_OPS_STATE_CB: {
        // Connection state change - clean up on close
        // args[0] = old_state, args[1] = new_state
        __u32 new_state = skops->args[1];
        if (new_state != TCP_CLOSE && new_state != TCP_CLOSE_WAIT &&
            new_state != TCP_TIME_WAIT) {
            return 0;  // Not a close event
        }
        is_cleanup = true;
        break;
    }
    default:
        return 0;  // Ignore other socket operations
    }

    // Build flow key from sock_ops context
    // sock_ops uses local/remote from the socket's perspective
    struct flow_key fkey = {};

    if (skops->family == AF_INET) {
        // IPv4: Use local/remote addresses
        // For PASSIVE (server): local=server, remote=client
        // For ACTIVE (client): local=client, remote=server
        fkey.saddr = skops->remote_ip4;  // Remote IP
        fkey.daddr = skops->local_ip4;   // Local IP
        fkey.sport = bpf_ntohl(skops->remote_port) >> 16;  // Remote port (in high 16 bits)
        fkey.dport = skops->local_port;  // Local port (already in host order)
        fkey.ip_version = 4;

        // sock_ops ports need conversion: remote_port is in network order in high 16 bits
        // local_port is in host order
        // We need network byte order for the flow key to match XDP
        fkey.sport = bpf_htons(fkey.sport);
        fkey.dport = bpf_htons(fkey.dport);
    } else if (skops->family == AF_INET6) {
        // IPv6: XOR-hash the 128-bit addresses into 32 bits
        // Same algorithm as XDP uses for IPv6 flows
        fkey.saddr = skops->remote_ip6[0] ^ skops->remote_ip6[1] ^
                     skops->remote_ip6[2] ^ skops->remote_ip6[3];
        fkey.daddr = skops->local_ip6[0] ^ skops->local_ip6[1] ^
                     skops->local_ip6[2] ^ skops->local_ip6[3];
        fkey.sport = bpf_ntohl(skops->remote_port) >> 16;
        fkey.dport = skops->local_port;
        fkey.ip_version = 6;

        fkey.sport = bpf_htons(fkey.sport);
        fkey.dport = bpf_htons(fkey.dport);
    } else {
        return 0;  // Unknown address family
    }

    fkey.protocol = IPPROTO_TCP_VAL;

    // Build reverse flow key (for bidirectional handling)
    struct flow_key reverse_fkey = {
        .saddr = fkey.daddr,
        .daddr = fkey.saddr,
        .sport = fkey.dport,
        .dport = fkey.sport,
        .protocol = IPPROTO_TCP_VAL,
        .ip_version = fkey.ip_version
    };

    if (is_cleanup) {
        // Delete flow entries on connection close
        bpf_map_delete_elem(&flow_cookie_map, &fkey);
        bpf_map_delete_elem(&flow_cookie_map, &reverse_fkey);
        return 0;
    }

    // Get socket cookie for new connections
    __u64 socket_cookie = bpf_get_socket_cookie(skops);
    if (socket_cookie == 0) {
        return 0;
    }

    // Cache the cookie for XDP to look up later
    struct flow_cookie_entry entry = {
        .socket_cookie = socket_cookie,
        .timestamp_ns = bpf_ktime_get_ns()
    };

    bpf_map_update_elem(&flow_cookie_map, &fkey, &entry, BPF_ANY);
    bpf_map_update_elem(&flow_cookie_map, &reverse_fkey, &entry, BPF_ANY);

    return 0;  // Success
}

char LICENSE[] SEC("license") = "GPL";
