/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * sslsniff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 sslsniff authors
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
 * sslsniff.bpf.c - eBPF probes for SSL/TLS interception
 * Supports OpenSSL, GnuTLS, and NSS (via NSPR)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_BUF_SIZE 16384
#define TASK_COMM_LEN 16

// Event types
#define EVENT_SSL_READ  0
#define EVENT_SSL_WRITE 1
#define EVENT_HANDSHAKE 2

// Data structure for SSL events
struct ssl_data_event {
    __u64 timestamp_ns;
    __u64 delta_ns;       // Latency (for handshake or request-response)
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
    __u64 buf_ptr;        // Buffer pointer
    __u32 len;            // Requested length
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

// Separate map for handshake start times (to avoid race with read/write)
// Key: tid (thread ID)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // tid
    __type(value, __u64); // start timestamp
} handshake_start_ns SEC(".maps");

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ssl_events SEC(".maps");

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

// =============================================================================
// SSL Read/Write Entry Probe
// Called for: SSL_read, SSL_write, gnutls_record_recv, gnutls_record_send,
//             PR_Read, PR_Write, PR_Recv, PR_Send
// =============================================================================

SEC("uprobe/ssl_rw_enter")
int BPF_UPROBE(probe_ssl_rw_enter, void *ssl_ctx, void *buf, int num) {
    __u32 tid = get_tid();
    
    // Save buffer address and length for the exit probe
    struct ssl_args args = {
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
    __u64 ts = bpf_ktime_get_ns();

    // Use separate map to avoid race with SSL_read/SSL_write during handshake
    bpf_map_update_elem(&handshake_start_ns, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("uretprobe/ssl_handshake_exit")
int BPF_URETPROBE(probe_ssl_handshake_exit) {
    __u32 tid = get_tid();
    __u32 zero = 0;

    // Lookup start timestamp from handshake-specific map
    __u64 *tsp = bpf_map_lookup_elem(&handshake_start_ns, &tid);
    if (!tsp) {
        return 0;
    }

    // Get return value
    int ret = PT_REGS_RC((struct pt_regs *)ctx);

    // Get event buffer
    struct ssl_data_event *event = bpf_map_lookup_elem(&ssl_data_heap, &zero);
    if (!event) {
        bpf_map_delete_elem(&handshake_start_ns, &tid);
        return 0;
    }

    // Fill metadata
    fill_event_metadata(event);
    event->event_type = EVENT_HANDSHAKE;
    event->len = (__u32)ret;  // Store return value (1=success, 0/-1=fail)
    event->buf_filled = 0;
    event->delta_ns = event->timestamp_ns - *tsp;

    // Submit event (small, no buffer data) - use fixed size for verifier
    bpf_ringbuf_output(&ssl_events, event, sizeof(struct ssl_data_event) - MAX_BUF_SIZE, 0);

    // Cleanup
    bpf_map_delete_elem(&handshake_start_ns, &tid);

    return 0;
}

// =============================================================================
// GnuTLS Probes
// For: gnutls_record_send, gnutls_record_recv
// =============================================================================

SEC("uprobe/gnutls_send_enter")
int BPF_UPROBE(probe_gnutls_send_enter, void *session, void *buf, size_t num) {
    __u32 tid = get_tid();

    // Save buffer address and length for the exit probe
    struct ssl_args args = {
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

    // Save buffer address and length for the exit probe
    struct ssl_args args = {
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

    // Save buffer address and length for the exit probe
    struct ssl_args args = {
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

    // Save buffer address and length for the exit probe
    struct ssl_args args = {
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

char LICENSE[] SEC("license") = "GPL";
