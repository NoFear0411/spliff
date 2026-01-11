# XDP & High-Performance Packet Processing Plan

**Status:** Planning / Research
**Target Version:** 0.7.0 (after HTTP/3 support)
**Last Updated:** 2026-01-11
**Prerequisite:** HTTP/3+QUIC implementation (v0.6.0)

---

## Executive Summary

This document outlines a comprehensive high-performance architecture for spliff that supports multiple packet capture modes from development to 100Gbps production environments. The design creates a **Dual-View Visibility** system:

- **Packet Layer (XDP/DPDK)**: Raw encrypted packets, timing, metadata, protocol detection
- **Application Layer (Uprobes)**: Decrypted plaintext content

Key features:
- **Content-based protocol detection** (not port-based)
- **Dynamic port learning** via Alt-Svc headers
- **Multi-threaded lock-free architecture**
- **Tiered deployment modes**: Kernel → XDP → AF_XDP → DPDK
- **100Gbps capable** with DPDK mode

---

## Table of Contents

- [Design Rationale](#design-rationale) - Key Q&A and design decisions
  - [Why XDP for HTTP Protocol Detection?](#why-xdp-for-http-protocol-detection)
  - [Why Content-Based Detection?](#why-content-based-detection-instead-of-port-based)
  - [Why This Threading Model?](#why-this-threading-model)
  - [Why Multiple Deployment Modes?](#why-support-multiple-deployment-modes)

1. [Architecture Overview](#1-architecture-overview)
2. [Deployment Modes](#2-deployment-modes)
3. [Content-Based Protocol Detection](#3-content-based-protocol-detection)
4. [Dynamic Port Learning (Alt-Svc)](#4-dynamic-port-learning-alt-svc)
5. [Multi-Threaded Architecture](#5-multi-threaded-architecture)
6. [Lock-Free Data Structures](#6-lock-free-data-structures)
7. [Adaptive Wait Strategy](#7-adaptive-wait-strategy)
8. [XDP Implementation](#8-xdp-implementation)
9. [AF_XDP Implementation](#9-af_xdp-implementation)
10. [DPDK Implementation](#10-dpdk-implementation)
11. [Flow Correlation](#11-flow-correlation)
12. [Memory Management](#12-memory-management)
13. [Implementation Phases](#13-implementation-phases)
14. [Dependencies](#14-dependencies)
15. [CLI Interface](#15-cli-interface)
16. [Challenges and Limitations](#16-challenges-and-limitations)
17. [References](#17-references)

---

## Design Rationale

This section captures the key questions and design decisions made during planning.

### Why XDP for HTTP Protocol Detection?

**Question**: How can XDP help with HTTP/3+QUIC and improve detection/parsing of all H1, H2, H3 protocols?

**Answer**: XDP provides **early protocol detection** before the application even completes the TLS/QUIC handshake. The key insight is that TLS and QUIC handshakes contain **unencrypted metadata**:

| Protocol | Transport | What XDP Can Extract (Unencrypted) |
|----------|-----------|-----------------------------------|
| HTTP/1.1 | TCP+TLS | SNI, ALPN from TLS ClientHello |
| HTTP/2 | TCP+TLS | SNI, ALPN from TLS ClientHello |
| HTTP/3 | QUIC (UDP) | QUIC version, Connection IDs, SNI/ALPN from CRYPTO frame |

**Benefits for each protocol:**

- **HTTP/1.1 & HTTP/2**: XDP parses TLS ClientHello to extract ALPN (`h2` vs `http/1.1`). We know which parser to use before `SSL_read` even fires.
- **HTTP/3**: XDP extracts QUIC Connection IDs from Initial packets. This enables session tracking across IP migration (mobile switching from WiFi to LTE).

### Why Content-Based Detection Instead of Port-Based?

**Question**: How do we handle `Alt-Svc: h3=":8443"` headers that specify non-standard ports?

**Answer**: Port 443 is **not reliable** for protocol detection:
- `alt-svc: h3=":8443"; ma=86400` redirects H3 to port 8443
- `alt-svc: h3="alt.example.com:443"` redirects to different host
- Internal services use arbitrary ports

**Solution**: Monitor **all connections** with XDP, detect protocols by **content signatures**, then categorize. This creates a feedback loop:

1. XDP detects TLS on any port
2. Uprobe captures HTTP response with Alt-Svc header
3. User-space parses Alt-Svc, extracts advertised H3 ports
4. Updates BPF map with learned ports
5. XDP now knows those ports are H3

### Why This Threading Model?

**Question**: What about thread pool libraries like pthreads vs CK + liburcu? How do we account for CPU usage, thread latency from wake-ups, and context switches when task execution time is unpredictable?

**Answer**: We analyzed three strategies:

**Strategy 1: Pure Spin-Wait (ck_ring polling only)**
```c
while (running) {
    if (ck_ring_dequeue(...)) process();
    __builtin_ia32_pause();  // Still burns CPU
}
```
- Latency: Excellent (< 100ns)
- CPU when idle: **Terrible (100%)**
- Use case: Dedicated packet processing cores (DPDK-style)

**Strategy 2: Pure Blocking (pthread_cond_wait)**
```c
while (running) {
    pthread_mutex_lock(&mutex);
    while (queue_empty) pthread_cond_wait(&cond, &mutex);
    item = dequeue();
    pthread_mutex_unlock(&mutex);
    process(item);
}
```
- Latency: Poor (1-10 μs due to mutex contention)
- CPU when idle: **Excellent (~0%)**
- Use case: Low-throughput, power-sensitive

**Strategy 3: Hybrid Adaptive (Recommended)**
```
Phase 1: Spin (1000 iterations, ~1-2 μs)
    ↓ no work
Phase 2: Yield (10 iterations, ~10-100 μs)
    ↓ still no work
Phase 3: Sleep on eventfd (poll with 10ms timeout)
```
- Latency under load: Excellent (< 100ns, spinning)
- Latency idle→busy: Good (1-2 μs, eventfd wake)
- CPU when idle: Good (~2%)
- Context switches: Low (only when truly idle)

**Why this combination:**
- **CK rings**: Lock-free, wait-free enqueue/dequeue
- **eventfd**: Efficient kernel-assisted wake-up (vs busy polling)
- **liburcu**: Zero-overhead reads for shared flow tables
- **jemalloc**: Multi-thread optimized memory allocation

### Threading Strategy Comparison

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LATENCY BREAKDOWN BY WORKER STATE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Worker is SPINNING (Phase 1):                                              │
│  ├── ck_ring_dequeue: ~20-50 ns                                            │
│  ├── No syscall, no context switch                                         │
│  └── Total latency: < 100 ns                                               │
│                                                                             │
│  Worker is YIELDING (Phase 2):                                              │
│  ├── sched_yield latency: ~1-5 μs                                          │
│  ├── May need to wait for scheduler                                        │
│  └── Total latency: 1-10 μs                                                │
│                                                                             │
│  Worker is SLEEPING (Phase 3):                                              │
│  ├── eventfd write (producer): ~100-200 ns                                 │
│  ├── Kernel wake-up: ~2-5 μs                                               │
│  ├── Context switch: ~2-10 μs                                              │
│  ├── poll() return: ~1-2 μs                                                │
│  └── Total latency: 5-50 μs                                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### CPU Usage Analysis

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CPU USAGE BY TRAFFIC RATE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Traffic: 0 events/sec (IDLE)                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Pure Spin:      ████████████████████████████████████████  100%      │  │
│  │  Adaptive:       ██                                          ~2%      │  │
│  │  Pure Blocking:  █                                           ~0%      │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  Traffic: 100K events/sec (MODERATE)                                       │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Pure Spin:      ████████████████████████████████████████  100%      │  │
│  │  Adaptive:       ████████████████                            40%      │  │
│  │  Pure Blocking:  ██████████████████████                      55%      │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  Traffic: 1M events/sec (HIGH)                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Pure Spin:      ████████████████████████████████████████  100%      │  │
│  │  Adaptive:       ██████████████████████████████████          85%      │  │
│  │  Pure Blocking:  ████████████████████████████████████████    95%      │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why Support Multiple Deployment Modes?

**Question**: What if we need to support 100Gbps with DPDK?

**Answer**: Different environments have different requirements:

| Environment | Bandwidth | Best Mode | Why |
|-------------|-----------|-----------|-----|
| Development laptop | < 1 Gbps | kernel | Easy setup, no special config |
| Cloud VM | 1-10 Gbps | xdp (generic) | No driver control, works everywhere |
| Production server | 10-40 Gbps | xdp (native) or af_xdp | Good performance, kernel features work |
| High-frequency trading | 40-100 Gbps | dpdk | Lowest latency, dedicated cores |
| Carrier/ISP | 100+ Gbps | dpdk | Only option at this scale |

**DPDK trade-offs:**
- Pro: 100+ Gbps line rate, sub-microsecond latency
- Con: Kernel bypass means no iptables, no routing, dedicated cores (100% CPU)
- Con: Complex setup (huge pages, vfio-pci driver binding)

---

## 1. Architecture Overview

### Unified Dual-Path Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              NETWORK INTERFACE                               │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        │                             │                             │
        ▼                             ▼                             ▼
┌───────────────┐           ┌───────────────┐           ┌───────────────┐
│  DPDK Mode    │           │  XDP/AF_XDP   │           │  Kernel Mode  │
│  (100+ Gbps)  │           │  (10-50 Gbps) │           │  (1-5 Gbps)   │
│               │           │               │           │               │
│  PMD polling  │           │  eBPF in      │           │  Raw sockets  │
│  Kernel bypass│           │  kernel/      │           │  Standard I/O │
│  Huge pages   │           │  zero-copy    │           │               │
└───────┬───────┘           └───────┬───────┘           └───────┬───────┘
        │                           │                           │
        └─────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     CONTENT-BASED PROTOCOL DETECTION                         │
│                                                                             │
│  Detect by CONTENT, not port:                                               │
│  • TLS: Record header 0x16 0x03 0x0X                                        │
│  • QUIC: Long header (0x80+), version field                                 │
│  • Plain HTTP: "GET ", "POST", "HTTP/"                                      │
│  • HTTP/2 Preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TRAFFIC CATEGORIZATION                               │
│                                                                             │
│  CAT_WEB_TLS_TCP   - HTTP/1.1 or H2 over TLS (TCP)                         │
│  CAT_WEB_QUIC      - HTTP/3 over QUIC (UDP)                                │
│  CAT_WEB_PLAIN     - Unencrypted HTTP                                       │
│  CAT_GRPC          - gRPC (detected via content-type)                       │
│  CAT_WEBSOCKET     - WebSocket (detected via upgrade)                       │
│  CAT_OTHER_TLS     - TLS but not HTTP                                       │
│  CAT_UNKNOWN       - Unclassified                                           │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FLOW-AFFINITY DISPATCHER                                  │
│                                                                             │
│  worker_id = hash(flow_key) % num_workers                                   │
│  Same flow ALWAYS goes to same worker → No locks for session state          │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
           ┌──────────────────────────┼──────────────────────────┐
           ▼                          ▼                          ▼
    ┌─────────────┐           ┌─────────────┐           ┌─────────────┐
    │  Worker #0  │           │  Worker #1  │           │  Worker #N  │
    │             │           │             │           │             │
    │ Lock-free   │           │ Lock-free   │           │ Lock-free   │
    │ input ring  │           │ input ring  │           │ input ring  │
    │ (ck_ring)   │           │ (ck_ring)   │           │ (ck_ring)   │
    │             │           │             │           │             │
    │ Thread-local│           │ Thread-local│           │ Thread-local│
    │ sessions    │           │ sessions    │           │ sessions    │
    │ (H1/H2/H3)  │           │ (H1/H2/H3)  │           │ (H1/H2/H3)  │
    │             │           │             │           │             │
    │ eventfd for │           │ eventfd for │           │ eventfd for │
    │ wake-up     │           │ wake-up     │           │ wake-up     │
    └─────────────┘           └─────────────┘           └─────────────┘
           │                          │                          │
           └──────────────────────────┼──────────────────────────┘
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FLOW CORRELATOR                                           │
│                                                                             │
│  Match encrypted packets (XDP/DPDK) with decrypted data (Uprobes)           │
│  Calculate decryption latency, detect unhooked traffic                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         OUTPUT THREAD                                        │
│                                                                             │
│  • Format output (colors, JSON)                                              │
│  • Parse Alt-Svc → update BPF maps (feedback loop)                          │
│  • Write to stdout/file                                                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Parallel Path: Uprobe Capture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    APPLICATION (curl, Firefox, etc.)                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SSL LIBRARY (OpenSSL, NSS, GnuTLS, WolfSSL)               │
│                                                                             │
│                         ┌─────────────────┐                                 │
│                         │ SSL_read/write  │ ← Uprobe attached               │
│                         └────────┬────────┘                                 │
└──────────────────────────────────┼──────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    eBPF RING BUFFER                                          │
│                    (Decrypted plaintext events)                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    INGESTION THREAD                                          │
│                    → Flow-affinity dispatch to workers                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Deployment Modes

### Mode Comparison

| Mode | Throughput | Latency | CPU Usage | Deployment | Use Case |
|------|------------|---------|-----------|------------|----------|
| **kernel** | 1-5 Gbps | 10-50 μs | Low | Easy | Development, testing |
| **xdp** | 10-25 Gbps | 2-10 μs | Medium | Moderate | Production, general use |
| **af_xdp** | 25-50 Gbps | 1-5 μs | Medium-High | Moderate | High-performance |
| **dpdk** | 100+ Gbps | 100-500 ns | Dedicated cores | Complex | Extreme performance |

### Mode Selection Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MODE SELECTION GUIDE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Traffic Rate?                                                              │
│       │                                                                     │
│       ├── < 5 Gbps ──────────────────────────► kernel mode                 │
│       │                                        (--mode kernel)              │
│       │                                                                     │
│       ├── 5-25 Gbps ─────────────────────────► xdp mode                    │
│       │                                        (--mode xdp)                 │
│       │                                                                     │
│       ├── 25-50 Gbps ────────────────────────► af_xdp mode                 │
│       │                                        (--mode af_xdp)              │
│       │                                                                     │
│       └── > 50 Gbps ─────────────────────────► dpdk mode                   │
│                                                (--mode dpdk)                │
│                                                                             │
│  Special Considerations:                                                    │
│  • Cloud VM (no driver control) → xdp generic                              │
│  • Bare metal with Intel/Mellanox → dpdk                                   │
│  • Need kernel features (iptables) → xdp or af_xdp                         │
│  • Maximum latency sensitivity → dpdk                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Content-Based Protocol Detection

### Why Content-Based?

Port 443 is not reliable:
- Alt-Svc can redirect H3 to any port (e.g., `alt-svc: h3=":8443"`)
- Internal services may use non-standard ports
- Some applications use TLS on custom ports

### Detection Logic

```c
typedef enum {
    CAT_UNKNOWN = 0,
    CAT_WEB_TLS_TCP,      // HTTP/1.1 or H2 over TLS
    CAT_WEB_QUIC,         // HTTP/3 over QUIC
    CAT_WEB_PLAIN,        // Unencrypted HTTP
    CAT_GRPC,             // gRPC
    CAT_WEBSOCKET,        // WebSocket
    CAT_OTHER_TLS,        // TLS but not HTTP
    CAT_DNS_DOH,          // DNS over HTTPS
    CAT_DNS_DOQ,          // DNS over QUIC
} traffic_category_t;

// Detect protocol from TCP payload
static inline traffic_category_t detect_tcp_protocol(
    const uint8_t *payload, size_t len) {

    if (len < 6) return CAT_UNKNOWN;

    // TLS Record Header: ContentType(1) + Version(2) + Length(2)
    // ContentType 0x16 = Handshake, 0x17 = Application Data
    if (payload[0] == 0x16 && payload[1] == 0x03 && payload[2] <= 0x04) {
        return CAT_WEB_TLS_TCP;  // TLS Handshake
    }

    if (payload[0] == 0x17 && payload[1] == 0x03) {
        return CAT_WEB_TLS_TCP;  // TLS Application Data
    }

    // Plain HTTP detection
    if (len >= 4) {
        if (memcmp(payload, "GET ", 4) == 0 ||
            memcmp(payload, "POST", 4) == 0 ||
            memcmp(payload, "PUT ", 4) == 0 ||
            memcmp(payload, "HEAD", 4) == 0 ||
            memcmp(payload, "HTTP", 4) == 0) {
            return CAT_WEB_PLAIN;
        }
    }

    // HTTP/2 Preface (24 bytes)
    if (len >= 24 && memcmp(payload, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) {
        return CAT_WEB_PLAIN;  // H2 cleartext (rare)
    }

    return CAT_UNKNOWN;
}

// Detect protocol from UDP payload
static inline traffic_category_t detect_udp_protocol(
    const uint8_t *payload, size_t len,
    uint16_t sport, uint16_t dport) {

    if (len < 5) return CAT_UNKNOWN;

    // QUIC Long Header: first bit set (0x80+)
    if (payload[0] & 0x80) {
        // Extract version (bytes 1-4)
        uint32_t version = (payload[1] << 24) | (payload[2] << 16) |
                           (payload[3] << 8) | payload[4];

        // QUIC v1: 0x00000001, QUIC v2: 0x6b3343cf
        // Draft versions: 0xff0000XX
        if (version == 0x00000001 || version == 0x6b3343cf ||
            (version & 0xffffff00) == 0xff000000 || version == 0) {
            return CAT_WEB_QUIC;
        }
    }

    // QUIC Short Header on known H3 port
    if (is_learned_h3_port(sport) || is_learned_h3_port(dport)) {
        return CAT_WEB_QUIC;
    }

    // DNS over QUIC (port 853)
    if (sport == 853 || dport == 853) {
        if (payload[0] & 0x80) return CAT_DNS_DOQ;
    }

    return CAT_UNKNOWN;
}
```

### TLS ClientHello Parsing (SNI/ALPN Extraction)

```c
// Extract SNI and ALPN from TLS ClientHello
struct tls_hello_info {
    char sni[256];              // Server Name Indication
    char alpn_protos[64];       // "h2", "http/1.1", "h3"
    uint16_t tls_version;
    bool has_sni;
    bool has_alpn;
};

int parse_tls_client_hello(const uint8_t *data, size_t len,
                           struct tls_hello_info *info) {
    // Record header: type(1) + version(2) + length(2)
    if (len < 5 || data[0] != 0x16) return -1;

    size_t record_len = (data[3] << 8) | data[4];
    if (len < 5 + record_len) return -1;

    // Handshake header: type(1) + length(3)
    const uint8_t *hs = data + 5;
    if (hs[0] != 0x01) return -1;  // ClientHello

    // Skip to extensions (complex parsing)
    // ... parse session_id, cipher_suites, compression_methods ...

    // Parse extensions for SNI (type 0x0000) and ALPN (type 0x0010)
    // ... extract SNI hostname and ALPN protocols ...

    return 0;
}
```

---

## 4. Dynamic Port Learning (Alt-Svc)

### Feedback Loop Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ALT-SVC FEEDBACK LOOP                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. XDP detects TLS on TCP:443                                             │
│          │                                                                  │
│          ▼                                                                  │
│  2. Uprobe captures HTTP/2 response headers                                │
│          │                                                                  │
│          ▼                                                                  │
│  3. User-space parses: "Alt-Svc: h3=\":8443\"; ma=86400"                   │
│          │                                                                  │
│          ▼                                                                  │
│  4. Update BPF map: learned_h3_ports[8443] = 1                             │
│          │                                                                  │
│          ▼                                                                  │
│  5. XDP now knows: UDP:8443 traffic is likely H3                           │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                                                                      │  │
│  │   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐     │  │
│  │   │   XDP    │───▶│  Uprobe  │───▶│  Output  │───▶│ BPF Map  │     │  │
│  │   │ Detect   │    │ Capture  │    │  Thread  │    │  Update  │     │  │
│  │   │ TLS:443  │    │ Response │    │  Parse   │    │          │     │  │
│  │   └──────────┘    └──────────┘    └──────────┘    └────┬─────┘     │  │
│  │        ▲                                               │           │  │
│  │        │                                               │           │  │
│  │        └───────────────────────────────────────────────┘           │  │
│  │                         Feedback                                    │  │
│  │                                                                      │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### BPF Maps for Dynamic Learning

```c
// Learned H3 ports from Alt-Svc headers
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);               // Port number
    __type(value, __u64);             // Expiration timestamp (ma= value)
} learned_h3_ports SEC(".maps");

// Learned H3 hosts from Alt-Svc (e.g., alt-svc: h3="alt.example.com:443")
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct alt_host_key); // IP + port
    __type(value, __u64);             // Expiration timestamp
} learned_h3_hosts SEC(".maps");
```

### Alt-Svc Parser

```c
// Parse Alt-Svc header and update BPF maps
// Example: "h3=\":443\"; ma=86400, h3-29=\":8443\"; ma=3600"

int parse_alt_svc_header(const char *value, int map_fd) {
    const char *p = value;

    while (*p) {
        // Look for h3 or h3-XX
        if (strncmp(p, "h3", 2) == 0) {
            // Skip to port
            const char *port_start = strchr(p, ':');
            if (port_start) {
                port_start++;
                if (*port_start == '"') port_start++;

                uint16_t port = (uint16_t)atoi(port_start);
                if (port > 0 && port < 65536) {
                    // Parse ma= for expiration
                    uint64_t expiry = time(NULL) + 86400;  // Default 24h
                    const char *ma = strstr(p, "ma=");
                    if (ma) {
                        expiry = time(NULL) + atoi(ma + 3);
                    }

                    // Update BPF map
                    bpf_map_update_elem(map_fd, &port, &expiry, BPF_ANY);
                    printf("[Alt-Svc] Learned H3 port: %u (expires: %lu)\n",
                           port, expiry);
                }
            }
        }

        // Move to next entry
        p = strchr(p, ',');
        if (!p) break;
        p++;
        while (*p == ' ') p++;
    }

    return 0;
}
```

---

## 5. Multi-Threaded Architecture

### Thread Roles

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         THREAD ARCHITECTURE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  MAIN THREAD                                                         │   │
│  │  • Parse CLI arguments                                               │   │
│  │  • Load BPF programs                                                 │   │
│  │  • Spawn all other threads                                           │   │
│  │  • Signal handling                                                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  PACKET INGESTION THREAD(S)                                          │   │
│  │  • Mode-specific packet capture:                                     │   │
│  │    - kernel: pcap/raw socket                                         │   │
│  │    - xdp: BPF ring buffer                                            │   │
│  │    - af_xdp: UMEM polling                                            │   │
│  │    - dpdk: PMD polling (multiple threads, one per RX queue)         │   │
│  │  • Protocol detection                                                │   │
│  │  • Flow-affinity dispatch to workers                                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  UPROBE INGESTION THREAD                                             │   │
│  │  • Poll eBPF ring buffer for SSL events                              │   │
│  │  • Dispatch to workers (same flow-affinity)                          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  WORKER THREADS (N, configurable)                                    │   │
│  │  • Thread-local session tables (no locks!)                           │   │
│  │  • Protocol parsing (llhttp, nghttp2, nghttp3)                       │   │
│  │  • Flow correlation                                                   │   │
│  │  • Adaptive wait (spin → yield → sleep)                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  OUTPUT THREAD                                                        │   │
│  │  • Collect parsed messages from workers                               │   │
│  │  • Format output (colors, JSON)                                       │   │
│  │  • File I/O                                                           │   │
│  │  • Alt-Svc parsing → BPF map updates                                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### CPU Core Allocation (Example: 16-core system)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CPU ALLOCATION (DPDK MODE)                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Core 0     │ System/OS (never use for DPDK)                               │
│  ──────────────────────────────────────────────────────────────────────    │
│  Core 1-4   │ DPDK PMD RX threads (poll-mode, 100% CPU)                    │
│             │ Each handles one NIC RX queue                                 │
│  ──────────────────────────────────────────────────────────────────────    │
│  Core 5-12  │ Worker threads (protocol parsing, correlation)               │
│             │ Adaptive wait (spin/sleep hybrid)                            │
│  ──────────────────────────────────────────────────────────────────────    │
│  Core 13    │ BPF ring buffer reader (uprobe events)                       │
│  ──────────────────────────────────────────────────────────────────────    │
│  Core 14    │ Output thread (formatting, file I/O)                         │
│  ──────────────────────────────────────────────────────────────────────    │
│  Core 15    │ Control plane (CLI, stats, config)                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Lock-Free Data Structures

### Library Selection

| Component | Library | Why |
|-----------|---------|-----|
| Work queues | **ck_ring (SPSC)** | Lock-free, wait-free, fastest |
| Shared read data | **liburcu** | Zero-overhead reads |
| Memory allocation | **jemalloc** | Multi-thread optimized |
| Wake-up signaling | **eventfd** | Efficient kernel sleep |

### Worker Context Structure

```c
#include <ck_ring.h>
#include <urcu/urcu-memb.h>

#define RING_SIZE 4096  // Must be power of 2

typedef struct {
    // Lock-free input queue (ingestion → worker)
    ck_ring_t in_ring;
    ck_ring_buffer_t in_buffer[RING_SIZE];

    // Lock-free output queue (worker → output)
    ck_ring_t out_ring;
    ck_ring_buffer_t out_buffer[RING_SIZE];

    // Wake-up signaling
    int wakeup_fd;              // eventfd
    _Atomic bool has_work;      // Fast check before syscall

    // Thread-local session storage (NO LOCKS NEEDED)
    struct session_table sessions;

    // Thread-local object pools
    struct object_pool event_pool;
    struct object_pool session_pool;

    // Statistics (atomic for monitoring)
    _Atomic uint64_t events_processed;
    _Atomic uint64_t events_dropped;
    _Atomic uint64_t spin_cycles;
    _Atomic uint64_t sleep_cycles;

    // Control
    _Atomic bool running;
    int worker_id;

} worker_ctx_t;
```

### Event Structure

```c
typedef struct {
    // Routing info
    uint64_t flow_hash;           // Pre-computed for dispatch

    // Event metadata
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t tid;
    uint8_t event_type;           // PACKET, UPROBE, etc.
    uint8_t event_source;         // XDP, DPDK, UPROBE
    uint8_t proto_hint;           // From detection
    uint8_t category;             // Traffic category

    // Flow key
    struct flow_key flow;

    // Payload (variable length)
    uint32_t data_len;
    uint8_t data[];               // Flexible array member

} worker_event_t;
```

---

## 7. Adaptive Wait Strategy

### The Problem

| Strategy | Latency (busy) | Latency (idle→busy) | CPU (idle) |
|----------|----------------|---------------------|------------|
| Pure spin | < 100 ns | < 100 ns | **100%** |
| Pure blocking | 1-10 μs | 2-5 μs | **~0%** |
| **Adaptive** | < 100 ns | 1-2 μs | **~2%** |

### Three-Phase Adaptive Wait

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ADAPTIVE WAIT PHASES                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐      │
│   │    PHASE 1      │────▶│    PHASE 2      │────▶│    PHASE 3      │      │
│   │   Spin-Wait     │     │     Yield       │     │     Sleep       │      │
│   │                 │     │                 │     │                 │      │
│   │ 1000 iterations │     │ 10 iterations   │     │ poll(eventfd)   │      │
│   │ ~1-2 μs         │     │ ~10-100 μs      │     │ 10ms timeout    │      │
│   │                 │     │                 │     │                 │      │
│   │ CPU: 100%       │     │ CPU: ~50%       │     │ CPU: ~0%        │      │
│   │ Latency: <100ns │     │ Latency: ~1μs   │     │ Latency: ~5μs   │      │
│   └─────────────────┘     └─────────────────┘     └─────────────────┘      │
│                                                                             │
│   If work arrives at any phase → immediately process and reset to Phase 1  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Implementation

```c
#define SPIN_ITERATIONS     1000
#define YIELD_ITERATIONS    10
#define POLL_TIMEOUT_MS     10
#define BATCH_SIZE          32

// Phase 1: Spin-wait (lowest latency, highest CPU)
static inline bool try_spin_dequeue(worker_ctx_t *ctx, worker_event_t **event) {
    for (int i = 0; i < SPIN_ITERATIONS; i++) {
        if (ck_ring_dequeue_spsc(&ctx->in_ring, ctx->in_buffer, event)) {
            return true;
        }
        __builtin_ia32_pause();  // x86 PAUSE - reduces power, CPU hint
    }
    atomic_fetch_add(&ctx->spin_cycles, SPIN_ITERATIONS);
    return false;
}

// Phase 2: Yield (give other threads a chance)
static inline bool try_yield_dequeue(worker_ctx_t *ctx, worker_event_t **event) {
    for (int i = 0; i < YIELD_ITERATIONS; i++) {
        sched_yield();
        if (ck_ring_dequeue_spsc(&ctx->in_ring, ctx->in_buffer, event)) {
            return true;
        }
    }
    return false;
}

// Phase 3: Sleep on eventfd (minimal CPU)
static inline bool try_sleep_dequeue(worker_ctx_t *ctx, worker_event_t **event) {
    struct pollfd pfd = { .fd = ctx->wakeup_fd, .events = POLLIN };

    int ret = poll(&pfd, 1, POLL_TIMEOUT_MS);
    if (ret > 0) {
        uint64_t val;
        read(ctx->wakeup_fd, &val, sizeof(val));  // Drain eventfd
    }

    atomic_fetch_add(&ctx->sleep_cycles, 1);
    return ck_ring_dequeue_spsc(&ctx->in_ring, ctx->in_buffer, event);
}

// Main worker loop
void *worker_thread(void *arg) {
    worker_ctx_t *ctx = arg;

    // Register with RCU
    urcu_memb_register_thread();

    // Pin to CPU (optional)
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(ctx->worker_id % get_nprocs(), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

    while (atomic_load(&ctx->running)) {
        worker_event_t *event = NULL;

        // Adaptive wait: spin → yield → sleep
        if (!try_spin_dequeue(ctx, &event)) {
            if (!try_yield_dequeue(ctx, &event)) {
                if (!try_sleep_dequeue(ctx, &event)) {
                    continue;
                }
            }
        }

        // Process event (and batch more if available)
        int processed = 0;
        do {
            process_event(ctx, event);
            pool_free(&ctx->event_pool, event);
            processed++;
            atomic_fetch_add(&ctx->events_processed, 1);
        } while (processed < BATCH_SIZE &&
                 ck_ring_dequeue_spsc(&ctx->in_ring, ctx->in_buffer, &event));
    }

    urcu_memb_unregister_thread();
    return NULL;
}
```

### Producer Side: Signal Worker

```c
int enqueue_to_worker(worker_ctx_t *worker, worker_event_t *event) {
    // Enqueue to lock-free ring
    if (!ck_ring_enqueue_spsc(&worker->in_ring, worker->in_buffer, event)) {
        return -1;  // Queue full
    }

    // Signal worker only if it might be sleeping
    if (!atomic_exchange(&worker->has_work, true)) {
        uint64_t val = 1;
        write(worker->wakeup_fd, &val, sizeof(val));
    }

    return 0;
}
```

---

## 8. XDP Implementation

### XDP Program

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD

// Shared maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u64);
} learned_h3_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, __u32);  // PID (from uprobe registration)
} flow_to_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);  // 1MB
} xdp_events SEC(".maps");

SEC("xdp")
int xdp_packet_monitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // IPv4 only for now
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    // Parse IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    struct flow_key key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .protocol = ip->protocol,
    };

    __u16 sport = 0, dport = 0;
    __u8 *payload = NULL;
    __u32 payload_len = 0;

    // Parse TCP/UDP
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        key.sport = tcp->source;
        key.dport = tcp->dest;
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);

        payload = (void *)tcp + (tcp->doff * 4);
        if (payload > data_end) return XDP_PASS;
        payload_len = data_end - payload;

    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;

        key.sport = udp->source;
        key.dport = udp->dest;
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);

        payload = (void *)(udp + 1);
        if (payload > data_end) return XDP_PASS;
        payload_len = bpf_ntohs(udp->len) - sizeof(*udp);

    } else {
        return XDP_PASS;
    }

    // Content-based protocol detection
    __u8 category = CAT_UNKNOWN;
    __u8 proto_hint = PROTO_UNKNOWN;

    if (ip->protocol == IPPROTO_TCP && payload_len >= 6) {
        // TLS detection
        if (payload[0] == 0x16 && payload[1] == 0x03) {
            category = CAT_WEB_TLS_TCP;
            // Could parse ClientHello for ALPN here
        }
        // Plain HTTP detection
        else if (payload_len >= 4) {
            if (__builtin_memcmp(payload, "GET ", 4) == 0 ||
                __builtin_memcmp(payload, "POST", 4) == 0 ||
                __builtin_memcmp(payload, "HTTP", 4) == 0) {
                category = CAT_WEB_PLAIN;
                proto_hint = PROTO_HTTP1;
            }
        }
    } else if (ip->protocol == IPPROTO_UDP && payload_len >= 5) {
        // QUIC detection
        if (payload[0] & 0x80) {
            __u32 version = (payload[1] << 24) | (payload[2] << 16) |
                           (payload[3] << 8) | payload[4];
            if (version == 0x00000001 || version == 0x6b3343cf ||
                (version & 0xffffff00) == 0xff000000) {
                category = CAT_WEB_QUIC;
                proto_hint = PROTO_HTTP3;
            }
        }
        // Check learned H3 ports
        __u64 *expiry = bpf_map_lookup_elem(&learned_h3_ports, &dport);
        if (expiry) {
            category = CAT_WEB_QUIC;
            proto_hint = PROTO_HTTP3;
        }
    }

    // Skip if not interesting
    if (category == CAT_UNKNOWN) return XDP_PASS;

    // Lookup PID for this flow
    __u32 *pid_ptr = bpf_map_lookup_elem(&flow_to_pid, &key);
    __u32 pid = pid_ptr ? *pid_ptr : 0;

    // Submit event
    struct xdp_event *e = bpf_ringbuf_reserve(&xdp_events, sizeof(*e), 0);
    if (e) {
        e->timestamp_ns = bpf_ktime_get_ns();
        e->pid = pid;
        e->len = data_end - data;
        e->sport = sport;
        e->dport = dport;
        e->saddr = ip->saddr;
        e->daddr = ip->daddr;
        e->protocol = ip->protocol;
        e->category = category;
        e->proto_hint = proto_hint;

        bpf_ringbuf_submit(e, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
```

---

## 9. AF_XDP Implementation

AF_XDP provides zero-copy packet delivery to userspace while still using XDP.

```c
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

struct af_xdp_socket {
    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fq;    // Fill queue
    struct xsk_ring_cons cq;    // Completion queue
    struct xsk_umem *umem;
    void *buffer;
    int queue_id;
};

int af_xdp_init(struct af_xdp_socket *sock, const char *ifname, int queue_id) {
    // Allocate UMEM (shared memory between kernel and userspace)
    size_t frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
    size_t num_frames = 4096;

    sock->buffer = mmap(NULL, num_frames * frame_size,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);

    struct xsk_umem_config umem_cfg = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = frame_size,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    };

    xsk_umem__create(&sock->umem, sock->buffer, num_frames * frame_size,
                     &sock->fq, &sock->cq, &umem_cfg);

    // Create XSK socket
    struct xsk_socket_config xsk_cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .bind_flags = XDP_ZEROCOPY,
    };

    xsk_socket__create(&sock->xsk, ifname, queue_id, sock->umem,
                       &sock->rx, &sock->tx, &xsk_cfg);

    // Populate fill queue
    __u32 idx;
    xsk_ring_prod__reserve(&sock->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++) {
        *xsk_ring_prod__fill_addr(&sock->fq, idx + i) = i * frame_size;
    }
    xsk_ring_prod__submit(&sock->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return 0;
}

// RX loop
void af_xdp_rx_loop(struct af_xdp_socket *sock, worker_ctx_t *workers, int num_workers) {
    while (g_running) {
        __u32 idx_rx = 0;
        unsigned int rcvd = xsk_ring_cons__peek(&sock->rx, BATCH_SIZE, &idx_rx);

        if (rcvd == 0) {
            // Poll for new packets
            struct pollfd pfd = { .fd = xsk_socket__fd(sock->xsk), .events = POLLIN };
            poll(&pfd, 1, 10);
            continue;
        }

        for (unsigned int i = 0; i < rcvd; i++) {
            __u64 addr = xsk_ring_cons__rx_desc(&sock->rx, idx_rx + i)->addr;
            __u32 len = xsk_ring_cons__rx_desc(&sock->rx, idx_rx + i)->len;

            void *pkt = xsk_umem__get_data(sock->buffer, addr);

            // Process packet (same as XDP userspace handler)
            process_packet(pkt, len, workers, num_workers);
        }

        xsk_ring_cons__release(&sock->rx, rcvd);

        // Replenish fill queue
        __u32 idx_fq;
        xsk_ring_prod__reserve(&sock->fq, rcvd, &idx_fq);
        for (unsigned int i = 0; i < rcvd; i++) {
            *xsk_ring_prod__fill_addr(&sock->fq, idx_fq + i) =
                xsk_ring_cons__rx_desc(&sock->rx, idx_rx + i)->addr;
        }
        xsk_ring_prod__submit(&sock->fq, rcvd);
    }
}
```

---

## 10. DPDK Implementation

### DPDK Initialization

```c
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#define NUM_RX_QUEUES    4
#define NUM_WORKERS      8
#define MBUF_POOL_SIZE   (1 << 20)
#define RING_SIZE        (1 << 16)

struct dpdk_context {
    uint16_t port_id;
    struct rte_mempool *mbuf_pool;
    struct rte_ring *worker_rings[NUM_WORKERS];

    _Atomic uint64_t rx_packets;
    _Atomic uint64_t rx_bytes;
    _Atomic uint64_t dropped;
};

int dpdk_init(int argc, char **argv, struct dpdk_context *ctx) {
    // Initialize EAL
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");

    // Create mbuf pool
    ctx->mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", MBUF_POOL_SIZE, 256, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    // Configure port with RSS
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_RSS,
            .offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM,
        },
        .rx_adv_conf.rss_conf = {
            .rss_key = NULL,
            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
        },
    };

    rte_eth_dev_configure(ctx->port_id, NUM_RX_QUEUES, 0, &port_conf);

    // Setup RX queues
    for (int q = 0; q < NUM_RX_QUEUES; q++) {
        rte_eth_rx_queue_setup(ctx->port_id, q, 4096,
                               rte_eth_dev_socket_id(ctx->port_id),
                               NULL, ctx->mbuf_pool);
    }

    // Create worker rings
    for (int w = 0; w < NUM_WORKERS; w++) {
        char name[32];
        snprintf(name, sizeof(name), "WORKER_%d", w);
        ctx->worker_rings[w] = rte_ring_create(name, RING_SIZE,
                                                rte_socket_id(),
                                                RING_F_SP_ENQ | RING_F_SC_DEQ);
    }

    // Start port
    rte_eth_dev_start(ctx->port_id);
    rte_eth_promiscuous_enable(ctx->port_id);

    return 0;
}
```

### DPDK RX Thread (Poll-Mode)

```c
#define BURST_SIZE 64

int dpdk_rx_thread(void *arg) {
    struct rx_thread_ctx *ctx = arg;
    struct rte_mbuf *bufs[BURST_SIZE];

    while (atomic_load(&g_running)) {
        // Poll for packets (never blocks!)
        uint16_t nb_rx = rte_eth_rx_burst(ctx->port_id, ctx->queue_id,
                                          bufs, BURST_SIZE);

        if (nb_rx == 0) continue;

        atomic_fetch_add(&ctx->dpdk->rx_packets, nb_rx);

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *mbuf = bufs[i];

            // Parse and classify
            struct packet_metadata meta;
            if (parse_dpdk_packet(mbuf, &meta) == 0) {
                // Dispatch to worker
                uint32_t worker_id = meta.flow_hash % NUM_WORKERS;

                if (rte_ring_enqueue(ctx->dpdk->worker_rings[worker_id],
                                     mbuf) != 0) {
                    rte_pktmbuf_free(mbuf);
                    atomic_fetch_add(&ctx->dpdk->dropped, 1);
                }
            } else {
                rte_pktmbuf_free(mbuf);
            }
        }
    }

    return 0;
}
```

### DPDK System Setup

```bash
# 1. Allocate huge pages (required for DPDK)
echo 8192 > /proc/sys/vm/nr_hugepages
# Or for 1GB pages:
# echo 8 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages

# 2. Load vfio-pci driver
modprobe vfio-pci

# 3. Bind NIC to DPDK
# First, find your NIC:
dpdk-devbind.py --status

# Bind to vfio-pci (replace with your PCIe address):
dpdk-devbind.py -b vfio-pci 0000:03:00.0

# 4. Run spliff with DPDK
spliff --mode dpdk -w 0000:03:00.0 --lcores 1-4,5-12
```

---

## 11. Flow Correlation

### Correlating Encrypted Packets with Decrypted Data

```c
struct correlation_entry {
    struct flow_key flow;

    // From XDP/DPDK (encrypted)
    uint64_t last_packet_ns;
    uint64_t total_encrypted_bytes;
    uint32_t packet_count;

    // From Uprobe (decrypted)
    uint64_t last_plaintext_ns;
    uint64_t total_decrypted_bytes;
    uint32_t event_count;
    uint32_t pid;

    // Computed
    uint64_t avg_decrypt_latency_ns;
};

// Calculate decryption latency
void correlate_events(struct correlation_entry *entry,
                      uint64_t packet_ns, uint64_t plaintext_ns) {
    if (packet_ns > 0 && plaintext_ns > packet_ns) {
        uint64_t latency = plaintext_ns - packet_ns;

        // Running average
        entry->avg_decrypt_latency_ns =
            (entry->avg_decrypt_latency_ns * entry->event_count + latency) /
            (entry->event_count + 1);
    }
}

// Detect unhooked traffic
void check_unhooked_traffic(struct correlation_entry *entry) {
    // If we see encrypted packets but no decrypted data,
    // the TLS library might not be hooked
    if (entry->packet_count > 100 && entry->event_count == 0) {
        printf("[ALERT] Unhooked TLS traffic detected: %s:%d -> %s:%d\n",
               format_ip(entry->flow.saddr), entry->flow.sport,
               format_ip(entry->flow.daddr), entry->flow.dport);
        printf("        %u packets, %lu bytes, no decrypted events\n",
               entry->packet_count, entry->total_encrypted_bytes);
    }
}
```

---

## 12. Memory Management

### Object Pool (Avoid malloc in hot path)

```c
typedef struct {
    void *free_list;
    size_t object_size;
    size_t capacity;
    _Atomic size_t in_use;
    void *memory;
    size_t memory_size;
} object_pool_t;

int pool_init(object_pool_t *pool, size_t obj_size, size_t count) {
    pool->object_size = obj_size;
    pool->capacity = count;
    pool->memory_size = obj_size * count;

    // Use huge pages if available
    pool->memory = mmap(NULL, pool->memory_size,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (pool->memory == MAP_FAILED) {
        // Fall back to regular pages
        pool->memory = mmap(NULL, pool->memory_size,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }

    // Build free list
    pool->free_list = NULL;
    for (size_t i = 0; i < count; i++) {
        void *obj = (char *)pool->memory + (i * obj_size);
        *(void **)obj = pool->free_list;
        pool->free_list = obj;
    }

    return 0;
}

// O(1) allocation
static inline void *pool_alloc(object_pool_t *pool) {
    if (!pool->free_list) return NULL;

    void *obj = pool->free_list;
    pool->free_list = *(void **)obj;
    atomic_fetch_add(&pool->in_use, 1);
    return obj;
}

// O(1) deallocation
static inline void pool_free(object_pool_t *pool, void *obj) {
    *(void **)obj = pool->free_list;
    pool->free_list = obj;
    atomic_fetch_sub(&pool->in_use, 1);
}
```

### DPDK Memory (Huge Pages + NUMA)

```c
// DPDK handles memory internally via rte_mempool
// Key considerations:
// 1. Pre-allocate all mbufs at startup
// 2. Use NUMA-local memory (rte_socket_id())
// 3. Use 1GB huge pages for best TLB performance

struct rte_mempool *create_numa_aware_pool(int numa_node) {
    return rte_pktmbuf_pool_create_by_ops(
        "MBUF_POOL",
        MBUF_POOL_SIZE,
        256,                    // Cache size
        0,                      // Private size
        RTE_MBUF_DEFAULT_BUF_SIZE,
        numa_node,              // NUMA node
        "ring_mp_mc"            // Multi-producer, multi-consumer
    );
}
```

---

## 13. Implementation Phases

### Phase 1: Multi-Threading Foundation

**Goals:**
- Implement worker thread pool with CK rings
- Add eventfd-based wake-up
- Implement adaptive wait strategy
- Add object pools for events

**Files:**
- `src/threading/worker.c` (new)
- `src/threading/pool.c` (new)
- `src/threading/dispatcher.c` (new)

**Deliverable:** Multi-threaded event processing without packet capture changes.

### Phase 2: Content-Based Detection

**Goals:**
- Implement protocol detection by content (not port)
- Add traffic categorization
- Monitor all ports, not just 443

**Files:**
- `src/protocol/detect.c` (new)
- `src/bpf/spliff.bpf.c` (update)

**Deliverable:** Protocol detection works on any port.

### Phase 3: XDP Integration

**Goals:**
- Add XDP program for packet metadata
- Implement flow correlation maps
- Connect XDP events to worker threads

**Files:**
- `src/bpf/xdp.bpf.c` (new)
- `src/capture/xdp.c` (new)

**Deliverable:** `--mode xdp` working.

### Phase 4: Alt-Svc Learning

**Goals:**
- Parse Alt-Svc headers in output thread
- Update BPF maps dynamically
- Add port expiration handling

**Files:**
- `src/protocol/altsvc.c` (new)

**Deliverable:** Dynamic H3 port learning.

### Phase 5: AF_XDP Mode

**Goals:**
- Implement AF_XDP socket setup
- Zero-copy packet delivery
- Integrate with worker threads

**Files:**
- `src/capture/af_xdp.c` (new)

**Deliverable:** `--mode af_xdp` working.

### Phase 6: DPDK Mode

**Goals:**
- Add DPDK initialization
- Implement PMD RX threads
- DPDK-specific memory management
- Worker integration

**Files:**
- `src/capture/dpdk.c` (new)
- `CMakeLists.txt` (DPDK optional dependency)

**Deliverable:** `--mode dpdk` working at 100Gbps.

### Phase 7: Correlation & Analytics

**Goals:**
- Decryption latency calculation
- Unhooked traffic detection
- Performance statistics

**Deliverable:** Full dual-view visibility.

---

## 14. Dependencies

### Core (Always Required)

| Library | Purpose | Install (Fedora) | Install (Ubuntu) |
|---------|---------|------------------|------------------|
| libbpf | BPF loading | `dnf install libbpf-devel` | `apt install libbpf-dev` |
| libelf | ELF parsing | `dnf install elfutils-libelf-devel` | `apt install libelf-dev` |
| zlib | Compression | `dnf install zlib-devel` | `apt install zlib1g-dev` |
| llhttp | HTTP/1.1 | (bundled or build) | (bundled or build) |
| nghttp2 | HTTP/2 | `dnf install nghttp2-devel` | `apt install libnghttp2-dev` |
| **ck** | Lock-free DS | `dnf install ck-devel` | `apt install libck-dev` |
| **liburcu** | Userspace RCU | `dnf install userspace-rcu-devel` | `apt install liburcu-dev` |
| **jemalloc** | Allocator | `dnf install jemalloc-devel` | `apt install libjemalloc-dev` |

### HTTP/3 Support (v0.6.0)

| Library | Purpose | Install |
|---------|---------|---------|
| nghttp3 | HTTP/3 | Build from source |

### AF_XDP Mode

| Library | Purpose | Install |
|---------|---------|---------|
| libxdp | AF_XDP helpers | `dnf install libxdp-devel` |

### DPDK Mode

| Library | Purpose | Install |
|---------|---------|---------|
| dpdk | Packet processing | `dnf install dpdk-devel` |
| numactl | NUMA support | `dnf install numactl-devel` |

### CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.20)
project(spliff C)

# Options
option(ENABLE_XDP    "Enable XDP support" ON)
option(ENABLE_AF_XDP "Enable AF_XDP support" ON)
option(ENABLE_DPDK   "Enable DPDK support" OFF)

# Core dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(CK REQUIRED ck)
pkg_check_modules(URCU REQUIRED liburcu)

# Threading
find_package(Threads REQUIRED)

# jemalloc (optional but recommended)
find_library(JEMALLOC_LIB jemalloc)
if(JEMALLOC_LIB)
    add_definitions(-DUSE_JEMALLOC)
    list(APPEND EXTRA_LIBS ${JEMALLOC_LIB})
endif()

# AF_XDP
if(ENABLE_AF_XDP)
    pkg_check_modules(LIBXDP libxdp)
    if(LIBXDP_FOUND)
        add_definitions(-DWITH_AF_XDP)
        list(APPEND EXTRA_LIBS ${LIBXDP_LIBRARIES})
        list(APPEND EXTRA_INCLUDES ${LIBXDP_INCLUDE_DIRS})
    endif()
endif()

# DPDK
if(ENABLE_DPDK)
    pkg_check_modules(DPDK REQUIRED libdpdk)
    add_definitions(-DWITH_DPDK)
    list(APPEND EXTRA_LIBS ${DPDK_LIBRARIES})
    list(APPEND EXTRA_INCLUDES ${DPDK_INCLUDE_DIRS})

    # DPDK requires specific compiler flags
    add_compile_options(-march=native)
endif()

# Build
add_executable(spliff
    src/main.c
    src/threading/worker.c
    src/threading/pool.c
    src/threading/dispatcher.c
    src/protocol/detect.c
    src/protocol/http1.c
    src/protocol/http2.c
    src/protocol/http3.c
    src/protocol/altsvc.c
    src/capture/kernel.c
    src/capture/xdp.c
    $<$<BOOL:${LIBXDP_FOUND}>:src/capture/af_xdp.c>
    $<$<BOOL:${ENABLE_DPDK}>:src/capture/dpdk.c>
    # ... other sources
)

target_include_directories(spliff PRIVATE
    ${LIBBPF_INCLUDE_DIRS}
    ${CK_INCLUDE_DIRS}
    ${URCU_INCLUDE_DIRS}
    ${EXTRA_INCLUDES}
)

target_link_libraries(spliff
    ${LIBBPF_LIBRARIES}
    ${CK_LIBRARIES}
    ${URCU_LIBRARIES}
    ${EXTRA_LIBS}
    Threads::Threads
)
```

---

## 15. CLI Interface

```
spliff [OPTIONS]

Capture Modes:
  --mode <mode>           Capture mode: kernel, xdp, af_xdp, dpdk
                          (default: xdp if available, else kernel)

XDP Options:
  -i, --interface <if>    Network interface for XDP/AF_XDP
  --xdp-mode <mode>       XDP attach mode: native, generic, offload
                          (default: native with generic fallback)
  --queues <n>            Number of RX queues for AF_XDP (default: auto)

DPDK Options:
  -w, --pci <addr>        PCIe address of NIC (e.g., 0000:03:00.0)
  --lcores <list>         Core list: rx_cores,worker_cores
                          (e.g., --lcores 1-4,5-12)
  --huge-pages <n>        Number of huge pages (default: 8192)

Threading Options:
  --workers <n>           Number of worker threads (default: auto)
  --pin-cores             Pin threads to CPU cores

Protocol Options:
  --category <cat>        Filter by category: all, tls, quic, plain, grpc
                          (default: all)
  --learn-alt-svc         Dynamically learn H3 ports from Alt-Svc headers
                          (default: enabled)

Analysis Options:
  --show-latency          Show decryption latency metrics
  --detect-unhooked       Alert on TLS traffic without uprobe coverage
  --show-stats            Show periodic statistics

Output Options:
  -o, --output <file>     Write output to file
  --format <fmt>          Output format: text, json, pcap
  --no-color              Disable colored output

Examples:
  # Development (low bandwidth)
  spliff --mode kernel -i eth0

  # Production (10-25 Gbps)
  spliff --mode xdp -i eth0 --workers 8

  # High-performance (25-50 Gbps)
  spliff --mode af_xdp -i eth0 --queues 4 --workers 12

  # Extreme (100 Gbps)
  sudo spliff --mode dpdk -w 0000:03:00.0 --lcores 1-4,5-12 --huge-pages 8192
```

---

## 16. Challenges and Limitations

### 16.1 Mode-Specific Limitations

| Mode | Limitation | Mitigation |
|------|------------|------------|
| kernel | Low throughput | Use for dev/testing only |
| xdp | Kernel involvement | Use af_xdp for better perf |
| af_xdp | NIC driver support needed | Fall back to generic |
| dpdk | Dedicated cores, complex setup | Only for extreme cases |

### 16.2 Protocol Detection Limitations

- **Encrypted payloads**: Cannot inspect TLS application data in XDP/DPDK
- **Fragmented TLS**: ClientHello may span packets
- **QUIC short headers**: After handshake, no version field

**Mitigation**: Use uprobe correlation for encrypted content.

### 16.3 QPACK State

- QPACK is stateful; missing initial packets breaks decoding
- Must capture from connection start

**Mitigation**: Warn user, show raw bytes as fallback.

### 16.4 Memory

- DPDK requires huge pages
- High packet rates need large buffers
- Object pools need tuning

**Mitigation**: Auto-tune based on available memory.

---

## 17. References

### XDP & eBPF
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [libbpf Documentation](https://libbpf.readthedocs.io/)
- [BPF & XDP Reference](https://docs.cilium.io/en/stable/bpf/)

### AF_XDP
- [AF_XDP Documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [libxdp](https://github.com/xdp-project/xdp-tools)

### DPDK
- [DPDK Documentation](https://doc.dpdk.org/)
- [DPDK Programmer's Guide](https://doc.dpdk.org/guides/prog_guide/)
- [DPDK Sample Applications](https://doc.dpdk.org/guides/sample_app_ug/)

### Lock-Free Programming
- [Concurrency Kit](https://github.com/concurrencykit/ck)
- [Userspace RCU](https://liburcu.org/)

### QUIC & HTTP/3
- [RFC 9000 - QUIC Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9114 - HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [nghttp3](https://github.com/ngtcp2/nghttp3)

---

*Document created: 2026-01-11*
*Last updated: 2026-01-11*
*Author: spliff development*
