# CODE-MAP.md - spliff v0.9.6 Comprehensive Code Map

> **Purpose:** AI-friendly and human-readable architecture reference for understanding, maintaining, and extending the spliff codebase.

## Table of Contents
1. [Project Overview](#project-overview)
2. [Directory Structure](#directory-structure)
3. [Source File Reference](#source-file-reference)
4. [Build System](#build-system)
5. [eBPF Programs](#ebpf-programs)
6. [Data Flow](#data-flow)
7. [Key Architectures](#key-architectures)
8. [Known Issues & TODOs](#known-issues--todos)

---

## Project Overview

**spliff** is a production-grade eBPF-based SSL/TLS traffic sniffer that captures decrypted HTTPS traffic without MITM proxies. Version 0.9.6 features:

- **Embedded BPF Skeleton**: CO-RE BTF bytecode embedded in binary, strip-safe
- **XDP-SSL Correlation**: Socket cookie "Golden Thread" links packets, sockets, and TLS data
- **Modular Protocol Architecture**: Clean plugin-style routing for HTTP/1, HTTP/2, detection
- **Multi-threaded Processing**: Lock-free worker threads with connection affinity
- **Shared Pool Architecture**: 8192-slot pre-allocated flow context pool with dual-index lookup

---

## Directory Structure

```
sslsniff/
├── CMakeLists.txt                  # CMake build config (C23, LTO, sanitizers, packaging)
├── Makefile                        # Convenience wrapper for CMake targets
├── Doxyfile                        # Doxygen documentation config
├── README.md                       # User documentation, examples, features
├── CHANGELOG.md                    # Version history and migration notes
├── LICENSE                         # GPL-3.0 for userspace, GPL-2.0 for BPF
├── src/
│   ├── main.c                      # Entry point, CLI parsing, orchestration
│   ├── include/
│   │   └── spliff.h                # Public API, shared types, version
│   ├── bpf/                        # Kernel eBPF programs and userspace BPF utilities
│   │   ├── spliff.bpf.c            # Main BPF program (XDP, sock_ops, uprobes)
│   │   ├── bpf_loader.c            # BPF loader, uprobe/XDP attachment
│   │   ├── bpf_loader.h            # BPF API: load, attach, discovery, XDP
│   │   ├── probe_handler.c         # Ring buffer event filtering and dispatch
│   │   ├── probe_handler.h         # Probe handler API and structures
│   │   ├── binary_scanner.c        # BoringSSL binary scanning (Chrome detection)
│   │   ├── binary_scanner.h        # Binary scanner API
│   │   ├── boringssl_offsets.h     # Known BoringSSL offsets by build ID database
│   │   └── vmlinux.h               # Auto-generated kernel BTF definitions (CO-RE)
│   ├── protocol/                   # Protocol detection and parsing (modular v0.9.5+)
│   │   ├── detector.c              # Vectorscan O(n) pattern matching for protocols
│   │   ├── detector.h              # Protocol detector API
│   │   ├── http1.c                 # HTTP/1.1 parser using llhttp
│   │   ├── http1.h                 # HTTP/1.1 API
│   │   ├── http2.c                 # HTTP/2 parser using nghttp2
│   │   ├── http2.h                 # HTTP/2 API
│   │   └── websocket.h             # WebSocket frame parser (stub)
│   ├── content/                    # Content decompression and identification
│   │   ├── decompressor.c          # gzip/zstd/brotli decompression
│   │   ├── decompressor.h          # Decompressor API
│   │   ├── signatures.c            # File magic detection (50+ formats)
│   │   └── signatures.h            # Signature database and API
│   ├── output/                     # Terminal output formatting and colors
│   │   ├── display.c               # Colored output, latency formatting
│   │   └── display.h               # Display API
│   ├── correlation/                # XDP-SSL correlation and flow pooling
│   │   ├── flow_context.c          # Shared pool management (dual-index lookup)
│   │   └── flow_context.h          # flow_context_t, pool types
│   ├── threading/                  # Multi-threaded event processing
│   │   ├── threading.h             # Threading API, worker struct, ring buffers
│   │   ├── dispatcher.c            # BPF ring consumer, flow routing
│   │   ├── manager.c               # Thread lifecycle (init, start, shutdown)
│   │   ├── worker.c                # Worker thread main loop
│   │   ├── output.c                # Output serialization thread
│   │   ├── state.c                 # Per-worker state (H2 pools, ALPN cache)
│   │   └── pool.c                  # Lock-free object pool
│   └── util/                       # Utility functions
│       ├── safe_str.c              # Safe string operations
│       └── safe_str.h              # String API
├── tests/                          # Unit tests
│   ├── test_http1.c
│   ├── test_http2.c
│   ├── test_xdp.c
│   └── test_common.c
└── docs/                           # Documentation
    └── CODE-MAP.md                 # This file
```

---

## Source File Reference

### Core Entry Point

#### `src/main.c` (~1610 lines)
**Purpose:** CLI orchestration, library discovery, BPF initialization, event loop control

**Key Functions:**
| Function | Purpose |
|----------|---------|
| `main()` | Parse args, initialize BPF, attach probes, run event loop |
| `attach_probes_for_pid()` | Dynamic probe attachment for discovered processes |
| `attach_openssl_probes()` | OpenSSL-specific probe setup |
| `attach_gnutls_probes()` | GnuTLS-specific probe setup |
| `attach_nss_probes()` | NSS-specific probe setup |
| `handle_process_exec_event()` | Process lifecycle handler |
| `process_worker_event()` | Per-worker event processor |
| `cleanup_all_resources()` | Master cleanup (atexit registered) |

**Global State:**
- `g_skel` - BPF skeleton (owns embedded BPF object)
- `g_loader` - BPF loader state
- `g_handler` - Ring buffer event handler
- `g_threading` - Multi-threaded dispatcher
- `g_config` - Runtime configuration

---

### Public Header

#### `src/include/spliff.h` (~476 lines)
**Purpose:** Public API, shared type definitions, version info

**Key Types:**
| Type | Purpose |
|------|---------|
| `protocol_t` | PROTO_HTTP1, PROTO_HTTP2, PROTO_HTTP3 |
| `xdp_category_t` | XDP packet classification |
| `flow_key_t` | 16-byte 5-tuple for flow identification |
| `xdp_packet_event_t` | 52-byte metadata-only XDP event |
| `http_message_t` | Parsed HTTP request/response |
| `config_t` | Global configuration |

**Constants:**
| Constant | Value |
|----------|-------|
| `MAX_HEADER_NAME` | 256 |
| `MAX_HEADER_VALUE` | 4096 |
| `MAX_HEADERS` | 128 |
| `MAX_BODY_BUFFER` | 1 MB |
| `XDP_PAYLOAD_MAX` | 128 bytes |
| `FLOW_POOL_CAPACITY` | 8192 |
| `SPLIFF_VERSION` | "0.9.6" |

---

### eBPF Programs & Loading

#### `src/bpf/spliff.bpf.c` (~3287 lines)
**Purpose:** Kernel eBPF programs for SSL/TLS interception, packet classification, socket tracking

**BPF Programs:**

| Program | Type | Purpose |
|---------|------|---------|
| `probe_ssl_rw_enter` | uprobe | SSL_read/SSL_write entry |
| `probe_ssl_write_exit` | uretprobe | Capture decrypted write data |
| `probe_ssl_read_exit` | uretprobe | Capture decrypted read data |
| `probe_ssl_set_fd_*` | uprobe | Track SSL* → fd mapping |
| `probe_openssl_alpn_*` | uprobe | ALPN negotiation capture |
| `xdp_classifier` | xdp | Packet classification, flow tracking |
| `sockops_established` | sock_ops | Cache socket cookies |
| `handle_process_exec` | tracepoint | Dynamic probe attachment |

**BPF Maps:**
| Map | Type | Purpose |
|-----|------|---------|
| `ssl_events` | ring_buffer | SSL/TLS decrypted data events |
| `xdp_events` | ring_buffer | XDP packet metadata |
| `process_events` | ring_buffer | Process lifecycle events |
| `ssl_to_fd` | hash | SSL* → {fd, socket_cookie} |
| `flow_cookie_map` | hash | 5-tuple → socket_cookie |
| `flow_states` | hash | flow_key → flow_state_t |

---

#### `src/bpf/bpf_loader.c` (~1757 lines)
**Purpose:** Load BPF programs, attach uprobes/XDP, discover SSL libraries

**Key Functions:**
| Function | Purpose |
|----------|---------|
| `bpf_loader_init()` | Initialize loader state |
| `bpf_loader_set_object()` | Set BPF object from skeleton |
| `bpf_loader_attach_uprobe()` | Attach uprobe to function |
| `bpf_loader_discover_libraries()` | System scan for SSL libraries |
| `bpf_loader_xdp_attach_all()` | Auto-attach to network interfaces |
| `bpf_loader_sockops_attach()` | Attach sock_ops to cgroup2 |
| `bpf_loader_cleanup()` | Detach all, close maps |

---

#### `src/bpf/probe_handler.c` (~449 lines)
**Purpose:** Poll ring buffer events, filter, dispatch to workers

**Event Types:**
| Event | Purpose |
|-------|---------|
| `EVENT_SSL_READ` | Decrypted TLS read data |
| `EVENT_SSL_WRITE` | Decrypted TLS write data |
| `EVENT_HANDSHAKE` | TLS handshake completion |
| `EVENT_ALPN` | ALPN protocol negotiation |
| `EVENT_PROCESS_EXEC` | New process execution |

---

#### `src/bpf/binary_scanner.c` (~345 lines)
**Purpose:** Detect BoringSSL in Chrome/Chromium binaries via build ID lookup

---

### Protocol Parsing

#### `src/protocol/detector.c` (~80 lines)
**Purpose:** O(n) protocol detection using vectorscan NFA

**Detection Results:**
| Result | Pattern |
|--------|---------|
| `PROTO_DETECT_HTTP1_REQ` | `^(GET\|POST\|PUT\|...)` |
| `PROTO_DETECT_HTTP1_RSP` | `^HTTP/1\.[01]` |
| `PROTO_DETECT_HTTP2` | `^PRI \* HTTP/2.0` |
| `PROTO_DETECT_TLS` | `^\x16\x03` |

---

#### `src/protocol/http1.c` (HTTP/1.1 parser)
**Purpose:** Parse HTTP/1.1 using llhttp (Node.js parser)

**Key Functions:**
| Function | Purpose |
|----------|---------|
| `http1_init()` | Initialize llhttp settings |
| `http1_try_process_event()` | Unified entry point |
| `http1_is_request()` | Heuristic request check |
| `http1_is_response()` | Heuristic response check |

---

#### `src/protocol/http2.c` (HTTP/2 parser)
**Purpose:** Parse HTTP/2 frames using nghttp2

**Key Functions:**
| Function | Purpose |
|----------|---------|
| `http2_init()` | Initialize nghttp2 callbacks |
| `http2_try_process_event()` | Unified entry point |
| `flow_h2_session_init()` | Create nghttp2 session |
| `flow_h2_new_stream()` | Allocate stream from pool |

**Stream Management:**
- 64 concurrent streams per flow
- Free-list allocation (O(1))
- Ghost stream timeout (10 seconds)

---

### Content Processing

#### `src/content/decompressor.c` (~412 lines)
**Purpose:** Decompress HTTP bodies

**Supported Formats:**
| Format | Library |
|--------|---------|
| gzip | zlib/zlib-ng |
| deflate | zlib |
| zstd | libzstd |
| brotli | libbrotlidec |

---

#### `src/content/signatures.c` (~793 lines)
**Purpose:** Identify file types via magic bytes (50+ formats)

**Categories:** Images, Video, Audio, Archives, Documents, Data formats

---

### Flow Correlation

#### `src/correlation/flow_context.h` (~1122 lines)
**Purpose:** Type definitions for shared pool architecture

**Key Types:**
```c
typedef struct flow_context {
    uint64_t socket_cookie;     // "Golden Thread" correlation key
    uint32_t pid, ssl_ctx;      // Dual-index lookup keys
    flow_state_t state;         // INIT, ACTIVE, CLOSING, CLOSED
    flow_proto_t proto;         // UNKNOWN, HTTP1, HTTP2, OTHER
    uint16_t flags;             // HAS_XDP, HAS_SSL, IN_COOKIE, IN_SHADOW
    atomic_uint32_t home_worker_id;  // CAS-protected worker claim
    union {
        http1_parser_t h1;
        http2_parser_t h2;
    } parser;
    char alpn[16];
} flow_context_t;
```

**Dual-Index Lookup:**
- `cookie_index`: socket_cookie → flow_id (primary)
- `shadow_index`: (pid, ssl_ctx) → flow_id (fallback)

---

#### `src/correlation/flow_context.c` (~1342 lines)
**Purpose:** Implement shared pool, dual-index lookup, atomic handover

**Key Functions:**
| Function | Purpose |
|----------|---------|
| `flow_manager_init()` | Allocate 8192 slots |
| `flow_get_by_cookie()` | Primary lookup |
| `flow_get_by_shadow()` | Fallback lookup |
| `flow_alloc()` | O(1) allocation |
| `flow_promote_cookie()` | Move shadow → cookie index |

---

### Threading

#### `src/threading/threading.h` (~1330 lines)
**Purpose:** Threading infrastructure definitions

**Configuration:**
| Constant | Value |
|----------|-------|
| `MAX_WORKERS` | 16 |
| `EVENT_RING_SIZE` | 4096 |
| `NAPI_BUDGET` | 64 events/loop |
| `EPOLL_TIMEOUT_MS` | 100 |

---

#### `src/threading/dispatcher.c` (~771 lines)
**Purpose:** Route events from BPF to workers

**Routing:** `hash(pid, ssl_ctx) % num_workers → worker_id`

---

#### `src/threading/worker.c` (~832 lines)
**Purpose:** Worker thread main loop

**Processing Order:**
1. `http1_try_process_event()` → if handled, return
2. `http2_try_process_event()` → if handled, return
3. `signature_detect()` + raw display

---

#### `src/threading/manager.c` (~481 lines)
**Purpose:** Thread lifecycle management

**Auto Thread Count:** `max(1, num_cpus - 3)` capped at 16

---

#### `src/threading/output.c` (~334 lines)
**Purpose:** Serialize output from workers to stdout

---

#### `src/threading/state.c` (~542 lines)
**Purpose:** Per-worker isolated state

**Per-Worker:**
- HTTP/2 session pool (16 sessions)
- ALPN cache (64 entries)
- Pending body buffers (256 entries)

---

### Output

#### `src/output/display.c` (~626 lines)
**Purpose:** Terminal output with ANSI colors

**Colors:** C_RESET, C_DIM, C_RED, C_GREEN, C_YELLOW, C_CYAN, C_MAGENTA

---

## Build System

### CMakeLists.txt

**Language:** C23 with `-Wall -Wextra -Wpedantic`

**Build Types:**
| Type | Flags |
|------|-------|
| Debug | `-O0 -g` + sanitizers |
| Release | `-O3` + LTO |
| RelWithSan | `-O2 -g` + sanitizers |

**Feature Flags:**
| Flag | Default | Purpose |
|------|---------|---------|
| `USE_VECTORSCAN` | ON | O(n) protocol detection |
| `USE_ZLIB_NG` | ON | SIMD decompression |
| `ENABLE_LTO` | ON | Link-time optimization |

**Dependencies:**
| Library | Purpose |
|---------|---------|
| libbpf | eBPF CO-RE loading |
| libelf | ELF binary parsing |
| zlib/zlib-ng | gzip decompression |
| zstd | Zstandard decompression |
| brotli | Brotli decompression |
| llhttp | HTTP/1.1 parsing |
| nghttp2 | HTTP/2 parsing |
| ck | Lock-free data structures |
| libxdp | XDP attachment |
| liburcu | RCU synchronization |
| jemalloc | Memory allocation |
| vectorscan/hyperscan | Pattern matching |
| pcre2 | Regex fallback |

---

## eBPF Programs

### Attachment Points

| Program Type | Attachment | Purpose |
|--------------|-----------|---------|
| uprobe | SSL library functions | Intercept decrypted TLS |
| xdp | Network interfaces | Classify packets |
| sock_ops | Cgroup2 | Cache socket cookies |
| tracepoint | sched_process_* | Process lifecycle |

### BPF Maps Summary

| Map | Key | Value | Size |
|-----|-----|-------|------|
| `ssl_events` | - | ring_buffer | 256 KB |
| `xdp_events` | - | ring_buffer | 256 KB |
| `ssl_to_fd` | SSL* | {fd, cookie} | 1024 |
| `flow_cookie_map` | 5-tuple | cookie | 8192 |
| `flow_states` | flow_key | state | 8192 |

---

## Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     KERNEL SPACE (eBPF)                         │
├─────────────────────────────────────────────────────────────────┤
│ uprobe: SSL_write(buf, len) → ssl_data_event → ringbuf          │
│ XDP: packet → flow state → xdp_packet_event → ringbuf           │
│ sock_ops: TCP established → flow_cookie_map[5-tuple] = cookie   │
└─────────────────────────────────────────────────────────────────┘
                    ↓ ring_buffer poll
┌─────────────────────────────────────────────────────────────────┐
│                   USER SPACE (spliff)                           │
├─────────────────────────────────────────────────────────────────┤
│ dispatcher_poll_ringbuf()                                       │
│   ↓ hash(pid, ssl_ctx) % num_workers                            │
│ worker input ring → worker thread                               │
│   ↓ flow_get_by_cookie() or shadow lookup                       │
│   ↓ http1_try_process_event() or http2_try_process_event()      │
│   ↓ output_write() → output ring → stdout                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Architectures

### 1. Shared Pool with Dual-Index Lookup

**Problem:** Events arrive from two async sources (SSL and XDP) with different identifiers.

**Solution:**
1. Pre-allocate 8192 flow contexts (no malloc in hot path)
2. Two indexes point to same pool:
   - `cookie_index[socket_cookie]` → primary, fast
   - `shadow_index[(pid, ssl_ctx)]` → fallback
3. Promote shadow → cookie when socket_cookie becomes available

### 2. Golden Thread (Socket Cookie Correlation)

**Three data sources linked by socket_cookie:**
- XDP: Raw packets with 5-tuple
- sock_ops: Socket state, caches cookie in `flow_cookie_map`
- SSL uprobes: Decrypted payload

**Result:** Single flow_context_t with complete L3/L4/L7 view

### 3. Connection Affinity

- `hash(pid, ssl_ctx) % num_workers` → deterministic routing
- Same connection always → same worker
- Worker has exclusive access (no locks on per-connection state)

### 4. Modular Protocol Architecture

```c
if (http1_try_process_event(...)) return;  // HTTP/1 handled
if (http2_try_process_event(...)) return;  // HTTP/2 handled
signature_detect(...);  // Fallback
```

### 5. Embedded BPF Skeleton (v0.9.6)

- BPF bytecode embedded via `bpftool gen skeleton`
- No external .bpf.o file needed
- Strip-safe, tamper-resistant single binary

---

## Known Issues & TODOs

### Protocol Detection
- [ ] HTTP parsing broken when ALPN event timing is off
- [ ] Need content-based protocol detection fallback
- [ ] ALPN event may arrive after data events

### Decompression
- [ ] ZSTD detected but not auto-decompressing bodies
- [ ] Content-Encoding header parsing incomplete

### Statistics
- [ ] Shutdown stats too basic for production
- [ ] Need per-worker metrics
- [ ] Missing latency percentiles

### Future Features
- [ ] HTTP/3 (QUIC) support
- [ ] WebSocket frame parsing
- [ ] TUI mode
- [ ] EDR/XDR integration

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Total Lines of Code | ~16,000+ |
| BPF Program | ~3,287 lines |
| Source Files | 25+ |
| SSL Libraries | 5 (OpenSSL, GnuTLS, NSS, WolfSSL, BoringSSL) |
| HTTP Protocols | 2 (HTTP/1.1, HTTP/2) |
| Decompression Formats | 4 |
| File Signatures | 50+ |
| Max Concurrent Flows | 8,192 |
| Max Workers | 16 |
| Max HTTP/2 Streams | 64 per flow |

---

*Last updated: v0.9.6 (January 2026)*
