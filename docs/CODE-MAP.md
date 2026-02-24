# CODE-MAP.md - spliff v0.10.0 Comprehensive Code Map

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

**spliff** is a production-grade eBPF-based SSL/TLS traffic sniffer that captures decrypted HTTPS traffic without MITM proxies. Version 0.10.0 (Omni-Ring Foundation) features:

- **SPMC Ring Transport** (v0.10.0): Vyukov bounded queue with mirrored virtual memory slots, 4096 capacity
- **Connection Affinity** (v0.10.0): MPSC overflow queues for misrouted stateful events (TTAS-CAS)
- **Reference Counting** (v0.10.0): `_Atomic uint32_t ref_count` with formal acquire/release lifecycle
- **Streaming Decompression** (v0.10.0): Per-flow gzip/zstd/brotli with bomb protection
- **Plaintext Flow Support** (v0.10.0): `FLOW_FLAG_PLAINTEXT` for non-TLS flows
- **Backpressure Control** (v0.10.0): Four-level hysteresis state machine (NORMAL→WARN→CRITICAL→SHED)
- **Dynamic Flow Pool**: On-demand allocation via jemalloc with incremental hash table resizing
- **XDP-SSL Correlation**: Socket cookie "Golden Thread" links packets, sockets, and TLS data
- **Three-File CMake** (v0.10.0): OBJECT libraries solve transitive dependency propagation
- **Embedded BPF Skeleton**: CO-RE BTF bytecode embedded in binary, strip-safe
- **RCU-Safe Memory Reclamation**: liburcu integration for safe deferred memory frees
- **Thread Safety**: Atomic counters, single-writer guarantees, correct ring semantics

---

## Directory Structure

```
spliff/
├── CMakeLists.txt                  # CMake build config (C23, LTO, sanitizers, packaging)
├── Makefile                        # Convenience wrapper for CMake targets
├── Doxyfile                        # Doxygen documentation config
├── README.md                       # User documentation, examples, features
├── CHANGELOG.md                    # Version history and migration notes
├── ISSUES.md                       # Known issues, limitations, resolved bugs
├── LICENSE                         # AGPL-3.0 for userspace, GPL-2.0 for BPF
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
│   │   ├── websocket.c             # WebSocket frame parser
│   │   └── websocket.h             # WebSocket API
│   ├── content/                    # Content decompression and identification
│   │   ├── decompressor.c          # Per-transaction gzip/zstd/brotli decompression
│   │   ├── decompressor.h          # Decompressor API
│   │   ├── stream_decompressor.c   # Per-flow streaming decompression with bomb protection (v0.10.0)
│   │   ├── stream_decompressor.h   # Streaming decompressor API
│   │   ├── signatures.c            # File magic detection (50+ formats)
│   │   └── signatures.h            # Signature database and API
│   ├── output/                     # Terminal output and logging
│   │   ├── display.c               # Colored output, startup display API (expanded v0.9.11)
│   │   ├── display.h               # Display API
│   │   ├── logger.c                # Async SPMC logging pipeline
│   │   ├── logger.h                # Logger API
│   │   ├── stats.c                 # Session statistics display
│   │   └── stats.h                 # Stats API
│   ├── correlation/                # XDP-SSL correlation and flow pooling
│   │   ├── flow_context.c          # Dynamic pool, dual-index lookup, deferred free
│   │   ├── flow_context.h          # flow_context_t, pool types, index types
│   │   ├── ck_cookie_index.c       # CK cookie hash table with RCU
│   │   ├── ck_cookie_index.h       # Cookie index API
│   │   ├── ck_shadow_index.c       # CK shadow hash table with RCU + secondary index
│   │   └── ck_shadow_index.h       # Shadow index API
│   ├── threading/                  # Multi-threaded event processing
│   │   ├── threading.h             # Threading API (reduced in v0.9.11)
│   │   ├── dispatcher.c            # BPF ring consumer, flow routing
│   │   ├── manager.c               # Thread lifecycle (init, start, shutdown)
│   │   ├── worker.c                # Worker thread main loop
│   │   ├── output.c                # Output serialization thread
│   │   ├── state.c                 # Per-worker state (minimal since v0.9.11)
│   │   ├── pool.c                  # Lock-free object pool
│   │   ├── deferred.c              # Per-worker deferred display queue
│   │   ├── deferred.h              # Deferred queue API
│   │   ├── xdp_ring.c              # Per-worker XDP SPSC ring
│   │   └── xdp_ring.h              # XDP ring API
│   ├── util/                       # Utility functions
│   │   ├── safe_str.c              # Safe string operations
│   │   ├── safe_str.h              # String API
│   │   ├── process.c               # Process info utilities (v0.9.11)
│   │   └── process.h               # Process API
│   ├── ring/                       # L1 ring transport (FROZEN, v0.10.0)
│   │   ├── ring_event.h            # 56-byte event, 64-bit routing word
│   │   ├── spmc_ring.h             # Vyukov SPMC ring with mirrored slots
│   │   ├── spmc_ring.c             # SPMC implementation with CAS backoff
│   │   ├── affinity.h              # Inline affinity check, MPSC overflow
│   │   ├── affinity.c              # Affinity routing implementation
│   │   ├── backpressure.h          # Four-level hysteresis state machine
│   │   ├── backpressure.c          # Backpressure implementation
│   │   ├── worker_dequeue.h        # Three-phase poll: overflow→SPMC→route
│   │   ├── worker_dequeue.c        # Worker dequeue implementation
│   │   └── adaptive_poll.h         # Header-only polling state machine
│   └── memory/                     # Memory infrastructure (v0.10.0)
│       ├── alignment.h             # Cache-line alignment macros
│       ├── mirrored_buffer.h       # Zero-copy mirrored virtual memory
│       ├── mirrored_buffer.c       # memfd + mmap mirrored buffer implementation
│       ├── hugepage.h              # Hugepage allocation helpers
│       ├── hugepage.c              # Hugepage implementation
│       ├── numa_alloc.h            # NUMA-aware allocation stubs
│       └── numa_alloc.c            # NUMA allocation implementation
├── src/CMakeLists.txt              # OBJECT libraries + main executable (v0.10.0)
├── tests/                          # Unit tests (17 suites, 19 files)
│   ├── CMakeLists.txt              # Test targets, CTest labels, module groups (v0.10.0)
│   ├── test_common.c              # Shared test helpers
│   ├── test_stubs.c               # Stub functions for isolated testing
│   ├── test_http1.c               # HTTP/1.x parser tests
│   ├── test_http2.c               # HTTP/2 parser tests
│   ├── test_flow_context.c        # Flow pool and dual-index tests
│   ├── test_flow_refcount.c       # Reference counting tests (v0.10.0)
│   ├── test_detector.c            # Vectorscan protocol detection tests
│   ├── test_websocket.c           # WebSocket frame parsing tests
│   ├── test_safe_str.c            # Safe string operation tests
│   ├── test_display.c             # Output formatting tests
│   ├── test_decompressor.c        # Per-transaction decompression tests
│   ├── test_stream_decompressor.c # Streaming decompression tests (v0.10.0)
│   ├── test_xdp.c                # XDP structure tests
│   ├── test_mirrored_buffer.c    # Mirrored buffer tests (v0.10.0)
│   ├── test_spmc_ring.c          # SPMC ring buffer tests (v0.10.0)
│   ├── test_concurrent.c         # Concurrent ring stress tests (v0.10.0)
│   ├── test_affinity.c           # Affinity routing tests (v0.10.0)
│   ├── test_backpressure.c       # Backpressure state machine tests (v0.10.0)
│   └── test_worker_dequeue.c     # Worker dequeue + adaptive poll tests (v0.10.0)
└── docs/                           # Documentation
    ├── ARCHITECTURE.md             # System diagrams and data flow
    ├── ARCHITECTURE-DECISIONS.md   # ADR-001 (SPMC), ADR-002 (three-layer), ADR-003 (session registry)
    ├── CODE-MAP.md                 # This file
    ├── REFACTOR-PLAN.md            # Omni-Ring implementation roadmap (Phases 1-9)
    ├── EDR_XDR_ROADMAP.md          # Long-term EDR/XDR vision
    └── TROUBLESHOOTING.md          # Common issues and solutions
```

---

## Source File Reference

### Core Entry Point

#### `src/main.c` (~1737 lines)
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
| `flow_key_t` | 16-byte 5-tuple for flow identification (IPv4) |
| `flow_key_v6_t` | 40-byte 5-tuple for IPv6 flows (v0.9.10) |
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
| `SPLIFF_VERSION` | "0.10.0" |

---

### eBPF Programs & Loading

#### `src/bpf/spliff.bpf.c` (~3372 lines)
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
| `ssl_to_fd` | LRU_HASH | SSL* → {fd, socket_cookie} |
| `flow_cookie_map` | hash | 5-tuple (IPv4) → socket_cookie |
| `flow_cookie_map_v6` | LRU_HASH | 40-byte IPv6 key → socket_cookie (v0.9.10) |
| `flow_states` | hash | flow_key → flow_state_t |

---

#### `src/bpf/bpf_loader.c` (~1786 lines)
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
| `find_cgroup2_mount()` | Dynamic cgroup2 path detection via /proc/mounts (v0.9.10) |
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

#### `src/bpf/binary_scanner.c` (~377 lines)
**Purpose:** Detect BoringSSL in Chrome/Chromium binaries via build ID lookup

---

### Protocol Parsing

#### `src/protocol/detector.c` (~276 lines)
**Purpose:** O(n) protocol detection using vectorscan NFA

**Detection Results:**
| Result | Pattern |
|--------|---------|
| `PROTO_DETECT_HTTP1_REQ` | `^(GET\|POST\|PUT\|...)` |
| `PROTO_DETECT_HTTP1_RSP` | `^HTTP/1\.[01]` |
| `PROTO_DETECT_HTTP2` | `^PRI \* HTTP/2.0` |
| `PROTO_DETECT_TLS` | `^\x16\x03` |

---

#### `src/protocol/http1.c` (~1163 lines)
**Purpose:** Parse HTTP/1.1 using llhttp (Node.js parser)

**Key Functions:**
| Function | Purpose |
|----------|---------|
| `http1_init()` | Initialize llhttp settings |
| `http1_try_process_event()` | Unified entry point |
| `http1_is_request()` | Heuristic request check |
| `http1_is_response()` | Heuristic response check |

---

#### `src/protocol/http2.c` (~1466 lines)
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

#### `src/content/decompressor.c` (~237 lines)
**Purpose:** Per-transaction HTTP body decompression

**Supported Formats:**
| Format | Library |
|--------|---------|
| gzip | zlib/zlib-ng |
| deflate | zlib |
| zstd | libzstd |
| brotli | libbrotlidec |

---

#### `src/content/stream_decompressor.c` (~350 lines) (NEW v0.10.0)
**Purpose:** Per-flow streaming decompression with bomb protection

**Key Features:**
- Streaming state persists across chunks (embedded in `body_ctx_t`)
- Bomb protection: >1000:1 ratio or >100MB output → permanent reject
- gzip/deflate (zlib-ng), zstd (ZSTD_DStream, windowLogMax=23), brotli
- Cleanup via `flow_free_resources()` on flow termination

**Key Functions:**
| Function | Purpose |
|----------|---------|
| `stream_decomp_init()` | Initialize streaming state for encoding |
| `stream_decomp_feed()` | Feed compressed chunk, get decompressed output |
| `stream_decomp_reset()` | Reset between HTTP transactions |
| `stream_decomp_cleanup()` | Free library contexts |

---

#### `src/content/signatures.c` (~694 lines)
**Purpose:** Identify file types via magic bytes (50+ formats)

**Categories:** Images, Video, Audio, Archives, Documents, Data formats

---

### Flow Correlation

#### `src/correlation/flow_context.h` (~1008 lines)
**Purpose:** Type definitions for dynamic flow pool architecture

**Key Types:**
```c
typedef struct flow_context {
    /* Cache Line 0: Identity + Lifecycle */
    uint64_t socket_cookie;         // "Golden Thread" correlation key
    uint32_t pid;                   // Process ID
    uint32_t generation;            // Allocation generation (stale pointer detect)
    uint64_t ssl_ctx;               // SSL context pointer
    flow_id_t self_id;              // Monotonic ID (debugging)
    struct flow_context *list_prev; // Active/deferred list pointer
    struct flow_context *list_next; // Active/deferred list pointer

    /* Network View (from XDP) */
    flow_key_t flow;                // 5-tuple: IPs and ports
    uint32_t ifindex;               // Network interface index
    uint64_t first_seen_ns;         // First packet timestamp
    uint64_t last_seen_ns;          // Last activity timestamp

    /* Traffic Counters (atomic v0.9.10) */
    _Atomic uint32_t pkts_in, pkts_out;
    _Atomic uint32_t bytes_in, bytes_out;

    /* Application View (from SSL) */
    char comm[16], alpn[16], ifname[16];

    /* Lifecycle (v0.10.0) */
    _Atomic uint32_t ref_count;     // Reference counting (replaces inflight_events)
                                    // flow_ref_acquire() / flow_ref_release()

    /* State and Flags */
    flow_proto_t proto;             // UNKNOWN, HTTP1, HTTP2, OTHER
    flow_state_t state;             // INIT, ACTIVE, CLOSING, CLOSED
    _Atomic uint8_t flags;          // HAS_XDP, HAS_SSL, IN_COOKIE, IN_SHADOW, PLAINTEXT

    /* Protocol Parser (union to save memory) */
    union {
        h1_parser_ctx_t h1;         // HTTP/1.x context
        h2_parser_ctx_t h2;         // HTTP/2 context
    } parser;

    /* Per-Flow Streaming Decompression (v0.10.0) */
    body_ctx_t body_ctx;            // Embedded stream_decomp_t with bomb protection
    ...
} flow_context_t;
```

**Dual-Index Lookup:**
- `cookie_index`: socket_cookie → `flow_context_t*` (primary, direct pointer)
- `shadow_index`: (pid, ssl_ctx) → `flow_context_t*` (fallback)
- Both use incremental resizing (8 entries/op at 75% load factor)

---

#### `src/correlation/flow_context.c` (~1450 lines)
**Purpose:** Dynamic pool management, dual-index lookup, deferred free, stream allocation

**Key Functions:**
| Function | Purpose |
|----------|---------|
| `flow_pool_init()` | Initialize pool (empty, on-demand allocation) |
| `flow_pool_alloc()` | Allocate flow via jemalloc (cache-line aligned) |
| `flow_pool_free()` | Deferred free (2-second grace period) |
| `flow_pool_drain_deferred()` | Reclaim deferred flows after grace period |
| `flow_manager_init()` | Initialize manager with pool + indexes (256-entry tables) |
| `flow_lookup()` | Dual-index lookup (cookie then shadow) |
| `flow_get_or_create()` | Lookup or allocate new flow |
| `flow_promote_cookie()` | Move shadow → cookie index when cookie becomes known |
| `flow_terminate()` | Remove from indexes, defer free |
| `flow_evict_stale()` | Janitor: evict inactive flows (O(active) scan) |
| `flow_update_xdp()` | Merge XDP packet metadata into flow |
| `flow_merge_ssl_info()` | Single-writer SSL info merge (v0.9.10) |
| `flow_manager_get_stats()` | Collect pool/index statistics for shutdown report |
| `flow_manager_print_stats()` | Print formatted session statistics |

---

#### `src/correlation/ck_cookie_index.c` (~230 lines) (v0.9.9, RCU v0.9.10)
**Purpose:** Lock-free cookie hash table using Concurrency Kit with liburcu integration

**Key Features:**
- SPMC-safe lookups (multiple workers, single dispatcher writer)
- Incremental resize with tombstone GC
- ~256 initial capacity, grows at 75% load
- **RCU-safe deferred free via `call_rcu()`** (v0.9.10)

**Key Functions:**
| Function | Purpose |
|----------|---------|
| `ck_cookie_index_init()` | Initialize CK hash set |
| `ck_cookie_index_insert()` | Insert cookie → flow mapping |
| `ck_cookie_index_lookup()` | Lock-free lookup by cookie |
| `ck_cookie_index_remove()` | Remove entry |

---

#### `src/correlation/ck_shadow_index.c` (~360 lines) (v0.9.9, RCU + Secondary Index v0.9.10)
**Purpose:** Lock-free shadow hash table for (pid, ssl_ctx) lookup with liburcu integration and secondary cookie index

**Key Features:**
- Used before socket_cookie is known
- Same SPMC-safe design as cookie index
- Flows promoted to cookie index via `flow_promote_cookie()`
- **RCU-safe deferred free via `call_rcu()`** (v0.9.10)
- **Secondary cookie index** for O(1) lookup by socket_cookie (v0.9.10, fixes M7)

**Dual Index Structure (v0.9.10):**
```c
typedef struct {
    ck_hs_t hs;           // Primary: (pid, ssl_ctx) → flow_context
    ck_hs_t by_cookie;    // Secondary: socket_cookie → flow_context (O(1))
    // ... stats
} ck_shadow_index_t;
```

**Key Functions:**
| Function | Purpose |
|----------|---------|
| `ck_shadow_index_init()` | Initialize both CK hash sets |
| `ck_shadow_index_insert()` | Insert (pid, ssl_ctx) → flow |
| `ck_shadow_index_lookup()` | Lock-free lookup by composite key |
| `ck_shadow_find_by_cookie()` | O(1) lookup by socket_cookie (v0.9.10) |
| `ck_shadow_index_add_cookie()` | Add to secondary cookie index (v0.9.10) |
| `ck_shadow_index_remove()` | Remove from both indexes |

---

### Threading

#### `src/threading/threading.h` (~1060 lines, reduced from ~1376 in v0.9.10)
**Purpose:** Threading infrastructure definitions (H2 pool types removed in v0.9.11)

**Configuration:**
| Constant | Value |
|----------|-------|
| `MAX_WORKERS` | 16 |
| `EVENT_RING_SIZE` | 4096 |
| `NAPI_BUDGET` | 64 events/loop |
| `EPOLL_TIMEOUT_MS` | 100 |

---

#### `src/threading/dispatcher.c` (~730 lines)
**Purpose:** Route events from BPF to workers (single-writer for flow mutations)

**Routing:** `hash(pid, ssl_ctx) % num_workers → worker_id`

**Thread Safety (v0.9.10):**
- Calls `flow_merge_ssl_info()` for single-writer SSL info updates
- RCU thread registration (`urcu_memb_register/unregister_thread`)

---

#### `src/threading/worker.c` (~850 lines)
**Purpose:** Worker thread main loop with NAPI-style adaptive polling

**Processing Order:**
1. `http1_try_process_event()` → if handled, return
2. `http2_try_process_event()` → if handled, return
3. `signature_detect()` + raw display

**Safety:**
- Generation check on dequeued events detects stale flow pointers
- **RCU thread registration** (`urcu_memb_register/unregister_thread`) (v0.9.10)

---

#### `src/threading/manager.c` (~393 lines)
**Purpose:** Thread lifecycle management

**Auto Thread Count:** `max(1, num_cpus - 3)` capped at 16

---

#### `src/threading/output.c` (~281 lines)
**Purpose:** Serialize output from workers to stdout

---

#### `src/threading/state.c` (~120 lines, reduced from ~620 in v0.9.10)
**Purpose:** Per-worker isolated state (minimal since v0.9.11)

**Per-Worker (v0.9.11):**
- Decompression buffer
- Body buffer
- HTTP/2 callbacks reference

**Removed in v0.9.11:** HTTP/2 session pools, ALPN cache, pending body buffers, H1 request cache
(all moved to per-flow management in flow_context_t)

---

#### `src/threading/deferred.c` (~424 lines) (NEW v0.9.9)
**Purpose:** Per-worker deferred display queue for XDP-SSL correlation timing

**Key Features:**
- Waits for FLOW_FLAG_HAS_XDP before display
- 100ms normal timeout, 20ms under load (backpressure)
- Force flush oldest 10% when queue exceeds max
- Checks xdp_category != UNKNOWN before display

**Key Functions:**
| Function | Purpose |
|----------|---------|
| `deferred_queue_init()` | Initialize per-worker queue |
| `deferred_display_or_enqueue()` | Display now or defer for XDP |
| `deferred_queue_flush()` | Process timed-out entries |

---

#### `src/threading/xdp_ring.c` (~132 lines) (v0.9.9, assertions v0.9.10)
**Purpose:** Per-worker XDP SPSC ring for event delivery

**Key Features:**
- Fixes timing race: workers check HAS_XDP before dispatcher polls
- Workers drain XDP ring FIRST, then process SSL events
- eventfd instant wakeup on ring push
- **`_Static_assert` for power-of-2 ring size** (v0.9.10)

**Key Functions:**
| Function | Purpose |
|----------|---------|
| `xdp_ring_init()` | Initialize SPSC ring + eventfd |
| `xdp_ring_push()` | Dispatcher pushes XDP event |
| `xdp_ring_pop()` | Worker pops XDP event |

---

### Ring Transport (L1 — FROZEN, v0.10.0)

#### `src/ring/ring_event.h` (header-only)
**Purpose:** 56-byte event structure with 64-bit routing word for connection affinity

#### `src/ring/spmc_ring.h/c` (~600 lines)
**Purpose:** Vyukov-style SPMC ring with mirrored virtual memory slots, CAS backoff, mlock

**Key Features:**
- Single-producer (dispatcher), multi-consumer (workers)
- Mirrored buffer eliminates wrap-around branching
- Exponential CAS backoff (4 workers optimal, 8+ degrades)

#### `src/ring/affinity.h/c` (~500 lines)
**Purpose:** Connection affinity routing with per-worker MPSC overflow queues

**Key Features:**
- Inline affinity check: `hash(pid, ssl_ctx) % num_workers`
- MPSC overflow (TTAS-CAS) for misrouted stateful events
- Cache-isolated producer/consumer lines (zero false sharing)

#### `src/ring/backpressure.h/c` (~300 lines)
**Purpose:** Four-level hysteresis state machine (NORMAL → WARN → CRITICAL → SHED)

#### `src/ring/worker_dequeue.h/c` (~400 lines)
**Purpose:** Three-phase consumption: overflow → SPMC → affinity route

#### `src/ring/adaptive_poll.h` (header-only)
**Purpose:** Polling state machine with exponential backoff for worker threads

---

### Memory Infrastructure (v0.10.0)

#### `src/memory/mirrored_buffer.h/c` (~300 lines)
**Purpose:** Zero-copy mirrored virtual memory via memfd + mmap for wrap-free ring buffers

**Key Features:**
- Two virtual mappings of the same physical pages (memfd-backed)
- Pre-fault with `MAP_POPULATE` + `mlock`
- memfd sealing (F_SEAL_SHRINK | F_SEAL_GROW) for safety

#### `src/memory/hugepage.h/c` (~200 lines)
**Purpose:** Transparent hugepage allocation for large ring buffer backing stores

#### `src/memory/alignment.h` (header-only)
**Purpose:** Cache-line alignment macros (`CACHE_ALIGNED`, `CACHELINE_SIZE`)

#### `src/memory/numa_alloc.h/c` (~100 lines)
**Purpose:** NUMA-aware allocation stubs (future: pin worker memory to local NUMA node)

---

### Output

#### `src/output/display.c` (~730 lines, expanded in v0.9.11)
**Purpose:** Terminal output with ANSI colors, dual checkmark XDP correlation display, centralized startup/diagnostic output

**Colors:** C_RESET, C_DIM, C_RED, C_GREEN, C_YELLOW, C_CYAN, C_MAGENTA

**Output Format:**
- `[XDP:TLS][App:H2] ✓✓` - Both XDP and App layer verified
- `[XDP:?][App:H1] ✓` - App layer only (XDP pending)
- XDP protocols: TLS, QUIC, HTTP, H2, Other, ?

**Startup Display API (v0.9.11):**
| Function | Purpose |
|----------|---------|
| `display_banner()` | Print startup header with version |
| `display_lib_found()` | Library discovery messages |
| `display_probe_attached()` | Probe attachment status |
| `display_xdp_attached()` | XDP interface attachment |
| `display_cgroup_attached()` | Cgroup sock_ops attachment |
| `display_warmup_status()` | BPF map warmup statistics |
| `display_error()` | Thread-safe stderr error output |
| `display_warning()` | Thread-safe stderr warning output |
| `display_debug()` | Debug-mode-only output |

---

#### `src/output/logger.c` (~470 lines) (v0.9.9, SPMC fix v0.9.10)
**Purpose:** Async logging pipeline for lock-free output serialization

**Key Features:**
- **SPMC free_ring** (multiple workers dequeue, single logger enqueues) - fixed v0.9.10
- MPSC log_ring for log messages
- Cache-aligned ring buffer storage (64-byte alignment v0.9.10)
- eventfd notification (edge-triggered)
- writev() batching for atomic output
- Zero malloc in hot path

**Key Functions:**
| Function | Purpose |
|----------|---------|
| `logger_init()` | Initialize ring buffer and entry pool |
| `log_enqueue()` | Push message to MPSC ring (lock-free) |
| `logger_thread_func()` | Consumer thread - batches and writes |
| `logger_shutdown()` | Drain queue and cleanup |

---

#### `src/output/stats.c` (~272 lines) (NEW v0.9.9)
**Purpose:** Unified session statistics display at shutdown

**Key Functions:**
| Function | Purpose |
|----------|---------|
| `stats_display()` | Print all session statistics |
| `stats_collect_worker()` | Gather per-worker metrics |
| `stats_collect_flow_pool()` | Gather flow pool metrics |

---

## Build System

### Architecture (3-File CMake Split, v0.10.0)

The build system uses three CMake files with OBJECT libraries to solve the transitive
dependency problem — adding a new dependency to `flow_context.c` now propagates automatically
to all test targets.

| File | Lines | Purpose |
|------|-------|---------|
| `CMakeLists.txt` | ~800 | Options, deps, BPF skeleton, docs, install, CPack |
| `src/CMakeLists.txt` | ~190 | 3 OBJECT libraries + main executable |
| `tests/CMakeLists.txt` | ~290 | INTERFACE library + 17 test targets + CTest labels |

**OBJECT Libraries:**
| Library | Files | Purpose |
|---------|-------|---------|
| `spliff_memory` | 1 | `mirrored_buffer.c` — shared by core + ring |
| `spliff_core` | 15 | Correlation, protocol, content, threading, util |
| `spliff_ring` | 4 | L1 transport layer (FROZEN) |

**INTERFACE Library:**
- `spliff_common_deps` wraps 9 shared link dependencies for heavy test targets
- Uses `${ALLOCATOR_TARGET}` (jemalloc or mimalloc) instead of hardcoded `PkgConfig::JEMALLOC`

**Language:** C23 with `-Wall -Wextra -Wpedantic`

**Build Types:**
| Type | Flags |
|------|-------|
| Debug | `-O0 -g` + sanitizers |
| Release | `-O3` + LTO |
| RelWithSan | `-O2 -g` + sanitizers |

**BPF Skeleton Generation:**
- `bpftool gen skeleton` embeds BPF bytecode at build time
- Target `bpf_skeleton` generates `spliff.skel.h` from compiled `spliff.bpf.o`

**Feature Flags:**
| Flag | Default | Purpose |
|------|---------|---------|
| `USE_VECTORSCAN` | ON | O(n) protocol detection |
| `USE_ZLIB_NG` | ON | SIMD decompression |
| `USE_MIMALLOC` | OFF | mimalloc instead of jemalloc |
| `ENABLE_LTO` | ON | Link-time optimization |
| `ENABLE_ZSTD` | ON | zstd decompression |
| `ENABLE_BROTLI` | ON | brotli decompression |

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
| jemalloc/mimalloc | Memory allocation |
| vectorscan/hyperscan | Pattern matching |
| pcre2 | Regex fallback |

### Makefile (Ninja Auto-Detection, v0.10.0)

The Makefile auto-detects Ninja for 2-5x faster incremental builds and provides
module-level test targets using CTest labels.

**Module Test Targets:**
| Target | Label | Suites |
|--------|-------|--------|
| `make test-ring` | ring | 5 (spmc_ring, affinity, concurrent, backpressure, worker_dequeue) |
| `make test-protocol` | protocol | 4 (http1, http2, websocket, detector) |
| `make test-flow` | flow | 2 (flow_context, flow_refcount) |
| `make test-content` | content | 2 (decompressor, stream_decompressor) |
| `make test-memory` | memory | 1 (mirrored_buffer) |
| `make test-util` | util | 3 (safe_str, display, xdp) |

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
| `ssl_to_fd` | SSL* | {fd, cookie} | LRU 8192 (v0.9.10) |
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
│   ↓ pack into ring_event_t (56B, routing word)                  │
│   ↓ enqueue to SPMC ring (4096 mirrored slots)                  │
│                                                                  │
│ worker_dequeue (three-phase poll):                               │
│   1. drain MPSC overflow inbox (zero CAS, highest priority)     │
│   2. dequeue from shared SPMC ring (CAS tail advance)           │
│   3. affinity_check → local or defer to target overflow queue   │
│   ↓ flow_lookup() — cookie_index (fast) or shadow_index         │
│   ↓ generation check — detect stale pointers                    │
│   ↓ http1_try_process_event() or http2_try_process_event()      │
│   ↓ output_write() → output ring → stdout                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Architectures

### 1. Dynamic Flow Pool with Dual-Index Lookup

**Problem:** Events arrive from two async sources (SSL and XDP) with different identifiers.

**Solution:**
1. Allocate flow contexts on-demand via jemalloc (~37 KB each, cache-line aligned)
2. Two pointer-based indexes into allocated flows:
   - `cookie_index[socket_cookie]` → `flow_context_t*` (primary, fast)
   - `shadow_index[(pid, ssl_ctx)]` → `flow_context_t*` (fallback)
3. Promote shadow → cookie when socket_cookie becomes available
4. Incremental hash table resizing (8 entries/op at 75% load, no stop-the-world rehash)
5. Deferred free with 2-second grace period + generation counters for stale pointer safety

### 2. Golden Thread (Socket Cookie Correlation)

**Three data sources linked by socket_cookie:**
- XDP: Raw packets with 5-tuple
- sock_ops: Socket state, caches cookie in `flow_cookie_map`
- SSL uprobes: Decrypted payload

**Result:** Single flow_context_t with complete L3/L4/L7 view

### 3. Connection Affinity (v0.10.0)

- `socket_cookie % num_workers` → deterministic routing via SPMC ring routing word
- Stateless events (HTTP/1) processed by any worker (AFFINITY_LOCAL)
- Stateful events (HTTP/2, WebSocket) routed to preferred worker
- Misrouted events → MPSC overflow queue (TTAS-CAS push, zero-CAS drain)
- Overflow full → process locally (slow path, increment `misrouted_local_hits`)

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

### 6. Centralized Session Statistics (v0.9.7)

- Unified shutdown report collects metrics from all subsystems
- Per-worker event counts, retry stats, CPU efficiency
- Flow pool analytics: active/peak counts, index hit rates, promotion rate
- XDP classification: packets, flows, sockops, correlation success rate
- SSL probe counters: total SSL_read/SSL_write interceptions

### 7. Thread Safety Model (v0.9.10)

**Single-Writer Pattern:**
- Dispatcher thread owns all write operations to flow indexes
- `flow_merge_ssl_info()` isolates SSL context writes to single writer
- Workers perform read-only lookups with atomic reads

**RCU Integration (liburcu):**
- `call_rcu()` for safe deferred memory reclamation in CK hash tables
- Threads register/unregister via `urcu_memb_register_thread()`
- Grace periods ensure readers never see freed memory

**Atomic Counters:**
- Per-flow counters (`pkts_in`, `bytes_in`, etc.) use `_Atomic uint32_t`
- Memory ordering: `memory_order_relaxed` for performance (counters are approximate)

**Ring Buffer Semantics (v0.10.0):**
- SPMC event ring: dispatcher→workers (Vyukov bounded, CAS tail, 4096 mirrored slots)
- MPSC overflow: workers→home worker (per-worker inbox, TTAS-CAS head, 64 slots)
- Logger `free_ring`: SPMC (workers dequeue, logger enqueues)
- Logger `log_ring`: MPSC (workers enqueue, logger dequeues)
- XDP rings: SPSC (dispatcher to worker)

---

## Known Issues & TODOs

See [../ISSUES.md](../ISSUES.md) for the full list of open issues, known limitations, and resolved bugs.

### Future Features
- [ ] Protocol detection engine + multi-protocol routing (Phase 4, v0.11.0)
- [ ] HTTP/3 (QUIC) support (planned v0.11.0)
- [ ] WebSocket upgrade detection + frame parsing (planned v0.11.0)
- [ ] TUI mode
- [ ] EDR/XDR agent mode + NATS event streaming

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Total Lines of Code | ~32,600 |
| BPF Program | ~3,372 lines |
| Source Files | 67 (.c + .h in src/) |
| Test Suites | 17 (19 test files) |
| SSL Libraries | 5 (OpenSSL, GnuTLS, NSS, WolfSSL, BoringSSL) |
| HTTP Protocols | 2 (HTTP/1.1, HTTP/2) |
| Decompression Formats | 4 (gzip, deflate, zstd, brotli) |
| File Signatures | 50+ |
| Max Workers | 16 |
| Max HTTP/2 Streams | 64 per flow |
| SPMC Ring Slots | 4096 (mirrored, zero-copy) |
| Overflow Queue | 64 slots per worker (MPSC) |

---

*Last updated: v0.10.0 (February 2026)*
