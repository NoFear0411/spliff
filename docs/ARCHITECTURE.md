# spliff Architecture

> Back to [README](../README.md)

## System Architecture

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│                                    USER SPACE                                             │
│                                                                                           │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐    │
│  │                              Applications                                         │    │
│  │   ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐                 │    │
│  │   │  curl   │  │ Firefox │  │ Chrome  │  │  Brave  │  │  wget   │                 │    │
│  │   └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘                 │    │
│  │        │            │            │            │            │                      │    │
│  │   ┌────▼────┐  ┌────▼────┐  ┌────▼────────────▼────┐  ┌────▼────┐                 │    │
│  │   │ OpenSSL │  │   NSS   │  │     BoringSSL ⚠️     │  │ GnuTLS  │  SSL Libraries  │    │
│  │   └────┬────┘  └────┬────┘  └──────────┬───────────┘  └────┬────┘                 │    │
│  │        │            │                  │                   │                      │    │
│  │        └────────────┴────────┬─────────┴───────────────────┘                      │    │
│  └──────────────────────────────┼────────────────────────────────────────────────────┘    │
│                                 │                                                         │
│                          ╔══════▼══════╗                                                  │
│                          ║ BPF Uprobes ║ ◄─── Dynamic attachment via /proc/PID/maps       │
│                          ╚══════╤══════╝      + BoringSSL binary scanning                 │
│                                 │                                                         │
│  ┌──────────────────────────────▼────────────────────────────────────────────────────┐    │
│  │                              spliff                                               │    │
│  │                                                                                   │    │
│  │  ┌──────────────────────────────────────────────────────────────────────────┐     │    │
│  │  │                        Ring Buffer Consumers                             │     │    │
│  │  │   ┌──────────────┐  ┌──────────────┐  ┌───────────────┐                  │     │    │
│  │  │   │ ssl_events   │  │ xdp_events   │  │ process_events│                  │     │    │
│  │  │   │ (TLS data)   │  │ (packets)    │  │ (exec/fork)   │                  │     │    │
│  │  │   └──────┬───────┘  └──────┬───────┘  └───────┬───────┘                  │     │    │
│  │  └──────────┼─────────────────┼──────────────────┼──────────────────────────┘     │    │
│  │             │                 │                  │                                │    │
│  │             └────────────┬────┴──────────────────┘                                │    │
│  │                          │    "Golden Thread" Correlation                         │    │
│  │                          │    (socket cookie links all three)                     │    │
│  │                          ▼                                                        │    │
│  │  ┌───────────────────────────────────────────────────────────────────────────┐    │    │
│  │  │   Dispatcher Thread                                                       │    │    │
│  │  │   ┌─────────────────────────────────────────────────────────────────────┐ │    │    │
│  │  │   │  flow_pool (dynamic)        cookie_index     shadow_index           │ │    │    │
│  │  │   │  malloc/free per flow       cookie → ctx*    (pid,ssl) → ctx*       │ │    │    │
│  │  │   └─────────────────────────────────────────────────────────────────────┘ │    │    │
│  │  │   • Dual-index lookup: cookie_index (fast) or shadow_index (fallback)     │    │    │
│  │  │   • XDP+SSL merge: flows gain HAS_XDP/HAS_SSL flags as events arrive      │    │    │
│  │  │   • Connection affinity: hash(pid, ssl_ctx) routes to consistent worker   │    │    │
│  │  └───────────┬───────────────────────────────────────────────────────────────┘    │    │
│  │              │ event + flow_context_t*                                            │    │
│  │      ┌───────┼───────┬───────────────┐                                            │    │
│  │      ▼       ▼       ▼               ▼                                            │    │
│  │  ┌───────┐┌───────┐┌───────┐    ┌───────┐   Lock-free SPSC queues                 │    │
│  │  │Worker0││Worker1││Worker2│... │WorkerN│   (Concurrency Kit)                     │    │
│  │  ├───────┤├───────┤├───────┤    ├───────┤                                         │    │
│  │  │ Claim ││ Claim ││ Claim │    │ Claim │   Worker claims flow via atomic CAS     │    │
│  │  │ flow  ││ flow  ││ flow  │    │ flow  │   on home_worker_id (single-writer)     │    │
│  │  └───┬───┘└───┬───┘└───┬───┘    └───┬───┘                                         │    │
│  │      │        │        │            │                                             │    │
│  │      └────────┴────────┴─────┬──────┘                                             │    │
│  │                              │                                                    │    │
│  │                              ▼                                                    │    │
│  │  ┌───────────────────────────────────────────────────────────────────────────┐    │    │
│  │  │   Protocol Detection & Routing (v0.9.5+)                                  │    │    │
│  │  │                                                                           │    │    │
│  │  │   ┌─────────────────┐                                                     │    │    │
│  │  │   │   Vectorscan    │  O(n) NFA pattern matching                          │    │    │
│  │  │   │   (proto_detect)│  HTTP/1, HTTP/2, TLS, WebSocket patterns            │    │    │
│  │  │   └────────┬────────┘                                                     │    │    │
│  │  │            │                                                              │    │    │
│  │  │            ▼                                                              │    │    │
│  │  │   ┌────────────────────────────────────────────────────────────────┐      │    │    │
│  │  │   │  if (http1_try_process_event()) return;  ──► http1.c           │      │    │    │
│  │  │   │  if (http2_try_process_event()) return;  ──► http2.c           │      │    │    │
│  │  │   │  fallback: signature detection, raw display                    │      │    │    │
│  │  │   └────────────────────────────────────────────────────────────────┘      │    │    │
│  │  │                                                                           │    │    │
│  │  │   Per-FLOW state (flow_context_t):                                        │    │    │
│  │  │   • flags: HAS_XDP, HAS_SSL, IN_COOKIE, IN_SHADOW                         │    │    │
│  │  │   • nghttp2 session + HPACK inflater + streams[64]                        │    │    │
│  │  │   • llhttp parser + current transaction                                   │    │    │
│  │  │   • ALPN, body buffers, hpack_corrupted                                   │    │    │
│  │  └───────────────────────────────────────────────────────────────────────────┘    │    │
│  │                              │                                                    │    │
│  │                              ▼                                                    │    │
│  │              ┌───────────────────────────┐                                        │    │
│  │              │      Output Thread        │  Serialized stdout/file                │    │
│  │              │  • Body decompression     │  (no interleaving)                     │    │
│  │              │  • File signature detect  │                                        │    │
│  │              └───────────────────────────┘                                        │    │
│  └───────────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                           │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│                                    KERNEL SPACE                                           │
│                                                                                           │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐     │
│  │                           BPF Programs (CO-RE/BTF)                               │     │
│  │                                                                                  │     │
│  │  ┌─────────────────────────────────────────────────────────────────────────┐     │     │
│  │  │                    XDP (eXpress Data Path)                              │     │     │
│  │  │                                                                         │     │     │
│  │  │   NIC ──► Packet ──► Flow State Machine ──► Protocol Classify           │     │     │
│  │  │           │         (SYN/DATA/FIN/RST)     (TLS/HTTP2/HTTP1)            │     │     │
│  │  │           ▼                                       │                     │     │     │
│  │  │      flow_states map                              ▼                     │     │     │
│  │  │           │                              xdp_events ring ──► userspace  │     │     │
│  │  │           │                                                             │     │     │
│  │  └───────────┼─────────────────────────────────────────────────────────────┘     │     │
│  │              │                                                                   │     │
│  │              │ lookup                                                            │     │
│  │              ▼                                                                   │     │
│  │  ╔═══════════════════════════════════════════════════════════════════════════╗   │     │
│  │  ║                    SOCKET COOKIE - "Golden Thread"                        ║   │     │
│  │  ║                                                                           ║   │     │
│  │  ║              ┌─────────────────┐       ┌─────────────────┐                ║   │     │
│  │  ║              │ flow_cookie_map │       │   ssl_to_fd     │                ║   │     │
│  │  ║              │ (5-tuple:cookie)│       │ (SSL*:fd:cookie)│                ║   │     │
│  │  ║              └────────┬────────┘       └────────┬────────┘                ║   │     │
│  │  ║                       │                         │                         ║   │     │
│  │  ║                       └────────────┬────────────┘                         ║   │     │
│  │  ║                                    │                                      ║   │     │
│  │  ║                           Socket Cookie (u64)                             ║   │     │
│  │  ║                      Links: Packets ↔ Sockets ↔ TLS Data                  ║   │     │
│  │  ║                                    │                                      ║   │     │
│  │  ╚════════════════════════════════════╪══════════════════════════════════════╝   │     │
│  │                 ┌─────────────────────┼─────────────────────┐                    │     │
│  │                 │                     │                     │                    │     │
│  │                 ▼                     ▼                     ▼                    │     │
│  │  ┌──────────────────────┐ ┌──────────────────────┐ ┌──────────────────────┐      │     │
│  │  │   sock_ops           │ │   Uprobes            │ │   (correlation)      │      │     │
│  │  │   (Socket Events)    │ │   (TLS Interception) │ │                      │      │     │
│  │  ├──────────────────────┤ ├──────────────────────┤ │  XDP packet metadata │      │     │
│  │  │ • ESTABLISHED_CB     │ │ • SSL_read/write     │ │  + sock state        │      │     │
│  │  │   → cache cookie     │ │   → decrypt data     │ │  + TLS plaintext     │      │     │
│  │  │ • STATE_CB           │ │ • SSL_set_fd         │ │  + PID/process       │      │     │
│  │  │   → cleanup on close │ │   → link SSL*→cookie │ │                      │      │     │
│  │  │                      │ │ • SSL_get_alpn       │ │  = Complete L7 view  │      │     │
│  │  │                      │ │   → protocol detect  │ │                      │      │     │
│  │  └──────────────────────┘ └──────────────────────┘ └──────────────────────┘      │     │
│  │                                                                                  │     │
│  │  ┌────────────────────────────────────────────────────────────────────────┐      │     │
│  │  │                    Tracepoints (Process Lifecycle)                     │      │     │
│  │  │                                                                        │      │     │
│  │  │   sched_process_exec ──► Detect new process ──► Dynamic probe attach   │      │     │
│  │  │   sched_process_fork ──► Track child processes                         │      │     │
│  │  │   sched_process_exit ──► Cleanup PID state ──► Free HTTP/2 sessions    │      │     │
│  │  │                                                                        │      │     │
│  │  └────────────────────────────────────────────────────────────────────────┘      │     │
│  │                                                                                  │     │
│  └──────────────────────────────────────────────────────────────────────────────────┘     │
│                                                                                           │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

## The "Golden Thread" – How Correlation Works

```
                            SOCKET COOKIE (u64)
                     ═══════════════════════════════
                     Unique per-TCP-connection identifier
                     generated by kernel, cached by sock_ops
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│      XDP      │   │   sock_ops    │   │    Uprobes    │
│   (packets)   │   │   (sockets)   │   │  (TLS data)   │
├───────────────┤   ├───────────────┤   ├───────────────┤
│ • Raw packets │   │ • TCP state   │   │ • Decrypted   │
│ • 5-tuple     │   │ • Connection  │   │   plaintext   │
│ • Flow state  │   │   lifecycle   │   │ • SSL context │
│ • Protocol ID │   │ • Cookie gen  │   │ • ALPN proto  │
└───────┬───────┘   └───────┬───────┘   └───────┬───────┘
        │                   │                   │
        │                   │                   │
════════╪═══════════════════╪═══════════════════╪════════════════
        │    KERNEL SPACE   │                   │
────────┼───────────────────┼───────────────────┼────────────────
        │    USER SPACE     │                   │
        │                   │                   │
        │  ┌────────────────┴───────────────────┴──────────┐
        │  │           BPF RING BUFFERS                    │
        │  │  ssl_events    xdp_events    process_events   │
        │  └────────────────────┬──────────────────────────┘
        │                       │
        │                       ▼
        │  ┌────────────────────────────────────────────────────┐
        │  │              DISPATCHER THREAD                     │
        │  │                                                    │
        │  │  ┌──────────────────────────────────────────────┐  │
        │  │  │              DUAL-INDEX LOOKUP               │  │
        │  │  │                                              │  │
        │  │  │  1. cookie_index: cookie → flow_ctx* (fast)   │  │
        │  │  │  2. shadow_index: (pid,ssl_ctx) → flow_ctx*  │  │
        │  │  │                                              │  │
        └──┼──┼──► flow_promote_cookie() links cookie later  │  │
           │  └──────────────────────────────────────────────┘  │
           │                       │                            │
           │                       ▼                            │
           │  ┌──────────────────────────────────────────────┐  │
           │  │           flow_pool (dynamic allocation)       │  │
           │  │  ┌────────────────────────────────────────┐  │  │
           │  │  │           flow_context_t               │  │  │
           │  │  │  • socket_cookie, pid, ssl_ctx         │  │  │
           │  │  │  • generation (stale pointer detect)   │  │  │
           │  │  │  • inflight_events (ref counting)      │  │  │
           │  │  │  • flags: HAS_XDP | HAS_SSL | IN_*     │  │  │
           │  │  │  • home_worker_id (atomic ownership)   │  │  │
           │  │  │  • parser.h2 (nghttp2 + streams[64])   │  │  │
           │  │  │  • parser.h1 (llhttp + transaction)    │  │  │
           │  │  │  • alpn, last_activity_ms              │  │  │
           │  │  └────────────────────────────────────────┘  │  │
           │  └──────────────────────────────────────────────┘  │
           └────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────┐
                    │   UNIFIED PER-FLOW VIEW     │
                    │                             │
                    │  Packet  +  Socket  +  TLS  │
                    │  (HAS_XDP)        (HAS_SSL) │
                    │                             │
                    │  → Complete L7 visibility   │
                    │  → IP:port from XDP         │
                    │  → Decrypted TLS content    │
                    │  → Request/response corr.   │
                    │  → Per-flow HTTP/2 streams  │
                    └─────────────────────────────┘
```

**Why this matters:** Commercial EDRs typically only see packets OR decrypted TLS, not both
correlated to the same flow. The socket cookie is the "golden thread" that ties all three
data sources together, giving spliff complete visibility into what data went over which
connection from which process.

## Dynamic Flow Pool Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                   DYNAMIC FLOW POOL ARCHITECTURE                     │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │           flow_pool (on-demand via jemalloc)                   │  │
│  │                                                                │  │
│  │  active_head → [ctx_A] ⇄ [ctx_B] ⇄ [ctx_D] → NULL            │  │
│  │                 gen=5     gen=12     gen=8                     │  │
│  │                 pid=100   pid=200    pid=300                   │  │
│  │                 wkr=2     wkr=0      wkr=1                    │  │
│  │                                                                │  │
│  │  deferred_head → [ctx_C] → NULL  (freed after 2s grace)       │  │
│  │                   gen=3                                        │  │
│  └────────────────────────────────────────────────────────────────┘  │
│              ▲                                   ▲                   │
│              │                                   │                   │
│  ┌───────────┴────────────┐        ┌─────────────┴───────────┐       │
│  │     cookie_index       │        │      shadow_index       │       │
│  │  key: socket_cookie    │        │  key: (pid, ssl_ctx)    │       │
│  │  value: flow_ctx*      │        │  value: flow_ctx*       │       │
│  │  (incremental resize)  │        │  (incremental resize)   │       │
│  │                        │        │                         │       │
│  │  cookie_A → ctx_A      │        │  (100, ctx1) → ctx_A    │       │
│  │  cookie_B → ctx_B      │        │  (200, ctx2) → ctx_B    │       │
│  │                        │        │  (300, ctx3) → ctx_D    │       │
│  └────────────────────────┘        └─────────────────────────┘       │
│                                                                      │
│  Per-Flow State (flow_context_t):                                    │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Cache line 0 (identity + lifecycle):                           │  │
│  │ • socket_cookie, pid, ssl_ctx, generation, list_prev/next      │  │
│  │                                                                │  │
│  │ Cache line 1 (network + timing):                               │  │
│  │ • flow_key, ifindex, first_seen, last_seen, counters           │  │
│  │                                                                │  │
│  │ Cache line 2+ (protocol state):                                │  │
│  │ • flags, home_worker_id, inflight_events (atomic)              │  │
│  │ • parser.h2 (nghttp2 + streams[64] + hpack_corrupted)         │  │
│  │ • parser.h1 (llhttp + current_txn)                            │  │
│  │ • alpn, body buffers, proto                                   │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  flow_transaction_t (per HTTP/2 stream):                             │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ stream_id │ state (RFC 7540) │ method, path, host, status      │  │
│  │ flags     │ last_active_ms   │ content_type, content_length    │  │
│  │ next_free │ body_buf, len    │ start_time_ns                   │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

**Key design properties:**
- **Dynamic allocation**: jemalloc on-demand, ~9 KB initial vs ~292 MB pre-allocated
- **Pointer-based indexes**: `flow_context_t*` directly, no indirection
- **Incremental resize**: Hash tables grow without latency spikes (8 entries/op)
- **Generation safety**: Stale pointer detection across worker threads
- **Inflight counting**: Reference-counted deferred free prevents use-after-free
- **Single-writer guarantee**: Atomic CAS on `home_worker_id` prevents races
- **O(1) stream allocation**: Free-list based pool for HTTP/2 streams
- **O(active) janitor**: Linked list traversal, not O(capacity) bitmap scan

## Data Flow

1. **Startup** → Scan `/proc/PID/maps` for SSL libraries, attach uprobes, seed `flow_cookie_map` via SOCK_DIAG, init flow pool + indexes (256-entry tables), init vectorscan detector
2. **Packet arrives** → XDP classifies protocol (TLS/HTTP2/HTTP1), tracks flow state, emits metadata
3. **TCP established** → sock_ops caches socket cookie in `flow_cookie_map` (5-tuple → cookie)
4. **SSL call** → Uprobe captures decrypted data, links SSL* → fd → socket cookie
5. **Flow lookup** → Dual-index lookup: cookie_index (fast) or shadow_index (pid, ssl_ctx) → `flow_context_t*`
6. **Worker claim** → Atomic CAS on `home_worker_id` ensures single-writer per flow; generation check detects stale pointers
7. **Protocol routing** (v0.9.5+) → `http1_try_process_event()` → `http2_try_process_event()` → fallback
8. **HTTP/2 streams** → O(1) allocation from free-list, per-stream body buffers, ghost stream timeout
9. **Output** → Serialized display with request/response correlation, ALPN indicator
10. **Cleanup** → Process exit triggers flow eviction, deferred free (2s grace + inflight drain), stream body buffer free

## Project Structure

```
spliff/
├── CMakeLists.txt              # CMake build configuration (C23, LTO, packaging)
├── Makefile                    # Convenience wrapper for CMake
├── Doxyfile                    # Doxygen documentation config
├── CHANGELOG.md                # Version history
├── ISSUES.md                   # Known issues tracker
├── LICENSE                     # GPL-3.0 license
├── README.md                   # Project overview
├── ISSUES.md                       # Known issues, limitations, resolved bugs
├── docs/
│   ├── ARCHITECTURE.md         # This file
│   ├── CODE-MAP.md             # Comprehensive code-level reference
│   ├── EDR_XDR_ROADMAP.md      # Long-term EDR/XDR vision
│   └── TROUBLESHOOTING.md      # Common issues and solutions
├── src/
│   ├── main.c                  # Entry point, CLI, orchestration
│   ├── include/
│   │   └── spliff.h            # Public header, shared types, version
│   ├── bpf/
│   │   ├── spliff.bpf.c        # eBPF programs (XDP, sock_ops, uprobes)
│   │   ├── bpf_loader.c        # BPF loader, XDP attach, library discovery
│   │   ├── bpf_loader.h        # BPF loader API
│   │   ├── probe_handler.c     # Event filtering and callback dispatch
│   │   ├── probe_handler.h     # Probe handler API
│   │   ├── binary_scanner.c    # BoringSSL offset detection
│   │   ├── binary_scanner.h    # Binary scanner API
│   │   ├── boringssl_offsets.h # Known BoringSSL offsets by build ID
│   │   └── vmlinux.h           # Kernel BTF type definitions (CO-RE)
│   ├── protocol/
│   │   ├── detector.c          # Vectorscan protocol detection
│   │   ├── detector.h          # Protocol detector API
│   │   ├── http1.c             # HTTP/1.1 parser (llhttp)
│   │   ├── http1.h             # HTTP/1.1 API
│   │   ├── http2.c             # HTTP/2 parser (nghttp2)
│   │   ├── http2.h             # HTTP/2 API
│   │   ├── websocket.c         # WebSocket frame parser
│   │   └── websocket.h         # WebSocket API
│   ├── content/
│   │   ├── decompressor.c      # gzip/brotli/zstd decompression
│   │   ├── decompressor.h      # Decompressor API
│   │   ├── signatures.c        # File magic detection (50+ formats)
│   │   └── signatures.h        # Signatures API
│   ├── output/
│   │   ├── display.c           # Terminal output, colors
│   │   └── display.h           # Display API
│   ├── correlation/
│   │   ├── flow_context.c      # Shared pool, dual-index lookup
│   │   └── flow_context.h      # flow_context_t, pool types
│   ├── threading/
│   │   ├── threading.h         # Threading API, structures
│   │   ├── dispatcher.c        # BPF ring consumer, worker routing
│   │   ├── worker.c            # Worker thread main loop
│   │   ├── output.c            # Output serialization thread
│   │   ├── state.c             # Per-worker state management
│   │   ├── pool.c              # Lock-free object pool
│   │   └── manager.c           # Thread lifecycle management
│   └── util/
│       ├── safe_str.c          # Safe string operations
│       └── safe_str.h          # String API
└── tests/
    ├── test_common.c           # Shared test utilities
    ├── test_http1.c            # HTTP/1.1 parser tests
    ├── test_http2.c            # HTTP/2 parser tests
    └── test_xdp.c              # XDP structure tests
```

Build output goes to `build/` directory (gitignored). Run `make docs` to generate Doxygen HTML documentation in `build/docs/html/`.
