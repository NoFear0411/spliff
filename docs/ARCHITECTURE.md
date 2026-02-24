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
│  │   │ OpenSSL │  │   NSS   │  │     BoringSSL ⚠️      │  │ GnuTLS  │  SSL Libraries  │    │
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
│  │              │ ring_event_t (56B, routing word)                                   │    │
│  │              ▼                                                                    │    │
│  │  ┌──────────────────────────────────────────────────────────────────────────┐     │    │
│  │  │   SPMC Ring (4096 mirrored slots, Vyukov bounded queue) v0.10.0          │     │    │
│  │  │   Producer: dispatcher (plain head advance, single-writer)               │     │    │
│  │  │   Consumers: workers (CAS tail advance, 4 optimal, 8+ degrades)          │     │    │
│  │  └───────┬───────┬───────┬───────────┬──────────────────────────────────────┘     │    │
│  │          ▼       ▼       ▼           ▼                                            │    │
│  │  ┌───────────┐┌───────────┐┌───────────┐  ┌───────────┐                           │    │
│  │  │ Worker 0  ││ Worker 1  ││ Worker 2  │..│ Worker N  │  Three-phase poll:        │    │
│  │  ├───────────┤├───────────┤├───────────┤  ├───────────┤  1. Drain MPSC overflow   │    │
│  │  │ Overflow  ││ Overflow  ││ Overflow  │  │ Overflow  │  2. Dequeue SPMC ring     │    │
│  │  │ inbox(64) ││ inbox(64) ││ inbox(64) │  │ inbox(64) │  3. Affinity check+route  │    │
│  │  └─────┬─────┘└─────┬─────┘└─────┬─────┘  └─────┬─────┘                           │    │
│  │        │            │            │              │                                 │    │
│  │        └────────────┴──────┬─────┴──────────────┘                                 │    │
│  │                            │                                                      │    │
│  │                            ▼                                                      │    │
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
│  │  │   • flags: HAS_XDP, HAS_SSL, IN_COOKIE, IN_SHADOW, PLAINTEXT (v0.10.0)    │    │    │
│  │  │   • ref_count: atomic reference counting (v0.10.0)                        │    │    │
│  │  │   • nghttp2 session + HPACK inflater + streams[64]                        │    │    │
│  │  │   • llhttp parser + current transaction                                   │    │    │
│  │  │   • body_ctx: streaming decompression with bomb protection (v0.10.0)      │    │    │
│  │  │   • ALPN, hpack_corrupted                                                 │    │    │
│  │  └───────────────────────────────────────────────────────────────────────────┘    │    │
│  │                              │                                                    │    │
│  │                              ▼                                                    │    │
│  │              ┌───────────────────────────┐                                        │    │
│  │              │      Output Thread        │  Serialized stdout/file                │    │
│  │              │  • File signature detect  │  (no interleaving)                     │    │
│  │              │  • Formatted display      │                                        │    │
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
│  │  ║              │ (5-tuple:cookie)│       │   (LRU_HASH)    │                ║   │     │
│  │  ║              │ + map_v6 (IPv6) │       │                 │                ║   │     │
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
        │  │  │  1. cookie_index: cookie → flow_ctx* (fast)  │  │
        │  │  │  2. shadow_index: (pid,ssl_ctx) → flow_ctx*  │  │
        │  │  │                                              │  │
        └──┼──┼──► flow_promote_cookie() links cookie later  │  │
           │  └──────────────────────────────────────────────┘  │
           │                       │                            │
           │                       ▼                            │
           │  ┌──────────────────────────────────────────────┐  │
           │  │           flow_pool (dynamic allocation)     │  │
           │  │  ┌────────────────────────────────────────┐  │  │
           │  │  │           flow_context_t               │  │  │
           │  │  │  • socket_cookie, pid, ssl_ctx         │  │  │
           │  │  │  • generation (stale pointer detect)   │  │  │
           │  │  │  • ref_count (ref counting)            │  │  │
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
│  │  active_head → [ctx_A] ⇄ [ctx_B] ⇄ [ctx_D] → NULL              │  │
│  │                 gen=5     gen=12     gen=8                     │  │
│  │                 pid=100   pid=200    pid=300                   │  │
│  │                 wkr=2     wkr=0      wkr=1                     │  │
│  │                                                                │  │
│  │  deferred_head → [ctx_C] → NULL  (freed after 2s grace)        │  │
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
│  │  cookie_A → ctx_A      │        │  by_composite:          │       │
│  │  cookie_B → ctx_B      │        │  (100, ctx1) → ctx_A    │       │
│  │                        │        │  (200, ctx2) → ctx_B    │       │
│  │                        │        │                         │       │
│  │                        │        │  by_cookie (v0.9.10):   │       │
│  │                        │        │  cookie_A → ctx_A (O(1))│       │
│  └────────────────────────┘        └─────────────────────────┘       │
│                                                                      │
│  Per-Flow State (flow_context_t):                                    │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Cache line 0 (identity + lifecycle):                           │  │
│  │ • socket_cookie, pid, ssl_ctx, generation, list_prev/next      │  │
│  │                                                                │  │
│  │ Cache line 1 (network + timing):                               │  │
│  │ • flow_key, ifindex, first_seen, last_seen, atomic counters    │  │
│  │                                                                │  │
│  │ Cache line 2+ (protocol state):                                │  │
│  │ • flags: HAS_XDP, HAS_SSL, IN_COOKIE, IN_SHADOW, PLAINTEXT     │  │
│  │ • ref_count (_Atomic uint32_t, v0.10.0)                        │  │
│  │ • home_worker_id (atomic ownership)                            │  │
│  │ • parser.h2 (nghttp2 + streams[64] + hpack_corrupted)          │  │
│  │ • parser.h1 (llhttp + current_txn)                             │  │
│  │ • body_ctx: stream_decomp_t with bomb protection (v0.10.0)     │  │
│  │ • alpn, proto                                                  │  │
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
- **Reference counting**: `_Atomic uint32_t ref_count` prevents use-after-free (v0.10.0)
- **Single-writer guarantee**: Atomic CAS on `home_worker_id` prevents races
- **Streaming decompression**: Per-flow `body_ctx_t` with bomb protection (v0.10.0)
- **Plaintext flow support**: `FLOW_FLAG_PLAINTEXT` for non-TLS flows (v0.10.0)
- **RCU-safe reclamation**: liburcu `call_rcu()` for safe deferred memory frees (v0.9.10)
- **Atomic counters**: Per-flow counters use `_Atomic` with relaxed ordering (v0.9.10)
- **O(1) stream allocation**: Free-list based pool for HTTP/2 streams
- **O(active) janitor**: Linked list traversal, not O(capacity) bitmap scan
- **IPv6 zero-collision**: Separate 40-byte `flow_key_v6` with full 128-bit addresses (v0.9.10)
- **Secondary cookie index**: O(1) lookup by socket_cookie in shadow_index (v0.9.10)
- **Dynamic cgroup2**: Parses `/proc/mounts` for cgroup2 mount point (v0.9.10)
- **Per-flow H2 sessions**: HTTP/2 sessions live in `flow_ctx->parser.h2`, not per-worker pools (v0.9.11)
- **Centralized display API**: Startup/diagnostic output via display.c module (v0.9.11)

## XDP Event Delivery (v0.9.9+)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   PER-WORKER XDP RING ARCHITECTURE                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Dispatcher Thread                                                      │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  BPF Ring Poll ──► xdp_events ──► flow_context lookup            │   │
│  │                                           │                      │   │
│  │                           ┌───────────────┼───────────────┐      │   │
│  │                           ▼               ▼               ▼      │   │
│  │                   ┌──────────────┐ ┌──────────────┐ ┌──────────┐ │   │
│  │                   │ XDP Ring [0] │ │ XDP Ring [1] │ │ Ring [N] │ │   │
│  │                   │   (SPSC)     │ │   (SPSC)     │ │  (SPSC)  │ │   │
│  │                   └──────┬───────┘ └──────┬───────┘ └────┬─────┘ │   │
│  └──────────────────────────┼────────────────┼──────────────┼───────┘   │
│                             │                │              │           │
│                             ▼                ▼              ▼           │
│  Worker Threads             │                │              │           │
│  ┌──────────────────────────┼────────────────┼──────────────┼───────┐   │
│  │  Worker[0]               │    Worker[1]   │  Worker[N]   │       │   │
│  │  ┌───────────────────────▼─┐  ┌───────────▼─┐  ┌─────────▼──┐    │   │
│  │  │ 1. Drain XDP ring FIRST │  │ 1. Drain XDP│  │ 1. Drain   │    │   │
│  │  │ 2. Set HAS_XDP flag     │  │ 2. Set flag │  │ 2. Set flag│    │   │
│  │  │ 3. Process SSL events   │  │ 3. SSL evts │  │ 3. SSL evts│    │   │
│  │  └─────────────────────────┘  └─────────────┘  └────────────┘    │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  **Problem solved:** Workers check HAS_XDP before dispatcher polls      │
│  **Solution:** Workers drain their XDP ring BEFORE processing SSL       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Deferred Display Queue (v0.9.9+)

```
┌────────────────────────────────────────────────────────────────────────┐
│                   DEFERRED DISPLAY QUEUE ARCHITECTURE                  │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  HTTP Message Ready ──► Check XDP Correlation Status                   │
│                                │                                       │
│              ┌─────────────────┴─────────────────┐                     │
│              ▼                                   ▼                     │
│    ┌─────────────────────┐            ┌─────────────────────┐          │
│    │  HAS_XDP && category│            │  Missing XDP data   │          │
│    │     != UNKNOWN      │            │  (no correlation)   │          │
│    └──────────┬──────────┘            └──────────┬──────────┘          │
│               │                                  │                     │
│               ▼                                  ▼                     │
│    ┌─────────────────────┐            ┌─────────────────────┐          │
│    │  DISPLAY IMMEDIATELY│            │   ENQUEUE DEFERRED  │          │
│    │  [XDP:TLS][App:H2]  │            │   (wait for XDP)    │          │
│    │      ✓✓             │            │                     │          │
│    └─────────────────────┘            └──────────┬──────────┘          │
│                                                  │                     │
│                                                  ▼                     │
│                                 ┌────────────────────────────────┐     │
│                                 │      DEFERRED QUEUE            │     │
│                                 │  ┌─────┬─────┬─────┬─────┐     │     │
│                                 │  │ msg │ msg │ msg │ ... │     │     │
│                                 │  │+flow│+flow│+flow│     │     │     │
│                                 │  └─────┴─────┴─────┴─────┘     │     │
│                                 │                                │     │
│                                 │  Timeout: 100ms normal         │     │
│                                 │           20ms under load      │     │
│                                 │  Flush: oldest 10% when full   │     │
│                                 └────────────────────────────────┘     │
│                                                                        │
│  **Problem solved:** XDP showing [?] despite successful correlation    │
│  **Solution:** Wait briefly for XDP metadata before display            │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

## Thread Safety Model (v0.9.10)

```
┌────────────────────────────────────────────────────────────────────────┐
│                   THREAD SAFETY & MEMORY RECLAMATION                   │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    DISPATCHER THREAD (SINGLE WRITER)            │   │
│  │                                                                 │   │
│  │  • Owns all write operations to flow indexes                    │   │
│  │  • Creates flows via flow_get_or_create()                       │   │
│  │  • Merges SSL info via flow_merge_ssl_info() (single-writer)    │   │
│  │  • Promotes flows: shadow_index → cookie_index                  │   │
│  │  • Terminates flows via flow_terminate()                        │   │
│  │                                                                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                         │
│              ┌───────────────┼───────────────┬───────────────┐         │
│              ▼               ▼               ▼               ▼         │
│  ┌────────────────┐ ┌────────────────┐ ┌────────────────┐ ┌─────────┐  │
│  │   Worker 0     │ │   Worker 1     │ │   Worker N     │ │ Logger  │  │
│  │   (READER)     │ │   (READER)     │ │   (READER)     │ │ Thread  │  │
│  ├────────────────┤ ├────────────────┤ ├────────────────┤ ├─────────┤  │
│  │ • Read-only    │ │ • Read-only    │ │ • Read-only    │ │ SPMC    │  │
│  │   index lookup │ │   index lookup │ │   index lookup │ │ dequeue │  │
│  │ • Atomic reads │ │ • Atomic reads │ │ • Atomic reads │ │ from    │  │
│  │ • RCU reader   │ │ • RCU reader   │ │ • RCU reader   │ │ free    │  │
│  │   critical     │ │   critical     │ │   critical     │ │ ring    │  │
│  │   sections     │ │   sections     │ │   sections     │ │         │  │
│  └────────────────┘ └────────────────┘ └────────────────┘ └─────────┘  │
│                                                                        │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    liburcu INTEGRATION (v0.9.10)                │   │
│  │                                                                 │   │
│  │  Memory Reclamation (RCU-safe deferred free):                   │   │
│  │  ┌─────────────────────────────────────────────────────────┐    │   │
│  │  │ 1. Writer removes entry from hash table                 │    │   │
│  │  │ 2. call_rcu(&entry->rcu_head, free_callback) schedules  │    │   │
│  │  │ 3. RCU grace period waits for all readers to quiesce    │    │   │
│  │  │ 4. Callback safely frees memory after grace period      │    │   │
│  │  └─────────────────────────────────────────────────────────┘    │   │
│  │                                                                 │   │
│  │  Thread Registration:                                           │   │
│  │  • urcu_memb_register_thread() on worker/dispatcher start       │   │
│  │  • urcu_memb_unregister_thread() on thread exit                 │   │
│  │  • synchronize_rcu() during graceful shutdown                   │   │
│  │                                                                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                        │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                 ATOMICS & RING SEMANTICS (v0.10.0)              │   │
│  │                                                                 │   │
│  │  Reference counting (v0.10.0):                                  │   │
│  │  • ref_count: _Atomic uint32_t per flow_context_t               │   │
│  │  • flow_ref_acquire() — relaxed (fast path)                     │   │
│  │  • flow_ref_release() — release ordering                        │   │
│  │  • Creator ref=1 at alloc, released in flow_terminate()         │   │
│  │                                                                 │   │
│  │  Per-flow counters (_Atomic, relaxed ordering):                 │   │
│  │  • pkts_in, pkts_out, bytes_in, bytes_out                       │   │
│  │                                                                 │   │
│  │  Ring buffer semantics:                                         │   │
│  │  • SPMC event ring: dispatcher→workers (Vyukov, CAS tail)       │   │
│  │  • MPSC overflow: workers→home worker (TTAS-CAS head, 64 slots) │   │
│  │  • Logger free_ring: SPMC, Logger log_ring: MPSC                │   │
│  │  • XDP rings: SPSC (dispatcher to worker)                       │   │
│  │                                                                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**Key Thread Safety Improvements:**
- **Single-writer guarantee** (v0.9.10): `flow_merge_ssl_info()` isolates all write operations to dispatcher thread
- **RCU-safe memory reclamation** (v0.9.10): liburcu `call_rcu()` ensures readers never see freed memory
- **Atomic counters** (v0.9.10): Per-flow packet/byte counters use `_Atomic` to prevent lost updates
- **Reference counting** (v0.10.0): `ref_count` replaces ad-hoc `inflight_events` with formal acquire/release semantics
- **SPMC event ring** (v0.10.0): Vyukov bounded queue with mirrored slots, CAS tail advance for worker dequeue
- **MPSC overflow** (v0.10.0): Per-worker inbox for misrouted stateful events (TTAS-CAS, zero-CAS drain)

## Data Flow

1. **Startup** → Scan `/proc/PID/maps` for SSL libraries, attach uprobes, seed `flow_cookie_map` via SOCK_DIAG, init flow pool + indexes (256-entry tables), init vectorscan detector
2. **Packet arrives** → XDP classifies protocol (TLS/HTTP2/HTTP1), tracks flow state, emits metadata
3. **TCP established** → sock_ops caches socket cookie in `flow_cookie_map` (5-tuple → cookie)
4. **SSL call** → Uprobe captures decrypted data, links SSL* → fd → socket cookie
5. **Dispatcher** → Polls BPF ring buffers, performs dual-index flow lookup (cookie_index or shadow_index), acquires ref_count, packs `ring_event_t` (56B), enqueues to SPMC ring (v0.10.0)
6. **Worker dequeue** (v0.10.0) → Three-phase poll: drain MPSC overflow inbox → dequeue from shared SPMC ring → affinity check (local or defer to target worker's overflow queue)
7. **Protocol routing** → `http1_try_process_event()` → `http2_try_process_event()` → fallback signature detection
8. **Streaming decompression** (v0.10.0) → Per-flow `body_ctx_t` with gzip/zstd/brotli, bomb protection (>1000:1 ratio or >100MB → permanent reject)
9. **HTTP/2 streams** → O(1) allocation from free-list, per-stream body buffers, ghost stream timeout (10s)
10. **Output** → Serialized display with request/response correlation, deferred display queue for XDP timing
11. **Cleanup** → Process exit triggers flow eviction, ref_count must reach 0, deferred free (2s grace), `stream_decomp_cleanup()` frees library contexts

See [CODE-MAP.md](CODE-MAP.md) for complete project structure and source file reference.

---

*Last updated: v0.10.0 (February 2026)*
