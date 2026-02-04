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
│  │  active_head → [ctx_A] ⇄ [ctx_B] ⇄ [ctx_D] → NULL             │  │
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
│  │ • flags, home_worker_id, inflight_events (atomic)              │  │
│  │ • parser.h2 (nghttp2 + streams[64] + hpack_corrupted)          │  │
│  │ • parser.h1 (llhttp + current_txn)                             │  │
│  │ • alpn, body buffers, proto                                    │  │
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
│    │      ✓✓            │            │                     │          │
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
│  │                    ATOMIC COUNTERS (v0.9.10)                    │   │
│  │                                                                 │   │
│  │  Per-flow counters use _Atomic with relaxed ordering:           │   │
│  │  • pkts_in, pkts_out    - atomic_fetch_add (relaxed)            │   │
│  │  • bytes_in, bytes_out  - atomic_fetch_add (relaxed)            │   │
│  │                                                                 │   │
│  │  Logger ring uses SPMC operations:                              │   │
│  │  • Workers: ck_ring_dequeue_spmc() from free_ring               │   │
│  │  • Logger:  ck_ring_enqueue_spsc() to free_ring                 │   │
│  │                                                                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**Key v0.9.10 Thread Safety Improvements:**
- **Single-writer guarantee**: `flow_merge_ssl_info()` isolates all write operations to dispatcher thread
- **RCU-safe memory reclamation**: liburcu `call_rcu()` ensures readers never see freed memory
- **Atomic counters**: Per-flow packet/byte counters are now `_Atomic` to prevent lost updates
- **Correct ring semantics**: Logger free_ring uses SPMC (multiple workers dequeue, single logger enqueues)

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

See [CODE-MAP.md](CODE-MAP.md) for complete project structure and source file reference.
