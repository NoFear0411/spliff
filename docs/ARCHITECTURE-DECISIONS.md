# Architecture Decisions

> Design decisions for the spliff Omni-Ring refactor.
> Each section documents the decision, rationale, and implications.

---

## ADR-001: SPMC Ring with Affinity Tagging (Phase 2)

**Status:** Accepted
**Date:** 2026-02-05
**Context:** Phase 2 Ring Buffer Redesign

### Decision

Replace per-worker SPSC queues with a **single SPMC ring** as the primary
dispatcher-to-worker transport. Events carry affinity tags for stateful
protocol routing.

### Current Architecture (v0.9.11)

```
Dispatcher ──┬──► SPSC Ring[0] ──► Worker 0
             ├──► SPSC Ring[1] ──► Worker 1
             ├──► SPSC Ring[2] ──► Worker 2
             └──► SPSC Ring[N] ──► Worker N

+ Per-worker XDP SPSC Ring (separate path)
```

Workers are assigned flows via `home_worker_id` (atomic CAS on first event).
Misrouted events are either re-homed or dropped. Parser state (nghttp2 sessions,
HPACK tables) lives inside `flow_context_t`, coupling flows to workers.

### New Architecture (Phase 2+3)

```
                    ┌────────────────────────────────────────────────────────┐
                    │             SPMC Ring (mirrored buffer)                │
Dispatcher ──────►  │  [tagged_event] [tagged_event] [tagged_event] ...     │
                    └────────┬──────────────┬──────────────┬─────────────────┘
                             │              │              │
                     CAS claim       CAS claim       CAS claim
                             │              │              │
                             ▼              ▼              ▼
                       Worker 0        Worker 1       Worker N
                    ┌──────────────┐┌──────────────┐┌──────────────┐
                    │ Affinity     ││ Affinity     ││ Affinity     │
                    │ check:       ││ check:       ││ check:       │
                    │              ││              ││              │
                    │ Stateless?   ││ Stateless?   ││ Stateless?   │
                    │ → process    ││ → process    ││ → process    │
                    │              ││              ││              │
                    │ Stateful +   ││ Stateful +   ││ Stateful +   │
                    │ I am home?   ││ I am home?   ││ I am home?   │
                    │ → process    ││ → process    ││ → process    │
                    │              ││              ││              │
                    │ Stateful +   ││ Stateful +   ││ Stateful +   │
                    │ not home?    ││ not home?    ││ not home?    │
                    │ → defer      ││ → defer      ││ → defer      │
                    └──────────────┘└──────────────┘└──────────────┘
                    │              ││              ││              │
                    │ Session      ││ Session      ││ Session      │
                    │ Registry     ││ Registry     ││ Registry     │
                    │ (Phase 3)    ││ (Phase 3)    ││ (Phase 3)    │
                    └──────────────┘└──────────────┘└──────────────┘
```

### Rationale

**Why SPMC over per-worker SPSC:**

1. **Load balancing:** Idle workers steal work. Current SPSC can leave workers
   starved if hash distribution is uneven. SPMC naturally balances load for
   stateless protocols (HTTP/1.x).

2. **Flow/parser decoupling:** The current architecture couples `flow_context_t`
   to a specific worker because parser state (nghttp2 session, HPACK table) is
   embedded in the flow. Phase 3 moves parser state to per-worker Session
   Registries, making flows portable across workers.

3. **Single queue simplicity:** One ring to monitor for backpressure, depth
   metrics, and adaptive behavior. Current N separate SPSC rings require N
   separate monitoring points.

4. **Proven in codebase:** CK's `ck_ring_dequeue_spmc()` is already used in
   spliff for the logger free ring (workers dequeue, logger enqueues). The SPMC
   pattern is battle-tested here.

**Why affinity tagging (not pure work-stealing):**

HTTP/2 connections carry significant session state (HPACK dynamic table,
stream table, nghttp2_session). This state is:
- Not thread-safe (nghttp2 is single-threaded per session)
- Expensive to serialize/deserialize
- Cache-hot on the assigned worker's L1/L2

Events for stateful protocols are tagged with `preferred_worker` to ensure
routing to the correct worker's Session Registry.

### Event Structure

```c
typedef struct {
    flow_context_t *flow_ctx;
    void *data;
    size_t data_len;
    uint16_t preferred_worker;
    uint16_t flags;
    uint64_t enqueue_ns;
    uint32_t generation;
    uint32_t _pad;
} tagged_event_t;

#define EVENT_FLAG_STATEFUL   (1 << 0)
#define EVENT_FLAG_URGENT     (1 << 1)
#define EVENT_FLAG_FIRST_DATA (1 << 2)
#define EVENT_FLAG_XDP        (1 << 3)
```

### Worker Dequeue Logic

```
dequeue event from SPMC ring (CAS on tail)

if event is STATELESS (H1):
    process immediately (any worker)

if event is STATEFUL (H2/WS):
    if preferred_worker == my_id:
        lookup/create session in local registry
        process with session state
    else:
        defer to preferred worker
```

### H2 Session Strategy: Connection-Scoped with Sticky Affinity

**Per-worker Session Registry** (Phase 3):

| Key | Value | Location |
|-----|-------|----------|
| `socket_cookie` | `h2_session_t*` | Worker thread-local |

Workflow:
1. Dispatcher: Receives event, computes `worker_id = socket_cookie % num_workers`
2. Tags event with `preferred_worker = worker_id, flags = STATEFUL`
3. Enqueues to SPMC ring
4. Worker dequeues, checks affinity, looks up session in local registry
5. If session missing: `nghttp2_session_new()` (lazy init)
6. Feeds data: `nghttp2_session_mem_recv()`

**Migration Policy: "Don't Migrate H2"**

Once an HTTP/2 connection is assigned to a worker, it stays there until close.

Rationale:
- HPACK state loss causes COMPRESSION_ERROR (fatal to connection)
- H2 connections are long-lived and multiplexed
- Slight load imbalance is acceptable vs connection termination
- EDR can recover on next TLS renegotiation or fresh SETTINGS frame (rare)

**Security benefit:** Connection-scoped sessions enable stream interdependency
tracking. A single H2 connection opening 1000 streams without sending data is
a classic L7 DDoS (stream flood) that stateless monitors miss.

### Backpressure Integration

```
Ring Fill Level    State        Action
─────────────────────────────────────────────
0-50%              NORMAL       Full processing
50-75%             ELEVATED     Log warning
75-90%             HIGH         Reduce NAPI budget
90-100%            CRITICAL     Signal eBPF via backpressure_map
```

### Phase Dependencies

| Phase | Deliverable | SPMC Impact |
|-------|-------------|-------------|
| **Phase 2** | SPMC ring + tagged events + backpressure | Transport ready |
| **Phase 3** | Session Registry + flow decoupling | Full benefits realized |

Phase 2 provides the transport mechanism. During Phase 2 (before Phase 3
completes), stateful events still use `home_worker_id` for affinity - the
SPMC ring coexists with the existing sticky routing until Session Registries
are implemented.

### Alternatives Considered

**1. Keep per-worker SPSC (status quo)**
- Pro: Simple, proven, no CAS contention
- Con: No load balancing, flows permanently coupled to workers
- Rejected: Blocks flow/parser decoupling goal

**2. Pure SPMC with no affinity**
- Pro: Maximum load balancing
- Con: Breaks H2 (HPACK state not thread-safe)
- Rejected: Requires serialization overhead or state loss

**3. Checkpoint serialization**
- Pro: True worker portability for all protocols
- Con: Serialize/deserialize HPACK table on every event
- Rejected: Unacceptable overhead at line speed

### Audit Findings (Informing This Decision)

From Section 2.1 code audit:

1. **probe_handler.c:** libbpf `ring_buffer__poll()` with single callback,
   50ms timeout in dispatcher, no batching or backpressure.

2. **XDP ring:** Per-worker SPSC with `alignas(64)` head/tail. Note: should
   be `alignas(128)` per our `CACHELINE_SIZE` to prevent spatial prefetcher
   false sharing.

3. **Worker loop:** NAPI-style with budget=64, adaptive timeout (1ms/100ms),
   deferred queue (64-slot bitmask). Processing order: XDP first, SSL second,
   deferred third.

4. **CK SPMC precedent:** `ck_ring_dequeue_spmc()` already used for logger
   free ring. Proven pattern in this codebase.

---

## ADR-002: Three-Layer Extensibility Architecture

**Status:** Accepted
**Date:** 2026-02-05
**Context:** Future-proofing spliff's evolution from SSL/TLS monitor to protocol-agnostic EDR agent

### Decision

Adopt a **three-layer architecture** where each layer has a strict responsibility
boundary. New protocols, heuristics, and EDR signals are added at Layer 3 without
ever touching Layer 1.

### The Three Layers

```
┌──────────────────────────────────────────────────────────────────────┐
│ Layer 3: Protocol Modules (pluggable)                               │
│   DNS parser, QUIC decoder, gRPC inspector, HTTP/3, custom EDR     │
│   → Registers event_type in namespace range, reads from registry    │
├──────────────────────────────────────────────────────────────────────┤
│ Layer 2: Session Registry + Metadata Slab (per-worker, plugin point)│
│   Per-connection state (HPACK, stream table, TLS session)           │
│   Per-event sidecar via ext.offset into metadata slab               │
│   → Keyed by socket_cookie, worker-local, no locking               │
├──────────────────────────────────────────────────────────────────────┤
│ Layer 1: Ring Transport (fixed, protocol-blind)                     │
│   SPMC ring + 56-byte ring_event_t + Vyukov sequences              │
│   → MUST NOT change. Ever. Slots are 64 bytes. Period.              │
└──────────────────────────────────────────────────────────────────────┘
```

### Four Probe Sources

All events enter the pipeline from one of four eBPF hook layers:

```
  NIC ──► XDP ──────────────┐
                             │
  Userspace libs ──► uprobes ┼──► Dispatcher ──► SPMC Ring ──► Workers
                             │
  Socket layer ──► sockops ──┤
                             │
  Kernel funcs ──► kprobes ──┘
```

**socket_cookie** (assigned by sockops at connect/accept) is the universal
correlator that ties all four sources into a single session. Workers use it
as the lookup key into their Session Registry.

### ring_event_t: The Layer 1 Contract

The 56-byte `ring_event_t` is frozen. It carries:

| Field | Size | Purpose |
|-------|------|---------|
| `socket_cookie` | 8B | Universal session key |
| `lookup_hint` | 8B | Phase 2: flow_ctx ptr; Phase 3: registry index |
| `data` | 8B | Zero-copy payload pointer |
| `data_len` | 8B | Payload length |
| `routing` | 8B | Bit-packed: flags, worker, type, source, generation |
| `enqueue_ns` | 8B | Queue latency tracking |
| union | 8B | `flow_key_hash` OR `ext{offset,size}` OR `ext_raw` |

The **extension union** is the escape hatch: when a protocol module needs
per-event metadata beyond 56 bytes, it writes to the metadata slab and stores
`ext.offset` + `ext.size` in the union (with `EVENT_FLAG_HAS_EXT` set).

### Event Type Namespace

The 8-bit `event_type` field is organized into ranges by probe layer:

```
  0x00-0x0F  Core lifecycle (connection open/close/migrate)
  0x10-0x1F  XDP / packet layer
  0x20-0x2F  TLS / uprobe layer
  0x30-0x3F  Socket / sockops layer
  0x40-0x4F  Kernel / kprobe layer (tcp_sendmsg, dns, etc.)
  0x50-0x5F  io_uring operations (create, connect, sendmsg)
  0x60-0x9F  Protocol modules (DNS, QUIC, gRPC, HTTP/3, ...)
  0xA0-0xAF  Process lifecycle (exec, exit, fork, privesc)
  0xB0-0xBF  File integrity (open, write, exec, delete)
  0xC0-0xCF  Enforcement actions (block IP, block exec, kill, RST)
  0xD0-0xDF  Reserved EDR
  0xE0-0xFF  User-defined / plugin
```

Adding a new protocol = pick a type value in the right range. No ring changes.

### How to Add a New Protocol (Example: QUIC)

1. **Claim event types** in the protocol module range:
   ```c
   EVENT_TYPE_QUIC_INITIAL   = 0x60,
   EVENT_TYPE_QUIC_HANDSHAKE = 0x61,
   EVENT_TYPE_QUIC_DATA      = 0x62,
   ```

2. **Write an eBPF probe** (kprobe or uprobe) that emits events with:
   - `socket_cookie` from sockops
   - `event_type` = one of the QUIC types
   - `probe_source` = `PROBE_SOURCE_KPROBE` (or UPROBE if hooking quiche/ngtcp2)

3. **Register a Layer 3 module** that handles QUIC event types:
   - Reads `socket_cookie` → looks up session in Layer 2 registry
   - Parses QUIC-specific data from `data` pointer
   - If per-event metadata needed: set `EVENT_FLAG_HAS_EXT`, write to slab

4. **Zero changes** to ring_event.h, spmc_ring.h, or any Layer 1 code.

### Rationale

**Why three layers (not two, not four):**

- Two layers (ring + handlers) doesn't separate session state from protocol
  logic, leading to the current coupling where `flow_context_t` contains both
  transport routing and parser state.

- Four layers (separate session + metadata + protocol) over-separates concerns
  that naturally live together in the per-worker processing loop.

- Three layers map cleanly to: transport (fixed), state (per-worker), logic
  (per-protocol). Each layer has one reason to change.

**Why the extension union (not a larger event):**

- 56 + 8 (Vyukov seq) = 64 bytes = exactly one hardware cache line.
  Growing the event to 120 bytes = 2 cache lines per slot = halved ring
  throughput for events that don't need the extra space.

- The metadata slab approach amortizes: most events (XDP metadata, connection
  close) need zero extension. Only complex events (e.g., TLS with cert chain)
  use the slab.

### Two-Stage Pipeline

Events flow through **two independent transport stages**. Do not confuse them:

```
STAGE 1: Kernel → Dispatcher (BPF ringbufs, kernel-managed)
┌──────────────────────────────────────────────────────────────┐
│  BPF ringbuf: network_events_rb  (XDP, sockops, kprobes)    │
│  BPF ringbuf: process_events_rb  (sched tracepoints)        │
│  BPF ringbuf: file_events_rb     (LSM hooks)                │──► Dispatcher
│  BPF ringbuf: drops_rb           (kfree_skb tracepoint)     │    (drains all,
│  BPF ringbuf: alerts_rb          (enforcement feedback)     │     normalizes to
└──────────────────────────────────────────────────────────────┘     ring_event_t)
                                                                        │
STAGE 2: Dispatcher → Workers (SPMC ring, userspace, Layer 1)          │
┌──────────────────────────────────────────────────────────────┐        │
│  SPMC Ring: [ring_event_t] [ring_event_t] [ring_event_t]    │◄───────┘
│             unified stream, 56-byte events, Vyukov sequences │
└──────────┬──────────────────┬──────────────────┬─────────────┘
           │                  │                  │
       Worker 0           Worker 1           Worker N
```

**Stage 1** is per-CPU, mmap'd, kernel-managed. Multiple BPF ringbufs are
natural here — different event sizes, different rates, no contention.

**Stage 2** is the single SPMC ring (Layer 1). Workers see one unified event
stream. The dispatcher is the single producer — it reads all BPF ringbufs,
packs each event into a `ring_event_t` with correct `probe_source` and
`event_type`, and enqueues to the SPMC ring.

**Future: Hot/Cold Two-Ring Expansion.** If enforcement latency becomes
critical (e.g., XDP_DROP decisions cannot wait behind 10K bulk events), the
SPMC ring may split into two: a small fast-path ring for urgent/enforcement
events and the main ring for everything else. Workers check the fast ring
first on every poll iteration. This gives priority isolation at 2× complexity
instead of N×. This is a future optimization, not a current requirement.

### Enforcement Feedback Path

The response engine (userspace) writes **back** to eBPF maps for enforcement:

```
Workers → Correlation Engine → Response Engine
                                    │
                                    ▼
                          bpf_map_update_elem()
                                    │
                          ┌─────────▼─────────┐
                          │  blocked_ips       │
                          │  blocked_files     │  (BPF maps)
                          │  monitored_paths   │
                          └────────────────────┘
                                    │
                          ┌─────────▼─────────┐
                          │  XDP: XDP_DROP     │
                          │  LSM: -EPERM       │  (eBPF enforcement)
                          │  sockops: log      │
                          └────────────────────┘
```

This feedback path uses `bpf_map_update_elem()` from userspace via the BPF
skeleton, **not** the SPMC ring. Layer 1 remains strictly one-directional
(dispatcher → workers). The map update API is a separate control plane.

### eBPF Helper Availability Notes

- **`bpf_d_path()`**: Only available in BPF LSM and tracing programs
  (kernel 5.10+). Not available in kprobes or sockops. File path resolution
  for non-LSM probes must happen in userspace (e.g., reading `/proc/PID/fd/N`).
  Returns truncated paths on deep directory trees (256-byte buffer limit).

- **`bpf_get_netns_cookie()`**: Available in sockops (5.0+) and XDP (5.15+).
  Not available in kprobes on older kernels. Use CO-RE feature detection.

- **`fexit`**: Preferred over kprobes for performance and cleaner argument
  access, but requires BTF. Fall back to kprobes on non-BTF kernels.

### io_uring Evasion Detection

io_uring allows userspace to perform syscall-equivalent operations (connect,
sendmsg, openat, unlink) via submission queue entries that **bypass the
syscall boundary entirely**. Traditional EDRs that hook syscalls via seccomp
or audit are blind to this. The "Curing" rootkit demonstrated full C2
communication chains invisible to Falco, Tetragon, and commercial agents.

**Why spliff is immune:** BPF LSM hooks fire at the kernel operation level,
below the syscall entry point. When io_uring's worker thread calls
`do_openat2()` internally, the VFS still invokes `security_file_open()` →
LSM `file_open` hook fires. Same for `security_socket_connect()`,
`security_socket_sendmsg()`, etc. Our `PROBE_SOURCE_LSM` sees all io_uring
operations — the attacker bypasses the syscall, not the security checkpoint.

**Three-layer detection strategy:**

```
Layer 1 (Primary):   BPF LSM hooks
                     security_file_open(), security_socket_connect(), etc.
                     → Fires regardless of syscall vs io_uring path
                     → Can enforce (-EPERM) even for io_uring ops

Layer 2 (Visibility): io_uring tracepoints
                      io_uring:io_uring_create — instance setup
                      io_uring:io_uring_submit_sqe — SQE with opcode
                      io_uring:io_uring_complete — operation result
                      → Complete audit trail of io_uring activity

Layer 3 (Behavioral): io_uring_setup() syscall detection
                      Non-server process creates io_uring instance
                      + performs network ops via io_uring
                      → threat_score increase (heuristic)
```

**Event type range:** io_uring operations use 0x50-0x5F within the kernel
namespace. The `PROBE_SOURCE_TRACEPOINT` tag distinguishes them from regular
kprobe events in the same namespace.

**CK vs io_uring for internal transport:** spliff uses CK (Concurrency Kit)
for its SPMC ring, not io_uring. CK provides pure-userspace lock-free
atomics (~10-50ns per operation). io_uring involves kernel crossings
(~200-500ns minimum), has been a prolific source of kernel CVEs, and is
disabled on hardened deployments (Android, ChromeOS, some server configs
via `kernel.io_uring_disabled`). An EDR tool should minimize its own kernel
attack surface — we monitor io_uring, we don't depend on it.

### Implications

1. **Layer 1 is frozen.** If you're tempted to add a field to `ring_event_t`,
   you're doing it wrong. Use the extension union or Session Registry.

2. **event_type is the dispatch key.** Workers switch on event_type to route
   to the correct Layer 3 module. The type alone determines handling.

3. **socket_cookie is the session key.** All probe sources that can access it
   set it. For non-network events (process exec, file open), the `socket_cookie`
   field carries an alternative key (PID, inode) — the event_type range
   determines the key's semantic meaning.

4. **Metadata slab is Phase 3 work.** The extension union infrastructure
   exists in Layer 1 now, but the actual slab allocator is a Phase 3 deliverable.

5. **BPF ringbufs are Stage 1, SPMC ring is Stage 2.** Adding a new BPF
   ringbuf (e.g., for a new sensor class) only requires a dispatcher drain
   loop addition — no Layer 1 changes.

6. **Enforcement is a control plane, not a data plane.** Map updates from
   userspace flow through the BPF skeleton API, never through the SPMC ring.

### Alternatives Considered

**1. Grow ring_event_t to 120 bytes (2 cache lines)**
- Pro: More inline space, no indirection
- Con: Every event pays 2× cache-line cost; most events don't need it
- Rejected: Violates "pay only for what you use"

**2. Per-protocol ring buffers**
- Pro: Each protocol gets its own event format
- Con: N rings × N monitoring points × N backpressure systems
- Rejected: Combinatorial complexity, breaks single-queue observability

**3. Variable-length events in ring**
- Pro: Events carry exactly what they need
- Con: Destroys cache-line alignment, makes Vyukov sequences impossible
- Rejected: Fundamentally incompatible with bounded lock-free ring

**4. Multiple SPMC rings (one per event category)**
- Pro: Priority isolation, independent backpressure
- Con: Workers poll N rings (latency), fragmented load balancing, N×
  backpressure state machines, smaller effective batch sizes
- Deferred: If priority isolation becomes necessary, prefer hot/cold two-ring
  model over full per-category split

---

## ADR-003: Session Registry — Arena-Backed Pool with Hash Index

**Status:** Accepted (design only, implementation deferred to Phase 3)
**Date:** 2026-02-05
**Context:** Layer 2 storage strategy for the Golden Thread EDR architecture

### Decision

Each worker owns a **session registry**: an arena-backed pool allocator for
fixed-size session structs, indexed by an open-addressing hash table keyed
on `session_key` (socket_cookie for network events, PID for process events).

### Architecture

```
Per-Worker Session Registry:

┌─ Hash Index ──────────────────────────────────────┐
│  bucket[0]: session_key=0xA001 → slot 3           │
│  bucket[1]: (empty)                               │
│  bucket[2]: session_key=0xC042 → slot 0           │
│  bucket[3]: session_key=0xB017 → slot 1           │
│  ...                                              │
└───────────────────────────┬───────────────────────┘
                            │ slot index
┌─ Arena (slot pool) ───────▼───────────────────────┐
│  [slot 0: golden_thread_t] [slot 1: golden_thread_t] │
│  [slot 2: FREE           ] [slot 3: golden_thread_t] │
│  ...                                                  │
│  free_bitmap: 0b...0100  (bit 2 = free)               │
│  free_hint: 2  (scan starts here on next alloc)       │
└───────────────────────────────────────────────────────┘
```

### The Session Struct (Golden Thread)

The `golden_thread_t` is the per-connection dossier that ties all probe
layers together:

```c
typedef struct golden_thread {
    /* Network identity */
    uint64_t session_key;         /* socket_cookie (primary key) */
    uint64_t flow_key_hash;       /* 5-tuple hash for XDP correlation */
    uint32_t netns_cookie;        /* Container/namespace identity */
    uint64_t cgroup_id;           /* cgroup for K8s pod identification */

    /* Process identity */
    uint32_t pid;                 /* Process ID */
    uint32_t ppid;                /* Parent PID (ancestry root) */
    uint32_t uid;                 /* User ID */
    char     comm[16];            /* Process name */

    /* Connection state */
    uint8_t  is_tls;              /* Marked by SSL_set_fd uprobe */
    uint8_t  is_vpn;              /* Marked by tunnel correlation */
    uint8_t  proto_detected;      /* Protocol identified by Layer 3 */
    uint8_t  threat_score;        /* 0-100, updated by heuristics */

    /* Timeline */
    uint64_t first_seen_ns;       /* First event timestamp */
    uint64_t last_seen_ns;        /* Last event timestamp */
    uint64_t bytes_sent;          /* Cumulative egress */
    uint64_t bytes_recv;          /* Cumulative ingress */

    /* Protocol-specific state (Layer 3 owned) */
    void    *protocol_state;      /* Opaque pointer to parser state */
    uint8_t  protocol_type;       /* Which Layer 3 module owns this */

    /* Padding to cache-line boundary */
} golden_thread_t;
```

Estimated size: ~160-256 bytes per session (exact layout TBD at implementation).

### Why Arena-Backed Pool

| Property | Arena Pool | Slab Allocator | Direct-Mapped Array |
|----------|-----------|----------------|---------------------|
| Alloc cost | O(1) bitmap scan | O(1) free-list pop | O(1) index |
| Free cost | O(1) bit flip | O(1) free-list push | O(1) zero |
| Cross-thread free | N/A (per-worker) | Needs magazines | N/A |
| Memory overhead | Free bitmap only | Per-slab metadata | Sparse keyspace waste |
| Cache locality | Sequential slots | Slab-local | Poor (sparse) |
| Bulk reset | memset bitmap | Walk all slabs | memset array |
| Implementation | Simple | Complex | Trivial but wasteful |

**Arena wins because:**

1. **Single object size.** Every session is a `golden_thread_t`. No size
   classes, no fragmentation. Fixed slots = zero waste.

2. **Per-worker, single-threaded.** Each worker owns its registry. Zero
   locking. Zero atomics. Allocation is a bitmap scan from a cached hint.

3. **Stable slot indices.** The arena never moves memory. Slot index stored
   in `ring_event_t.lookup_hint` (Phase 3 transition) is stable for the
   session's lifetime. `&registry->slots[ev->lookup_hint]` is a single
   pointer add.

4. **Bulk reset on shutdown.** `memset(bitmap, 0xFF, ...)` frees all slots.
   No destructor walk.

5. **mmap-friendly.** Arena can be backed by `mmap(MAP_ANONYMOUS | MAP_HUGETLB)`
   for hugepage backing. Physical pages committed on first touch only.

### Sizing

```
Typical deployment: 100K concurrent connections, 4 workers
  → 25K sessions per worker × 256 bytes = 6.4 MB per worker
  → Total: 25.6 MB (fits in L3 cache on modern CPUs)

Maximum deployment: 1M concurrent connections, 8 workers
  → 125K sessions per worker × 256 bytes = 32 MB per worker
  → Total: 256 MB (acceptable for dedicated EDR host)
```

### Hash Table Design

Open-addressing with linear probing (Robin Hood variant):

- **Key:** `uint64_t session_key`
- **Value:** `uint32_t slot_idx` (index into arena)
- **Load factor:** 0.7 max (resize at 70% occupancy)
- **Empty sentinel:** `key == 0` (socket_cookie is never 0)
- **Tombstone:** Not needed — Robin Hood displacement + backward shift delete

Open addressing avoids pointer chasing on collision chains. Per-worker
ownership means no concurrent access, so no atomic operations in the
hash table.

### lookup_hint Transition (Phase 2 → Phase 3)

```
Phase 2 (current):
  ring_event_t.lookup_hint = (uintptr_t)flow_ctx;
  // Workers: flow_ctx = (struct flow_context *)ev->lookup_hint;

Phase 3 (with session registry):
  ring_event_t.lookup_hint = slot_idx;  // 32-bit arena index
  // Workers: session = &registry->slots[ev->lookup_hint];
```

The transition is transparent: `lookup_hint` is a 64-bit field that changes
semantic meaning based on the phase. No ring_event_t changes required.

### Alternatives Considered

**1. Global shared registry (all workers access one)**
- Pro: No session duplication
- Con: Lock contention on every lookup, destroys cache locality
- Rejected: Per-worker is the only sane option for lock-free hot path

**2. Slab allocator (mimalloc-style)**
- Pro: Battle-tested, handles multiple object sizes
- Con: Over-engineered for single-type, single-thread use case
- Rejected: Arena is simpler and equally fast for our constraints

**3. Direct-mapped array (`session = &base[session_key & mask]`)**
- Pro: O(1) lookup, no hash table
- Con: socket_cookie is sparse 64-bit — array sized for keyspace is absurdly large
- Rejected: Unacceptable memory waste

---
