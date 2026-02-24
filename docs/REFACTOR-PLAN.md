# spliff Omni-Ring Architecture Refactor Plan

**Based on:** research/omni-ring-complete-reference.md, research/vyukov_spmc_mpsc.txt,
research/Final.txt, research/LEGAL.txt
**Cross-Reference:** docs/RESEARCH-ANALYSIS.md (comprehensive research paper)
**Current Version:** 0.9.11
**Target:** 1.0.0 (production-ready, stable API)
**Versioning:** Semantic versioning (0.9.x → 0.10.0 → ... → 1.0.0)
**Estimated Duration:** 8-12 weeks across multiple sessions
**Last Updated:** 2026-02-24 (Phase 3 complete)

---

## Consolidated Roadmap

This plan merges the Omni-Ring architectural improvements with the feature roadmap.

```
v0.9.11 (Current)
    │
    ├─► v0.10.0 - FOUNDATION ──────────────────────────────────────────────┐
    │   ├── Phase 1: Memory Infrastructure ✅ COMPLETE (b037f88)           │
    │   ├── Phase 2: Ring Buffer Redesign  ✅ COMPLETE (5b48e76..4189fdf)  │
    │   └── Phase 3: Flow Context Redesign ✅ COMPLETE (6aaa96f..e641dd5)  │
    │       └── Refcount, ZSTD streaming, plaintext flows, bomb protection │
    │                                                                      │
    ├─► v0.11.0 - PROTOCOL EXPANSION ──────────────────────────────────────┤
    │   └── Phase 4: Protocol Detection/Routing/Parsing                    │
    │       ├── Plain HTTP capture (Vectorscan plaintext detection)        │
    │       ├── WebSocket (upgrade detection + frame parsing)              │
    │       ├── gRPC (HTTP/2 routing recognition)                          │
    │       └── HTTP/3 + QUIC (nghttp3/ngtcp2, UDP flow tracking)          │
    │                                                                      │
    ├─► v0.12.0 - DISPATCHER & OBSERVABILITY ──────────────────────────────┤
    │   ├── Phase 5: Dispatcher Refactoring (single-writer, batching)      │
    │   └── Phase 6: Observability & Metrics (comprehensive telemetry)     │
    │                                                                      │
    ├─► v0.13.0+ - HARDENING ──────────────────────────────────────────────┤
    │   ├── Phase 7: Security Hardening (bombs, ReDoS, backpressure)       │
    │   ├── Phase 8: Performance Optimizations (CPU features, tuning)      │
    │   └── Phase 9: Testing & Validation (benchmarks, stress tests)       │
    │                                                                      │
    └─► v1.0.0 - PRODUCTION READY ─────────────────────────────────────────┘
        └── Stable API, full Omni-Ring architecture, all protocols
```

### Version-Feature Mapping

| Version | Theme | Key Deliverables |
|---------|-------|------------------|
| **v0.10.0** | Foundation | ~~Mirrored buffers~~ ✅, ~~SPMC rings~~ ✅, ~~refcounted flows~~ ✅, ~~ZSTD streaming~~ ✅ |
| **v0.11.0** | Protocols | Plain HTTP, WebSocket, gRPC detection, HTTP/3 + QUIC |
| **v0.12.0** | Operations | Enhanced dispatcher, comprehensive metrics, alerting |
| **v0.13.0+** | Hardening | Security mitigations, performance tuning, stress testing |
| **v1.0.0** | Release | Production-ready, stable API, documentation complete |

---

## Research Validation Summary

> Cross-referenced against `vyukov_spmc_mpsc.txt`, `Final.txt`, `LEGAL.txt`.
> Full analysis: `docs/RESEARCH-ANALYSIS.md`

**Research validates existing design (no changes needed):**
- Two-stage pipeline (BPF MPSC → Vyukov SPMC) — matches ADR-001/ADR-002
- 64-byte slots (8B seq + 56B event) — NOT the 128B variant in some research diagrams
- 128-byte header isolation (head/tail/config on separate super-lines)
- Three-stage batch enqueue with single fence
- CAS backoff with `ck_pr_stall()` prevents coherency storms
- socket_cookie as universal session correlator
- Four-level backpressure with hysteresis deadbands

**Research adds value (incorporated into plan):**
- Per-worker jemalloc arenas for heap isolation (deferred to Phase 5+)
- WASM detection modules for sandboxed rule execution (deferred to Phase 7+)
- NATS JetStream + Protobuf export pipeline (Phase 5)
- Multi-channel BPF ringbufs with priority drain (Phase 4)
- io_uring async logging in Logger thread (Phase 5, with caution per ADR-002)
- Cross-platform sensor abstraction: macOS ESF, BSD DTrace (Phase 8+)
- Business model: AGPL-v3 + Commercial dual-license (non-engineering decision)

**Research conflicts with existing design (rejected):**
- 128B slots with anti-prefetch padding — wastes half ring capacity, 64B is correct
- Mixed C11 `_Atomic`/stdatomic with CK primitives — CK exclusively is correct
- Per-event-type SPMC rings — single ring with type dispatch is simpler/faster

**Where spliff is ahead of the research:**
- Affinity routing with MPSC overflow + hop-limit guard (not covered in research)
- Backpressure with hysteresis deadbands and transition matrix (research has simple "drop")
- io_uring evasion detection three-layer strategy (ADR-002, absent from research)
- Three-layer frozen L1 with extension union (more disciplined than research's design)

---

## Executive Summary

This plan transforms spliff from its current architecture to the Omni-Ring design, addressing:
1. **Memory Management** - Mirrored VM buffers, NUMA awareness, hugepages
2. **Ring Buffer Architecture** - Proper MPSC/SPMC with ghost gap handling
3. **Flow/Parser Decoupling** - Reference-counted flows with lazy initialization
4. **Protocol Detection** - Two-tier ALPN + Vectorscan streaming, multi-protocol support
5. **Network Visibility** - Plain HTTP capture, UDP/QUIC flow tracking
6. **Observability** - Comprehensive metrics and flexible export
7. **Security** - Decompression bombs, ReDoS protection, graceful degradation

---

## Phase 1: Foundation & Memory Infrastructure ✅ COMPLETE
**Status:** All tasks complete. Committed in `b037f88`.
**Sessions:** 1

### Delivered Files
| File | Description |
|------|-------------|
| `src/memory/alignment.h` | 128-byte cache-line macros (`CACHE_ALIGNED`, `IS_POWER_OF_TWO`, buffer size limits) |
| `src/memory/mirrored_buffer.h` | Mirrored buffer API with state machine for data race protection |
| `src/memory/mirrored_buffer.c` | memfd_create() + dual mmap(), hugepage fallback, memfd sealing, pre-fault helper |
| `src/memory/hugepage.h/c` | Hugepage availability check via `/proc/meminfo`, `MAP_HUGETLB` allocation |
| `src/memory/numa_alloc.h/c` | NUMA stubs + NIC node detection (full NUMA deferred to post-1.0) |
| `tests/test_mirrored_buffer.c` | 33 tests covering wrap-around, state machine, hugepage detection |

### Post-Completion Hardening (applied in later commits)
- `dfeb4cd`: Promoted memfd sealing warning from debug-only to all builds
- `4189fdf`: Added `mirrored_buffer_prefault()` for standalone pre-faulting + mlock

---

## Phase 2: Ring Buffer Redesign ✅ COMPLETE
**Status:** All tasks complete. Commits `5b48e76`..`4189fdf` (6 commits).
**Sessions:** 3

### 2.1 MPSC Ring Buffer (eBPF → Dispatcher) — Audit Only
Verified that libbpf's `BPF_MAP_TYPE_RINGBUF` handles MPSC correctly.
Ghost gap handling confirmed via `bpf_ringbuf_reserve()`/`bpf_ringbuf_submit()`.
Sharded ring buffers deferred to Phase 5+ (single ring sufficient at current scale).

### 2.2 SPMC Ring Buffer (Dispatcher → Workers) — Delivered
| File | Description |
|------|-------------|
| `src/ring/ring_event.h` | 56-byte event header with 64-bit routing word, 7 probe sources, 8-bit type namespace, `EVENT_FLAG_ROUTED` hop-limit |
| `src/ring/spmc_ring.h` | Ring struct: 3×128B cache lines (producer/tail/config), pointer-based slots, mirrored buffer handle |
| `src/ring/spmc_ring.c` | Vyukov enqueue/dequeue (single + batch), three-stage pipeline, CAS backoff, mlock for slot pages |
| `src/ring/affinity.h` | Inline affinity check + per-worker MPSC overflow queue (64 slots, Vyukov sequences) |
| `src/ring/affinity.c` | TTAS-CAS push, zero-CAS drain, acquire fence for ARM correctness |
| `src/ring/backpressure.h` | Four-level state machine (NORMAL/ELEVATED/HIGH/CRITICAL) with hysteresis deadbands, hot/cold cache-line split |
| `src/ring/backpressure.c` | Threshold precomputation, transition recorder with matrix and time-in-level tracking |

### 2.3 Worker Consumption — Delivered
| File | Description |
|------|-------------|
| `src/ring/worker_dequeue.h` | Three-phase poll API: overflow drain → SPMC batch → affinity route, per-worker stats |
| `src/ring/worker_dequeue.c` | BP_CRITICAL fast path, hop-limit guard, OOB worker bounds check, stack-local scratch buffer |
| `src/ring/adaptive_poll.h` | Header-only polling state machine: IDLE/LIGHT/MEDIUM/BUSY with BP override and full-batch inversion |

### Test Suites (Phase 2)
| File | Tests | Coverage |
|------|-------|---------|
| `tests/test_spmc_ring.c` | 35 | Layout, routing, lifecycle, enqueue/dequeue, batch, wrap-around, diagnostics |
| `tests/test_affinity.c` | 12 | MPSC push/drain, overflow, concurrency |
| `tests/test_concurrent.c` | 22 | Multi-thread SPMC stress, CAS contention |
| `tests/test_backpressure.c` | 27 | Hysteresis, transitions, clamping, matrix |
| `tests/test_worker_dequeue.c` | 35 | Three-phase poll, BP_CRITICAL, hop-limit, adaptive poll, mixed scenarios |

### Architecture Decisions
- **ADR-001**: Vyukov SPMC with mirrored buffer slots (docs/ARCHITECTURE-DECISIONS.md)
- **ADR-002**: Three-layer extensibility, two-stage pipeline
- **ADR-003**: Session registry design (Phase 3, design only)
- **CAS scaling**: Documented 4-worker sweet spot, 8+ degradation in spmc_ring.h

---

## Phase 3: Flow Context Redesign
**Priority:** High
**Estimated Sessions:** 3-4
**Target Version:** v0.10.0

This phase includes ZSTD streaming decompression and flow context support for plaintext (non-TLS) flows.

### 3.1 Reference Counting Model ✅ COMPLETE (6aaa96f)
**File:** `src/correlation/flow_context.h`, `src/correlation/flow_context.c`

Replaced ad-hoc `inflight_events` with formal `_Atomic uint32_t ref_count`.
- Creator's reference (1) initialized in `flow_pool_alloc()`, released in `flow_terminate()`
- Dispatcher acquires ref before dispatch, worker releases after processing
- Inline helpers: `flow_ref_acquire()` (relaxed), `flow_ref_release()` (release), `flow_ref_count()` (acquire)
- Deferred free gate: both ref_count==0 AND 2s grace required before actual free
- 11 tests in `tests/test_flow_refcount.c`

### 3.2 Per-Flow Mirrored Buffers — DEFERRED
**Reason:** Body buffers are written sequentially, never wrap. Mirrored buffers add
complexity without benefit here. Revisit for TCP reassembly (Phase 4+).

### 3.3 Lazy Parser Initialization ✅ ALREADY DONE
**File:** `src/threading/worker.c`

Already implemented: HTTP/2 checks `parser.h2.session == NULL` before `flow_h2_session_init()`,
HTTP/1 checks `parser.h1.initialized` before `flow_h1_parser_init()`. Late init handles
ALPN arriving after initial claim. No changes needed.

### 3.4 Per-Flow Vectorscan Stream State — DEFERRED
**Reason:** Vectorscan is used for one-shot protocol detection (`hs_scan` in BLOCK mode).
Once `ctx->proto` is cached, scanning stops. Streaming mode only needed for ongoing
security pattern matching (Phase 7).

### 3.5 Per-Flow Streaming Decompression ✅ COMPLETE (e641dd5)
**Files:** `src/content/stream_decompressor.h`, `src/content/stream_decompressor.c`

New streaming decompression module supporting gzip/deflate (zlib-ng), zstd, and brotli:
- `stream_decomp_t` embedded in `body_ctx_t` for per-flow lifetime
- Lazy init on first chunk, reset between HTTP responses on persistent connections
- ZSTD: `ZSTD_DStream` with `ZSTD_d_windowLogMax=23` (8MB window cap)
- gzip/deflate: zlib-ng `inflateInit2(15+32)` for auto-detect wrapper
- Brotli: `BrotliDecoderCreateInstance` streaming decoder
- Bomb protection: >1000:1 ratio and >100MB total output, permanent reject until reset
- Automatic cleanup in `flow_free_resources()` via `stream_decomp_cleanup()`
- 13 tests in `tests/test_stream_decompressor.c`

### 3.6 Plaintext Flow Support ✅ COMPLETE (6aaa96f)
**Files:** `src/correlation/flow_context.h`, `src/correlation/flow_context.c`

- Added `FLOW_FLAG_PLAINTEXT = (1 << 5)` to `enum flow_flags`
- `flow_is_plaintext()` inline helper for flag checking
- Auto-detect: `ssl_ctx == 0 && cookie != 0` sets PLAINTEXT flag in `flow_get_or_create()`
- State transition: INIT→ACTIVE allowed with only XDP (no SSL required) for plaintext flows
- Tests in `tests/test_flow_refcount.c` (plaintext tests #6-#9)

---

## Phase 4: Protocol Detection & Multi-Protocol Support
**Priority:** High
**Estimated Sessions:** 5-7
**Target Version:** v0.11.0

This phase consolidates all protocol work: detection infrastructure, plain HTTP, WebSocket, gRPC, and HTTP/3+QUIC.

### 4.1 Two-Tier Detection Strategy
**File:** `src/protocol/detector.c`

| Task | Description | Complexity |
|------|-------------|------------|
| 4.1.1 | Add `is_encrypted` flag to SSL events from eBPF | Low |
| 4.1.2 | TLS flows: Wait for ALPN before sending to workers | Medium |
| 4.1.3 | Plaintext flows: Send immediately for Vectorscan detection | Low |
| 4.1.4 | Add detection timeout (4KB window) | Medium |

**Current Gap:** ALPN detection exists; need cleaner separation of TLS vs plaintext paths.

### 4.2 ALPN Routing Table
**File:** `src/protocol/alpn_router.c` (NEW)

| Task | Description | Complexity |
|------|-------------|------------|
| 4.2.1 | Define `alpn_route_t` structure (alpn_id, protocol, init_parser) | Low |
| 4.2.2 | Implement `init_parser_from_alpn(flow, alpn, len)` | Medium |
| 4.2.3 | Add routes: h2, http/1.1, h3, grpc-exp, mqtt (stub) | Low |

**Current Gap:** ALPN handling exists but not as clean routing table.

### 4.3 Vectorscan Protocol Detection Database
**File:** `src/protocol/detector.c`

| Task | Description | Complexity |
|------|-------------|------------|
| 4.3.1 | Separate protocol detection patterns from security patterns | Medium |
| 4.3.2 | Compile protocol detection DB with HS_MODE_STREAM | Low |
| 4.3.3 | Implement streaming detection with callback | Medium |
| 4.3.4 | Add dual scratch spaces (detection + analysis) per worker | Medium |

**Current Gap:** Vectorscan exists; need streaming mode for fragmented detection.

### 4.4 Plain HTTP Capture (Unencrypted)
**Files:** `src/bpf/spliff.bpf.c`, `src/protocol/detector.c`, `src/threading/dispatcher.c`

| Task | Description | Complexity |
|------|-------------|------------|
| 4.4.1 | Add kprobe/XDP hook for plaintext TCP recv (non-TLS flows) | High |
| 4.4.2 | Filter TLS flows (check for 0x16 0x03 TLS header) in eBPF | Medium |
| 4.4.3 | Route plaintext flows through Vectorscan HTTP detection | Medium |
| 4.4.4 | Add `--plain-http` CLI flag to enable/disable | Low |
| 4.4.5 | Display plain HTTP with `[Plain]` indicator | Low |

**Current Gap:** Only TLS-intercepted traffic captured; no visibility into unencrypted HTTP.

### 4.5 WebSocket Support
**Files:** `src/protocol/websocket.c` (exists), `src/protocol/detector.c`

| Task | Description | Complexity |
|------|-------------|------------|
| 4.5.1 | Add WebSocket upgrade detection pattern to Vectorscan | Low |
| 4.5.2 | Integrate existing `websocket.c` frame parser into flow processing | Medium |
| 4.5.3 | Add WebSocket frame display (opcode, payload preview) | Medium |
| 4.5.4 | Handle WebSocket continuation frames | Medium |
| 4.5.5 | Track WebSocket state per-flow (handshake → frames) | Medium |

**Current Gap:** WebSocket parser exists (`websocket.c`) but not integrated into flow processing.

### 4.6 gRPC Detection & Routing
**Files:** `src/protocol/alpn_router.c`, `src/protocol/http2.c`

| Task | Description | Complexity |
|------|-------------|------------|
| 4.6.1 | Add `grpc-exp` ALPN route | Low |
| 4.6.2 | Detect gRPC via content-type header (`application/grpc`) | Low |
| 4.6.3 | Add `[gRPC]` indicator to HTTP/2 display | Low |
| 4.6.4 | Parse gRPC length-prefixed messages (optional) | Medium |

**Current Gap:** gRPC uses HTTP/2; need detection and display differentiation.

### 4.7 HTTP/3 + QUIC Support
**Files:** NEW `src/protocol/http3.c`, `src/bpf/spliff.bpf.c`
**Dependencies:** nghttp3, ngtcp2 (or alternative H3 library)

| Task | Description | Complexity |
|------|-------------|------------|
| 4.7.1 | Add nghttp3/ngtcp2 dependencies to CMakeLists.txt | Low |
| 4.7.2 | Implement UDP flow tracking in XDP (QUIC uses UDP) | High |
| 4.7.3 | Detect QUIC via Initial packet header (0x00-0x3f version) | Medium |
| 4.7.4 | Add `h3` ALPN route for QUIC-TLS flows | Low |
| 4.7.5 | Create `http3.c` parser wrapper around nghttp3 | High |
| 4.7.6 | Implement QPACK header decompression | High |
| 4.7.7 | Handle QUIC connection migration (changing 4-tuple) | High |
| 4.7.8 | Display HTTP/3 with `[H3]` indicator | Low |

**Current Gap:** No UDP flow tracking; no QUIC/HTTP3 parsing. Major feature addition.

### 4.8 Protocol Parser Registry
**File:** `src/protocol/registry.c` (NEW)

| Task | Description | Complexity |
|------|-------------|------------|
| 4.8.1 | Define `protocol_parser_t` interface (init, process, cleanup) | Medium |
| 4.8.2 | Create parser registry with dynamic registration | Medium |
| 4.8.3 | Refactor http1.c, http2.c, websocket.c to use registry | Medium |
| 4.8.4 | Add http3.c to registry | Low |

**Rationale:** Clean abstraction for multiple protocol parsers with consistent interface.

---

## Phase 5: Dispatcher Refactoring
**Priority:** High
**Estimated Sessions:** 2

### 5.1 Single-Writer Flow Mutations
**File:** `src/threading/dispatcher.c`

| Task | Description | Complexity |
|------|-------------|------------|
| 5.1.1 | Audit all flow mutations happen only in dispatcher | Medium |
| 5.1.2 | Remove any worker-side flow mutations (except atomic counters) | Medium |
| 5.1.3 | Document single-writer guarantee in code comments | Low |

**Current Gap:** v0.9.10 added `flow_merge_ssl_info()` for single-writer; verify complete.

### 5.2 Flow Table with Collision Handling
**File:** `src/correlation/ck_cookie_index.c`

| Task | Description | Complexity |
|------|-------------|------------|
| 5.2.1 | Audit CK hash table collision handling | Medium |
| 5.2.2 | Add chain length limit (MAX_CHAIN_LENGTH=100) for DoS protection | Medium |
| 5.2.3 | Switch to jemalloc arena for flow table entries | Low |

**Current Gap:** CK hash tables exist; verify collision handling is robust.

### 5.3 Adaptive Batching
**File:** `src/threading/dispatcher.c`

| Task | Description | Complexity |
|------|-------------|------------|
| 5.3.1 | Implement batch threshold (64 flows) before signaling workers | Medium |
| 5.3.2 | Add timeout (50μs) for low-traffic scenarios | Medium |
| 5.3.3 | Use eventfd for worker wake-up | Medium |

**Current Gap:** Current design may wake workers too frequently.

---

## Phase 6: Observability & Metrics
**Priority:** Medium
**Estimated Sessions:** 2

### 6.1 Comprehensive Metrics Structure
**File:** `src/metrics/metrics.h` (NEW)

| Task | Description | Complexity |
|------|-------------|------------|
| 6.1.1 | Define `metrics_t` structure (see research 11.1.1) | Medium |
| 6.1.2 | Allocate in shared memory (for multi-process monitoring) | Low |
| 6.1.3 | Add atomic counters for all categories | Medium |

### 6.2 Metrics Collection Points
**Files:** Various

| Task | Description | Complexity |
|------|-------------|------------|
| 6.2.1 | Add flow lifecycle counters (created, destroyed, active) | Low |
| 6.2.2 | Add protocol detection counters (ALPN, regex, timeout) | Low |
| 6.2.3 | Add error counters (drops, bombs, overflows) | Low |
| 6.2.4 | Add latency histogram tracking | Medium |

### 6.3 eBPF Drop Monitoring
**File:** `src/bpf/spliff.bpf.c`

| Task | Description | Complexity |
|------|-------------|------------|
| 6.3.1 | Add per-CPU `drop_stats_map` | Medium |
| 6.3.2 | Increment counters on ring full, parse error, backpressure | Low |
| 6.3.3 | Add userspace monitoring thread to poll drop stats | Medium |

### 6.4 Prometheus Export (Optional)
**File:** `src/metrics/prometheus.c` (NEW)

| Task | Description | Complexity |
|------|-------------|------------|
| 6.4.1 | Implement simple HTTP server on port 9090 | Medium |
| 6.4.2 | Format metrics in Prometheus text format | Low |
| 6.4.3 | Add CLI flag `--metrics-port` | Low |

---

## Phase 7: Security Hardening
**Priority:** Medium
**Estimated Sessions:** 1-2

### 7.1 Decompression Bomb Protection
**File:** `src/content/decompressor.c`

| Task | Description | Complexity |
|------|-------------|------------|
| 7.1.1 | Add MAX_DECOMPRESSED_RATIO (1000:1) check | Low |
| 7.1.2 | Add MAX_DECOMPRESSED_SIZE (100MB) check | Low |
| 7.1.3 | Increment metrics on detection | Low |
| 7.1.4 | Drop flow on bomb detection | Low |

### 7.2 Vectorscan Timeout (ReDoS Protection)
**File:** `src/protocol/detector.c`

| Task | Description | Complexity |
|------|-------------|------------|
| 7.2.1 | Add `scan_start_ns` to flow detection state | Low |
| 7.2.2 | Check timeout (10ms) in match callback | Low |
| 7.2.3 | Abort scan on timeout | Low |

### 7.3 Buffer Overflow Protection
**File:** `src/correlation/flow_context.c`

| Task | Description | Complexity |
|------|-------------|------------|
| 7.3.1 | Implement `append_to_stream_buffer_safe()` (research 6.3.2) | Medium |
| 7.3.2 | Flush early on overflow attempt | Low |
| 7.3.3 | Drop flow if single packet exceeds buffer | Low |

### 7.4 Graceful Degradation
**File:** `src/bpf/spliff.bpf.c`, `src/threading/dispatcher.c`

| Task | Description | Complexity |
|------|-------------|------------|
| 7.4.1 | Add `backpressure_map` for eBPF ↔ userspace signaling | Medium |
| 7.4.2 | Drop non-TCP traffic under backpressure | Low |
| 7.4.3 | Log when entering/exiting backpressure state | Low |

---

## Phase 8: Performance Optimizations
**Priority:** Medium-Low
**Estimated Sessions:** 1-2

### 8.1 CPU Feature Detection
**File:** `src/util/cpu_features.c` (NEW)

| Task | Description | Complexity |
|------|-------------|------------|
| 8.1.1 | Detect AVX-512/AVX2/SSE4.2 via cpuid | Medium |
| 8.1.2 | Detect hugepage support | Low |
| 8.1.3 | Create dispatch config based on features | Low |

### 8.2 Interrupt Coalescing Documentation
**File:** `docs/TUNING.md` (NEW)

| Task | Description | Complexity |
|------|-------------|------------|
| 8.2.1 | Document ethtool commands for interrupt coalescing | Low |
| 8.2.2 | Document NIC ring buffer sizing | Low |
| 8.2.3 | Document CPU pinning for dispatcher | Low |

### 8.3 Zero-Copy Uprobe Arena (Future)
**File:** TBD

| Task | Description | Complexity |
|------|-------------|------------|
| 8.3.1 | Research shared memory arena for uprobe payloads | High |
| 8.3.2 | Implementation deferred to future version | - |

---

## Phase 9: Testing & Validation
**Priority:** Critical (runs parallel to other phases)
**Estimated Sessions:** Ongoing

### 9.1 Unit Tests
| Task | Description | Complexity |
|------|-------------|------------|
| 9.1.1 | Mirrored buffer wrap-around tests | Medium |
| 9.1.2 | SPMC ring concurrent access tests | High |
| 9.1.3 | Reference counting lifecycle tests | Medium |
| 9.1.4 | Decompression bomb detection tests | Low |

### 9.2 Integration Tests
| Task | Description | Complexity |
|------|-------------|------------|
| 9.2.1 | End-to-end HTTP/1.1 capture test | Medium |
| 9.2.2 | End-to-end HTTP/2 capture test | Medium |
| 9.2.3 | Backpressure handling test | High |
| 9.2.4 | Graceful shutdown test | Medium |

### 9.3 Performance Benchmarks
| Task | Description | Complexity |
|------|-------------|------------|
| 9.3.1 | Throughput benchmark (Gbps) | Medium |
| 9.3.2 | Latency benchmark (μs percentiles) | Medium |
| 9.3.3 | Memory usage benchmark (flows/GB) | Low |

---

## Dependency Graph

```
Phase 1 (Memory) ─────────┬──────────────────────────────────────────────────────────┐
                          │                                                          │
Phase 2 (Ring Buffers) ───┼─────────────────────────────────────────────┐            │
                          │                                             │            │
Phase 3 (Flow Context) ───┤                                             │            │
                          │                                             │            │
Phase 4 (Protocol) ───────┼───────────────────────┐                     │            │
                          │                       │                     │            │
Phase 5 (Dispatcher) ─────┼───────────────────────┤                     │            │
                          │                       │                     │            │
                          │                       v                     v            v
                          │              Phase 6 (Metrics) ──► Phase 7 (Security) ──► Phase 8 (Perf)
                          │                                                          │
                          └──────────────────────────────────────────────────────────┘
                                                                                     │
                                                                         Phase 9 (Testing)
```

---

## Migration Strategy

### Incremental Refactoring (Recommended)

1. ~~**Week 1-2:** Complete Phase 1 (Memory Infrastructure)~~ ✅ DONE
   - Mirrored buffers, hugepage stubs, NUMA stubs, alignment macros

2. ~~**Week 2-3:** Complete Phases 2-3 (Ring Buffers + Flow Context)~~ ✅ DONE
   - Phase 2: SPMC ring, affinity, backpressure, worker dequeue, adaptive poll
   - Phase 3: ref_count, plaintext flows, streaming decompression, bomb protection

3. **Week 3-4:** Complete Phases 4-5 (Protocol + Dispatcher)
   - Builds on new flow context
   - Can run new and old code paths in parallel

4. **Week 4-5:** Complete Phases 6-7 (Metrics + Security)
   - Additive changes
   - Low risk

5. **Week 5-6:** Complete Phase 8 (Performance) + Final Testing
   - Optimization pass
   - Benchmark validation

### Feature Flags

Consider adding compile-time flags to enable/disable new code paths:

```c
#define OMNI_RING_MIRRORED_BUFFERS 1
#define OMNI_RING_SPMC_WORKERS 1
#define OMNI_RING_REFCOUNT_FLOWS 1
```

---

## Files to Create

| File | Purpose | Phase | Status |
|------|---------|-------|--------|
| `src/memory/mirrored_buffer.h/c` | Mirrored VM buffer with memfd + pre-fault | 1 | ✅ |
| `src/memory/numa_alloc.h/c` | NUMA stubs + NIC node detection | 1 | ✅ |
| `src/memory/hugepage.h/c` | Hugepage availability + allocation | 1 | ✅ |
| `src/memory/alignment.h` | 128-byte cache-line macros | 1 | ✅ |
| `src/ring/ring_event.h` | 56-byte event with routing word | 2 | ✅ |
| `src/ring/spmc_ring.h/c` | Vyukov SPMC with mirrored slots | 2 | ✅ |
| `src/ring/affinity.h/c` | Affinity check + MPSC overflow | 2 | ✅ |
| `src/ring/backpressure.h/c` | Four-level state machine with hysteresis | 2 | ✅ |
| `src/ring/worker_dequeue.h/c` | Three-phase worker consumption | 2 | ✅ |
| `src/ring/adaptive_poll.h` | Polling timeout state machine | 2 | ✅ |
| `src/content/stream_decompressor.h/c` | Per-flow streaming decompression | 3 | ✅ |
| `src/protocol/alpn_router.c` | ALPN → parser routing | 4 | |
| `src/protocol/alpn_router.h` | ALPN router API | 4 | |
| `src/protocol/registry.c` | Protocol parser registry | 4 | |
| `src/protocol/registry.h` | Parser registry API | 4 | |
| `src/protocol/http3.c` | HTTP/3 parser (nghttp3 wrapper) | 4 | |
| `src/protocol/http3.h` | HTTP/3 API | 4 | |
| `src/protocol/quic.c` | QUIC flow tracking | 4 | |
| `src/protocol/quic.h` | QUIC API | 4 | |
| `src/metrics/metrics.c` | Metrics collection | 6 | |
| `src/metrics/metrics.h` | Metrics structure | 6 | |
| `src/metrics/prometheus.c` | Prometheus export (optional) | 6 | |
| `src/util/cpu_features.c` | CPU feature detection | 8 | |
| `src/util/cpu_features.h` | CPU features API | 8 | |
| `docs/TUNING.md` | Performance tuning guide | 8 | |

## Files to Modify (Major)

| File | Changes | Phase |
|------|---------|-------|
| `src/correlation/flow_context.h` | ref_count, plaintext flag, stream_decomp_t ✅ | 3 |
| `src/correlation/flow_context.c` | ref counting, plaintext detection, stream cleanup ✅ | 3 |
| `src/threading/dispatcher.c` | SPMC integration, batch signaling | 2, 5 |
| `src/threading/worker.c` | Batch dequeue, dual scratch spaces | 2 |
| `src/protocol/detector.c` | Streaming detection, plaintext HTTP, WebSocket patterns | 4 |
| `src/protocol/websocket.c` | Integrate into flow processing | 4 |
| `src/protocol/http2.c` | gRPC detection, registry integration | 4 |
| `src/content/decompressor.c` | Per-flow state, ZSTD streaming, bomb protection | 3 |
| `src/bpf/spliff.bpf.c` | Drop stats, backpressure map, UDP/QUIC tracking, plaintext hooks | 4, 6 |
| `CMakeLists.txt` | nghttp3/ngtcp2 deps, new files, optional libnuma | 1, 4 |
| `README.md` | Updated roadmap, new protocol support | All |

---

## Design Decisions (Resolved)

1. **NUMA:** Deferred - implement stubs and detection only. Full NUMA allocation after core refactor complete.

2. **Prometheus Metrics:** Nice-to-have. Focus on metrics structure with flexible export (stdout, file, future Prometheus).

3. **Sharded eBPF Rings:** Deferred to optimization phase. Start with single ring; benchmark will determine if sharding needed.

4. **Zero-Copy Uprobe Arena:** Deferred to future release. High complexity, current model sufficient.

5. **Backward Compatibility:** None. Full refactor with old code removal after each phase stabilizes.

6. **Code Quality Requirements:**
   - Clean, well-structured code
   - Security-first design
   - Doxygen documentation for all public APIs
   - Git commits after each phase to mark progress

7. **Versioning:** Follows semantic versioning. Building toward **1.0.0** release.
   - 0.9.x → Incremental improvements within current architecture
   - 0.10.0 → First major architectural milestone (Omni-Ring foundation)
   - 0.1x.x → Continued architectural improvements
   - 1.0.0 → Production-ready, stable API, full Omni-Ring architecture

---

## Session Approach

Each coding session should:

1. **Start:** Review this plan, identify target tasks
2. **Implement:** Complete 3-5 tasks from current phase
3. **Test:** Run existing tests + add new tests for changes
4. **Document:** Update CODE-MAP.md and ARCHITECTURE.md
5. **Commit:** Small, focused commits with clear messages

### Code Quality Standards

All new code must follow:

```c
/**
 * @file mirrored_buffer.c
 * @brief Zero-copy ring buffer with mirrored virtual memory
 * @version 2.0
 *
 * Implements virtual memory mirroring to eliminate wrap-around
 * branching in ring buffer operations.
 */

/**
 * @brief Create a mirrored virtual memory buffer
 *
 * Maps the same physical pages twice consecutively in virtual address
 * space, allowing seamless wrap-around without copying.
 *
 * @param size Buffer size in bytes (must be power of 2 and page-aligned)
 * @return Pointer to mirrored_buffer_t or NULL on failure
 *
 * @note Caller must call mirrored_buffer_destroy() to free resources
 * @warning Size must be power of 2; function will abort otherwise
 *
 * @example
 * mirrored_buffer_t *buf = mirrored_buffer_create(1024 * 1024);
 * if (!buf) { handle_error(); }
 * // Write at end wraps to beginning transparently
 * memcpy(buf->base + offset, data, len);
 */
mirrored_buffer_t *mirrored_buffer_create(size_t size);
```

### Git Commit Strategy

**During Phase:** Small, incremental commits for each logical unit:
```
feat(memory): add mirrored_buffer_t structure definition
feat(memory): implement mirrored_buffer_create with memfd backing
test(memory): add mirrored buffer wrap-around tests
docs(memory): add Doxygen comments to mirrored_buffer.h
```

**Phase Completion:** Bump version and tag after all phase tests pass:
```bash
# Update version in src/include/spliff.h
# Example: Phase 1 complete → 0.9.12
git tag -a v0.9.12 -m "feat: Memory infrastructure (Omni-Ring Phase 1)"
```

### Old Code Removal

After phase stabilizes (tests green, no regressions):
1. Identify deprecated code paths
2. Remove in separate commit: `refactor: remove legacy linear buffer code`
3. Update CODE-MAP.md to reflect removal

---

Ready to begin when you are.
