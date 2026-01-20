# Shared Pool Architecture: Implementation Plan

**Version:** 1.1
**Date:** 2026-01-20
**Status:** Phase 3.6 Complete (v0.9.2)

## Executive Summary

This document describes the implementation plan for the **Shared Pool with Dual Index** architecture, the gold standard for eBPF-based observability tools. This architecture provides:

- **Zero-copy consistency**: Data never moves, only index entries change
- **Atomic handover**: 4-byte flow_id writes instead of struct copies
- **Predictable performance**: Pre-allocated pool, no malloc in hot path
- **Unknown traffic resilience**: Handles both "mice" (short) and "elephant" (long) flows

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                    SHARED POOL ARCHITECTURE                          │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                 flow_pool (THE SINGLE SOURCE OF TRUTH)         │ │
│  │  ┌──────────┬──────────┬──────────┬──────────┬──────────┐     │ │
│  │  │ slot[0]  │ slot[1]  │ slot[2]  │ slot[3]  │   ...    │     │ │
│  │  │ active=1 │ active=1 │ active=0 │ active=1 │          │     │ │
│  │  │ cookie=A │ cookie=B │ (free)   │ cookie=0 │          │     │ │
│  │  │ pid=100  │ pid=200  │          │ pid=300  │          │     │ │
│  │  └──────────┴──────────┴──────────┴──────────┴──────────┘     │ │
│  │       ▲           ▲                     ▲                      │ │
│  │   id=0        id=1                  id=3                       │ │
│  └────────────────────────────────────────────────────────────────┘ │
│              ▲                                    ▲                  │
│              │                                    │                  │
│  ┌───────────┴────────────┐        ┌─────────────┴───────────┐     │
│  │     cookie_index       │        │      shadow_index       │     │
│  │  key: socket_cookie    │        │  key: (pid, ssl_ctx)    │     │
│  │  value: flow_id (u32)  │        │  value: flow_id (u32)   │     │
│  │                        │        │                         │     │
│  │  cookie_A → 0          │        │  (100, ctx1) → 0        │     │
│  │  cookie_B → 1          │        │  (200, ctx2) → 1        │     │
│  │                        │        │  (300, ctx3) → 3        │     │
│  └────────────────────────┘        └─────────────────────────┘     │
└──────────────────────────────────────────────────────────────────────┘
```

## Event Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         EVENT LIFECYCLE                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. NEW FLOW (SSL event with cookie=0)                              │
│     ├── Allocate slot[N] from pool (bitmap O(1))                    │
│     ├── Initialize flow_context_t in slot[N]                        │
│     ├── Insert (pid, ssl_ctx) → N into shadow_index                 │
│     └── Return slot[N] pointer                                      │
│                                                                     │
│  2. COOKIE ARRIVES (sockops or later SSL event)                     │
│     ├── Lookup N from shadow_index using (pid, ssl_ctx)             │
│     ├── Update slot[N].socket_cookie = cookie                       │
│     ├── Insert cookie → N into cookie_index                         │
│     └── Shadow index entry remains (both valid)                     │
│                                                                     │
│  3. SUBSEQUENT EVENTS                                               │
│     ├── If cookie != 0: lookup in cookie_index → N                  │
│     ├── If cookie == 0: lookup in shadow_index → N                  │
│     └── Access slot[N] directly (no copy)                           │
│                                                                     │
│  4. FLOW TERMINATION                                                │
│     ├── Remove from cookie_index (if present)                       │
│     ├── Remove from shadow_index                                    │
│     ├── Free parser resources in slot[N]                            │
│     └── Mark slot[N] as free in bitmap                              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Memory Layout

| Component | Size | Notes |
|-----------|------|-------|
| `flow_context_t` | ~512 bytes | 64-byte aligned for cache |
| Pool (8192 slots) | 4 MB | Pre-allocated, no malloc |
| Cookie index | 96 KB | 8192 × 12 bytes |
| Shadow index | 160 KB | 8192 × 20 bytes |
| Free bitmap | 1 KB | 128 × 8 bytes |
| **Total** | **~4.25 MB** | For 8K concurrent flows |

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Index value type | `uint32_t flow_id` | 4-byte atomic write, bounds-checkable |
| Free slot tracking | Bitmap + `__builtin_ctzll()` | O(1) allocation |
| Hash collision | Linear probing | Cache-friendly, simple |
| Pool sizing | 8192 slots | Handles most server workloads |
| Alignment | 64 bytes | Cache line optimization |

---

## Implementation Phases

### Phase 1: Core Data Structures (13 tasks)

Create the foundational types and operations in `src/correlation/flow_context.h` and `src/correlation/flow_context.c`.

| Task | Description | Status |
|------|-------------|--------|
| 1.1 | Define `flow_id_t` and `FLOW_ID_INVALID` constant | ✅ Done |
| 1.2 | Design `flow_pool_t` with pre-allocated slots array | ✅ Done |
| 1.3 | Add `free_bitmap` for O(1) slot allocation | ✅ Done |
| 1.4 | Design `cookie_index_t` (socket_cookie → flow_id) | ✅ Done |
| 1.5 | Design `shadow_index_t` ((pid,ssl_ctx) → flow_id) | ✅ Done |
| 1.6 | Implement `flow_pool_init/cleanup` | ✅ Done |
| 1.7 | Implement `flow_pool_alloc` (bitmap-based) | ✅ Done |
| 1.8 | Implement `flow_pool_free` | ✅ Done |
| 1.9 | Implement `cookie_index_insert/lookup/remove` | ✅ Done |
| 1.10 | Implement `shadow_index_insert/lookup/remove` | ✅ Done |
| 1.11 | Implement unified `flow_lookup` | ✅ Done |
| 1.12 | Implement `flow_get_or_create` | ✅ Done |
| 1.13 | Implement `flow_promote_cookie` | ✅ Done |

### Phase 2: Dispatcher Integration (7 tasks)

Wire the new structures into the dispatcher thread.

| Task | Description | Status |
|------|-------------|--------|
| 2.1 | Add `flow_pool` + indexes to `dispatcher_ctx_t` | ✅ Done |
| 2.2 | Update `dispatcher_init` to create pool and indexes | ✅ Done |
| 2.3 | Update `dispatcher_cleanup` to free resources | ✅ Done |
| 2.4 | Update XDP handler to use Shared Pool | ✅ Done |
| 2.5 | Update SSL event handler to use `shadow_index` | ✅ Done |
| 2.6 | Add cookie promotion when sockops provides cookie | ✅ Done |
| 2.7 | Update janitor to evict from pool and both indexes | ✅ Done |

### Phase 3: Worker Integration (4 tasks)

Update workers to use unified flow context.

| Task | Description | Status |
|------|-------------|--------|
| 3.1 | Update `worker_event_t` to carry `flow_id` | ✅ Done |
| 3.2 | Update workers to resolve `flow_id` → `flow_context_t*` | ✅ Done |
| 3.3 | Migrate protocol parsers to use `flow_context.parser` | 🔶 Partial |
| 3.4 | Remove duplicate caches from `worker_state_t` | ⬜ Deferred |

**Task 3.3 Notes:**
- ✅ ALPN storage: `flow_ctx->alpn` populated on EVENT_ALPN
- ✅ ALPN lookup: `process_worker_event()` prefers `flow_ctx->alpn`
- ✅ Parser init: `flow_init_parser()` called when ALPN received
- ✅ HTTP/1 parser: `flow_h1_parser_init()` called on worker claim (infrastructure ready)
- ✅ HTTP/2 parser: `flow_h2_session_init()` called on worker claim (infrastructure ready)
- ⬜ HTTP/1 parsing: Still uses global `http1_parse()` - needs migration
- ⬜ HTTP/2 parsing: Still uses global `g_h2_connections[]` - needs migration
- ⬜ Stream tracking: HTTP/2 streams still use `worker_state.h2_streams[]`

**Task 3.4 Notes:**
Deferred - requires completing HTTP/2 stream migration first. Current architecture:
- `worker_state_t.alpn_cache[]` → can be removed (flow_ctx->alpn used)
- `worker_state_t.h2_connections[]` → keep (connection-level nghttp2 sessions)
- `worker_state_t.h2_streams[]` → keep (per-stream state for HTTP/2 multiplexing)

### Phase 3.5: Worker Affinity ("Hybrid Sticky" Architecture)

Implements thread-safe HTTP/2 processing without locking by establishing
single-writer ownership of each flow.

| Task | Description | Status |
|------|-------------|--------|
| 3.5.1 | Add `home_worker_id` to `flow_context_t` | ✅ Done |
| 3.5.2 | Implement atomic CAS claim in worker loop | ✅ Done |
| 3.5.3 | Add `events_misrouted` counter for diagnostics | ✅ Done |
| 3.5.4 | Init H2 session on claim (`flow_h2_session_init()`) | ✅ Done |
| 3.5.5 | Expose `http2_get_callbacks()` for session init | ✅ Done |
| 3.5.6 | Init H1 parser on claim (`flow_h1_parser_init()`) | ✅ Done |
| 3.5.7 | Expose `http1_get_settings()` for parser init | ✅ Done |
| 3.5.8 | Implement worker-to-worker forwarding | ⬜ Pending |

**Architecture:**
```
┌─────────────────────────────────────────────────────────────────┐
│                    Hybrid Sticky Architecture                    │
├─────────────────────────────────────────────────────────────────┤
│  1. Discovery Phase (Claim)                                      │
│     Worker receives event → atomic CAS on home_worker_id         │
│     If CAS succeeds → worker owns flow → initialize parser       │
│                                                                  │
│  2. Data Phase (Route)                                           │
│     Worker receives event → check home_worker_id                 │
│     If owner → process directly                                  │
│     If not owner → forward to home worker (TODO)                 │
│                                                                  │
│  3. Benefits                                                     │
│     - No mutex contention (single-writer guarantee)              │
│     - Cache-friendly (all flow state in one structure)           │
│     - Linear scaling with worker count                           │
└─────────────────────────────────────────────────────────────────┘
```

### Phase 3.6: Unified Transaction Architecture

Replaces global `g_h2_connections` and `g_h2_streams` with flow-based storage.
Fixes race conditions and memory leaks in multi-threaded HTTP/2 parsing.

| Task | Description | Status |
|------|-------------|--------|
| 3.6.1 | Define `flow_transaction_t` structure | ✅ Done |
| 3.6.2 | Update `h1_parser_ctx_t` with embedded `txn` | ✅ Done |
| 3.6.3 | Update `h2_parser_ctx_t` with `streams[]` array | ✅ Done |
| 3.6.4 | Create transaction helper functions | ✅ Done |
| 3.6.5 | Update HTTP/1 to use persistent parser | ⬜ Pending |
| 3.6.6 | Update HTTP/2 callbacks for flow-based streams | ✅ Done |
| 3.6.7 | Update `process_worker_event` for flow parsing | ✅ Done |
| 3.6.8 | Remove global `g_h2_connections`, `g_h2_streams` | ⬜ Pending |

**Phase A Complete (2026-01-20):**
- `flow_transaction_t` defined in `flow_context.h` with RFC 7540-aligned state machine
- `h1_parser_ctx_t` has embedded `txn` for sequential request/response
- `h2_parser_ctx_t` has `streams[64]` array with O(1) free-list allocation
- `hpack_corrupted` flag for connection-fatal HPACK errors
- Helper functions: `flow_h2_alloc_stream()`, `flow_h2_find_stream()`,
  `flow_h2_free_stream()`, `flow_h2_reap_ghosts()`, `flow_txn_alloc_body()`,
  `flow_txn_append_body()`, `flow_txn_free_body()`, `flow_h1_reset_txn()`
- Stream pool initialized in `flow_h2_session_init()` with linked free list

**Phase B Complete (2026-01-20):**
- `h2_callback_ctx_t` extended with `flow_ctx` pointer
- All nghttp2 callbacks updated to populate `flow_transaction_t`:
  - `on_begin_headers_callback`: Creates stream, sets state
  - `on_header_callback`: Populates method, path, host, status, content-type
  - `on_frame_recv_callback`: Handles END_STREAM, state transitions
  - `on_data_chunk_recv_callback`: Appends body data to `flow_txn_append_body()`
  - `on_stream_close_callback`: Sets CLOSED/RESET state
  - `on_invalid_frame_recv_callback`: Sets `hpack_corrupted` on HPACK errors
  - `on_error_callback`: Sets `hpack_corrupted` on compression errors
- `http2_process_frame_flow()` bridge function created
- `process_worker_event()` in main.c updated to call `http2_process_frame_flow()`
- Backward compatibility maintained (both global pools AND flow_transaction_t populated)

**Architecture:**
```
┌─────────────────────────────────────────────────────────────────┐
│              Unified Transaction Architecture                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  flow_transaction_t: Common structure for HTTP/1 and HTTP/2     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ stream_id      │ Request: method, path, timestamp          │ │
│  │ state, flags   │ Response: status, content-type, encoding  │ │
│  │                │ Body: *buffer (dynamic), len, capacity    │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  HTTP/1 (Sequential):           HTTP/2 (Multiplexed):           │
│  ┌─────────────────────┐       ┌─────────────────────────────┐  │
│  │ h1_parser_ctx_t     │       │ h2_parser_ctx_t             │  │
│  │ ├─ llhttp (persist) │       │ ├─ nghttp2 session          │  │
│  │ └─ current_txn ─────┼─┐     │ └─ streams[] ───────────────┼┐ │
│  └─────────────────────┘ │     └─────────────────────────────┘│ │
│                          │                                     │ │
│                          ▼                                     ▼ │
│              [flow_transaction_t]        [txn_1][txn_3][txn_5]  │
│              (one active at a time)      (concurrent streams)   │
│                                                                  │
│  Body Buffer Strategy:                                           │
│  - Allocated ONLY when -b flag AND response has body            │
│  - Per-transaction (handles H2 interleaving correctly)          │
│  - Freed when transaction completes                             │
│                                                                  │
│  Benefits:                                                       │
│  - No global pools = no race conditions                         │
│  - Persistent H1 parser handles fragmented packets              │
│  - Per-stream H2 buffers handle multiplexed DATA frames         │
│  - Memory-efficient: allocate body only when needed             │
└─────────────────────────────────────────────────────────────────┘
```

**Key Design Decisions:**

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Body allocation | Dynamic, on-demand | Most requests have no body (GET); saves memory |
| H2 stream storage | Fixed pool with free list | O(1) alloc/free, no pointer instability |
| H1 parser | Persistent in flow_ctx | Handles headers/body spanning TCP segments |
| Transaction lifecycle | Tied to flow ownership | Single-writer guarantee via home_worker_id |
| Stream slot reuse | Free list (O(1)) | Efficient allocation without linear search |
| HPACK error handling | Connection-fatal flag | RFC 7540 requires GOAWAY on COMPRESSION_ERROR |
| Ghost stream detection | Per-stream last_active_ms | Prevents Slowloris-style resource exhaustion |

### Phase 3.7: TCP Sequence Validation (Future - Phase B)

**Problem**: HPACK is a byte-stream protocol. Any out-of-order or duplicate TCP
segments corrupt the compression context, blinding the sniffer.

| Task | Description | Status |
|------|-------------|--------|
| 3.7.1 | Add `next_seq_c2s`, `next_seq_s2c` to h2_parser_ctx_t | ⬜ Future |
| 3.7.2 | Implement sequence validation (drop dups, detect gaps) | ⬜ Future |
| 3.7.3 | Set `hpack_corrupted` on gap detection | ⬜ Future |
| 3.7.4 | Add TCP segment trimming for partial overlaps | ⬜ Future |

**Validation Logic**:
```
if (seq == next_seq) { process(data); next_seq += len; }
else if (seq < next_seq) { drop; }  // duplicate/retransmit
else { set_corrupted; }              // gap detected
```

### Phase 3.8: Out-of-Order Reassembly (Future - Phase C)

Buffer "future" packets when gaps occur, replay when gap fills.

| Task | Description | Status |
|------|-------------|--------|
| 3.8.1 | Add OOO buffer (8-16 packets per direction) | ⬜ Future |
| 3.8.2 | Implement sorted insertion by sequence number | ⬜ Future |
| 3.8.3 | Add gap-fill detection and buffer replay | ⬜ Future |
| 3.8.4 | Add timeout (100ms) for unfilled gaps | ⬜ Future |

### Phase 3.9: Opaque Mode Fallback (Future - Phase D)

When HPACK is corrupted, fall back to frame-header-only parsing.

| Task | Description | Status |
|------|-------------|--------|
| 3.9.1 | Implement 9-byte frame header parser | ⬜ Future |
| 3.9.2 | Track stream activity without HPACK | ⬜ Future |
| 3.9.3 | Add heuristic frame sync for mid-stream join | ⬜ Future |
| 3.9.4 | Alert on large DATA frames (exfil detection) | ⬜ Future |

**Opaque Mode Capabilities**:
- Parse frame headers: length, type, flags, stream_id
- Track stream creation/closure without header content
- Detect large data transfers (potential exfiltration)
- Works even when HPACK state is unknown (mid-stream join)

### Phase 4: Statistics & Debug (3 tasks)

Add observability for the new architecture.

| Task | Description | Status |
|------|-------------|--------|
| 4.1 | Add pool statistics (allocated, peak, reused) | ⬜ Pending |
| 4.2 | Add index statistics (hits, misses, promotions) | ⬜ Pending |
| 4.3 | Update debug output to show correlation path | ⬜ Pending |

### Phase 5: Testing & Documentation (4 tasks)

Verify correctness and update docs.

| Task | Description | Status |
|------|-------------|--------|
| 5.1 | Build and fix compilation errors | ✅ Done |
| 5.2 | Test without VPN - verify dual-index correlation | ⬜ Pending |
| 5.3 | Test under burst load - verify no dropped events | ⬜ Pending |
| 5.4 | Update documentation with final architecture | ⬜ Pending |

---

## API Reference (Planned)

### Pool Operations

```c
/**
 * @brief Initialize the flow context pool
 * @param pool      Pool structure to initialize
 * @param capacity  Number of slots (should be power of 2)
 * @return 0 on success, -1 on failure
 */
int flow_pool_init(flow_pool_t *pool, size_t capacity);

/**
 * @brief Allocate a slot from the pool
 * @param pool  The flow pool
 * @return flow_id of allocated slot, or FLOW_ID_INVALID if full
 */
flow_id_t flow_pool_alloc(flow_pool_t *pool);

/**
 * @brief Free a slot back to the pool
 * @param pool  The flow pool
 * @param id    The flow_id to free
 */
void flow_pool_free(flow_pool_t *pool, flow_id_t id);

/**
 * @brief Get pointer to flow context by ID
 * @param pool  The flow pool
 * @param id    The flow_id
 * @return Pointer to flow_context_t, or NULL if invalid
 */
flow_context_t *flow_pool_get(flow_pool_t *pool, flow_id_t id);
```

### Index Operations

```c
/**
 * @brief Insert entry into cookie index
 * @return 0 on success, -1 if full
 */
int cookie_index_insert(cookie_index_t *idx, uint64_t cookie, flow_id_t id);

/**
 * @brief Lookup flow_id by socket cookie
 * @return flow_id, or FLOW_ID_INVALID if not found
 */
flow_id_t cookie_index_lookup(cookie_index_t *idx, uint64_t cookie);

/**
 * @brief Insert entry into shadow index
 * @return 0 on success, -1 if full
 */
int shadow_index_insert(shadow_index_t *idx, uint32_t pid,
                        uint64_t ssl_ctx, flow_id_t id);

/**
 * @brief Lookup flow_id by (pid, ssl_ctx)
 * @return flow_id, or FLOW_ID_INVALID if not found
 */
flow_id_t shadow_index_lookup(shadow_index_t *idx, uint32_t pid,
                              uint64_t ssl_ctx);
```

### Unified Lookup

```c
/**
 * @brief Unified flow lookup - tries cookie first, then shadow
 *
 * This is the main entry point for event correlation:
 * 1. If cookie != 0, lookup in cookie_index
 * 2. If not found, lookup in shadow_index using (pid, ssl_ctx)
 * 3. Return flow_context_t* or NULL
 *
 * @param mgr     Flow manager (contains pool + indexes)
 * @param cookie  Socket cookie (0 if unknown)
 * @param pid     Process ID
 * @param ssl_ctx SSL context pointer
 * @return Pointer to flow_context_t, or NULL if not found
 */
flow_context_t *flow_lookup(flow_manager_t *mgr, uint64_t cookie,
                            uint32_t pid, uint64_t ssl_ctx);

/**
 * @brief Get or create flow context
 *
 * If flow exists (by cookie or shadow key), returns it.
 * Otherwise, allocates new slot and adds to shadow_index.
 *
 * @param mgr     Flow manager
 * @param cookie  Socket cookie (0 if unknown)
 * @param pid     Process ID
 * @param ssl_ctx SSL context pointer
 * @return Pointer to flow_context_t, or NULL if pool full
 */
flow_context_t *flow_get_or_create(flow_manager_t *mgr, uint64_t cookie,
                                    uint32_t pid, uint64_t ssl_ctx);

/**
 * @brief Promote flow to cookie index when cookie becomes available
 *
 * Called when sockops provides socket_cookie for a flow that was
 * initially created with cookie=0.
 *
 * @param mgr     Flow manager
 * @param pid     Process ID (to find in shadow_index)
 * @param ssl_ctx SSL context (to find in shadow_index)
 * @param cookie  Newly available socket cookie
 * @return 0 on success, -1 if flow not found
 */
int flow_promote_cookie(flow_manager_t *mgr, uint32_t pid,
                        uint64_t ssl_ctx, uint64_t cookie);
```

---

## Comparison: Old vs New

| Aspect | Old (Migration) | New (Shared Pool) |
|--------|-----------------|-------------------|
| Data storage | Two separate tables | Single pool |
| Handover | memcpy (~200 bytes) | 4-byte ID write |
| Race condition | Possible during copy | Eliminated |
| Memory | Variable (malloc) | Fixed (pre-alloc) |
| Cache behavior | Unpredictable | Excellent locality |
| Code complexity | High (migration FSM) | Low (just indexes) |

---

## Files to Modify

| File | Changes |
|------|---------|
| `src/correlation/flow_context.h` | Complete rewrite with new structures |
| `src/correlation/flow_context.c` | Complete rewrite with new implementation |
| `src/threading/dispatcher.c` | Replace flow_cache, add cookie promotion |
| `src/threading/threading.h` | Add flow_manager_t to dispatcher_ctx_t |
| `src/threading/worker.c` | Use flow_id, resolve to context |
| `src/threading/state.c` | Remove duplicate caches |
| `CMakeLists.txt` | Already includes flow_context.c |

---

## Success Criteria

1. **Zero data movement**: Flow context allocated once, never copied
2. **Atomic handover**: Cookie promotion is a single index insertion
3. **No lost events**: Both indexes always point to valid pool slot
4. **High throughput**: Pre-allocated pool, O(1) operations
5. **Clean statistics**: Track hits/misses/promotions for debugging

---

## Changelog

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-20 | 1.1 | Phase 3.6 complete: flow_transaction_t, HTTP/2 callbacks, http2_process_frame_flow() |
| 2026-01-19 | 1.0 | Initial plan document |
