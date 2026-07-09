# Changelog

All notable changes to spliff will be documented in this file.

## [0.10.3] - 2026-07-09

### Fixed

- Build failure on Linux kernel 7.0+ with libbpf ≤1.6.3. Kernel 7.0 added an
  `aux__prog` parameter to `bpf_stream_vprintk` that libbpf does not yet know
  about, causing a declaration conflict between vmlinux.h and bpf_helpers.h.
  Include order in `spliff.bpf.c` is now guarded by `SPLIFF_KERNEL_7_0_PLUS`
  (auto-detected from `uname -r` at configure time) and renames libbpf's stale
  4-arg declaration so vmlinux.h's canonical 5-arg version wins.
- Fedora dependency name in README: `nghttp2-devel` → `libnghttp2-devel`.

### Changed

- `vmlinux.h` is now regenerated at build time from `/sys/kernel/btf/vmlinux`
  via bpftool and written to `${CMAKE_BINARY_DIR}`. No longer committed.
  Every host builds against its own kernel. Configure fails early on kernels
  without `CONFIG_DEBUG_INFO_BTF`.
- Silence bpftool BTF-dump `-Wmissing-declarations` warnings (forward-declared
  kernel structs inside outer scopes — harmless).

### Removed

- Committed `src/bpf/vmlinux.h` (now generated). Added to `.gitignore`.
- Dead local `total_bytes` accumulator in `drain_and_write` — `bytes_written`
  atomic already tracks the actual `writev()` return value.

## [0.10.2] - 2026-04-16

### Changed

- Strip redundant `@author`/`@copyright`/`@license` Doxygen tags from 49 file
  headers. SPDX-License-Identifier is the canonical source.
- Replace hand-coded FNV-1a hex literals with `FNV_OFFSET_BASIS`/`FNV_PRIME`
  constants in flow_context.c, ck_cookie_index.c, ck_shadow_index.c, threading.h.
- Const-widen read-only parameters: `bpf_loader_get_link_count`,
  `bpf_loader_xdp_is_active`, `bpf_loader_sockops_is_attached`,
  `bpf_loader_xdp_get_last_error`, `threading_is_running`,
  `dispatcher_get_xdp_events_received`, `flow_ref_count`, `flow_is_plaintext`,
  `probe_handler_set_filter_pids`.
- Tighten `http2_frame_name` parameter from `int` to `uint8_t`.

### Removed

- Dead type `ssl_event_t` from spliff.h (zero references, replaced by
  `ssl_data_event_t` in probe_handler.h).
- Dead enum `h2_stream_state_t` and `H2_STREAM_*` enumerators from http2.h
  (zero references, replaced by `txn_state_t` in flow_context.h).
- Dead macro `#define inflateReset zng_inflateReset` from stream_decompressor.c.
- Unused variable `original_gen` from test_flow_context.c.
- 10 v0.9.11 tombstone comment blocks from main.c, worker.c, state.c, threading.h.
- 13 redundant "FIX L1: Use relaxed ordering" comments from dispatcher.c.
- `@details` restatement blocks from safe_str.c, display.c, logger.c, logger.h.

## [0.10.1] - 2026-03-28

### Fixed

- **Shutdown use-after-free**: Reordered cleanup sequence to drain
  ring buffers before freeing flow state. Previously,
  `threading_cleanup()` freed the flow manager before
  `bpf_loader_cleanup()` drained the XDP ring, causing
  heap-buffer-overflow when ring callbacks referenced freed memory.
  Cleanup order is now: detach sources, drain rings, free state.

## [0.10.0] - 2026-02-24

### Omni-Ring Foundation Release

Major architectural release implementing the Omni-Ring memory and transport
infrastructure. Introduces zero-copy mirrored buffers, lock-free SPMC ring
transport, formal reference counting for flow lifecycle management, per-flow
streaming decompression with bomb protection, and a modernized CMake build
system. This release lays the foundation for v0.11.0 protocol expansion.

**15 commits, 46 files changed, +14,146 / -867 lines**
**19 new source files, 8 new test files, 2 new CMake files**

### Added

#### Phase 1: Memory Infrastructure (`src/memory/`)
- **mirrored_buffer.h/c**: Zero-copy ring buffers using virtual memory mirroring
  (`memfd_create` + dual `mmap`). Eliminates wrap-around branching for contiguous
  reads across buffer boundaries. Includes `mirrored_buffer_prefault()` for
  page-fault-free hot paths.
- **hugepage.h/c**: Transparent hugepage integration with `madvise(MADV_HUGEPAGE)`
  for reduced TLB pressure on large allocations.
- **numa_alloc.h/c**: NUMA-aware allocation stubs (API surface for future
  `mbind()`/`set_mempolicy()` integration).
- **alignment.h**: Cache-line alignment macros and power-of-2 validation for
  buffer sizing.
- **Tests**: `test_mirrored_buffer.c` — 33 tests covering creation, wraparound
  reads, prefault, edge cases.

#### Phase 2: Ring Buffer Redesign (`src/ring/`) — L1 Transport, FROZEN
- **ring_event.h**: 56-byte event structure with 64-bit routing word and
  `EVENT_FLAG_ROUTED` for affinity-based worker dispatch.
- **spmc_ring.h/c**: Vyukov-style single-producer multi-consumer ring with
  mirrored slot storage, CAS backoff, and `mlock` to prevent slot swapping.
  Optimal at 4 workers; 8+ shows CAS contention (documented).
- **affinity.h/c**: Inline affinity check with MPSC overflow queue using
  TTAS-CAS (test-and-test-and-set with compare-and-swap).
- **backpressure.h/c**: Four-level hysteresis state machine (NORMAL → WARN →
  CRITICAL → DROP) for flow-control signaling.
- **worker_dequeue.h/c**: Three-phase worker consumption pattern:
  overflow drain → SPMC dequeue → routed dispatch.
- **adaptive_poll.h**: Header-only polling state machine for dynamic
  sleep/spin tuning based on queue depth.
- **Tests**: 5 suites, 131 tests — `test_spmc_ring.c`, `test_affinity.c`,
  `test_concurrent.c`, `test_backpressure.c`, `test_worker_dequeue.c`.
- **Docs**: ADR-001 (SPMC ring), ADR-002 (three-layer transport), ADR-003
  (session registry design).

#### Phase 3: Flow Context Redesign
- **Reference counting** (`flow_context.h/c`): `_Atomic uint32_t ref_count`
  replaces `inflight_events` counter. Inline API: `flow_ref_acquire()` (relaxed),
  `flow_ref_release()` (release + acquire fence), `flow_ref_count()` (acquire).
  Creator holds ref=1 at allocation, released in `flow_terminate()`.
- **Plaintext flow support**: `FLOW_FLAG_PLAINTEXT = (1 << 5)` with automatic
  detection when `ssl_ctx == 0`. Plaintext flows transition to ACTIVE with XDP
  data only (no SSL handshake required).
- **Streaming decompression** (`stream_decompressor.h/c`): Per-flow streaming
  decompression for gzip/deflate (zlib-ng), zstd (`ZSTD_DStream`, windowLogMax=23),
  and brotli. Bomb protection: >1000:1 compression ratio or >100MB output triggers
  permanent reject per flow.
- **Mirrored body buffers**: `flow_transaction_t` uses `mirrored_buffer_t` instead
  of heap-allocated body buffers, enabling zero-copy wrapping for contiguous body
  access. `stream_decomp_t` embedded per-transaction for per-stream decompression.
- **Encoding detection**: `detect_encoding_type()` maps Content-Encoding headers
  to `compress_type_t` for streaming decompressor initialization.
- **Tests**: `test_flow_refcount.c` (11 tests), `test_stream_decompressor.c`
  (13 tests).

#### Build System Modernization
- **OBJECT libraries**: 3 compile-once-link-many libraries eliminate 96 redundant
  compilations across test targets:
  - `spliff_memory` (1 file) — shared by core and ring consumers
  - `spliff_core` (15 files) — correlation, protocol, content, threading, util
  - `spliff_ring` (4 files) — L1 transport layer
- **INTERFACE library**: `spliff_common_deps` wraps 9 shared link dependencies
  using `${ALLOCATOR_TARGET}` (not hardcoded jemalloc).
- **Subdirectory split**: `CMakeLists.txt` split into 3 files via
  `add_subdirectory(src)` and `add_subdirectory(tests)`.
- **CTest labels**: Module-level test grouping (ring, protocol, flow, content,
  memory, util) for targeted test runs.
- **Ninja auto-detection**: Makefile uses `-G Ninja` when available for 2-5x
  faster incremental builds.
- **Module test targets**: `make test-ring`, `make test-protocol`,
  `make test-flow`, `make test-content`, `make test-memory`, `make test-util`.
- **Parallel ctest**: `ctest --parallel $(nproc)` for concurrent test execution.

### Fixed
- **Hardcoded jemalloc in tests**: 5 test targets used `PkgConfig::JEMALLOC`
  instead of `${ALLOCATOR_TARGET}`, breaking `cmake -DUSE_MIMALLOC=ON` builds.
- **bpftool not validated**: Now uses `find_program(BPFTOOL bpftool REQUIRED)`
  with `${BPFTOOL}` variable in BPF skeleton generation.
- **CMAKE_EXE_LINKER_FLAGS string append**: Replaced with modern
  `target_link_options(spliff PRIVATE -static-libgcc)`.
- **Dead TEST_COMMON_SOURCES variable**: Removed unreferenced variable (lines
  739-746 of old CMakeLists.txt).
- **memfd sealing warning**: Promoted from debug-only to all builds so production
  users see when kernel sealing fails.

### Changed
- `inflight_events` field renamed to `ref_count` with formal reference counting
  semantics across dispatcher (acquire) and worker (release) paths.
- `flow_free_resources()` cleanup order updated: streaming decompressor cleanup
  moved into `flow_txn_free_body()` per-transaction, not per-flow.
- Body buffer allocation uses fixed 256KB mirrored buffers instead of growing
  heap allocations with realloc.
- CMakeLists.txt reduced from 1291 to 802 lines; test target maintenance now
  requires editing one file instead of six.

### Technical Details
- **New source files**: 19 (memory: 6, ring: 10, content: 2, CMake: 2)
- **New test files**: 8 test suites added (total: 17 suites)
- **Total test count**: ~220 tests across 17 suites
- **Architecture docs**: 3 ADRs, 1 research analysis paper
- **Build**: Ninja auto-detected, parallel ctest, module-level test targets

### Migration Notes
- The `inflight_events` field in `flow_context_t` is now `ref_count`. Any code
  directly accessing this field must use the `flow_ref_acquire()`/`flow_ref_release()`
  API instead.
- Transaction body buffers (`flow_transaction_t`) now use `body_mirror`
  (`mirrored_buffer_t *`) instead of `body_buf` (`uint8_t *`). The `body_capacity`
  field is removed; buffer size is fixed at 256KB.
- Test targets now live in `tests/CMakeLists.txt`. Adding new test targets should
  follow the patterns there (use `spliff_core`/`spliff_ring`/`spliff_memory` object
  libraries where applicable).
- Adding a new dependency to `flow_context.c` now only requires updating
  `spliff_core`'s `target_link_libraries` in `src/CMakeLists.txt`.

## [0.9.11] - 2026-02-04

### Architecture Simplification Release

Major architectural cleanup removing legacy per-worker HTTP/2 pools in favor of
the unified per-flow session management introduced in v0.9.5. This release
removes ~1,300 lines of dead code and consolidates display functions into a
dedicated API.

### Removed

#### Per-Worker HTTP/2 Pools (~935 lines from threading module)
- **h2_connections[]**: Per-worker H2 connection array (MAX_H2_SESSIONS_PER_WORKER)
- **h2_streams[]**: Per-worker stream tracking array
- **alpn_cache[]**: Per-worker ALPN negotiation cache
- **pending_bodies[]**: Per-worker HTTP/1.1 body accumulation buffers
- **h1_request_cache[]**: Per-worker request correlation cache
- **H2_CONN_STATE enum**: Legacy connection state machine (IDLE, CONNECTING, ESTABLISHED, ERROR, CLOSING)
- **h2_shadow_queue_t**: Deferred cleanup queue for H2 sessions
- **h2_deferred_cleanup_t**: Cleanup entry structure
- **h2_connection_local_t**: Per-connection local state structure

#### Dead Functions (~128 lines from protocol modules)
- **http1_parse_headers()**: Unused wrapper around http1_parse()
- **http1_find_body_start()**: Unused body boundary finder (llhttp handles this)
- **http1_decode_chunked()**: Unused chunked decoder (llhttp handles internally)
- **signature_is_binary()**: Deprecated in favor of signature_detect_full()

#### No-Op Stubs (~25 lines)
- **flow_manager_print_stats()**: Stats now centralized in main.c
- **threading_print_stats()**: Stats now centralized in main.c
- **dispatcher_cleanup_pid()**: Flow cleanup centralized in flow_free_resources()
- **get_worker_id()**: Replaced by get_worker_id_ex() with socket_cookie support

### Added

#### Centralized Display API (~355 lines in output module)
- **Startup Display Functions**:
  - `display_banner()`: Startup header with version
  - `display_lib_found()`: Library discovery messages
  - `display_probe_attached()`: Probe attachment status
  - `display_xdp_attached()`: XDP interface attachment status
  - `display_cgroup_attached()`: Cgroup sock_ops attachment status
  - `display_warmup_status()`: BPF map warmup statistics

- **Diagnostic Functions**:
  - `display_error()`: Thread-safe error output to stderr
  - `display_warning()`: Thread-safe warning output to stderr
  - `display_debug()`: Debug-mode-only output

- **Thread Safety**: stderr output protected by pthread mutex

#### Process Utilities Module (NEW: src/util/process.c/h)
- **proc_get_name()**: Unified /proc/PID/comm reader (C23 with [[nodiscard]])
- **proc_exists()**: Process existence check
- Consolidates duplicate implementations from main.c and dispatcher.c
- Defensive input validation and null-terminated output guarantees

### Changed

#### HTTP/2 Session Management
- Sessions now exclusively managed per-flow via `flow_ctx->parser.h2`
- Worker state reduced to: decomp_buf, body_buf, h2_callbacks only
- Eliminates per-worker session isolation overhead

#### Code Organization
- Startup/diagnostic printing moved from main.c to display module
- Process name resolution consolidated in util module
- Timing function get_time_ns() unified (removed duplicate in flow_context.c)

### Technical Details
- **Files modified**: 21 source files
- **Insertions**: 566 lines
- **Deletions**: 1,323 lines
- **Net change**: -757 lines (36% reduction in touched modules)
- **New files**: src/util/process.c, src/util/process.h
- **Threading state reduction**: ~619 lines removed from state.c
- **Header reduction**: ~316 lines removed from threading.h

### Migration Notes
- No API changes for external callers
- Per-flow H2 sessions (`flow_ctx->parser.h2`) remain the single source of truth
- All removed code was confirmed dead via Doxygen call graphs and grep analysis

## [0.9.10] - 2026-02-03

### Security & Stability Audit Release

This release addresses 25 issues identified during a comprehensive code audit,
including 5 critical bugs, 7 high-priority issues, and integration of liburcu
for safe memory reclamation.

### Fixed

#### Critical Fixes (P0)
- **C1: BPF in-place map modifications** - Session info updates now use copy-modify-update
  pattern with explicit `bpf_map_update_elem()` instead of non-persisting pointer writes
- **C2: XDP-uprobe correlation race** - Added reverse flow key lookup in XDP, reducing
  cookie correlation failures by trying both forward and reverse 5-tuple keys
- **C4: Thread safety violation in flow_lookup_ex()** - Split into read-only lookup (SPMC safe)
  and separate `flow_merge_ssl_info()` for single-writer context (dispatcher only)
- **C5: Logger free_ring MPSC/SPMC mismatch** - Fixed to use `ck_ring_dequeue_spmc` for
  multiple consumers (workers) and `ck_ring_enqueue_spsc` for single producer (logger)

#### High Priority Fixes (P1)
- **H1: ssl_to_fd map exhaustion** - Changed from `BPF_MAP_TYPE_HASH` to `LRU_HASH` to
  prevent silent failures after 8K connections via automatic LRU eviction
- **H2: XDP reverse flow key lookup** - Now tries reverse key when forward lookup fails,
  catching asymmetric flow scenarios and late cookie arrivals
- **H4/H5: CK defer flag ignored** - Integrated liburcu `call_rcu()` for safe deferred
  memory reclamation in both `ck_cookie_index.c` and `ck_shadow_index.c`
- **H6: Non-atomic flow counters** - Made `pkts_in`, `pkts_out`, `bytes_in`, `bytes_out`
  atomic with `_Atomic uint32_t` and `atomic_fetch_add_explicit()` operations
- **H7: XDP callback failure silent in non-debug** - Warning now always displayed when
  XDP event callback registration fails (affects Golden Thread correlation)

#### Medium Priority Fixes (P2)
- **M5: Logger ring buffer alignment** - Changed from `calloc()` to `aligned_alloc()`
  with `LOG_CACHE_LINE` (64-byte) alignment to prevent false sharing
- **M9: liburcu integration** - Full implementation with `urcu_memb_register_thread()`
  in worker and dispatcher threads, enabling RCU-safe deferred frees

#### Low Priority Fixes (P3)
- **H3: sockops byte order documentation** - Added clear documentation for BPF sock_ops
  port semantics (remote_port: upper 16 bits network order, local_port: host order)
- **L1: Dispatcher stats relaxed ordering** - Changed stats counters from seq_cst to
  `memory_order_relaxed` (non-synchronizing counters don't need sequential consistency)
- **L2: Output stats relaxed ordering** - Same fix for `bytes_written` and `messages_written`
- **L3: Deferred queue cache alignment** - Changed from `calloc()` to `aligned_alloc(64,...)`
  for `deferred_msg_t` entries to prevent false sharing between workers
- **L4: MEMLOCK initialization** - Added `memset(&saved_memlock, 0, ...)` before `getrlimit()`
  to prevent undefined behavior if getrlimit fails
- **L5: XDP detach state accuracy** - Only clear `attached` flag on successful detach;
  keep `true` if detach fails to reflect actual kernel state
- **L6: g_probed_paths thread ownership** - Added Doxygen `@thread_safety` documentation
  documenting main-thread-only access pattern

### Added
- **liburcu Integration**: Full userspace RCU support for lock-free data structures
  - `call_rcu()` deferred free callbacks in CK hash table allocators
  - Thread registration/unregistration in worker and dispatcher threads
  - Grace period tracking for safe memory reclamation
- **flow_merge_ssl_info()**: New single-writer function for merging SSL context into
  XDP-created flows, maintaining SPMC thread safety invariants
- **Compile-time invariant checks**: `_Static_assert` for ring buffer power-of-2 sizes
  in `logger.h` and `xdp_ring.h`

### Changed
- **Build system**: Separated `build-sanitize/` directory for `make relsan` and `make sanitize`
  targets, preventing overwrites of debug builds
- **Build system**: Added `liburcu-cds` to CMake dependencies for `call_rcu()` support
- **BPF code documentation**: Added extensive comments explaining copy-modify-update pattern,
  RCU integration points, and thread safety contracts
- **RCU API**: Using explicit `urcu_memb_call_rcu()` flavor-prefixed function for clarity

### Technical Details
- **Files modified**: 14 source files across BPF, correlation, output, and threading modules
- **New dependencies**: liburcu-memb + liburcu-cds (for `call_rcu()` deferred free support)
- **Thread safety model**: Documented SPMC contracts with `@thread_safety` Doxygen tags
- **Memory ordering**: Uses `memory_order_relaxed` for stats counters, `memory_order_acquire` for
  active flag checks, `memory_order_release` for inflight event tracking, RCU barriers for hash
  table operations
- **Cache alignment**: Consistent 64-byte alignment for ring buffers and deferred queue entries

### Audit Summary
| Category | Count | Critical | High | Medium | Low | Fixed |
|----------|-------|----------|------|--------|-----|-------|
| BPF Kernel | 8 | 3 | 3 | 2 | 0 | ✅ |
| Correlation | 6 | 1 | 3 | 2 | 0 | ✅ |
| Output | 2 | 1 | 0 | 1 | 0 | ✅ |
| Threading | 3 | 0 | 0 | 1 | 2 | ✅ |
| Main/Loader | 4 | 0 | 1 | 1 | 2 | ✅ |
| Build/Arch | 2 | 0 | 0 | 2 | 0 | ✅ |
| **Total** | **25** | **5** | **7** | **9** | **4** | **25/25** |

### v0.9.10 Remaining Items (This Session)
| ID | Issue | Status |
|----|-------|--------|
| M1 | IPv6 full key (zero collisions) | ✅ Fixed |
| M2 | BPF counter atomicity | ✅ Documented as intentional |
| M3 | Dynamic cgroup2 detection | ✅ Fixed |
| M4 | Alignment verification | ✅ Fixed |
| M6 | response_buf alignment | ✅ Fixed |
| M7 | Secondary cookie index O(1) | ✅ Fixed |
| M8 | Architecture coupling docs | ✅ Fixed |

**All 25 audit items + 6 deferred items now resolved in v0.9.10.**

#### Additional Medium Priority Fixes (P2) - This Session
- **M1: IPv6 zero-collision correlation** - Added `struct flow_key_v6` (40 bytes) with full 128-bit
  IPv6 addresses and separate `flow_cookie_map_v6` BPF map. Eliminates XOR hash collisions (~50%
  at 65K flows). Includes extension header walking (bounded loop, MAX_IPV6_EXT_HEADERS=5).
- **M3: Dynamic cgroup2 detection** - Replaced hardcoded cgroup_paths[] with `find_cgroup2_mount()`
  that parses `/proc/mounts` for cgroup2 filesystem type, with fallback to standard paths.
  Works across all distributions (Fedora 31+, Ubuntu 21.10+, RHEL 9+).
- **M4: Alignment verification** - Added `_Static_assert(alignof(max_align_t) >= 16)` in
  `flow_context.c` to verify compile-time alignment support, with documentation of jemalloc
  requirement for 64-byte cache-line alignment.
- **M6: response_buf alignment** - Changed `malloc()` to `aligned_alloc(64, ...)` for HTTP/2
  65KB response buffer to prevent false sharing and enable SIMD optimizations.
- **M7: O(1) cookie lookup** - Added secondary `ck_hs` index (`by_cookie`) to `ck_shadow_index`
  keyed by socket_cookie. Replaces O(n) scan with O(1) hash lookup. ~8KB memory cost.
- **M8: Architecture coupling documentation** - Added Doxygen comment in `flow_context.c`
  documenting intentional Protocol layer coupling and rationale for deferring decoupling.

Note: M2 (BPF non-atomic counters) documented as intentional trade-off at `spliff.bpf.c:3075-3087`.
All audit items from v0.9.10 now resolved.

## [0.9.9] - 2026-02-03

### Added
- **Async MPSC Logger**: Lock-free logging pipeline for serialized output
  - MPSC ring buffer with pre-allocated entry pool
  - eventfd notification (edge-triggered)
  - writev() batching for atomic output
  - Zero malloc in hot path

- **Per-Worker XDP Rings**: SPSC rings for XDP event delivery to workers
  - Fixes timing race where workers check HAS_XDP before dispatcher polls
  - Workers process XDP events FIRST, then SSL events
  - eventfd instant wakeup on ring push

- **Deferred Display Queue**: XDP-SSL correlation synchronization
  - 100ms normal timeout, 20ms under load (backpressure valve)
  - Force flush oldest 10% when queue exceeds max
  - Waits for both FLOW_FLAG_HAS_XDP AND xdp_category != UNKNOWN

- **CK Hash Tables**: Lock-free cookie and shadow indexes
  - SPMC-safe lookups (multiple workers, single dispatcher)
  - Incremental resize with tombstone GC
  - ~256 initial capacity, grows at 75% load

- **Dual Checkmark XDP Display**: Output shows XDP and App layer verification
  - Format: `[XDP:proto][App:proto] ✓✓` when both verified
  - Single checkmark when only App layer available
  - XDP protocols: TLS, QUIC, HTTP, H2, Other, ?
  - App protocols: H1, H2, ?

- **Session Statistics Module**: Unified stats display at shutdown
  - Extracted from scattered fprintf to dedicated module
  - All stats via `stats_display()` function

- **Handshake Correlation ID**: TLS handshakes show `#xxxx` correlation

- **display_hpack_error()**: Dedicated HPACK decode error display function

### Changed
- **Flow Context Refactoring**: 843 lines changed
  - Dual index system (cookie + shadow) replaces single hash
  - Deferred free with grace period and inflight tracking
  - Generation counter for safe pointer validation

- **Threading Architecture**: XDP events routed to workers
  - Dispatcher pushes XDP to per-worker SPSC rings
  - Workers process XDP before SSL for correct ordering
  - Fixes XDP correlation timing race

- **Atomic Handshake Deduplication**: Uses atomic_exchange to prevent duplicates

### Removed
- **[HTTP/2 connection] messages**: Redundant - ALPN:h2 in output is sufficient
- **Dead code**: Removed unused display_handshake() and display_flow_info()

### Fixed
- XDP showing `[?]` despite successful correlation (AMBIGUOUS event race)
- Duplicate TLS handshake messages under high load
- Workers checking HAS_XDP before XDP events processed

### Technical Details
- New files: logger.c/h, stats.c/h, deferred.c/h, xdp_ring.c/h, ck_cookie_index.c/h, ck_shadow_index.c/h
- 2221 insertions, 1292 deletions across 19 files
- Net: +929 lines

## [0.9.8] - 2026-01-29

### Added
- **Dynamic Flow Pool**: On-demand allocation via jemalloc replaces fixed 8192-slot pre-allocated pool
  - Initial memory reduced from ~292 MB to ~9 KB (two 256-entry hash tables)
  - No artificial capacity limit — bounded only by system memory
  - `aligned_alloc(64, ...)` for cache-line-aligned flow contexts
  - OOM counter (`alloc_failures`) for production monitoring

- **Incremental Hash Table Resizing**: Cookie and shadow indexes grow without latency spikes
  - Tables start at 256 entries, grow at 75% load factor
  - Incremental migration: 8 entries moved per insert/lookup operation
  - Adaptive batch size (8→32) under pressure to prevent resize storms
  - Both insert and lookup drive migration (prevents stall during read-heavy workloads)
  - New tables start clean — no tombstone accumulation after growth

- **Generation Counter**: Safe pointer validation for worker threads
  - `uint32_t generation` on `flow_context_t` incremented on each allocation
  - `uint32_t expected_gen` on `worker_event_t` set by dispatcher at enqueue time
  - Workers check `flow_ctx->generation != expected_gen` before processing
  - Catches both freed and reused flows with a single 4-byte compare

- **Flow Reference Counting**: Prevents use-after-free during flow cleanup
  - `_Atomic uint32_t ref_count` on `flow_context_t` tracks all live references
  - Starts at 1 (creator's ref), dispatcher acquires before dispatch, worker releases after processing
  - Creator's ref released in `flow_terminate()`; deferred free blocks until ref_count reaches zero
  - Inline helpers: `flow_ref_acquire()`, `flow_ref_release()`, `flow_ref_count()`

- **Deferred Free with Grace Period**: Safe memory reclamation for flow contexts
  - Terminated flows moved to deferred FIFO queue instead of immediate free
  - 2-second grace period ensures all in-flight worker events complete
  - Janitor drains deferred queue during periodic sweeps
  - Combined with generation counter provides defense-in-depth

- **Intrusive Linked List**: O(active) flow traversal replaces O(8192) bitmap scan
  - `list_prev`/`list_next` pointers in flow_context_t first cache line
  - Janitor walks only active flows, not all 8192 slots
  - Active list maintained via head insertion/removal

- **Binary Scanner Deduplication**: "Unknown build ID" messages printed once per unique binary
  - Static tracking of up to 64 unique build IDs
  - Prevents repeated messages when same binary scanned by multiple code paths
  - Diagnostic output includes binary path for easier debugging

### Changed
- **All Libraries Mandatory**: Removed all conditional compilation guards
  - `HAVE_THREADING`, `HAVE_NGHTTP2`, `HAVE_ZSTD`, `HAVE_BROTLI`, `HAVE_ZLIB_NG`,
    `HAVE_VECTORSCAN`/`HAVE_HYPERSCAN` — all removed
  - Build definitions simplified to just `PCRE2_CODE_UNIT_WIDTH=8`
  - No more fallback stubs or degraded-mode code paths

- **Index Values**: Indexes store `flow_context_t*` pointers directly instead of `flow_id_t` indices
  - Eliminates `flow_pool_get()` indirection on every lookup
  - Dispatcher and janitor work with pointers throughout

- **Cache-Line-Conscious Layout**: `flow_context_t` restructured for hot-path performance
  - Cache line 0: identity (cookie, pid, ssl_ctx) + lifecycle (generation, list pointers)
  - Cache line 1: flow key, timestamps, counters
  - Cache line 2: strings (comm, alpn, ifname), state, flags
  - Correlation lookups touch 1 cache line, janitor touches 1-2

- **Flow Pool Statistics**: Updated for dynamic architecture
  - Removed `pool_capacity` (no fixed capacity)
  - Added `pool_alloc_failures` counter
  - Stats display: "Active: N flows, peak M" instead of "N / 8192 active"

### Removed
- Fixed 8192-slot pre-allocated flow pool (`FLOW_POOL_CAPACITY`)
- Bitmap-based allocation/deallocation (`FLOW_BITMAP_WORDS`)
- `INDEX_LOAD_FACTOR` constant (replaced by incremental resize logic)
- `flow_pool_get()` inline function (indexes return pointers directly)
- All `#ifdef HAVE_*` conditional compilation guards across 7 source files
- Vectorscan/Hyperscan manual fallback stub (~110 lines)
- nghttp2 disabled-mode stubs (~90 lines)

### Technical Details
- Modified: `flow_context.h`, `flow_context.c`, `threading.h`, `dispatcher.c`, `worker.c`,
  `main.c`, `manager.c`, `CMakeLists.txt`, `decompressor.c`, `http1.c`, `http2.c`,
  `detector.c`, `state.c`, `binary_scanner.c`
- New constants: `FLOW_INDEX_INITIAL_CAPACITY` (256), `FLOW_INDEX_GROW_BATCH` (8),
  `FLOW_DEFERRED_FREE_GRACE_NS` (2s)
- Net change: -157 lines (790 insertions, 947 deletions) across 13 files

## [0.9.7] - 2026-01-28

### Added
- **Centralized Session Statistics**: All shutdown metrics displayed from a single function in main.c
  - Unified report replaces scattered printing across `manager.c`, `flow_context.c`, and `main.c`
  - All stats shown unconditionally in every build (no `-d` debug flag required)
  - Production-grade visibility: event pipeline, per-worker breakdown, flow pool analytics,
    XDP classification, sockops events, and SSL probe counters
  - Human-readable byte formatting for output size (KB/MB/GB)
  - ANSI color highlighting for warnings and CPU efficiency status

### Changed
- **Statistics Architecture**: Modules now expose getter-only APIs; printing centralized in main.c
  - New `threading_stats_t` aggregate struct and `threading_get_aggregate_stats()` getter
  - `threading_print_stats()` and `flow_manager_print_stats()` reduced to no-ops
  - Cleanup ordering: stats collected after `threading_shutdown()` but before `threading_cleanup()`

### Technical Details
- Modified: `threading.h`, `manager.c`, `flow_context.c`, `main.c`
- New type: `threading_stats_t` (aggregates dispatcher + workers + output + flow pool)
- New function: `threading_get_aggregate_stats()`, `print_shutdown_stats()`, `format_bytes()`

## [0.9.6] - 2026-01-26

### Added
- **Embedded BPF Skeleton**: BPF bytecode now embedded in binary via libbpf skeleton pattern
  - Eliminates security risk of external `.bpf.o` file replacement
  - CO-RE compliant - works with stripped production binaries
  - Uses `bpftool gen skeleton` during build for embedded bytecode + BTF
  - No more "failed to open spliff.bpf.o: -ENOENT" errors when running from different directories

- **XDP Interface Status Display**: Clear per-interface mode reporting
  - Shows each interface name with actual mode: `eth0 [native]`, `lo [skb]`
  - Suppresses confusing libbpf kernel error messages during mode probing
  - Graceful native → SKB fallback with accurate status reporting

### Fixed
- **XDP-SSL Correlation**: Critical bug where XDP metadata was missing from HTTP output
  - Root cause: `flow_lookup_ex()` rejected XDP-only flows (ssl_ctx=0) for SSL events
  - Fix: Allow XDP-created flows to merge with SSL events via FLOW_FLAG_HAS_SSL
  - Fix: Add merged flows to shadow_index for bidirectional lookup
  - HTTP output now shows IP:port info (e.g., `192.168.50.235:40772 → 142.250.202.10:443`)

- **Vectorscan Thread Memory Leak**: Thread-local scratch space now properly cleaned up
  - Added `proto_detector_thread_cleanup()` called by worker thread cleanup
  - Prevents memory growth in long-running sessions with multiple worker threads

- **Release Mode Output**: Removed spurious `[DETECTOR] Initialized with vectorscan` message

### Changed
- **BPF Loading Architecture**: Migrated from file-based to skeleton-based loading
  - `bpf_loader_set_object()` accepts skeleton-owned bpf_object
  - Cleanup sequence prevents double-free (skeleton owns the object)
  - Build system generates `spliff.skel.h` header automatically

### Technical Details
- New files: `spliff.skel.h` (generated at build time)
- Modified: `CMakeLists.txt`, `bpf_loader.c/h`, `main.c`, `flow_context.c`, `detector.c`
- Binary size: ~460KB (includes embedded BPF bytecode + BTF)

## [0.9.5] - 2026-01-26

### Added
- **Vectorscan Protocol Detection**: High-performance pattern matching for HTTP protocol identification
  - `src/protocol/detector.c`: Vectorscan-based protocol detector with O(n) NFA matching
  - Integrated zlib-ng (native mode) for SIMD-accelerated compression
  - Fallback to PCRE2-JIT when vectorscan unavailable

- **Modular Protocol Architecture**: Enterprise-grade separation of concerns
  - `http1_try_process_event()`: Unified HTTP/1 entry point in http1.c
  - `http2_try_process_event()`: Unified HTTP/2 entry point in http2.c
  - main.c reduced to clean orchestration code (~190 lines moved to protocol modules)
  - Each protocol handler returns `true` if processed, enabling clean fallback chain

- **HTTP/1.1 Parser Direction Switching**: Automatic request↔response detection
  - llhttp parser reinitializes with correct type when direction changes
  - Fixes `HPE_INVALID_METHOD` errors when parsing responses after requests
  - Persistent parser state maintained per-flow

- **HTTP/1.1 Body Display**: Proper body output on message completion
  - `h1_display_body_flow()`: Displays body when message_complete callback fires
  - Consistent with HTTP/2 body display architecture
  - Respects `-b` flag for body display control

- **HTTP/1.1 Request URL Preservation**: Response display shows original request URL
  - `last_request_host`, `last_request_path`, `last_request_method` fields in `h1_parser_ctx_t`
  - Saved before parser reset on new message

- **HTTP/2 Response Body Display**: Fixed body accumulation and display
  - DATA frame handler now allocates body buffer on first use
  - `flow_txn_append_body()` called when `g_config.show_body` is set
  - Body displayed when END_STREAM flag received

- **HTTP/2 Lazy Session Initialization**: Sessions created on-demand in protocol module
  - `http2_process_frame_flow()` initializes session when proto=HTTP2 but session=NULL
  - Eliminates need for session init code in main.c
  - Handles timing races between ALPN events and first data packets

### Changed
- **Worker Cache Locality**: Atomic re-homing for nghttp2 thread safety
  - `home_worker_id` atomic CAS for flow ownership transfer
  - Dispatcher routes to flow's home worker when available
  - Prevents concurrent access to nghttp2 sessions (NOT thread-safe per docs)

- **Dispatcher Routing**: Home-worker-aware event routing
  - Flow lookup performed BEFORE worker ID calculation
  - Existing flows route to their home worker for cache locality
  - New/unclaimed flows use hash-based routing

- **Build System**: Updated dependencies
  - zlib-ng 2.3.2 in native mode (zng_ prefix)
  - vectorscan for O(n) pattern matching
  - jemalloc 5.3.0 memory allocator

- **Code Organization**: Protocol logic moved to dedicated modules
  - HTTP/1 detection, parsing, display → `src/protocol/http1.c`
  - HTTP/2 preface, frames, sessions, noise suppression → `src/protocol/http2.c`
  - main.c now handles: orchestration, special events (ALPN, handshake), fallback display

### Fixed
- **HTTP/2 Session Initialization**: Late init for misrouted events
  - Parser initialization now works when events arrive before flow is claimed
  - `[Worker N] Late H2 init for flow_id=X` debug output

- **HTTP/2 Body Accumulation**: DATA frames now properly accumulate body
  - Bug: `if (txn && txn->body_buf)` required body_buf to already exist
  - Fix: `if (txn)` + conditional `flow_txn_append_body()` call

### Removed
- **Legacy Flow Cache**: Deleted `src/correlation/flow_cache.c` and `flow_cache.h` (751 lines)
- **HTTP/2 Global Pools**: Removed legacy `g_h2_streams[]`, `g_h2_connections[]`
- **HTTP/2 Duplicate Code**: Consolidated from 2074 lines to ~800 lines in http2.c

### Architecture
```
main.c (orchestration only, ~50 lines of protocol routing)
    │
    ├── http1_try_process_event() ──► http1.c (all HTTP/1 logic)
    │       └── Detection, parser init, direction switching, body display
    │
    ├── http2_try_process_event() ──► http2.c (all HTTP/2 logic)
    │       └── Preface, mid-connection, session mgmt, noise suppression
    │
    └── Fallback: vectorscan detection, signature detection, raw display
```
- Both llhttp (HTTP/1.1) and nghttp2 (HTTP/2) are NOT thread-safe per-instance
- Flow `home_worker_id` ensures single-writer access per parser
- Dual-index correlation (cookie + shadow) provides fallback correlation

### Statistics
- **23 files changed**, 2,748 insertions(+), 3,923 deletions(-)
- **Net reduction**: ~1,175 lines of code
- **main.c**: 642 lines removed (protocol logic moved to modules)
- **http2.c**: Consolidated from 2074 lines to ~800 lines

## [0.9.4] - 2026-01-25

### Removed
- **Phase 5 Complete**: Legacy code removal (~3,400 lines deleted)
  - Deleted `src/correlation/flow_cache.c` and `flow_cache.h` (751 lines)
  - Removed HTTP/2 global pools: `g_h2_streams[]`, `g_h2_connections[]`
  - Removed per-worker caches: `alpn_cache[]`, `pending_bodies[]`, `h1_request_cache[]`
  - Removed legacy HTTP/1 fallback parser in main.c (~287 lines)
  - Removed dual-path XDP/SSL correlation code from dispatcher
  - Removed deprecated functions: `http2_set_flow_info()`, `http2_has_session()`, `http2_get_stream()`, `http2_free_stream()`
  - Removed worker cache functions: `worker_get_alpn()`, `worker_set_alpn()`, `worker_find_pending_body()`, etc.

### Changed
- **Single Source of Truth**: Shared Pool (`flow_context_t`) is now the exclusive correlation mechanism
  - All HTTP/1 parsing uses `http1_parse_flow()` with flow context
  - All HTTP/2 parsing uses `http2_process_frame_flow()` with flow context
  - ALPN stored in `flow_ctx->alpn` only (no worker cache fallback)
  - Body accumulation uses `flow_ctx->body` only

- **Simplified Worker Event Structure**
  - Removed `flow_info` field (was legacy XDP cache pointer)
  - `needs_cookie_retry` now based on `FLOW_FLAG_HAS_XDP` status

### Architecture
- Completed migration from per-worker + global pools to unified Shared Pool
- Flow lifecycle fully managed by `flow_manager_t` with dual-index lookup
- Worker threads operate exclusively on `flow_context_t` instances

## [0.9.3] - 2026-01-24

### Added
- **BPF Flow Cache Warm-up**: Direct BPF map iteration for accurate correlation
  - `flow_cache_warmup_from_bpf()`: Iterates `flow_states` map at startup
  - Uses real socket cookies instead of inode pseudo-cookies
  - Significantly improves correlation rate for pre-existing connections

- **Dual-Index Flow Lookup**: Extended correlation path visibility
  - `flow_lookup_ex()`: Returns which index was used (COOKIE, SHADOW, CREATED, NONE)
  - `flow_lookup_path_t` enum for tracking correlation paths
  - Debug output shows correlation path in `-d` mode

- **Pool Statistics API**: Runtime visibility into flow pool health
  - `flow_pool_stats_t`: Capacity, allocations, frees, index hit rates
  - `flow_manager_get_stats()` / `flow_manager_print_stats()`
  - Statistics shown in threading summary output

- **BPF Cookie Lookup Function**: Direct map query fallback
  - `bpf_loader_lookup_flow_by_cookie()`: O(n) fallback lookup
  - `bpf_loader_get_flow_states_fd()`: Access BPF map fd

### Changed
- **Legacy Code Cleanup**: Removed deprecated global pools and duplicate caches
  - Deprecated `pending_body_entry_t` with migration notes
  - Deprecated `alpn_cache_entry_t` in favor of flow-local storage
  - Removed redundant global pool references from threading code

- **Phase 4.1-4.3 Complete**: Pool statistics and correlation debug output
  - Flow janitor evicts from both legacy cache and Shared Pool
  - Correlation path visible in debug mode for troubleshooting
  - VPN detection: expected ~7% correlation rate through WireGuard

### Fixed
- **Pre-existing Connection Correlation**: Major improvement in correlation rate
  - Root cause: XDP FLOW_NEW events not emitted for already-classified flows
  - Fix: BPF map warm-up provides real cookies to userspace cache
  - Improvement: ~55% → ~80%+ correlation for pre-existing connections

### Architecture
```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Shared Pool Architecture (v0.9.3)                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────┐     ┌──────────────────┐     ┌──────────────────┐    │
│   │ SSL Events  │────►│  Dual-Index      │────►│  flow_context_t  │    │
│   │ (uprobe)    │     │  Lookup          │     │  Pool (8192)     │    │
│   └─────────────┘     │  ┌────────────┐  │     └──────────────────┘    │
│                       │  │cookie_index│  │              │              │
│   ┌─────────────┐     │  │(fast path) │  │     ┌────────▼────────┐    │
│   │ XDP Events  │────►│  ├────────────┤  │────►│ Per-Flow State  │    │
│   │ (FLOW_NEW)  │     │  │shadow_index│  │     │  • H2 streams   │    │
│   └─────────────┘     │  │(fallback)  │  │     │  • H1 parser    │    │
│         │             │  └────────────┘  │     │  • Body buffer  │    │
│         │             └──────────────────┘     └─────────────────┘    │
│         │                                                              │
│         ▼                                                              │
│   ┌─────────────┐     ┌──────────────────┐                             │
│   │ flow_cache  │────►│  5-tuple lookup  │◄── BPF warm-up at startup   │
│   │ (legacy)    │     │  by cookie       │                             │
│   └─────────────┘     └──────────────────┘                             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Known Issues
- **Partial Correlation for Some Domains**: ~20% of requests may lack XDP correlation
  - Affects: domains accessed immediately at startup (fonts, CDNs)
  - Cause: timing race between SSL events and XDP map population
  - Impact: cosmetic only (HTTP content captured, just no IP metadata)
  - Workaround: BPF warm-up mitigates but cannot fully eliminate

- **VPN/Tunnel Impact**: XDP sees encrypted outer packets, not inner TCP
  - WireGuard/OpenVPN: ~7% correlation rate expected
  - Solution: attach XDP to tunnel interface (tun0, wg0) if needed

## [0.9.2] - 2026-01-20

### Added
- **Unified Transaction Architecture (Phase 3.6)**: Per-flow HTTP/2 stream storage
  - `flow_transaction_t` structure with RFC 7540-aligned state machine
  - States: IDLE, OPEN, HALF_CLOSED_LOCAL, HALF_CLOSED_REMOTE, CLOSED, RESET, ERROR
  - Transaction flags for END_STREAM tracking, body allocation, display state
  - O(1) stream slot allocation via free-list in fixed 64-stream array
  - Per-stream `last_active_ms` timestamp for ghost stream detection
  - `http2_process_frame_flow()` bridge function for flow-aware processing

- **HTTP/2 Stream Pool Management**: Thread-safe stream lifecycle
  - `flow_h2_init_stream_pool()`: Initialize free-list linked array
  - `flow_h2_alloc_stream()`: O(1) allocation from free list
  - `flow_h2_find_stream()`: Lookup by stream ID with activity tracking
  - `flow_h2_free_stream()`: Return slot to free list with body cleanup
  - `flow_h2_reap_ghosts()`: Timeout-based cleanup (10s default)
  - `flow_txn_alloc_body()` / `flow_txn_append_body()` / `flow_txn_free_body()`

- **HPACK Corruption Detection**: Connection-fatal error handling
  - `hpack_corrupted` flag in `h2_parser_ctx_t` per RFC 7540 Section 4.3
  - nghttp2 error callbacks set flag on inflate failures
  - `http2_process_frame_flow()` early-exits when HPACK is corrupted
  - Prevents cascading decode failures and resource waste

### Changed
- **HTTP/2 Callbacks**: Dual population of global pools AND flow_transaction_t
  - `on_begin_headers_callback`: Creates flow stream, sets TXN_STATE_OPEN
  - `on_header_callback`: Populates method, path, host, status, content-type
  - `on_frame_recv_callback`: Handles END_STREAM, state transitions
  - `on_data_chunk_recv_callback`: Appends body data to flow stream
  - `on_stream_close_callback`: Sets CLOSED/RESET state
  - Backward compatible - legacy global pools still populated

- **h2_parser_ctx_t**: Extended with stream pool fields
  - `streams[64]`: Fixed array of flow_transaction_t
  - `free_head`: Head of free-list for O(1) allocation
  - `active_count`: Number of active streams
  - `hpack_corrupted`: Connection-fatal HPACK error flag

- **h1_parser_ctx_t**: Added embedded `txn` field for HTTP/1.1 transaction

### Technical Details
- Worker affinity via `hash(pid, ssl_ctx) % num_workers` unchanged
- `home_worker_id` atomic CAS ensures single-writer guarantee per flow
- Stream timeout: 10 seconds (FLOW_STREAM_TIMEOUT_MS)
- Maximum streams per flow: 64 (FLOW_MAX_H2_STREAMS)

## [0.9.1] - 2026-01-19

### Fixed
- **XDP-SSL Dispatcher Context Mismatch**: XDP events now properly correlate with SSL data
  - Re-register XDP callback after threading_start() to use initialized flow_cache
  - Socket cookie lookup now finds cached XDP flow metadata for HTTP output

- **Flow Direction Normalization**: HTTP request/response pairs show correct IP direction
  - Requests display: `client:port → server:port`
  - Responses display: `server:port → client:port`
  - Uses XDP flow_direction field instead of hardcoded port assumptions

- **XDP Category Mapping**: Fixed incomplete category-to-string mapping
  - Now uses enum constants (XDP_CAT_TLS_TCP, etc.) for type safety
  - Handles all 6 categories: Unknown, TLS, QUIC, HTTP, H2, Other

- **Removed BPF Debug Statements**: Cleaned up bpf_printk calls from production code
  - Removed XDP cookie lookup debug output
  - Removed sockops handler debug logging

### Changed
- **Runtime Debug Mode**: `-d` flag now controls debug output in both debug and release builds
  - HTTP/2 frame logging gated by g_config.debug_mode
  - XDP correlation debug output conditional on debug mode
  - Unified behavior across build configurations

- **Threading Statistics**: Improved user-friendly display format
  - Simplified default output shows events captured/processed
  - Per-worker breakdown and CPU efficiency only shown in debug mode
  - Added interpretive labels (Excellent/Good/High load) for CPU efficiency

### Known Issues
- **First Request Timing**: Initial HTTP request from each process may lack XDP correlation
  - Subsequent requests correlate correctly
  - Under high traffic, some request/response pairs may miss correlation
  - Root cause: race between SSL event and sockops flow_cookie_map population
  - Investigation ongoing

## [0.9.0] - 2026-01-18

### Added
- **Comprehensive Doxygen Documentation**: Full API documentation for all modules
  - File-level documentation with architecture diagrams
  - Function documentation with parameters, return values, and usage notes
  - Structure documentation with field descriptions
  - Grouped functions by category using `@defgroup`
  - ASCII diagrams in `@code` blocks for visual architecture understanding
  - CMake integration: `make docs` generates HTML documentation

- **Dynamic Process Monitoring**: EDR-style process lifecycle tracking
  - BPF tracepoints for `sched_process_exec` and `sched_process_fork`
  - Runtime detection of processes starting after spliff launch
  - Dynamic uprobe attachment to newly discovered SSL libraries
  - Process exit cleanup via `sched_process_exit` tracepoint

- **BoringSSL/Chromium Detection (Experimental)**: Browser SSL interception
  - Heuristic binary scanning for stripped BoringSSL binaries
  - Automatic detection of Chrome, Chromium, Brave, and Edge browsers
  - Function offset discovery without debug symbols
  - Path-based deduplication prevents duplicate probe attachment
  - **Note**: Experimental feature - may be flaky due to stripped binaries

- **HPACK Fallback Parser**: Mid-stream HTTP/2 recovery
  - Attempts literal header parsing when HPACK decompression fails
  - Improves capture success rate for mid-connection attachments

### Changed
- **Documentation**: All source files now include comprehensive Doxygen comments
  - Threading module: threading.h, manager.c, dispatcher.c, worker.c, output.c, state.c, pool.c
  - Protocol module: http1.c, http2.c
  - Content module: decompressor.c, signatures.c
  - Output module: display.c
  - Utility module: safe_str.c

### Known Issues
- **Chrome/Chromium Support**: Experimental and may cause crashes or miss traffic
  - BoringSSL offsets vary between browser versions and distributions
  - No stable ABI - function signatures may change without notice
  - Recommended to use Firefox (NSS) for reliable browser traffic capture

## [0.8.1] - 2026-01-13

### Fixed
- **sock_ops Connection Cleanup**: Added `BPF_SOCK_OPS_STATE_CB` handler to remove stale entries from `flow_cookie_map` when TCP connections close
  - Triggers on transitions to `TCP_CLOSE`, `TCP_CLOSE_WAIT`, `TCP_TIME_WAIT`
  - Deletes both forward and reverse flow keys
  - Prevents map bloat for high-volume short-lived connections
  - Complements existing LRU eviction with proactive cleanup

## [0.8.0] - 2026-01-13

### Added
- **XDP Packet-Level Flow Tracking**: High-performance packet capture at network interface level
  - Auto-attaches to all suitable network interfaces (physical and virtual)
  - Native mode with automatic SKB fallback for unsupported drivers
  - Protocol detection: TLS, HTTP/2 preface, HTTP/1.x at packet level
  - Flow state machine tracks connection lifecycle (SYN, data, FIN/RST)

- **sock_ops Cookie Caching ("Golden Thread")**: Socket-to-packet correlation
  - `sock_ops` BPF program hooks TCP connection establishment events
  - Caches socket cookies at `ACTIVE_ESTABLISHED_CB` and `PASSIVE_ESTABLISHED_CB`
  - XDP reads cached cookies via `flow_cookie_map` for uprobe correlation
  - Enables linking packet-level data with SSL session data

- **Connection Warm-up**: Existing connection tracking at startup
  - Uses netlink `SOCK_DIAG` to enumerate existing TCP sockets
  - Seeds `flow_cookie_map` with connections established before attachment
  - Enables correlation with long-lived connections

- **XDP Statistics**: Debug-mode performance metrics
  - Packet counts (total, TCP)
  - Flow lifecycle (created, classified, ambiguous)
  - Gatekeeper hits, cookie failures, ringbuf drops
  - Displayed at shutdown with `-d` flag

### Technical Details
- BPF verifier compatibility: "check-pointer-first" pattern for bounds validation
  - Prevents Clang from inverting comparisons that do arithmetic on `pkt_end`
  - `asm volatile` barriers lock pointer arithmetic before comparisons
- New BPF maps: `flow_states`, `flow_cookie_map`, `xdp_events`, `xdp_stats_map`
- sock_ops replaces SK_LOOKUP (which doesn't support `bpf_get_socket_cookie`)
- Cgroup-based attachment for system-wide socket cookie tracking

## [0.7.1] - 2026-01-12

### Added
- **HTTP/1.1 Request-Response Correlation**: Responses now show associated request URL
  - Request cache tracks (pid, ssl_ctx) → (method, path, host) per connection
  - Response display includes URL from cached request for correlation
  - Both single-threaded and multi-threaded modes supported

- **ALPN Protocol Indicator**: Display shows negotiated protocol
  - Format: `ALPN:h2` or `ALPN:http/1.1`
  - Shown for both requests and responses
  - Uses actual ALPN from TLS negotiation when available

### Changed
- **Unified Display Format**: Consistent output regardless of HTTP version
  - Request: `→ METHOD https://host/path ALPN:protocol process (PID) [latency] [stream N]`
  - Response: `← STATUS https://host/path ALPN:protocol content-type (size) process (PID) [latency] [stream N]`
  - Arrow direction: `→` for outgoing requests, `←` for incoming responses

### Fixed
- **TLS Handshake Probe Duplication**: Removed redundant `SSL_do_handshake` probes
  - `SSL_connect` internally calls `SSL_do_handshake`, causing duplicate events
  - Now only attaches to `SSL_connect` for OpenSSL handshake detection
  - Note: Multiple handshakes per connection are still possible (session resumption)

## [0.7.0] - 2026-01-12

### Added
- **BPF-Level Socket Family Filtering**: Kernel-level IPC traffic elimination
  - CO-RE helper walks `task_struct → files_struct → fdtable → file → socket → sock → skc_family`
  - Filters AF_UNIX (IPC) traffic at BPF level before reaching userspace
  - Keeps only AF_INET/AF_INET6 (web) traffic for processing

- **SSL_set_fd Hook for OpenSSL**: Maps SSL* to OS file descriptor
  - Enables socket family lookup for OpenSSL connections
  - `tracked_sessions` map stores protocol type and socket family per connection
  - `ssl_to_fd` map tracks SSL context to fd mapping

- **NSS SSL Layer Verification**: Filters non-SSL PRFileDesc traffic
  - `SSL_ImportFD` hook tracks verified SSL connections
  - `is_nss_ssl_fd()` check in PR_Write/PR_Read exit probes
  - Eliminates Firefox IPC noise from non-SSL NSPR layers

- **Session Cleanup Hooks**: Prevents BPF map exhaustion
  - `SSL_free` (OpenSSL): Cleans up `tracked_sessions` and `ssl_to_fd`
  - `PR_Close` (NSS): Cleans up `nss_ssl_fds` and `tracked_sessions`
  - `gnutls_deinit` (GnuTLS): Cleans up `tracked_sessions`

### Changed
- **HPACK Mid-Stream Recovery**: Improved error handling strategy
  - Removed aggressive table reset that corrupted subsequent decodes
  - New approach: Skip first few errors, recreate inflater after 5+ persistent errors
  - Tracks `hpack_error_count` and `hpack_success_count` per connection
  - `mid_stream_joined` flag for detected mid-stream connections

- **IPC Filtering Always-On**: Removed `--filter-ipc` CLI option
  - BPF kernel-level filtering handles socket family checks
  - Userspace heuristics provide additional backup filtering
  - Simplifies user experience - optimal filtering is automatic

### Technical Details
- New BPF maps: `tracked_sessions`, `ssl_to_fd`, `ssl_fd_args_map`
- ALPN parsing in BPF: Routes connections to correct parser (llhttp vs nghttp2)
- Session state machine with protocol detection (PROTO_HTTP1, PROTO_HTTP2)

## [0.6.1] - 2026-01-12

### Fixed
- **Segmentation Fault in Multi-Threaded Mode**: Fixed format string mismatch in `output_write`
  - Format string had 14 `%s` specifiers but only 13 string arguments
  - `msg.pid` (uint32_t) was being interpreted as a pointer, causing SEGV

- **HTTP/2 Requests Displayed as Responses**: Fixed `event_type` not passed to HTTP/2 processor
  - `ssl_data_event_t.event_type` field now correctly set in all bpf_event initializers
  - Requests no longer misidentified as responses with status 0

- **HTTP/2 HPACK Error Recovery**: Reset dynamic table on decompression failure
  - Mid-stream capture causes HPACK dynamic table desync (unavoidable limitation)
  - On inflate error, now clears and reinitializes the HPACK dynamic table
  - Prevents cascading decode failures after joining existing connection

- **HTTP/2 Frame Validation**: Added frame type vs stream_id validation per RFC 7540
  - DATA, HEADERS, PRIORITY, RST_STREAM, PUSH_PROMISE, CONTINUATION require stream_id > 0
  - SETTINGS, PING, GOAWAY require stream_id == 0
  - WINDOW_UPDATE allowed on both connection (0) and streams

- **Suppress HPACK Decode Failures**: Skip display of responses with status=0
  - Status code 0 indicates HPACK decompression failed (mid-stream capture)
  - Prevents confusing "← 0" output in response display

### Changed
- Enhanced IPC/noise filtering for raw READ/WRITE events
  - Small writes (≤13 bytes) on HTTP/2 connections suppressed as control frames
  - Block-sized reads (4096, 8192, etc.) without HTTP signatures filtered
  - Common control frame sizes (4, 8, 9, 13 bytes) automatically suppressed

## [0.6.0] - 2026-01-11

### Added
- **Multi-Threaded Event Processing**: Complete lock-free threading infrastructure
  - Dispatcher thread polls BPF ring buffer and routes events to workers
  - Worker threads process HTTP/1.1 and HTTP/2 with per-worker isolated state
  - Output thread serializes formatted output to prevent interleaving
  - Connection affinity: `hash(pid, ssl_ctx) % num_workers` ensures same connection always routes to same worker
  - Auto-detects optimal worker count: `max(1, CPUs-3)` capped at 16 workers

- **Lock-Free Data Structures**: Uses Concurrency Kit (ck) library
  - SPSC rings for dispatcher→worker and worker→output communication
  - Lock-free object pools for event and output message allocation
  - Adaptive wait strategy: spin (1000 iters) → yield (10 iters) → eventfd sleep (10ms)

- **Per-Worker State Isolation**: Thread-safe protocol processing
  - Per-worker ALPN cache for protocol negotiation tracking
  - Per-worker pending body buffers for HTTP/1.1 response reassembly
  - Per-worker decompression buffers (eliminates static buffer races)
  - Per-worker HTTP/2 session and stream tracking

- **New CLI Options**:
  - `-t, --threads N`: Set worker thread count (0=auto, default: auto)
  - `--no-threading`: Disable multi-threading for single-threaded mode

### Changed
- CMake now shows CK library in dependencies and threading status in options
- Both HTTP/1.1 and HTTP/2 protocols use the threading infrastructure
- Graceful shutdown drains all queues before exiting
- Statistics printed at shutdown showing events processed/dropped per worker

### Dependencies
- New optional dependency: `ck` (Concurrency Kit) library
  - Fedora: `sudo dnf install ck-devel`
  - Ubuntu/Debian: `sudo apt install libck-dev`
  - Falls back to single-threaded mode if ck is not available

## [0.5.3] - 2026-01-11

### Added
- **Enhanced File Signature Detection**: Expanded from ~27 to ~50 web-relevant signatures
  - New formats: AVIF, HEIC, HEVC, M4A, M4B, 3GP, DASH, XZ, LZ4, BZIP2, FLV, TIFF, PSD, CUR
  - Container format variants: RAR5, ZIP empty/spanned archives, multiple MP3 frame sync patterns
  - Mach-O endianness variants, Android DEX files
  - ISO Base Media File Format (ISOBMFF) brand detection for MP4/MOV/HEIC/AVIF variants

- **File Class Categorization**: New `file_class_t` enum for semantic grouping
  - Categories: Image, Video, Audio, Archive, Document, Font, Executable, Database, Container
  - `signature_class_name()` API returns human-readable class names

- **"Most Specific Wins" Matching**: Signatures sorted by magic length at initialization
  - Uses qsort for automatic priority ordering (longest magic bytes first)
  - Prevents short signatures from shadowing more specific ones

- **Trailer Byte Validation**: Optional end-of-file signature verification
  - PNG (IEND chunk), GIF (00 3B), JPEG (EOI marker), PDF (%%EOF)
  - `signature_detect_full()` API with `validate_trailer` parameter
  - Shows "(trailer mismatch)" warning when validation fails

- **New CLI Option `-x`**: Hexdump body display with file signature detection
  - Shows detected file type, class, and size in body header
  - Always displays hex dump (16 bytes per line with ASCII)
  - Implies `-b` (show body)

### Changed
- `signature_result_t` struct provides full detection metadata: description, class, is_binary, trailer_valid, confidence
- Legacy `signature_detect()` API preserved for backward compatibility
- Signature initialization checks return value and warns on failure

## [0.5.1] - 2026-01-11

### Fixed
- **Firefox IPC Filtering**: Removed "Socket Thread" from IPC thread patterns
  - "Socket Thread" is Firefox's legitimate web traffic thread, not IPC
  - Fixes issue where `--filter-ipc` filtered out all Firefox web traffic

- **HTTP/2 Preface Detection**: Added partial preface pattern matching
  - Recognizes `"PRI "` prefix to avoid false IPC classification
  - Fixes HTTP/2 sessions being filtered before establishment

- **HTTP/2 Control Frame Suppression**: Suppress noisy control frames in release mode
  - Hides SETTINGS, WINDOW_UPDATE, PING, RST_STREAM, PRIORITY frames
  - Small writes (< 9 bytes) on active HTTP/2 sessions are suppressed
  - Debug mode (`-d`) preserves all raw events for protocol development

### Changed
- Test executables excluded from default build target (use `make test` to build and run)
- Added `debug_mode` to global config for conditional raw event display

### Removed
- Unused `is_verified_nss_ssl_fd()` function (cleanup)

## [0.5.0] - 2026-01-10

### Added
- **ALPN Protocol Detection**: Hook ALPN negotiation functions for definitive HTTP/1.1 vs HTTP/2 detection
  - OpenSSL: `SSL_get0_alpn_selected`
  - GnuTLS: `gnutls_alpn_get_selected_protocol`
  - NSS: `SSL_GetNextProto`
  - WolfSSL: `wolfSSL_ALPN_GetProtocol`
  - ALPN events display negotiated protocol before data transfer begins

- **IPC/Internal Traffic Filtering**: New `--filter-ipc` option to reduce browser noise
  - Content-based detection (HTTP signatures vs binary data ratio)
  - Known internal thread pattern filtering (Cache2 I/O, Timer, Socket Thread, etc.)
  - Filters non-HTTP traffic from multi-process browsers like Firefox

- **Enhanced Process Scanner**: Comprehensive SSL library discovery
  - Scans ALL running processes (removed early-exit limitation)
  - Tracks multiple unique library paths per type
  - New `--show-libs` option displays discovery statistics
  - Reports: processes scanned, SSL-enabled processes, unique paths found

- **WolfSSL Support**: Added support for wolfSSL library
  - Automatic discovery of `libwolfssl.so`
  - Hooks for `wolfSSL_read` and `wolfSSL_write`

- **Firefox Bundled Library Paths**: Static path discovery for Firefox's bundled NSS
  - `/usr/lib/firefox/`, `/usr/lib64/firefox/`
  - `/opt/firefox/`
  - `/snap/firefox/current/usr/lib/firefox/`

### Changed
- Library discovery now returns extended results with all unique paths per library type
- `lib_discovery_result_t` structure expanded with statistics and multi-path tracking

## [0.4.0] - 2026-01-09

### Added
- **Process Exit Handler**: BPF tracepoint to cleanup sessions when processes die
  - Added `sched_process_exit` tracepoint handler in BPF
  - Added `http2_cleanup_pid()` to free HTTP/2 sessions and stream buffers
  - Added `cleanup_pending_bodies_pid()` to free HTTP/1.1 pending body buffers
  - Prevents memory leaks when monitored processes exit unexpectedly

- **Dynamic Library Discovery**: Find SSL libraries via `/proc/PID/maps`
  - Added `bpf_loader_discover_libraries()` to scan process memory maps
  - Added `bpf_loader_find_library_dynamic()` with fallback to static paths
  - Supports Flatpak/Snap containers and bundled SSL libraries
  - When `--pid` is specified, scans those PIDs for library paths

- **SSL Context Connection Tracking**: Track connections by `(PID, ssl_ctx)` tuple
  - Isolates HTTP/2 sessions per actual SSL connection
  - Supports multiple concurrent SSL connections per process (e.g., browser tabs)
  - Correctly tracks HTTP/1.1 body accumulation per connection

### Changed
- Library discovery now tries dynamic `/proc/maps` discovery before static paths
- Event structure includes `ssl_ctx` field for connection isolation

## [0.3.0] - 2026-01-09

### Changed
- **Build System**: Migrated from legacy Makefile to CMake
  - CMake 3.20+ required
  - Makefile retained as wrapper for backward compatibility
  - Added CPack support for .deb and .rpm packaging
- **License**: Re-licensed under AGPL-3.0-only (GPL-2.0-only for BPF code)
- **C Standard**: Now requires C23 with GNU extensions

### Added
- `RelWithSan` build type: Optimized build (-O2) with sanitizers for testing
- SPDX license identifiers in all source files
- Proper CMake sanitizer detection (compile + link test)
- HTTP/2 unit tests (`tests/test_http2.c`) with 9 test cases
- `make test` target for running all tests

### Security
- **Fixed command injection vulnerability** in `bpf_loader_find_library()`
  - Removed unsafe popen() with shell command containing user input
  - Now uses direct filesystem search with input validation
- Added input validation for library names (alphanumeric, dots, dashes only)

### Code Quality
- Replaced all `atoi()` calls with `strtol()` + error checking
- Replaced `strtok()` with thread-safe `strtok_r()`
- Added `malloc()` return value checks (prevents NULL dereference)
- Fixed memory leak in `http2_cleanup()` (stream body buffers now freed)

### Fixed
- **--comm filter**: Now checks both process comm name AND executable path
  - Firefox child processes ("Web Content", "Socket Thread") now match `--comm firefox`
- **--ppid filter**: Now traverses full process tree (up to 5 levels)
  - Correctly captures grandchildren and deeper descendants
- **HTTP/2 mid-connection detection**: Recognizes HEADERS, WINDOW_UPDATE, DATA frames
  - Previously only detected SETTINGS frames on stream 0
- **HTTP/2 buffer corruption**: Fixed infinite buffering when joining mid-stream
  - Added frame header validation (length, type, stream ID sanity checks)
  - Added automatic recovery mechanism for corrupted state
  - Prevents buffer filling up and blocking all HTTP/2 traffic
- **Thread filtering**: Removed overly aggressive filtering of "Web Content", "Renderer"
  - These Firefox processes actually make HTTP requests
- **NSS non-HTTP traffic**: Filter out local file I/O captured by NSPR probes
  - ELF, Mach-O, SQLite, Java class files are silently skipped
  - Reduces noise from Firefox loading shared libraries via NSPR
- CMake sanitizer library detection (checks both compile and link)

## [0.2.6] - 2026-01-08

### Added
- NSS handshake probe (SSL_ForceHandshake in libssl3.so) for Firefox TLS handshake tracking

## [0.2.5] - 2026-01-08

### Added
- NSS PR_Send and PR_Recv probes for better NSPR socket I/O coverage
- Root privilege check at startup with helpful error message

## [0.2.4] - 2026-01-08

### Fixed
- TLS handshake events now display correctly
- Separate BPF map for handshake timestamps (fixes race with SSL read/write)
- Filter bypass for handshake events (buf_filled=0 was being filtered)
- Skip in-progress handshake events (SSL_ERROR_WANT_READ/WRITE)

### Added
- SSL_connect probe for client-side TLS handshakes

## [0.2.3] - 2026-01-08

### Added
- `-l` option: Show SSL operation latency in request/response output
- `-H` option: Show TLS handshake events with duration
- Handshake probes for OpenSSL (SSL_do_handshake) and GnuTLS (gnutls_handshake)

## [0.2.2] - 2026-01-08

### Fixed
- Multi-event body tracking for responses split across SSL_read events
- Process name resolution via /proc/PID/comm (fixes thread name display)
- Compressed body decompression for gzip/brotli/zstd chunked responses
- Header display in non-compact mode

## [0.2.1] - 2025-01-08

### Changed
- **HTTP/1.1 Parser**: Replaced custom parser with llhttp library
  - Uses HTTP_BOTH mode for automatic request/response detection
  - Automatic chunked transfer encoding decoding
  - Streaming callback architecture for robust parsing
- **Simplified main.c**: Unified request/response handling via `http1_parse()`

### Added
- `http1_parse()` API with integrated body handling
- `is_chunked`, `http_major`, `http_minor` fields in `http_message_t`
- Unit tests for HTTP/1.1 parser (`tests/test_http1.c`)
- llhttp as required dependency in Makefile

## [0.1.0] - 2025-01-05

### Added
- **SSL/TLS Library Support**
  - OpenSSL: `SSL_read`, `SSL_write`, `SSL_read_ex`, `SSL_write_ex`
  - GnuTLS: `gnutls_record_recv`, `gnutls_record_send`
  - NSS/NSPR: `PR_Read`, `PR_Write`, `PR_Recv`, `PR_Send`

- **HTTP Protocol Support**
  - HTTP/1.1 full header parsing
  - HTTP/1.1 chunked transfer encoding
  - HTTP/1.1 body aggregation and buffering
  - HTTP/2 frame parsing (HEADERS, DATA, SETTINGS, WINDOW_UPDATE, etc.)
  - HTTP/2 HPACK header decompression
  - HTTP/2 Huffman decoding
  - HTTP/2 stream tracking with request/response correlation

- **Body Handling**
  - Automatic decompression: gzip, deflate
  - Optional decompression: zstd, brotli (compile-time)
  - Smart content display (text vs binary detection)
  - 40+ file signature detection via magic bytes
  - Request correlation for body display

- **Filtering Options**
  - Filter by PID(s): `-p 1234` or `-p 1234,5678`
  - Filter by parent PID: `--ppid 1234`
  - Filter by process name: `--comm curl`
  - Filter by SSL library: `--openssl`, `--gnutls`, `--nss`

- **Output Features**
  - Colored output (disable with `-C`)
  - Millisecond timestamps
  - Latency measurement for HTTP/1.1 (`-l`)
  - TLS handshake detection (`-H`)
  - Compact mode (`-c`)
  - Body display (`-b`)
  - Debug/hexdump mode (`-d`, `-x`)

- **Build System**
  - Auto-detection of Linux distribution
  - Auto-detection of optional libraries (zstd, brotli)
  - `make deps` for dependency installation
  - `make release` for optimized builds

### File Signatures Supported
Images: JPEG, PNG, GIF87/89, WebP, BMP, ICO, AVIF, HEIC
Video: MP4, MOV, WebM, AVI, M4V, QuickTime
Audio: MP3, OGG, FLAC, WAV, M4A
Archives: ZIP, GZIP, ZSTD, 7-Zip, RAR, XZ, BZ2
Documents: PDF
Fonts: WOFF, WOFF2, TTF, OTF
Binary: WebAssembly, ELF, Mach-O, Java class, SQLite

### Known Limitations
- HPACK dynamic table not maintained (static table only)
- HTTP/2 CONTINUATION frames have basic support only
- NSS captures all NSPR I/O (includes non-HTTP traffic)
- Requires kernel 5.x+ with BTF support

---

## Version Numbering

This project uses semantic versioning: MAJOR.MINOR.PATCH

- MAJOR: Incompatible changes
- MINOR: New features, backward compatible
- PATCH: Bug fixes, backward compatible
