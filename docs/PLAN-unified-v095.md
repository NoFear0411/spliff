# Unified Implementation Plan: Golden Thread + C23 Optimizations (v0.9.5)

## Overview

This plan combines the Golden Thread protocol detection fix with modern C23
performance optimizations. All new code will be written with optimizations
built-in from the start.

**Version Target**: v0.9.5 "Golden Thread"

---

## Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| Protocol Detector Module | ✅ COMPLETE | `src/protocol/detector.c/h` created |
| Modular HTTP/1 Entry Point | ✅ COMPLETE | `http1_try_process_event()` |
| Modular HTTP/2 Entry Point | ✅ COMPLETE | `http2_try_process_event()` |
| main.c Simplification | ✅ COMPLETE | ~190 lines moved to protocol modules |
| Dispatcher ALPN Handling | ✅ COMPLETE | Already uses socket_cookie correlation |
| CMakeLists.txt Updates | ✅ COMPLETE | Vectorscan/zlib-ng options added |
| C23 Structure Alignment | 🔄 PARTIAL | Some alignments in place |

### Phase 5.5 Completion Summary (v0.9.5)

The modular protocol architecture refactoring is complete:

```
main.c (orchestration only)
    │
    ├── http1_try_process_event() ──► http1.c (all HTTP/1 logic)
    │       │
    │       └── Detection, parser init, flow-based parsing
    │
    ├── http2_try_process_event() ──► http2.c (all HTTP/2 logic)
    │       │
    │       └── Preface, mid-connection, session mgmt, noise suppression
    │
    └── Fallback: vectorscan detection, raw display
```

**Files Changed:**
- `src/protocol/detector.c/h` - NEW: Vectorscan protocol detection
- `src/protocol/http1.c/h` - Added unified entry point
- `src/protocol/http2.c/h` - Added unified entry point
- `src/main.c` - Simplified to orchestration (~190 lines removed)

---

## Architecture: Vectorscan-Powered Protocol Detection

Instead of manual `http1_is_request()` / `http2_is_preface()` checks scattered
throughout the codebase, we'll use **vectorscan** for unified, high-performance
protocol detection.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Unified Protocol Detection Pipeline                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                    │
│   │ BPF Layer   │    │ Dispatcher  │    │ Worker      │                    │
│   │             │    │             │    │             │                    │
│   │ ALPN Probe ─┼───▶│ Store ALPN  │    │             │                    │
│   │ (uprobe)    │    │ in flow_ctx │    │             │                    │
│   │             │    │             │    │             │                    │
│   │ XDP Packet ─┼───▶│ Lookup/     │───▶│ Check proto │                    │
│   │             │    │ Create flow │    │             │                    │
│   │             │    │             │    │ if UNKNOWN: │                    │
│   │ SSL Data ───┼───▶│ Attach      │───▶│   vectorscan│                    │
│   │ (uprobe)    │    │ flow_ctx    │    │   detect()  │                    │
│   └─────────────┘    └─────────────┘    └──────┬──────┘                    │
│                                                │                            │
│                                                ▼                            │
│                                    ┌─────────────────────┐                  │
│                                    │ Vectorscan Patterns │                  │
│                                    ├─────────────────────┤                  │
│                                    │ ID 0: HTTP/1.x RSP  │                  │
│                                    │ ID 1: HTTP/1.x REQ  │                  │
│                                    │ ID 2: HTTP/2 Preface│                  │
│                                    │ ID 3: TLS Record    │                  │
│                                    │ ID 4: WebSocket     │                  │
│                                    └─────────────────────┘                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Components

### Component 1: Protocol Detector Module (NEW)

**File**: `src/protocol/detector.h` / `detector.c`

A new unified protocol detection module using vectorscan.

```c
/* src/protocol/detector.h */
#ifndef PROTOCOL_DETECTOR_H
#define PROTOCOL_DETECTOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "../correlation/flow_context.h"

/**
 * @brief Protocol detection result
 *
 * Detected via vectorscan pattern matching for O(n) linear time.
 */
typedef enum {
    PROTO_DETECT_UNKNOWN    = 0,
    PROTO_DETECT_HTTP1_REQ  = 1,  /* HTTP/1.x request (GET, POST, etc.) */
    PROTO_DETECT_HTTP1_RSP  = 2,  /* HTTP/1.x response (HTTP/1.x 200) */
    PROTO_DETECT_HTTP2      = 3,  /* HTTP/2 preface or frame */
    PROTO_DETECT_TLS        = 4,  /* TLS record (encrypted) */
    PROTO_DETECT_WEBSOCKET  = 5,  /* WebSocket frame */
} proto_detect_result_t;

/**
 * @brief Initialize protocol detector
 *
 * Compiles vectorscan patterns. Call once at startup.
 * Thread-safe after initialization.
 *
 * @return 0 on success, -1 on failure
 */
int proto_detector_init(void);

/**
 * @brief Cleanup protocol detector
 *
 * Frees vectorscan database and scratch space.
 */
void proto_detector_cleanup(void);

/**
 * @brief Detect protocol from packet data
 *
 * Uses vectorscan for O(n) linear-time pattern matching.
 *
 * @param data    Packet payload
 * @param len     Payload length
 * @return Detection result
 *
 * @note This function is thread-safe (uses per-thread scratch)
 */
[[nodiscard]]
proto_detect_result_t proto_detect(const uint8_t *restrict data, size_t len);

/**
 * @brief Detect and initialize flow protocol
 *
 * Combines detection with flow_context initialization.
 * Sets flow->proto based on detection result.
 *
 * @param ctx     Flow context (may be NULL)
 * @param data    Packet payload
 * @param len     Payload length
 * @return Detected flow protocol type
 */
[[nodiscard]]
flow_proto_t proto_detect_and_init(flow_context_t *restrict ctx,
                                    const uint8_t *restrict data,
                                    size_t len);

/**
 * @brief Get per-thread scratch space
 *
 * Vectorscan requires per-thread scratch for thread safety.
 * Uses thread-local storage for automatic management.
 */
void *proto_get_scratch(void);

#endif /* PROTOCOL_DETECTOR_H */
```

```c
/* src/protocol/detector.c */
#include "detector.h"
#include <hs/hs.h>
#include <stdio.h>
#include <threads.h>  /* C23 thread-local storage */

/*============================================================================
 * Vectorscan Database (Global, Read-Only After Init)
 *============================================================================*/

static hs_database_t *g_proto_db = NULL;

/* Thread-local scratch space */
static thread_local hs_scratch_t *tls_scratch = NULL;

/*============================================================================
 * Pattern Definitions
 *============================================================================*/

/* Protocol detection patterns - compiled into NFA */
static const char *PROTO_PATTERNS[] = {
    /* ID 0: HTTP/1.x Response */
    "^HTTP/1\\.[01] [0-9]{3}",

    /* ID 1: HTTP/1.x Request (common methods) */
    "^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) [^ ]+ HTTP/1\\.[01]",

    /* ID 2: HTTP/2 Connection Preface */
    "^PRI \\* HTTP/2\\.0\r\n\r\nSM\r\n\r\n",

    /* ID 3: TLS Record (ContentType: Handshake=22, Application=23) */
    "^[\\x16\\x17]\\x03[\\x00-\\x03]",

    /* ID 4: WebSocket Frame (FIN + opcode, masked) */
    "^[\\x81\\x82\\x88\\x89\\x8a][\\x80-\\xff]",
};

static const unsigned int PROTO_PATTERN_IDS[] = {0, 1, 2, 3, 4};
static const unsigned int PROTO_PATTERN_FLAGS[] = {
    HS_FLAG_SINGLEMATCH,  /* Stop after first match */
    HS_FLAG_SINGLEMATCH,
    HS_FLAG_SINGLEMATCH,
    HS_FLAG_SINGLEMATCH,
    HS_FLAG_SINGLEMATCH,
};
static const size_t PROTO_PATTERN_COUNT = 5;

/*============================================================================
 * Match Callback
 *============================================================================*/

struct match_ctx {
    proto_detect_result_t result;
};

static int on_match(unsigned int id,
                    unsigned long long from [[maybe_unused]],
                    unsigned long long to [[maybe_unused]],
                    unsigned int flags [[maybe_unused]],
                    void *context) {
    struct match_ctx *ctx = context;

    /* Map pattern ID to detection result */
    switch (id) {
        case 0: ctx->result = PROTO_DETECT_HTTP1_RSP; break;
        case 1: ctx->result = PROTO_DETECT_HTTP1_REQ; break;
        case 2: ctx->result = PROTO_DETECT_HTTP2; break;
        case 3: ctx->result = PROTO_DETECT_TLS; break;
        case 4: ctx->result = PROTO_DETECT_WEBSOCKET; break;
        default: ctx->result = PROTO_DETECT_UNKNOWN; break;
    }

    return 1;  /* Stop scanning - we found a match */
}

/*============================================================================
 * Public API
 *============================================================================*/

int proto_detector_init(void) {
    hs_compile_error_t *error = NULL;

    hs_error_t ret = hs_compile_multi(
        PROTO_PATTERNS,
        PROTO_PATTERN_FLAGS,
        PROTO_PATTERN_IDS,
        PROTO_PATTERN_COUNT,
        HS_MODE_BLOCK,
        NULL,  /* Use default platform */
        &g_proto_db,
        &error
    );

    if (ret != HS_SUCCESS) {
        fprintf(stderr, "Protocol detector: pattern compile failed: %s\n",
                error ? error->message : "unknown error");
        hs_free_compile_error(error);
        return -1;
    }

    return 0;
}

void proto_detector_cleanup(void) {
    if (tls_scratch) {
        hs_free_scratch(tls_scratch);
        tls_scratch = NULL;
    }
    if (g_proto_db) {
        hs_free_database(g_proto_db);
        g_proto_db = NULL;
    }
}

void *proto_get_scratch(void) {
    if (!tls_scratch && g_proto_db) [[unlikely]] {
        hs_alloc_scratch(g_proto_db, &tls_scratch);
    }
    return tls_scratch;
}

proto_detect_result_t proto_detect(const uint8_t *restrict data, size_t len) {
    if (!g_proto_db || !data || len == 0) [[unlikely]] {
        return PROTO_DETECT_UNKNOWN;
    }

    hs_scratch_t *scratch = proto_get_scratch();
    if (!scratch) [[unlikely]] {
        return PROTO_DETECT_UNKNOWN;
    }

    struct match_ctx ctx = { .result = PROTO_DETECT_UNKNOWN };

    hs_scan(g_proto_db, (const char *)data, len, 0, scratch, on_match, &ctx);

    return ctx.result;
}

flow_proto_t proto_detect_and_init(flow_context_t *restrict ctx,
                                    const uint8_t *restrict data,
                                    size_t len) {
    if (!ctx) {
        return FLOW_PROTO_UNKNOWN;
    }

    /* Already detected - return cached value */
    if (ctx->proto != FLOW_PROTO_UNKNOWN) [[likely]] {
        return ctx->proto;
    }

    /* Run vectorscan detection */
    proto_detect_result_t result = proto_detect(data, len);

    /* Map to flow protocol */
    switch (result) {
        case PROTO_DETECT_HTTP1_REQ:
        case PROTO_DETECT_HTTP1_RSP:
            ctx->proto = FLOW_PROTO_HTTP1;
            break;

        case PROTO_DETECT_HTTP2:
            ctx->proto = FLOW_PROTO_HTTP2;
            break;

        case PROTO_DETECT_TLS:
        case PROTO_DETECT_WEBSOCKET:
        case PROTO_DETECT_UNKNOWN:
        default:
            ctx->proto = FLOW_PROTO_UNKNOWN;
            break;
    }

    return ctx->proto;
}
```

---

### Component 2: Updated Dispatcher (ALPN Handling)

**File**: `src/threading/dispatcher.c`

Fix ALPN event handling to use socket_cookie for correlation.

```c
/* In dispatch_ssl_event() - ALPN handling */

if (bpf_event->event_type == EVENT_ALPN) {
    flow_context_t *flow_ctx = NULL;
    flow_lookup_path_t path = FLOW_PATH_NONE;

    /*
     * ALPN events from uprobes always have socket_cookie
     * (via get_ssl_socket_cookie in BPF). Use it as primary key.
     */
    if (bpf_event->socket_cookie != 0) [[likely]] {
        /* Try cookie index first (fast path) */
        flow_ctx = flow_lookup_ex(&ctx->flow_mgr,
                                   bpf_event->socket_cookie,
                                   bpf_event->pid,
                                   bpf_event->ssl_ctx,
                                   &path);

        /* Create if not found - we have the golden thread (cookie) */
        if (!flow_ctx) {
            flow_ctx = flow_get_or_create(&ctx->flow_mgr,
                                          bpf_event->socket_cookie,
                                          bpf_event->pid,
                                          bpf_event->ssl_ctx);
            if (flow_ctx) {
                path = FLOW_PATH_CREATED;
            }
        }
    } else [[unlikely]] {
        /* Fallback: no cookie, use shadow index */
        flow_ctx = flow_get_or_create(&ctx->flow_mgr, 0,
                                      bpf_event->pid,
                                      bpf_event->ssl_ctx);
    }

    /* Store ALPN and initialize parser */
    if (flow_ctx && bpf_event->buf_filled > 0) {
        size_t alpn_len = (size_t)bpf_event->buf_filled;
        if (alpn_len > sizeof(flow_ctx->alpn) - 1) {
            alpn_len = sizeof(flow_ctx->alpn) - 1;
        }
        memcpy(flow_ctx->alpn, bpf_event->data, alpn_len);
        flow_ctx->alpn[alpn_len] = '\0';

        /* Initialize protocol parser based on ALPN */
        flow_init_parser(flow_ctx, flow_ctx->alpn);
        flow_ctx->flags |= FLOW_FLAG_HAS_SSL;

        if (ctx->debug_mode) {
            fprintf(stderr, "[DISPATCHER] ALPN '%s' stored in flow (path=%d)\n",
                    flow_ctx->alpn, path);
        }
    }

    /* Continue to dispatch event to worker for display */
}
```

---

### Component 3: Updated Worker (Content Detection Fallback)

**File**: `src/main.c`

Replace manual detection with vectorscan-powered `proto_detect_and_init()`.

```c
/* In process_worker_event() */

/* Handle ALPN - just display, dispatcher already stored it */
if (event->event_type == EVENT_ALPN) {
    if (event->flow_ctx && event->flow_ctx->alpn[0]) {
        output_write(worker, "%s[ALPN]%s %s PID %u (%s)\n",
                    display_color(C_CYAN), display_color(C_RESET),
                    event->flow_ctx->alpn,
                    event->pid, event->comm);
    }
    return;
}

if (event->data_len == 0) return;

const uint8_t *restrict data = event->data;
const size_t len = event->data_len;

/*
 * Protocol Detection: Vectorscan-Powered
 *
 * Priority:
 * 1. ALPN negotiation (already set by dispatcher if available)
 * 2. Content-based detection via vectorscan (fallback)
 */
if (event->flow_ctx) {
    if (event->flow_ctx->proto == FLOW_PROTO_UNKNOWN) [[unlikely]] {
        /* Content-based detection using vectorscan */
        proto_detect_and_init(event->flow_ctx, data, len);
    }

    /* Now route based on detected protocol */
    switch (event->flow_ctx->proto) {
        case FLOW_PROTO_HTTP1:
            /* Initialize parser if needed */
            if (!event->flow_ctx->parser.h1.initialized) [[unlikely]] {
                flow_h1_parser_init(event->flow_ctx, http1_get_settings());
            }

            /* Parse using flow-based parser */
            ssl_data_event_t bpf_event = {
                .timestamp_ns = event->timestamp_ns,
                .delta_ns = event->delta_ns,
                .pid = event->pid,
                .tid = event->tid,
                .uid = event->uid,
                .event_type = event->event_type,
                .buf_filled = (int32_t)len,
            };
            memcpy(bpf_event.comm, event->comm, TASK_COMM_LEN);

            if (http1_parse_flow(event->flow_ctx, data, len, &bpf_event) >= 0) {
                return;  /* Successfully parsed */
            }
            break;

        case FLOW_PROTO_HTTP2:
            /* HTTP/2 processing... */
            process_http2_flow(event, data, len);
            return;

        default:
            break;
    }
}

/* Fallback: raw display with content signature */
goto show_raw;
```

---

### Component 4: CMakeLists.txt Updates

```cmake
# ============================================================================
# Performance Options
# ============================================================================

option(USE_ZLIB_NG "Use zlib-ng instead of zlib (faster SIMD decompression)" ON)
option(USE_VECTORSCAN "Use vectorscan for protocol detection" ON)
option(USE_MIMALLOC "Use mimalloc instead of jemalloc" OFF)

# ============================================================================
# Compression Library
# ============================================================================

if(USE_ZLIB_NG)
    pkg_check_modules(ZLIB_NG IMPORTED_TARGET zlib-ng)
    if(ZLIB_NG_FOUND)
        message(STATUS "Using zlib-ng: ${ZLIB_NG_VERSION}")
        set(ZLIB_TARGET PkgConfig::ZLIB_NG)
        set(HAVE_ZLIB_NG TRUE)
    else()
        message(STATUS "zlib-ng not found, falling back to zlib")
        pkg_check_modules(ZLIB REQUIRED IMPORTED_TARGET zlib)
        set(ZLIB_TARGET PkgConfig::ZLIB)
    endif()
else()
    pkg_check_modules(ZLIB REQUIRED IMPORTED_TARGET zlib)
    set(ZLIB_TARGET PkgConfig::ZLIB)
endif()

# ============================================================================
# Pattern Matching Engine
# ============================================================================

if(USE_VECTORSCAN)
    # Try vectorscan first (portable Hyperscan fork)
    pkg_check_modules(VECTORSCAN IMPORTED_TARGET vectorscan)
    if(VECTORSCAN_FOUND)
        message(STATUS "Using vectorscan: ${VECTORSCAN_VERSION}")
        set(PATTERN_TARGET PkgConfig::VECTORSCAN)
        set(HAVE_VECTORSCAN TRUE)
    else()
        # Fallback to Intel Hyperscan
        pkg_check_modules(HYPERSCAN IMPORTED_TARGET hyperscan)
        if(HYPERSCAN_FOUND)
            message(STATUS "Using hyperscan: ${HYPERSCAN_VERSION}")
            set(PATTERN_TARGET PkgConfig::HYPERSCAN)
            set(HAVE_HYPERSCAN TRUE)
        else()
            message(WARNING "Neither vectorscan nor hyperscan found - using pcre2 fallback")
            pkg_check_modules(PCRE2 REQUIRED IMPORTED_TARGET libpcre2-8)
            set(PATTERN_TARGET PkgConfig::PCRE2)
            set(HAVE_PCRE2 TRUE)
        endif()
    endif()
else()
    pkg_check_modules(PCRE2 REQUIRED IMPORTED_TARGET libpcre2-8)
    set(PATTERN_TARGET PkgConfig::PCRE2)
    set(HAVE_PCRE2 TRUE)
endif()

# ============================================================================
# Source Files (Updated)
# ============================================================================

set(SPLIFF_SOURCES
    src/main.c
    src/util/safe_str.c
    src/content/signatures.c
    src/content/decompressor.c
    src/protocol/http1.c
    src/protocol/http2.c
    src/protocol/detector.c          # NEW: Vectorscan protocol detection
    src/bpf/bpf_loader.c
    src/bpf/binary_scanner.c
    src/bpf/probe_handler.c
    src/output/display.c
    src/correlation/flow_context.c
    src/threading/pool.c
    src/threading/state.c
    src/threading/worker.c
    src/threading/dispatcher.c
    src/threading/output.c
    src/threading/manager.c
)

# ============================================================================
# Link Libraries
# ============================================================================

target_link_libraries(spliff PRIVATE
    ${ZLIB_TARGET}           # zlib or zlib-ng
    ${PATTERN_TARGET}        # vectorscan, hyperscan, or pcre2
    # ... rest unchanged
)

# ============================================================================
# Compile Definitions
# ============================================================================

target_compile_definitions(spliff PRIVATE
    $<$<BOOL:${HAVE_ZLIB_NG}>:HAVE_ZLIB_NG>
    $<$<BOOL:${HAVE_VECTORSCAN}>:HAVE_VECTORSCAN>
    $<$<BOOL:${HAVE_HYPERSCAN}>:HAVE_HYPERSCAN>
    $<$<BOOL:${HAVE_PCRE2}>:HAVE_PCRE2>
    # ... rest unchanged
)
```

---

### Component 5: C23 Structure Updates

**File**: `src/correlation/flow_context.h`

```c
/* Add C23 headers */
#include <stdalign.h>
#include <stdatomic.h>

/**
 * @brief Unified Flow Context - The "Double View"
 *
 * Cache-line aligned for optimal performance.
 * Hot fields grouped in first cache line.
 */
typedef struct flow_context {
    /*=== HOT PATH - Cache Line 1 (64 bytes) ===*/
    alignas(64) uint64_t socket_cookie;     /* Primary key */
    uint64_t last_seen_ns;                  /* For timeout */
    _Atomic uint32_t home_worker_id;        /* Sticky affinity */
    uint32_t pid;
    flow_proto_t proto;                     /* Detected protocol */
    flow_state_t state;
    uint8_t flags;
    uint8_t xdp_category;
    uint8_t _pad_hot[6];                    /* Pad to 64 bytes */

    /*=== WARM PATH - Cache Line 2 (64 bytes) ===*/
    alignas(64) uint64_t ssl_ctx;
    uint64_t first_seen_ns;
    flow_id_t self_id;
    uint32_t ifindex;
    uint32_t uid;
    uint32_t pkts_in;
    uint32_t pkts_out;
    uint32_t bytes_in;
    uint32_t bytes_out;
    uint8_t _pad_warm[8];

    /*=== COLD PATH - Remaining fields ===*/
    alignas(64) flow_key_t flow;            /* 5-tuple */
    char comm[16];
    char alpn[16];
    char ifname[16];

    /*=== Parser Union ===*/
    union {
        h1_parser_ctx_t h1;
        h2_parser_ctx_t h2;
    } parser;

    /*=== Body Assembly ===*/
    body_ctx_t body;

    /*=== State ===*/
    _Atomic bool active;

} flow_context_t;

/* Verify cache line alignment */
_Static_assert(offsetof(flow_context_t, ssl_ctx) == 64,
               "Warm path must start at cache line 2");
_Static_assert(offsetof(flow_context_t, flow) == 128,
               "Cold path must start at cache line 3");
```

**File**: `src/threading/threading.h`

```c
/**
 * @brief Per-worker context
 *
 * Cache-line aligned to prevent false sharing between workers.
 */
typedef struct alignas(64) worker_context {
    /*=== HOT PATH - Frequently accessed ===*/
    alignas(64) ck_ring_t in_ring;
    ck_ring_buffer_t *in_buffer;
    _Atomic uint64_t events_processed;
    _Atomic uint64_t events_dropped;

    /*=== WARM PATH ===*/
    alignas(64) ck_ring_t out_ring;
    ck_ring_buffer_t *out_buffer;
    int wakeup_fd;
    int epoll_fd;
    int worker_id;

    /*=== COLD PATH ===*/
    alignas(64) worker_state_t *state;
    pthread_t thread;
    _Atomic bool running;
    _Atomic bool should_stop;

} worker_context_t;
```

---

## Files Summary

| File | Action | Description |
|------|--------|-------------|
| `src/protocol/detector.h` | CREATE | Vectorscan protocol detection API |
| `src/protocol/detector.c` | CREATE | Vectorscan implementation |
| `src/threading/dispatcher.c` | MODIFY | ALPN handling with socket_cookie |
| `src/main.c` | MODIFY | Use proto_detect_and_init() |
| `src/correlation/flow_context.h` | MODIFY | Cache-line alignment |
| `src/threading/threading.h` | MODIFY | Worker struct alignment |
| `CMakeLists.txt` | MODIFY | Add vectorscan/zlib-ng options |

---

## Build & Test

### Install Dependencies

```bash
# Fedora
sudo dnf install vectorscan-devel zlib-ng-devel

# Ubuntu/Debian (may need to build vectorscan from source)
sudo apt install zlib1g-ng-dev
git clone https://github.com/VectorCamp/vectorscan
cd vectorscan && cmake -B build && sudo cmake --install build

# Verify
pkg-config --modversion vectorscan
pkg-config --modversion zlib-ng
```

### Build

```bash
# Clean build with new options
rm -rf build-release
cmake -B build-release -DCMAKE_BUILD_TYPE=Release \
      -DUSE_VECTORSCAN=ON -DUSE_ZLIB_NG=ON
cmake --build build-release -j$(nproc)
```

### Test

```bash
# Test 1: ALPN-based detection
curl -v https://httpbin.org/get
./build-release/spliff -d | grep -E "ALPN|HTTP"

# Test 2: Content-based fallback (comment out ALPN probes temporarily)
# Should still detect HTTP via vectorscan

# Test 3: Performance
hyperfine './build-release/spliff -d &; sleep 2; pkill spliff'
```

---

## Migration Path

### If Vectorscan Not Available

The code gracefully falls back:

```c
#ifdef HAVE_VECTORSCAN
    #include <hs/hs.h>
    // Use vectorscan
#elif defined(HAVE_HYPERSCAN)
    #include <hs/hs.h>
    // Use hyperscan (same API)
#else
    // Fallback to manual detection (existing http1_is_request, etc.)
    flow_proto_t proto_detect_and_init(flow_context_t *ctx,
                                        const uint8_t *data, size_t len) {
        if (http1_is_request(data, len) || http1_is_response(data, len)) {
            ctx->proto = FLOW_PROTO_HTTP1;
        } else if (http2_is_preface(data, len)) {
            ctx->proto = FLOW_PROTO_HTTP2;
        }
        return ctx->proto;
    }
#endif
```

---

## Success Criteria

1. **100% Protocol Detection**: Every HTTP flow detected (ALPN or content)
2. **O(n) Pattern Matching**: Vectorscan provides linear-time detection
3. **Cache-Optimal**: Hot fields in first cache line
4. **Zero False Sharing**: Workers don't contend on same cache lines
5. **Backward Compatible**: Falls back gracefully without vectorscan

---

## Next Phases (Beyond v0.9.5)

### Phase 6: BPF/XDP Improvements (v0.10.0)

- Complete IPv6 socket correlation (expand flow_key to 128-bit)
- Expand ring buffer sizes (ssl_events: 1MB, xdp_events: 2MB)
- Atomic state machine with guard for race prevention
- Per-CPU LRU accounting with `BPF_F_NO_COMMON_LRU`
- Split flow_state into hot/cold paths
- Exponential backoff in cookie retry
- Cache-line alignment for hot structures

### Phase 7: HTTP/3 + QUIC Support (v0.11.0)

- QUIC protocol detection in XDP
- QUIC session tracking with ngtcp2
- HTTP/3 frame parsing with nghttp3
- `quic_try_process_event()` unified entry point
