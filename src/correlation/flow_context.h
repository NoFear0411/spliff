/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * flow_context.h - Shared Pool Architecture for XDP-SSL Correlation
 *
 * This module implements the "Shared Pool with Dual Index" architecture,
 * the gold standard for eBPF-based observability. Key principles:
 *
 *   1. SINGLE SOURCE OF TRUTH: All flow data lives in one pre-allocated pool
 *   2. DUAL INDEXING: Two indexes point to the same pool entries
 *      - cookie_index: socket_cookie → flow_id (primary, fast path)
 *      - shadow_index: (pid, ssl_ctx) → flow_id (fallback for early events)
 *   3. ZERO-COPY: Data never moves, only 4-byte index entries change
 *   4. ATOMIC HANDOVER: Cookie promotion is a single index insertion
 *
 * @see docs/SHARED_POOL_ARCHITECTURE.md for full design documentation
 */

#ifndef FLOW_CONTEXT_H
#define FLOW_CONTEXT_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <llhttp.h>
#include <nghttp2/nghttp2.h>
#include "../include/spliff.h"

/*============================================================================
 * Constants and Configuration
 *============================================================================*/

/**
 * @defgroup flow_config Flow Context Configuration
 * @brief Compile-time configuration for the shared pool
 * @{
 */

/** Maximum concurrent flows (power of 2 for efficient hashing) */
#define FLOW_POOL_CAPACITY      8192

/** Flow timeout in nanoseconds (60 seconds) */
#define FLOW_TIMEOUT_NS         (60ULL * 1000000000ULL)

/** Number of 64-bit words in the free bitmap */
#define FLOW_BITMAP_WORDS       (FLOW_POOL_CAPACITY / 64)

/** Index load factor - resize when 75% full (not implemented, fixed size) */
#define INDEX_LOAD_FACTOR       0.75

/** @} */

/*============================================================================
 * Core Types
 *============================================================================*/

/**
 * @defgroup flow_types Flow Context Types
 * @brief Core type definitions for the shared pool
 * @{
 */

/**
 * @brief Flow identifier - index into the pool
 *
 * Using a 32-bit ID instead of a pointer provides:
 * - Smaller index entries (4 bytes vs 8 bytes)
 * - Bounds checking capability
 * - Same pattern as eBPF map values
 */
typedef uint32_t flow_id_t;

/** Invalid flow ID sentinel value */
#define FLOW_ID_INVALID         UINT32_MAX

/**
 * @brief Protocol type for parser selection
 */
typedef enum {
    FLOW_PROTO_UNKNOWN = 0,     /**< Not yet determined */
    FLOW_PROTO_HTTP1   = 1,     /**< HTTP/1.x - use llhttp */
    FLOW_PROTO_HTTP2   = 2,     /**< HTTP/2 - use nghttp2 */
    FLOW_PROTO_OTHER   = 3      /**< Other (not parsed) */
} flow_proto_t;

/**
 * @brief Flow lifecycle state
 */
typedef enum {
    FLOW_STATE_INIT     = 0,    /**< Slot allocated, minimal data */
    FLOW_STATE_ACTIVE   = 1,    /**< Both XDP and SSL data present */
    FLOW_STATE_CLOSING  = 2,    /**< FIN/RST seen, draining */
    FLOW_STATE_CLOSED   = 3     /**< Ready for cleanup */
} flow_state_t;

/** @} */

/*============================================================================
 * Transaction/Stream Architecture (Phase 3.6)
 *============================================================================*/

/**
 * @defgroup flow_transaction Transaction Types
 * @brief Per-stream/request state for HTTP/1 and HTTP/2
 * @{
 */

/** Maximum concurrent streams per HTTP/2 connection */
#define FLOW_MAX_H2_STREAMS     64

/** Stream timeout in milliseconds (10 seconds for ghost stream detection) */
#define FLOW_STREAM_TIMEOUT_MS  10000

/**
 * @brief Transaction state machine (RFC 7540 aligned for HTTP/2)
 *
 * States follow HTTP/2 stream lifecycle but apply to HTTP/1 transactions too.
 * For HTTP/1, only IDLE → OPEN → CLOSED path is typical (no half-closed).
 */
typedef enum {
    TXN_STATE_IDLE            = 0,  /**< Stream ID reserved, no frames sent */
    TXN_STATE_OPEN            = 1,  /**< Headers received, data may follow */
    TXN_STATE_HALF_CLOSED_LOCAL  = 2,  /**< We sent END_STREAM (response done) */
    TXN_STATE_HALF_CLOSED_REMOTE = 3,  /**< Peer sent END_STREAM (request done) */
    TXN_STATE_CLOSED          = 4,  /**< Both sides done, can be reaped */
    TXN_STATE_RESET           = 5,  /**< RST_STREAM received, aborted */
    TXN_STATE_ERROR           = 6   /**< Protocol error, connection may be dead */
} txn_state_t;

/**
 * @brief Transaction flags (bitfield)
 */
enum txn_flags {
    TXN_FLAG_REQ_END_STREAM   = (1 << 0),  /**< Request END_STREAM seen */
    TXN_FLAG_RSP_END_STREAM   = (1 << 1),  /**< Response END_STREAM seen */
    TXN_FLAG_HAS_BODY         = (1 << 2),  /**< Body data present */
    TXN_FLAG_BODY_ALLOCATED   = (1 << 3),  /**< body_buf dynamically allocated */
    TXN_FLAG_DISPLAYED        = (1 << 4),  /**< Already printed to output */
    TXN_FLAG_CHUNKED          = (1 << 5),  /**< Transfer-Encoding: chunked */
    TXN_FLAG_COMPRESSED       = (1 << 6),  /**< Content-Encoding present */
    TXN_FLAG_KEEP_ALIVE       = (1 << 7),  /**< HTTP/1.1 Connection: keep-alive */
    TXN_FLAG_REQ_HEADERS_DONE = (1 << 8),  /**< Request headers displayed */
    TXN_FLAG_RSP_HEADERS_DONE = (1 << 9)   /**< Response headers displayed */
};

/**
 * @brief Per-transaction/stream context
 *
 * Unified structure for both HTTP/1 requests and HTTP/2 streams.
 * For HTTP/1, there's typically one active transaction at a time.
 * For HTTP/2, multiple streams can be multiplexed.
 *
 * @par Memory Management
 * - Transactions are allocated from fixed-size arrays (no malloc per stream)
 * - Body buffers are allocated dynamically only when -b option is enabled
 * - Free list for O(1) allocation using next_free
 *
 * @par Ghost Stream Detection
 * - last_active_ms tracks last activity timestamp
 * - Streams idle longer than FLOW_STREAM_TIMEOUT_MS are candidates for reaping
 */
typedef struct flow_transaction {
    /*=== Stream Identity (12 bytes) ===*/
    int32_t stream_id;              /**< HTTP/2 stream ID or 0 for HTTP/1 */
    txn_state_t state;              /**< Current state */
    direction_t direction;          /**< DIR_REQUEST or DIR_RESPONSE */

    /*=== Flags and Timestamps (16 bytes) ===*/
    uint16_t flags;                 /**< TXN_FLAG_* bitfield */
    uint16_t _pad;                  /**< Alignment */
    uint32_t last_active_ms;        /**< Monotonic timestamp for timeout */
    uint64_t start_time_ns;         /**< Request start for latency calc */

    /*=== Request Info (144 bytes) ===*/
    char method[16];                /**< HTTP method (GET, POST, etc.) */
    char path[256];                 /**< Request path/URI */
    char host[128];                 /**< Host header value */

    /*=== Response Info (56 bytes) ===*/
    int status_code;                /**< HTTP status (200, 404, etc.) */
    size_t content_length;          /**< Content-Length or 0 if chunked */
    char content_type[64];          /**< Content-Type for body parsing */
    char encoding[32];              /**< Content-Encoding (gzip, br, etc.) */

    /*=== Body Buffer (dynamically allocated, 24 bytes) ===*/
    uint8_t *body_buf;              /**< Body data (NULL if not capturing) */
    size_t body_len;                /**< Current body length */
    size_t body_capacity;           /**< Allocated capacity */

    /*=== Free List (4 bytes) ===*/
    int32_t next_free;              /**< Index of next free slot (-1 = end) */
} flow_transaction_t;

/** @} */

/*============================================================================
 * Protocol Parser Contexts
 *============================================================================*/

/**
 * @defgroup flow_parsers Protocol Parser Structures
 * @brief Parser state embedded in flow_context_t
 * @{
 */

/**
 * @brief HTTP/1.x parser context
 *
 * Contains llhttp parser and settings. The parser is initialized
 * lazily when the first HTTP/1.x data arrives.
 *
 * @par Transaction Handling
 * HTTP/1.x is request-response sequential. current_txn points to the
 * active transaction. Pipelining is handled by completing one txn
 * before starting the next (state machine enforces this).
 */
typedef struct {
    llhttp_t parser;                /**< llhttp parser instance */
    llhttp_settings_t settings;     /**< Parser callback settings */
    bool initialized;               /**< true if parser is ready */

    /*=== Header Parsing State (persistent across TCP segments) ===*/
    char current_header_name[128];  /**< Header name being accumulated */
    size_t header_name_len;         /**< Current header name length */
    bool in_header_value;           /**< true if parsing header value */
    bool headers_complete;          /**< true when headers section done */
    bool message_complete;          /**< true when full message parsed */

    /*=== Last Request URL (for response display) ===*/
    char last_request_host[128];    /**< Host from last request */
    char last_request_path[256];    /**< Path from last request */
    char last_request_method[16];   /**< Method from last request */

    /*=== Transaction Support ===*/
    flow_transaction_t txn;         /**< Single transaction (HTTP/1 is sequential) */
} h1_parser_ctx_t;

/**
 * @brief HTTP/2 session context
 *
 * Contains nghttp2 session for request parsing and HPACK inflater
 * for response header decoding. Buffers are allocated lazily.
 *
 * @par Stream Management
 * Fixed-size array of FLOW_MAX_H2_STREAMS transactions. Uses free list
 * for O(1) allocation. Streams are indexed by hash(stream_id) with
 * linear probing for collision resolution.
 *
 * @par HPACK Error Handling (RFC 7540)
 * HPACK errors are connection-fatal. When hpack_corrupted is set:
 * - Stop feeding data to nghttp2 session
 * - Mark all streams as ERROR
 * - Continue receiving frames for cleanup only
 * nghttp2 does not support mid-stream HPACK recovery (unlike Go/Rust).
 */
typedef struct {
    struct nghttp2_session *session;        /**< nghttp2 server session */
    struct nghttp2_hd_inflater *inflater;   /**< HPACK decoder */
    uint8_t *reassembly_buf;                /**< Frame reassembly buffer */
    size_t reassembly_len;                  /**< Current buffer usage */
    size_t reassembly_capacity;             /**< Buffer capacity */
    bool preface_seen;                      /**< Client preface received */
    bool settings_seen;                     /**< Server SETTINGS received */

    /*=== Stream Pool (replaces global g_h2_streams) ===*/
    flow_transaction_t streams[FLOW_MAX_H2_STREAMS]; /**< Per-stream state */
    int32_t free_head;                      /**< Head of free list (-1 = full) */
    uint32_t active_count;                  /**< Number of active streams */

    /*=== HPACK State ===*/
    bool hpack_corrupted;                   /**< Connection-fatal HPACK error */

    /*=== Callback Context (Phase 3.6 migration) ===*/
    /**
     * @brief Opaque callback context for nghttp2
     *
     * Points to h2_callback_ctx_t (defined in http2.c).
     * Allocated by flow_h2_session_init() and freed by flow_free_resources().
     * This enables flow-based processing without global pool dependency.
     */
    void *callback_ctx;                     /**< Opaque nghttp2 callback context */
} h2_parser_ctx_t;

/**
 * @brief Response body assembly state
 *
 * Accumulates chunked or streaming response bodies for display.
 * Handles decompression of gzip/brotli/zstd content.
 */
typedef struct {
    uint8_t *buffer;                /**< Accumulation buffer */
    size_t len;                     /**< Current data length */
    size_t capacity;                /**< Allocated capacity */
    size_t expected;                /**< Content-Length (0 if chunked) */
    char content_type[128];         /**< Content-Type header */
    char encoding[32];              /**< Content-Encoding */
    bool needs_decompress;          /**< Requires decompression */
    bool header_printed;            /**< Headers already output */
} body_ctx_t;

/** @} */

/*============================================================================
 * Flow Context Structure
 *============================================================================*/

/**
 * @defgroup flow_context Flow Context
 * @brief The unified "Double View" structure
 * @{
 */

/**
 * @brief Unified Flow Context - The "Double View"
 *
 * This structure combines network metadata (from XDP) and application
 * state (from SSL uprobes) into a single, cache-aligned structure.
 *
 * @par Memory Layout
 * Aligned to 64 bytes for cache line optimization. Fields are ordered
 * to minimize padding and group frequently-accessed data together.
 *
 * @par Ownership
 * Each flow_context_t is owned by exactly one worker thread, determined
 * by: worker_id = socket_cookie % num_workers (or hash(pid,ssl_ctx) if
 * cookie unknown). This eliminates the need for locking.
 *
 * @par Lifecycle
 * 1. Allocated from pool when first event arrives
 * 2. Added to shadow_index immediately (always has pid+ssl_ctx)
 * 3. Added to cookie_index when socket_cookie becomes known
 * 4. Parser initialized when ALPN detected
 * 5. Freed on timeout or explicit termination
 */
typedef struct flow_context {
    /*=== Identity (32 bytes) ===*/
    uint64_t socket_cookie;         /**< Primary key (0 if unknown) */
    uint32_t pid;                   /**< Process ID */
    uint64_t ssl_ctx;               /**< SSL context pointer */
    flow_id_t self_id;              /**< Own index in pool (for debugging) */
    uint32_t _pad1;                 /**< Alignment padding */

    /*=== Network View - from XDP (48 bytes) ===*/
    flow_key_t flow;                /**< 5-tuple: IPs and ports (28 bytes) */
    uint32_t ifindex;               /**< Network interface index */
    uint64_t first_seen_ns;         /**< First packet timestamp */
    uint64_t last_seen_ns;          /**< Last activity timestamp */

    /*=== Traffic Counters (16 bytes) ===*/
    uint32_t pkts_in;               /**< Ingress packet count */
    uint32_t pkts_out;              /**< Egress packet count */
    uint32_t bytes_in;              /**< Ingress byte count */
    uint32_t bytes_out;             /**< Egress byte count */

    /*=== Application View - from SSL (48 bytes) ===*/
    char comm[16];                  /**< Process command name */
    char alpn[16];                  /**< ALPN result (h2, http/1.1) */
    char ifname[16];                /**< Interface name */

    /*=== State and Flags (8 bytes) ===*/
    flow_proto_t proto;             /**< Detected protocol */
    flow_state_t state;             /**< Lifecycle state */
    uint8_t xdp_category;           /**< XDP protocol category */
    uint8_t flags;                  /**< Bit flags (see below) */
    uint32_t uid;                   /**< User ID */

    /*=== Protocol Parser (union to save memory) ===*/
    union {
        h1_parser_ctx_t h1;         /**< HTTP/1.x context */
        h2_parser_ctx_t h2;         /**< HTTP/2 context */
    } parser;

    /*=== Body Assembly ===*/
    body_ctx_t body;                /**< Response body state */

    /*=== Thread Safety / Worker Affinity ===*/
    /**
     * @brief Slot active flag
     *
     * Set to true when slot is allocated, false when freed.
     * Uses acquire/release semantics for visibility across threads.
     */
    _Atomic bool active;

    /**
     * @brief Home worker ID for "Sticky" worker affinity
     *
     * Implements the "Hybrid Sticky" architecture for thread-safe access
     * without locking. The first worker to process an event for this flow
     * claims ownership via atomic CAS (Compare-And-Swap).
     *
     * @par Discovery Phase (Claim)
     * @code
     *   uint32_t expected = WORKER_ID_NONE;
     *   if (atomic_compare_exchange_strong(&ctx->home_worker_id, &expected, my_id)) {
     *       // I am now the home worker - initialize parser state
     *   }
     * @endcode
     *
     * @par Data Phase (Route)
     * @code
     *   if (atomic_load(&ctx->home_worker_id) == my_id) {
     *       // Direct path: process locally
     *   } else {
     *       // Forward to home worker via SPSC ring
     *   }
     * @endcode
     *
     * @par Benefits
     * - No mutex contention (single-writer guarantee)
     * - Cache-friendly (all flow state in one structure)
     * - Linear scaling with worker count
     *
     * @note Value is WORKER_ID_NONE (UINT32_MAX) until claimed
     */
    _Atomic uint32_t home_worker_id;

} __attribute__((aligned(64))) flow_context_t;

/**
 * @brief Sentinel value indicating no home worker assigned
 *
 * Used as initial value for home_worker_id. First worker to perform
 * successful CAS from WORKER_ID_NONE to their ID becomes the owner.
 */
#define WORKER_ID_NONE  UINT32_MAX

/**
 * @brief Flow context flags
 */
enum flow_flags {
    FLOW_FLAG_HAS_XDP     = (1 << 0),   /**< XDP data populated */
    FLOW_FLAG_HAS_SSL     = (1 << 1),   /**< SSL data populated */
    FLOW_FLAG_IN_COOKIE   = (1 << 2),   /**< In cookie_index */
    FLOW_FLAG_IN_SHADOW   = (1 << 3),   /**< In shadow_index */
    FLOW_FLAG_PARSER_INIT = (1 << 4)    /**< Parser initialized */
};

/** @} */

/*============================================================================
 * Index Structures
 *============================================================================*/

/**
 * @defgroup flow_indexes Index Structures
 * @brief Hash tables mapping keys to flow_id
 * @{
 */

/**
 * @brief Cookie index entry
 *
 * Maps socket_cookie to flow_id. Uses open addressing with
 * linear probing for collision resolution.
 */
typedef struct {
    uint64_t cookie;                /**< Socket cookie (key) */
    flow_id_t id;                   /**< Flow ID (value) */
    uint32_t _pad;                  /**< Alignment */
} cookie_entry_t;

/**
 * @brief Cookie index hash table
 *
 * Primary index for fast lookups when socket_cookie is known.
 * Most lookups should hit this index.
 */
typedef struct {
    cookie_entry_t *buckets;        /**< Hash table buckets */
    size_t capacity;                /**< Number of buckets */
    _Atomic uint64_t count;         /**< Active entries */
    _Atomic uint64_t hits;          /**< Successful lookups */
    _Atomic uint64_t misses;        /**< Failed lookups */
} cookie_index_t;

/**
 * @brief Shadow index entry
 *
 * Maps (pid, ssl_ctx) pair to flow_id. Used as fallback when
 * socket_cookie is not yet known.
 */
typedef struct {
    uint32_t pid;                   /**< Process ID (key part 1) */
    uint64_t ssl_ctx;               /**< SSL context (key part 2) */
    flow_id_t id;                   /**< Flow ID (value) */
} shadow_entry_t;

/**
 * @brief Shadow index hash table
 *
 * Fallback index for early SSL events before socket_cookie is known.
 * Every flow has an entry here; not all flows are in cookie_index.
 */
typedef struct {
    shadow_entry_t *buckets;        /**< Hash table buckets */
    size_t capacity;                /**< Number of buckets */
    _Atomic uint64_t count;         /**< Active entries */
    _Atomic uint64_t hits;          /**< Successful lookups */
    _Atomic uint64_t promotions;    /**< Flows promoted to cookie_index */
} shadow_index_t;

/** @} */

/*============================================================================
 * Flow Pool Structure
 *============================================================================*/

/**
 * @defgroup flow_pool Flow Pool
 * @brief Pre-allocated pool of flow contexts
 * @{
 */

/**
 * @brief Flow context pool - the single source of truth
 *
 * All flow_context_t instances live in this pre-allocated array.
 * The indexes (cookie_index, shadow_index) store flow_id values
 * that index into this pool.
 *
 * @par Allocation Strategy
 * Uses a bitmap for O(1) free slot finding via __builtin_ctzll().
 * Each bit represents one slot: 1 = free, 0 = allocated.
 *
 * @par Thread Safety
 * Pool allocation/deallocation must be done by a single thread
 * (the dispatcher). Workers only read/write existing slots.
 */
typedef struct {
    flow_context_t *slots;              /**< Pre-allocated context array */
    size_t capacity;                    /**< Total number of slots */
    uint64_t free_bitmap[FLOW_BITMAP_WORDS]; /**< 1=free, 0=used */
    _Atomic uint64_t allocated;         /**< Currently allocated count */
    _Atomic uint64_t peak;              /**< Peak allocation (high water) */
    _Atomic uint64_t total_allocs;      /**< Total allocations */
    _Atomic uint64_t total_frees;       /**< Total frees */
} flow_pool_t;

/** @} */

/*============================================================================
 * Flow Manager Structure
 *============================================================================*/

/**
 * @defgroup flow_manager Flow Manager
 * @brief Top-level container for pool and indexes
 * @{
 */

/**
 * @brief Flow manager - unified access to pool and indexes
 *
 * This structure groups the pool and both indexes together for
 * convenient parameter passing. Typically embedded in dispatcher_ctx_t.
 */
typedef struct {
    flow_pool_t pool;               /**< The flow context pool */
    cookie_index_t cookie_idx;      /**< Primary index by cookie */
    shadow_index_t shadow_idx;      /**< Fallback index by (pid,ssl_ctx) */
} flow_manager_t;

/** @} */

/*============================================================================
 * Pool Operations
 *============================================================================*/

/**
 * @defgroup flow_pool_ops Pool Operations
 * @brief Allocation and deallocation from the pool
 * @{
 */

/**
 * @brief Initialize the flow pool
 *
 * Allocates the slot array and initializes the free bitmap.
 * All slots start as free (bitmap bits = 1).
 *
 * @param pool      Pool to initialize
 * @param capacity  Number of slots (should be FLOW_POOL_CAPACITY)
 * @return 0 on success, -1 on allocation failure
 */
int flow_pool_init(flow_pool_t *pool, size_t capacity);

/**
 * @brief Cleanup the flow pool
 *
 * Frees parser resources for all active slots, then frees the array.
 *
 * @param pool  Pool to cleanup
 */
void flow_pool_cleanup(flow_pool_t *pool);

/**
 * @brief Allocate a slot from the pool
 *
 * Finds a free slot using the bitmap (O(1) with __builtin_ctzll).
 * Initializes the slot to zeroed state with self_id set.
 *
 * @param pool  The flow pool
 * @return flow_id of allocated slot, or FLOW_ID_INVALID if full
 */
flow_id_t flow_pool_alloc(flow_pool_t *pool);

/**
 * @brief Free a slot back to the pool
 *
 * Frees any parser resources, marks slot inactive, updates bitmap.
 *
 * @param pool  The flow pool
 * @param id    The flow_id to free
 */
void flow_pool_free(flow_pool_t *pool, flow_id_t id);

/**
 * @brief Get pointer to flow context by ID
 *
 * Performs bounds checking before returning pointer.
 *
 * @param pool  The flow pool
 * @param id    The flow_id
 * @return Pointer to flow_context_t, or NULL if invalid ID
 */
static inline flow_context_t *flow_pool_get(flow_pool_t *pool, flow_id_t id) {
    if (!pool || !pool->slots || id >= pool->capacity) {
        return NULL;
    }
    return &pool->slots[id];
}

/** @} */

/*============================================================================
 * Index Operations
 *============================================================================*/

/**
 * @defgroup flow_index_ops Index Operations
 * @brief Hash table operations for both indexes
 * @{
 */

/**
 * @brief Initialize cookie index
 *
 * @param idx       Index to initialize
 * @param capacity  Number of buckets
 * @return 0 on success, -1 on failure
 */
int cookie_index_init(cookie_index_t *idx, size_t capacity);

/**
 * @brief Cleanup cookie index
 *
 * @param idx  Index to cleanup
 */
void cookie_index_cleanup(cookie_index_t *idx);

/**
 * @brief Insert into cookie index
 *
 * @param idx     The index
 * @param cookie  Socket cookie (key)
 * @param id      Flow ID (value)
 * @return 0 on success, -1 if full
 */
int cookie_index_insert(cookie_index_t *idx, uint64_t cookie, flow_id_t id);

/**
 * @brief Lookup in cookie index
 *
 * @param idx     The index
 * @param cookie  Socket cookie to find
 * @return flow_id, or FLOW_ID_INVALID if not found
 */
flow_id_t cookie_index_lookup(cookie_index_t *idx, uint64_t cookie);

/**
 * @brief Remove from cookie index
 *
 * @param idx     The index
 * @param cookie  Socket cookie to remove
 */
void cookie_index_remove(cookie_index_t *idx, uint64_t cookie);

/**
 * @brief Initialize shadow index
 *
 * @param idx       Index to initialize
 * @param capacity  Number of buckets
 * @return 0 on success, -1 on failure
 */
int shadow_index_init(shadow_index_t *idx, size_t capacity);

/**
 * @brief Cleanup shadow index
 *
 * @param idx  Index to cleanup
 */
void shadow_index_cleanup(shadow_index_t *idx);

/**
 * @brief Insert into shadow index
 *
 * @param idx      The index
 * @param pid      Process ID (key part 1)
 * @param ssl_ctx  SSL context (key part 2)
 * @param id       Flow ID (value)
 * @return 0 on success, -1 if full
 */
int shadow_index_insert(shadow_index_t *idx, uint32_t pid,
                        uint64_t ssl_ctx, flow_id_t id);

/**
 * @brief Lookup in shadow index
 *
 * @param idx      The index
 * @param pid      Process ID
 * @param ssl_ctx  SSL context
 * @return flow_id, or FLOW_ID_INVALID if not found
 */
flow_id_t shadow_index_lookup(shadow_index_t *idx, uint32_t pid,
                              uint64_t ssl_ctx);

/**
 * @brief Remove from shadow index
 *
 * @param idx      The index
 * @param pid      Process ID
 * @param ssl_ctx  SSL context
 */
void shadow_index_remove(shadow_index_t *idx, uint32_t pid, uint64_t ssl_ctx);

/** @} */

/*============================================================================
 * Flow Manager Operations
 *============================================================================*/

/**
 * @defgroup flow_mgr_ops Flow Manager Operations
 * @brief High-level operations on the flow manager
 * @{
 */

/**
 * @brief Initialize flow manager
 *
 * Initializes pool and both indexes.
 *
 * @param mgr  Manager to initialize
 * @return 0 on success, -1 on failure
 */
int flow_manager_init(flow_manager_t *mgr);

/**
 * @brief Cleanup flow manager
 *
 * Cleans up pool and both indexes.
 *
 * @param mgr  Manager to cleanup
 */
void flow_manager_cleanup(flow_manager_t *mgr);

/**
 * @brief Correlation path used for flow lookup
 *
 * Indicates which index was used to find the flow.
 * Used for debugging and statistics.
 */
typedef enum {
    FLOW_PATH_NONE     = 0,  /**< Flow not found */
    FLOW_PATH_COOKIE   = 1,  /**< Found via cookie_index (fast path) */
    FLOW_PATH_SHADOW   = 2,  /**< Found via shadow_index (fallback) */
    FLOW_PATH_CREATED  = 3   /**< Newly created */
} flow_lookup_path_t;

/**
 * @brief Unified flow lookup
 *
 * Tries cookie_index first (fast path), falls back to shadow_index.
 *
 * @param mgr      Flow manager
 * @param cookie   Socket cookie (0 if unknown)
 * @param pid      Process ID
 * @param ssl_ctx  SSL context
 * @return Pointer to flow_context_t, or NULL if not found
 */
flow_context_t *flow_lookup(flow_manager_t *mgr, uint64_t cookie,
                            uint32_t pid, uint64_t ssl_ctx);

/**
 * @brief Extended flow lookup with path information
 *
 * Same as flow_lookup() but also returns which index was used.
 * Useful for debugging and monitoring correlation efficiency.
 *
 * @param mgr      Flow manager
 * @param cookie   Socket cookie (0 if unknown)
 * @param pid      Process ID
 * @param ssl_ctx  SSL context
 * @param path_out Output: which lookup path was used (may be NULL)
 * @return Pointer to flow_context_t, or NULL if not found
 */
flow_context_t *flow_lookup_ex(flow_manager_t *mgr, uint64_t cookie,
                               uint32_t pid, uint64_t ssl_ctx,
                               flow_lookup_path_t *path_out);

/**
 * @brief Get or create flow context
 *
 * If flow exists, returns it. Otherwise allocates new slot,
 * initializes with provided keys, and adds to shadow_index.
 * If cookie != 0, also adds to cookie_index.
 *
 * @param mgr      Flow manager
 * @param cookie   Socket cookie (0 if unknown)
 * @param pid      Process ID
 * @param ssl_ctx  SSL context
 * @return Pointer to flow_context_t, or NULL if pool full
 */
flow_context_t *flow_get_or_create(flow_manager_t *mgr, uint64_t cookie,
                                    uint32_t pid, uint64_t ssl_ctx);

/**
 * @brief Promote flow to cookie index
 *
 * Called when socket_cookie becomes available for a flow that was
 * created with cookie=0. Updates the flow's socket_cookie field
 * and adds entry to cookie_index.
 *
 * @param mgr      Flow manager
 * @param pid      Process ID (to find flow)
 * @param ssl_ctx  SSL context (to find flow)
 * @param cookie   Newly available socket cookie
 * @return 0 on success, -1 if flow not found
 */
int flow_promote_cookie(flow_manager_t *mgr, uint32_t pid,
                        uint64_t ssl_ctx, uint64_t cookie);

/**
 * @brief Terminate and free a flow
 *
 * Removes from both indexes, frees resources, returns slot to pool.
 *
 * @param mgr  Flow manager
 * @param ctx  Flow context to terminate
 */
void flow_terminate(flow_manager_t *mgr, flow_context_t *ctx);

/**
 * @brief Evict stale flows
 *
 * Scans pool for flows older than timeout and frees them.
 *
 * @param mgr         Flow manager
 * @param current_ns  Current timestamp
 * @return Number of flows evicted
 */
int flow_evict_stale(flow_manager_t *mgr, uint64_t current_ns);

/**
 * @brief Pool statistics snapshot
 *
 * Read-only snapshot of pool and index statistics for monitoring
 * and debugging. All values are captured atomically.
 */
typedef struct {
    /* Pool statistics */
    uint64_t pool_capacity;         /**< Total pool slots */
    uint64_t pool_allocated;        /**< Currently allocated flows */
    uint64_t pool_peak;             /**< Peak allocation (high water) */
    uint64_t pool_total_allocs;     /**< Lifetime allocations */
    uint64_t pool_total_frees;      /**< Lifetime frees */

    /* Cookie index statistics */
    uint64_t cookie_count;          /**< Entries in cookie index */
    uint64_t cookie_hits;           /**< Successful cookie lookups */
    uint64_t cookie_misses;         /**< Failed cookie lookups */

    /* Shadow index statistics */
    uint64_t shadow_count;          /**< Entries in shadow index */
    uint64_t shadow_hits;           /**< Successful shadow lookups */
    uint64_t shadow_promotions;     /**< Flows promoted to cookie index */
} flow_pool_stats_t;

/**
 * @brief Get pool statistics snapshot
 *
 * Captures a consistent snapshot of all pool and index statistics.
 * Uses atomic loads for thread-safety.
 *
 * @param mgr    Flow manager
 * @param stats  Output structure to fill
 */
void flow_manager_get_stats(flow_manager_t *mgr, flow_pool_stats_t *stats);

/**
 * @brief Print pool statistics to stderr
 *
 * Displays human-readable pool statistics for debugging and monitoring.
 * Called from threading_print_stats() on shutdown.
 *
 * @param mgr          Flow manager
 * @param debug_mode   If true, show detailed breakdown
 */
void flow_manager_print_stats(flow_manager_t *mgr, bool debug_mode);

/** @} */

/*============================================================================
 * Flow Context Helpers
 *============================================================================*/

/**
 * @defgroup flow_helpers Flow Context Helpers
 * @brief Utility functions for flow_context_t
 * @{
 */

/**
 * @brief Update flow with XDP packet metadata
 *
 * @param ctx  Flow context
 * @param evt  XDP packet event
 */
void flow_update_xdp(flow_context_t *ctx, const xdp_packet_event_t *evt);

/**
 * @brief Initialize protocol parser based on ALPN
 *
 * Sets up parser type (HTTP/1 or HTTP/2) based on negotiated protocol.
 * For HTTP/2, only marks the proto type - call flow_h2_session_init()
 * separately to create the nghttp2 session (done by home worker).
 *
 * @param ctx   Flow context
 * @param alpn  ALPN string ("h2", "http/1.1", etc.)
 * @return 0 on success, -1 on failure
 */
int flow_init_parser(flow_context_t *ctx, const char *alpn);

/**
 * @brief Fully initialize HTTP/2 session for a flow
 *
 * Called by the home worker when first HTTP/2 data arrives. Creates
 * nghttp2 server session, HPACK inflater, and reassembly buffer.
 *
 * @par Usage
 * @code
 *   // In worker claim logic:
 *   if (atomic_compare_exchange_strong(&ctx->home_worker_id, &expected, my_id)) {
 *       if (ctx->proto == FLOW_PROTO_HTTP2 && !ctx->parser.h2.session) {
 *           flow_h2_session_init(ctx, g_callbacks, callback_context);
 *       }
 *   }
 * @endcode
 *
 * @param ctx   Flow context with proto == FLOW_PROTO_HTTP2
 * @param cbs   nghttp2 session callbacks
 * @param user  User data for callbacks
 * @return 0 on success, -1 on failure
 */
int flow_h2_session_init(flow_context_t *ctx, nghttp2_session_callbacks *cbs,
                          void *user);

/**
 * @brief Initialize HTTP/1 parser for a flow
 *
 * Called by the home worker when first HTTP/1 data arrives. Configures
 * the llhttp parser with the global callback settings.
 *
 * @par Usage
 * @code
 *   // In worker claim logic:
 *   if (atomic_compare_exchange_strong(&ctx->home_worker_id, &expected, my_id)) {
 *       if (ctx->proto == FLOW_PROTO_HTTP1 && !ctx->parser.h1.initialized) {
 *           flow_h1_parser_init(ctx, http1_get_settings());
 *       }
 *   }
 * @endcode
 *
 * @param ctx       Flow context with proto == FLOW_PROTO_HTTP1
 * @param settings  llhttp settings with callbacks (from http1_get_settings())
 * @return 0 on success, -1 on failure
 */
int flow_h1_parser_init(flow_context_t *ctx, llhttp_settings_t *settings);

/**
 * @brief Free flow context resources (parser, buffers)
 *
 * Does not free the slot itself - just internal resources.
 *
 * @param ctx  Flow context
 */
void flow_free_resources(flow_context_t *ctx);

/** @} */

/*============================================================================
 * Transaction/Stream Operations
 *============================================================================*/

/**
 * @defgroup flow_txn_ops Transaction Operations
 * @brief Helper functions for stream/transaction management
 * @{
 */

/**
 * @brief Initialize HTTP/2 stream pool free list
 *
 * Called once when H2 session is initialized. Links all stream slots
 * into a free list for O(1) allocation.
 *
 * @param ctx  Flow context with proto == FLOW_PROTO_HTTP2
 */
void flow_h2_init_stream_pool(flow_context_t *ctx);

/**
 * @brief Allocate a stream slot for HTTP/2
 *
 * O(1) allocation from free list. Initializes stream_id and resets state.
 *
 * @param ctx        Flow context
 * @param stream_id  HTTP/2 stream ID
 * @return Pointer to transaction, or NULL if pool exhausted
 */
flow_transaction_t *flow_h2_alloc_stream(flow_context_t *ctx, int32_t stream_id);

/**
 * @brief Find stream by ID in HTTP/2 context
 *
 * Linear search through active streams. For 64 slots, this is acceptable.
 * Future: hash table if stream count increases.
 *
 * @param ctx        Flow context
 * @param stream_id  HTTP/2 stream ID to find
 * @return Pointer to transaction, or NULL if not found
 */
flow_transaction_t *flow_h2_find_stream(flow_context_t *ctx, int32_t stream_id);

/**
 * @brief Free a stream slot back to pool
 *
 * Frees any body buffer, resets state, returns to free list.
 *
 * @param ctx  Flow context
 * @param txn  Transaction to free
 */
void flow_h2_free_stream(flow_context_t *ctx, flow_transaction_t *txn);

/**
 * @brief Reap timed-out "ghost" streams
 *
 * Scans active streams and frees any that have been idle longer than
 * FLOW_STREAM_TIMEOUT_MS. Called periodically by worker.
 *
 * @param ctx         Flow context
 * @param current_ms  Current monotonic timestamp in milliseconds
 * @return Number of streams reaped
 */
int flow_h2_reap_ghosts(flow_context_t *ctx, uint32_t current_ms);

/**
 * @brief Reset HTTP/1 transaction for next request
 *
 * Clears transaction state but keeps parser. Called when response
 * completes and connection remains open (keep-alive).
 *
 * @param ctx  Flow context with proto == FLOW_PROTO_HTTP1
 */
void flow_h1_reset_txn(flow_context_t *ctx);

/**
 * @brief Allocate body buffer for transaction
 *
 * Dynamically allocates body buffer when -b option is enabled.
 * Called when first body data arrives.
 *
 * @param txn       Transaction to allocate buffer for
 * @param capacity  Initial capacity (will grow as needed)
 * @return 0 on success, -1 on allocation failure
 */
int flow_txn_alloc_body(flow_transaction_t *txn, size_t capacity);

/**
 * @brief Append data to transaction body buffer
 *
 * Grows buffer as needed. Does nothing if body capture disabled.
 *
 * @param txn   Transaction
 * @param data  Data to append
 * @param len   Length of data
 * @return 0 on success, -1 on allocation failure
 */
int flow_txn_append_body(flow_transaction_t *txn, const uint8_t *data, size_t len);

/**
 * @brief Free transaction body buffer
 *
 * @param txn  Transaction
 */
void flow_txn_free_body(flow_transaction_t *txn);

/**
 * @brief Get monotonic time in milliseconds
 *
 * Used for ghost stream detection timestamps.
 *
 * @return Current time in milliseconds since boot
 */
uint32_t flow_get_monotonic_ms(void);

/** @} */

#endif /* FLOW_CONTEXT_H */
