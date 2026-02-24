/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * flow_context.h - Dynamic Flow Pool with Dual Index for XDP-SSL Correlation
 *
 * This module implements the "Dynamic Pool with Dual Index" architecture:
 *
 *   1. SINGLE SOURCE OF TRUTH: All flow data in dynamically allocated contexts
 *   2. DUAL INDEXING: Two incrementally-resizing hash tables point to contexts
 *      - cookie_index: socket_cookie → flow_context_t* (primary, fast path)
 *      - shadow_index: (pid, ssl_ctx) → flow_context_t* (fallback for early events)
 *   3. ZERO-COPY: Data never moves, only pointer-sized index entries change
 *   4. ATOMIC HANDOVER: Cookie promotion is a single index insertion
 *   5. NO CAPACITY LIMIT: Flows allocated on demand via jemalloc
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
#include "../content/stream_decompressor.h"
#include "../memory/mirrored_buffer.h"

/*============================================================================
 * Constants and Configuration
 *============================================================================*/

/**
 * @defgroup flow_config Flow Context Configuration
 * @brief Compile-time configuration for the dynamic pool
 * @{
 */

/** Flow timeout in nanoseconds (60 seconds) */
#define FLOW_TIMEOUT_NS         (60ULL * 1000000000ULL)

/** Initial hash table capacity (power of 2, grows as needed) */
#define FLOW_INDEX_INITIAL_CAPACITY  256

/** Entries migrated per insert/lookup during incremental resize */
#define FLOW_INDEX_GROW_BATCH        8

/** Deferred free grace period: 2 seconds (protects stale worker pointers) */
#define FLOW_DEFERRED_FREE_GRACE_NS  (2ULL * 1000000000ULL)

/** @} */

/*============================================================================
 * Core Types
 *============================================================================*/

/**
 * @defgroup flow_types Flow Context Types
 * @brief Core type definitions for the dynamic pool
 * @{
 */

/**
 * @brief Flow identifier - monotonic allocation counter
 *
 * Using a 32-bit ID provides debugging traceability.
 * Indexes now store pointers directly; this ID is for logging only.
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

    /*=== Body Buffer (mirrored, fixed 256KB, 16 bytes) ===*/
    mirrored_buffer_t *body_mirror; /**< Mirrored body buffer (NULL until first chunk) */
    size_t body_len;                /**< Current data length in buffer */

    /*=== Streaming Decompression (per-transaction) ===*/
    stream_decomp_t stream_decomp;  /**< Per-txn streaming decompressor */

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
 * Cache line 0 contains identity + lifecycle (generation, list pointers).
 *
 * @par Ownership
 * Each flow_context_t is owned by exactly one worker thread, determined
 * by: worker_id = socket_cookie % num_workers (or hash(pid,ssl_ctx) if
 * cookie unknown). This eliminates the need for locking.
 *
 * @par Lifecycle
 * 1. Allocated via aligned_alloc when first event arrives
 * 2. Added to shadow_index immediately (always has pid+ssl_ctx)
 * 3. Added to cookie_index when socket_cookie becomes known
 * 4. Parser initialized when ALPN detected
 * 5. Freed via deferred free (2s grace) on timeout or termination
 */
typedef struct flow_context {
    /*=== Cache Line 0: Identity + Lifecycle (64 bytes) ===*/
    uint64_t socket_cookie;         /**< Primary key (0 if unknown) */
    uint32_t pid;                   /**< Process ID */
    uint32_t generation;            /**< Allocation generation (never 0) */
    uint64_t ssl_ctx;               /**< SSL context pointer */
    flow_id_t self_id;              /**< Monotonic ID (for debugging/logging) */
    uint32_t _pad0;                 /**< Alignment padding */
    struct flow_context *list_prev; /**< Active/deferred list: previous */
    struct flow_context *list_next; /**< Active/deferred list: next */

    /*=== Network View - from XDP (48 bytes) ===*/
    flow_key_t flow;                /**< 5-tuple: IPs and ports (28 bytes) */
    uint32_t ifindex;               /**< Network interface index */
    uint64_t first_seen_ns;         /**< First packet timestamp */
    uint64_t last_seen_ns;          /**< Last activity timestamp */

    /*=== Traffic Counters (16 bytes) ===*/
    /* FIX H6: Make counters atomic to prevent lost updates from concurrent access.
     * Multiple threads may update these (dispatcher via XDP, workers via SSL). */
    _Atomic uint32_t pkts_in;       /**< Ingress packet count (atomic) */
    _Atomic uint32_t pkts_out;      /**< Egress packet count (atomic) */
    _Atomic uint32_t bytes_in;      /**< Ingress byte count (atomic) */
    _Atomic uint32_t bytes_out;     /**< Egress byte count (atomic) */

    /*=== Application View - from SSL (48 bytes) ===*/
    char comm[16];                  /**< Process command name */
    char alpn[16];                  /**< ALPN result (h2, http/1.1) */
    char ifname[16];                /**< Interface name */

    /*=== State and Flags (8 bytes) ===*/
    flow_proto_t proto;             /**< Detected protocol */
    flow_state_t state;             /**< Lifecycle state */
    uint8_t xdp_category;           /**< XDP protocol category */
    uint8_t xdp_direction;          /**< XDP packet direction (1=ingress, 2=egress) */
    _Atomic uint8_t flags;          /**< Bit flags - atomic for thread safety */
    uint8_t _pad_flags;             /**< Padding for alignment */
    uint32_t uid;                   /**< User ID */

    /*=== Protocol Parser (union to save memory) ===*/
    /** @brief Protocol-specific parser context (union to save memory) */
    union {
        h1_parser_ctx_t h1;         /**< HTTP/1.x context */
        h2_parser_ctx_t h2;         /**< HTTP/2 context */
    } parser;

    /*=== Thread Safety / Worker Affinity ===*/
    /**
     * @brief Slot active flag
     *
     * Set to true when slot is allocated, false when freed.
     * Uses acquire/release semantics for visibility across threads.
     */
    _Atomic bool active;

    /**
     * @brief Reference count for safe deferred deallocation.
     *
     * Starts at 1 (creator's reference via flow_pool_alloc). Acquired by
     * dispatcher before dispatching an event, released by worker after
     * processing. Creator's reference released via flow_terminate().
     * Deferred free will not release resources while ref_count > 0.
     *
     * @see flow_ref_acquire(), flow_ref_release(), flow_ref_count()
     */
    _Atomic uint32_t ref_count;

    /**
     * @brief Home worker ID for "Sticky" worker affinity
     *
     * Implements the "Hybrid Sticky" architecture for thread-safe access
     * without locking. The first worker to process an event for this flow
     * claims ownership via atomic CAS (Compare-And-Swap).
     *
     * @note Value is WORKER_ID_NONE (UINT32_MAX) until claimed
     */
    _Atomic uint32_t home_worker_id;

    /*=== Handshake Deduplication (Fix #2) ===*/
    /**
     * @brief Last handshake event timestamp for deduplication
     *
     * SSL_do_handshake() can be called multiple times during TLS negotiation
     * (WANT_READ/WANT_WRITE retries). Track the last handshake timestamp to
     * deduplicate events within a 100ms window.
     */
    uint64_t last_handshake_ns;

    /**
     * @brief True if handshake completion has been displayed
     *
     * Atomic flag to prevent duplicate handshake output when SSL_do_handshake()
     * is called multiple times during TLS negotiation. Uses atomic_exchange
     * to ensure only one thread displays the handshake event.
     */
    _Atomic bool handshake_displayed;

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
    FLOW_FLAG_PARSER_INIT = (1 << 4),   /**< Parser initialized */
    FLOW_FLAG_PLAINTEXT   = (1 << 5)    /**< Non-TLS flow (XDP-only, no SSL) */
};

/** @} */

/*============================================================================
 * Reference Count Helpers (Inline)
 *============================================================================*/

/**
 * @defgroup flow_refcount Reference Counting
 * @brief Atomic reference counting for safe deferred deallocation
 *
 * @par Memory Ordering Rationale
 * - Acquire (increment): relaxed — caller already holds a reference,
 *   so the object is guaranteed alive. No cross-thread synchronization
 *   needed for the increment itself.
 * - Release (decrement): release — ensures all prior writes by the
 *   releasing thread are visible to the janitor's acquire-load.
 * - Drain check (read): acquire — synchronizes with workers' release
 *   stores, ensuring the janitor sees a consistent count.
 * @{
 */

/**
 * @brief Acquire a reference to a flow context.
 *
 * Called by the dispatcher before dispatching an event that carries
 * a flow_context_t pointer. The caller must already hold a reference.
 *
 * @param ctx  Flow context (must not be NULL)
 * @return Previous reference count (before increment)
 */
static inline uint32_t flow_ref_acquire(flow_context_t *ctx) {
    return atomic_fetch_add_explicit(&ctx->ref_count, 1,
                                      memory_order_relaxed);
}

/**
 * @brief Release a reference to a flow context.
 *
 * Called by workers after processing an event, and by the creator
 * (via flow_terminate) when the flow is being destroyed.
 *
 * @param ctx  Flow context (must not be NULL)
 * @return true if this was the last reference (count reached 0)
 */
static inline bool flow_ref_release(flow_context_t *ctx) {
    uint32_t prev = atomic_fetch_sub_explicit(&ctx->ref_count, 1,
                                               memory_order_release);
    return (prev == 1);  /* was 1, now 0 */
}

/**
 * @brief Read the current reference count (snapshot).
 *
 * Uses acquire semantics to synchronize with workers' releases,
 * ensuring the janitor sees all completed decrements.
 *
 * @param ctx  Flow context (must not be NULL)
 * @return Current reference count
 */
static inline uint32_t flow_ref_count(flow_context_t *ctx) {
    return atomic_load_explicit(&ctx->ref_count, memory_order_acquire);
}

/**
 * @brief Check if a flow is plaintext (non-TLS).
 *
 * Plaintext flows are observed only via XDP packet capture without
 * any SSL/TLS hooks. They can transition to ACTIVE with only XDP
 * data (no SSL view required).
 *
 * @param ctx  Flow context (must not be NULL)
 * @return true if FLOW_FLAG_PLAINTEXT is set
 */
static inline bool flow_is_plaintext(flow_context_t *ctx) {
    return (atomic_load_explicit(&ctx->flags, memory_order_acquire) &
            FLOW_FLAG_PLAINTEXT) != 0;
}

/** @} */

/*============================================================================
 * Index Structures (Thread-Safe CK Hash Sets)
 *============================================================================*/

/**
 * @defgroup flow_indexes Index Structures
 * @brief Thread-safe SPMC hash tables using CK hs
 *
 * @par Thread Safety Model (SPMC)
 * These indexes use Concurrency Kit's ck_hs for lock-free SPMC access:
 * - Single-Producer: Only dispatcher thread performs writes (insert/remove)
 * - Multiple-Consumer: Workers can safely lookup during writes/resize
 *
 * This architectural constraint is CRITICAL for thread safety. All functions
 * that modify the indexes (insert, remove) MUST only be called from the
 * dispatcher thread.
 *
 * @see ck_cookie_index.h for cookie index implementation
 * @see ck_shadow_index.h for shadow index implementation
 * @{
 */

#include "ck_cookie_index.h"
#include "ck_shadow_index.h"

/**
 * @brief Type alias for CK-based cookie index
 * @see ck_cookie_index.h
 */
typedef ck_cookie_index_t cookie_index_t;

/**
 * @brief Type alias for CK-based shadow index
 * @see ck_shadow_index.h
 */
typedef ck_shadow_index_t shadow_index_t;

/** @} */

/*============================================================================
 * Flow Pool Structure
 *============================================================================*/

/**
 * @defgroup flow_pool Flow Pool
 * @brief Dynamic pool of flow contexts with deferred free
 * @{
 */

/**
 * @brief Dynamic flow context pool
 *
 * Flows are allocated on demand via aligned_alloc (64-byte aligned for
 * cache line optimization). An intrusive doubly-linked list tracks active
 * flows for O(active) janitor traversal. Freed flows enter a deferred
 * free queue (2s grace period) to protect against stale worker pointers.
 *
 * @par Thread Safety
 * Pool allocation/deallocation must be done by a single thread
 * (the dispatcher). Workers only read/write existing contexts.
 */
typedef struct {
    flow_context_t *active_head;    /**< Head of active doubly-linked list */
    flow_context_t *deferred_head;  /**< Deferred free FIFO: oldest */
    flow_context_t *deferred_tail;  /**< Deferred free FIFO: newest */
    _Atomic uint64_t allocated;     /**< Currently active count */
    _Atomic uint64_t peak;          /**< Peak allocation (high water) */
    _Atomic uint64_t total_allocs;  /**< Lifetime allocations */
    _Atomic uint64_t total_frees;   /**< Lifetime frees */
    _Atomic uint64_t alloc_failures; /**< OOM counter */
    _Atomic uint64_t next_id;       /**< Monotonic ID counter */
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
 * @brief Allocation and deallocation from the dynamic pool
 * @{
 */

/**
 * @brief Initialize the flow pool
 *
 * Zeroes the struct and initializes counters. No pre-allocation.
 *
 * @param pool  Pool to initialize
 * @return 0 on success, -1 on failure
 */
int flow_pool_init(flow_pool_t *pool);

/**
 * @brief Cleanup the flow pool
 *
 * Frees all active and deferred flows.
 *
 * @param pool  Pool to cleanup
 */
void flow_pool_cleanup(flow_pool_t *pool);

/**
 * @brief Allocate a new flow context
 *
 * Uses aligned_alloc(64, sizeof(flow_context_t)) via jemalloc.
 * Initializes to zeroed state, assigns monotonic ID and generation.
 * Inserts at head of active list.
 *
 * @param pool  The flow pool
 * @return Pointer to new flow_context_t, or NULL if OOM
 */
flow_context_t *flow_pool_alloc(flow_pool_t *pool);

/**
 * @brief Free a flow context (deferred)
 *
 * Marks inactive, removes from active list, adds to deferred FIFO.
 * Actual free() happens after FLOW_DEFERRED_FREE_GRACE_NS.
 *
 * @param pool  The flow pool
 * @param ctx   The flow context to free
 */
void flow_pool_free(flow_pool_t *pool, flow_context_t *ctx);

/**
 * @brief Drain deferred free queue
 *
 * Frees entries whose grace period has expired.
 *
 * @param pool  The flow pool
 * @param now   Current timestamp in nanoseconds
 */
void flow_pool_drain_deferred(flow_pool_t *pool, uint64_t now);

/**
 * @brief Force drain all flows at shutdown
 *
 * Immediately frees ALL flows in active and deferred lists without
 * waiting for grace periods. Use only at program shutdown.
 *
 * @param pool  The flow pool to drain
 */
void flow_pool_force_drain(flow_pool_t *pool);

/** @} */

/*============================================================================
 * Index Operations (Delegated to CK Wrappers)
 *============================================================================*/

/**
 * @defgroup flow_index_ops Index Operations
 * @brief Thread-safe hash table operations delegated to CK wrappers
 *
 * @par Thread Safety
 * All write operations (init, cleanup, insert, remove) MUST only be called
 * from the dispatcher thread. Lookup operations are safe from any thread.
 * @{
 */

/*
 * Cookie index operations are now provided by ck_cookie_index.h:
 * - ck_cookie_index_init()
 * - ck_cookie_index_cleanup()
 * - ck_cookie_index_insert()
 * - ck_cookie_index_lookup()
 * - ck_cookie_index_remove()
 *
 * Shadow index operations are now provided by ck_shadow_index.h:
 * - ck_shadow_index_init()
 * - ck_shadow_index_cleanup()
 * - ck_shadow_index_insert()
 * - ck_shadow_index_lookup()
 * - ck_shadow_index_remove()
 * - ck_shadow_find_by_cookie()
 */

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
 * Initializes pool and both indexes (starting at FLOW_INDEX_INITIAL_CAPACITY).
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
 * @brief Force drain all flows at shutdown
 *
 * Wrapper for flow_pool_force_drain() that operates on the manager's pool.
 * Immediately frees all flows without grace periods.
 *
 * @param mgr  Manager whose pool to drain
 */
void flow_manager_force_drain(flow_manager_t *mgr);

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
 * @brief Merge SSL info into XDP-created flow (single-writer only)
 *
 * FIX C4: This function performs write operations and MUST only be called
 * from the dispatcher thread (single-writer context).
 *
 * XDP-SSL Correlation: XDP events create flows with ssl_ctx=0.
 * When SSL events arrive with the same cookie, call this to merge
 * the SSL context and PID into the XDP-created flow.
 *
 * @param mgr      Flow manager
 * @param ctx      Flow context to update (must be active)
 * @param pid      Process ID to merge (0 = don't update)
 * @param ssl_ctx  SSL context to merge (0 = don't update)
 * @return 0 on success, -1 on error
 *
 * @par Thread Safety: Single-writer only (dispatcher thread)
 */
int flow_merge_ssl_info(flow_manager_t *mgr, flow_context_t *ctx,
                        uint32_t pid, uint64_t ssl_ctx);

/**
 * @brief Get or create flow context
 *
 * If flow exists, returns it. Otherwise allocates new context,
 * initializes with provided keys, and adds to shadow_index.
 * If cookie != 0, also adds to cookie_index.
 *
 * @param mgr      Flow manager
 * @param cookie   Socket cookie (0 if unknown)
 * @param pid      Process ID
 * @param ssl_ctx  SSL context
 * @return Pointer to flow_context_t, or NULL if OOM
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
 * Removes from both indexes, frees resources, adds to deferred free queue.
 *
 * @param mgr  Flow manager
 * @param ctx  Flow context to terminate
 */
void flow_terminate(flow_manager_t *mgr, flow_context_t *ctx);

/**
 * @brief Evict stale flows
 *
 * Walks active list for flows older than timeout and terminates them.
 * Also drains the deferred free queue.
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
    uint64_t pool_allocated;        /**< Currently active flows */
    uint64_t pool_peak;             /**< Peak allocation (high water) */
    uint64_t pool_total_allocs;     /**< Lifetime allocations */
    uint64_t pool_total_frees;      /**< Lifetime frees */
    uint64_t pool_alloc_failures;   /**< OOM allocation failures */

    /* Cookie index statistics */
    uint64_t cookie_count;          /**< Entries in cookie index */
    uint64_t cookie_hits;           /**< Successful cookie lookups */
    uint64_t cookie_misses;         /**< Failed cookie lookups */

    /* Shadow index statistics */
    uint64_t shadow_count;          /**< Entries in shadow index */
    uint64_t shadow_hits;           /**< Successful shadow lookups */
    uint64_t shadow_promotions;     /**< Flows promoted to cookie index */
    uint64_t shadow_merges;         /**< XDP flows merged into SSL flows */
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
 * @param ctx       Flow context with proto == FLOW_PROTO_HTTP1
 * @param settings  llhttp settings with callbacks (from http1_get_settings())
 * @return 0 on success, -1 on failure
 */
int flow_h1_parser_init(flow_context_t *ctx, llhttp_settings_t *settings);

/**
 * @brief Free flow context resources (parser, buffers)
 *
 * Does not free the context itself - just internal resources.
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
 * @brief Initialize HTTP/2 stream pool for a flow context
 * @param[in,out] ctx Flow context to initialize
 */
void flow_h2_init_stream_pool(flow_context_t *ctx);

/**
 * @brief Allocate HTTP/2 stream transaction
 * @param[in,out] ctx       Flow context
 * @param[in]     stream_id HTTP/2 stream identifier
 * @return Transaction pointer, or NULL on failure
 */
flow_transaction_t *flow_h2_alloc_stream(flow_context_t *ctx, int32_t stream_id);

/**
 * @brief Find existing HTTP/2 stream transaction
 * @param[in] ctx       Flow context
 * @param[in] stream_id HTTP/2 stream identifier
 * @return Transaction pointer, or NULL if not found
 */
flow_transaction_t *flow_h2_find_stream(flow_context_t *ctx, int32_t stream_id);

/**
 * @brief Free HTTP/2 stream transaction
 * @param[in,out] ctx Flow context
 * @param[in]     txn Transaction to free
 */
void flow_h2_free_stream(flow_context_t *ctx, flow_transaction_t *txn);

/**
 * @brief Reap idle/ghost HTTP/2 streams
 * @param[in,out] ctx        Flow context
 * @param[in]     current_ms Current monotonic time in milliseconds
 * @return Number of streams reaped
 */
int flow_h2_reap_ghosts(flow_context_t *ctx, uint32_t current_ms);

/**
 * @brief Reset HTTP/1 transaction state for new request
 * @param[in,out] ctx Flow context
 */
void flow_h1_reset_txn(flow_context_t *ctx);

/**
 * @brief Allocate body buffer for transaction
 * @param[in,out] txn      Transaction
 * @param[in]     capacity Initial buffer capacity
 * @return 0 on success, -1 on failure
 */
int flow_txn_alloc_body(flow_transaction_t *txn, size_t capacity);

/**
 * @brief Append data to transaction body buffer
 * @param[in,out] txn  Transaction
 * @param[in]     data Data to append
 * @param[in]     len  Data length
 * @return 0 on success, -1 on failure
 */
int flow_txn_append_body(flow_transaction_t *txn, const uint8_t *data, size_t len);

/**
 * @brief Free transaction body buffer
 * @param[in,out] txn Transaction
 */
void flow_txn_free_body(flow_transaction_t *txn);

/**
 * @brief Get pointer to transaction body data
 *
 * Returns the base address of the mirrored body buffer, or NULL
 * if no body has been allocated yet.
 *
 * @param txn  Transaction (may be NULL)
 * @return Pointer to body data, or NULL
 */
static inline uint8_t *flow_txn_body_ptr(const flow_transaction_t *txn) {
    if (!txn || !txn->body_mirror) return NULL;
    return (uint8_t *)txn->body_mirror->base;
}

/**
 * @brief Get current monotonic time in milliseconds
 * @return Monotonic milliseconds since boot
 */
uint32_t flow_get_monotonic_ms(void);

/** @} */

#endif /* FLOW_CONTEXT_H */
