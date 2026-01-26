/**
 * @file threading.h
 * @brief Multi-threaded event processing infrastructure
 *
 * @details This module provides the threading architecture for spliff's
 * high-performance event processing pipeline. The design uses lock-free
 * data structures and connection affinity to achieve scalability.
 *
 * @par Thread Architecture:
 * @code
 *   Main Thread
 *       │
 *       ▼
 *   Dispatcher Thread ──► polls BPF ring buffer
 *       │
 *       ├──► Worker 0 ──► processes connections 0, N, 2N, ...
 *       ├──► Worker 1 ──► processes connections 1, N+1, 2N+1, ...
 *       └──► Worker K ──► processes connections K, N+K, 2N+K, ...
 *                │
 *                └──► Output Thread ──► serializes to stdout
 * @endcode
 *
 * @par Connection Affinity:
 * Events are routed to workers using a hash of (pid, ssl_ctx). This
 * ensures all events for a single connection always go to the same worker,
 * eliminating need for locks on per-connection state (HTTP/2 sessions,
 * HPACK contexts, stream buffers).
 *
 * @par Lock-Free Data Structures:
 * - CK ring buffers for inter-thread queues
 * - Object pools for zero-allocation fast path
 * - Atomic counters for statistics
 * - eventfd for sleep/wake coordination
 *
 * @par Per-Worker State:
 * Each worker maintains isolated copies of:
 * - HTTP/2 connection pool (nghttp2 sessions)
 * - HTTP/2 stream pool (per-stream buffers)
 * - ALPN cache (protocol negotiation results)
 * - Pending body tracking (chunked response assembly)
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef THREADING_H
#define THREADING_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <ck_ring.h>

#include "../include/spliff.h"
#include "../bpf/probe_handler.h"
#include "../protocol/http2.h"  /* For h2_stream_state_t, frame types */
#include "../correlation/flow_context.h"  /* For flow_manager_t (Shared Pool) */

/**
 * @defgroup threading_config Threading Configuration Constants
 * @brief Tuning parameters for the threading subsystem
 * @{
 */

/**
 * @name Ring Buffer Sizes
 * Must be power of 2 for CK ring buffer efficiency.
 * @{
 */
#define EVENT_RING_SIZE         4096    /**< Worker input queue capacity */
#define OUTPUT_RING_SIZE        4096    /**< Output queue capacity */
/** @} */

/**
 * @name Object Pool Sizes
 * Pre-allocated objects for zero-malloc fast path.
 * @{
 */
#define EVENT_POOL_SIZE         4096    /**< Event objects per worker */
#define OUTPUT_POOL_SIZE        1024    /**< Output message objects per worker */
/** @} */

/**
 * @name NAPI-Style Adaptive Polling
 * Budget-based loop: process events up to budget, then sleep if caught up.
 * Zero CPU when idle (epoll blocks), zero syscall overhead under heavy load.
 * @{
 */
#define NAPI_BUDGET             64      /**< Max events per loop iteration */
#define EPOLL_TIMEOUT_MS        100     /**< Sleep timeout when caught up */
#define EPOLL_RETRY_TIMEOUT_MS  1       /**< Short timeout when retries pending */
/** @} */

/**
 * @name Cookie Retry Queue
 * Handles SSL-sockops timing race where SSL events arrive before XDP events
 * populate the flow_cache. Uses bitmask for O(1) slot operations.
 * @{
 */
#define MAX_COOKIE_RETRIES      3       /**< Retry attempts before giving up */
#define MAX_DEFERRED_EVENTS     64      /**< Fits in uint64_t bitmask */
#define RETRY_TICK_INTERVAL     4       /**< Process retries every N iterations */
/** @} */

/**
 * @name Output Batching
 * @{
 */
#define BATCH_SIZE              32      /**< Output messages collected per iteration */
/** @} */

/**
 * @name Per-Worker Resource Limits
 * Each worker maintains isolated pools sized by these limits.
 * @{
 */
#define MAX_H2_SESSIONS_PER_WORKER      16   /**< HTTP/2 connections per worker */
#define MAX_H2_STREAMS_PER_WORKER       128  /**< HTTP/2 streams per worker */
/** @} */

/**
 * @name Global Limits
 * @{
 */
#define MAX_WORKERS             16      /**< Maximum worker thread count */
/** @} */

/**
 * @name Output Sizing
 * @{
 */
#define OUTPUT_MSG_MAX_SIZE     (64 * 1024)  /**< Max formatted output (64KB) */
/** @} */

/** @} */ /* end threading_config group */

/**
 * @defgroup threading_forward Forward Declarations
 * @brief External types used by threading module
 * @{
 */
struct nghttp2_session;           /**< nghttp2 HTTP/2 session handle */
struct nghttp2_hd_inflater;       /**< nghttp2 HPACK decompressor */
struct nghttp2_session_callbacks; /**< nghttp2 callback table */
/** @} */

/**
 * @defgroup threading_h2 HTTP/2 Per-Worker Structures
 * @brief Worker-local HTTP/2 state to avoid cross-thread locking
 * @{
 */

/** Response reassembly buffer size for fragmented HTTP/2 frames */
#define H2_REASSEMBLY_BUF_SIZE 65536

/* Note: h2_stream_state_t and H2_BODY_BUFFER_SIZE are defined in http2.h */

/**
 * @brief Per-connection HTTP/2 session state (worker-local)
 *
 * Each worker maintains its own pool of HTTP/2 connections. Connection
 * affinity routing ensures the same (pid, ssl_ctx) always goes to the
 * same worker, so no locking is needed on this state.
 *
 * @par Session Parsing Strategy:
 * - server_session parses client requests (we're acting as "server")
 * - response_inflater decodes server response headers (separate HPACK context)
 * - This dual-context approach handles both directions of HTTP/2 traffic
 */
typedef struct h2_connection_local {
    uint32_t pid;           /**< Process ID owning this connection */
    uint64_t ssl_ctx;       /**< SSL context pointer (connection identifier) */
    bool active;            /**< true if slot is in use */

    /** nghttp2 server session for parsing client->server requests */
    struct nghttp2_session *server_session;

    /** HPACK inflater for decoding server->client response headers */
    struct nghttp2_hd_inflater *response_inflater;

    bool client_preface_seen;   /**< Received HTTP/2 client connection preface */
    bool server_settings_seen;  /**< Received server SETTINGS frame */

    /** Buffer for reassembling fragmented response frames */
    uint8_t *response_buf;
    size_t response_buf_len;    /**< Current data in response_buf */

    uint64_t last_activity_ns;  /**< Timestamp for LRU eviction */

    char comm[TASK_COMM_LEN];   /**< Cached process name */
    char alpn_proto[16];        /**< Negotiated ALPN protocol (e.g., "h2") */
} h2_connection_local_t;

/**
 * @brief Per-stream HTTP/2 state (worker-local)
 *
 * Tracks individual HTTP/2 streams within a connection. HTTP/2 multiplexes
 * multiple request/response pairs over a single connection, each identified
 * by a unique stream ID.
 *
 * @par Stream Lifecycle:
 * 1. Created when HEADERS frame opens new stream
 * 2. Accumulates request headers, then request body (if any)
 * 3. Receives response headers, then response body
 * 4. Freed when stream closes (END_STREAM, RST_STREAM, or connection close)
 *
 * @par Lookup Key:
 * Streams are uniquely identified by (pid, ssl_ctx, stream_id).
 */
typedef struct h2_stream_local {
    /** @name Stream Identity (Lookup Key) */
    /** @{ */
    uint32_t pid;           /**< Process ID */
    uint64_t ssl_ctx;       /**< SSL context pointer */
    int32_t stream_id;      /**< HTTP/2 stream identifier (odd=client, even=server) */
    bool active;            /**< true if slot is in use */
    /** @} */

    h2_stream_state_t state;  /**< Current stream state (IDLE, OPEN, HALF_CLOSED, etc.) */

    /** @name Request Information */
    /** @{ */
    char method[MAX_METHOD_LEN];        /**< HTTP method (GET, POST, etc.) */
    char path[MAX_PATH_LEN];            /**< Request path with query string */
    char authority[MAX_HEADER_VALUE];   /**< :authority pseudo-header (host) */
    char scheme[16];                    /**< :scheme pseudo-header (https) */
    uint64_t request_time_ns;           /**< Timestamp when request started */
    bool request_headers_done;          /**< All request headers received */
    bool request_complete;              /**< Request fully received (including body) */
    /** @} */

    /** @name Response Information */
    /** @{ */
    int status_code;                /**< HTTP status code (200, 404, etc.) */
    char content_type[256];         /**< Content-Type header value */
    char content_encoding[64];      /**< Content-Encoding (gzip, br, etc.) */
    size_t content_length;          /**< Content-Length if specified, 0 otherwise */
    uint64_t response_time_ns;      /**< Timestamp when response started */
    bool response_headers_done;     /**< All response headers received */
    bool response_complete;         /**< Response fully received */
    /** @} */

    /** @name Headers Storage */
    /** @{ */
    http_header_t headers[MAX_HEADERS]; /**< Collected headers array */
    int header_count;                   /**< Number of headers stored */
    bool headers_displayed;             /**< Already output to user */
    /** @} */

    /** @name Body Accumulation */
    /** @{ */
    uint8_t *body_buf;      /**< Dynamically allocated body buffer */
    size_t body_buf_size;   /**< Allocated capacity of body_buf */
    size_t body_len;        /**< Actual body bytes received */
    /** @} */

    /** @name Display Metadata */
    /** @{ */
    uint64_t delta_ns;          /**< Time delta for output formatting */
    char comm[TASK_COMM_LEN];   /**< Process name for display */
    /** @} */
} h2_stream_local_t;

/** @} */ /* end threading_h2 group */

/**
 * @defgroup threading_event Event Structures
 * @brief Inter-thread communication data structures
 * @{
 */

/**
 * @brief Worker event - copied from BPF ring buffer
 *
 * The dispatcher copies events from the BPF ring buffer into these
 * structures and enqueues them to worker input rings. This decouples
 * the BPF ring buffer consumption rate from worker processing rate.
 *
 * @par Memory Management:
 * Allocated from per-worker object pools (event_pool) to avoid malloc
 * in the hot path. Freed back to pool after processing.
 *
 * @par Routing:
 * worker_id and flow_hash are pre-computed by the dispatcher for
 * efficient event distribution.
 */
typedef struct worker_event {
    /** @name BPF Event Metadata */
    /** @{ */
    uint64_t timestamp_ns;      /**< Kernel timestamp (CLOCK_MONOTONIC) */
    uint64_t delta_ns;          /**< Time since previous event */
    uint64_t ssl_ctx;           /**< SSL context pointer (connection ID) */
    uint64_t socket_cookie;     /**< Socket cookie for XDP correlation ("Golden Thread") */
    uint32_t pid;               /**< Process ID */
    uint32_t tid;               /**< Thread ID */
    uint32_t uid;               /**< User ID */
    uint32_t event_type;        /**< Event type (EVENT_SSL_READ, etc.) */
    int32_t buf_filled;         /**< Bytes captured (-1 if error) */
    char comm[TASK_COMM_LEN];   /**< Process command name */
    /** @} */

    /** @name Routing Information */
    /** @{ */
    uint32_t worker_id;     /**< Target worker (pre-computed by dispatcher) */
    uint32_t flow_hash;     /**< FNV-1a hash of (pid, ssl_ctx) */
    /** @} */

    /** @name Shared Pool Correlation */
    /** @{ */
    flow_id_t flow_id;           /**< Flow ID in shared pool (FLOW_ID_INVALID if none) */
    flow_context_t *flow_ctx;    /**< Resolved flow context (NULL until resolved) */
    bool needs_cookie_retry;     /**< True if XDP data not yet available for retry */
    /** @} */

    /** @name Payload */
    /** @{ */
    uint32_t data_len;              /**< Actual payload length */
    uint8_t data[MAX_BUF_SIZE];     /**< SSL plaintext data (up to 16KB) */
    /** @} */
} worker_event_t;

/**
 * @brief Formatted output message - produced by workers, consumed by output thread
 *
 * Workers format SSL events into human-readable or JSON output and enqueue
 * these messages to the output thread. The output thread serializes messages
 * to stdout/file in timestamp order.
 *
 * @par Ordering Guarantees:
 * - Messages sorted by timestamp_ns, then sequence
 * - sequence breaks ties when multiple events have same timestamp
 * - Output thread may buffer briefly to ensure ordering
 *
 * @par Memory Management:
 * Allocated from per-worker output_pool. Freed by output thread after writing.
 */
typedef struct output_msg {
    uint64_t timestamp_ns;  /**< Event timestamp for ordering */
    uint32_t sequence;      /**< Sequence number (breaks timestamp ties) */
    uint32_t worker_id;     /**< Source worker for debugging */
    size_t len;             /**< Length of formatted data */
    char data[OUTPUT_MSG_MAX_SIZE]; /**< Formatted output string */
} output_msg_t;

/**
 * @brief Deferred event slot for cookie retry
 *
 * Uses flow identity (cookie + timestamp) to detect cache thrashing
 * where a slot gets reused by a different flow before retry completes.
 */
typedef struct deferred_event {
    worker_event_t *event;          /**< Deferred event pointer */
    uint64_t original_cookie;       /**< Expected cookie for identity check */
    uint64_t defer_time_ns;         /**< When event was deferred */
    uint8_t retry_count;            /**< Number of retry attempts */
} deferred_event_t;

/** @} */ /* end threading_event group */

/**
 * @defgroup threading_pool Object Pool
 * @brief Lock-free object pool for zero-allocation fast path
 * @{
 */

/**
 * @brief Lock-free object pool using CK ring free-list
 *
 * Pre-allocates a fixed number of objects at initialization time.
 * Allocation and deallocation are O(1) lock-free operations using
 * a CK ring buffer as a free-list.
 *
 * @par Usage Pattern:
 * @code
 * object_pool_t pool;
 * pool_init(&pool, sizeof(worker_event_t), 4096);
 *
 * worker_event_t *evt = pool_alloc(&pool);
 * if (evt) {
 *     // use evt...
 *     pool_free(&pool, evt);
 * }
 *
 * pool_destroy(&pool);
 * @endcode
 *
 * @par Thread Safety:
 * All operations are lock-free and safe for concurrent access.
 */
typedef struct object_pool {
    void *base;                 /**< Base memory allocation (contiguous block) */
    size_t obj_size;            /**< Size of each object in bytes */
    size_t capacity;            /**< Total number of objects in pool */

    /** Lock-free free-list implemented as CK ring buffer */
    ck_ring_t ring;
    ck_ring_buffer_t *ring_buf;

    /** @name Statistics (atomic for thread-safe reads) */
    /** @{ */
    _Atomic uint64_t alloc_count;       /**< Total successful allocations */
    _Atomic uint64_t free_count;        /**< Total deallocations */
    _Atomic uint64_t alloc_failures;    /**< Allocation failures (pool exhausted) */
    /** @} */
} object_pool_t;

/**
 * @name Pool API
 * @{
 */

/**
 * @brief Initialize object pool with pre-allocated objects
 *
 * @param[out] pool     Pool to initialize
 * @param[in]  obj_size Size of each object in bytes
 * @param[in]  capacity Number of objects to pre-allocate (should be power of 2)
 *
 * @return 0 on success, -1 on allocation failure
 */
int pool_init(object_pool_t *pool, size_t obj_size, size_t capacity);

/**
 * @brief Destroy pool and free all memory
 *
 * @param[in] pool Pool to destroy
 *
 * @warning All allocated objects must be returned before calling this
 */
void pool_destroy(object_pool_t *pool);

/**
 * @brief Allocate object from pool (lock-free)
 *
 * @param[in] pool Pool to allocate from
 *
 * @return Pointer to object, or NULL if pool exhausted
 *
 * @note O(1) lock-free operation
 */
void *pool_alloc(object_pool_t *pool);

/**
 * @brief Return object to pool (lock-free)
 *
 * @param[in] pool Pool to return object to
 * @param[in] obj  Object to free (must have come from this pool)
 *
 * @note O(1) lock-free operation
 */
void pool_free(object_pool_t *pool, void *obj);

/** @} */ /* end Pool API */
/** @} */ /* end threading_pool group */

/**
 * @defgroup threading_cache Per-Worker Cache Structures
 * @brief Worker-local caches for connection metadata
 * @{
 */

/** @} */ /* end threading_cache group */

/**
 * @defgroup threading_state Per-Worker State
 * @brief Worker-local state eliminating cross-thread locking
 * @{
 */

/**
 * @brief Worker-local state container
 *
 * Each worker thread maintains isolated state for all connections it handles.
 * Connection affinity routing ensures the same (pid, ssl_ctx) always routes
 * to the same worker, so no locks are needed on this state.
 *
 * @par State Components:
 * - HTTP/2 connection pool: nghttp2 sessions and HPACK contexts
 * - HTTP/2 stream pool: per-stream request/response state
 * - ALPN cache: protocol negotiation results
 * - Pending bodies: chunked response assembly buffers
 * - HTTP/1.1 cache: request-response correlation
 * - Scratch buffers: decompression and body parsing
 *
 * @par Scaling:
 * Each worker has fixed-size pools. Total system capacity scales linearly
 * with worker count (e.g., 4 workers = 4x connection capacity).
 */
typedef struct worker_state {
    int worker_id;          /**< Worker index (0 to num_workers-1) */

    /** @name HTTP/2 Connection Pool */
    /** @{ */
    h2_connection_local_t *h2_connections;  /**< Connection state array */
    int h2_connection_count;                /**< Active connections */
    int h2_connection_capacity;             /**< Array capacity */
    /** @} */

    /** @name HTTP/2 Stream Pool */
    /** @{ */
    h2_stream_local_t *h2_streams;  /**< Stream state array */
    int h2_stream_count;            /**< Active streams */
    int h2_stream_capacity;         /**< Array capacity */
    /** @} */

    /** @name Scratch Buffers */
    /** @{ */
    uint8_t *decomp_buf;        /**< Decompression output buffer */
    size_t decomp_buf_size;     /**< decomp_buf capacity */
    uint8_t *body_buf;          /**< HTTP/1 body parsing buffer */
    size_t body_buf_size;       /**< body_buf capacity */
    /** @} */

    /** nghttp2 session callbacks (thread-local copy for safety) */
    struct nghttp2_session_callbacks *h2_callbacks;

    bool initialized;           /**< true after successful init */
} worker_state_t;

/**
 * @name Worker State API
 * @{
 */

/**
 * @brief Initialize worker state with allocated pools
 *
 * @param[out] state     State structure to initialize
 * @param[in]  worker_id Worker index (for logging/debugging)
 *
 * @return 0 on success, -1 on allocation failure
 */
int worker_state_init(worker_state_t *state, int worker_id);

/**
 * @brief Cleanup worker state and free all resources
 *
 * @param[in] state State to cleanup
 */
void worker_state_cleanup(worker_state_t *state);

/** @} */ /* end Worker State API */
/** @} */ /* end threading_state group */

/**
 * @defgroup threading_worker Worker Thread
 * @brief Per-worker thread context and API
 * @{
 */

/**
 * @brief Per-worker thread context
 *
 * Each worker thread processes events from its input queue, parses
 * SSL traffic, and enqueues formatted output to the output thread.
 *
 * @par Queue Architecture:
 * - in_ring: Dispatcher enqueues events here (SPSC: single producer)
 * - out_ring: Worker enqueues formatted output (SPSC: single producer)
 *
 * @par NAPI-Style Adaptive Polling:
 * Workers use a budget-based loop similar to Linux NAPI:
 * - Process up to NAPI_BUDGET events per iteration
 * - If work_done < budget: caught up, sleep via epoll_wait
 * - If work_done == budget: heavy traffic, loop immediately
 * This provides zero CPU when idle, zero syscall overhead under load.
 *
 * @par Cookie Retry Queue:
 * Handles SSL-sockops timing race with bitmask-based deferred event queue.
 * Events with valid socket_cookie but missing flow_info are deferred
 * and retried after flow_cache is populated by XDP events.
 *
 * @par Memory Management:
 * - event_pool: Pre-allocated event objects (returned to pool after processing)
 * - output_pool: Pre-allocated output messages (freed by output thread)
 */
typedef struct worker_ctx {
    int worker_id;              /**< Worker index (0 to num_workers-1) */
    pthread_t thread;           /**< Worker thread handle */

    /** @name Input Queue (dispatcher -> worker) */
    /** @{ */
    ck_ring_t in_ring;              /**< Lock-free SPSC ring buffer */
    ck_ring_buffer_t *in_buffer;    /**< Ring buffer storage */
    /** @} */

    /** @name Output Queue (worker -> output thread) */
    /** @{ */
    ck_ring_t out_ring;             /**< Lock-free SPSC ring buffer */
    ck_ring_buffer_t *out_buffer;   /**< Ring buffer storage */
    /** @} */

    /** @name Wake-up Signaling (NAPI-style epoll) */
    /** @{ */
    int wakeup_fd;              /**< eventfd for sleep/wake coordination */
    int epoll_fd;               /**< epoll fd for efficient blocking */
    _Atomic bool has_work;      /**< Fast-path check before sleeping */
    /** @} */

    /** @name Cookie Retry Queue (bitmask-based) */
    /** @{ */
    uint64_t deferred_busy_mask;    /**< Bit N = slot N is occupied */
    deferred_event_t deferred_slots[MAX_DEFERRED_EVENTS]; /**< Fixed array */
    uint64_t retry_tick;            /**< Global tick counter for batch retry */
    _Atomic uint64_t deferred_count;     /**< Current deferred events */
    _Atomic uint64_t deferred_successes; /**< Retry successes */
    _Atomic uint64_t deferred_failures;  /**< Retry failures (gave up) */
    /** @} */

    /** Per-worker protocol state (HTTP/2, caches, buffers) */
    worker_state_t state;

    /** @name Object Pools */
    /** @{ */
    object_pool_t event_pool;   /**< Pool for incoming event objects */
    object_pool_t output_pool;  /**< Pool for outgoing formatted messages */
    /** @} */

    /** @name Statistics (atomic for thread-safe reads) */
    /** @{ */
    _Atomic uint64_t events_processed;  /**< Total events handled */
    _Atomic uint64_t events_dropped;    /**< Events dropped (queue full) */
    _Atomic uint64_t events_misrouted;  /**< Events for flows owned by another worker */
    _Atomic uint64_t spin_cycles;       /**< Time spent in spin wait */
    _Atomic uint64_t yield_cycles;      /**< Time spent in yield wait */
    _Atomic uint64_t sleep_cycles;      /**< Time spent sleeping */
    /** @} */

    _Atomic bool running;       /**< false signals thread to exit */
} worker_ctx_t;

/**
 * @name Worker API
 * @{
 */

/**
 * @brief Initialize worker context
 *
 * Allocates queues, pools, and initializes per-worker state.
 *
 * @param[out] ctx       Worker context to initialize
 * @param[in]  worker_id Worker index
 *
 * @return 0 on success, -1 on failure
 */
int worker_init(worker_ctx_t *ctx, int worker_id);

/**
 * @brief Cleanup worker context and free resources
 *
 * @param[in] ctx Worker context to cleanup
 */
void worker_cleanup(worker_ctx_t *ctx);

/**
 * @brief Worker thread main function
 *
 * Thread entry point. Loops processing events until running becomes false.
 *
 * @param[in] arg Pointer to worker_ctx_t
 *
 * @return NULL
 */
void *worker_thread_main(void *arg);

/** @} */ /* end Worker API */
/** @} */ /* end threading_worker group */

/**
 * @defgroup threading_dispatcher Dispatcher Thread
 * @brief BPF ring buffer consumer and event router
 * @{
 */

/**
 * @brief Process lifecycle callback type
 *
 * Called directly by dispatcher for process exec/exit events.
 * These events are not dispatched to workers - they're handled
 * immediately for dynamic SSL library detection.
 *
 * @param[in] event BPF event data
 * @param[in] ctx   User-provided context
 */
typedef void (*process_lifecycle_cb_t)(const ssl_data_event_t *event, void *ctx);

/**
 * @brief Dispatcher thread context
 *
 * The dispatcher is the single consumer of the BPF ring buffer. It:
 * 1. Polls the BPF ring buffer for SSL events
 * 2. Computes flow affinity hash for each event
 * 3. Routes events to the appropriate worker
 * 4. Handles process lifecycle events directly (not routed to workers)
 *
 * @par Event Routing:
 * Events are routed using flow_hash(pid, ssl_ctx) % num_workers.
 * This ensures all events for a connection go to the same worker.
 *
 * @par XDP Integration:
 * Also handles XDP flow discovery/termination events for network
 * correlation with SSL traffic.
 */
typedef struct dispatcher_ctx {
    pthread_t thread;           /**< Dispatcher thread handle */

    probe_handler_t *handler;   /**< BPF ring buffer handle */

    /** @name Worker Array */
    /** @{ */
    worker_ctx_t *workers;      /**< Array of worker contexts */
    int num_workers;            /**< Number of workers */
    /** @} */

    /** @name Process Lifecycle Callback */
    /** @{ */
    process_lifecycle_cb_t lifecycle_cb; /**< Callback for exec/exit events */
    void *lifecycle_ctx;                 /**< User context for callback */
    /** @} */

    /** @name Statistics (atomic for thread-safe reads) */
    /** @{ */
    _Atomic uint64_t events_dispatched; /**< Events routed to workers */
    _Atomic uint64_t events_dropped;    /**< Events dropped (queue full) */
    /** @} */

    /** @name XDP Statistics */
    /** @{ */
    _Atomic uint64_t xdp_flows_discovered;  /**< New flows detected */
    _Atomic uint64_t xdp_flows_terminated;  /**< Flows closed/timed out */
    _Atomic uint64_t xdp_ambiguous_events;  /**< Ambiguous protocol events */
    _Atomic uint64_t xdp_events_dropped;    /**< XDP events dropped */
    _Atomic uint64_t xdp_debug_samples;     /**< Debug sampling counter */
    /** @} */

    /** @name Shared Pool Flow Manager */
    /** @{ */
    flow_manager_t flow_mgr;    /**< Unified pool with dual indexes */
    /** @} */

    _Atomic bool running;       /**< false signals thread to exit */
} dispatcher_ctx_t;

/**
 * @name Dispatcher API
 * @{
 */

/**
 * @brief Initialize dispatcher context
 *
 * @param[out] ctx         Dispatcher context to initialize
 * @param[in]  handler     BPF ring buffer handle
 * @param[in]  workers     Array of worker contexts
 * @param[in]  num_workers Number of workers
 *
 * @return 0 on success, -1 on failure
 */
int dispatcher_init(dispatcher_ctx_t *ctx, probe_handler_t *handler,
                    worker_ctx_t *workers, int num_workers);

/**
 * @brief Cleanup dispatcher context
 *
 * @param[in] ctx Dispatcher context to cleanup
 */
void dispatcher_cleanup(dispatcher_ctx_t *ctx);

/**
 * @brief Dispatcher thread main function
 *
 * Thread entry point. Polls BPF ring buffer and routes events until
 * running becomes false.
 *
 * @param[in] arg Pointer to dispatcher_ctx_t
 *
 * @return NULL
 */
void *dispatcher_thread_main(void *arg);

/**
 * @brief Set process lifecycle callback for dynamic SSL detection
 *
 * @param[in] ctx      Dispatcher context
 * @param[in] cb       Callback function
 * @param[in] user_ctx User context passed to callback
 */
void dispatcher_set_lifecycle_callback(dispatcher_ctx_t *ctx,
                                        process_lifecycle_cb_t cb,
                                        void *user_ctx);

/**
 * @brief Cleanup all state for a terminated process
 *
 * Called when a process exits. Cleans up HTTP/2 sessions, streams,
 * caches, and pending bodies across all workers.
 *
 * @param[in] ctx Dispatcher context
 * @param[in] pid Process ID that exited
 */
void dispatcher_cleanup_pid(dispatcher_ctx_t *ctx, uint32_t pid);

/**
 * @brief XDP event handler callback
 *
 * Can be registered with bpf_loader_xdp_set_event_callback() to handle
 * XDP flow discovery, termination, and ambiguous traffic events.
 *
 * @param[in] ctx     User context (dispatcher_ctx_t*)
 * @param[in] data    Event data
 * @param[in] data_sz Event data size
 *
 * @return 0 on success
 */
int dispatcher_xdp_event_handler(void *ctx, void *data, size_t data_sz);

/** @} */ /* end Dispatcher API */
/** @} */ /* end threading_dispatcher group */

/**
 * @defgroup threading_output Output Thread
 * @brief Serializes formatted output from all workers
 * @{
 */

/**
 * @brief Output thread context
 *
 * The output thread collects formatted messages from all worker output
 * queues and writes them to stdout or a file. It ensures ordered output
 * even with parallel workers.
 *
 * @par Collection Strategy:
 * Round-robins across worker output queues, collecting messages and
 * writing them in timestamp order.
 *
 * @par Ordering:
 * Messages are written in timestamp order using output_msg_t::timestamp_ns.
 * The sequence field breaks ties for events with identical timestamps.
 */
typedef struct output_ctx {
    pthread_t thread;           /**< Output thread handle */

    /** @name Worker Access */
    /** @{ */
    worker_ctx_t *workers;      /**< Worker array (for output queue access) */
    int num_workers;            /**< Number of workers to collect from */
    /** @} */

    FILE *output_file;          /**< Output destination (NULL = stdout) */

    /** @name Statistics (atomic for thread-safe reads) */
    /** @{ */
    _Atomic uint64_t messages_written;  /**< Total messages written */
    _Atomic uint64_t bytes_written;     /**< Total bytes written */
    /** @} */

    _Atomic bool running;       /**< false signals thread to exit */
} output_ctx_t;

/**
 * @name Output Thread API
 * @{
 */

/**
 * @brief Initialize output thread context
 *
 * @param[out] ctx         Output context to initialize
 * @param[in]  workers     Worker array (for output queue access)
 * @param[in]  num_workers Number of workers
 * @param[in]  output_file Output destination (NULL for stdout)
 *
 * @return 0 on success, -1 on failure
 */
int output_init(output_ctx_t *ctx, worker_ctx_t *workers, int num_workers,
                FILE *output_file);

/**
 * @brief Cleanup output thread context
 *
 * @param[in] ctx Output context to cleanup
 */
void output_cleanup(output_ctx_t *ctx);

/**
 * @brief Output thread main function
 *
 * Thread entry point. Collects and writes output until running becomes false.
 *
 * @param[in] arg Pointer to output_ctx_t
 *
 * @return NULL
 */
void *output_thread_main(void *arg);

/** @} */ /* end Output Thread API */
/** @} */ /* end threading_output group */

/**
 * @defgroup threading_manager Threading Manager
 * @brief Top-level coordinator for all threads
 * @{
 */

/**
 * @brief Main threading manager - coordinates all threads
 *
 * The threading manager is the top-level controller for the threading
 * subsystem. It owns all thread contexts and coordinates startup/shutdown.
 *
 * @par Thread Ownership:
 * - 1 dispatcher thread
 * - N worker threads (configurable, typically CPU cores - 1)
 * - 1 output thread
 *
 * @par Lifecycle:
 * 1. threading_init() - allocate and initialize contexts
 * 2. threading_start() - start all threads
 * 3. (run until shutdown requested)
 * 4. threading_shutdown() - signal threads to stop
 * 5. threading_cleanup() - join threads and free resources
 */
typedef struct threading_mgr {
    /** @name Thread Contexts */
    /** @{ */
    dispatcher_ctx_t dispatcher;            /**< Dispatcher context */
    worker_ctx_t workers[MAX_WORKERS];      /**< Worker contexts array */
    output_ctx_t output;                    /**< Output thread context */
    /** @} */

    /** @name Configuration */
    /** @{ */
    int num_workers;        /**< Active worker count */
    bool pin_cores;         /**< Pin threads to CPU cores */
    /** @} */

    /** @name State */
    /** @{ */
    bool initialized;               /**< true after successful init */
    _Atomic bool shutdown_requested; /**< Signals shutdown in progress */
    /** @} */
} threading_mgr_t;

/**
 * @name Threading Manager API
 * @{
 */

/**
 * @brief Initialize threading manager
 *
 * Allocates and initializes all thread contexts but does not start threads.
 *
 * @param[out] mgr         Manager to initialize
 * @param[in]  num_workers Number of worker threads (0 = auto-detect)
 * @param[in]  pin_cores   Pin threads to specific CPU cores
 *
 * @return 0 on success, -1 on failure
 *
 * @note Use threading_default_workers() to determine optimal worker count
 */
int threading_init(threading_mgr_t *mgr, int num_workers, bool pin_cores);

/**
 * @brief Start all threads
 *
 * Starts dispatcher, workers, and output threads.
 *
 * @param[in] mgr     Initialized manager
 * @param[in] handler BPF ring buffer handle for dispatcher
 *
 * @return 0 on success, -1 on failure
 */
int threading_start(threading_mgr_t *mgr, probe_handler_t *handler);

/**
 * @brief Request graceful shutdown
 *
 * Signals all threads to stop. Call threading_cleanup() to wait for
 * threads to exit and free resources.
 *
 * @param[in] mgr Manager to shutdown
 */
void threading_shutdown(threading_mgr_t *mgr);

/**
 * @brief Wait for threads and cleanup resources
 *
 * Joins all threads and frees allocated memory.
 *
 * @param[in] mgr Manager to cleanup
 *
 * @note Must call threading_shutdown() first
 */
void threading_cleanup(threading_mgr_t *mgr);

/**
 * @brief Print threading statistics
 *
 * Outputs statistics for dispatcher, workers, and output thread
 * including events processed, dropped, and wait cycle breakdown.
 *
 * @param[in] mgr Manager to print stats for
 */
void threading_print_stats(threading_mgr_t *mgr);

/**
 * @brief Calculate optimal worker count
 *
 * Returns CPU_CORES - 2 (reserving cores for dispatcher and output),
 * with minimum of 1 and maximum of MAX_WORKERS.
 *
 * @return Recommended number of worker threads
 */
int threading_default_workers(void);

/** @} */ /* end Threading Manager API */
/** @} */ /* end threading_manager group */

/**
 * @defgroup threading_util Utility Functions
 * @brief Helper functions for threading subsystem
 * @{
 */

/**
 * @brief Compute flow affinity hash
 *
 * Uses FNV-1a hash algorithm for good distribution across workers.
 * The same (pid, ssl_ctx) pair always produces the same hash, ensuring
 * connection affinity.
 *
 * @param[in] pid     Process ID
 * @param[in] ssl_ctx SSL context pointer
 *
 * @return 32-bit hash value
 *
 * @par Algorithm:
 * FNV-1a with 64-bit prime, truncated to 32 bits:
 * - XOR each input component
 * - Multiply by FNV prime (1099511628211)
 * - Include both halves of ssl_ctx for better distribution
 */
static inline uint32_t flow_hash(uint32_t pid, uint64_t ssl_ctx) {
    uint64_t hash = 14695981039346656037ULL;  /* FNV offset basis */
    hash ^= pid;
    hash *= 1099511628211ULL;                  /* FNV prime */
    hash ^= ssl_ctx;
    hash *= 1099511628211ULL;
    hash ^= (ssl_ctx >> 32);
    hash *= 1099511628211ULL;
    return (uint32_t)hash;
}

/**
 * @brief Get worker ID for a connection using socket_cookie-first strategy
 *
 * Uses socket_cookie for sharding when available (preferred). This ensures
 * XDP packets and SSL uprobe events for the same connection land on the
 * same worker, enabling correlation without cross-thread synchronization.
 *
 * Falls back to flow_hash(pid, ssl_ctx) when socket_cookie is unavailable
 * (e.g., before sockops has cached the cookie, or for non-socket events).
 *
 * @par Research Reference:
 * "Using (pid, ssl_ctx) for sharding is problematic because XDP packets
 * have no knowledge of ssl_ctx address. By sharding on socket_cookie,
 * you ensure all data for a flow—regardless of whether it's from XDP
 * or a Uprobe—lands in the same worker's queue."
 *
 * @param[in] socket_cookie Socket cookie (0 if unavailable)
 * @param[in] pid           Process ID (fallback)
 * @param[in] ssl_ctx       SSL context pointer (fallback)
 * @param[in] num_workers   Total number of workers
 *
 * @return Worker index (0 to num_workers-1)
 */
static inline int get_worker_id_ex(uint64_t socket_cookie, uint32_t pid,
                                    uint64_t ssl_ctx, int num_workers) {
    if (socket_cookie != 0) {
        /* Preferred: use socket_cookie for XDP-SSL correlation */
        return (int)(socket_cookie % (uint64_t)num_workers);
    }
    /* Fallback: use pid+ssl_ctx hash when cookie unavailable */
    return flow_hash(pid, ssl_ctx) % num_workers;
}

/**
 * @brief Legacy get_worker_id for backward compatibility
 *
 * @deprecated Use get_worker_id_ex() with socket_cookie for XDP correlation
 */
static inline int get_worker_id(uint32_t pid, uint64_t ssl_ctx, int num_workers) {
    return flow_hash(pid, ssl_ctx) % num_workers;
}

/**
 * @brief Get current time in nanoseconds
 *
 * Returns CLOCK_MONOTONIC time for consistent timestamps.
 *
 * @return Nanoseconds since arbitrary epoch
 */
uint64_t get_time_ns(void);

/**
 * @brief Get thread-local worker state
 *
 * Returns the worker_state_t for the current worker thread.
 * Used by protocol parsers to access per-worker caches.
 *
 * @return Worker state pointer, or NULL if not a worker thread
 */
worker_state_t *get_current_worker_state(void);

/**
 * @brief Set thread-local worker state
 *
 * Called during worker thread initialization to set up TLS.
 *
 * @param[in] state Worker state to associate with current thread
 */
void set_current_worker_state(worker_state_t *state);

/** @} */ /* end threading_util group */

/**
 * @defgroup threading_h2mgmt Per-Worker HTTP/2 Management
 * @brief Worker-local HTTP/2 session and stream management
 * @{
 */

/**
 * @name Connection Management
 * @{
 */

/**
 * @brief Get or create HTTP/2 connection state
 *
 * @param[in] state   Worker state
 * @param[in] pid     Process ID
 * @param[in] ssl_ctx SSL context pointer
 * @param[in] create  true to create if not found
 *
 * @return Connection state, or NULL if not found/couldn't create
 */
h2_connection_local_t *worker_get_h2_connection(worker_state_t *state,
                                                  uint32_t pid, uint64_t ssl_ctx,
                                                  bool create);

/**
 * @brief Cleanup HTTP/2 connection and associated streams
 *
 * Destroys nghttp2 session, HPACK inflater, and all streams.
 *
 * @param[in] state Worker state
 * @param[in] conn  Connection to cleanup
 */
void worker_cleanup_h2_connection(worker_state_t *state, h2_connection_local_t *conn);

/** @} */

/**
 * @name Stream Management
 * @{
 */

/**
 * @brief Get or create HTTP/2 stream state
 *
 * @param[in] state     Worker state
 * @param[in] pid       Process ID
 * @param[in] ssl_ctx   SSL context pointer
 * @param[in] stream_id HTTP/2 stream identifier
 * @param[in] create    true to create if not found
 *
 * @return Stream state, or NULL if not found/couldn't create
 */
h2_stream_local_t *worker_get_h2_stream(worker_state_t *state,
                                          uint32_t pid, uint64_t ssl_ctx,
                                          int32_t stream_id, bool create);

/**
 * @brief Free HTTP/2 stream state
 *
 * @param[in] state  Worker state
 * @param[in] stream Stream to free
 */
void worker_free_h2_stream(worker_state_t *state, h2_stream_local_t *stream);

/**
 * @brief Cleanup all streams for a connection
 *
 * Called when connection closes to free all associated streams.
 *
 * @param[in] state   Worker state
 * @param[in] pid     Process ID
 * @param[in] ssl_ctx SSL context pointer
 */
void worker_cleanup_h2_streams_for_connection(worker_state_t *state,
                                                uint32_t pid, uint64_t ssl_ctx);

/** @} */
/** @} */ /* end threading_h2mgmt group */

/**
 * @defgroup threading_stats Statistics Functions
 * @brief Thread-safe statistics accessors
 * @{
 */

/**
 * @brief Get object pool statistics
 *
 * @param[in]  pool     Pool to query
 * @param[out] allocs   Total allocations (optional, NULL to skip)
 * @param[out] frees    Total deallocations (optional)
 * @param[out] failures Allocation failures (optional)
 */
void pool_get_stats(object_pool_t *pool, uint64_t *allocs, uint64_t *frees,
                    uint64_t *failures);

/**
 * @brief Get dispatcher statistics
 *
 * @param[in]  ctx        Dispatcher context
 * @param[out] dispatched Events dispatched to workers (optional)
 * @param[out] dropped    Events dropped (optional)
 */
void dispatcher_get_stats(dispatcher_ctx_t *ctx, uint64_t *dispatched,
                          uint64_t *dropped);

/**
 * @brief Get dispatcher XDP statistics
 *
 * @param[in]  ctx              Dispatcher context
 * @param[out] flows_discovered New flows detected (optional)
 * @param[out] flows_terminated Flows closed (optional)
 * @param[out] ambiguous        Ambiguous events (optional)
 * @param[out] dropped          Dropped XDP events (optional)
 */
void dispatcher_get_xdp_stats(dispatcher_ctx_t *ctx, uint64_t *flows_discovered,
                               uint64_t *flows_terminated, uint64_t *ambiguous,
                               uint64_t *dropped);

/**
 * @brief Get output thread statistics
 *
 * @param[in]  ctx      Output context
 * @param[out] messages Messages written (optional)
 * @param[out] bytes    Bytes written (optional)
 */
void output_get_stats(output_ctx_t *ctx, uint64_t *messages, uint64_t *bytes);

/** @} */ /* end threading_stats group */

/**
 * @defgroup threading_outhelp Output Helpers
 * @brief Worker functions for enqueueing formatted output
 * @{
 */

/**
 * @brief Allocate output message from worker's pool
 *
 * @param[in] worker Worker context
 *
 * @return Output message, or NULL if pool exhausted
 */
output_msg_t *output_alloc(worker_ctx_t *worker);

/**
 * @brief Enqueue output message to output thread
 *
 * @param[in] worker Worker context
 * @param[in] msg    Message to enqueue (ownership transferred)
 *
 * @return 0 on success, -1 if queue full
 */
int output_enqueue(worker_ctx_t *worker, output_msg_t *msg);

/**
 * @brief Format and enqueue output message (printf-style)
 *
 * Convenience function combining output_alloc, snprintf, and output_enqueue.
 *
 * @param[in] worker Worker context
 * @param[in] fmt    printf format string
 * @param[in] ...    Format arguments
 *
 * @return 0 on success, -1 on failure
 */
int output_write(worker_ctx_t *worker, const char *fmt, ...);

/** @} */ /* end threading_outhelp group */

/**
 * @defgroup threading_helpers Manager Helpers
 * @brief Global manager access functions
 * @{
 */

/**
 * @brief Check if threading manager is running
 *
 * @param[in] mgr Manager to check
 *
 * @return true if threads are running
 */
bool threading_is_running(threading_mgr_t *mgr);

/**
 * @brief Get global threading manager instance
 *
 * Returns the singleton manager created by threading_init().
 *
 * @return Manager pointer, or NULL if not initialized
 */
threading_mgr_t *threading_get_manager(void);

/** @} */ /* end threading_helpers group */

#endif /* THREADING_H */
