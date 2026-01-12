/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * threading.h - Multi-threaded event processing infrastructure
 *
 * Architecture:
 *   Main Thread -> Dispatcher Thread -> Worker Threads -> Output Thread
 *
 * The dispatcher polls BPF ring buffer and routes events to workers
 * using connection affinity (same pid+ssl_ctx always goes to same worker).
 * Workers process events with per-worker state (no locks needed).
 * Output thread serializes formatted output to stdout.
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

/* ============================================================================
 * Configuration Constants
 * ============================================================================ */

/* Ring buffer sizes (must be power of 2) */
#define EVENT_RING_SIZE         4096
#define OUTPUT_RING_SIZE        4096

/* Object pool sizes */
#define EVENT_POOL_SIZE         4096
#define OUTPUT_POOL_SIZE        1024

/* Adaptive wait parameters */
#define SPIN_ITERATIONS         1000    /* ~1-2 microseconds */
#define YIELD_ITERATIONS        10      /* ~10-100 microseconds */
#define POLL_TIMEOUT_MS         10      /* 10ms max sleep */

/* Batch processing */
#define BATCH_SIZE              32

/* Per-worker limits (scaled by worker count) */
#define MAX_H2_SESSIONS_PER_WORKER      16
#define MAX_H2_STREAMS_PER_WORKER       128
#define MAX_ALPN_CACHE_PER_WORKER       32
#define MAX_PENDING_BODIES_PER_WORKER   4

/* Maximum workers */
#define MAX_WORKERS             16

/* Output message max size */
#define OUTPUT_MSG_MAX_SIZE     (64 * 1024)  /* 64KB formatted output */

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

struct nghttp2_session;
struct nghttp2_hd_inflater;
struct nghttp2_session_callbacks;

/* ============================================================================
 * HTTP/2 Structures (per-worker local versions)
 * ============================================================================ */

/* Response reassembly buffer size (per-worker) */
#define H2_REASSEMBLY_BUF_SIZE 65536

/* Note: h2_stream_state_t and H2_BODY_BUFFER_SIZE are defined in http2.h */

/*
 * Per-connection HTTP/2 session state (worker-local)
 */
typedef struct h2_connection_local {
    uint32_t pid;
    uint64_t ssl_ctx;
    bool active;

    /* nghttp2 server session for parsing requests */
    struct nghttp2_session *server_session;

    /* HPACK inflater for decoding response headers */
    struct nghttp2_hd_inflater *response_inflater;

    /* Connection state */
    bool client_preface_seen;
    bool server_settings_seen;

    /* Response reassembly buffer for fragmented frames */
    uint8_t *response_buf;
    size_t response_buf_len;

    /* Timestamp for LRU cleanup */
    uint64_t last_activity_ns;

    /* Process name cache */
    char comm[TASK_COMM_LEN];

    /* ALPN negotiated protocol */
    char alpn_proto[16];
} h2_connection_local_t;

/*
 * Per-stream HTTP/2 state (worker-local)
 */
typedef struct h2_stream_local {
    /* Key */
    uint32_t pid;
    uint64_t ssl_ctx;
    int32_t stream_id;
    bool active;

    /* State machine */
    h2_stream_state_t state;

    /* Request info */
    char method[MAX_METHOD_LEN];
    char path[MAX_PATH_LEN];
    char authority[MAX_HEADER_VALUE];
    char scheme[16];
    uint64_t request_time_ns;
    bool request_headers_done;
    bool request_complete;

    /* Response info */
    int status_code;
    char content_type[256];
    char content_encoding[64];
    size_t content_length;
    uint64_t response_time_ns;
    bool response_headers_done;
    bool response_complete;

    /* Headers storage */
    http_header_t headers[MAX_HEADERS];
    int header_count;
    bool headers_displayed;

    /* Body accumulation */
    uint8_t *body_buf;
    size_t body_buf_size;
    size_t body_len;

    /* Metadata for display */
    uint64_t delta_ns;
    char comm[TASK_COMM_LEN];
} h2_stream_local_t;

/* ============================================================================
 * Event Structure (for inter-thread communication)
 * ============================================================================ */

/*
 * Worker event - copied from BPF ring buffer
 * This is what gets enqueued to worker input rings
 */
typedef struct worker_event {
    /* BPF event metadata */
    uint64_t timestamp_ns;
    uint64_t delta_ns;
    uint64_t ssl_ctx;
    uint32_t pid;
    uint32_t tid;
    uint32_t uid;
    uint32_t event_type;
    int32_t buf_filled;
    char comm[TASK_COMM_LEN];

    /* Pre-computed routing */
    uint32_t worker_id;
    uint32_t flow_hash;

    /* Payload (variable length, up to MAX_BUF_SIZE) */
    uint32_t data_len;
    uint8_t data[MAX_BUF_SIZE];
} worker_event_t;

/* ============================================================================
 * Output Message Structure
 * ============================================================================ */

/*
 * Formatted output message - produced by workers, consumed by output thread
 */
typedef struct output_msg {
    uint64_t timestamp_ns;      /* For ordering */
    uint32_t sequence;          /* Sequence within same timestamp */
    uint32_t worker_id;         /* Source worker */
    size_t len;                 /* Output length */
    char data[OUTPUT_MSG_MAX_SIZE];
} output_msg_t;

/* ============================================================================
 * Object Pool
 * ============================================================================ */

/*
 * Lock-free object pool using a simple free-list
 * Pre-allocates objects to avoid malloc in hot path
 */
typedef struct object_pool {
    void *base;                 /* Base allocation */
    size_t obj_size;            /* Size of each object */
    size_t capacity;            /* Total objects */

    /* Lock-free free-list */
    ck_ring_t ring;
    ck_ring_buffer_t *ring_buf;

    /* Statistics */
    _Atomic uint64_t alloc_count;
    _Atomic uint64_t free_count;
    _Atomic uint64_t alloc_failures;
} object_pool_t;

/* Pool API */
int pool_init(object_pool_t *pool, size_t obj_size, size_t capacity);
void pool_destroy(object_pool_t *pool);
void *pool_alloc(object_pool_t *pool);
void pool_free(object_pool_t *pool, void *obj);

/* ============================================================================
 * ALPN Cache Entry (per-worker)
 * ============================================================================ */

typedef struct {
    uint32_t pid;
    uint64_t ssl_ctx;
    char alpn_proto[16];
    bool active;
} alpn_cache_entry_t;

/* ============================================================================
 * Pending Body Entry (per-worker)
 * ============================================================================ */

typedef struct {
    uint32_t pid;
    uint64_t ssl_ctx;
    size_t expected_len;
    size_t received_len;
    char content_type[256];
    char content_encoding[64];
    bool active;
    bool header_printed;
    bool needs_decompression;
    uint8_t *accum_buf;         /* Dynamically allocated */
    size_t accum_len;
    size_t accum_capacity;
} pending_body_entry_t;

/* ============================================================================
 * HTTP/1.1 Request Cache Entry (per-worker)
 * ============================================================================ */

#define MAX_H1_REQUEST_CACHE_PER_WORKER 16

typedef struct {
    uint32_t pid;
    uint64_t ssl_ctx;
    char method[16];
    char path[512];
    char host[256];      /* From Host header */
    bool active;
} h1_request_entry_t;

/* ============================================================================
 * Per-Worker State
 * ============================================================================ */

/*
 * Worker-local state - replaces global arrays
 * Each worker has isolated state, eliminating need for locks
 */
typedef struct worker_state {
    int worker_id;

    /* HTTP/2 connection pool */
    h2_connection_local_t *h2_connections;
    int h2_connection_count;
    int h2_connection_capacity;

    /* HTTP/2 stream pool */
    h2_stream_local_t *h2_streams;
    int h2_stream_count;
    int h2_stream_capacity;

    /* ALPN cache */
    alpn_cache_entry_t alpn_cache[MAX_ALPN_CACHE_PER_WORKER];
    int alpn_cache_count;

    /* Pending bodies */
    pending_body_entry_t pending_bodies[MAX_PENDING_BODIES_PER_WORKER];
    int pending_body_count;

    /* HTTP/1.1 request cache (for request-response correlation) */
    h1_request_entry_t h1_request_cache[MAX_H1_REQUEST_CACHE_PER_WORKER];
    int h1_request_count;

    /* Decompression buffer (per-worker to avoid static buffer races) */
    uint8_t *decomp_buf;
    size_t decomp_buf_size;

    /* HTTP/1 body buffer */
    uint8_t *body_buf;
    size_t body_buf_size;

    /* nghttp2 session callbacks (thread-local copy) */
    struct nghttp2_session_callbacks *h2_callbacks;

    /* Initialization flag */
    bool initialized;
} worker_state_t;

/* Worker state API */
int worker_state_init(worker_state_t *state, int worker_id);
void worker_state_cleanup(worker_state_t *state);

/* ============================================================================
 * Worker Context
 * ============================================================================ */

/*
 * Per-worker thread context
 */
typedef struct worker_ctx {
    int worker_id;
    pthread_t thread;

    /* Input queue (dispatcher -> worker) */
    ck_ring_t in_ring;
    ck_ring_buffer_t *in_buffer;

    /* Output queue (worker -> output thread) */
    ck_ring_t out_ring;
    ck_ring_buffer_t *out_buffer;

    /* Wake-up signaling */
    int wakeup_fd;              /* eventfd for sleep/wake */
    _Atomic bool has_work;      /* Fast-path check before sleep */

    /* Per-worker state (HTTP/2 sessions, caches, buffers) */
    worker_state_t state;

    /* Object pools */
    object_pool_t event_pool;   /* For incoming events */
    object_pool_t output_pool;  /* For outgoing formatted messages */

    /* Statistics */
    _Atomic uint64_t events_processed;
    _Atomic uint64_t events_dropped;
    _Atomic uint64_t spin_cycles;
    _Atomic uint64_t yield_cycles;
    _Atomic uint64_t sleep_cycles;

    /* Control */
    _Atomic bool running;
} worker_ctx_t;

/* Worker API */
int worker_init(worker_ctx_t *ctx, int worker_id);
void worker_cleanup(worker_ctx_t *ctx);
void *worker_thread_main(void *arg);

/* ============================================================================
 * Dispatcher Context
 * ============================================================================ */

/*
 * Dispatcher thread context
 * Polls BPF ring buffer and routes events to workers
 */
typedef struct dispatcher_ctx {
    pthread_t thread;

    /* BPF ring buffer handle */
    probe_handler_t *handler;

    /* Worker array */
    worker_ctx_t *workers;
    int num_workers;

    /* Statistics */
    _Atomic uint64_t events_dispatched;
    _Atomic uint64_t events_dropped;

    /* XDP statistics */
    _Atomic uint64_t xdp_flows_discovered;
    _Atomic uint64_t xdp_flows_terminated;
    _Atomic uint64_t xdp_ambiguous_events;
    _Atomic uint64_t xdp_events_dropped;
    _Atomic uint64_t xdp_debug_samples;      /* Debug output sampling counter */

    /* Control */
    _Atomic bool running;
} dispatcher_ctx_t;

/* Dispatcher API */
int dispatcher_init(dispatcher_ctx_t *ctx, probe_handler_t *handler,
                    worker_ctx_t *workers, int num_workers);
void dispatcher_cleanup(dispatcher_ctx_t *ctx);
void *dispatcher_thread_main(void *arg);

/* XDP event handler - can be used as callback for bpf_loader_xdp_set_event_callback()
 * Handles flow discovery, termination, and ambiguous traffic events */
int dispatcher_xdp_event_handler(void *ctx, void *data, size_t data_sz);

/* ============================================================================
 * Output Context
 * ============================================================================ */

/*
 * Output thread context
 * Collects formatted output from workers and serializes to stdout
 */
typedef struct output_ctx {
    pthread_t thread;

    /* Worker array (for output ring access) */
    worker_ctx_t *workers;
    int num_workers;

    /* Output file (NULL = stdout) */
    FILE *output_file;

    /* Statistics */
    _Atomic uint64_t messages_written;
    _Atomic uint64_t bytes_written;

    /* Control */
    _Atomic bool running;
} output_ctx_t;

/* Output API */
int output_init(output_ctx_t *ctx, worker_ctx_t *workers, int num_workers,
                FILE *output_file);
void output_cleanup(output_ctx_t *ctx);
void *output_thread_main(void *arg);

/* ============================================================================
 * Threading Manager
 * ============================================================================ */

/*
 * Main threading manager - coordinates all threads
 */
typedef struct threading_mgr {
    /* Thread contexts */
    dispatcher_ctx_t dispatcher;
    worker_ctx_t workers[MAX_WORKERS];
    output_ctx_t output;

    /* Configuration */
    int num_workers;
    bool pin_cores;

    /* State */
    bool initialized;
    _Atomic bool shutdown_requested;
} threading_mgr_t;

/* Threading manager API */
int threading_init(threading_mgr_t *mgr, int num_workers, bool pin_cores);
int threading_start(threading_mgr_t *mgr, probe_handler_t *handler);
void threading_shutdown(threading_mgr_t *mgr);
void threading_cleanup(threading_mgr_t *mgr);
void threading_print_stats(threading_mgr_t *mgr);

/* Calculate default worker count based on CPU cores */
int threading_default_workers(void);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/* Flow affinity hash - same (pid, ssl_ctx) always maps to same worker */
static inline uint32_t flow_hash(uint32_t pid, uint64_t ssl_ctx) {
    /* FNV-1a hash for good distribution */
    uint64_t hash = 14695981039346656037ULL;
    hash ^= pid;
    hash *= 1099511628211ULL;
    hash ^= ssl_ctx;
    hash *= 1099511628211ULL;
    hash ^= (ssl_ctx >> 32);
    hash *= 1099511628211ULL;
    return (uint32_t)hash;
}

/* Get worker ID for a given flow */
static inline int get_worker_id(uint32_t pid, uint64_t ssl_ctx, int num_workers) {
    return flow_hash(pid, ssl_ctx) % num_workers;
}

/* Get current time in nanoseconds */
uint64_t get_time_ns(void);

/* Thread-local accessor for current worker state */
worker_state_t *get_current_worker_state(void);
void set_current_worker_state(worker_state_t *state);

/* ============================================================================
 * Per-Worker HTTP/2 Management Functions
 * ============================================================================ */

/* Connection management */
h2_connection_local_t *worker_get_h2_connection(worker_state_t *state,
                                                  uint32_t pid, uint64_t ssl_ctx,
                                                  bool create);
void worker_cleanup_h2_connection(worker_state_t *state, h2_connection_local_t *conn);

/* Stream management */
h2_stream_local_t *worker_get_h2_stream(worker_state_t *state,
                                          uint32_t pid, uint64_t ssl_ctx,
                                          int32_t stream_id, bool create);
void worker_free_h2_stream(worker_state_t *state, h2_stream_local_t *stream);
void worker_cleanup_h2_streams_for_connection(worker_state_t *state,
                                                uint32_t pid, uint64_t ssl_ctx);

/* ALPN cache */
const char *worker_get_alpn(worker_state_t *state, uint32_t pid, uint64_t ssl_ctx);
void worker_set_alpn(worker_state_t *state, uint32_t pid, uint64_t ssl_ctx,
                       const char *alpn);

/* Pending body management */
pending_body_entry_t *worker_find_pending_body(worker_state_t *state,
                                                  uint32_t pid, uint64_t ssl_ctx);
pending_body_entry_t *worker_create_pending_body(worker_state_t *state,
                                                    uint32_t pid, uint64_t ssl_ctx,
                                                    size_t expected_len,
                                                    const char *content_type,
                                                    const char *content_encoding);
void worker_clear_pending_body(worker_state_t *state, pending_body_entry_t *entry);
void worker_cleanup_pending_bodies_pid(worker_state_t *state, uint32_t pid);

/* HTTP/1.1 request cache management (for request-response correlation) */
h1_request_entry_t *worker_find_h1_request(worker_state_t *state,
                                            uint32_t pid, uint64_t ssl_ctx);
void worker_set_h1_request(worker_state_t *state, uint32_t pid, uint64_t ssl_ctx,
                           const char *method, const char *path, const char *host);
void worker_clear_h1_request(worker_state_t *state, uint32_t pid, uint64_t ssl_ctx);

/* ============================================================================
 * Statistics Functions
 * ============================================================================ */

void pool_get_stats(object_pool_t *pool, uint64_t *allocs, uint64_t *frees,
                    uint64_t *failures);
void dispatcher_get_stats(dispatcher_ctx_t *ctx, uint64_t *dispatched,
                          uint64_t *dropped);
void dispatcher_get_xdp_stats(dispatcher_ctx_t *ctx, uint64_t *flows_discovered,
                               uint64_t *flows_terminated, uint64_t *ambiguous,
                               uint64_t *dropped);
void output_get_stats(output_ctx_t *ctx, uint64_t *messages, uint64_t *bytes);

/* ============================================================================
 * Output Helpers (for workers to enqueue formatted output)
 * ============================================================================ */

output_msg_t *output_alloc(worker_ctx_t *worker);
int output_enqueue(worker_ctx_t *worker, output_msg_t *msg);
int output_write(worker_ctx_t *worker, const char *fmt, ...);

/* ============================================================================
 * Manager Helpers
 * ============================================================================ */

bool threading_is_running(threading_mgr_t *mgr);
threading_mgr_t *threading_get_manager(void);

#endif /* THREADING_H */
