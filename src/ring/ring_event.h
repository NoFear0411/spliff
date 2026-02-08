/**
 * @file ring_event.h
 * @brief 56-byte ring event routing header for protocol-blind SPMC dispatch
 *
 * @details Fixed-size routing envelope that carries events through the SPMC
 * ring from dispatcher to workers. Designed for zero pointer-chasing:
 * workers use socket_cookie for session lookup, not flow_ctx pointers.
 *
 * @par Design Contract
 * This structure is the **Layer 1 transport header**. It MUST NOT grow
 * beyond 56 bytes. Protocol-specific metadata belongs in:
 * - **Session Registry** (Layer 2): per-connection state, looked up via socket_cookie
 * - **Extension sidecar** (Layer 2): per-event metadata via ext.offset into metadata slab
 * - **Protocol Modules** (Layer 3): parser state, heuristic scores
 *
 * Adding a new protocol or heuristic MUST NOT require changes to this file.
 * See ADR-002 for the three-layer extensibility architecture.
 *
 * @par Slot Layout (64 bytes = 1 hardware cache line)
 * @code
 *   [0..7]   seq            Vyukov sequence (atomic, ring-managed)
 *   [8..63]  ring_event_t   This structure (56 bytes)
 * @endcode
 *
 * @par Routing Word (64-bit, bit-packed)
 * All routing metadata in a single register-width load:
 * @code
 *   [0..7]   flags            EVENT_FLAG_* bits
 *   [8..15]  preferred_worker Worker affinity hint (0-255)
 *   [16..23] event_type       EVENT_TYPE_* classification
 *   [24..27] probe_source     PROBE_SOURCE_* origin (4 bits)
 *   [28..31] reserved         Future use (4 bits)
 *   [32..63] generation       Stale hint detection (32 bits)
 * @endcode
 *
 * @par Four Probe Sources
 * @code
 *   XDP       → NIC ingress: 5-tuple, payload, protocol detection
 *   uprobes   → Userspace libs: TLS decrypt, library-specific events
 *   sockops   → Socket layer: connect/accept/close, socket options (the glue)
 *   kprobes   → Kernel funcs: plaintext TCP/UDP, DNS, non-TLS traffic
 * @endcode
 * socket_cookie (set by sockops at connect/accept) is the universal correlator
 * that ties all four probe sources into a single session.
 *
 * @see docs/ARCHITECTURE-DECISIONS.md ADR-001 (SPMC transport)
 * @see docs/ARCHITECTURE-DECISIONS.md ADR-002 (Three-layer extensibility)
 * @see src/ring/spmc_ring.h SPMC ring transport
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef SPLIFF_RING_EVENT_H
#define SPLIFF_RING_EVENT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * @defgroup ring_event Ring Event
 * @brief 56-byte routing header for protocol-blind SPMC dispatch
 * @{
 */

/*============================================================================
 * Event Flags (bits [0..7] of routing word)
 *============================================================================*/

/** Event requires sticky worker affinity (stateful protocol) */
#define EVENT_FLAG_STATEFUL     (1U << 0)

/** High-priority event (FIN/RST, connection close) */
#define EVENT_FLAG_URGENT       (1U << 1)

/** First data for this flow (triggers lazy session init) */
#define EVENT_FLAG_FIRST_DATA   (1U << 2)

/** XDP metadata event (network-layer correlation) */
#define EVENT_FLAG_XDP          (1U << 3)

/**
 * @brief Event has been routed through an overflow queue (hop-limit guard)
 *
 * Set by workers when pushing to another worker's MPSC overflow queue.
 * When a worker dequeues an event with this flag, it MUST process locally
 * regardless of affinity — prevents ping-pong oscillation under load.
 *
 * @par Anti-Oscillation
 * Without this: Worker A defers to B → B's overflow full → B defers to A → loop.
 * With this: Worker A sets ROUTED → B sees ROUTED → B processes locally.
 */
#define EVENT_FLAG_ROUTED       (1U << 5)

/**
 * @brief Last 8 bytes carry extended metadata, not flow_key_hash
 *
 * When set, the event's last field is interpreted as ext (offset + size
 * into per-ring metadata slab) rather than a 5-tuple hash.
 * The event_type determines semantics. Workers check this flag before
 * accessing the union to avoid misinterpretation.
 */
#define EVENT_FLAG_HAS_EXT      (1U << 4)

/*============================================================================
 * Probe Source (bits [24..27] of routing word)
 *============================================================================*/

/**
 * @brief eBPF hook origin that generated this event
 *
 * Identifies which probe layer produced the event. The dispatcher sets
 * this when constructing the routing word. Workers can use it for
 * source-specific handling or filtering.
 *
 * @note 4 bits = 16 sources. Currently 7 defined, 9 reserved.
 */
typedef enum {
    PROBE_SOURCE_UNKNOWN    = 0,   /**< Source not set (legacy events) */
    PROBE_SOURCE_XDP        = 1,   /**< XDP hook (NIC ingress) */
    PROBE_SOURCE_UPROBE     = 2,   /**< Uprobe (userspace library hook) */
    PROBE_SOURCE_SOCKOPS    = 3,   /**< Sockops (socket lifecycle glue) */
    PROBE_SOURCE_KPROBE     = 4,   /**< Kprobe (kernel function hook) */
    PROBE_SOURCE_TRACEPOINT = 5,   /**< Tracepoint (sched_exec, kfree_skb) */
    PROBE_SOURCE_LSM        = 6,   /**< LSM hook (file_open, bprm_check) */
} probe_source_t;

/*============================================================================
 * Event Types (bits [16..23] of routing word)
 *
 * 8-bit namespace (256 types) organized by probe layer.
 * Protocol modules register new types in their respective range.
 * Adding a new type here does NOT require ring_event_t changes.
 *
 * Namespace Allocation:
 *   0x00-0x0F  Core lifecycle (connection open/close/migrate)
 *   0x10-0x1F  XDP / packet layer
 *   0x20-0x2F  TLS / uprobe layer
 *   0x30-0x3F  Socket / sockops layer
 *   0x40-0x4F  Kernel / kprobe layer (tcp_sendmsg, dns, etc.)
 *   0x50-0x5F  io_uring operations (create, connect, sendmsg — evasion detection)
 *   0x60-0x9F  Protocol modules (DNS, QUIC, gRPC, HTTP/3, ...)
 *   0xA0-0xAF  Process lifecycle (exec, exit, fork, privesc)
 *   0xB0-0xBF  File integrity (open, write, exec, delete)
 *   0xC0-0xCF  Enforcement actions (block IP, block exec, kill, RST)
 *   0xD0-0xDF  Reserved EDR
 *   0xE0-0xFF  User-defined / plugin
 *============================================================================*/

/** @brief Event classification for worker dispatch */
typedef enum {

    /*--- Core lifecycle (0x00-0x0F) ----------------------------------------*/

    EVENT_TYPE_SSL_DATA      = 0x00,  /**< SSL/TLS application data (legacy) */
    EVENT_TYPE_CONN_CLOSE    = 0x02,  /**< Connection close (FIN/RST) */

    /*--- XDP / packet layer (0x10-0x1F) ------------------------------------*/

    EVENT_TYPE_XDP_META      = 0x10,  /**< XDP packet metadata (5-tuple) */
    EVENT_TYPE_XDP_AMBIGUOUS = 0x11,  /**< Ambiguous XDP payload */

    /*--- TLS / uprobe layer (0x20-0x2F) ------------------------------------*/

    EVENT_TYPE_TLS_DATA      = 0x20,  /**< Decrypted TLS application data */
    EVENT_TYPE_TLS_HANDSHAKE = 0x21,  /**< TLS handshake event */

    /*--- Socket / sockops layer (0x30-0x3F) --------------------------------*/

    EVENT_TYPE_SOCK_CONNECT  = 0x30,  /**< New connection (socket_cookie assigned) */
    EVENT_TYPE_SOCK_ACCEPT   = 0x31,  /**< Accepted connection (server side) */
    EVENT_TYPE_SOCK_CLOSE    = 0x32,  /**< Socket closed (sockops layer) */
    EVENT_TYPE_SOCK_STATE    = 0x33,  /**< TCP state change notification */

    /*--- Kernel / kprobe layer (0x40-0x5F) ---------------------------------*/

    EVENT_TYPE_PLAIN_DATA    = 0x40,  /**< Plaintext TCP/UDP payload */
    EVENT_TYPE_DNS_QUERY     = 0x41,  /**< DNS query (request or response) */

} event_type_t;

/*============================================================================
 * Routing Word Layout
 *============================================================================*/

#define ROUTE_FLAGS_SHIFT       0
#define ROUTE_FLAGS_MASK        0xFFULL
#define ROUTE_WORKER_SHIFT      8
#define ROUTE_WORKER_MASK       0xFFULL
#define ROUTE_TYPE_SHIFT        16
#define ROUTE_TYPE_MASK         0xFFULL
#define ROUTE_SOURCE_SHIFT      24
#define ROUTE_SOURCE_MASK       0x0FULL      /* 4 bits [24..27] */
#define ROUTE_GEN_SHIFT         32
#define ROUTE_GEN_MASK          0xFFFFFFFFULL

/**
 * @brief Pack routing metadata into a single 64-bit word
 *
 * @param flags    EVENT_FLAG_* bits (8 bits)
 * @param worker   Preferred worker ID (8 bits, 0-255)
 * @param type     EVENT_TYPE_* value (8 bits)
 * @param gen      Generation counter for stale detection (32 bits)
 * @return Packed routing word (probe_source defaults to 0)
 */
static inline uint64_t route_pack(uint8_t flags, uint8_t worker,
                                  uint8_t type, uint32_t gen) {
    return ((uint64_t)flags)
         | ((uint64_t)worker << ROUTE_WORKER_SHIFT)
         | ((uint64_t)type   << ROUTE_TYPE_SHIFT)
         | ((uint64_t)gen    << ROUTE_GEN_SHIFT);
}

/**
 * @brief Pack routing metadata with probe source
 *
 * Extended version that includes the eBPF hook origin.
 *
 * @param flags    EVENT_FLAG_* bits (8 bits)
 * @param worker   Preferred worker ID (8 bits, 0-255)
 * @param type     EVENT_TYPE_* value (8 bits)
 * @param source   PROBE_SOURCE_* origin (4 bits)
 * @param gen      Generation counter for stale detection (32 bits)
 * @return Packed routing word
 */
static inline uint64_t route_pack_ext(uint8_t flags, uint8_t worker,
                                      uint8_t type, uint8_t source,
                                      uint32_t gen) {
    return ((uint64_t)flags)
         | ((uint64_t)worker << ROUTE_WORKER_SHIFT)
         | ((uint64_t)type   << ROUTE_TYPE_SHIFT)
         | ((uint64_t)(source & 0x0F) << ROUTE_SOURCE_SHIFT)
         | ((uint64_t)gen    << ROUTE_GEN_SHIFT);
}

/** Extract flags from routing word */
static inline uint8_t route_flags(uint64_t routing) {
    return (uint8_t)(routing & ROUTE_FLAGS_MASK);
}

/** Extract preferred worker from routing word */
static inline uint8_t route_worker(uint64_t routing) {
    return (uint8_t)((routing >> ROUTE_WORKER_SHIFT) & ROUTE_WORKER_MASK);
}

/** Extract event type from routing word */
static inline uint8_t route_type(uint64_t routing) {
    return (uint8_t)((routing >> ROUTE_TYPE_SHIFT) & ROUTE_TYPE_MASK);
}

/** Extract probe source from routing word */
static inline uint8_t route_source(uint64_t routing) {
    return (uint8_t)((routing >> ROUTE_SOURCE_SHIFT) & ROUTE_SOURCE_MASK);
}

/** Extract generation from routing word (top 32 bits) */
static inline uint32_t route_generation(uint64_t routing) {
    return (uint32_t)(routing >> ROUTE_GEN_SHIFT);
}

/*============================================================================
 * Ring Event Structure
 *============================================================================*/

/* Forward declare to avoid circular includes */
struct flow_context;

/**
 * @brief 56-byte ring event routing header
 *
 * All fields are 8 bytes for homogeneous layout (no padding, no alignment
 * issues). Combined with the 8-byte Vyukov sequence, each slot is exactly
 * one 64-byte hardware cache line.
 *
 * @par Field Ordering (follows worker hot path):
 * 1. socket_cookie → identity (routing decision)
 * 2. lookup_hint   → session lookup (process or defer)
 * 3. data/data_len → payload access
 * 4. routing       → flags, affinity, type, source, generation
 * 5. enqueue_ns    → latency tracking
 * 6. union         → XDP correlation hash OR extended metadata offset
 *
 * @par The Extension Union (last 8 bytes)
 * This is the **extensibility escape hatch**. Protocol modules that need
 * per-event metadata beyond the routing header use ext.offset to point
 * into a shared metadata slab. Events that don't need it carry the
 * flow_key_hash for XDP correlation (the default).
 *
 * Check EVENT_FLAG_HAS_EXT before interpreting the union:
 * @code
 *   if (route_flags(ev->routing) & EVENT_FLAG_HAS_EXT) {
 *       metadata = slab_base + ev->ext.offset;
 *   } else {
 *       hash = ev->flow_key_hash;
 *   }
 * @endcode
 */
typedef struct ring_event {
    /**
     * @brief Primary session key (universal correlator)
     *
     * Set by sockops at connect/accept. Ties XDP packets, TLS decrypts,
     * kernel events, and socket lifecycle into one session. Never changes
     * for the lifetime of a connection.
     */
    uint64_t socket_cookie;

    /**
     * @brief Opaque lookup hint (Phase 2 → Phase 3 transition)
     *
     * Phase 2: (uintptr_t)flow_ctx — cast pointer, workers dereference.
     * Phase 3: Direct-mapped registry index — base + (hint << scale).
     *
     * Use ring_event_flow_ctx() for type-safe access in Phase 2.
     */
    uint64_t lookup_hint;

    /** Zero-copy pointer into mirrored buffer (or eBPF ringbuf) */
    void *data;

    /** Payload length in bytes */
    uint64_t data_len;

    /**
     * @brief Bit-packed routing metadata (single register load)
     *
     * @see route_pack(), route_pack_ext(), route_flags(), route_worker(),
     *      route_type(), route_source(), route_generation()
     */
    uint64_t routing;

    /** CLOCK_MONOTONIC_RAW timestamp at enqueue (queue latency tracking) */
    uint64_t enqueue_ns;

    /**
     * @brief Extension union: XDP hash OR per-event metadata offset
     *
     * Default: flow_key_hash for XDP-SSL correlation and stale hint
     * validation. When EVENT_FLAG_HAS_EXT is set: ext.offset indexes
     * into a per-ring metadata slab for protocol-specific per-event data.
     *
     * This union is the extensibility escape hatch — it allows per-event
     * metadata to grow beyond 56 bytes without changing the ring slot size.
     */
    union {
        /**
         * @brief Pre-computed 5-tuple hash (default, when !EVENT_FLAG_HAS_EXT)
         *
         * Used for XDP correlation and stale hint validation.
         * Computed by dispatcher at enqueue time.
         */
        uint64_t flow_key_hash;

        /**
         * @brief Extended metadata reference (when EVENT_FLAG_HAS_EXT)
         *
         * Points into a per-ring metadata slab. The slab is allocated
         * alongside the ring and accessible to all workers.
         */
        struct {
            uint32_t offset;   /**< Byte offset into metadata slab (0 = none) */
            uint32_t size;     /**< Metadata size in bytes */
        } ext;

        /** Raw 8-byte extension for small inline protocol data */
        uint64_t ext_raw;
    };

} ring_event_t;

/*============================================================================
 * Compile-Time Validation
 *============================================================================*/

_Static_assert(sizeof(ring_event_t) == 56,
               "ring_event_t must be exactly 56 bytes (7 x uint64_t)");

/*
 * Field offset asserts: workers depend on exact layout for hot-path
 * register loads. Reordering fields silently breaks routing decisions.
 */
_Static_assert(offsetof(ring_event_t, socket_cookie) == 0,
               "socket_cookie must be first (identity check on dequeue)");
_Static_assert(offsetof(ring_event_t, routing) == 32,
               "routing word must be at offset 32 (single register load)");
_Static_assert(offsetof(ring_event_t, enqueue_ns) == 40,
               "enqueue_ns must be at offset 40 (latency tracking)");

/*============================================================================
 * Inline Accessors
 *============================================================================*/

/**
 * @brief Phase 2 accessor: get flow_ctx pointer from lookup_hint
 *
 * In Phase 3, this will be replaced by a registry index lookup:
 * @code
 *   #ifdef PHASE_3
 *     return &worker_registry[ev->lookup_hint];
 *   #endif
 * @endcode
 *
 * @param ev Pointer to ring event
 * @return flow_context pointer (may be NULL)
 */
static inline struct flow_context *ring_event_flow_ctx(const ring_event_t *ev) {
    if (!ev) return NULL;
    return (struct flow_context *)(uintptr_t)ev->lookup_hint;
}

/** Check if event requires sticky worker affinity */
static inline bool ring_event_is_stateful(const ring_event_t *ev) {
    return ev && (route_flags(ev->routing) & EVENT_FLAG_STATEFUL);
}

/** Check if event is high priority (FIN/RST) */
static inline bool ring_event_is_urgent(const ring_event_t *ev) {
    return ev && (route_flags(ev->routing) & EVENT_FLAG_URGENT);
}

/** Check if this is the first data for the flow */
static inline bool ring_event_is_first_data(const ring_event_t *ev) {
    return ev && (route_flags(ev->routing) & EVENT_FLAG_FIRST_DATA);
}

/** Check if this is an XDP metadata event */
static inline bool ring_event_is_xdp(const ring_event_t *ev) {
    return ev && (route_flags(ev->routing) & EVENT_FLAG_XDP);
}

/** Check if event has already been routed through an overflow queue */
static inline bool ring_event_is_routed(const ring_event_t *ev) {
    return ev && (route_flags(ev->routing) & EVENT_FLAG_ROUTED);
}

/**
 * @brief Mark event as routed (set hop-limit flag)
 *
 * Must be called before pushing to another worker's overflow queue.
 * Once set, the receiving worker will process locally — no further routing.
 */
static inline void ring_event_mark_routed(ring_event_t *ev) {
    if (ev) ev->routing |= EVENT_FLAG_ROUTED;
}

/** Check if event carries extended metadata (ext union) */
static inline bool ring_event_has_ext(const ring_event_t *ev) {
    return ev && (route_flags(ev->routing) & EVENT_FLAG_HAS_EXT);
}

/** Get preferred worker for affinity check */
static inline uint8_t ring_event_preferred_worker(const ring_event_t *ev) {
    return ev ? route_worker(ev->routing) : 0;
}

/** Get event generation for stale detection */
static inline uint32_t ring_event_generation(const ring_event_t *ev) {
    return ev ? route_generation(ev->routing) : 0;
}

/** Get probe source that generated this event */
static inline uint8_t ring_event_probe_source(const ring_event_t *ev) {
    return ev ? route_source(ev->routing) : 0;
}

/** @} */ /* end of ring_event group */

#endif /* SPLIFF_RING_EVENT_H */
