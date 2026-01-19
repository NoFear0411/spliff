/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * flow_cache.h - XDP flow information cache for correlation with SSL events
 *
 * The "Golden Thread" correlation links XDP network metadata with SSL/TLS
 * decrypted content using the socket cookie as the universal key.
 */

#ifndef FLOW_CACHE_H
#define FLOW_CACHE_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include "../include/spliff.h"

/**
 * @brief Flow information cached from XDP events
 *
 * This structure captures network-layer metadata from XDP packets
 * that can be correlated with SSL events via socket_cookie.
 */
typedef struct flow_info {
    uint64_t socket_cookie;      /**< Key: socket cookie ("Golden Thread") */
    flow_key_t flow;             /**< 5-tuple: src/dst IP and ports */
    uint64_t first_seen_ns;      /**< Connection start timestamp */
    uint64_t last_seen_ns;       /**< Last packet timestamp */
    uint32_t pkt_count;          /**< Packets seen on this flow */
    uint32_t byte_count;         /**< Bytes transferred */
    uint32_t ifindex;            /**< Network interface index */
    uint8_t category;            /**< XDP protocol category */
    uint8_t direction;           /**< Direction: 1=ingress, 2=egress */
    char ifname[16];             /**< Interface name (resolved from ifindex) */
    bool active;                 /**< True if slot is in use */
} flow_info_t;

/**
 * @brief Flow cache configuration
 */
#define FLOW_CACHE_SIZE 8192     /**< Support ~8K concurrent connections */
#define FLOW_CACHE_TIMEOUT_NS (60ULL * 1000000000ULL)  /**< 60 second timeout */

/**
 * @brief Flow cache context
 *
 * Hash table implementation for O(1) lookup by socket_cookie.
 * Uses linear probing for collision resolution.
 */
typedef struct flow_cache {
    flow_info_t *entries;        /**< Pre-allocated entry array */
    size_t capacity;             /**< Number of slots */
    _Atomic uint64_t hits;       /**< Successful lookups */
    _Atomic uint64_t misses;     /**< Failed lookups */
    _Atomic uint64_t inserts;    /**< Total insertions */
    _Atomic uint64_t evictions;  /**< Entries evicted (stale or collision) */
    _Atomic uint64_t count;      /**< Current active entries */
} flow_cache_t;

/**
 * @brief Initialize flow cache
 *
 * @param cache     Pointer to flow cache structure
 * @param capacity  Number of entries to allocate
 * @return 0 on success, -1 on failure
 */
int flow_cache_init(flow_cache_t *cache, size_t capacity);

/**
 * @brief Cleanup flow cache and free resources
 *
 * @param cache     Pointer to flow cache structure
 */
void flow_cache_cleanup(flow_cache_t *cache);

/**
 * @brief Insert or update flow info from XDP event
 *
 * If the socket_cookie already exists, update the last_seen_ns and counters.
 * If it doesn't exist, create a new entry.
 *
 * @param cache         Flow cache
 * @param socket_cookie Socket cookie (the "Golden Thread" key)
 * @param evt           XDP packet event containing flow metadata
 * @return 0 on success, -1 on failure (cache full)
 */
int flow_cache_upsert(flow_cache_t *cache, uint64_t socket_cookie,
                      const xdp_packet_event_t *evt);

/**
 * @brief Lookup flow info by socket_cookie
 *
 * @param cache         Flow cache
 * @param socket_cookie Socket cookie to lookup
 * @return Pointer to flow_info if found, NULL otherwise
 */
flow_info_t *flow_cache_lookup(flow_cache_t *cache, uint64_t socket_cookie);

/**
 * @brief Mark flow as terminated (FIN/RST received)
 *
 * @param cache         Flow cache
 * @param socket_cookie Socket cookie of terminated flow
 */
void flow_cache_terminate(flow_cache_t *cache, uint64_t socket_cookie);

/**
 * @brief Evict stale entries (older than timeout)
 *
 * Call periodically to reclaim slots from long-idle connections.
 *
 * @param cache      Flow cache
 * @param current_ns Current timestamp (nanoseconds)
 * @return Number of entries evicted
 */
int flow_cache_evict_stale(flow_cache_t *cache, uint64_t current_ns);

/**
 * @brief Get cache statistics
 *
 * @param cache     Flow cache
 * @param hits      Output: successful lookups
 * @param misses    Output: failed lookups
 * @param inserts   Output: total insertions
 * @param evictions Output: evicted entries
 */
void flow_cache_get_stats(flow_cache_t *cache, uint64_t *hits, uint64_t *misses,
                          uint64_t *inserts, uint64_t *evictions);

#endif /* FLOW_CACHE_H */
