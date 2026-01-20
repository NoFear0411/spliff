/**
 * @file flow_cache.c
 * @brief XDP flow information cache implementation
 *
 * @details Hash table with linear probing for O(1) average lookup.
 * Keyed by socket_cookie (the "Golden Thread" for XDP-SSL correlation).
 *
 * @par Architecture:
 * @code
 *   XDP packet event
 *         │
 *         ▼
 *   flow_cache_upsert()
 *         │
 *         ├─── Hash socket_cookie → slot
 *         │
 *         ├─── Linear probe for existing/empty slot
 *         │
 *         └─── Update counters or create new entry
 *
 *   SSL event processing
 *         │
 *         ▼
 *   flow_cache_lookup(socket_cookie)
 *         │
 *         └─── Returns flow_info_t with network metadata
 * @endcode
 *
 * @par Thread Safety:
 * The cache uses atomic counters for statistics but is NOT fully
 * thread-safe for concurrent modifications. In spliff's architecture,
 * XDP events are processed by the dispatcher thread while SSL events
 * are processed by worker threads - coordination happens at a higher level.
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "flow_cache.h"
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>

/**
 * @brief FNV-1a hash for 64-bit socket_cookie
 */
static inline uint64_t hash_cookie(uint64_t cookie) {
    uint64_t hash = 14695981039346656037ULL;
    hash ^= cookie;
    hash *= 1099511628211ULL;
    hash ^= (cookie >> 32);
    hash *= 1099511628211ULL;
    return hash;
}

/**
 * @brief Get slot index for a socket_cookie
 */
static inline size_t get_slot(flow_cache_t *cache, uint64_t cookie) {
    return hash_cookie(cookie) % cache->capacity;
}

int flow_cache_init(flow_cache_t *cache, size_t capacity) {
    if (!cache || capacity == 0) {
        return -1;
    }

    cache->entries = calloc(capacity, sizeof(flow_info_t));
    if (!cache->entries) {
        return -1;
    }

    cache->capacity = capacity;
    atomic_store(&cache->hits, 0);
    atomic_store(&cache->misses, 0);
    atomic_store(&cache->inserts, 0);
    atomic_store(&cache->evictions, 0);
    atomic_store(&cache->count, 0);

    return 0;
}

void flow_cache_cleanup(flow_cache_t *cache) {
    if (cache && cache->entries) {
        free(cache->entries);
        cache->entries = NULL;
        cache->capacity = 0;
    }
}

int flow_cache_upsert(flow_cache_t *cache, uint64_t socket_cookie,
                      const xdp_packet_event_t *evt) {
    if (!cache || !cache->entries || !evt || socket_cookie == 0) {
        return -1;
    }

    size_t start = get_slot(cache, socket_cookie);
    size_t max_probe = cache->capacity / 4;  // Limit probing to 25%

    /* Linear probing to find existing or empty slot */
    for (size_t i = 0; i < max_probe; i++) {
        size_t slot = (start + i) % cache->capacity;
        flow_info_t *entry = &cache->entries[slot];

        /* Use acquire to see any prior writes */
        bool is_active = atomic_load_explicit(&entry->active, memory_order_acquire);

        /* Found existing entry - update it */
        if (is_active && entry->socket_cookie == socket_cookie) {
            entry->last_seen_ns = evt->timestamp_ns;
            entry->pkt_count++;
            entry->byte_count += evt->pkt_len;
            return 0;
        }

        /* Found empty slot - create new entry */
        if (!is_active) {
            /* Populate all fields BEFORE setting active */
            entry->socket_cookie = socket_cookie;
            memcpy(&entry->flow, &evt->flow, sizeof(flow_key_t));
            entry->first_seen_ns = evt->timestamp_ns;
            entry->last_seen_ns = evt->timestamp_ns;
            entry->pkt_count = 1;
            entry->byte_count = evt->pkt_len;
            entry->ifindex = evt->ifindex;
            entry->category = evt->category;
            entry->direction = evt->direction;

            /* Resolve interface name from ifindex */
            if (evt->ifindex > 0) {
                if (if_indextoname(evt->ifindex, entry->ifname) == NULL) {
                    snprintf(entry->ifname, sizeof(entry->ifname), "if%u", evt->ifindex);
                }
            } else {
                entry->ifname[0] = '\0';
            }

            /* Release ensures all prior writes are visible to readers */
            atomic_store_explicit(&entry->active, true, memory_order_release);
            atomic_fetch_add(&cache->inserts, 1);
            atomic_fetch_add(&cache->count, 1);
            return 0;
        }
    }

    /* Cache is congested in this region - evict oldest entry */
    size_t oldest_slot = start;
    uint64_t oldest_time = UINT64_MAX;

    for (size_t i = 0; i < max_probe; i++) {
        size_t slot = (start + i) % cache->capacity;
        flow_info_t *entry = &cache->entries[slot];
        bool is_active = atomic_load_explicit(&entry->active, memory_order_acquire);
        if (is_active && entry->last_seen_ns < oldest_time) {
            oldest_time = entry->last_seen_ns;
            oldest_slot = slot;
        }
    }

    /* Evict and reuse - mark inactive first, then repopulate */
    flow_info_t *entry = &cache->entries[oldest_slot];
    atomic_store_explicit(&entry->active, false, memory_order_release);

    /* Populate all fields BEFORE setting active */
    entry->socket_cookie = socket_cookie;
    memcpy(&entry->flow, &evt->flow, sizeof(flow_key_t));
    entry->first_seen_ns = evt->timestamp_ns;
    entry->last_seen_ns = evt->timestamp_ns;
    entry->pkt_count = 1;
    entry->byte_count = evt->pkt_len;
    entry->ifindex = evt->ifindex;
    entry->category = evt->category;
    entry->direction = evt->direction;

    if (evt->ifindex > 0) {
        if (if_indextoname(evt->ifindex, entry->ifname) == NULL) {
            snprintf(entry->ifname, sizeof(entry->ifname), "if%u", evt->ifindex);
        }
    } else {
        entry->ifname[0] = '\0';
    }

    /* Release ensures all prior writes are visible to readers */
    atomic_store_explicit(&entry->active, true, memory_order_release);
    atomic_fetch_add(&cache->evictions, 1);
    atomic_fetch_add(&cache->inserts, 1);

    return 0;
}

/**
 * @brief Lookup flow info by socket_cookie (thread-safe with acquire semantics)
 *
 * Uses atomic_load_explicit with memory_order_acquire to ensure all
 * writes by the dispatcher thread are visible when active==true.
 *
 * @param cache         Flow cache
 * @param socket_cookie Socket cookie to lookup
 * @return Pointer to flow_info if found, NULL otherwise
 */
flow_info_t *flow_cache_lookup(flow_cache_t *cache, uint64_t socket_cookie) {
    if (!cache || !cache->entries || socket_cookie == 0) {
        return NULL;
    }

    size_t start = get_slot(cache, socket_cookie);
    size_t max_probe = cache->capacity / 4;

    for (size_t i = 0; i < max_probe; i++) {
        size_t slot = (start + i) % cache->capacity;
        flow_info_t *entry = &cache->entries[slot];

        /* Acquire ensures we see all writes made before active was set */
        bool is_active = atomic_load_explicit(&entry->active, memory_order_acquire);

        if (is_active && entry->socket_cookie == socket_cookie) {
            atomic_fetch_add(&cache->hits, 1);
            return entry;  /* All fields guaranteed visible due to acquire */
        }

        /* Empty slot means cookie not in cache */
        if (!is_active) {
            break;
        }
    }

    atomic_fetch_add(&cache->misses, 1);
    return NULL;
}

/**
 * @brief Mark flow as terminated (FIN/RST received)
 *
 * Uses atomic_store_explicit with memory_order_release to ensure
 * visibility to worker threads.
 *
 * @param cache         Flow cache
 * @param socket_cookie Socket cookie of terminated flow
 */
void flow_cache_terminate(flow_cache_t *cache, uint64_t socket_cookie) {
    if (!cache || !cache->entries || socket_cookie == 0) {
        return;
    }

    size_t start = get_slot(cache, socket_cookie);
    size_t max_probe = cache->capacity / 4;

    for (size_t i = 0; i < max_probe; i++) {
        size_t slot = (start + i) % cache->capacity;
        flow_info_t *entry = &cache->entries[slot];

        bool is_active = atomic_load_explicit(&entry->active, memory_order_acquire);
        if (is_active && entry->socket_cookie == socket_cookie) {
            atomic_store_explicit(&entry->active, false, memory_order_release);
            atomic_fetch_sub(&cache->count, 1);
            return;
        }

        if (!is_active) {
            break;
        }
    }
}

/**
 * @brief Evict stale entries (older than timeout)
 *
 * Call periodically to reclaim slots from long-idle connections.
 * Uses atomic operations for thread safety.
 *
 * @param cache      Flow cache
 * @param current_ns Current timestamp (nanoseconds)
 * @return Number of entries evicted
 */
int flow_cache_evict_stale(flow_cache_t *cache, uint64_t current_ns) {
    if (!cache || !cache->entries) {
        return 0;
    }

    int evicted = 0;
    uint64_t timeout_threshold = current_ns - FLOW_CACHE_TIMEOUT_NS;

    for (size_t i = 0; i < cache->capacity; i++) {
        flow_info_t *entry = &cache->entries[i];
        bool is_active = atomic_load_explicit(&entry->active, memory_order_acquire);
        if (is_active && entry->last_seen_ns < timeout_threshold) {
            atomic_store_explicit(&entry->active, false, memory_order_release);
            atomic_fetch_sub(&cache->count, 1);
            atomic_fetch_add(&cache->evictions, 1);
            evicted++;
        }
    }

    return evicted;
}

void flow_cache_get_stats(flow_cache_t *cache, uint64_t *hits, uint64_t *misses,
                          uint64_t *inserts, uint64_t *evictions) {
    if (!cache) {
        return;
    }
    if (hits) *hits = atomic_load(&cache->hits);
    if (misses) *misses = atomic_load(&cache->misses);
    if (inserts) *inserts = atomic_load(&cache->inserts);
    if (evictions) *evictions = atomic_load(&cache->evictions);
}
