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
#include "../include/spliff.h"
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <netinet/tcp.h>
#include <bpf/bpf.h>  /* For bpf_map_get_next_key, bpf_map_lookup_elem */

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

/* ============================================================================
 * Userspace Warm-up - Seed flow_cache from existing TCP connections
 * ============================================================================
 * Fixes correlation gap for pre-existing connections at startup.
 * XDP doesn't emit FLOW_NEW events for already-classified flows, so we
 * must populate flow_cache manually using netlink SOCK_DIAG.
 *
 * Uses inode as pseudo-cookie to match BPF warm-up in bpf_loader.c.
 */

/**
 * @brief Insert a synthetic flow entry for warm-up
 *
 * Creates a flow_info_t entry from netlink data. Uses direct slot insertion
 * to avoid needing an xdp_packet_event_t structure.
 *
 * @param cache         Flow cache
 * @param socket_cookie Socket inode as pseudo-cookie
 * @param saddr         Source IP (network byte order)
 * @param daddr         Dest IP (network byte order)
 * @param sport         Source port (network byte order)
 * @param dport         Dest port (network byte order)
 * @param timestamp_ns  Current timestamp
 * @return 0 on success, -1 on failure
 */
static int flow_cache_warmup_insert(flow_cache_t *cache, uint64_t socket_cookie,
                                    uint32_t saddr, uint32_t daddr,
                                    uint16_t sport, uint16_t dport,
                                    uint64_t timestamp_ns) {
    if (!cache || !cache->entries || socket_cookie == 0) {
        return -1;
    }

    size_t start = hash_cookie(socket_cookie) % cache->capacity;
    size_t max_probe = cache->capacity / 4;

    for (size_t i = 0; i < max_probe; i++) {
        size_t slot = (start + i) % cache->capacity;
        flow_info_t *entry = &cache->entries[slot];

        bool is_active = atomic_load_explicit(&entry->active, memory_order_acquire);

        /* Skip if already exists */
        if (is_active && entry->socket_cookie == socket_cookie) {
            return 0;
        }

        /* Found empty slot */
        if (!is_active) {
            entry->socket_cookie = socket_cookie;
            entry->flow.saddr = saddr;
            entry->flow.daddr = daddr;
            entry->flow.sport = sport;
            entry->flow.dport = dport;
            entry->flow.ip_version = 4;  /* IPv4 only for now */
            entry->first_seen_ns = timestamp_ns;
            entry->last_seen_ns = timestamp_ns;
            entry->pkt_count = 0;
            entry->byte_count = 0;
            entry->ifindex = 0;  /* Unknown from SOCK_DIAG */
            entry->category = XDP_CAT_TLS_TCP;  /* Assume TLS for SSL warm-up */
            entry->direction = 0;  /* Unknown */
            entry->ifname[0] = '\0';

            atomic_store_explicit(&entry->active, true, memory_order_release);
            atomic_fetch_add(&cache->inserts, 1);
            atomic_fetch_add(&cache->count, 1);
            return 0;
        }
    }

    return -1;  /* Cache congested */
}

int flow_cache_warmup_from_netlink(flow_cache_t *cache, bool debug) {
    if (!cache || !cache->entries) {
        return 0;
    }

    int seeded = 0;

    /* Create netlink socket for SOCK_DIAG */
    int nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_SOCK_DIAG);
    if (nl_sock < 0) {
        if (debug) fprintf(stderr, "  [FlowCache] Warm-up: Cannot create netlink socket\n");
        return 0;
    }

    /* Build request for TCP sockets in active states */
    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 req;
    } request = {
        .nlh = {
            .nlmsg_len = sizeof(request),
            .nlmsg_type = SOCK_DIAG_BY_FAMILY,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
            .nlmsg_seq = 1,
        },
        .req = {
            .sdiag_family = AF_INET,
            .sdiag_protocol = IPPROTO_TCP,
            .idiag_ext = 0,
            .idiag_states = (1 << TCP_ESTABLISHED) | (1 << TCP_SYN_SENT) |
                            (1 << TCP_SYN_RECV) | (1 << TCP_FIN_WAIT1) |
                            (1 << TCP_FIN_WAIT2) | (1 << TCP_CLOSE_WAIT),
        },
    };

    if (send(nl_sock, &request, sizeof(request), 0) < 0) {
        if (debug) fprintf(stderr, "  [FlowCache] Warm-up: Netlink send failed\n");
        close(nl_sock);
        return 0;
    }

    /* Get current timestamp */
    uint64_t now_ns = 0;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        now_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    }

    /* Receive and process responses */
    char buf[32768];
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct sockaddr_nl sa;
    struct msghdr msg = {
        .msg_name = &sa,
        .msg_namelen = sizeof(sa),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    bool done = false;
    while (!done) {
        ssize_t len = recvmsg(nl_sock, &msg, 0);
        if (len < 0) {
            break;
        }

        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        while (NLMSG_OK(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                done = true;
                break;
            }
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                done = true;
                break;
            }

            struct inet_diag_msg *diag = NLMSG_DATA(nlh);

            /* Use socket inode as pseudo-cookie (matches BPF warm-up) */
            uint64_t cookie = diag->idiag_inode;

            if (cookie != 0) {
                /* Insert for client→server direction */
                if (flow_cache_warmup_insert(cache, cookie,
                                             diag->id.idiag_src[0],
                                             diag->id.idiag_dst[0],
                                             diag->id.idiag_sport,
                                             diag->id.idiag_dport,
                                             now_ns) == 0) {
                    seeded++;
                }
            }

            nlh = NLMSG_NEXT(nlh, len);
        }
    }

    close(nl_sock);

    if (debug && seeded > 0) {
        fprintf(stderr, "  [FlowCache] Warm-up (netlink): Seeded %d existing TCP connections\n", seeded);
    }

    return seeded;
}

/* ============================================================================
 * BPF Map Warm-up - Seed flow_cache from BPF flow_states map
 * ============================================================================
 * Iterates the BPF flow_states map directly to get real socket cookies.
 * This is more accurate than netlink warm-up which uses inode as pseudo-cookie.
 */

/* Must match struct flow_key in spliff.bpf.c (16 bytes packed) */
struct flow_cache_bpf_key {
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint8_t  protocol;
    uint8_t  ip_version;
    uint8_t  _pad[2];
} __attribute__((packed));

/* Must match struct flow_state in spliff.bpf.c (36 bytes packed) */
struct flow_cache_bpf_state {
    uint64_t socket_cookie;
    uint64_t first_seen_ns;
    uint64_t last_seen_ns;
    uint32_t pkt_count;
    uint32_t byte_count;
    uint8_t  category;
    uint8_t  state;
    uint8_t  direction;
    uint8_t  flags;
} __attribute__((packed));

int flow_cache_warmup_from_bpf(flow_cache_t *cache, int flow_states_fd, bool debug) {
    if (!cache || !cache->entries || flow_states_fd < 0) {
        return 0;
    }

    int seeded = 0;
    struct flow_cache_bpf_key key = {0};
    struct flow_cache_bpf_key next_key;
    struct flow_cache_bpf_state value;

    /* Get current timestamp */
    uint64_t now_ns = 0;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        now_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    }

    /* Iterate through all flow_states entries */
    while (bpf_map_get_next_key(flow_states_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(flow_states_fd, &next_key, &value) == 0) {
            /* Only seed entries with valid socket cookies */
            if (value.socket_cookie != 0) {
                if (flow_cache_warmup_insert(cache, value.socket_cookie,
                                             next_key.saddr, next_key.daddr,
                                             next_key.sport, next_key.dport,
                                             now_ns) == 0) {
                    seeded++;
                }
            }
        }
        key = next_key;
    }

    if (debug && seeded > 0) {
        fprintf(stderr, "  [FlowCache] Warm-up (BPF): Seeded %d flows with real cookies\n", seeded);
    }

    return seeded;
}
