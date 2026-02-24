/**
 * @file numa_alloc.h
 * @brief NUMA-aware allocation stubs with topology detection
 *
 * @details Provides NUMA topology detection and allocation stubs for future
 * optimization. The full NUMA implementation is deferred to post-1.0 as the
 * primary development environment is single-socket.
 *
 * @par Current Status: STUBS ONLY
 * - Detection: Reads /sys/class/net/{ifname}/device/numa_node for NIC affinity
 * - Allocation: Falls back to aligned_alloc (128-byte aligned for cache lines)
 * - Pinning: Logs intent but does not actually pin threads
 *
 * @par Why NUMA Matters (Future Optimization):
 * @code
 * Single-Socket (Current):
 *   All memory access: ~50ns
 *   No optimization needed
 *
 * Dual-Socket (Future Production):
 *   Local NUMA access:  ~50ns
 *   Remote NUMA access: ~150ns (+100ns penalty)
 *
 * At 10Gbps (~1M pkts/sec):
 *   Remote penalty = ~100ms/sec wasted on memory stalls
 * @endcode
 *
 * @par Integration Pattern:
 * @code
 * // At startup, detect where the NIC is attached
 * int nic_node = numa_detect_nic_node("eth0");
 * numa_log_topology();
 *
 * // Allocate buffers on the same node as the NIC (future)
 * void *buf = numa_alloc_on_node(size, nic_node);
 *
 * // Pin worker threads to the NIC's NUMA node (future)
 * numa_pin_thread(worker_tid, nic_node);
 * @endcode
 *
 * @note Full implementation requires libnuma; current stubs work without it.
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license AGPL-3.0-only
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef SPLIFF_NUMA_ALLOC_H
#define SPLIFF_NUMA_ALLOC_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @defgroup numa NUMA Topology and Allocation
 * @brief NUMA-aware memory management (stubs for future optimization)
 * @{
 */

/**
 * @brief Special node value indicating "any node" or "unknown"
 */
#define NUMA_NODE_ANY (-1)

/**
 * @brief Maximum NUMA nodes supported
 *
 * Most servers have 2-8 NUMA nodes; 16 covers extreme cases.
 */
#define NUMA_MAX_NODES 16

/**
 * @brief NUMA topology information
 */
typedef struct {
    int node_count;                        /**< Number of NUMA nodes detected */
    int nic_node;                          /**< Node where primary NIC is attached */
    uint64_t node_memory[NUMA_MAX_NODES];  /**< Memory per node in bytes */
    bool available;                        /**< True if NUMA is available */
} numa_topology_t;

/**
 * @brief Detect the NUMA node of a network interface
 *
 * Reads /sys/class/net/<ifname>/device/numa_node to determine which
 * NUMA node the NIC is attached to. This is critical for allocating
 * ring buffers on the same node to avoid cross-node memory access.
 *
 * @param ifname Network interface name (e.g., "eth0", "enp3s0")
 * @return NUMA node number (0+), or NUMA_NODE_ANY if unknown/error
 *
 * @note Returns NUMA_NODE_ANY for virtual interfaces (lo, veth, etc.)
 *       as they have no physical NUMA affinity.
 */
int numa_detect_nic_node(const char *ifname);

/**
 * @brief Get overall NUMA topology
 *
 * Detects NUMA configuration by reading /sys/devices/system/node/.
 * Populates node count and per-node memory sizes.
 *
 * @param topo Output structure to populate
 * @return true if NUMA is available, false if single-node or error
 */
bool numa_get_topology(numa_topology_t *topo);

/**
 * @brief Log NUMA topology at startup
 *
 * Prints detected NUMA configuration for troubleshooting.
 * Useful for verifying that the agent will allocate on the correct node.
 */
void numa_log_topology(void);

/**
 * @brief Allocate memory on a specific NUMA node
 *
 * @par Current Implementation (STUB):
 * Falls back to regular malloc(). Full implementation requires libnuma.
 *
 * @param size  Size in bytes to allocate
 * @param node  Target NUMA node, or NUMA_NODE_ANY for default
 * @return Pointer to allocated memory, or NULL on failure
 *
 * @note Caller must use numa_free() to release the memory.
 *
 * @todo Implement with numa_alloc_onnode() when libnuma is available.
 */
void *numa_alloc_on_node(size_t size, int node);

/**
 * @brief Allocate memory with hugepages on a specific NUMA node
 *
 * @par Current Implementation (STUB):
 * Falls back to hugepage_alloc(). Full implementation requires libnuma.
 *
 * @param size  Size in bytes to allocate
 * @param node  Target NUMA node, or NUMA_NODE_ANY for default
 * @return Pointer to allocated memory, or NULL on failure
 *
 * @todo Implement with mbind() when libnuma is available.
 */
void *numa_alloc_hugepages_on_node(size_t size, int node);

/**
 * @brief Free memory allocated with numa_alloc_on_node()
 *
 * @param ptr  Pointer to memory
 * @param size Size that was allocated
 *
 * @note Safe to call with NULL ptr (no-op).
 */
void numa_free(void *ptr, size_t size);

/**
 * @brief Pin a thread to a specific NUMA node's CPUs
 *
 * @par Current Implementation (STUB):
 * Logs the intent but does not actually set CPU affinity.
 * Full implementation requires reading node CPU masks and pthread_setaffinity_np().
 *
 * @param thread_id  Thread ID (from pthread_self() or gettid())
 * @param node       Target NUMA node
 * @return true on success (stub: always returns true), false on error
 *
 * @todo Implement with numa_node_to_cpus() + sched_setaffinity().
 */
bool numa_pin_thread(uint64_t thread_id, int node);

/**
 * @brief Check if NUMA is available on this system
 *
 * @return true if multiple NUMA nodes detected, false otherwise
 */
bool numa_is_available(void);

/**
 * @brief Get the NUMA node of the current thread
 *
 * @return Current NUMA node, or 0 if NUMA unavailable
 *
 * @note Stub implementation always returns 0.
 */
int numa_current_node(void);

/**
 * @brief Get distance between two NUMA nodes
 *
 * Returns a relative distance metric useful for prioritizing "nearby"
 * nodes if the local node is full.
 *
 * @par Current Implementation (STUB):
 * Returns constant 10 for local (same node) or 20 for remote.
 * Full implementation would read from /sys/devices/system/node/nodeN/distance.
 *
 * @param from Source NUMA node
 * @param to   Destination NUMA node
 * @return Distance metric (lower is better), 10 for local, 20 for remote
 */
int numa_get_distance(int from, int to);

/** @} */ /* end of numa group */

#endif /* SPLIFF_NUMA_ALLOC_H */
