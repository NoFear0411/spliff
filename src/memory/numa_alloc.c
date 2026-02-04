/**
 * @file numa_alloc.c
 * @brief NUMA topology detection and allocation stubs
 *
 * @details Implements NUMA detection via sysfs, with allocation functions
 * that use aligned_alloc for cache-line alignment. Full NUMA-aware allocation
 * is deferred to post-1.0 optimization phase.
 *
 * @par Detection Implementation:
 * - NIC node: /sys/class/net/<ifname>/device/numa_node
 * - Node count: /sys/devices/system/node/node* directories
 * - Node memory: /sys/devices/system/node/node<N>/meminfo
 *
 * @par Allocation Implementation (STUBS):
 * - numa_alloc_on_node() uses aligned_alloc(128, size) for cache alignment
 * - numa_alloc_hugepages_on_node() uses hugepage_alloc()
 * - numa_pin_thread() uses generic sched_setaffinity() (logs target)
 *
 * @see numa_alloc.h for API documentation
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

/* _GNU_SOURCE defined via CMake for sched_setaffinity */

#include "numa_alloc.h"
#include "hugepage.h"
#include "alignment.h"

#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * @brief Read a single integer from a sysfs file
 *
 * @param path Full path to sysfs file
 * @return Integer value, or -1 on error
 */
static int read_sysfs_int(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    char buf[32];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n <= 0) {
        return -1;
    }

    buf[n] = '\0';
    return atoi(buf);
}

/**
 * @brief Read memory size from a node's meminfo
 *
 * Parses /sys/devices/system/node/node<N>/meminfo for MemTotal.
 *
 * @param node NUMA node number
 * @return Memory in bytes, or 0 on error
 */
static uint64_t read_node_memory(int node) {
    char path[128];
    snprintf(path, sizeof(path),
             "/sys/devices/system/node/node%d/meminfo", node);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return 0;
    }

    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n <= 0) {
        return 0;
    }
    buf[n] = '\0';

    /* Look for "MemTotal:" line */
    const char *key = "MemTotal:";
    char *pos = strstr(buf, key);
    if (!pos) {
        return 0;
    }

    pos += strlen(key);
    while (*pos == ' ') pos++;

    /* Parse value (in KB) and convert to bytes */
    uint64_t kb = (uint64_t)strtoull(pos, NULL, 10);
    return kb * 1024;
}

/**
 * @brief Count NUMA nodes by scanning /sys/devices/system/node/
 *
 * @return Number of NUMA nodes (minimum 1)
 */
static int count_numa_nodes(void) {
    const char *node_path = "/sys/devices/system/node";
    DIR *dir = opendir(node_path);
    if (!dir) {
        return 1;  /* Assume single node if sysfs unavailable */
    }

    int count = 0;
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        /* Match "node0", "node1", etc. */
        if (strncmp(entry->d_name, "node", 4) == 0 &&
            entry->d_name[4] >= '0' && entry->d_name[4] <= '9') {
            count++;
        }
    }

    closedir(dir);
    return (count > 0) ? count : 1;
}

int numa_detect_nic_node(const char *ifname) {
    if (!ifname || !ifname[0]) {
        return NUMA_NODE_ANY;
    }

    /*
     * Read /sys/class/net/<ifname>/device/numa_node
     *
     * This file contains the NUMA node number where the NIC is attached.
     * Virtual interfaces (lo, veth) don't have a "device" symlink.
     */
    char path[256];
    snprintf(path, sizeof(path),
             "/sys/class/net/%s/device/numa_node", ifname);

    int node = read_sysfs_int(path);

    /*
     * Some systems report -1 for devices not on a specific NUMA node
     * (e.g., onboard NICs on single-socket systems).
     */
    if (node < 0) {
        return NUMA_NODE_ANY;
    }

    return node;
}

bool numa_get_topology(numa_topology_t *topo) {
    if (!topo) {
        return false;
    }

    memset(topo, 0, sizeof(*topo));
    topo->nic_node = NUMA_NODE_ANY;

    topo->node_count = count_numa_nodes();
    topo->available = (topo->node_count > 1);

    /* Read memory size for each node */
    for (int i = 0; i < topo->node_count && i < NUMA_MAX_NODES; i++) {
        topo->node_memory[i] = read_node_memory(i);
    }

    return topo->available;
}

void numa_log_topology(void) {
    numa_topology_t topo;
    numa_get_topology(&topo);

    if (!topo.available) {
        fprintf(stderr, "[INFO] NUMA_TOPOLOGY: Single-node system "
                        "(no NUMA optimization needed)\n");
        return;
    }

    fprintf(stderr, "[INFO] NUMA_TOPOLOGY: %d nodes detected\n",
            topo.node_count);

    for (int i = 0; i < topo.node_count && i < NUMA_MAX_NODES; i++) {
        uint64_t mb = topo.node_memory[i] / (1024 * 1024);
        fprintf(stderr, "[INFO] NUMA_TOPOLOGY: Node %d: %lu MB\n",
                i, (unsigned long)mb);
    }

    if (topo.nic_node != NUMA_NODE_ANY) {
        fprintf(stderr, "[INFO] NUMA_TOPOLOGY: Primary NIC on node %d\n",
                topo.nic_node);
    }

    fprintf(stderr, "[INFO] NUMA_TOPOLOGY: NOTE - NUMA allocation is stubbed; "
                    "using local allocation. Full implementation post-1.0.\n");
}

bool numa_is_available(void) {
    return count_numa_nodes() > 1;
}

int numa_current_node(void) {
    /*
     * STUB: Would use getcpu() or read /proc/self/numa_maps
     * For now, return 0 (assume local node).
     */
    return 0;
}

int numa_get_distance(int from, int to) {
    /*
     * STUB IMPLEMENTATION
     *
     * Full implementation would read:
     *   /sys/devices/system/node/node<from>/distance
     * Which contains space-separated distances to all nodes.
     *
     * For now, return simple constants:
     *   10 = local (same node)
     *   20 = remote (different node)
     */
    if (from == to) {
        return 10;  /* Local access */
    }
    return 20;  /* Remote access */
}

void *numa_alloc_on_node(size_t size, int node) {
    /*
     * STUB IMPLEMENTATION
     *
     * Use aligned_alloc with 128-byte alignment for cache-line alignment.
     * This ensures the memory plays well with our CACHE_ALIGNED structures.
     *
     * Full implementation would use:
     *   void *ptr = mmap(...);
     *   mbind(ptr, size, MPOL_BIND, node_mask, ...);
     *
     * The memory will be allocated on the first-touch node.
     */
    (void)node;  /* Unused in stub */

    /*
     * Round up size to multiple of CACHELINE_SIZE for aligned_alloc
     */
    size_t aligned_size = (size + CACHELINE_SIZE - 1) & ~(CACHELINE_SIZE - 1);

    /*
     * aligned_alloc requires size to be multiple of alignment.
     * C11 guarantees this behavior.
     */
    void *ptr = aligned_alloc(CACHELINE_SIZE, aligned_size);

    /*
     * TODO(post-1.0): Implement NUMA-aware allocation with libnuma
     *
     * Priority: Medium (only matters on multi-socket servers)
     * Dependencies: libnuma-devel package
     * Implementation:
     *   #include <numa.h>
     *   return numa_alloc_onnode(size, node);
     */

    return ptr;
}

void *numa_alloc_hugepages_on_node(size_t size, int node) {
    /*
     * STUB IMPLEMENTATION
     *
     * Full implementation would use mbind() after hugepage_alloc()
     * to bind the pages to a specific NUMA node.
     */
    (void)node;  /* Unused in stub */

    /*
     * TODO(post-1.0): Implement NUMA-aware hugepage allocation
     *
     * Implementation:
     *   void *ptr = hugepage_alloc(size);
     *   if (ptr && node >= 0) {
     *       unsigned long node_mask = 1UL << node;
     *       mbind(ptr, size, MPOL_BIND, &node_mask, NUMA_MAX_NODES, 0);
     *   }
     *   return ptr;
     */

    return hugepage_alloc(size);
}

void numa_free(void *ptr, size_t size) {
    /*
     * For stub implementation using aligned_alloc(), we use free().
     * (aligned_alloc memory is freed with free() per C11)
     *
     * Full implementation with numa_alloc_onnode() would use:
     *   numa_free(ptr, size);
     */
    (void)size;  /* Unused with aligned_alloc-based stub */

    free(ptr);
}

bool numa_pin_thread(uint64_t thread_id, int node) {
    /*
     * STUB IMPLEMENTATION with basic sched_setaffinity
     *
     * This is a "generic" pinning that logs the target.
     * Full NUMA-aware pinning would:
     * 1. Read /sys/devices/system/node/node<N>/cpulist
     * 2. Build a CPU mask from that list
     * 3. Apply with sched_setaffinity()
     *
     * For now, we just log the request for performance profiling.
     */

    fprintf(stderr, "[DEBUG] NUMA_PIN: Thread %lu requested pin to node %d\n",
            (unsigned long)thread_id, node);

    /*
     * On single-node systems (our current target), there's nothing to pin to.
     * We still log the request so DEBUG_LOG shows where we *would* have pinned.
     */
    if (!numa_is_available()) {
        fprintf(stderr, "[DEBUG] NUMA_PIN: Single-node system, "
                        "no pinning needed\n");
        return true;
    }

    /*
     * TODO(post-1.0): Implement actual thread pinning
     *
     * Implementation outline:
     *   char cpulist_path[128];
     *   snprintf(cpulist_path, sizeof(cpulist_path),
     *            "/sys/devices/system/node/node%d/cpulist", node);
     *   // Parse cpulist (e.g., "0-3,8-11") into cpu_set_t
     *   cpu_set_t cpuset;
     *   CPU_ZERO(&cpuset);
     *   // ... parse and set CPUs ...
     *   return sched_setaffinity((pid_t)thread_id, sizeof(cpuset), &cpuset) == 0;
     */

    fprintf(stderr, "[DEBUG] NUMA_PIN: STUB - thread not actually pinned "
                    "(post-1.0 feature)\n");

    return true;  /* Stub always "succeeds" */
}
