/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * sslsniff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 sslsniff authors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * bpf_loader.h - BPF program loading and uprobe attachment
 */

#ifndef BPF_LOADER_H
#define BPF_LOADER_H

#include <stdbool.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_LINKS 32

/* BPF loader state */
typedef struct {
    struct bpf_object *obj;
    struct bpf_link *links[MAX_LINKS];
    int link_count;
} bpf_loader_t;

/* Initialize BPF loader - returns 0 on success, -1 on failure */
[[nodiscard]] int bpf_loader_init(bpf_loader_t *loader);

/* Load BPF object from file - returns 0 on success, negative on failure */
[[nodiscard]] int bpf_loader_load(bpf_loader_t *loader, const char *filename);

/* Find a library path by name (static paths) - returns 0 on success, -1 if not found */
int bpf_loader_find_library(const char *name, char *path, size_t size);

/* Library types for dynamic discovery */
typedef enum {
    LIB_OPENSSL = 0,
    LIB_GNUTLS,
    LIB_NSS,
    LIB_NSS_SSL,
    LIB_TYPE_COUNT
} lib_type_t;

/* Discovered library information */
typedef struct {
    char path[512];
    lib_type_t type;
    bool found;
} discovered_lib_t;

/* Discovery result - holds multiple library paths */
typedef struct {
    discovered_lib_t libs[LIB_TYPE_COUNT];
    int count;
} lib_discovery_result_t;

/* Discover SSL libraries from running processes
 * Scans /proc/PID/maps to find actually loaded libraries.
 * @param pids       Array of PIDs to scan (NULL = scan all processes)
 * @param pid_count  Number of PIDs in array
 * @param result     Output: discovered library information
 * @return 0 on success (at least one library found), -1 on failure
 */
int bpf_loader_discover_libraries(const int *pids, int pid_count,
                                   lib_discovery_result_t *result);

/* Find library path with dynamic discovery fallback
 * Tries /proc/PID/maps first, falls back to static paths.
 * @param name       Library name (e.g., "libssl.so")
 * @param path       Output buffer for found path
 * @param size       Size of output buffer
 * @param pids       Optional: specific PIDs to scan
 * @param pid_count  Number of PIDs (0 to scan all processes)
 * @return 0 on success, -1 if not found
 */
int bpf_loader_find_library_dynamic(const char *name, char *path, size_t size,
                                     const int *pids, int pid_count);

/* Attach uprobe to a symbol - returns 0 on success, -1 on failure
 * Note: Failure to attach individual probes is often non-fatal */
int bpf_loader_attach_uprobe(bpf_loader_t *loader, const char *lib,
                             const char *sym, const char *prog_name,
                             bool is_ret, bool debug);

/* Attach tracepoint - returns 0 on success, -1 on failure */
int bpf_loader_attach_tracepoint(bpf_loader_t *loader, const char *category,
                                  const char *name, const char *prog_name,
                                  bool debug);

/* Get BPF object (for ring buffer setup) */
struct bpf_object *bpf_loader_get_object(bpf_loader_t *loader);

/* Get number of attached probes */
int bpf_loader_get_link_count(bpf_loader_t *loader);

/* Cleanup BPF resources */
void bpf_loader_cleanup(bpf_loader_t *loader);

#endif /* BPF_LOADER_H */
