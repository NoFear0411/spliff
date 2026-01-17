/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
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
 */

#include "bpf_loader.h"
#include "binary_scanner.h"
#include "boringssl_offsets.h"
#include "../include/spliff.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdarg.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <linux/if_link.h>
#include <fcntl.h>

/* Initialize BPF loader */
int bpf_loader_init(bpf_loader_t *loader) {
    if (!loader) return -1;

    memset(loader, 0, sizeof(*loader));
    loader->obj = NULL;
    loader->link_count = 0;

    /* Initialize XDP state */
    loader->xdp.xdp_prog = NULL;
    loader->xdp.interface_count = 0;
    loader->xdp.xdp_rb = NULL;
    loader->xdp.event_callback = NULL;
    loader->xdp.callback_ctx = NULL;
    loader->xdp.xdp_events_fd = -1;
    loader->xdp.session_registry_fd = -1;
    loader->xdp.flow_states_fd = -1;
    loader->xdp.xdp_stats_fd = -1;
    loader->xdp.cookie_to_ssl_fd = -1;
    loader->xdp.flow_cookie_map_fd = -1;
    loader->xdp.enabled = false;
    loader->xdp.sockops_link = NULL;
    loader->xdp.cgroup_fd = -1;

    /* Set memory limits for BPF */
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    return 0;
}

/* Load BPF object from file */
int bpf_loader_load(bpf_loader_t *loader, const char *filename) {
    if (!loader || !filename) return -1;

    loader->obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(loader->obj)) {
        loader->obj = NULL;
        return -1;
    }

    int err = bpf_object__load(loader->obj);
    if (err) {
        bpf_object__close(loader->obj);
        loader->obj = NULL;
        return err;
    }

    return 0;
}

/* Validate library name - only allow safe characters */
static bool is_safe_library_name(const char *name) {
    if (!name || !*name) return false;

    /* Library names should only contain: a-z, A-Z, 0-9, ., -, _ */
    for (const char *p = name; *p; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) {
            return false;
        }
    }
    return true;
}

/* Find a library path by name (safe implementation without shell) */
int bpf_loader_find_library(const char *name, char *path, size_t size) {
    if (!name || !path || size == 0) return -1;

    /* Validate library name to prevent path traversal */
    if (!is_safe_library_name(name)) return -1;

    /* Common library directories to search */
    const char *dirs[] = {
        "/usr/lib/x86_64-linux-gnu/",
        "/lib/x86_64-linux-gnu/",
        "/usr/lib64/",
        "/lib64/",
        "/usr/lib/",
        "/lib/",
        "/usr/lib/aarch64-linux-gnu/",
        "/lib/aarch64-linux-gnu/",
        NULL
    };

    /* Try exact name first */
    for (int i = 0; dirs[i]; i++) {
        snprintf(path, size, "%s%s", dirs[i], name);
        if (access(path, F_OK) == 0) return 0;
    }

    /* Try versioned library names (e.g., libssl.so -> libssl.so.3) */
    const char *ext = strrchr(name, '.');
    if (ext && strcmp(ext, ".so") == 0) {
        char base[256];
        size_t base_len = ext - name;
        if (base_len >= sizeof(base)) return -1;
        memcpy(base, name, base_len);
        base[base_len] = '\0';

        /* Try common version suffixes */
        const char *versions[] = { ".so.3", ".so.30", ".so.1", ".so.4", NULL };
        for (int i = 0; dirs[i]; i++) {
            for (int v = 0; versions[v]; v++) {
                snprintf(path, size, "%s%s%s", dirs[i], base, versions[v]);
                if (access(path, F_OK) == 0) return 0;
            }
        }
    }

    return -1;
}

/* Library name patterns for dynamic discovery */
static const char *lib_patterns[] = {
    [LIB_OPENSSL]   = "libssl.so",
    [LIB_GNUTLS]    = "libgnutls.so",
    [LIB_NSS]       = "libnspr4.so",
    [LIB_NSS_SSL]   = "libssl3.so",
    [LIB_WOLFSSL]   = "libwolfssl.so",
    [LIB_BORINGSSL] = NULL,  /* Statically linked - no library pattern */
};

/* Library type names for display */
static const char *lib_type_names[] = {
    [LIB_OPENSSL]   = "OpenSSL",
    [LIB_GNUTLS]    = "GnuTLS",
    [LIB_NSS]       = "NSS",
    [LIB_NSS_SSL]   = "NSS-SSL",
    [LIB_WOLFSSL]   = "WolfSSL",
    [LIB_BORINGSSL] = "BoringSSL",
};

/* Get library type name */
const char *bpf_loader_lib_type_name(lib_type_t type) {
    if (type >= 0 && type < LIB_TYPE_COUNT) {
        return lib_type_names[type];
    }
    return "Unknown";
}

/* Check if path matches a library pattern and return type */
static int match_library_pattern(const char *path, lib_type_t *out_type) {
    for (int i = 0; i < LIB_TYPE_COUNT; i++) {
        if (lib_patterns[i] && strstr(path, lib_patterns[i]) != NULL) {
            *out_type = (lib_type_t)i;
            return 0;
        }
    }
    return -1;
}

/* Check if path is already in extended results for a type */
static bool path_already_tracked(lib_discovery_result_t *result, lib_type_t type, const char *path) {
    lib_paths_t *ext = &result->extended[type];
    for (int i = 0; i < ext->path_count; i++) {
        if (strcmp(ext->paths[i], path) == 0) {
            return true;
        }
    }
    return false;
}

/* Add path to extended results */
static void add_extended_path(lib_discovery_result_t *result, lib_type_t type, const char *path) {
    lib_paths_t *ext = &result->extended[type];
    if (ext->path_count < MAX_PATHS_PER_TYPE) {
        strncpy(ext->paths[ext->path_count], path, 511);
        ext->paths[ext->path_count][511] = '\0';
        ext->path_count++;
        ext->found = true;
        result->total_unique_paths++;
    }
}

/* Parse /proc/PID/maps to find loaded SSL libraries */
static int parse_proc_maps(int pid, lib_discovery_result_t *result) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *f = fopen(maps_path, "r");
    if (!f) return -1;

    result->processes_scanned++;
    bool found_ssl = false;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        /* Format: address perms offset dev inode pathname */
        /* Find the pathname (starts with /) */
        char *pathname = strchr(line, '/');
        if (!pathname) continue;

        /* Remove trailing newline */
        char *nl = strchr(pathname, '\n');
        if (nl) *nl = '\0';

        /* Check if this is a library we care about */
        lib_type_t lib_type;
        if (match_library_pattern(pathname, &lib_type) == 0) {
            found_ssl = true;

            /* Quick lookup (first path found per type) - backward compatible */
            if (!result->libs[lib_type].found) {
                strncpy(result->libs[lib_type].path, pathname,
                        sizeof(result->libs[lib_type].path) - 1);
                result->libs[lib_type].path[sizeof(result->libs[lib_type].path) - 1] = '\0';
                result->libs[lib_type].type = lib_type;
                result->libs[lib_type].found = true;
                result->libs[lib_type].process_count = 1;
                result->count++;

                /* Also add to extended paths */
                add_extended_path(result, lib_type, pathname);
            } else {
                /* Already have this type, increment process count for primary */
                result->libs[lib_type].process_count++;

                /* Track additional unique paths */
                if (!path_already_tracked(result, lib_type, pathname)) {
                    add_extended_path(result, lib_type, pathname);
                }
            }
        }
    }

    if (found_ssl) {
        result->processes_with_ssl++;
    }

    fclose(f);
    return 0;
}

/* Firefox bundled library paths to check */
static const char *firefox_bundled_paths[] = {
    "/usr/lib/firefox/libnspr4.so",
    "/usr/lib/firefox/libssl3.so",
    "/usr/lib/firefox/libnss3.so",
    "/usr/lib64/firefox/libnspr4.so",
    "/usr/lib64/firefox/libssl3.so",
    "/usr/lib64/firefox/libnss3.so",
    "/opt/firefox/libnspr4.so",
    "/opt/firefox/libssl3.so",
    "/snap/firefox/current/usr/lib/firefox/libnspr4.so",
    "/snap/firefox/current/usr/lib/firefox/libssl3.so",
    "/snap/core22/current/usr/lib/x86_64-linux-gnu/libssl.so.3",
    NULL
};

/* Check for Firefox bundled libraries */
static void check_firefox_bundled_libs(lib_discovery_result_t *result) {
    for (int i = 0; firefox_bundled_paths[i] != NULL; i++) {
        const char *path = firefox_bundled_paths[i];

        /* Check if file exists */
        if (access(path, F_OK) != 0) continue;

        /* Determine library type */
        lib_type_t lib_type;
        if (match_library_pattern(path, &lib_type) != 0) continue;

        /* Add if not already tracked */
        if (!path_already_tracked(result, lib_type, path)) {
            add_extended_path(result, lib_type, path);

            /* Also update primary if not set */
            if (!result->libs[lib_type].found) {
                strncpy(result->libs[lib_type].path, path,
                        sizeof(result->libs[lib_type].path) - 1);
                result->libs[lib_type].path[sizeof(result->libs[lib_type].path) - 1] = '\0';
                result->libs[lib_type].type = lib_type;
                result->libs[lib_type].found = true;
                result->libs[lib_type].process_count = 0;  /* Static discovery */
                result->count++;
            }
        }
    }
}

/* Discover SSL libraries from running processes */
int bpf_loader_discover_libraries(const int *pids, int pid_count,
                                   lib_discovery_result_t *result) {
    if (!result) return -1;

    memset(result, 0, sizeof(*result));

    if (pids && pid_count > 0) {
        /* Scan specific PIDs */
        for (int i = 0; i < pid_count; i++) {
            parse_proc_maps(pids[i], result);
        }
    } else {
        /* Scan all processes in /proc */
        DIR *proc = opendir("/proc");
        if (!proc) return -1;

        struct dirent *entry;
        while ((entry = readdir(proc)) != NULL) {
            /* Skip non-numeric entries */
            if (!isdigit((unsigned char)entry->d_name[0])) continue;

            char *endptr;
            long pid_long = strtol(entry->d_name, &endptr, 10);
            if (*endptr != '\0' || pid_long <= 0 || pid_long > INT_MAX) continue;

            parse_proc_maps((int)pid_long, result);
            /* NOTE: No early exit - scan ALL processes for complete discovery */
        }

        closedir(proc);
    }

    /* Also check Firefox bundled paths */
    check_firefox_bundled_libs(result);

    return (result->count > 0) ? 0 : -1;
}

/* Print discovered libraries (for verbose output) */
void bpf_loader_print_discovery(const lib_discovery_result_t *result) {
    if (!result) return;

    printf("SSL Library Discovery:\n");
    printf("  Processes scanned: %d\n", result->processes_scanned);
    printf("  Processes with SSL: %d\n", result->processes_with_ssl);
    printf("  Unique library paths: %d\n", result->total_unique_paths);
    printf("\n");

    for (int type = 0; type < LIB_TYPE_COUNT; type++) {
        const lib_paths_t *ext = &result->extended[type];
        if (!ext->found) continue;

        printf("  %s:\n", lib_type_names[type]);
        for (int i = 0; i < ext->path_count; i++) {
            const char *marker = (i == 0) ? "(primary)" : "";
            printf("    %s %s\n", ext->paths[i], marker);
        }
    }
    printf("\n");
}

/* Track scanned paths to avoid duplicate scanning */
#define MAX_SCANNED_PATHS 256
static char scanned_paths[MAX_SCANNED_PATHS][512];
static int scanned_path_count = 0;

static bool path_already_scanned(const char *path) {
    for (int i = 0; i < scanned_path_count; i++) {
        if (strcmp(scanned_paths[i], path) == 0) {
            return true;
        }
    }
    return false;
}

static void mark_path_scanned(const char *path) {
    if (scanned_path_count < MAX_SCANNED_PATHS) {
        snprintf(scanned_paths[scanned_path_count], sizeof(scanned_paths[0]), "%s", path);
        scanned_path_count++;
    }
}

/* Check if a binary path is already tracked in BoringSSL discovery results */
static bool boringssl_path_tracked(lib_discovery_result_t *result, const char *path) {
    for (int i = 0; i < result->boringssl_count; i++) {
        if (strcmp(result->boringssl[i].path, path) == 0) {
            return true;
        }
    }
    return false;
}

/* Discover BoringSSL binaries from running processes (EDR-style detection) */
int bpf_loader_discover_boringssl(lib_discovery_result_t *result,
                                   uint64_t min_size_mb, bool debug) {
    if (!result) return -1;

    /* Reset BoringSSL discovery state */
    memset(result->boringssl, 0, sizeof(result->boringssl));
    result->boringssl_count = 0;

    /* Reset scanned paths tracker */
    scanned_path_count = 0;

    uint64_t min_size_bytes = min_size_mb * 1024 * 1024;

    DIR *proc = opendir("/proc");
    if (!proc) return -1;

    int known_count = 0;
    struct dirent *dir_entry;

    while ((dir_entry = readdir(proc)) != NULL) {
        /* Skip non-numeric entries */
        if (!isdigit((unsigned char)dir_entry->d_name[0])) continue;

        char *endptr;
        long pid_long = strtol(dir_entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid_long <= 0 || pid_long > INT_MAX) continue;
        int pid = (int)pid_long;

        /* Read /proc/PID/exe to get binary path */
        char exe_link[64];
        char exe_path[512];
        snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);

        ssize_t len = readlink(exe_link, exe_path, sizeof(exe_path) - 1);
        if (len <= 0) continue;
        exe_path[len] = '\0';

        /* Skip deleted binaries (shows as "path (deleted)") */
        if (strstr(exe_path, "(deleted)") != NULL) continue;

        /* Skip if already scanned (avoids duplicate scanning) */
        if (path_already_scanned(exe_path)) {
            /* If it's a known BoringSSL binary, increment process count */
            if (boringssl_path_tracked(result, exe_path)) {
                for (int i = 0; i < result->boringssl_count; i++) {
                    if (strcmp(result->boringssl[i].path, exe_path) == 0) {
                        result->boringssl[i].process_count++;
                        break;
                    }
                }
            }
            continue;
        }

        /* Mark as scanned BEFORE checking size/content (prevents rescanning) */
        mark_path_scanned(exe_path);

        /* Check binary size (performance filter) */
        struct stat st;
        if (stat(exe_path, &st) != 0) continue;
        uint64_t binary_size = (uint64_t)st.st_size;

        if (min_size_bytes > 0 && binary_size < min_size_bytes) continue;

        if (debug) {
            fprintf(stderr, "[boringssl] Scanning: %s (%.1f MB)\n",
                    exe_path, binary_size / (1024.0 * 1024.0));
        }

        /* Check for BoringSSL signature in binary */
        if (!binary_has_boringssl(exe_path)) {
            if (debug && binary_size > 100 * 1024 * 1024) {
                /* Log large binaries that don't have BoringSSL for debugging */
                fprintf(stderr, "[boringssl]   No BoringSSL signature (skipped)\n");
            }
            continue;
        }

        if (debug) {
            fprintf(stderr, "[boringssl]   BoringSSL signature found\n");
        }

        /* Scan binary for offsets using build ID lookup */
        struct boringssl_offsets offsets;
        int scan_result = scan_binary_for_boringssl(exe_path, &offsets, debug);

        /* Add to discovery results */
        if (result->boringssl_count >= MAX_BORINGSSL_BINARIES) {
            if (debug) {
                fprintf(stderr, "[boringssl] Max binaries reached, skipping %s\n", exe_path);
            }
            continue;
        }

        discovered_boringssl_t *out = &result->boringssl[result->boringssl_count];
        snprintf(out->path, sizeof(out->path), "%s", exe_path);
        snprintf(out->build_id, sizeof(out->build_id), "%s", offsets.build_id);
        out->binary_size = binary_size;
        out->process_count = 1;

        if (scan_result == 0 && offsets.found) {
            out->offsets_known = true;
            out->ssl_read_offset = offsets.ssl_read_offset;
            out->ssl_write_offset = offsets.ssl_write_offset;
            out->ssl_read_impl_offset = offsets.ssl_read_impl_offset;
            out->ssl_write_impl_offset = offsets.ssl_write_impl_offset;
            out->do_payload_read_offset = offsets.do_payload_read_offset;
            out->socket_read_offset = offsets.socket_read_offset;
            out->on_read_ready_offset = offsets.on_read_ready_offset;
            out->version_info = offsets.version_info;
            known_count++;

            if (debug) {
                fprintf(stderr, "[boringssl]   Matched: %s (build %s)\n",
                        out->version_info ? out->version_info : "unknown",
                        out->build_id);
            }
        } else {
            out->offsets_known = false;
            if (debug) {
                fprintf(stderr, "[boringssl]   Unknown build ID: %s\n", out->build_id);
            }
        }

        result->boringssl_count++;
    }

    closedir(proc);
    return known_count;
}

/* Find library with dynamic discovery fallback */
int bpf_loader_find_library_dynamic(const char *name, char *path, size_t size,
                                     const int *pids, int pid_count) {
    if (!name || !path || size == 0) return -1;

    /* Determine which library type we're looking for */
    lib_type_t target_type = LIB_TYPE_COUNT;
    for (int i = 0; i < LIB_TYPE_COUNT; i++) {
        if (strstr(name, lib_patterns[i]) != NULL) {
            target_type = (lib_type_t)i;
            break;
        }
    }

    if (target_type != LIB_TYPE_COUNT) {
        /* Try dynamic discovery */
        lib_discovery_result_t result;
        if (bpf_loader_discover_libraries(pids, pid_count, &result) == 0) {
            if (result.libs[target_type].found) {
                strncpy(path, result.libs[target_type].path, size - 1);
                path[size - 1] = '\0';
                return 0;
            }
        }
    }

    /* Fall back to static search */
    return bpf_loader_find_library(name, path, size);
}

/* Attach uprobe to a symbol */
int bpf_loader_attach_uprobe(bpf_loader_t *loader, const char *lib,
                             const char *sym, const char *prog_name,
                             bool is_ret, bool debug) {
    if (!loader || !loader->obj || !lib || !sym || !prog_name) return -1;

    struct bpf_program *prog = bpf_object__find_program_by_name(loader->obj, prog_name);
    if (!prog) {
        if (debug) {
            DEBUG_LOG("Program '%s' not found in BPF object", prog_name);
        }
        return -1;
    }

    LIBBPF_OPTS(bpf_uprobe_opts, opts, .func_name = sym, .retprobe = is_ret);

    if (loader->link_count >= SPLIFF_MAX_LINKS) return -1;

    loader->links[loader->link_count] = bpf_program__attach_uprobe_opts(prog, -1, lib, 0, &opts);

    if (!libbpf_get_error(loader->links[loader->link_count])) {
        if (debug) {
            printf("  [DEBUG] Attached %s:%s → %s\n", lib, sym, prog_name);
        }
        loader->link_count++;
        return 0;
    }

    if (debug) {
        DEBUG_LOG("Failed to attach %s:%s", lib, sym);
    }
    loader->links[loader->link_count] = NULL;
    return -1;
}

/* Attach uprobe by file offset (for stripped binaries) */
int bpf_loader_attach_uprobe_offset(bpf_loader_t *loader, const char *binary,
                                     uint64_t offset, const char *prog_name,
                                     bool is_ret, bool debug) {
    if (!loader || !loader->obj || !binary || !prog_name || offset == 0)
        return -1;

    struct bpf_program *prog = bpf_object__find_program_by_name(loader->obj, prog_name);
    if (!prog) {
        if (debug) {
            DEBUG_LOG("Program '%s' not found in BPF object", prog_name);
        }
        return -1;
    }

    /* For offset-based attachment, set func_name to NULL and use offset */
    LIBBPF_OPTS(bpf_uprobe_opts, opts,
        .func_name = NULL,
        .retprobe = is_ret
    );

    if (loader->link_count >= SPLIFF_MAX_LINKS) {
        if (debug) {
            DEBUG_LOG("Maximum link count reached");
        }
        return -1;
    }

    /* Attach with pid=-1 to capture all processes using this binary */
    loader->links[loader->link_count] = bpf_program__attach_uprobe_opts(
        prog, -1, binary, offset, &opts);

    if (!libbpf_get_error(loader->links[loader->link_count])) {
        if (debug) {
            printf("  [DEBUG] Attached %s:0x%lx → %s%s\n",
                   binary, offset, prog_name, is_ret ? " (ret)" : "");
        }
        loader->link_count++;
        return 0;
    }

    long err = libbpf_get_error(loader->links[loader->link_count]);
    /* Always print this error - uprobe offset attachment failures need visibility */
    fprintf(stderr, "  [ERROR] Failed to attach uprobe %s:0x%lx → %s (errno: %ld - %s)\n",
            binary, offset, prog_name, -err, strerror((int)-err));
    loader->links[loader->link_count] = NULL;
    (void)debug;
    return -1;
}

/* Attach tracepoint */
int bpf_loader_attach_tracepoint(bpf_loader_t *loader, const char *category,
                                  const char *name, const char *prog_name,
                                  bool debug) {
    if (!loader || !loader->obj || !category || !name || !prog_name) return -1;

    struct bpf_program *prog = bpf_object__find_program_by_name(loader->obj, prog_name);
    if (!prog) {
        if (debug) {
            DEBUG_LOG("Program '%s' not found in BPF object", prog_name);
        }
        return -1;
    }

    if (loader->link_count >= SPLIFF_MAX_LINKS) return -1;

    loader->links[loader->link_count] = bpf_program__attach_tracepoint(prog, category, name);

    if (!libbpf_get_error(loader->links[loader->link_count])) {
        if (debug) {
            printf("  [DEBUG] Attached tracepoint:%s/%s → %s\n", category, name, prog_name);
        }
        loader->link_count++;
        return 0;
    }

    if (debug) {
        DEBUG_LOG("Failed to attach tracepoint %s/%s", category, name);
    }
    loader->links[loader->link_count] = NULL;
    return -1;
}

/* Get BPF object (for ring buffer setup) */
struct bpf_object *bpf_loader_get_object(bpf_loader_t *loader) {
    return loader ? loader->obj : NULL;
}

/* Get number of attached probes */
int bpf_loader_get_link_count(bpf_loader_t *loader) {
    return loader ? loader->link_count : 0;
}

/* Cleanup BPF resources */
void bpf_loader_cleanup(bpf_loader_t *loader) {
    if (!loader) return;

    /* Detach XDP from all interfaces first */
    bpf_loader_xdp_detach_all(loader, false);

    /* Detach sock_ops program */
    bpf_loader_sockops_detach(loader, false);

    /* Free XDP ring buffer */
    if (loader->xdp.xdp_rb) {
        ring_buffer__free(loader->xdp.xdp_rb);
        loader->xdp.xdp_rb = NULL;
    }

    /* Reset XDP state */
    loader->xdp.xdp_prog = NULL;
    loader->xdp.interface_count = 0;
    loader->xdp.xdp_events_fd = -1;
    loader->xdp.session_registry_fd = -1;
    loader->xdp.flow_states_fd = -1;
    loader->xdp.xdp_stats_fd = -1;
    loader->xdp.cookie_to_ssl_fd = -1;
    loader->xdp.flow_cookie_map_fd = -1;
    loader->xdp.enabled = false;

    /* Close all links */
    for (int i = 0; i < SPLIFF_MAX_LINKS; i++) {
        if (loader->links[i]) {
            bpf_link__destroy(loader->links[i]);
            loader->links[i] = NULL;
        }
    }

    /* Close BPF object */
    if (loader->obj) {
        bpf_object__close(loader->obj);
        loader->obj = NULL;
    }

    loader->link_count = 0;
}

// =============================================================================
// XDP Implementation
// =============================================================================

/* Helper to set XDP error */
static void xdp_set_error(xdp_loader_t *xdp, xdp_error_t *err_out,
                          int code, const char *fmt, ...) {
    char msg[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    if (xdp) {
        xdp->last_error.code = code;
        strncpy(xdp->last_error.message, msg, sizeof(xdp->last_error.message) - 1);
        xdp->last_error.message[sizeof(xdp->last_error.message) - 1] = '\0';
    }
    if (err_out) {
        err_out->code = code;
        strncpy(err_out->message, msg, sizeof(err_out->message) - 1);
        err_out->message[sizeof(err_out->message) - 1] = '\0';
    }
}

/* Get XDP mode name for display */
const char *bpf_loader_xdp_mode_name(xdp_mode_t mode) {
    switch (mode) {
        case XDP_MODE_SKB:     return "skb";
        case XDP_MODE_NATIVE:  return "native";
        case XDP_MODE_OFFLOAD: return "offload";
        default:               return "unknown";
    }
}

/* Convert our mode enum to libbpf XDP flags */
static __u32 mode_to_xdp_flags(xdp_mode_t mode) {
    switch (mode) {
        case XDP_MODE_NATIVE:  return XDP_FLAGS_DRV_MODE;
        case XDP_MODE_OFFLOAD: return XDP_FLAGS_HW_MODE;
        case XDP_MODE_SKB:
        default:               return XDP_FLAGS_SKB_MODE;
    }
}

/* Check kernel support for XDP features */
int bpf_loader_xdp_check_kernel_support(xdp_error_t *err_out) {
    struct utsname uts;
    if (uname(&uts) != 0) {
        if (err_out) {
            err_out->code = -errno;
            snprintf(err_out->message, sizeof(err_out->message),
                     "Failed to get kernel version: %s", strerror(errno));
        }
        return -1;
    }

    /* Parse kernel version (major.minor.patch) */
    int major = 0, minor = 0;
    sscanf(uts.release, "%d.%d", &major, &minor);

    /* Require Linux >= 5.8 for XDP socket lookup (bpf_skc_lookup_tcp) */
    if (major < 5 || (major == 5 && minor < 8)) {
        if (err_out) {
            err_out->code = -ENOTSUP;
            snprintf(err_out->message, sizeof(err_out->message),
                     "Kernel %d.%d too old for XDP socket lookup (need >= 5.8)",
                     major, minor);
        }
        return -1;
    }

    return 0;
}

/* Ring buffer callback wrapper */
static int xdp_rb_callback(void *ctx, void *data, size_t data_sz) {
    bpf_loader_t *loader = (bpf_loader_t *)ctx;
    if (!loader || !loader->xdp.event_callback) {
        return 0;  /* Discard event if no callback */
    }
    return loader->xdp.event_callback(loader->xdp.callback_ctx, data, data_sz);
}

/* Initialize XDP subsystem */
int bpf_loader_xdp_init(bpf_loader_t *loader, bool debug, xdp_error_t *err_out) {
    if (!loader || !loader->obj) {
        if (err_out) {
            xdp_set_error(NULL, err_out, -EINVAL, "Loader or BPF object not initialized");
        }
        return -1;
    }

    xdp_loader_t *xdp = &loader->xdp;

    /* Find XDP program */
    xdp->xdp_prog = bpf_object__find_program_by_name(loader->obj, "xdp_flow_tracker");
    if (!xdp->xdp_prog) {
        xdp_set_error(xdp, err_out, -ENOENT, "XDP program 'xdp_flow_tracker' not found");
        return -1;
    }

    if (debug) {
        printf("  [XDP] Found program: xdp_flow_tracker\n");
    }

    /* Find required maps */
    struct bpf_map *map;

    map = bpf_object__find_map_by_name(loader->obj, "flow_states");
    if (!map) {
        xdp_set_error(xdp, err_out, -ENOENT, "Required map 'flow_states' not found");
        return -1;
    }
    xdp->flow_states_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(loader->obj, "session_registry");
    if (!map) {
        xdp_set_error(xdp, err_out, -ENOENT, "Required map 'session_registry' not found");
        return -1;
    }
    xdp->session_registry_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(loader->obj, "xdp_events");
    if (!map) {
        xdp_set_error(xdp, err_out, -ENOENT, "Required map 'xdp_events' not found");
        return -1;
    }
    xdp->xdp_events_fd = bpf_map__fd(map);

    if (debug) {
        printf("  [XDP] Found required maps: flow_states, session_registry, xdp_events\n");
    }

    /* Find optional maps */
    map = bpf_object__find_map_by_name(loader->obj, "cookie_to_ssl");
    if (map) {
        xdp->cookie_to_ssl_fd = bpf_map__fd(map);
        if (debug) printf("  [XDP] Found optional map: cookie_to_ssl\n");
    }

    map = bpf_object__find_map_by_name(loader->obj, "flow_cookie_map");
    if (map) {
        xdp->flow_cookie_map_fd = bpf_map__fd(map);
        if (debug) printf("  [XDP] Found map: flow_cookie_map (for cookie caching)\n");
    }

    map = bpf_object__find_map_by_name(loader->obj, "xdp_stats_map");
    if (map) {
        xdp->xdp_stats_fd = bpf_map__fd(map);
        if (debug) printf("  [XDP] Found optional map: xdp_stats_map\n");
    }

    xdp->enabled = true;
    if (debug) {
        printf("  [XDP] Initialization complete\n");
    }

    return 0;
}

/* Register callback for XDP ring buffer events */
int bpf_loader_xdp_set_event_callback(bpf_loader_t *loader,
                                       xdp_event_callback_t callback,
                                       void *ctx) {
    if (!loader || !loader->xdp.enabled) {
        return -1;
    }

    loader->xdp.event_callback = callback;
    loader->xdp.callback_ctx = ctx;

    /* Create ring buffer if not already created */
    if (!loader->xdp.xdp_rb && loader->xdp.xdp_events_fd >= 0) {
        loader->xdp.xdp_rb = ring_buffer__new(loader->xdp.xdp_events_fd,
                                               xdp_rb_callback,
                                               loader, NULL);
        if (!loader->xdp.xdp_rb) {
            xdp_set_error(&loader->xdp, NULL, -ENOMEM, "Failed to create ring buffer");
            return -1;
        }
    }

    return 0;
}

/* Check if interface is virtual (veth, docker, virbr, etc.)
 * Note: /sys/class/net/{name}/device check is more reliable for physical detection,
 * but this prefix list handles common edge cases where device symlink exists
 * but the interface is still logically virtual.
 */
static bool is_virtual_interface(const char *name) {
    const char *virtual_prefixes[] = {
        "veth", "docker", "virbr", "br-", "vlan", "bond",
        "tun", "tap", "vxlan", "geneve", "wg",
        "ipvlan", "macvlan", "xfrm",  /* Additional virtual types */
        NULL
    };

    for (int i = 0; virtual_prefixes[i]; i++) {
        if (strncmp(name, virtual_prefixes[i], strlen(virtual_prefixes[i])) == 0) {
            return true;
        }
    }
    return false;
}

/* Discover active network interfaces */
int bpf_loader_xdp_discover_interfaces(xdp_iface_info_t *ifaces, int max,
                                        int *count, int flags, bool debug) {
    if (!ifaces || !count || max <= 0) {
        return -1;
    }

    *count = 0;
    DIR *dir = opendir("/sys/class/net");
    if (!dir) {
        return -1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        closedir(dir);
        return -1;
    }

    int skipped_count = 0;  /* Track skipped interfaces for truncation warning */
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;

        /* Skip . and .. */
        if (name[0] == '.') continue;

        /* Skip loopback if requested */
        if ((flags & XDP_DISCOVER_SKIP_LOOPBACK) && strcmp(name, "lo") == 0) {
            continue;
        }

        /* Skip virtual interfaces if requested */
        if ((flags & XDP_DISCOVER_SKIP_VIRTUAL) && is_virtual_interface(name)) {
            continue;
        }

        /* Skip names longer than kernel limit (IFNAMSIZ = 16, max name = 15 chars) */
        size_t name_len = strlen(name);
        if (name_len >= IFNAMSIZ) {
            continue;  /* Invalid interface name length */
        }

        /* Get interface info via ioctl */
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        memcpy(ifr.ifr_name, name, name_len);  /* name_len < IFNAMSIZ guaranteed */

        if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
            continue;  /* Skip interfaces we can't query */
        }

        unsigned int if_flags = ifr.ifr_flags;

        /* Skip interfaces that are down if requested */
        if ((flags & XDP_DISCOVER_ONLY_UP) && !(if_flags & IFF_UP)) {
            continue;
        }

        /* Get interface index */
        if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
            continue;
        }
        unsigned int ifindex = ifr.ifr_ifindex;

        /* Get MTU */
        unsigned int mtu = 0;
        if (ioctl(sock, SIOCGIFMTU, &ifr) == 0) {
            mtu = ifr.ifr_mtu;
        } else if (debug) {
            printf("  [XDP] Warning: Could not get MTU for %s\n", name);
        }

        /* Check if physical (has a driver in /sys/class/net/<name>/device)
         * Path length: 15 + name_len(max 15) + 7 + 1 = 38 bytes max */
        char device_path[64];
        snprintf(device_path, sizeof(device_path), "/sys/class/net/%.*s/device",
                 (int)name_len, name);
        bool is_physical = (access(device_path, F_OK) == 0);

        /* Skip non-physical if only_physical requested */
        if ((flags & XDP_DISCOVER_ONLY_PHYSICAL) && !is_physical) {
            continue;
        }

        /* Check if we have room */
        if (*count >= max) {
            skipped_count++;
            continue;
        }

        /* Add to result */
        xdp_iface_info_t *info = &ifaces[*count];
        strncpy(info->name, name, sizeof(info->name) - 1);
        info->name[sizeof(info->name) - 1] = '\0';
        info->ifindex = ifindex;
        info->mtu = mtu;
        info->flags = if_flags;
        info->is_physical = is_physical;

        (*count)++;

        if (debug) {
            printf("  [XDP] Discovered interface: %s (idx=%u, mtu=%u, %s%s)\n",
                   name, ifindex, mtu,
                   (if_flags & IFF_UP) ? "UP" : "DOWN",
                   is_physical ? ", physical" : ", virtual");
        }
    }

    /* Warn if truncated */
    if (skipped_count > 0 && debug) {
        printf("  [XDP] Warning: Discovered interfaces truncated, %d skipped (max=%d)\n",
               skipped_count, max);
    }

    close(sock);
    closedir(dir);
    return 0;
}

/* Attach XDP program to a specific interface */
int bpf_loader_xdp_attach(bpf_loader_t *loader, const char *ifname,
                          xdp_mode_t mode, bool debug, xdp_error_t *err_out) {
    if (!loader || !loader->xdp.enabled || !ifname) {
        xdp_set_error(&loader->xdp, err_out, -EINVAL, "Invalid parameters");
        return -1;
    }

    xdp_loader_t *xdp = &loader->xdp;

    /* Validate interface name length (kernel limit is IFNAMSIZ=16) */
    size_t ifname_len = strlen(ifname);
    if (ifname_len == 0 || ifname_len >= IFNAMSIZ) {
        xdp_set_error(xdp, err_out, -EINVAL, "Invalid interface name length");
        return -1;
    }

    if (xdp->interface_count >= MAX_XDP_INTERFACES) {
        xdp_set_error(xdp, err_out, -ENOSPC, "Maximum interfaces reached (%d)",
                      MAX_XDP_INTERFACES);
        return -1;
    }

    /* Get interface index */
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        xdp_set_error(xdp, err_out, -ENODEV, "Interface '%s' not found", ifname);
        return -1;
    }

    /* Get program fd */
    int prog_fd = bpf_program__fd(xdp->xdp_prog);
    if (prog_fd < 0) {
        xdp_set_error(xdp, err_out, -ENOENT, "XDP program fd not available");
        return -1;
    }

    /* Try preferred mode first, fall back to SKB */
    xdp_mode_t actual_mode = mode;
    __u32 xdp_flags = mode_to_xdp_flags(mode);
    int err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);

    if (err && mode != XDP_MODE_SKB) {
        /* Fall back to SKB mode */
        if (debug) {
            printf("  [XDP] %s mode failed on %s, falling back to SKB mode\n",
                   bpf_loader_xdp_mode_name(mode), ifname);
        }
        actual_mode = XDP_MODE_SKB;
        xdp_flags = XDP_FLAGS_SKB_MODE;
        err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
    }

    if (err) {
        xdp_set_error(xdp, err_out, err, "Failed to attach XDP to %s: %s",
                      ifname, strerror(-err));
        return -1;
    }

    /* Record attachment (ifname_len validated < IFNAMSIZ at function start) */
    xdp_interface_t *iface = &xdp->interfaces[xdp->interface_count];
    memcpy(iface->name, ifname, ifname_len);
    iface->name[ifname_len] = '\0';
    iface->ifindex = ifindex;
    iface->prog_fd = prog_fd;
    iface->mode = actual_mode;
    iface->attached = true;
    xdp->interface_count++;

    if (debug) {
        printf("  [XDP] Attached to %s (idx=%u) in %s mode\n",
               ifname, ifindex, bpf_loader_xdp_mode_name(actual_mode));
    }

    return (int)actual_mode;
}

/* Attach XDP program to all suitable network interfaces (auto-discovery) */
int bpf_loader_xdp_attach_all(bpf_loader_t *loader, bool debug) {
    if (!loader || !loader->xdp.enabled) {
        return 0;
    }

    xdp_iface_info_t ifaces[MAX_XDP_INTERFACES];
    int count = 0;

    if (bpf_loader_xdp_discover_interfaces(ifaces, MAX_XDP_INTERFACES, &count,
                                            XDP_DISCOVER_DEFAULT, debug) != 0) {
        return 0;
    }

    int attached = 0;
    for (int i = 0; i < count; i++) {
        /* Try native mode first (best performance), auto-fallback to SKB */
        if (bpf_loader_xdp_attach(loader, ifaces[i].name,
                                   XDP_MODE_NATIVE, debug, NULL) >= 0) {
            attached++;
        }
    }

    if (debug) {
        printf("  [XDP] Attached to %d of %d discovered interfaces\n",
               attached, count);
    }

    return attached;
}

/* Attach sock_ops program for socket cookie caching */
int bpf_loader_sockops_attach(bpf_loader_t *loader, bool debug) {
    if (!loader || !loader->obj) {
        return -1;
    }

    xdp_loader_t *xdp = &loader->xdp;

    /* Find the sock_ops program */
    struct bpf_program *sockops_prog = bpf_object__find_program_by_name(
        loader->obj, "sockops_cache_cookie");
    if (!sockops_prog) {
        if (debug) {
            printf("  [SOCKOPS] Program 'sockops_cache_cookie' not found\n");
        }
        return -1;
    }

    /* Open root cgroup for attachment
     * sock_ops programs must be attached to a cgroup.
     * We use the root cgroup (cgroup2) so all connections are tracked.
     */
    const char *cgroup_paths[] = {
        "/sys/fs/cgroup",           /* cgroup2 unified hierarchy */
        "/sys/fs/cgroup/unified",   /* cgroup2 on hybrid systems */
        NULL
    };

    int cgroup_fd = -1;
    for (int i = 0; cgroup_paths[i] != NULL; i++) {
        cgroup_fd = open(cgroup_paths[i], O_RDONLY | O_DIRECTORY);
        if (cgroup_fd >= 0) {
            if (debug) {
                printf("  [SOCKOPS] Using cgroup: %s\n", cgroup_paths[i]);
            }
            break;
        }
    }

    if (cgroup_fd < 0) {
        if (debug) {
            printf("  [SOCKOPS] Cannot open cgroup (cgroup2 required)\n");
        }
        return -1;
    }

    /* Attach sock_ops to the cgroup */
    xdp->sockops_link = bpf_program__attach_cgroup(sockops_prog, cgroup_fd);
    if (!xdp->sockops_link || libbpf_get_error(xdp->sockops_link)) {
        if (debug) {
            printf("  [SOCKOPS] Failed to attach to cgroup: %s\n",
                   strerror(errno));
        }
        close(cgroup_fd);
        xdp->sockops_link = NULL;
        return -1;
    }

    xdp->cgroup_fd = cgroup_fd;

    if (debug) {
        printf("  [SOCKOPS] Attached socket cookie caching program\n");
    }

    return 0;
}

/* Detach sock_ops program */
void bpf_loader_sockops_detach(bpf_loader_t *loader, bool debug) {
    if (!loader) return;

    xdp_loader_t *xdp = &loader->xdp;

    if (xdp->sockops_link) {
        bpf_link__destroy(xdp->sockops_link);
        xdp->sockops_link = NULL;
        if (debug) {
            printf("  [SOCKOPS] Detached socket cookie caching program\n");
        }
    }

    if (xdp->cgroup_fd >= 0) {
        close(xdp->cgroup_fd);
        xdp->cgroup_fd = -1;
    }
}

/* Detach XDP program from a specific interface */
int bpf_loader_xdp_detach(bpf_loader_t *loader, const char *ifname, bool debug) {
    if (!loader || !ifname) {
        return -1;
    }

    xdp_loader_t *xdp = &loader->xdp;

    /* Find interface in our list */
    for (int i = 0; i < xdp->interface_count; i++) {
        if (strcmp(xdp->interfaces[i].name, ifname) == 0 &&
            xdp->interfaces[i].attached) {

            /* Detach XDP - pass 0 for flags to auto-detect */
            int err = bpf_xdp_detach(xdp->interfaces[i].ifindex, 0, NULL);
            if (err && debug) {
                printf("  [XDP] Warning: detach from %s failed: %s\n",
                       ifname, strerror(-err));
            }

            xdp->interfaces[i].attached = false;

            if (debug) {
                printf("  [XDP] Detached from %s\n", ifname);
            }
            return 0;
        }
    }

    return -1;  /* Not found */
}

/* Detach XDP from all attached interfaces */
void bpf_loader_xdp_detach_all(bpf_loader_t *loader, bool debug) {
    if (!loader) return;

    xdp_loader_t *xdp = &loader->xdp;

    for (int i = 0; i < xdp->interface_count; i++) {
        if (xdp->interfaces[i].attached) {
            int err = bpf_xdp_detach(xdp->interfaces[i].ifindex, 0, NULL);
            if (err && debug) {
                printf("  [XDP] Warning: detach from %s failed: %s\n",
                       xdp->interfaces[i].name, strerror(-err));
            }
            xdp->interfaces[i].attached = false;

            if (debug) {
                printf("  [XDP] Detached from %s\n", xdp->interfaces[i].name);
            }
        }
    }
}

/* Check if XDP is attached to a specific interface */
bool bpf_loader_xdp_is_attached(bpf_loader_t *loader, const char *ifname) {
    if (!loader || !ifname) return false;

    xdp_loader_t *xdp = &loader->xdp;
    for (int i = 0; i < xdp->interface_count; i++) {
        if (strcmp(xdp->interfaces[i].name, ifname) == 0) {
            return xdp->interfaces[i].attached;
        }
    }
    return false;
}

/* Get list of currently attached interfaces */
int bpf_loader_xdp_get_attached_interfaces(bpf_loader_t *loader,
                                            xdp_interface_t *ifaces, int max) {
    if (!loader || !ifaces || max <= 0) return 0;

    xdp_loader_t *xdp = &loader->xdp;
    int count = 0;

    for (int i = 0; i < xdp->interface_count && count < max; i++) {
        if (xdp->interfaces[i].attached) {
            memcpy(&ifaces[count], &xdp->interfaces[i], sizeof(xdp_interface_t));
            count++;
        }
    }

    return count;
}

/* Get the XDP ring buffer */
struct ring_buffer *bpf_loader_xdp_get_ring_buffer(bpf_loader_t *loader) {
    if (!loader || !loader->xdp.enabled) return NULL;
    return loader->xdp.xdp_rb;
}

/* Poll XDP ring buffer for events */
int bpf_loader_xdp_poll(bpf_loader_t *loader, int timeout_ms) {
    if (!loader || !loader->xdp.xdp_rb) return -1;
    return ring_buffer__poll(loader->xdp.xdp_rb, timeout_ms);
}

/* Session policy structure for BPF map (matches BPF definition) */
struct session_policy {
    uint32_t proto_type;
    uint8_t silenced;
    uint8_t _pad[3];
};

/* Update session registry (the "Gatekeeper") */
int bpf_loader_xdp_update_policy(bpf_loader_t *loader, uint64_t cookie,
                                  uint32_t proto_type, bool silenced) {
    if (!loader || !loader->xdp.enabled || loader->xdp.session_registry_fd < 0) {
        return -1;
    }

    struct session_policy policy = {
        .proto_type = proto_type,
        .silenced = silenced ? 1 : 0,
        ._pad = {0}
    };

    return bpf_map_update_elem(loader->xdp.session_registry_fd,
                               &cookie, &policy, BPF_ANY);
}

/* XDP stats structure (matches BPF definition in spliff.bpf.c) */
struct xdp_stats_kernel {
    uint64_t packets_total;
    uint64_t packets_tcp;
    uint64_t flows_created;
    uint64_t flows_classified;
    uint64_t flows_ambiguous;
    uint64_t flows_terminated;
    uint64_t gatekeeper_hits;
    uint64_t cookie_failures;
    uint64_t ringbuf_drops;
};

/* Read XDP statistics (aggregates per-CPU counters) */
int bpf_loader_xdp_read_stats(bpf_loader_t *loader, xdp_stats_t *stats) {
    if (!loader || !stats || loader->xdp.xdp_stats_fd < 0) {
        return -1;
    }

    /* Zero output */
    memset(stats, 0, sizeof(*stats));

    /* Get number of CPUs */
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0) {
        return -1;
    }

    /* Allocate per-CPU values array */
    struct xdp_stats_kernel *values = calloc(num_cpus, sizeof(*values));
    if (!values) {
        return -1;
    }

    /* Read from per-CPU array map (key 0) */
    uint32_t key = 0;
    if (bpf_map_lookup_elem(loader->xdp.xdp_stats_fd, &key, values) != 0) {
        free(values);
        return -1;
    }

    /* Sum across all CPUs */
    for (int i = 0; i < num_cpus; i++) {
        stats->packets_total     += values[i].packets_total;
        stats->packets_tcp       += values[i].packets_tcp;
        stats->flows_created     += values[i].flows_created;
        stats->flows_classified  += values[i].flows_classified;
        stats->flows_ambiguous   += values[i].flows_ambiguous;
        stats->flows_terminated  += values[i].flows_terminated;
        stats->gatekeeper_hits   += values[i].gatekeeper_hits;
        stats->cookie_failures   += values[i].cookie_failures;
        stats->ringbuf_drops     += values[i].ringbuf_drops;
    }

    free(values);
    return 0;
}

/* Check if XDP is enabled and has at least one attached interface */
bool bpf_loader_xdp_is_active(bpf_loader_t *loader) {
    if (!loader || !loader->xdp.enabled) return false;

    for (int i = 0; i < loader->xdp.interface_count; i++) {
        if (loader->xdp.interfaces[i].attached) {
            return true;
        }
    }
    return false;
}

/* Get last XDP error */
const xdp_error_t *bpf_loader_xdp_get_last_error(bpf_loader_t *loader) {
    if (!loader) return NULL;
    return &loader->xdp.last_error;
}

/* ============================================================================
 * Cookie Warm-up - Seed flow_cookie_map with existing connections
 * ============================================================================
 * Uses netlink SOCK_DIAG to enumerate TCP sockets and their cookies.
 * This allows XDP to correlate with connections established before attachment.
 *
 * BYTE ORDER NOTE:
 * All three sources use NETWORK BYTE ORDER for addresses and ports:
 *   - XDP: Parses directly from packet headers (network order)
 *   - sock_ops: ctx->local_ip4, ctx->remote_port, etc. (network order)
 *   - SOCK_DIAG: inet_diag_msg.id.idiag_src/dst/sport/dport (network order)
 * We preserve network byte order throughout to ensure map key consistency.
 */

#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>

/* Flow key structure matching BPF (must match spliff.bpf.c struct flow_key) */
struct warmup_flow_key {
    __u32 saddr;      /* Network byte order */
    __u32 daddr;      /* Network byte order */
    __u16 sport;      /* Network byte order */
    __u16 dport;      /* Network byte order */
    __u8  ip_version;
    __u8  _pad[3];
} __attribute__((packed));

/* Cookie entry structure matching BPF (must match struct flow_cookie_entry) */
struct warmup_cookie_entry {
    __u64 socket_cookie;
    __u64 timestamp_ns;
};

/* Warm-up flow_cookie_map with existing TCP connections */
int bpf_loader_xdp_warmup_cookies(bpf_loader_t *loader, bool debug) {
    if (!loader || loader->xdp.flow_cookie_map_fd < 0) {
        return 0;
    }

    int seeded = 0;

    /* Create netlink socket for SOCK_DIAG */
    int nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_SOCK_DIAG);
    if (nl_sock < 0) {
        if (debug) printf("  [XDP] Warm-up: Cannot create netlink socket\n");
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

    /* Send request */
    if (send(nl_sock, &request, sizeof(request), 0) < 0) {
        if (debug) printf("  [XDP] Warm-up: Netlink send failed\n");
        close(nl_sock);
        return 0;
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

    __u64 now_ns = 0;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        now_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    }

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

            /* Build flow key - KEEP NETWORK BYTE ORDER
             * inet_diag_msg provides all values in network byte order,
             * which matches how XDP and sock_ops construct their keys. */
            struct warmup_flow_key fkey = {
                .saddr = diag->id.idiag_src[0],  /* Network order - DO NOT convert */
                .daddr = diag->id.idiag_dst[0],  /* Network order - DO NOT convert */
                .sport = diag->id.idiag_sport,   /* Network order - DO NOT convert */
                .dport = diag->id.idiag_dport,   /* Network order - DO NOT convert */
                .ip_version = 4,
            };

            /* Use socket inode as pseudo-cookie
             * Note: This isn't the real socket cookie from bpf_get_socket_cookie(),
             * but the inode provides a unique identifier for correlation.
             * For true cookie matching, sock_ops will overwrite with real cookie
             * when the connection sends/receives data. */
            __u64 cookie = diag->idiag_inode;

            if (cookie != 0) {
                struct warmup_cookie_entry entry = {
                    .socket_cookie = cookie,
                    .timestamp_ns = now_ns,
                };

                /* Update map for client→server direction */
                if (bpf_map_update_elem(loader->xdp.flow_cookie_map_fd,
                                        &fkey, &entry, BPF_NOEXIST) == 0) {
                    seeded++;
                }

                /* Update map for server→client direction (reverse 5-tuple) */
                struct warmup_flow_key reverse = {
                    .saddr = fkey.daddr,
                    .daddr = fkey.saddr,
                    .sport = fkey.dport,
                    .dport = fkey.sport,
                    .ip_version = 4,
                };
                bpf_map_update_elem(loader->xdp.flow_cookie_map_fd,
                                    &reverse, &entry, BPF_NOEXIST);
            }

            nlh = NLMSG_NEXT(nlh, len);
        }
    }

    close(nl_sock);

    if (debug && seeded > 0) {
        printf("  [XDP] Warm-up: Seeded %d existing TCP connections\n", seeded);
    }

    return seeded;
}
