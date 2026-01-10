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
 */

#include "bpf_loader.h"
#include "../include/sslsniff.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <limits.h>

/* Initialize BPF loader */
int bpf_loader_init(bpf_loader_t *loader) {
    if (!loader) return -1;

    memset(loader, 0, sizeof(*loader));
    loader->obj = NULL;
    loader->link_count = 0;

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
    [LIB_OPENSSL] = "libssl.so",
    [LIB_GNUTLS]  = "libgnutls.so",
    [LIB_NSS]     = "libnspr4.so",
    [LIB_NSS_SSL] = "libssl3.so",
};

/* Check if path matches a library pattern and return type */
static int match_library_pattern(const char *path, lib_type_t *out_type) {
    for (int i = 0; i < LIB_TYPE_COUNT; i++) {
        if (strstr(path, lib_patterns[i]) != NULL) {
            *out_type = (lib_type_t)i;
            return 0;
        }
    }
    return -1;
}

/* Parse /proc/PID/maps to find loaded SSL libraries */
static int parse_proc_maps(int pid, lib_discovery_result_t *result) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *f = fopen(maps_path, "r");
    if (!f) return -1;

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
            /* Only store if not already found (first occurrence wins) */
            if (!result->libs[lib_type].found) {
                strncpy(result->libs[lib_type].path, pathname,
                        sizeof(result->libs[lib_type].path) - 1);
                result->libs[lib_type].path[sizeof(result->libs[lib_type].path) - 1] = '\0';
                result->libs[lib_type].type = lib_type;
                result->libs[lib_type].found = true;
                result->count++;
            }
        }
    }

    fclose(f);
    return 0;
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

            /* Early exit if we found all library types */
            if (result->count >= LIB_TYPE_COUNT) break;
        }

        closedir(proc);
    }

    return (result->count > 0) ? 0 : -1;
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

    if (loader->link_count >= MAX_LINKS) return -1;

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

    if (loader->link_count >= MAX_LINKS) return -1;

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

    /* Close all links */
    for (int i = 0; i < MAX_LINKS; i++) {
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
