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
#include "../../include/sslsniff.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <errno.h>

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
