/*
 * binary_scanner.h - BoringSSL function detection via build ID lookup
 *
 * This module provides detection of SSL_read/SSL_write functions in
 * stripped binaries like Chrome/Chromium that statically link BoringSSL.
 *
 * Detection method:
 * 1. Extract ELF build ID from the binary
 * 2. Look up offsets in the embedded database (boringssl_offsets.h)
 * 3. Return file offsets suitable for uprobe attachment
 *
 * To add support for a new browser version:
 * 1. Get build ID: readelf -n /path/to/browser | grep 'Build ID'
 * 2. Get debug symbols and extract offsets with nm
 * 3. Add entry to boringssl_offsets.h
 */

#ifndef BINARY_SCANNER_H
#define BINARY_SCANNER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Maximum build ID hex string length (SHA-256 = 64 hex chars + null) */
#define BUILD_ID_HEX_MAX 65

/* Results from scanning a binary for BoringSSL */
struct boringssl_offsets {
    uint64_t ssl_write_offset;       /* File offset of SSL_write function */
    uint64_t ssl_read_offset;        /* File offset of SSL_read function */
    /* Internal "Golden Hooks" - the actual hot paths in Chrome */
    uint64_t ssl_read_impl_offset;   /* ssl_read_impl(ssl_st*) - internal read */
    uint64_t ssl_write_impl_offset;  /* DoPayloadWrite() - internal write */
    /* Async I/O hooks - Chrome's event-driven network model */
    uint64_t socket_read_offset;     /* SSLClientSocketImpl::ReadIfReady - async entry */
    uint64_t on_read_ready_offset;   /* SSLClientSocketImpl::OnReadReady - completion */
    /* DoPayloadRead receives raw char* buffer directly (not IOBuffer wrapper) */
    uint64_t do_payload_read_offset; /* SSLClientSocketImpl::DoPayloadRead - best hook */
    bool found;                       /* True if offsets were found in database */
    char binary_path[256];            /* Path to the scanned binary */
    char build_id[BUILD_ID_HEX_MAX]; /* Build ID hex string */
    const char *version_info;         /* Version info from database (or NULL) */
};

/*
 * Check if a binary contains BoringSSL signatures
 * Returns true if BoringSSL-specific strings are found
 */
bool binary_has_boringssl(const char *binary_path);

/*
 * Scan a binary for BoringSSL SSL_read/SSL_write function offsets
 *
 * Uses build-ID based database lookup for reliable detection.
 *
 * Parameters:
 *   binary_path - Path to the ELF binary to scan
 *   offsets     - Output structure for the discovered offsets
 *   debug       - Enable debug output
 *
 * Returns:
 *   0 on success (offsets found in database)
 *  -1 on failure (unknown build ID or parse error)
 *
 * The offsets returned are FILE offsets (not virtual addresses).
 * These can be used directly with bpf_program__attach_uprobe_opts()
 * by setting uprobe_opts.func_name = NULL and using the offset parameter.
 */
int scan_binary_for_boringssl(const char *binary_path,
                               struct boringssl_offsets *offsets,
                               bool debug);

/*
 * Scan for Chrome binary in standard locations
 * Returns the path to the found binary, or NULL if not found
 */
const char *find_chrome_binary(void);

/*
 * Scan for Chromium binary in standard locations
 * Returns the path to the found binary, or NULL if not found
 */
const char *find_chromium_binary(void);

#endif /* BINARY_SCANNER_H */
