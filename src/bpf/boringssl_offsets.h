/*
 * boringssl_offsets.h - Known BoringSSL function offsets by build ID
 *
 * This database maps ELF build IDs to SSL_read/SSL_write file offsets
 * for Chrome, Chromium, and other Chromium-based browsers.
 *
 * To add a new entry:
 * 1. Get build ID: readelf -n /path/to/chrome | grep 'Build ID'
 * 2. Get debug symbols (Chrome provides them as separate downloads)
 * 3. Get offsets: nm -C /path/to/chrome.debug | grep -E ' t SSL_read$| t SSL_write$'
 * 4. Add entry below with version info
 *
 * Note: Offsets are FILE offsets (not virtual addresses).
 * The 't' symbol type indicates these are local/static text symbols.
 */

#ifndef BORINGSSL_OFFSETS_H
#define BORINGSSL_OFFSETS_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief BoringSSL function offset entry for build ID database
 */
struct boringssl_offset_entry {
    const char *build_id;        /**< ELF build ID hex string */
    const char *version_info;    /**< Human-readable version (e.g., "Chrome 144.0.7559.59") */
    uint64_t ssl_read_offset;    /**< File offset of SSL_read */
    uint64_t ssl_write_offset;   /**< File offset of SSL_write */
    uint64_t ssl_read_impl_offset;   /**< ssl_read_impl(ssl_st*) - internal read (Golden Hook) */
    uint64_t ssl_write_impl_offset;  /**< DoPayloadWrite() - write entry point (Golden Hook) */
    uint64_t socket_read_offset;     /**< SSLClientSocketImpl::ReadIfReady - async read entry */
    uint64_t on_read_ready_offset;   /**< SSLClientSocketImpl::OnReadReady - async completion */
    uint64_t do_payload_read_offset; /**< SSLClientSocketImpl::DoPayloadRead - best hook point */
};

/*
 * Offset database - add new entries here
 *
 * Format:
 *   { "build_id_hex", "Browser Version", ssl_read_offset, ssl_write_offset },
 *
 * To contribute: Submit a PR with new entries discovered from debug symbols.
 */
static const struct boringssl_offset_entry boringssl_offset_db[] = {
    /*
     * Google Chrome Stable Channel
     */
    {
        .build_id = "7b575d0ef2979a30eff85b5495fabe770231def9",
        .version_info = "Chrome 144.0.7559.59 (Fedora x86_64)",
        /* NOTE: For this Chrome build, nm values from debug symbols ARE file offsets.
         * No vaddr conversion needed - use values directly from:
         * nm -C chrome.debug | grep -E 'SSL_read|SSL_write|ssl_read_impl' */
        .ssl_read_offset = 0x045d9c70,        /* SSL_read */
        .ssl_write_offset = 0x04fe50e0,       /* SSL_write */
        /* Internal "Golden Hooks" - these are the actual hot paths */
        .ssl_read_impl_offset = 0x0a4204c0,   /* ssl_read_impl */
        .ssl_write_impl_offset = 0x04fe4fc0,  /* DoPayloadWrite */
        /* Async I/O hooks - Chrome's event-driven network model
         * SSLClientSocketImpl::ReadIfReady: Async read entry point
         * SSLClientSocketImpl::OnReadReady: Called when async read completes, triggers SSL_read */
        .socket_read_offset = 0x045d9650,     /* ReadIfReady */
        .on_read_ready_offset = 0x0a69f920,   /* OnReadReady */
        .do_payload_read_offset = 0,          /* TODO: find from Chrome debug symbols */
    },

    /*
     * Chromium (Fedora)
     *
     * IMPORTANT: nm gives VIRTUAL ADDRESSES. For uprobes we need FILE OFFSETS.
     * Conversion: File Offset = Virtual Address - (VADDR - FileOffset of .text)
     *
     * For Chromium 143 on Fedora:
     *   .text VADDR:       0x158f000
     *   .text File Offset: 0x158e000
     *   Difference:        0x1000
     *
     * So: File Offset = VA - 0x1000
     */
    {
        .build_id = "201e55986ba90f3f2c45523c1c61a8a179bd4ed7",
        .version_info = "Chromium 143.0.7499.192 (Fedora x86_64)",
        /* FILE OFFSETS (VA - 0x1000) for uprobe attachment */
        .ssl_read_offset = 0x083b02d0,        /* SSL_read (VA 0x83b12d0) */
        .ssl_write_offset = 0x083b0790,       /* SSL_write (VA 0x83b1790) */
        /* Internal functions - DISABLED: wrong signatures, cause crashes
         * ssl_read_impl(SSL*) - only takes SSL*, no buf/len
         * DoPayloadWrite() - no buffer args, pulls from internal state */
        .ssl_read_impl_offset = 0x083b03d0,   /* ssl_read_impl (VA 0x83b13d0) - DO NOT USE */
        .ssl_write_impl_offset = 0x0898fbc0,  /* DoPayloadWrite (VA 0x8990bc0) - DO NOT USE */
        /* Async I/O hooks - complex C++ ABI, need more analysis */
        .socket_read_offset = 0x0898f4d0,     /* ReadIfReady (VA 0x89904d0) */
        .on_read_ready_offset = 0x0898fe70,   /* OnReadReady (VA 0x8990e70) */
        /* DoPayloadRead(this, span.data, span.size) - base::span passed by value */
        .do_payload_read_offset = 0x0898f580, /* DoPayloadRead (VA 0x8990580) */
    },

    /*
     * Electron Apps (add entries as discovered)
     */

    /*
     * Brave Browser (add entries as discovered)
     */

    /* Sentinel - marks end of array (must be last) */
    { NULL, NULL, 0, 0, 0, 0, 0, 0, 0 }
};

#define BORINGSSL_OFFSET_DB_COUNT \
    (sizeof(boringssl_offset_db) / sizeof(boringssl_offset_db[0]) - 1)

#endif /* BORINGSSL_OFFSETS_H */
