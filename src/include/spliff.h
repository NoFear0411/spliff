/**
 * @file spliff.h
 * @brief Core header file for spliff - eBPF-based SSL/TLS traffic sniffer
 *
 * @details This header defines the fundamental data structures, constants, and
 * type definitions shared between all components of spliff. It includes:
 *
 * - Version information and build configuration
 * - Debug logging macros
 * - Protocol and event type enumerations
 * - XDP (eXpress Data Path) packet capture structures
 * - HTTP message parsing structures
 * - SSL event capture structures
 * - Global configuration structure
 *
 * @note This header must be kept in sync with the BPF program (spliff.bpf.c)
 * for structures that are shared between userspace and kernel space.
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef SPLIFF_H
#define SPLIFF_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/**
 * @defgroup version Version Information
 * @brief Version constants and macros for spliff
 * @{
 */

/** @brief Full version string (major.minor.patch) */
#define SPLIFF_VERSION "0.9.0"

/** @brief Major version number (breaking changes) */
#define SPLIFF_VERSION_MAJOR 0

/** @brief Minor version number (new features) */
#define SPLIFF_VERSION_MINOR 9

/** @brief Patch version number (bug fixes) */
#define SPLIFF_VERSION_PATCH 0

/** @} */ /* end of version group */

/**
 * @defgroup debug Debug Logging
 * @brief Debug logging macros - only active in DEBUG builds
 * @{
 */

#ifdef DEBUG
/**
 * @brief General debug logging macro
 * @param fmt Format string (printf-style)
 * @param ... Variable arguments for format string
 */
#define DEBUG_LOG(fmt, ...) fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__)

/**
 * @brief HTTP/2 specific debug logging macro
 * @param fmt Format string (printf-style)
 * @param ... Variable arguments for format string
 */
#define DEBUG_H2(fmt, ...) fprintf(stderr, "[H2 DEBUG] " fmt "\n", ##__VA_ARGS__)

/**
 * @brief Main module debug logging macro
 * @param fmt Format string (printf-style)
 * @param ... Variable arguments for format string
 */
#define DEBUG_MAIN(fmt, ...) fprintf(stderr, "[MAIN DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_LOG(fmt, ...) ((void)0)
#define DEBUG_H2(fmt, ...) ((void)0)
#define DEBUG_MAIN(fmt, ...) ((void)0)
#endif

/** @} */ /* end of debug group */

/**
 * @defgroup limits Size Limits
 * @brief Maximum buffer and array sizes used throughout spliff
 * @{
 */

/** @brief Maximum length of an HTTP header name */
#define MAX_HEADER_NAME     256

/** @brief Maximum length of an HTTP header value */
#define MAX_HEADER_VALUE    4096

/** @brief Maximum number of HTTP headers per message */
#define MAX_HEADERS         128

/** @brief Maximum length of a URL path */
#define MAX_PATH_LEN        2048

/** @brief Maximum length of an HTTP method name */
#define MAX_METHOD_LEN      32

/** @brief Maximum body buffer size (1 MB) */
#define MAX_BODY_BUFFER     (1 << 20)

/** @brief Length of task/process command name (from kernel TASK_COMM_LEN) */
#define TASK_COMM_LEN       16

/** @} */ /* end of limits group */

/**
 * @defgroup protocols Protocol Types
 * @brief Application layer protocol identification
 * @{
 */

/**
 * @brief Application layer protocol type enumeration
 *
 * Identifies the HTTP protocol version detected in captured traffic.
 * Used for routing events to appropriate protocol parsers.
 */
typedef enum {
    PROTO_UNKNOWN = 0,  /**< Protocol not yet determined */
    PROTO_HTTP1,        /**< HTTP/1.0 or HTTP/1.1 */
    PROTO_HTTP2,        /**< HTTP/2 (binary framing) */
    PROTO_HTTP3         /**< HTTP/3 over QUIC (future) */
} protocol_t;

/**
 * @brief Event source enumeration
 *
 * Distinguishes between events captured at different network layers:
 * - Uprobe events contain decrypted SSL/TLS data
 * - XDP events contain raw (encrypted) packet metadata
 */
typedef enum {
    EVENT_SOURCE_UPROBE = 0,  /**< Decrypted data from SSL library uprobes */
    EVENT_SOURCE_XDP          /**< Raw packets from XDP (eXpress Data Path) */
} event_source_t;

/** @} */ /* end of protocols group */

/**
 * @defgroup xdp XDP Packet Capture
 * @brief Structures and constants for XDP-based packet capture
 *
 * XDP (eXpress Data Path) provides high-performance packet capture at the
 * network driver level. These structures are shared with the BPF program
 * and must be kept in sync with spliff.bpf.c.
 *
 * @note Event type is inferred from struct size + tcp_flags:
 * - size == 172 && payload_len > 0 → AMBIGUOUS (send to PCRE2-JIT)
 * - size == 52 && tcp_flags & (FIN|RST) → FLOW_END (terminated)
 * - size == 52 otherwise → FLOW_NEW (new classified flow)
 *
 * @{
 */

/**
 * @name TCP Flags
 * @brief TCP flag constants for flow lifecycle detection
 * @{
 */
#define TCP_FLAG_FIN  0x01  /**< Connection termination */
#define TCP_FLAG_SYN  0x02  /**< Connection initiation */
#define TCP_FLAG_RST  0x04  /**< Connection reset */
#define TCP_FLAG_ACK  0x10  /**< Acknowledgment */
/** @} */

/**
 * @brief XDP packet event type identifier
 * @note Always 6, matches BPF EVENT_XDP_PACKET constant
 */
#define EVENT_XDP_PACKET 6

/**
 * @brief Maximum payload bytes captured for PCRE2-JIT classification
 */
#define XDP_PAYLOAD_MAX 128

/**
 * @brief XDP protocol category enumeration
 *
 * Categories are assigned by the XDP program based on initial packet
 * inspection. UNKNOWN packets require userspace PCRE2-JIT classification.
 *
 * @note Must match CAT_* defines in spliff.bpf.c
 */
typedef enum {
    XDP_CAT_UNKNOWN = 0,     /**< Unclassified, needs PCRE2-JIT analysis */
    XDP_CAT_TLS_TCP = 1,     /**< TLS over TCP (could be H1 or H2) */
    XDP_CAT_QUIC = 2,        /**< QUIC/HTTP3 over UDP (stub for future) */
    XDP_CAT_PLAIN_HTTP = 3,  /**< Unencrypted HTTP/1.x */
    XDP_CAT_H2_PREFACE = 4,  /**< HTTP/2 connection preface detected */
    XDP_CAT_OTHER = 5        /**< Non-HTTP traffic */
} xdp_category_t;

/**
 * @brief Network flow key (5-tuple)
 *
 * Uniquely identifies a network flow for BPF map lookups. This structure
 * is 16 bytes and must match struct flow_key in spliff.bpf.c exactly.
 *
 * @note IPv6 flows use XOR-hashed addresses (32-bit) stored in saddr/daddr
 * fields. This loses some precision but allows unified IPv4/IPv6 handling.
 *
 * @warning All IP addresses and ports are in network byte order.
 */
typedef struct {
    uint32_t saddr;      /**< Source IP (v4) or XOR-hash (v6), network order */
    uint32_t daddr;      /**< Destination IP (v4) or XOR-hash (v6), network order */
    uint16_t sport;      /**< Source port, network byte order */
    uint16_t dport;      /**< Destination port, network byte order */
    uint8_t  protocol;   /**< IP protocol: IPPROTO_TCP (6) or IPPROTO_UDP (17) */
    uint8_t  ip_version; /**< IP version: 4 or 6 */
    uint8_t  _pad[2];    /**< Padding for 16-byte alignment */
} __attribute__((packed)) flow_key_t;

/**
 * @brief XDP packet event (metadata only)
 *
 * Sent by the XDP program for flow lifecycle events:
 * - New flow discovery (when category != UNKNOWN)
 * - Flow termination (when tcp_flags & (FIN|RST))
 *
 * Size: 52 bytes (must match struct xdp_packet_event in spliff.bpf.c)
 *
 * @see xdp_payload_event_t for events that include payload data
 */
typedef struct {
    uint64_t timestamp_ns;   /**< Absolute timestamp for latency calculations */
    uint64_t socket_cookie;  /**< "Golden Thread" - correlates with SSL uprobes */
    flow_key_t flow;         /**< 5-tuple for flow identification/map lookup */

    uint32_t pkt_len;        /**< Wire length of the packet */
    uint32_t ifindex;        /**< Network interface index */
    uint32_t event_type;     /**< Always EVENT_XDP_PACKET (6) */

    uint16_t payload_off;    /**< L4 payload offset from packet start (layer 2) */
    uint8_t  category;       /**< Protocol category (xdp_category_t) */
    uint8_t  tls_type;       /**< TLS record type if category == TLS_TCP */
    uint8_t  direction;      /**< 0=unknown, 1=ingress, 2=egress */
    uint8_t  tcp_flags;      /**< TCP flags (SYN/FIN/RST/ACK) */
    uint8_t  _pad[2];        /**< Padding for 8-byte alignment */
} __attribute__((packed)) xdp_packet_event_t;

/**
 * @brief XDP payload event (includes payload for classification)
 *
 * Sent when the XDP program cannot classify a flow and needs userspace
 * PCRE2-JIT pattern matching:
 * - category == UNKNOWN and payload_len > 0
 *
 * Size: 172 bytes (must match struct xdp_payload_event in spliff.bpf.c)
 *
 * @see xdp_packet_event_t for metadata-only events
 */
typedef struct {
    uint64_t timestamp_ns;   /**< Event timestamp */
    uint64_t socket_cookie;  /**< Correlation key to SSL uprobes */
    flow_key_t flow;         /**< 5-tuple for flow identification */

    uint32_t payload_len;    /**< Actual bytes captured (≤ XDP_PAYLOAD_MAX) */
    uint32_t event_type;     /**< Always EVENT_XDP_PACKET (6) */
    uint8_t  category;       /**< Best-guess category from XDP inspection */
    uint8_t  _pad[3];        /**< Alignment padding */
    uint8_t  payload[XDP_PAYLOAD_MAX]; /**< First 128 bytes for PCRE2 analysis */
} __attribute__((packed)) xdp_payload_event_t;

/** @} */ /* end of xdp group */

/**
 * @defgroup http HTTP Message Structures
 * @brief Structures for parsed HTTP messages
 * @{
 */

/**
 * @brief HTTP message direction
 */
typedef enum {
    DIR_REQUEST = 0,   /**< Client-to-server request */
    DIR_RESPONSE = 1   /**< Server-to-client response */
} direction_t;

/**
 * @brief Single HTTP header (name-value pair)
 */
typedef struct {
    char name[MAX_HEADER_NAME];   /**< Header name (e.g., "Content-Type") */
    char value[MAX_HEADER_VALUE]; /**< Header value */
} http_header_t;

/**
 * @brief Parsed HTTP message
 *
 * Contains all parsed information from an HTTP request or response,
 * supporting both HTTP/1.x and HTTP/2 protocols.
 *
 * @note For HTTP/2, the stream_id field identifies the multiplexed stream.
 */
typedef struct {
    protocol_t protocol;     /**< Detected protocol version */
    direction_t direction;   /**< Request or response */

    /* Request fields (populated for DIR_REQUEST) */
    char method[MAX_METHOD_LEN];     /**< HTTP method (GET, POST, etc.) */
    char path[MAX_PATH_LEN];         /**< Request path/URI */
    char authority[MAX_HEADER_VALUE];/**< HTTP/2 :authority or HTTP/1.x Host */
    char scheme[16];                 /**< HTTP/2 :scheme (http/https) */

    /* Response fields (populated for DIR_RESPONSE) */
    int status_code;          /**< HTTP status code (200, 404, etc.) */
    char status_text[64];     /**< HTTP/1.x status text ("OK", "Not Found") */

    /* Headers */
    http_header_t headers[MAX_HEADERS]; /**< Parsed headers */
    int header_count;                   /**< Number of headers */

    /* Body metadata */
    size_t content_length;       /**< Content-Length value, 0 if not present */
    char content_type[256];      /**< Content-Type header value */
    char content_encoding[64];   /**< Content-Encoding (gzip, br, etc.) */
    bool is_chunked;             /**< True if Transfer-Encoding: chunked */

    /* HTTP version (for HTTP/1.x) */
    uint8_t http_major;  /**< HTTP major version (1 for HTTP/1.x) */
    uint8_t http_minor;  /**< HTTP minor version (0 or 1 for HTTP/1.x) */

    /* HTTP/2 specific */
    int32_t stream_id;   /**< HTTP/2 stream identifier */

    /* ALPN negotiated protocol */
    char alpn_proto[16]; /**< ALPN protocol (e.g., "h2", "http/1.1") */

    /* Process metadata */
    uint32_t pid;               /**< Process ID that generated this traffic */
    char comm[TASK_COMM_LEN];   /**< Process command name */
    uint64_t timestamp_ns;      /**< Event timestamp (nanoseconds) */
    uint64_t delta_ns;          /**< SSL operation latency (nanoseconds) */
} http_message_t;

/** @} */ /* end of http group */

/**
 * @defgroup ssl SSL Event Capture
 * @brief Structures for captured SSL/TLS events from BPF uprobes
 * @{
 */

/**
 * @brief Captured SSL event from BPF uprobes
 *
 * Contains raw SSL/TLS data captured by eBPF uprobes attached to
 * SSL library functions (SSL_read, SSL_write, etc.).
 *
 * @note Uses a flexible array member for variable-length payload data.
 */
typedef struct {
    uint32_t pid;               /**< Process ID */
    uint32_t tid;               /**< Thread ID */
    uint64_t timestamp_ns;      /**< Capture timestamp */
    char comm[TASK_COMM_LEN];   /**< Process command name */
    uint8_t direction;          /**< 0=write(request), 1=read(response) */
    uint32_t len;               /**< Length of data buffer */
    uint8_t data[];             /**< Captured SSL data (flexible array member) */
} ssl_event_t;

/** @} */ /* end of ssl group */

/**
 * @defgroup config Configuration
 * @brief Runtime configuration structures
 * @{
 */

/**
 * @brief Global configuration structure
 *
 * Contains all runtime configuration options set from command-line
 * arguments. This structure is set once at startup and read by all
 * components throughout execution.
 *
 * @warning Thread safety: This structure is read-only after initialization.
 */
typedef struct {
    /**
     * @name Process Filtering
     * @brief Options for filtering captured traffic by process
     * @{
     */
    uint32_t *pids;         /**< Array of PIDs to filter (NULL = all) */
    int pid_count;          /**< Number of PIDs in filter array */
    uint32_t ppid;          /**< Parent PID filter (0 = disabled) */
    char comm_filter[16];   /**< Process name filter (empty = all) */
    /** @} */

    /**
     * @name Library Selection
     * @brief Options for selecting which SSL libraries to instrument
     * @{
     */
    bool use_openssl;  /**< Attach to OpenSSL/libssl */
    bool use_gnutls;   /**< Attach to GnuTLS */
    bool use_nss;      /**< Attach to NSS (Firefox, etc.) */
    /** @} */

    /**
     * @name Display Options
     * @brief Options controlling output formatting and content
     * @{
     */
    bool compact_mode;   /**< Use compact single-line format */
    bool show_body;      /**< Display HTTP body content */
    bool show_headers;   /**< Display HTTP headers */
    bool show_latency;   /**< Show SSL operation latency */
    bool show_handshake; /**< Show SSL handshake events */
    bool hexdump_mode;   /**< Raw hexdump mode (no parsing) */
    bool hexdump_body;   /**< Show body as hexdump with signatures (-x) */
    bool use_colors;     /**< Enable ANSI color output */
    bool filter_ipc;     /**< Filter out IPC/Unix socket traffic */
    bool debug_mode;     /**< Debug mode - show raw events */
    /** @} */

    /**
     * @name Threading
     * @brief Multi-threading configuration
     * @{
     */
    int worker_threads;  /**< Number of worker threads (0 = auto) */
    /** @} */

    /**
     * @name Output Format
     * @brief Output format selection
     * @{
     */
    /**
     * @brief Selected output format
     *
     * - FMT_TEXT: Human-readable text output (default)
     * - FMT_JSON: JSON output for machine processing
     * - FMT_COMPACT: Compact single-line output
     */
    enum { FMT_TEXT, FMT_JSON, FMT_COMPACT } output_format;
    /** @} */
} config_t;

/**
 * @brief Global configuration instance
 *
 * Set by main() during startup, read-only thereafter.
 *
 * @warning Do not modify after initialization to maintain thread safety.
 */
extern config_t g_config;

/** @} */ /* end of config group */

#endif /* SPLIFF_H */
