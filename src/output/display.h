/**
 * @file display.h
 * @brief Console output formatting and display functions
 *
 * @details This module handles all formatted console output for spliff,
 * including:
 *
 * - ANSI color support with configurable enable/disable
 * - HTTP request and response formatting
 * - Header display
 * - Body content display (text and hexdump modes)
 * - TLS handshake event display
 * - Timestamp and latency formatting
 *
 * The module respects the global color configuration and provides
 * consistent formatting across all output types.
 *
 * @par Output Format Examples:
 *
 * HTTP Request:
 * @code
 * 10:30:45.123 → GET https://example.com/api ALPN:h2 curl (1234) [1.5ms] [stream 1]
 * @endcode
 *
 * HTTP Response:
 * @code
 * 10:30:45.234 ← 200 https://example.com/api ALPN:h2 application/json (1234 bytes) curl (1234) [2.1ms]
 * @endcode
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license LGPL-3.0-only
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

#ifndef DISPLAY_H
#define DISPLAY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../include/spliff.h"

/* Forward declaration for flow context (avoid circular include) */
struct flow_context;

/**
 * @defgroup display Display and Output
 * @brief Console output formatting functions
 * @{
 */

/**
 * @defgroup ansi_colors ANSI Color Codes
 * @brief Terminal color escape sequences
 * @{
 */

#define C_RESET   "\033[0m"   /**< Reset all attributes */
#define C_BOLD    "\033[1m"   /**< Bold/bright text */
#define C_DIM     "\033[2m"   /**< Dim/faint text */
#define C_RED     "\033[31m"  /**< Red foreground (errors, 4xx/5xx) */
#define C_GREEN   "\033[32m"  /**< Green foreground (success, 2xx) */
#define C_YELLOW  "\033[33m"  /**< Yellow foreground (latency, 3xx) */
#define C_BLUE    "\033[34m"  /**< Blue foreground (responses) */
#define C_MAGENTA "\033[35m"  /**< Magenta foreground (TLS handshake) */
#define C_CYAN    "\033[36m"  /**< Cyan foreground (headers, process) */
#define C_WHITE   "\033[37m"  /**< White foreground */

/** @} */ /* end of ansi_colors group */

/**
 * @brief Initialize the display module
 *
 * Must be called before using other display functions.
 * Sets up color output configuration.
 *
 * @param[in] use_colors Enable ANSI color output
 *
 * @return 0 on success, negative on error
 */
int display_init(bool use_colors);

/**
 * @brief Clean up display module resources
 *
 * Call when shutting down to release any resources.
 * Currently a no-op but provided for future extensibility.
 */
void display_cleanup(void);

/**
 * @brief Get color code respecting color configuration
 *
 * Returns the color code if colors are enabled, empty string otherwise.
 * Use this instead of directly using color macros to respect user preference.
 *
 * @param[in] color_code ANSI color escape sequence (e.g., C_RED)
 *
 * @return The color code if colors enabled, "" otherwise
 *
 * @par Example:
 * @code
 * printf("%sError:%s message\n",
 *        display_color(C_RED), display_color(C_RESET));
 * @endcode
 */
const char *display_color(const char *color_code);

/**
 * @brief Format latency for human-readable display
 *
 * Converts nanosecond latency to appropriate units:
 * - < 1000ns: displayed as ns
 * - < 1ms: displayed as µs
 * - < 1s: displayed as ms
 * - >= 1s: displayed as s
 *
 * @param[in]  delta_ns Latency in nanoseconds
 * @param[out] buf      Output buffer for formatted string
 * @param[in]  size     Size of output buffer
 *
 * @par Example Output:
 * @code
 * "500ns", "1.5us", "2.34ms", "1.00s"
 * @endcode
 */
void display_format_latency(uint64_t delta_ns, char *buf, size_t size);

/**
 * @brief Get current time as formatted timestamp string
 *
 * Formats current wall-clock time as HH:MM:SS.mmm (millisecond precision).
 * Thread-safe implementation using localtime_r.
 *
 * @param[out] buf  Output buffer for timestamp string
 * @param[in]  size Size of output buffer (recommend >= 16)
 *
 * @par Example Output:
 * @code
 * "10:30:45.123"
 * @endcode
 */
void display_get_timestamp(char *buf, size_t size);

/**
 * @brief Display formatted HTTP request
 *
 * Outputs a formatted HTTP request line including:
 * - Timestamp
 * - Request direction arrow (→)
 * - HTTP method (bold)
 * - Full URL (scheme://authority/path)
 * - ALPN protocol
 * - Process name and PID
 * - Latency (if enabled)
 * - Stream ID (for HTTP/2)
 *
 * @param[in] msg Parsed HTTP message (must be a request)
 *
 * @see display_http_response() for response formatting
 */
void display_http_request(const http_message_t *msg);

/**
 * @brief Display formatted HTTP response
 *
 * Outputs a formatted HTTP response line including:
 * - Timestamp
 * - Response direction arrow (←)
 * - Status code (color-coded: green=2xx, yellow=3xx, red=4xx/5xx)
 * - Request URL (for correlation)
 * - ALPN protocol
 * - Content-Type
 * - Content-Length
 * - Process name and PID
 * - Latency (if enabled)
 * - Stream ID (for HTTP/2)
 *
 * @param[in] msg Parsed HTTP message (must be a response)
 *
 * @see display_http_request() for request formatting
 */
void display_http_response(const http_message_t *msg);

/**
 * @brief Display HTTP headers
 *
 * Outputs all headers from the message in "name: value" format,
 * indented with header names colored.
 *
 * @param[in] msg Parsed HTTP message containing headers
 *
 * @par Example Output:
 * @code
 *   Content-Type: application/json
 *   Content-Length: 1234
 *   Cache-Control: no-cache
 * @endcode
 */
void display_http_headers(const http_message_t *msg);

/**
 * @brief Display HTTP body content
 *
 * Displays body content with automatic format detection:
 * - Text content (HTML, JSON, XML, etc.) is displayed as-is
 * - Binary content is displayed as a truncated hexdump
 *
 * If g_config.hexdump_body is true, delegates to display_body_hex()
 * for hexdump with signature detection.
 *
 * @param[in] data         Body content bytes
 * @param[in] len          Length of body content
 * @param[in] content_type Content-Type header value (may be NULL)
 *
 * @note Text content is printed in full; binary is limited to 512 bytes
 *
 * @see display_body_hex() for hexdump with signature detection
 */
void display_body(const uint8_t *data, size_t len, const char *content_type);

/**
 * @brief Display body as hexdump with file signature detection
 *
 * Always displays body as hexdump format, with automatic detection of
 * file signatures (magic bytes) to identify content type. Useful for
 * debugging and analyzing binary protocols.
 *
 * Features:
 * - File signature detection (images, archives, documents, etc.)
 * - Signature class and description display
 * - Trailer validation status for formats that support it
 * - Standard hexdump format with ASCII column
 *
 * @param[in] data         Body content bytes
 * @param[in] len          Length of body content
 * @param[in] content_type Content-Type header value (may be NULL)
 *
 * @par Example Output:
 * @code
 * ─── Body │ PNG Image [Image] (1234 bytes) ───
 * 0000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  .PNG........IHDR
 * 0010  00 00 04 00 00 00 04 00  08 06 00 00 00 7f 1d 2b  ...............+
 * ... (500 more bytes)
 * ────────────
 * @endcode
 *
 * @see display_body() for automatic text/binary handling
 * @see signature_detect_full() for signature detection details
 */
void display_body_hex(const uint8_t *data, size_t len, const char *content_type);

/**
 * @brief Display TLS handshake event with optional flow correlation
 *
 * Outputs a formatted TLS handshake completion event with:
 * - Timestamp
 * - Lock emoji (🔒)
 * - Handshake status (complete)
 * - Handshake duration
 * - Network endpoint info (if XDP correlation available)
 * - Process name and PID
 * - Correlation ID (for linking to HTTP traffic)
 *
 * In-progress events (result < 0) are silently skipped to avoid
 * noise from WANT_READ/WANT_WRITE retries.
 *
 * @param[in] pid       Process ID that completed handshake
 * @param[in] comm      Process command name
 * @param[in] delta_ns  Handshake duration in nanoseconds
 * @param[in] result    Handshake result (0 or 1 = success, < 0 = skip)
 * @param[in] flow_ctx  Optional flow context for network info (may be NULL)
 *
 * @par Example Output:
 * @code
 * 10:30:45.123 🔒 TLS handshake complete [45.2ms] 192.168.1.100:54321 → 93.184.216.34:443 curl (1234) #a1b2
 * @endcode
 *
 * @note Different SSL libraries use different return value conventions:
 *       - OpenSSL: 1=success, 0=error, -1=retry
 *       - NSS: 0=success, -1=failure
 *       - GnuTLS: 0=success, negative=error
 */
void display_handshake_ex(uint32_t pid, const char *comm, uint64_t delta_ns,
                          int result, const struct flow_context *flow_ctx);

/**
 * @brief Display HPACK decode error for HTTP/2 streams
 *
 * Outputs a formatted error message when HPACK decoding fails for an
 * HTTP/2 stream. Shows request URL if available from partial decode.
 *
 * @param[in] stream_id HTTP/2 stream ID
 * @param[in] host      Host header value (may be NULL/empty)
 * @param[in] path      Request path (may be NULL/empty)
 * @param[in] pid       Process ID
 * @param[in] comm      Process command name
 *
 * @par Example Output:
 * @code
 * 10:30:45.123 ← [HPACK decode error] https://example.com/api [stream 1] curl (1234)
 * @endcode
 */
void display_hpack_error(int32_t stream_id, const char *host, const char *path,
                         uint32_t pid, const char *comm);

/**
 * @defgroup startup_display Startup Display
 * @brief Functions for startup and initialization messages
 *
 * These functions output directly to stdout (before async logger starts).
 * All are single-threaded safe and flush immediately.
 * @{
 */

/**
 * @brief Display application banner with version
 *
 * Shows the spliff banner art and version string at startup.
 *
 * @param[in] version Version string (e.g., "0.10.0")
 */
void display_banner(const char *version);

/**
 * @brief Display discovered SSL library
 *
 * Shows a library found during auto-discovery with path and details.
 *
 * @param[in] lib_type Library type (e.g., "OpenSSL", "BoringSSL", "NSS")
 * @param[in] path     Full path to the library
 * @param[in] details  Additional details (version, etc.) or NULL
 *
 * @par Example Output:
 * @code
 * ├─ OpenSSL: /usr/lib/libssl.so.3 (3.0.2)
 * @endcode
 */
void display_lib_found(const char *lib_type, const char *path, const char *details);

/**
 * @brief Display warning when no SSL libraries found
 */
void display_no_libs_warning(void);

/**
 * @brief Display uprobe attachment success
 *
 * @param[in] lib    Library name
 * @param[in] symbol Function symbol name
 * @param[in] prog   BPF program name
 */
void display_probe_attached(const char *lib, const char *symbol, const char *prog);

/**
 * @brief Display probe attachment summary
 *
 * @param[in] count Total number of probes attached
 */
void display_probe_summary(int count);

/**
 * @brief Display XDP program attachment status
 *
 * @param[in] ifaces Array of interface names
 * @param[in] modes  Array of XDP modes ("native", "skb", etc.)
 * @param[in] count  Number of interfaces
 */
void display_xdp_attached(const char **ifaces, const char **modes, int count);

/**
 * @brief Display sockops program status
 *
 * @param[in] success True if sockops attached successfully
 */
void display_sockops_status(bool success);

/**
 * @brief Display XDP warmup connection count
 *
 * @param[in] connections Number of warmup connections
 */
void display_xdp_warmup(int connections);

/**
 * @brief Display capture started message
 */
void display_capture_started(void);

/**
 * @brief Display active filters
 *
 * @param[in] comm  Command name filter or NULL
 * @param[in] pids  Array of PID filters or NULL
 * @param[in] count Number of PIDs
 * @param[in] ppid  Parent PID filter or 0
 */
void display_filters(const char *comm, const uint32_t *pids, int count, uint32_t ppid);

/**
 * @brief Display shutdown message
 */
void display_done(void);

/** @} */ /* end of startup_display group */

/**
 * @defgroup diagnostic_display Diagnostic Display
 * @brief Functions for error, warning, and debug output
 *
 * These functions use stderr for diagnostic messages.
 * Thread-safe via mutex protection.
 * @{
 */

/**
 * @brief Display error message
 *
 * Outputs a red-colored error message to stderr.
 * Thread-safe with mutex protection.
 *
 * @param[in] fmt Printf-style format string
 * @param[in] ... Format arguments
 */
void display_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/**
 * @brief Display warning message
 *
 * Outputs a yellow-colored warning message to stderr.
 * Thread-safe with mutex protection.
 *
 * @param[in] fmt Printf-style format string
 * @param[in] ... Format arguments
 */
void display_warning(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/**
 * @brief Display debug message with category
 *
 * Outputs a timestamped debug message to stderr.
 * Only outputs if g_config.debug_mode is true.
 * Thread-safe with mutex protection.
 *
 * @param[in] category Category tag (e.g., "XDP", "H1", "SSL")
 * @param[in] fmt      Printf-style format string
 * @param[in] ...      Format arguments
 *
 * @par Example Output:
 * @code
 * [DEBUG][10:30:45.123][XDP] Packet classified as TLS
 * @endcode
 */
void display_debug(const char *category, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/** @} */ /* end of diagnostic_display group */

/** @} */ /* end of display group */

#endif /* DISPLAY_H */
