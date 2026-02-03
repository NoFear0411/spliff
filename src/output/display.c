/**
 * @file display.c
 * @brief Implementation of console output formatting and display functions
 *
 * @details This file implements the display module for spliff, handling
 * all formatted console output including HTTP traffic, TLS events,
 * and body content visualization.
 *
 * Key features:
 * - Thread-local formatting buffer for lock-free output
 * - Async output via MPSC logger
 * - Configurable ANSI color output
 * - Automatic content type detection (text vs binary)
 * - Human-readable latency formatting
 * - File signature detection for binary content
 *
 * @see display.h for public API documentation
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "display.h"
#include "logger.h"
#include "../content/signatures.h"
#include "../correlation/flow_context.h"  /* For FLOW_FLAG_HAS_XDP */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <arpa/inet.h>  /* For inet_ntop, ntohs */

/* ═══════════════════════════════════════════════════════════════════════════
 * TLS Formatting Buffer
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Maximum size of TLS formatting buffer */
#define TLS_DISPLAY_BUF_SIZE (64 * 1024)

/** Thread-local formatting buffer */
static __thread char tls_display_buf[TLS_DISPLAY_BUF_SIZE];

/** Current position in TLS buffer */
static __thread size_t tls_display_len = 0;

/**
 * @brief Reset TLS buffer for new message
 */
static inline void display_begin(void)
{
    tls_display_len = 0;
}

/**
 * @brief Append formatted text to TLS buffer
 *
 * @param fmt Printf format string
 * @param ... Format arguments
 * @return Number of characters appended, or -1 on error
 */
static int display_append(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

static int display_append(const char *fmt, ...)
{
    if (tls_display_len >= TLS_DISPLAY_BUF_SIZE) {
        return -1;  /* Buffer full */
    }

    size_t remaining = TLS_DISPLAY_BUF_SIZE - tls_display_len;

    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(tls_display_buf + tls_display_len, remaining, fmt, args);
    va_end(args);

    if (len < 0) {
        return -1;
    }

    if ((size_t)len >= remaining) {
        /* Truncated - still advance to end */
        tls_display_len = TLS_DISPLAY_BUF_SIZE;
        return (int)remaining - 1;
    }

    tls_display_len += (size_t)len;
    return len;
}

/**
 * @brief Append raw bytes to TLS buffer
 *
 * @param data Data to append
 * @param len Length of data
 * @return Number of bytes appended
 */
static size_t display_append_raw(const void *data, size_t len)
{
    if (tls_display_len >= TLS_DISPLAY_BUF_SIZE) {
        return 0;
    }

    size_t remaining = TLS_DISPLAY_BUF_SIZE - tls_display_len;
    size_t copy_len = len < remaining ? len : remaining;

    memcpy(tls_display_buf + tls_display_len, data, copy_len);
    tls_display_len += copy_len;

    return copy_len;
}

/**
 * @brief Flush TLS buffer to async logger
 */
static inline void display_flush(void)
{
    if (tls_display_len > 0) {
        log_enqueue(tls_display_buf, tls_display_len);
        tls_display_len = 0;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Global State
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Global color output setting
 *
 * When true, ANSI escape codes are included in output.
 * When false, all color codes are replaced with empty strings.
 *
 * @internal
 */
static bool g_use_colors = true;

int display_init(bool use_colors) {
    g_use_colors = use_colors;
    return 0;
}

/**
 * @brief Clean up display module resources
 *
 * Currently a no-op, but provided for API completeness and
 * future extensibility (e.g., flushing buffered output).
 */
void display_cleanup(void) {
    /* No cleanup needed */
}

const char *display_color(const char *color_code) {
    return g_use_colors ? color_code : "";
}

void display_format_latency(uint64_t delta_ns, char *buf, size_t size) {
    if (delta_ns < 1000) {
        snprintf(buf, size, "%luns", (unsigned long)delta_ns);
    } else if (delta_ns < 1000000) {
        snprintf(buf, size, "%.1fus", delta_ns / 1000.0);
    } else if (delta_ns < 1000000000) {
        snprintf(buf, size, "%.2fms", delta_ns / 1000000.0);
    } else {
        snprintf(buf, size, "%.2fs", delta_ns / 1000000000.0);
    }
}

void display_get_timestamp(char *buf, size_t size) {
    if (size == 0) return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_buf;
    struct tm *tm = localtime_r(&ts.tv_sec, &tm_buf);
    if (tm) {
        snprintf(buf, size, "%02d:%02d:%02d.%03ld",
                 tm->tm_hour, tm->tm_min, tm->tm_sec, ts.tv_nsec / 1000000);
    } else {
        buf[0] = '\0';
    }
}

/**
 * @brief Get XDP protocol name from category
 *
 * Returns the network-layer protocol that XDP detected in packets.
 * This is independent of what the application-layer parser found.
 *
 * @param category XDP flow category from packet classification
 * @return Short protocol name (TLS, HTTP, QUIC, H2, ?, Other)
 */
static const char *get_xdp_proto_name(uint8_t category) {
    switch (category) {
        case XDP_CAT_TLS_TCP:     return "TLS";
        case XDP_CAT_QUIC:        return "QUIC";
        case XDP_CAT_PLAIN_HTTP:  return "HTTP";
        case XDP_CAT_H2_PREFACE:  return "H2";
        case XDP_CAT_OTHER:       return "Other";
        case XDP_CAT_UNKNOWN:
        default:                  return "?";
    }
}

/**
 * @brief Get application protocol name from parser protocol
 *
 * Returns the application-layer protocol that the parser detected.
 *
 * @param protocol Protocol from HTTP parser (PROTO_HTTP1, PROTO_HTTP2, etc.)
 * @return Short protocol name (H1, H2, ?)
 */
static const char *get_app_proto_name(protocol_t protocol) {
    switch (protocol) {
        case PROTO_HTTP1:   return "H1";
        case PROTO_HTTP2:   return "H2";
        /* Future: PROTO_HTTP3 -> "H3" */
        default:            return "?";
    }
}

/**
 * @brief Append XDP flow correlation info to TLS buffer
 *
 * Shows network-layer metadata from XDP packet capture, correlated with
 * SSL data via the socket cookie ("Golden Thread").
 *
 * Output format:
 * @code
 *               ├─ 192.168.1.100:54321 → 93.184.216.34:443 [TLS] (eth0)
 * @endcode
 *
 * @param msg HTTP message with flow info populated from XDP correlation
 */
static void display_append_flow_info(const http_message_t *msg) {
    if (!msg || !msg->has_flow_info) {
        return;
    }

    char ip1[INET6_ADDRSTRLEN];
    char ip2[INET6_ADDRSTRLEN];

    if (msg->flow_ip_version == 4) {
        inet_ntop(AF_INET, &msg->flow_src_ip, ip1, sizeof(ip1));
        inet_ntop(AF_INET, &msg->flow_dst_ip, ip2, sizeof(ip2));
    } else {
        /* For IPv6, we only have 32-bit XOR hash, show as hex */
        snprintf(ip1, sizeof(ip1), "%08x", ntohl(msg->flow_src_ip));
        snprintf(ip2, sizeof(ip2), "%08x", ntohl(msg->flow_dst_ip));
    }

    uint16_t port1 = ntohs(msg->flow_src_port);
    uint16_t port2 = ntohs(msg->flow_dst_port);

    /**
     * @par Flow Direction Normalization
     *
     * The XDP program captures packets on the local network interface and stores
     * the 5-tuple as seen on the wire (saddr:sport → daddr:dport). The flow_direction
     * field indicates the semantic direction:
     *
     * - @c 1 = Client → Server: saddr is the local client, daddr is the remote server
     * - @c 2 = Server → Client: saddr is the remote server, daddr is the local client
     *
     * For consistent user experience, we normalize the display based on HTTP direction:
     *
     * @par Request Display
     * Always show: @c local_client:port → remote_server:port
     *
     * @par Response Display
     * Always show: @c remote_server:port → local_client:port
     *
     * This ensures the arrow direction matches the logical data flow regardless of
     * which packet direction XDP happened to capture first.
     */
    const char *left_ip, *right_ip;
    uint16_t left_port, right_port;

    if (msg->flow_direction == 1) {
        /* Packet captured was client→server: saddr=client, daddr=server */
        if (msg->direction == DIR_REQUEST) {
            /* Request: show client → server (use as-is) */
            left_ip = ip1; left_port = port1;
            right_ip = ip2; right_port = port2;
        } else {
            /* Response: show server → client (swap endpoints) */
            left_ip = ip2; left_port = port2;
            right_ip = ip1; right_port = port1;
        }
    } else {
        /* Packet captured was server→client: saddr=server, daddr=client */
        if (msg->direction == DIR_REQUEST) {
            /* Request: show client → server (swap endpoints) */
            left_ip = ip2; left_port = port2;
            right_ip = ip1; right_port = port1;
        } else {
            /* Response: show server → client (use as-is) */
            left_ip = ip1; left_port = port1;
            right_ip = ip2; right_port = port2;
        }
    }

    /* Build correlation display: [XDP:proto][App:proto] ✓✓
     *
     * Two-layer verification with dual checkmarks:
     * - XDP proto: What XDP detected at packet level (TLS, HTTP, QUIC, ?)
     * - App proto: What uprobe/parser detected at application level (H1, H2, H3)
     * - First ✓:  Socket cookie correlation succeeded (we have flow info)
     * - Second ✓: XDP classification succeeded (category != UNKNOWN)
     *
     * This design is extensible for future non-SSL and HTTP/3 support.
     * The dual checkmark system allows users to see correlation quality at a glance.
     */
    const char *xdp_proto = get_xdp_proto_name(msg->flow_category);
    const char *app_proto = get_app_proto_name(msg->protocol);

    /* Determine verification status:
     * - First checkmark: Always present here (has_flow_info == true to reach this code)
     * - Second checkmark: XDP successfully classified the traffic (not unknown) */
    bool xdp_classified = (msg->flow_category != XDP_CAT_UNKNOWN);

    display_append("              %s|-%s %s%s:%u → %s:%u%s %s[XDP:%s][App:%s]%s",
           display_color(C_DIM), display_color(C_RESET),
           display_color(C_DIM),
           left_ip, left_port,
           right_ip, right_port,
           display_color(C_RESET),
           display_color(C_CYAN), xdp_proto, app_proto, display_color(C_RESET));

    /* Append checkmarks: first for correlation, second for XDP classification */
    if (xdp_classified) {
        display_append(" %s✓✓%s", display_color(C_GREEN), display_color(C_RESET));
    } else {
        display_append(" %s✓%s", display_color(C_YELLOW), display_color(C_RESET));
    }

    if (msg->flow_ifname[0]) {
        display_append(" %s(%s)%s", display_color(C_DIM), msg->flow_ifname, display_color(C_RESET));
    }

    display_append("\n");
}

void display_http_request(const http_message_t *msg) {
    display_begin();

    char ts[32];
    display_get_timestamp(ts, sizeof(ts));

    /* Build full URI - sized for authority + path + protocol prefix */
    char full_uri[MAX_HEADER_VALUE + MAX_PATH_LEN + 16];
    if (msg->authority[0]) {
        snprintf(full_uri, sizeof(full_uri), "https://%s%s", msg->authority, msg->path);
    } else {
        snprintf(full_uri, sizeof(full_uri), "%s", msg->path);
    }

    /* Determine ALPN protocol string - prefer alpn_proto if available */
    const char *alpn_str = NULL;
    if (msg->alpn_proto[0]) {
        alpn_str = msg->alpn_proto;
    } else if (msg->protocol == PROTO_HTTP2) {
        alpn_str = "h2";
    } else {
        alpn_str = "http/1.1";
    }

    /* Format: <timestamp> → <method> <full URI> ALPN:<protocol> <process> (<PID>) [latency] [stream N] */
    display_append("%s%s%s %s→%s %s%s%s %s %sALPN:%s%s",
           display_color(C_DIM), ts, display_color(C_RESET),
           display_color(C_GREEN), display_color(C_RESET),
           display_color(C_BOLD), msg->method, display_color(C_RESET),
           full_uri,
           display_color(C_DIM), alpn_str, display_color(C_RESET));

    display_append(" %s%s%s %s(%u)%s",
           display_color(C_CYAN), msg->comm, display_color(C_RESET),
           display_color(C_DIM), msg->pid, display_color(C_RESET));

    /* Show latency if enabled and available */
    if (g_config.show_latency && msg->delta_ns > 0) {
        char lat[32];
        display_format_latency(msg->delta_ns, lat, sizeof(lat));
        display_append(" %s[%s]%s", display_color(C_YELLOW), lat, display_color(C_RESET));
    }

    /* Show stream ID for HTTP/2 */
    if (msg->protocol == PROTO_HTTP2 && msg->stream_id > 0) {
        display_append(" %s[stream %d]%s", display_color(C_DIM), msg->stream_id, display_color(C_RESET));
    }

    /* Show correlation ID for request-response pairing (last 4 hex digits) */
    if (msg->correlation_id != 0) {
        display_append(" %s#%04x%s",
               display_color(C_DIM),
               (uint16_t)(msg->correlation_id & 0xFFFF),
               display_color(C_RESET));
    }

    display_append("\n");

    /* Show XDP flow correlation info if available */
    display_append_flow_info(msg);

    display_flush();
}

void display_http_response(const http_message_t *msg) {
    display_begin();

    char ts[32];
    display_get_timestamp(ts, sizeof(ts));

    const char *status_color = C_GREEN;
    if (msg->status_code >= 400) status_color = C_RED;
    else if (msg->status_code >= 300) status_color = C_YELLOW;

    /* Determine ALPN protocol string - prefer alpn_proto if available */
    const char *alpn_str = NULL;
    if (msg->alpn_proto[0]) {
        alpn_str = msg->alpn_proto;
    } else if (msg->protocol == PROTO_HTTP2) {
        alpn_str = "h2";
    } else {
        alpn_str = "http/1.1";
    }

    /* Format: <timestamp> ← <status> <URL> ALPN:<protocol> <content-type> (<size>) <process> (<PID>) [latency] [stream N] */
    display_append("%s%s%s %s←%s %s%d%s",
           display_color(C_DIM), ts, display_color(C_RESET),
           display_color(C_BLUE), display_color(C_RESET),
           display_color(status_color), msg->status_code, display_color(C_RESET));

    /* Show request URL for correlation */
    if (msg->authority[0]) {
        display_append(" %s://%s%s",
               msg->scheme[0] ? msg->scheme : "https",
               msg->authority,
               msg->path);
    }

    /* Show ALPN after URL */
    display_append(" %sALPN:%s%s", display_color(C_DIM), alpn_str, display_color(C_RESET));

    if (msg->content_type[0]) {
        display_append(" %s%s%s", display_color(C_DIM), msg->content_type, display_color(C_RESET));
    }

    if (msg->content_length > 0) {
        display_append(" %s(%zu bytes)%s", display_color(C_DIM), msg->content_length, display_color(C_RESET));
    }

    display_append(" %s%s%s %s(%u)%s",
           display_color(C_CYAN), msg->comm, display_color(C_RESET),
           display_color(C_DIM), msg->pid, display_color(C_RESET));

    /* Show latency if enabled and available */
    if (g_config.show_latency && msg->delta_ns > 0) {
        char lat[32];
        display_format_latency(msg->delta_ns, lat, sizeof(lat));
        display_append(" %s[%s]%s", display_color(C_YELLOW), lat, display_color(C_RESET));
    }

    /* Show stream ID for HTTP/2 */
    if (msg->protocol == PROTO_HTTP2 && msg->stream_id > 0) {
        display_append(" %s[stream %d]%s", display_color(C_DIM), msg->stream_id, display_color(C_RESET));
    }

    /* Show correlation ID for request-response pairing (last 4 hex digits) */
    if (msg->correlation_id != 0) {
        display_append(" %s#%04x%s",
               display_color(C_DIM),
               (uint16_t)(msg->correlation_id & 0xFFFF),
               display_color(C_RESET));
    }

    display_append("\n");

    /* Show XDP flow correlation info if available */
    display_append_flow_info(msg);

    display_flush();
}

void display_http_headers(const http_message_t *msg) {
    display_begin();

    for (int i = 0; i < msg->header_count && i < MAX_HEADERS; i++) {
        display_append("  %s%s:%s %s\n",
               display_color(C_CYAN), msg->headers[i].name,
               display_color(C_RESET), msg->headers[i].value);
    }

    display_flush();
}

/**
 * @brief Check if content type indicates text content
 *
 * Checks for common text MIME types that should be displayed as-is
 * rather than as hexdump.
 *
 * @param content_type Content-Type header value
 * @return true if content is textual, false for binary
 *
 * @internal
 */
static bool is_text_content_type(const char *content_type) {
    if (!content_type || !content_type[0]) return false;

    /* Common text content types */
    return (strstr(content_type, "text/") != NULL ||
            strstr(content_type, "application/json") != NULL ||
            strstr(content_type, "application/xml") != NULL ||
            strstr(content_type, "application/javascript") != NULL ||
            strstr(content_type, "application/x-www-form-urlencoded") != NULL ||
            strstr(content_type, "+json") != NULL ||
            strstr(content_type, "+xml") != NULL);
}

/**
 * @brief Check if data appears to be printable text
 *
 * Samples the first 512 bytes to determine if the content
 * is likely text (printable ASCII or valid UTF-8).
 *
 * @param data Data buffer to check
 * @param len  Length of data
 * @return true if data appears to be text, false if binary
 *
 * @internal
 */
static bool is_printable_text(const uint8_t *data, size_t len) {
    /* Sample first 512 bytes to check */
    size_t check_len = len > 512 ? 512 : len;

    for (size_t i = 0; i < check_len; i++) {
        uint8_t c = data[i];
        /* Allow printable ASCII, newline, carriage return, tab */
        if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
            return false;
        }
        /* Reject high bytes (likely binary) unless valid UTF-8 */
        if (c > 127) {
            /* Simple UTF-8 check: multi-byte sequences start with 11xxxxxx */
            if ((c & 0xC0) != 0xC0 && (c & 0xC0) != 0x80) {
                return false;
            }
        }
    }
    return true;
}

void display_body(const uint8_t *data, size_t len, const char *content_type) {
    if (len == 0) return;

    /* Delegate to hex display if -x flag is set */
    if (g_config.hexdump_body) {
        display_body_hex(data, len, content_type);
        return;
    }

    display_begin();

    display_append("%s─── Body ───%s\n", display_color(C_DIM), display_color(C_RESET));

    /* Determine if this is text content */
    bool is_text = is_text_content_type(content_type) || is_printable_text(data, len);

    if (is_text) {
        /* Append text content directly */
        display_append_raw(data, len);
        /* Ensure newline at end */
        if (len > 0 && data[len-1] != '\n') {
            display_append("\n");
        }
    } else {
        /* Binary content - show hexdump (truncated) */
        size_t print_len = len > 512 ? 512 : len;
        for (size_t i = 0; i < print_len; i += 16) {
            display_append("%s%04zx%s  ", display_color(C_DIM), i, display_color(C_RESET));
            /* Hex bytes */
            for (size_t j = 0; j < 16; j++) {
                if (i + j < print_len) {
                    display_append("%02x ", data[i + j]);
                } else {
                    display_append("   ");
                }
            }
            display_append(" ");
            /* ASCII representation */
            for (size_t j = 0; j < 16 && i + j < print_len; j++) {
                uint8_t c = data[i + j];
                display_append("%c", (c >= 32 && c < 127) ? c : '.');
            }
            display_append("\n");
        }
        if (len > 512) {
            display_append("%s... (%zu more bytes)%s\n",
                   display_color(C_DIM), len - 512, display_color(C_RESET));
        }
    }
    display_append("%s────────────%s\n", display_color(C_DIM), display_color(C_RESET));

    display_flush();
}

void display_body_hex(const uint8_t *data, size_t len, const char *content_type) {
    if (len == 0) return;

    display_begin();

    /* Detect file signature */
    signature_result_t sig_result;
    bool detected = signature_detect_full(data, len, true, &sig_result);

    /* Print header with signature info */
    display_append("%s─── Body", display_color(C_DIM));

    if (detected) {
        /* Show: type [class] (confidence) */
        display_append(" │ %s%s%s [%s%s%s]",
               display_color(C_CYAN), sig_result.description, display_color(C_DIM),
               display_color(C_YELLOW), signature_class_name(sig_result.file_class),
               display_color(C_DIM));

        /* Show trailer validation status if applicable */
        if (!sig_result.trailer_valid) {
            display_append(" %s(trailer mismatch)%s", display_color(C_RED), display_color(C_DIM));
        }
    } else if (content_type && content_type[0]) {
        display_append(" │ %s", content_type);
    }

    display_append(" (%zu bytes) ───%s\n", len, display_color(C_RESET));

    /* Always show hexdump in -x mode */
    size_t print_len = len > 512 ? 512 : len;
    for (size_t i = 0; i < print_len; i += 16) {
        display_append("%s%04zx%s  ", display_color(C_DIM), i, display_color(C_RESET));

        /* Hex bytes */
        for (size_t j = 0; j < 16; j++) {
            if (i + j < print_len) {
                display_append("%02x ", data[i + j]);
            } else {
                display_append("   ");
            }
            /* Extra space at 8-byte boundary */
            if (j == 7) display_append(" ");
        }

        display_append(" ");

        /* ASCII representation */
        for (size_t j = 0; j < 16 && i + j < print_len; j++) {
            uint8_t c = data[i + j];
            display_append("%c", (c >= 32 && c < 127) ? c : '.');
        }
        display_append("\n");
    }

    if (len > 512) {
        display_append("%s... (%zu more bytes)%s\n",
               display_color(C_DIM), len - 512, display_color(C_RESET));
    }

    display_append("%s────────────%s\n", display_color(C_DIM), display_color(C_RESET));

    display_flush();
}

void display_handshake_ex(uint32_t pid, const char *comm, uint64_t delta_ns,
                          int result, const flow_context_t *flow_ctx) {
    /* Skip in-progress events (WANT_READ/WANT_WRITE) */
    if (result < 0) {
        return;
    }

    display_begin();

    char ts[32];
    display_get_timestamp(ts, sizeof(ts));

    const char *status = "complete";
    const char *status_color = C_GREEN;

    display_append("%s%s%s %s🔒%s TLS handshake %s%s%s",
           display_color(C_DIM), ts, display_color(C_RESET),
           display_color(C_MAGENTA), display_color(C_RESET),
           display_color(status_color), status, display_color(C_RESET));

    /* Show handshake duration */
    if (delta_ns > 0) {
        char lat[32];
        display_format_latency(delta_ns, lat, sizeof(lat));
        display_append(" %s[%s]%s", display_color(C_YELLOW), lat, display_color(C_RESET));
    }

    /* Show flow info if available */
    if (flow_ctx && (atomic_load_explicit(&flow_ctx->flags, memory_order_acquire) & FLOW_FLAG_HAS_XDP)) {
        char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
        if (flow_ctx->flow.ip_version == 4) {
            inet_ntop(AF_INET, &flow_ctx->flow.saddr, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &flow_ctx->flow.daddr, dst_ip, sizeof(dst_ip));
        } else {
            /* IPv6 or unknown - show as hex for now */
            snprintf(src_ip, sizeof(src_ip), "%08x", ntohl(flow_ctx->flow.saddr));
            snprintf(dst_ip, sizeof(dst_ip), "%08x", ntohl(flow_ctx->flow.daddr));
        }
        display_append(" %s%s:%u → %s:%u%s",
               display_color(C_DIM),
               src_ip, ntohs(flow_ctx->flow.sport),
               dst_ip, ntohs(flow_ctx->flow.dport),
               display_color(C_RESET));
    }

    display_append(" %s%s%s %s(%u)%s",
           display_color(C_CYAN), comm, display_color(C_RESET),
           display_color(C_DIM), pid, display_color(C_RESET));

    /* Show correlation ID for linking to HTTP traffic */
    if (flow_ctx && flow_ctx->socket_cookie != 0) {
        /* Use socket_cookie as correlation ID (same as HTTP messages) */
        display_append(" %s#%04x%s",
               display_color(C_DIM),
               (uint16_t)(flow_ctx->socket_cookie & 0xFFFF),
               display_color(C_RESET));
    }

    display_append("\n");
    display_flush();
}

void display_hpack_error(int32_t stream_id, const char *host, const char *path,
                         uint32_t pid, const char *comm) {
    display_begin();

    char ts[32];
    display_get_timestamp(ts, sizeof(ts));

    display_append("%s%s%s %s←%s %s[HPACK decode error]%s",
           display_color(C_DIM), ts, display_color(C_RESET),
           display_color(C_BLUE), display_color(C_RESET),
           display_color(C_RED), display_color(C_RESET));

    /* Show URL if available from request */
    if (host && host[0]) {
        display_append(" https://%s%s",
               host,
               (path && path[0]) ? path : "/");
    }

    /* Show stream ID and process info */
    display_append(" %s[stream %d]%s %s%s%s %s(%u)%s\n",
           display_color(C_DIM), stream_id, display_color(C_RESET),
           display_color(C_CYAN), comm ? comm : "unknown", display_color(C_RESET),
           display_color(C_DIM), pid, display_color(C_RESET));

    display_flush();
}
