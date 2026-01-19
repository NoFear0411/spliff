/**
 * @file display.c
 * @brief Implementation of console output formatting and display functions
 *
 * @details This file implements the display module for spliff, handling
 * all formatted console output including HTTP traffic, TLS events,
 * and body content visualization.
 *
 * Key features:
 * - Thread-safe timestamp generation
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
#include "../content/signatures.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>  /* For inet_ntop, ntohs */

/**
 * @brief Global color output setting
 *
 * When true, ANSI escape codes are included in output.
 * When false, all color codes are replaced with empty strings.
 *
 * @internal
 */
static bool g_use_colors = true;

/**
 * @brief Initialize the display module
 *
 * @param use_colors Whether to enable ANSI color output
 * @return Always returns 0 (success)
 */
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

/**
 * @brief Get color code respecting color configuration
 *
 * @param color_code The ANSI color code to potentially return
 * @return The color code if colors enabled, empty string otherwise
 */
const char *display_color(const char *color_code) {
    return g_use_colors ? color_code : "";
}

/**
 * @brief Format latency for human-readable display
 *
 * Automatically selects appropriate units based on magnitude:
 * - Nanoseconds for < 1µs
 * - Microseconds for < 1ms
 * - Milliseconds for < 1s
 * - Seconds for >= 1s
 *
 * @param delta_ns Latency in nanoseconds
 * @param buf      Output buffer
 * @param size     Size of output buffer
 */
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

/**
 * @brief Get current timestamp as formatted string
 *
 * Thread-safe implementation using POSIX localtime_r.
 * Format: HH:MM:SS.mmm
 *
 * @param buf  Output buffer
 * @param size Size of output buffer
 */
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
 * @brief Get XDP category name string for display output
 *
 * @param category XDP flow category from packet classification
 * @return Short human-readable category name
 */
static const char *get_xdp_category_name(uint8_t category) {
    switch (category) {
        case XDP_CAT_UNKNOWN:     return "?";
        case XDP_CAT_TLS_TCP:     return "TLS";
        case XDP_CAT_QUIC:        return "QUIC";
        case XDP_CAT_PLAIN_HTTP:  return "HTTP";
        case XDP_CAT_H2_PREFACE:  return "H2";
        case XDP_CAT_OTHER:       return "Other";
        default:                  return "?";
    }
}

/**
 * @brief Display XDP flow correlation info
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
void display_flow_info(const http_message_t *msg) {
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

    const char *category = get_xdp_category_name(msg->flow_category);

    printf("              %s|-%s %s%s:%u → %s:%u%s %s[%s]%s",
           display_color(C_DIM), display_color(C_RESET),
           display_color(C_DIM),
           left_ip, left_port,
           right_ip, right_port,
           display_color(C_RESET),
           display_color(C_CYAN), category, display_color(C_RESET));

    if (msg->flow_ifname[0]) {
        printf(" %s(%s)%s", display_color(C_DIM), msg->flow_ifname, display_color(C_RESET));
    }

    printf("\n");
}

/**
 * @brief Display formatted HTTP request
 *
 * Output format:
 * @code
 * HH:MM:SS.mmm → METHOD https://host/path ALPN:proto process (pid) [latency] [stream N]
 *               ├─ src:port -> dst:port [TLS] (ifname)
 * @endcode
 *
 * @param msg HTTP message containing request data
 */
void display_http_request(const http_message_t *msg) {
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
    printf("%s%s%s %s→%s %s%s%s %s %sALPN:%s%s",
           display_color(C_DIM), ts, display_color(C_RESET),
           display_color(C_GREEN), display_color(C_RESET),
           display_color(C_BOLD), msg->method, display_color(C_RESET),
           full_uri,
           display_color(C_DIM), alpn_str, display_color(C_RESET));

    printf(" %s%s%s %s(%u)%s",
           display_color(C_CYAN), msg->comm, display_color(C_RESET),
           display_color(C_DIM), msg->pid, display_color(C_RESET));

    /* Show latency if enabled and available */
    if (g_config.show_latency && msg->delta_ns > 0) {
        char lat[32];
        display_format_latency(msg->delta_ns, lat, sizeof(lat));
        printf(" %s[%s]%s", display_color(C_YELLOW), lat, display_color(C_RESET));
    }

    /* Show stream ID for HTTP/2 */
    if (msg->protocol == PROTO_HTTP2 && msg->stream_id > 0) {
        printf(" %s[stream %d]%s", display_color(C_DIM), msg->stream_id, display_color(C_RESET));
    }

    printf("\n");

    /* Show XDP flow correlation info if available */
    display_flow_info(msg);
}

/**
 * @brief Display formatted HTTP response
 *
 * Output format:
 * @code
 * HH:MM:SS.mmm ← STATUS https://host/path ALPN:proto content-type (size) process (pid) [latency] [stream N]
 * @endcode
 *
 * Status codes are color-coded:
 * - 2xx: Green (success)
 * - 3xx: Yellow (redirect)
 * - 4xx/5xx: Red (error)
 *
 * @param msg HTTP message containing response data
 */
void display_http_response(const http_message_t *msg) {
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
    printf("%s%s%s %s←%s %s%d%s",
           display_color(C_DIM), ts, display_color(C_RESET),
           display_color(C_BLUE), display_color(C_RESET),
           display_color(status_color), msg->status_code, display_color(C_RESET));

    /* Show request URL for correlation */
    if (msg->authority[0]) {
        printf(" %s://%s%s",
               msg->scheme[0] ? msg->scheme : "https",
               msg->authority,
               msg->path);
    }

    /* Show ALPN after URL */
    printf(" %sALPN:%s%s", display_color(C_DIM), alpn_str, display_color(C_RESET));

    if (msg->content_type[0]) {
        printf(" %s%s%s", display_color(C_DIM), msg->content_type, display_color(C_RESET));
    }

    if (msg->content_length > 0) {
        printf(" %s(%zu bytes)%s", display_color(C_DIM), msg->content_length, display_color(C_RESET));
    }

    printf(" %s%s%s %s(%u)%s",
           display_color(C_CYAN), msg->comm, display_color(C_RESET),
           display_color(C_DIM), msg->pid, display_color(C_RESET));

    /* Show latency if enabled and available */
    if (g_config.show_latency && msg->delta_ns > 0) {
        char lat[32];
        display_format_latency(msg->delta_ns, lat, sizeof(lat));
        printf(" %s[%s]%s", display_color(C_YELLOW), lat, display_color(C_RESET));
    }

    /* Show stream ID for HTTP/2 */
    if (msg->protocol == PROTO_HTTP2 && msg->stream_id > 0) {
        printf(" %s[stream %d]%s", display_color(C_DIM), msg->stream_id, display_color(C_RESET));
    }

    printf("\n");

    /* Show XDP flow correlation info if available */
    display_flow_info(msg);
}

/**
 * @brief Display HTTP headers
 *
 * @param msg HTTP message containing headers to display
 */
void display_http_headers(const http_message_t *msg) {
    for (int i = 0; i < msg->header_count && i < MAX_HEADERS; i++) {
        printf("  %s%s:%s %s\n",
               display_color(C_CYAN), msg->headers[i].name,
               display_color(C_RESET), msg->headers[i].value);
    }
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

/**
 * @brief Display HTTP body content
 *
 * Automatically determines display format based on content type
 * and data inspection. Text content is printed as-is, binary
 * content is shown as hexdump.
 *
 * @param data         Body data
 * @param len          Length of body data
 * @param content_type Content-Type header (may be NULL)
 */
void display_body(const uint8_t *data, size_t len, const char *content_type) {
    if (len == 0) return;

    /* Delegate to hex display if -x flag is set */
    if (g_config.hexdump_body) {
        display_body_hex(data, len, content_type);
        return;
    }

    printf("%s─── Body ───%s\n", display_color(C_DIM), display_color(C_RESET));

    /* Determine if this is text content */
    bool is_text = is_text_content_type(content_type) || is_printable_text(data, len);

    if (is_text) {
        /* Print full text content - no truncation for -b mode */
        fwrite(data, 1, len, stdout);
        /* Ensure newline at end */
        if (len > 0 && data[len-1] != '\n') {
            printf("\n");
        }
    } else {
        /* Binary content - show hexdump (truncated) */
        size_t print_len = len > 512 ? 512 : len;
        for (size_t i = 0; i < print_len; i += 16) {
            printf("%s%04zx%s  ", display_color(C_DIM), i, display_color(C_RESET));
            /* Hex bytes */
            for (size_t j = 0; j < 16; j++) {
                if (i + j < print_len) {
                    printf("%02x ", data[i + j]);
                } else {
                    printf("   ");
                }
            }
            printf(" ");
            /* ASCII representation */
            for (size_t j = 0; j < 16 && i + j < print_len; j++) {
                uint8_t c = data[i + j];
                printf("%c", (c >= 32 && c < 127) ? c : '.');
            }
            printf("\n");
        }
        if (len > 512) {
            printf("%s... (%zu more bytes)%s\n",
                   display_color(C_DIM), len - 512, display_color(C_RESET));
        }
    }
    printf("%s────────────%s\n", display_color(C_DIM), display_color(C_RESET));
}

/**
 * @brief Display body as hexdump with file signature detection
 *
 * Always shows hexdump format with automatic file signature
 * detection using magic bytes. Displays detected file type,
 * class, and trailer validation status when applicable.
 *
 * @param data         Body data
 * @param len          Length of body data
 * @param content_type Content-Type header (fallback if no signature detected)
 */
void display_body_hex(const uint8_t *data, size_t len, const char *content_type) {
    if (len == 0) return;

    /* Detect file signature */
    signature_result_t sig_result;
    bool detected = signature_detect_full(data, len, true, &sig_result);

    /* Print header with signature info */
    printf("%s─── Body", display_color(C_DIM));

    if (detected) {
        /* Show: type [class] (confidence) */
        printf(" │ %s%s%s [%s%s%s]",
               display_color(C_CYAN), sig_result.description, display_color(C_DIM),
               display_color(C_YELLOW), signature_class_name(sig_result.file_class),
               display_color(C_DIM));

        /* Show trailer validation status if applicable */
        if (!sig_result.trailer_valid) {
            printf(" %s(trailer mismatch)%s", display_color(C_RED), display_color(C_DIM));
        }
    } else if (content_type && content_type[0]) {
        printf(" │ %s", content_type);
    }

    printf(" (%zu bytes) ───%s\n", len, display_color(C_RESET));

    /* Always show hexdump in -x mode */
    size_t print_len = len > 512 ? 512 : len;
    for (size_t i = 0; i < print_len; i += 16) {
        printf("%s%04zx%s  ", display_color(C_DIM), i, display_color(C_RESET));

        /* Hex bytes */
        for (size_t j = 0; j < 16; j++) {
            if (i + j < print_len) {
                printf("%02x ", data[i + j]);
            } else {
                printf("   ");
            }
            /* Extra space at 8-byte boundary */
            if (j == 7) printf(" ");
        }

        printf(" ");

        /* ASCII representation */
        for (size_t j = 0; j < 16 && i + j < print_len; j++) {
            uint8_t c = data[i + j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        printf("\n");
    }

    if (len > 512) {
        printf("%s... (%zu more bytes)%s\n",
               display_color(C_DIM), len - 512, display_color(C_RESET));
    }

    printf("%s────────────%s\n", display_color(C_DIM), display_color(C_RESET));
}

/**
 * @brief Display TLS handshake event
 *
 * Shows completed TLS handshakes with timing information.
 * Skips in-progress events (result < 0) to reduce noise.
 *
 * @param pid      Process ID
 * @param comm     Process name
 * @param delta_ns Handshake duration in nanoseconds
 * @param result   Handshake result code
 */
void display_handshake(uint32_t pid, const char *comm, uint64_t delta_ns, int result) {
    char ts[32];
    display_get_timestamp(ts, sizeof(ts));

    /* Different SSL libraries have different return value conventions:
     * OpenSSL SSL_do_handshake:  1 = success, 0 = error, -1 = need retry
     * NSS SSL_ForceHandshake:    0 = success (SECSuccess), -1 = failure
     * GnuTLS gnutls_handshake:   0 = success, negative = error/retry
     *
     * We treat both 0 and 1 as success, negative as in-progress/error */
    if (result < 0) {
        return;  /* Skip in-progress events (WANT_READ/WANT_WRITE) */
    }

    const char *status = "complete";
    const char *status_color = C_GREEN;

    printf("%s%s%s %s🔒%s TLS handshake %s%s%s",
           display_color(C_DIM), ts, display_color(C_RESET),
           display_color(C_MAGENTA), display_color(C_RESET),
           display_color(status_color), status, display_color(C_RESET));

    /* Show handshake duration */
    if (delta_ns > 0) {
        char lat[32];
        display_format_latency(delta_ns, lat, sizeof(lat));
        printf(" %s[%s]%s", display_color(C_YELLOW), lat, display_color(C_RESET));
    }

    printf(" %s%s%s %s(%u)%s\n",
           display_color(C_CYAN), comm, display_color(C_RESET),
           display_color(C_DIM), pid, display_color(C_RESET));
}
