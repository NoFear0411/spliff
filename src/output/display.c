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

#include "display.h"
#include "../content/signatures.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/* Global color setting */
static bool g_use_colors = true;

/* Initialize display module */
int display_init(bool use_colors) {
    g_use_colors = use_colors;
    return 0;
}

/* Cleanup */
void display_cleanup(void) {
    /* No cleanup needed */
}

/* Get color code (respects color setting) */
const char *display_color(const char *color_code) {
    return g_use_colors ? color_code : "";
}

/* Format latency for display */
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

/* Get current timestamp string (thread-safe) */
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

/* Display HTTP request */
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

    /* Determine protocol version string */
    const char *proto_str = (msg->protocol == PROTO_HTTP2) ? "HTTP/2" : "HTTP/1.1";

    /* Format: <timestamp> ← <method> <full URI> <protocol> [ALPN] <process name> <PID> [latency] */
    printf("%s%s%s %s←%s %s%s%s %s %s%s%s",
           display_color(C_DIM), ts, display_color(C_RESET),
           display_color(C_GREEN), display_color(C_RESET),
           display_color(C_BOLD), msg->method, display_color(C_RESET),
           full_uri,
           display_color(C_DIM), proto_str, display_color(C_RESET));

    /* Show ALPN if available */
    if (msg->alpn_proto[0]) {
        printf(" %s[%s]%s", display_color(C_MAGENTA), msg->alpn_proto, display_color(C_RESET));
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
    printf("\n");
}

/* Display HTTP response */
void display_http_response(const http_message_t *msg) {
    char ts[32];
    display_get_timestamp(ts, sizeof(ts));

    const char *status_color = C_GREEN;
    if (msg->status_code >= 400) status_color = C_RED;
    else if (msg->status_code >= 300) status_color = C_YELLOW;

    /* Format: <timestamp> → <status code> <content-type> <size> [ALPN] <process name> <PID> [latency] */
    printf("%s%s%s %s→%s %s%d%s",
           display_color(C_DIM), ts, display_color(C_RESET),
           display_color(C_BLUE), display_color(C_RESET),
           display_color(status_color), msg->status_code, display_color(C_RESET));

    if (msg->content_type[0]) {
        printf(" %s", msg->content_type);
    }

    if (msg->content_length > 0) {
        printf(" %s(%zu bytes)%s", display_color(C_DIM), msg->content_length, display_color(C_RESET));
    }

    /* Show ALPN if available */
    if (msg->alpn_proto[0]) {
        printf(" %s[%s]%s", display_color(C_MAGENTA), msg->alpn_proto, display_color(C_RESET));
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
    printf("\n");
}

/* Display HTTP headers */
void display_http_headers(const http_message_t *msg) {
    for (int i = 0; i < msg->header_count && i < MAX_HEADERS; i++) {
        printf("  %s%s:%s %s\n",
               display_color(C_CYAN), msg->headers[i].name,
               display_color(C_RESET), msg->headers[i].value);
    }
}

/* Check if content type indicates text */
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

/* Check if data looks like printable text */
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

/* Display body content */
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

/* Display body with file signature detection and hexdump */
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

/* Display TLS handshake event */
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
