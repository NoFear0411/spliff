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

#ifndef DISPLAY_H
#define DISPLAY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../include/spliff.h"

/* ANSI color codes */
#define C_RESET   "\033[0m"
#define C_BOLD    "\033[1m"
#define C_DIM     "\033[2m"
#define C_RED     "\033[31m"
#define C_GREEN   "\033[32m"
#define C_YELLOW  "\033[33m"
#define C_BLUE    "\033[34m"
#define C_MAGENTA "\033[35m"
#define C_CYAN    "\033[36m"
#define C_WHITE   "\033[37m"

/* Initialize display module */
int display_init(bool use_colors);

/* Cleanup */
void display_cleanup(void);

/* Get color code (respects color setting) */
const char *display_color(const char *color_code);

/* Format latency for display */
void display_format_latency(uint64_t delta_ns, char *buf, size_t size);

/* Get current timestamp string */
void display_get_timestamp(char *buf, size_t size);

/* Display HTTP request */
void display_http_request(const http_message_t *msg);

/* Display HTTP response */
void display_http_response(const http_message_t *msg);

/* Display HTTP headers */
void display_http_headers(const http_message_t *msg);

/* Display body content */
void display_body(const uint8_t *data, size_t len, const char *content_type);

/* Display body with file signature detection and hexdump */
void display_body_hex(const uint8_t *data, size_t len, const char *content_type);

/* Display TLS handshake event */
void display_handshake(uint32_t pid, const char *comm, uint64_t delta_ns, int result);

#endif /* DISPLAY_H */
