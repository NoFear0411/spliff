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
 *
 * test_common.c - Common test infrastructure (provides g_config)
 */

#include "../include/sslsniff.h"

/* Global configuration - normally in main.c */
config_t g_config = {
    .use_colors = false,    /* Disable colors in tests */
    .show_body = false,
    .compact_mode = false,
    .show_latency = false,
    .show_handshake = false,
    .use_openssl = true,
    .use_gnutls = true,
    .use_nss = true,
};
