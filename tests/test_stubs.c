/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * test_stubs.c - Stub functions for unit tests that don't need full threading
 */

#include "../src/threading/threading.h"

/* Stub global threading manager pointer for tests */
static threading_mgr_t *g_threading_mgr_stub = NULL;

threading_mgr_t *threading_get_manager(void) {
    return g_threading_mgr_stub;
}
