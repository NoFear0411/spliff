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
 *
 * test_xdp.c - Unit tests for XDP structures and constants (v0.8.0+)
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <arpa/inet.h>
#include "../src/include/spliff.h"
#include "../src/bpf/bpf_loader.h"

#define TEST(name) printf("TEST: %s... ", name)
#define PASS() printf("\033[32mPASS\033[0m\n")
#define FAIL(msg) do { printf("\033[31mFAIL: %s\033[0m\n", msg); failures++; } while(0)

static int failures = 0;

/* =============================================================================
 * Structure Size Tests - Critical for BPF/Userspace ABI Compatibility
 * =============================================================================
 * These tests ensure our userspace structures match what BPF expects.
 * Size mismatches cause silent data corruption or ring buffer parse errors.
 */

static void test_flow_key_size(void) {
    TEST("flow_key_t size (16 bytes)");

    /* flow_key_t must be exactly 16 bytes for BPF map compatibility */
    if (sizeof(flow_key_t) != 16) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Expected 16, got %zu", sizeof(flow_key_t));
        FAIL(buf);
        return;
    }

    PASS();
}

static void test_flow_key_layout(void) {
    TEST("flow_key_t field layout");

    /* Verify field offsets for packed struct - must match spliff.bpf.c */
    if (offsetof(flow_key_t, saddr) != 0) {
        FAIL("saddr offset wrong");
        return;
    }
    if (offsetof(flow_key_t, daddr) != 4) {
        FAIL("daddr offset wrong");
        return;
    }
    if (offsetof(flow_key_t, sport) != 8) {
        FAIL("sport offset wrong");
        return;
    }
    if (offsetof(flow_key_t, dport) != 10) {
        FAIL("dport offset wrong");
        return;
    }
    if (offsetof(flow_key_t, protocol) != 12) {
        FAIL("protocol offset wrong");
        return;
    }
    if (offsetof(flow_key_t, ip_version) != 13) {
        FAIL("ip_version offset wrong");
        return;
    }

    PASS();
}

static void test_flow_key_fields(void) {
    TEST("flow_key_t protocol and ip_version fields");

    flow_key_t fkey = {0};

    /* Set TCP/IPv4 flow */
    fkey.protocol = 6;  /* IPPROTO_TCP */
    fkey.ip_version = 4;

    if (fkey.protocol != 6) {
        FAIL("protocol field wrong");
        return;
    }
    if (fkey.ip_version != 4) {
        FAIL("ip_version field wrong");
        return;
    }

    /* Set UDP/IPv6 flow */
    fkey.protocol = 17;  /* IPPROTO_UDP */
    fkey.ip_version = 6;

    if (fkey.protocol != 17) {
        FAIL("protocol field wrong for UDP");
        return;
    }
    if (fkey.ip_version != 6) {
        FAIL("ip_version field wrong for IPv6");
        return;
    }

    PASS();
}

static void test_xdp_packet_event_size(void) {
    TEST("xdp_packet_event_t size (52 bytes)");

    /* xdp_packet_event_t must be exactly 52 bytes for dispatcher type inference
     * Size breakdown: 8+8+16+4+4+4+2+1+1+1+1+2 = 52 bytes */
    if (sizeof(xdp_packet_event_t) != 52) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Expected 52, got %zu", sizeof(xdp_packet_event_t));
        FAIL(buf);
        return;
    }

    PASS();
}

static void test_xdp_payload_event_size(void) {
    TEST("xdp_payload_event_t size (172 bytes)");

    /* xdp_payload_event_t must be exactly 172 bytes for dispatcher type inference */
    if (sizeof(xdp_payload_event_t) != 172) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Expected 172, got %zu", sizeof(xdp_payload_event_t));
        FAIL(buf);
        return;
    }

    PASS();
}

static void test_xdp_payload_max(void) {
    TEST("XDP_PAYLOAD_MAX constant");

    /* Must match spliff.bpf.c definition */
    if (XDP_PAYLOAD_MAX != 128) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Expected 128, got %d", XDP_PAYLOAD_MAX);
        FAIL(buf);
        return;
    }

    PASS();
}

/* =============================================================================
 * Enum Value Tests - Must Match BPF Definitions
 * =============================================================================
 */

static void test_xdp_category_values(void) {
    TEST("xdp_category_t enum values");

    /* These must match CAT_* defines in spliff.bpf.c */
    if (XDP_CAT_UNKNOWN != 0) {
        FAIL("XDP_CAT_UNKNOWN != 0");
        return;
    }
    if (XDP_CAT_TLS_TCP != 1) {
        FAIL("XDP_CAT_TLS_TCP != 1");
        return;
    }
    if (XDP_CAT_QUIC != 2) {
        FAIL("XDP_CAT_QUIC != 2");
        return;
    }
    if (XDP_CAT_PLAIN_HTTP != 3) {
        FAIL("XDP_CAT_PLAIN_HTTP != 3");
        return;
    }
    if (XDP_CAT_H2_PREFACE != 4) {
        FAIL("XDP_CAT_H2_PREFACE != 4");
        return;
    }
    if (XDP_CAT_OTHER != 5) {
        FAIL("XDP_CAT_OTHER != 5");
        return;
    }

    PASS();
}

static void test_tcp_flag_values(void) {
    TEST("TCP flag constants");

    /* Standard TCP flags (RFC 793) */
    if (TCP_FLAG_FIN != 0x01) {
        FAIL("TCP_FLAG_FIN != 0x01");
        return;
    }
    if (TCP_FLAG_SYN != 0x02) {
        FAIL("TCP_FLAG_SYN != 0x02");
        return;
    }
    if (TCP_FLAG_RST != 0x04) {
        FAIL("TCP_FLAG_RST != 0x04");
        return;
    }
    if (TCP_FLAG_ACK != 0x10) {
        FAIL("TCP_FLAG_ACK != 0x10");
        return;
    }

    PASS();
}

static void test_event_type_constant(void) {
    TEST("EVENT_XDP_PACKET constant");

    /* Must match BPF definition */
    if (EVENT_XDP_PACKET != 6) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Expected 6, got %d", EVENT_XDP_PACKET);
        FAIL(buf);
        return;
    }

    PASS();
}

/* =============================================================================
 * XDP Mode Name Tests
 * =============================================================================
 */

static void test_xdp_mode_names(void) {
    TEST("bpf_loader_xdp_mode_name()");

    const char *name;

    name = bpf_loader_xdp_mode_name(XDP_MODE_SKB);
    if (strcmp(name, "skb") != 0) {
        char buf[64];
        snprintf(buf, sizeof(buf), "SKB mode: expected 'skb', got '%s'", name);
        FAIL(buf);
        return;
    }

    name = bpf_loader_xdp_mode_name(XDP_MODE_NATIVE);
    if (strcmp(name, "native") != 0) {
        char buf[64];
        snprintf(buf, sizeof(buf), "NATIVE mode: expected 'native', got '%s'", name);
        FAIL(buf);
        return;
    }

    name = bpf_loader_xdp_mode_name(XDP_MODE_OFFLOAD);
    if (strcmp(name, "offload") != 0) {
        char buf[64];
        snprintf(buf, sizeof(buf), "OFFLOAD mode: expected 'offload', got '%s'", name);
        FAIL(buf);
        return;
    }

    /* Invalid mode */
    name = bpf_loader_xdp_mode_name((xdp_mode_t)99);
    if (strcmp(name, "unknown") != 0) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Invalid mode: expected 'unknown', got '%s'", name);
        FAIL(buf);
        return;
    }

    PASS();
}

/* =============================================================================
 * XDP Stats Structure Tests
 * =============================================================================
 */

static void test_xdp_stats_fields(void) {
    TEST("xdp_stats_t structure");

    xdp_stats_t stats = {0};

    /* Verify all fields are accessible and initialize to 0 */
    if (stats.packets_total != 0) {
        FAIL("packets_total not zero-initialized");
        return;
    }
    if (stats.packets_tcp != 0) {
        FAIL("packets_tcp not zero-initialized");
        return;
    }
    if (stats.flows_created != 0) {
        FAIL("flows_created not zero-initialized");
        return;
    }
    if (stats.flows_classified != 0) {
        FAIL("flows_classified not zero-initialized");
        return;
    }
    if (stats.flows_ambiguous != 0) {
        FAIL("flows_ambiguous not zero-initialized");
        return;
    }
    if (stats.flows_terminated != 0) {
        FAIL("flows_terminated not zero-initialized");
        return;
    }
    if (stats.gatekeeper_hits != 0) {
        FAIL("gatekeeper_hits not zero-initialized");
        return;
    }
    if (stats.cookie_failures != 0) {
        FAIL("cookie_failures not zero-initialized");
        return;
    }
    if (stats.ringbuf_drops != 0) {
        FAIL("ringbuf_drops not zero-initialized");
        return;
    }

    PASS();
}

/* =============================================================================
 * Flow Key Byte Order Tests
 * =============================================================================
 */

static void test_flow_key_network_byte_order(void) {
    TEST("flow_key_t network byte order");

    flow_key_t fkey = {0};

    /* Set IP addresses in network byte order (as XDP sees them) */
    fkey.saddr = inet_addr("192.168.1.100");  /* 0x6401a8c0 in little-endian */
    fkey.daddr = inet_addr("10.0.0.1");       /* 0x0100000a in little-endian */
    fkey.sport = htons(12345);
    fkey.dport = htons(443);

    /* Verify values are in network byte order */
    if (ntohs(fkey.sport) != 12345) {
        FAIL("sport byte order wrong");
        return;
    }
    if (ntohs(fkey.dport) != 443) {
        FAIL("dport byte order wrong");
        return;
    }

    /* IP addresses should match */
    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &fkey.saddr, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &fkey.daddr, dst_str, sizeof(dst_str));

    if (strcmp(src_str, "192.168.1.100") != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "saddr mismatch: %s", src_str);
        FAIL(buf);
        return;
    }
    if (strcmp(dst_str, "10.0.0.1") != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "daddr mismatch: %s", dst_str);
        FAIL(buf);
        return;
    }

    PASS();
}

/* =============================================================================
 * XDP Interface Info Tests
 * =============================================================================
 */

static void test_xdp_iface_info_size(void) {
    TEST("xdp_iface_info_t structure");

    xdp_iface_info_t iface = {0};

    /* Verify structure is usable */
    strncpy(iface.name, "eth0", sizeof(iface.name));
    iface.ifindex = 2;
    iface.mtu = 1500;
    iface.flags = 0x1043; /* IFF_UP | IFF_RUNNING | IFF_BROADCAST | IFF_MULTICAST */
    iface.is_physical = true;

    if (strcmp(iface.name, "eth0") != 0) {
        FAIL("name field wrong");
        return;
    }
    if (iface.ifindex != 2) {
        FAIL("ifindex field wrong");
        return;
    }
    if (iface.mtu != 1500) {
        FAIL("mtu field wrong");
        return;
    }
    if (!iface.is_physical) {
        FAIL("is_physical field wrong");
        return;
    }

    PASS();
}

/* =============================================================================
 * Discovery Flag Tests
 * =============================================================================
 */

static void test_discovery_flags(void) {
    TEST("XDP discovery flags");

    /* Verify flag bits don't overlap */
    if (XDP_DISCOVER_SKIP_LOOPBACK != (1 << 0)) {
        FAIL("SKIP_LOOPBACK wrong bit");
        return;
    }
    if (XDP_DISCOVER_SKIP_VIRTUAL != (1 << 1)) {
        FAIL("SKIP_VIRTUAL wrong bit");
        return;
    }
    if (XDP_DISCOVER_ONLY_UP != (1 << 2)) {
        FAIL("ONLY_UP wrong bit");
        return;
    }
    if (XDP_DISCOVER_ONLY_PHYSICAL != (1 << 3)) {
        FAIL("ONLY_PHYSICAL wrong bit");
        return;
    }

    /* Verify default includes expected flags */
    int def = XDP_DISCOVER_DEFAULT;
    if (!(def & XDP_DISCOVER_SKIP_LOOPBACK)) {
        FAIL("Default should skip loopback");
        return;
    }
    if (!(def & XDP_DISCOVER_ONLY_UP)) {
        FAIL("Default should require UP");
        return;
    }

    PASS();
}

/* =============================================================================
 * Library Type Name Tests
 * =============================================================================
 */

static void test_lib_type_names(void) {
    TEST("bpf_loader_lib_type_name()");

    const char *name;

    name = bpf_loader_lib_type_name(LIB_OPENSSL);
    if (strcmp(name, "OpenSSL") != 0) {
        FAIL("LIB_OPENSSL name wrong");
        return;
    }

    name = bpf_loader_lib_type_name(LIB_GNUTLS);
    if (strcmp(name, "GnuTLS") != 0) {
        FAIL("LIB_GNUTLS name wrong");
        return;
    }

    name = bpf_loader_lib_type_name(LIB_NSS);
    if (strcmp(name, "NSS") != 0) {
        FAIL("LIB_NSS name wrong");
        return;
    }

    name = bpf_loader_lib_type_name(LIB_NSS_SSL);
    if (strcmp(name, "NSS-SSL") != 0) {
        FAIL("LIB_NSS_SSL name wrong");
        return;
    }

    name = bpf_loader_lib_type_name(LIB_WOLFSSL);
    if (strcmp(name, "WolfSSL") != 0) {
        FAIL("LIB_WOLFSSL name wrong");
        return;
    }

    /* Invalid type */
    name = bpf_loader_lib_type_name((lib_type_t)99);
    if (strcmp(name, "Unknown") != 0) {
        FAIL("Invalid type should return 'Unknown'");
        return;
    }

    PASS();
}

/* =============================================================================
 * XDP Event Packet Layout Tests
 * =============================================================================
 */

static void test_xdp_packet_event_layout(void) {
    TEST("xdp_packet_event_t field offsets");

    /* Verify packed struct layout matches BPF expectations */
    if (offsetof(xdp_packet_event_t, timestamp_ns) != 0) {
        FAIL("timestamp_ns offset wrong");
        return;
    }
    if (offsetof(xdp_packet_event_t, socket_cookie) != 8) {
        FAIL("socket_cookie offset wrong");
        return;
    }
    if (offsetof(xdp_packet_event_t, flow) != 16) {
        FAIL("flow offset wrong");
        return;
    }
    if (offsetof(xdp_packet_event_t, pkt_len) != 32) {
        FAIL("pkt_len offset wrong");
        return;
    }
    if (offsetof(xdp_packet_event_t, ifindex) != 36) {
        FAIL("ifindex offset wrong");
        return;
    }
    if (offsetof(xdp_packet_event_t, event_type) != 40) {
        FAIL("event_type offset wrong");
        return;
    }
    if (offsetof(xdp_packet_event_t, payload_off) != 44) {
        FAIL("payload_off offset wrong");
        return;
    }
    if (offsetof(xdp_packet_event_t, category) != 46) {
        FAIL("category offset wrong");
        return;
    }
    if (offsetof(xdp_packet_event_t, tls_type) != 47) {
        FAIL("tls_type offset wrong");
        return;
    }
    if (offsetof(xdp_packet_event_t, direction) != 48) {
        FAIL("direction offset wrong");
        return;
    }
    if (offsetof(xdp_packet_event_t, tcp_flags) != 49) {
        FAIL("tcp_flags offset wrong");
        return;
    }

    PASS();
}

static void test_xdp_payload_event_layout(void) {
    TEST("xdp_payload_event_t field offsets");

    /* Verify packed struct layout */
    if (offsetof(xdp_payload_event_t, timestamp_ns) != 0) {
        FAIL("timestamp_ns offset wrong");
        return;
    }
    if (offsetof(xdp_payload_event_t, socket_cookie) != 8) {
        FAIL("socket_cookie offset wrong");
        return;
    }
    if (offsetof(xdp_payload_event_t, flow) != 16) {
        FAIL("flow offset wrong");
        return;
    }
    if (offsetof(xdp_payload_event_t, payload_len) != 32) {
        FAIL("payload_len offset wrong");
        return;
    }
    if (offsetof(xdp_payload_event_t, event_type) != 36) {
        FAIL("event_type offset wrong");
        return;
    }
    if (offsetof(xdp_payload_event_t, category) != 40) {
        FAIL("category offset wrong");
        return;
    }
    if (offsetof(xdp_payload_event_t, payload) != 44) {
        FAIL("payload offset wrong");
        return;
    }

    /* Payload should end at byte 172 */
    if (offsetof(xdp_payload_event_t, payload) + XDP_PAYLOAD_MAX != 172) {
        char buf[64];
        snprintf(buf, sizeof(buf), "payload end: expected 172, got %zu",
                 offsetof(xdp_payload_event_t, payload) + XDP_PAYLOAD_MAX);
        FAIL(buf);
        return;
    }

    PASS();
}

/* =============================================================================
 * Main
 * =============================================================================
 */

int main(void) {
    printf("\n=== XDP Structure & Constant Tests (v0.8.0+) ===\n\n");

    /* Structure size tests (critical for BPF ABI) */
    test_flow_key_size();
    test_flow_key_layout();
    test_flow_key_fields();
    test_xdp_packet_event_size();
    test_xdp_payload_event_size();
    test_xdp_payload_max();

    /* Enum value tests */
    test_xdp_category_values();
    test_tcp_flag_values();
    test_event_type_constant();

    /* XDP mode and stats */
    test_xdp_mode_names();
    test_xdp_stats_fields();

    /* Byte order and layout */
    test_flow_key_network_byte_order();
    test_xdp_packet_event_layout();
    test_xdp_payload_event_layout();

    /* Interface and discovery */
    test_xdp_iface_info_size();
    test_discovery_flags();

    /* Library loader */
    test_lib_type_names();

    printf("\n");
    if (failures == 0) {
        printf("\033[32mAll XDP tests passed!\033[0m\n");
        return 0;
    } else {
        printf("\033[31m%d XDP test(s) failed\033[0m\n", failures);
        return 1;
    }
}
