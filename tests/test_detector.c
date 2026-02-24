/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * test_detector.c - Unit tests for vectorscan-powered protocol detection
 *
 * Tests cover:
 * - Protocol detection (HTTP/1.x, HTTP/2, TLS, WebSocket)
 * - Thread-local scratch management
 * - Engine availability checks
 * - Flow protocol initialization
 * - Edge cases and error handling
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "../src/protocol/detector.h"
#include "../src/protocol/http1.h"
#include "../src/protocol/http2.h"

#define TEST(name) printf("TEST: %s... ", name)
#define PASS() printf("\033[32mPASS\033[0m\n")
#define FAIL(msg) do { printf("\033[31mFAIL: %s\033[0m\n", msg); failures++; } while(0)

static int failures = 0;

/*----------------------------------------------------------------------------
 * Test Data: Protocol samples
 *----------------------------------------------------------------------------*/

/* HTTP/1.x Request samples */
static const char *HTTP1_REQUESTS[] = {
    "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "POST /api HTTP/1.1\r\nHost: api.test\r\n\r\n",
    "PUT /data HTTP/1.1\r\nContent-Type: application/json\r\n\r\n",
    "DELETE /item/123 HTTP/1.1\r\n\r\n",
    "HEAD /check HTTP/1.0\r\n\r\n",
    "OPTIONS * HTTP/1.1\r\n\r\n",
    "PATCH /update HTTP/1.1\r\n\r\n",
    "CONNECT proxy.example.com:443 HTTP/1.1\r\n\r\n",
    "TRACE /debug HTTP/1.1\r\n\r\n",
};
static const size_t HTTP1_REQUEST_COUNT = sizeof(HTTP1_REQUESTS) / sizeof(HTTP1_REQUESTS[0]);

/* HTTP/1.x Response samples */
static const char *HTTP1_RESPONSES[] = {
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    "HTTP/1.0 404 Not Found\r\n\r\n",
    "HTTP/1.1 301 Moved Permanently\r\nLocation: /new\r\n\r\n",
    "HTTP/1.1 500 Internal Server Error\r\n\r\n",
    "HTTP/1.1 204 No Content\r\n\r\n",
    "HTTP/1.0 302 Found\r\n\r\n",
    "HTTP/1.1 403 Forbidden\r\n\r\n",
    "HTTP/1.1 100 Continue\r\n\r\n",
};
static const size_t HTTP1_RESPONSE_COUNT = sizeof(HTTP1_RESPONSES) / sizeof(HTTP1_RESPONSES[0]);

/* HTTP/2 Connection Preface (24 bytes magic) */
static const uint8_t HTTP2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
static const size_t HTTP2_PREFACE_LEN = 24;

/* TLS Record samples (Content-Type + Version) */
static const uint8_t TLS_HANDSHAKE_12[] = { 0x16, 0x03, 0x03, 0x00, 0x05 }; /* TLS 1.2 handshake */
static const uint8_t TLS_HANDSHAKE_11[] = { 0x16, 0x03, 0x02, 0x00, 0x10 }; /* TLS 1.1 handshake */
static const uint8_t TLS_HANDSHAKE_10[] = { 0x16, 0x03, 0x01, 0x00, 0x20 }; /* TLS 1.0 handshake */
static const uint8_t TLS_APPDATA[] = { 0x17, 0x03, 0x03, 0x00, 0x30 };     /* TLS application data */

/* WebSocket frame samples (FIN + masked opcode) */
static const uint8_t WS_TEXT_FRAME[] = { 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f }; /* text frame */
static const uint8_t WS_BINARY_FRAME[] = { 0x82, 0x80 };   /* binary frame, empty */
static const uint8_t WS_PING_FRAME[] = { 0x89, 0x80 };     /* ping */
static const uint8_t WS_PONG_FRAME[] = { 0x8a, 0x80 };     /* pong */
static const uint8_t WS_CLOSE_FRAME[] = { 0x88, 0x82 };    /* close */

/* Non-matching data */
static const char *UNKNOWN_DATA[] = {
    "Hello, World!",
    "{ \"json\": true }",
    "<?xml version=\"1.0\"?>",
    "SSH-2.0-OpenSSH_8.9",
    "\x00\x00\x00\x00",
    "random garbage data here",
};
static const size_t UNKNOWN_DATA_COUNT = sizeof(UNKNOWN_DATA) / sizeof(UNKNOWN_DATA[0]);

/*----------------------------------------------------------------------------
 * Initialization Tests
 *----------------------------------------------------------------------------*/

static void test_init_cleanup(void) {
    TEST("proto_detector_init/cleanup");

    int result = proto_detector_init();
    if (result < 0) {
        FAIL("proto_detector_init failed");
        return;
    }

    /* Cleanup should not crash */
    proto_detector_cleanup();

    /* Re-init should work */
    result = proto_detector_init();
    if (result < 0) {
        FAIL("proto_detector_init failed on re-init");
        return;
    }

    proto_detector_cleanup();
    PASS();
}

static void test_thread_cleanup(void) {
    TEST("proto_detector_thread_cleanup");

    proto_detector_init();

    /* Trigger scratch allocation by doing a detection */
    proto_detect((const uint8_t *)"test", 4);

    /* Thread cleanup should not crash */
    proto_detector_thread_cleanup();

    /* Cleanup again should be safe (idempotent) */
    proto_detector_thread_cleanup();

    proto_detector_cleanup();
    PASS();
}

/*----------------------------------------------------------------------------
 * Engine Information Tests
 *----------------------------------------------------------------------------*/

static void test_engine_name(void) {
    TEST("proto_detector_engine_name");

    proto_detector_init();

    const char *name = proto_detector_engine_name();
    if (!name || strlen(name) == 0) {
        FAIL("Engine name is empty");
        proto_detector_cleanup();
        return;
    }

    /* Should be one of: "vectorscan", "hyperscan", "pcre2", "manual" */
    printf("(%s) ", name);

    if (strcmp(name, "vectorscan") != 0 &&
        strcmp(name, "hyperscan") != 0 &&
        strcmp(name, "pcre2") != 0 &&
        strcmp(name, "manual") != 0) {
        FAIL("Unknown engine name");
        proto_detector_cleanup();
        return;
    }

    proto_detector_cleanup();
    PASS();
}

static void test_is_nfa_engine(void) {
    TEST("proto_detector_is_nfa_engine");

    proto_detector_init();

    bool is_nfa = proto_detector_is_nfa_engine();
    const char *name = proto_detector_engine_name();

    /* NFA engine should be vectorscan or hyperscan */
    if (is_nfa) {
        if (strcmp(name, "vectorscan") != 0 && strcmp(name, "hyperscan") != 0) {
            FAIL("NFA engine but name is not vectorscan/hyperscan");
            proto_detector_cleanup();
            return;
        }
    } else {
        if (strcmp(name, "pcre2") != 0 && strcmp(name, "manual") != 0) {
            FAIL("Non-NFA engine but name is not pcre2/manual");
            proto_detector_cleanup();
            return;
        }
    }

    printf("(%s) ", is_nfa ? "yes" : "no");

    proto_detector_cleanup();
    PASS();
}

/*----------------------------------------------------------------------------
 * HTTP/1.x Detection Tests
 *----------------------------------------------------------------------------*/

static void test_detect_http1_request(void) {
    TEST("proto_detect HTTP/1.x request");

    proto_detector_init();

    for (size_t i = 0; i < HTTP1_REQUEST_COUNT; i++) {
        const char *req = HTTP1_REQUESTS[i];
        proto_detect_result_t result = proto_detect((const uint8_t *)req, strlen(req));

        if (result != PROTO_DETECT_HTTP1_REQ) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Request %zu detected as %d (expected %d)",
                     i, result, PROTO_DETECT_HTTP1_REQ);
            FAIL(buf);
            proto_detector_cleanup();
            return;
        }
    }

    proto_detector_cleanup();
    PASS();
}

static void test_detect_http1_response(void) {
    TEST("proto_detect HTTP/1.x response");

    proto_detector_init();

    for (size_t i = 0; i < HTTP1_RESPONSE_COUNT; i++) {
        const char *resp = HTTP1_RESPONSES[i];
        proto_detect_result_t result = proto_detect((const uint8_t *)resp, strlen(resp));

        if (result != PROTO_DETECT_HTTP1_RSP) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Response %zu detected as %d (expected %d)",
                     i, result, PROTO_DETECT_HTTP1_RSP);
            FAIL(buf);
            proto_detector_cleanup();
            return;
        }
    }

    proto_detector_cleanup();
    PASS();
}

/*----------------------------------------------------------------------------
 * HTTP/2 Detection Tests
 *----------------------------------------------------------------------------*/

static void test_detect_http2_preface(void) {
    TEST("proto_detect HTTP/2 preface");

    proto_detector_init();

    proto_detect_result_t result = proto_detect(HTTP2_PREFACE, HTTP2_PREFACE_LEN);
    if (result != PROTO_DETECT_HTTP2) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Detected as %d (expected %d)", result, PROTO_DETECT_HTTP2);
        FAIL(buf);
        proto_detector_cleanup();
        return;
    }

    /* Preface with additional data after */
    uint8_t preface_plus[48];
    memcpy(preface_plus, HTTP2_PREFACE, HTTP2_PREFACE_LEN);
    memset(preface_plus + HTTP2_PREFACE_LEN, 0, 24);

    result = proto_detect(preface_plus, sizeof(preface_plus));
    if (result != PROTO_DETECT_HTTP2) {
        FAIL("Preface with trailing data not detected");
        proto_detector_cleanup();
        return;
    }

    proto_detector_cleanup();
    PASS();
}

/*----------------------------------------------------------------------------
 * TLS Detection Tests
 *----------------------------------------------------------------------------*/

static void test_detect_tls(void) {
    TEST("proto_detect TLS");

    proto_detector_init();

    struct {
        const uint8_t *data;
        size_t len;
        const char *name;
    } tls_samples[] = {
        { TLS_HANDSHAKE_12, sizeof(TLS_HANDSHAKE_12), "TLS 1.2 handshake" },
        { TLS_HANDSHAKE_11, sizeof(TLS_HANDSHAKE_11), "TLS 1.1 handshake" },
        { TLS_HANDSHAKE_10, sizeof(TLS_HANDSHAKE_10), "TLS 1.0 handshake" },
        { TLS_APPDATA, sizeof(TLS_APPDATA), "TLS application data" },
    };

    for (size_t i = 0; i < sizeof(tls_samples) / sizeof(tls_samples[0]); i++) {
        proto_detect_result_t result = proto_detect(tls_samples[i].data, tls_samples[i].len);
        if (result != PROTO_DETECT_TLS) {
            char buf[128];
            snprintf(buf, sizeof(buf), "%s detected as %d (expected %d)",
                     tls_samples[i].name, result, PROTO_DETECT_TLS);
            FAIL(buf);
            proto_detector_cleanup();
            return;
        }
    }

    proto_detector_cleanup();
    PASS();
}

/*----------------------------------------------------------------------------
 * WebSocket Detection Tests
 *----------------------------------------------------------------------------*/

static void test_detect_websocket(void) {
    TEST("proto_detect WebSocket");

    proto_detector_init();

    struct {
        const uint8_t *data;
        size_t len;
        const char *name;
    } ws_samples[] = {
        { WS_TEXT_FRAME, sizeof(WS_TEXT_FRAME), "text frame" },
        { WS_BINARY_FRAME, sizeof(WS_BINARY_FRAME), "binary frame" },
        { WS_PING_FRAME, sizeof(WS_PING_FRAME), "ping" },
        { WS_PONG_FRAME, sizeof(WS_PONG_FRAME), "pong" },
        { WS_CLOSE_FRAME, sizeof(WS_CLOSE_FRAME), "close" },
    };

    for (size_t i = 0; i < sizeof(ws_samples) / sizeof(ws_samples[0]); i++) {
        proto_detect_result_t result = proto_detect(ws_samples[i].data, ws_samples[i].len);
        if (result != PROTO_DETECT_WEBSOCKET) {
            char buf[128];
            snprintf(buf, sizeof(buf), "%s detected as %d (expected %d)",
                     ws_samples[i].name, result, PROTO_DETECT_WEBSOCKET);
            FAIL(buf);
            proto_detector_cleanup();
            return;
        }
    }

    proto_detector_cleanup();
    PASS();
}

/*----------------------------------------------------------------------------
 * Unknown Protocol Tests
 *----------------------------------------------------------------------------*/

static void test_detect_unknown(void) {
    TEST("proto_detect unknown protocols");

    proto_detector_init();

    for (size_t i = 0; i < UNKNOWN_DATA_COUNT; i++) {
        const char *data = UNKNOWN_DATA[i];
        proto_detect_result_t result = proto_detect((const uint8_t *)data, strlen(data));

        if (result != PROTO_DETECT_UNKNOWN) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Data %zu ('%.20s...') detected as %d",
                     i, data, result);
            FAIL(buf);
            proto_detector_cleanup();
            return;
        }
    }

    proto_detector_cleanup();
    PASS();
}

/*----------------------------------------------------------------------------
 * Edge Cases
 *----------------------------------------------------------------------------*/

static void test_detect_edge_cases(void) {
    TEST("proto_detect edge cases");

    proto_detector_init();

    /* NULL data */
    proto_detect_result_t result = proto_detect(NULL, 0);
    if (result != PROTO_DETECT_UNKNOWN) {
        FAIL("NULL data should return UNKNOWN");
        proto_detector_cleanup();
        return;
    }

    /* Zero length */
    result = proto_detect((const uint8_t *)"test", 0);
    if (result != PROTO_DETECT_UNKNOWN) {
        FAIL("Zero length should return UNKNOWN");
        proto_detector_cleanup();
        return;
    }

    /* Single byte */
    uint8_t single = 0x16; /* TLS content type */
    result = proto_detect(&single, 1);
    /* Should not crash, might return UNKNOWN or partial match */

    /* Very short HTTP/1.x (incomplete) */
    result = proto_detect((const uint8_t *)"GET", 3);
    if (result == PROTO_DETECT_HTTP1_REQ) {
        /* Pattern requires full method + space + path + version */
        FAIL("Partial GET should not match");
        proto_detector_cleanup();
        return;
    }

    proto_detector_cleanup();
    PASS();
}

/*----------------------------------------------------------------------------
 * proto_detect_and_init Tests
 *----------------------------------------------------------------------------*/

static void test_detect_and_init_http1(void) {
    TEST("proto_detect_and_init HTTP/1.x");

    proto_detector_init();

    /* Create a minimal flow context */
    flow_context_t ctx = {0};
    ctx.proto = FLOW_PROTO_UNKNOWN;

    const char *req = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
    flow_proto_t result = proto_detect_and_init(&ctx, (const uint8_t *)req, strlen(req));

    if (result != FLOW_PROTO_HTTP1) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Expected FLOW_PROTO_HTTP1, got %d", result);
        FAIL(buf);
        proto_detector_cleanup();
        return;
    }

    if (ctx.proto != FLOW_PROTO_HTTP1) {
        FAIL("Context proto not updated");
        proto_detector_cleanup();
        return;
    }

    proto_detector_cleanup();
    PASS();
}

static void test_detect_and_init_http2(void) {
    TEST("proto_detect_and_init HTTP/2");

    proto_detector_init();

    flow_context_t ctx = {0};
    ctx.proto = FLOW_PROTO_UNKNOWN;

    flow_proto_t result = proto_detect_and_init(&ctx, HTTP2_PREFACE, HTTP2_PREFACE_LEN);

    if (result != FLOW_PROTO_HTTP2) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Expected FLOW_PROTO_HTTP2, got %d", result);
        FAIL(buf);
        proto_detector_cleanup();
        return;
    }

    if (ctx.proto != FLOW_PROTO_HTTP2) {
        FAIL("Context proto not updated");
        proto_detector_cleanup();
        return;
    }

    proto_detector_cleanup();
    PASS();
}

static void test_detect_and_init_cached(void) {
    TEST("proto_detect_and_init cached");

    proto_detector_init();

    /* Pre-set the protocol */
    flow_context_t ctx = {0};
    ctx.proto = FLOW_PROTO_HTTP1;

    /* Pass HTTP/2 data, but should return cached HTTP/1 */
    flow_proto_t result = proto_detect_and_init(&ctx, HTTP2_PREFACE, HTTP2_PREFACE_LEN);

    if (result != FLOW_PROTO_HTTP1) {
        FAIL("Should return cached protocol");
        proto_detector_cleanup();
        return;
    }

    proto_detector_cleanup();
    PASS();
}

static void test_detect_and_init_null_ctx(void) {
    TEST("proto_detect_and_init NULL context");

    proto_detector_init();

    /* NULL context should return UNKNOWN */
    flow_proto_t result = proto_detect_and_init(NULL, HTTP2_PREFACE, HTTP2_PREFACE_LEN);

    if (result != FLOW_PROTO_UNKNOWN) {
        FAIL("NULL context should return UNKNOWN");
        proto_detector_cleanup();
        return;
    }

    proto_detector_cleanup();
    PASS();
}

static void test_detect_and_init_tls_stays_unknown(void) {
    TEST("proto_detect_and_init TLS stays UNKNOWN");

    proto_detector_init();

    flow_context_t ctx = {0};
    ctx.proto = FLOW_PROTO_UNKNOWN;

    /* TLS detection should not set a flow protocol (encrypted) */
    flow_proto_t result = proto_detect_and_init(&ctx, TLS_HANDSHAKE_12, sizeof(TLS_HANDSHAKE_12));

    if (result != FLOW_PROTO_UNKNOWN) {
        char buf[64];
        snprintf(buf, sizeof(buf), "TLS should stay UNKNOWN, got %d", result);
        FAIL(buf);
        proto_detector_cleanup();
        return;
    }

    proto_detector_cleanup();
    PASS();
}

/*----------------------------------------------------------------------------
 * Consistency with http1/http2 modules
 *----------------------------------------------------------------------------*/

static void test_consistency_with_http1(void) {
    TEST("consistency with http1_is_request/response");

    proto_detector_init();

    /* All data that http1_is_request() accepts should be detected as HTTP1_REQ */
    for (size_t i = 0; i < HTTP1_REQUEST_COUNT; i++) {
        const char *req = HTTP1_REQUESTS[i];
        bool is_req = http1_is_request((const uint8_t *)req, strlen(req));
        proto_detect_result_t detected = proto_detect((const uint8_t *)req, strlen(req));

        if (is_req && detected != PROTO_DETECT_HTTP1_REQ) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Inconsistency: http1_is_request=true but detected=%d", detected);
            FAIL(buf);
            proto_detector_cleanup();
            return;
        }
    }

    /* All data that http1_is_response() accepts should be detected as HTTP1_RSP */
    for (size_t i = 0; i < HTTP1_RESPONSE_COUNT; i++) {
        const char *resp = HTTP1_RESPONSES[i];
        bool is_resp = http1_is_response((const uint8_t *)resp, strlen(resp));
        proto_detect_result_t detected = proto_detect((const uint8_t *)resp, strlen(resp));

        if (is_resp && detected != PROTO_DETECT_HTTP1_RSP) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Inconsistency: http1_is_response=true but detected=%d", detected);
            FAIL(buf);
            proto_detector_cleanup();
            return;
        }
    }

    proto_detector_cleanup();
    PASS();
}

static void test_consistency_with_http2(void) {
    TEST("consistency with http2_is_preface");

    proto_detector_init();

    /* HTTP/2 preface detection should be consistent */
    bool is_preface = http2_is_preface(HTTP2_PREFACE, HTTP2_PREFACE_LEN);
    proto_detect_result_t detected = proto_detect(HTTP2_PREFACE, HTTP2_PREFACE_LEN);

    if (is_preface && detected != PROTO_DETECT_HTTP2) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Inconsistency: http2_is_preface=true but detected=%d", detected);
        FAIL(buf);
        proto_detector_cleanup();
        return;
    }

    proto_detector_cleanup();
    PASS();
}

/*----------------------------------------------------------------------------
 * Main
 *----------------------------------------------------------------------------*/

int main(void) {
    printf("\n=== Protocol Detector Tests (vectorscan) ===\n\n");

    /* Init/cleanup */
    test_init_cleanup();
    test_thread_cleanup();

    /* Engine info */
    test_engine_name();
    test_is_nfa_engine();

    /* Protocol detection */
    test_detect_http1_request();
    test_detect_http1_response();
    test_detect_http2_preface();
    test_detect_tls();
    test_detect_websocket();
    test_detect_unknown();

    /* Edge cases */
    test_detect_edge_cases();

    /* proto_detect_and_init */
    test_detect_and_init_http1();
    test_detect_and_init_http2();
    test_detect_and_init_cached();
    test_detect_and_init_null_ctx();
    test_detect_and_init_tls_stays_unknown();

    /* Consistency checks */
    test_consistency_with_http1();
    test_consistency_with_http2();

    printf("\n");
    if (failures == 0) {
        printf("\033[32mAll tests passed!\033[0m\n");
        return 0;
    } else {
        printf("\033[31m%d test(s) failed\033[0m\n", failures);
        return 1;
    }
}
