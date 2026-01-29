/**
 * @file test_http2.c
 * @brief Unit tests for HTTP/2 protocol parsing (nghttp2)
 *
 * Tests the HTTP/2 module's public API:
 * - http2_init/cleanup lifecycle
 * - http2_is_preface detection
 * - http2_frame_name lookup
 * - http2_is_valid_frame_header validation
 *
 * Note: Session/stream management is in flow_context.c (see test_flow_context.c)
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "../src/include/spliff.h"
#include "../src/protocol/http2.h"

/* Stub global config for http2.c verbose output */
config_t g_config = {0};

#define TEST(name) printf("TEST: %s... ", name)
#define PASS() printf("\033[32mPASS\033[0m\n")
#define FAIL(msg) do { printf("\033[31mFAIL: %s\033[0m\n", msg); failures++; } while(0)

static int failures = 0;

/* HTTP/2 connection preface (client) */
static const char H2_CLIENT_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define H2_CLIENT_PREFACE_LEN 24

/* Build an HTTP/2 frame header (9 bytes) */
static void build_frame_header(uint8_t *buf, uint32_t length, uint8_t type,
                                uint8_t flags, uint32_t stream_id) {
    buf[0] = (length >> 16) & 0xff;
    buf[1] = (length >> 8) & 0xff;
    buf[2] = length & 0xff;
    buf[3] = type;
    buf[4] = flags;
    buf[5] = (stream_id >> 24) & 0x7f;  /* Clear reserved bit */
    buf[6] = (stream_id >> 16) & 0xff;
    buf[7] = (stream_id >> 8) & 0xff;
    buf[8] = stream_id & 0xff;
}

/* ============================================================================
 * Lifecycle Tests
 * ============================================================================ */

static void test_init_cleanup(void) {
    TEST("http2_init/cleanup");

    int result = http2_init();
    if (result < 0) {
        FAIL("http2_init failed");
        return;
    }

    http2_cleanup();

    /* Should be able to init again after cleanup */
    result = http2_init();
    if (result < 0) {
        FAIL("http2_init failed after cleanup");
        return;
    }

    http2_cleanup();
    PASS();
}

/* ============================================================================
 * Preface Detection Tests
 * ============================================================================ */

static void test_is_preface(void) {
    TEST("http2_is_preface valid");

    if (!http2_is_preface((const uint8_t *)H2_CLIENT_PREFACE, H2_CLIENT_PREFACE_LEN)) {
        FAIL("Failed to detect valid preface");
        return;
    }

    /* Preface with trailing data */
    uint8_t preface_plus[32];
    memcpy(preface_plus, H2_CLIENT_PREFACE, H2_CLIENT_PREFACE_LEN);
    memset(preface_plus + H2_CLIENT_PREFACE_LEN, 0, 8);
    if (!http2_is_preface(preface_plus, sizeof(preface_plus))) {
        FAIL("Failed to detect preface with trailing data");
        return;
    }

    PASS();
}

static void test_is_preface_negative(void) {
    TEST("http2_is_preface negative cases");

    /* Too short */
    if (http2_is_preface((const uint8_t *)H2_CLIENT_PREFACE, 10)) {
        FAIL("False positive on short data");
        return;
    }

    /* HTTP/1.1 request */
    const char *http1 = "GET / HTTP/1.1\r\nHost: foo\r\n\r\n";
    if (http2_is_preface((const uint8_t *)http1, strlen(http1))) {
        FAIL("False positive on HTTP/1.1");
        return;
    }

    /* SETTINGS frame (not preface) */
    uint8_t settings[9];
    build_frame_header(settings, 0, H2_FRAME_SETTINGS, 0, 0);
    if (http2_is_preface(settings, sizeof(settings))) {
        FAIL("False positive on SETTINGS frame");
        return;
    }

    /* Corrupted preface */
    uint8_t corrupted[24];
    memcpy(corrupted, H2_CLIENT_PREFACE, 24);
    corrupted[10] = 'X';
    if (http2_is_preface(corrupted, 24)) {
        FAIL("False positive on corrupted preface");
        return;
    }

    /* Zero length */
    if (http2_is_preface((const uint8_t *)"", 0)) {
        FAIL("False positive on empty data");
        return;
    }

    PASS();
}

/* ============================================================================
 * Frame Name Tests
 * ============================================================================ */

static void test_frame_names(void) {
    TEST("http2_frame_name");

    struct {
        int type;
        const char *expected;
    } tests[] = {
        { H2_FRAME_DATA,          "DATA" },
        { H2_FRAME_HEADERS,       "HEADERS" },
        { H2_FRAME_PRIORITY,      "PRIORITY" },
        { H2_FRAME_RST_STREAM,    "RST_STREAM" },
        { H2_FRAME_SETTINGS,      "SETTINGS" },
        { H2_FRAME_PUSH_PROMISE,  "PUSH_PROMISE" },
        { H2_FRAME_PING,          "PING" },
        { H2_FRAME_GOAWAY,        "GOAWAY" },
        { H2_FRAME_WINDOW_UPDATE, "WINDOW_UPDATE" },
        { H2_FRAME_CONTINUATION,  "CONTINUATION" },
    };

    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        const char *name = http2_frame_name(tests[i].type);
        if (strcmp(name, tests[i].expected) != 0) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Type %d: expected '%s', got '%s'",
                     tests[i].type, tests[i].expected, name);
            FAIL(buf);
            return;
        }
    }

    /* Unknown frame type */
    if (strcmp(http2_frame_name(99), "UNKNOWN") != 0) {
        FAIL("Unknown type should return 'UNKNOWN'");
        return;
    }

    PASS();
}

/* ============================================================================
 * Frame Header Validation Tests
 * ============================================================================ */

static void test_frame_validation_valid(void) {
    TEST("http2_is_valid_frame_header valid frames");

    uint8_t frame[9];

    /* SETTINGS on stream 0 */
    build_frame_header(frame, 0, H2_FRAME_SETTINGS, 0x00, 0);
    if (!http2_is_valid_frame_header(frame, 9)) {
        FAIL("Valid SETTINGS rejected");
        return;
    }

    /* HEADERS on stream 1 */
    build_frame_header(frame, 256, H2_FRAME_HEADERS, 0x25, 1);
    if (!http2_is_valid_frame_header(frame, 9)) {
        FAIL("Valid HEADERS rejected");
        return;
    }

    /* DATA with max default size (16384) */
    build_frame_header(frame, 16384, H2_FRAME_DATA, 0x00, 3);
    if (!http2_is_valid_frame_header(frame, 9)) {
        FAIL("Valid DATA (16KB) rejected");
        return;
    }

    /* Max sane length (64KB) */
    build_frame_header(frame, H2_MAX_SANE_FRAME_LEN, H2_FRAME_DATA, 0x01, 5);
    if (!http2_is_valid_frame_header(frame, 9)) {
        FAIL("Valid 64KB DATA rejected");
        return;
    }

    /* All valid frame types */
    for (int type = 0; type <= H2_MAX_VALID_FRAME_TYPE; type++) {
        uint32_t stream_id = (type == 4 || type == 6 || type == 7) ? 0 : 1;
        build_frame_header(frame, 10, (uint8_t)type, 0x00, stream_id);
        if (!http2_is_valid_frame_header(frame, 9)) {
            char buf[64];
            snprintf(buf, sizeof(buf), "Valid frame type %d rejected", type);
            FAIL(buf);
            return;
        }
    }

    PASS();
}

static void test_frame_validation_invalid(void) {
    TEST("http2_is_valid_frame_header invalid frames");

    uint8_t frame[9];

    /* Oversized frame (> 64KB) */
    build_frame_header(frame, H2_MAX_SANE_FRAME_LEN + 1, H2_FRAME_DATA, 0x00, 1);
    if (http2_is_valid_frame_header(frame, 9)) {
        FAIL("Oversized frame should be rejected");
        return;
    }

    /* Huge frame (8MB - corruption) */
    build_frame_header(frame, 8978441, H2_FRAME_DATA, 0x00, 1);
    if (http2_is_valid_frame_header(frame, 9)) {
        FAIL("Huge frame should be rejected");
        return;
    }

    /* Unknown frame type (99) */
    build_frame_header(frame, 100, 99, 0x00, 1);
    if (http2_is_valid_frame_header(frame, 9)) {
        FAIL("Unknown type 99 should be rejected");
        return;
    }

    /* Garbage frame type (223) */
    build_frame_header(frame, 100, 223, 0x3d, 1);
    if (http2_is_valid_frame_header(frame, 9)) {
        FAIL("Garbage type 223 should be rejected");
        return;
    }

    /* Huge stream ID */
    build_frame_header(frame, 100, H2_FRAME_HEADERS, 0x25, 0x7FFFFFFF);
    if (http2_is_valid_frame_header(frame, 9)) {
        FAIL("Huge stream ID should be rejected");
        return;
    }

    /* Garbage stream ID from corruption */
    build_frame_header(frame, 100, H2_FRAME_DATA, 0x00, 1061814757);
    if (http2_is_valid_frame_header(frame, 9)) {
        FAIL("Garbage stream ID should be rejected");
        return;
    }

    PASS();
}

static void test_frame_validation_buffer_size(void) {
    TEST("http2_is_valid_frame_header buffer size");

    uint8_t frame[32];
    build_frame_header(frame, 0, H2_FRAME_SETTINGS, 0x00, 0);

    /* Buffer too small */
    if (http2_is_valid_frame_header(frame, 8)) {
        FAIL("Should reject buffer < 9 bytes");
        return;
    }

    if (http2_is_valid_frame_header(frame, 0)) {
        FAIL("Should reject empty buffer");
        return;
    }

    /* Exactly 9 bytes */
    if (!http2_is_valid_frame_header(frame, 9)) {
        FAIL("Should accept exactly 9 bytes");
        return;
    }

    /* Larger buffer */
    if (!http2_is_valid_frame_header(frame, sizeof(frame))) {
        FAIL("Should accept larger buffer");
        return;
    }

    PASS();
}

/* ============================================================================
 * Frame Header Encoding Tests
 * ============================================================================ */

static void test_frame_header_encoding(void) {
    TEST("Frame header encoding");

    uint8_t frame[9];

    /* SETTINGS with flags */
    build_frame_header(frame, 0, H2_FRAME_SETTINGS, 0x01, 0);
    if (frame[3] != H2_FRAME_SETTINGS || frame[4] != 0x01) {
        FAIL("Wrong type/flags encoding");
        return;
    }

    /* Length 256 */
    build_frame_header(frame, 256, H2_FRAME_HEADERS, 0x25, 1);
    if (frame[0] != 0 || frame[1] != 1 || frame[2] != 0) {
        FAIL("Wrong length encoding for 256");
        return;
    }

    /* Length 16384 */
    build_frame_header(frame, 16384, H2_FRAME_DATA, 0x00, 3);
    uint32_t decoded = ((uint32_t)frame[0] << 16) |
                       ((uint32_t)frame[1] << 8) |
                       (uint32_t)frame[2];
    if (decoded != 16384) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrong decoded length: %u", decoded);
        FAIL(buf);
        return;
    }

    /* Stream ID */
    build_frame_header(frame, 0, H2_FRAME_DATA, 0x00, 100);
    uint32_t stream_id = ((uint32_t)(frame[5] & 0x7f) << 24) |
                         ((uint32_t)frame[6] << 16) |
                         ((uint32_t)frame[7] << 8) |
                         (uint32_t)frame[8];
    if (stream_id != 100) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrong stream ID: %u", stream_id);
        FAIL(buf);
        return;
    }

    PASS();
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    printf("=== HTTP/2 Parser Tests (nghttp2) ===\n\n");

    test_init_cleanup();
    test_is_preface();
    test_is_preface_negative();
    test_frame_names();
    test_frame_validation_valid();
    test_frame_validation_invalid();
    test_frame_validation_buffer_size();
    test_frame_header_encoding();

    printf("\n");
    if (failures == 0) {
        printf("\033[32mAll tests passed!\033[0m\n");
        return 0;
    } else {
        printf("\033[31m%d test(s) failed\033[0m\n", failures);
        return 1;
    }
}
