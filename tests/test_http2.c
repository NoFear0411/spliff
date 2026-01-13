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
 * test_http2.c - Unit tests for nghttp2-based HTTP/2 parser
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "../src/include/spliff.h"
#include "../src/protocol/http2.h"

#define TEST(name) printf("TEST: %s... ", name)
#define PASS() printf("\033[32mPASS\033[0m\n")
#define FAIL(msg) do { printf("\033[31mFAIL: %s\033[0m\n", msg); failures++; } while(0)

static int failures = 0;

/* HTTP/2 connection preface (client) */
static const uint8_t H2_CLIENT_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define H2_CLIENT_PREFACE_LEN 24

/* Build an HTTP/2 frame header */
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

/* Test HTTP/2 initialization and cleanup */
static void test_init_cleanup(void) {
    TEST("http2_init/cleanup");

    int result = http2_init();
    if (result < 0) {
        FAIL("http2_init failed");
        return;
    }

    /* Should be able to init again after cleanup */
    http2_cleanup();

    result = http2_init();
    if (result < 0) {
        FAIL("http2_init failed after cleanup");
        return;
    }

    http2_cleanup();
    PASS();
}

/* Test HTTP/2 client preface detection */
static void test_is_preface(void) {
    TEST("http2_is_preface");

    /* Valid preface */
    if (!http2_is_preface(H2_CLIENT_PREFACE, H2_CLIENT_PREFACE_LEN)) {
        FAIL("Failed to detect valid preface");
        return;
    }

    /* Preface with extra data after */
    uint8_t preface_plus[32];
    memcpy(preface_plus, H2_CLIENT_PREFACE, H2_CLIENT_PREFACE_LEN);
    memset(preface_plus + H2_CLIENT_PREFACE_LEN, 0, 8);
    if (!http2_is_preface(preface_plus, sizeof(preface_plus))) {
        FAIL("Failed to detect preface with trailing data");
        return;
    }

    /* Too short */
    if (http2_is_preface(H2_CLIENT_PREFACE, 10)) {
        FAIL("False positive on short data");
        return;
    }

    /* Invalid preface */
    const uint8_t invalid[] = "GET / HTTP/1.1\r\nHost: foo\r\n\r\n";
    if (http2_is_preface(invalid, sizeof(invalid) - 1)) {
        FAIL("False positive on HTTP/1.1 request");
        return;
    }

    /* HTTP/2 response (not preface) */
    uint8_t settings_frame[9];
    build_frame_header(settings_frame, 0, H2_FRAME_SETTINGS, 0, 0);
    if (http2_is_preface(settings_frame, sizeof(settings_frame))) {
        FAIL("False positive on SETTINGS frame");
        return;
    }

    PASS();
}

/* Test HTTP/2 frame type names */
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
    const char *unknown = http2_frame_name(99);
    if (strcmp(unknown, "UNKNOWN") != 0) {
        FAIL("Unknown type should return 'UNKNOWN'");
        return;
    }

    PASS();
}

/* Test session tracking */
static void test_session_tracking(void) {
    TEST("http2_has_session");

    http2_init();

    /* No session initially */
    if (http2_has_session(12345, 0)) {
        FAIL("Session exists before creation");
        http2_cleanup();
        return;
    }

    /* Note: Sessions are created internally by http2_process_frame
     * We can't easily test this without mocking BPF events */

    http2_cleanup();
    PASS();
}

/* Test stream management */
static void test_stream_management(void) {
    TEST("http2_get_stream");

    http2_init();

    /* Create a stream */
    h2_stream_t *stream1 = http2_get_stream(1000, 0, 1, true);
    if (!stream1) {
        FAIL("Failed to create stream");
        http2_cleanup();
        return;
    }

    if (stream1->pid != 1000 || stream1->stream_id != 1) {
        FAIL("Stream has wrong PID or stream_id");
        http2_cleanup();
        return;
    }

    /* Get same stream (no create) */
    h2_stream_t *stream1_again = http2_get_stream(1000, 0, 1, false);
    if (stream1_again != stream1) {
        FAIL("Should return same stream pointer");
        http2_cleanup();
        return;
    }

    /* Create another stream for same PID */
    h2_stream_t *stream3 = http2_get_stream(1000, 0, 3, true);
    if (!stream3 || stream3 == stream1) {
        FAIL("Failed to create second stream");
        http2_cleanup();
        return;
    }

    /* Create stream for different PID */
    h2_stream_t *stream_other = http2_get_stream(2000, 0, 1, true);
    if (!stream_other || stream_other == stream1) {
        FAIL("Failed to create stream for different PID");
        http2_cleanup();
        return;
    }

    /* Non-existent stream without create */
    h2_stream_t *nonexistent = http2_get_stream(9999, 0, 99, false);
    if (nonexistent) {
        FAIL("Should return NULL for non-existent stream");
        http2_cleanup();
        return;
    }

    /* Free a stream */
    http2_free_stream(1000, 0, 1);
    h2_stream_t *freed = http2_get_stream(1000, 0, 1, false);
    if (freed) {
        FAIL("Stream should be freed");
        http2_cleanup();
        return;
    }

    /* Stream 3 should still exist */
    h2_stream_t *still_exists = http2_get_stream(1000, 0, 3, false);
    if (!still_exists) {
        FAIL("Other stream should still exist");
        http2_cleanup();
        return;
    }

    http2_cleanup();
    PASS();
}

/* Test frame header parsing */
static void test_frame_header_format(void) {
    TEST("Frame header format");

    uint8_t frame[9];

    /* SETTINGS frame on stream 0 */
    build_frame_header(frame, 0, H2_FRAME_SETTINGS, 0x01, 0);
    if (frame[0] != 0 || frame[1] != 0 || frame[2] != 0) {
        FAIL("Wrong length encoding");
        return;
    }
    if (frame[3] != H2_FRAME_SETTINGS) {
        FAIL("Wrong type");
        return;
    }
    if (frame[4] != 0x01) {
        FAIL("Wrong flags");
        return;
    }
    if (frame[5] != 0 || frame[6] != 0 || frame[7] != 0 || frame[8] != 0) {
        FAIL("Wrong stream ID");
        return;
    }

    /* HEADERS frame on stream 1 with length 256 */
    build_frame_header(frame, 256, H2_FRAME_HEADERS, 0x25, 1);
    if (frame[0] != 0 || frame[1] != 1 || frame[2] != 0) {
        FAIL("Wrong length encoding for 256");
        return;
    }
    if (frame[3] != H2_FRAME_HEADERS) {
        FAIL("Wrong type for HEADERS");
        return;
    }
    if (frame[8] != 1) {
        FAIL("Wrong stream ID for stream 1");
        return;
    }

    /* Large length (16384 = max default frame size) */
    build_frame_header(frame, 16384, H2_FRAME_DATA, 0x00, 3);
    uint32_t decoded_len = ((uint32_t)frame[0] << 16) |
                           ((uint32_t)frame[1] << 8) |
                           (uint32_t)frame[2];
    if (decoded_len != 16384) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrong decoded length: %u", decoded_len);
        FAIL(buf);
        return;
    }

    PASS();
}

/* Test stream ID validation (odd = client-initiated, even = server-initiated) */
static void test_stream_id_rules(void) {
    TEST("Stream ID rules");

    http2_init();

    /* Client-initiated streams are odd */
    h2_stream_t *client_stream = http2_get_stream(1000, 0, 1, true);
    if (!client_stream) {
        FAIL("Failed to create client stream");
        http2_cleanup();
        return;
    }

    /* Stream 3, 5, 7 are also valid client streams */
    for (int id = 3; id <= 7; id += 2) {
        h2_stream_t *s = http2_get_stream(1000, 0, id, true);
        if (!s) {
            char buf[64];
            snprintf(buf, sizeof(buf), "Failed to create client stream %d", id);
            FAIL(buf);
            http2_cleanup();
            return;
        }
    }

    /* Server-initiated streams are even (but stream 0 is connection-level) */
    h2_stream_t *server_stream = http2_get_stream(1000, 0, 2, true);
    if (!server_stream) {
        FAIL("Failed to create server stream");
        http2_cleanup();
        return;
    }

    http2_cleanup();
    PASS();
}

/* Test frame header validation (for mid-stream join recovery) */
static void test_frame_validation(void) {
    TEST("http2_is_valid_frame_header");

    uint8_t frame[9];

    /* Valid SETTINGS frame on stream 0 */
    build_frame_header(frame, 0, H2_FRAME_SETTINGS, 0x00, 0);
    if (!http2_is_valid_frame_header(frame)) {
        FAIL("Valid SETTINGS frame rejected");
        return;
    }

    /* Valid HEADERS frame on stream 1 with typical length */
    build_frame_header(frame, 256, H2_FRAME_HEADERS, 0x25, 1);
    if (!http2_is_valid_frame_header(frame)) {
        FAIL("Valid HEADERS frame rejected");
        return;
    }

    /* Valid DATA frame with max default size (16384) */
    build_frame_header(frame, 16384, H2_FRAME_DATA, 0x00, 3);
    if (!http2_is_valid_frame_header(frame)) {
        FAIL("Valid DATA frame (16KB) rejected");
        return;
    }

    /* Valid frame at max sane length (64KB) */
    build_frame_header(frame, H2_MAX_SANE_FRAME_LEN, H2_FRAME_DATA, 0x01, 5);
    if (!http2_is_valid_frame_header(frame)) {
        FAIL("Valid 64KB DATA frame rejected");
        return;
    }

    /* INVALID: Frame length too large (over 64KB) */
    build_frame_header(frame, H2_MAX_SANE_FRAME_LEN + 1, H2_FRAME_DATA, 0x00, 1);
    if (http2_is_valid_frame_header(frame)) {
        FAIL("Oversized frame should be rejected");
        return;
    }

    /* INVALID: Frame length way too large (8MB - typical corruption value) */
    build_frame_header(frame, 8978441, H2_FRAME_DATA, 0x00, 1);
    if (http2_is_valid_frame_header(frame)) {
        FAIL("Huge frame (8MB) should be rejected");
        return;
    }

    /* INVALID: Unknown frame type (> 9) */
    build_frame_header(frame, 100, 99, 0x00, 1);
    if (http2_is_valid_frame_header(frame)) {
        FAIL("Unknown frame type 99 should be rejected");
        return;
    }

    /* INVALID: Unknown frame type (223 - from debug output) */
    build_frame_header(frame, 100, 223, 0x3d, 1);
    if (http2_is_valid_frame_header(frame)) {
        FAIL("Unknown frame type 223 should be rejected");
        return;
    }

    /* INVALID: Stream ID too large (billions - garbage value) */
    build_frame_header(frame, 100, H2_FRAME_HEADERS, 0x25, 0x7FFFFFFF);
    if (http2_is_valid_frame_header(frame)) {
        FAIL("Huge stream ID should be rejected");
        return;
    }

    /* INVALID: Stream ID from debug output (1061814757) */
    build_frame_header(frame, 100, H2_FRAME_DATA, 0x00, 1061814757);
    if (http2_is_valid_frame_header(frame)) {
        FAIL("Garbage stream ID 1061814757 should be rejected");
        return;
    }

    /* Valid: Stream 0 for connection-level frames */
    build_frame_header(frame, 4, H2_FRAME_WINDOW_UPDATE, 0x00, 0);
    if (!http2_is_valid_frame_header(frame)) {
        FAIL("Valid WINDOW_UPDATE on stream 0 rejected");
        return;
    }

    /* Valid: All frame types 0-9 should be accepted with correct stream_id
     * Per HTTP/2 spec:
     *   - SETTINGS (4), PING (6), GOAWAY (7) require stream_id=0
     *   - DATA (0), HEADERS (1), PRIORITY (2), RST_STREAM (3), PUSH_PROMISE (5), CONTINUATION (9) require stream_id>0
     *   - WINDOW_UPDATE (8) can be on any stream
     */
    for (int type = 0; type <= H2_MAX_VALID_FRAME_TYPE; type++) {
        uint32_t stream_id;
        switch (type) {
        case 0x04: /* SETTINGS */
        case 0x06: /* PING */
        case 0x07: /* GOAWAY */
            stream_id = 0;  /* Connection-level frames */
            break;
        default:
            stream_id = 1;  /* Stream-specific frames */
            break;
        }
        build_frame_header(frame, 10, (uint8_t)type, 0x00, stream_id);
        if (!http2_is_valid_frame_header(frame)) {
            char buf[64];
            snprintf(buf, sizeof(buf), "Valid frame type %d rejected", type);
            FAIL(buf);
            return;
        }
    }

    PASS();
}

/* Test multiple sessions */
static void test_multiple_pids(void) {
    TEST("Multiple PID sessions");

    http2_init();

    /* Create streams for multiple PIDs */
    uint32_t pids[] = { 1001, 1002, 1003, 1004, 1005 };
    for (size_t i = 0; i < sizeof(pids)/sizeof(pids[0]); i++) {
        h2_stream_t *s = http2_get_stream(pids[i], 0, 1, true);
        if (!s) {
            char buf[64];
            snprintf(buf, sizeof(buf), "Failed for PID %u", pids[i]);
            FAIL(buf);
            http2_cleanup();
            return;
        }
        if (s->pid != pids[i]) {
            FAIL("Stream has wrong PID");
            http2_cleanup();
            return;
        }
    }

    /* Verify each PID's stream is independent */
    for (size_t i = 0; i < sizeof(pids)/sizeof(pids[0]); i++) {
        h2_stream_t *s = http2_get_stream(pids[i], 0, 1, false);
        if (!s || s->pid != pids[i]) {
            FAIL("Stream lookup failed or wrong PID");
            http2_cleanup();
            return;
        }
    }

    /* Free one and verify others unaffected */
    http2_free_stream(1003, 0, 1);
    if (http2_get_stream(1003, 0, 1, false)) {
        FAIL("Freed stream still exists");
        http2_cleanup();
        return;
    }
    if (!http2_get_stream(1002, 0, 1, false) || !http2_get_stream(1004, 0, 1, false)) {
        FAIL("Adjacent streams affected by free");
        http2_cleanup();
        return;
    }

    http2_cleanup();
    PASS();
}

int main(void) {
    printf("\n=== HTTP/2 Parser Tests (nghttp2) ===\n\n");

    test_init_cleanup();
    test_is_preface();
    test_frame_names();
    test_session_tracking();
    test_stream_management();
    test_frame_header_format();
    test_stream_id_rules();
    test_frame_validation();
    test_multiple_pids();

    printf("\n");
    if (failures == 0) {
        printf("\033[32mAll tests passed!\033[0m\n");
        return 0;
    } else {
        printf("\033[31m%d test(s) failed\033[0m\n", failures);
        return 1;
    }
}
