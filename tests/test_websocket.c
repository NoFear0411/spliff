/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * test_websocket.c - Unit tests for WebSocket frame parser (RFC 6455)
 *
 * Tests cover:
 * - Frame header parsing (FIN, RSV, opcode, mask, length)
 * - Variable payload length encoding (7-bit, 16-bit, 64-bit)
 * - Masking/unmasking operations
 * - Control frame validation (CLOSE, PING, PONG)
 * - Upgrade request/response detection
 * - ws_is_frame heuristic validation
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "../src/protocol/websocket.h"

#define TEST(name) printf("TEST: %s... ", name)
#define PASS() printf("\033[32mPASS\033[0m\n")
#define FAIL(msg) do { printf("\033[31mFAIL: %s\033[0m\n", msg); failures++; } while(0)

static int failures = 0;

/*============================================================================
 * Frame Parsing Tests
 *============================================================================*/

static void test_parse_text_frame_unmasked(void) {
    TEST("ws_parse_frame text unmasked");

    /* Text frame, FIN=1, opcode=0x1 (text), no mask, payload="Hello" */
    /* Binary: 0x81 0x05 'H' 'e' 'l' 'l' 'o' */
    uint8_t frame[] = { 0x81, 0x05, 'H', 'e', 'l', 'l', 'o' };

    ws_frame_t parsed;
    int consumed = ws_parse_frame(frame, sizeof(frame), &parsed);

    if (consumed != 7) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrong consumed: %d (expected 7)", consumed);
        FAIL(buf);
        return;
    }

    if (!parsed.fin) {
        FAIL("FIN should be true");
        return;
    }

    if (parsed.opcode != WS_OPCODE_TEXT) {
        FAIL("Wrong opcode");
        return;
    }

    if (parsed.masked) {
        FAIL("Should not be masked");
        return;
    }

    if (parsed.payload_len != 5) {
        FAIL("Wrong payload length");
        return;
    }

    if (memcmp(parsed.payload, "Hello", 5) != 0) {
        FAIL("Wrong payload content");
        return;
    }

    PASS();
}

static void test_parse_text_frame_masked(void) {
    TEST("ws_parse_frame text masked");

    /* Text frame, FIN=1, opcode=0x1, masked, payload="Hello" (XOR with mask) */
    /* Mask key: 0x37 0xfa 0x21 0x3d */
    /* "Hello" XOR mask = 0x7f 0x9f 0x4d 0x51 0x58 */
    uint8_t frame[] = {
        0x81, 0x85,                         /* FIN=1, opcode=text, MASK=1, len=5 */
        0x37, 0xfa, 0x21, 0x3d,             /* Mask key */
        0x7f, 0x9f, 0x4d, 0x51, 0x58        /* Masked "Hello" */
    };

    ws_frame_t parsed;
    int consumed = ws_parse_frame(frame, sizeof(frame), &parsed);

    if (consumed != 11) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrong consumed: %d (expected 11)", consumed);
        FAIL(buf);
        return;
    }

    if (!parsed.masked) {
        FAIL("Should be masked");
        return;
    }

    if (parsed.payload_len != 5) {
        FAIL("Wrong payload length");
        return;
    }

    /* Verify mask key */
    if (memcmp(parsed.mask_key, "\x37\xfa\x21\x3d", 4) != 0) {
        FAIL("Wrong mask key");
        return;
    }

    /* Unmask and verify */
    uint8_t payload_copy[5];
    memcpy(payload_copy, parsed.payload, 5);
    ws_unmask_payload(payload_copy, 5, parsed.mask_key);

    if (memcmp(payload_copy, "Hello", 5) != 0) {
        FAIL("Wrong unmasked payload");
        return;
    }

    PASS();
}

static void test_parse_binary_frame(void) {
    TEST("ws_parse_frame binary");

    /* Binary frame with some binary data */
    uint8_t data[] = { 0x00, 0x01, 0x02, 0x03, 0xff };
    uint8_t frame[7] = { 0x82, 0x05 };  /* FIN=1, opcode=binary, len=5 */
    memcpy(frame + 2, data, 5);

    ws_frame_t parsed;
    int consumed = ws_parse_frame(frame, sizeof(frame), &parsed);

    if (consumed != 7) {
        FAIL("Wrong consumed length");
        return;
    }

    if (parsed.opcode != WS_OPCODE_BINARY) {
        FAIL("Wrong opcode");
        return;
    }

    if (memcmp(parsed.payload, data, 5) != 0) {
        FAIL("Wrong payload content");
        return;
    }

    PASS();
}

static void test_parse_16bit_length(void) {
    TEST("ws_parse_frame 16-bit length");

    /* Frame with 16-bit extended length = 256 bytes */
    uint8_t frame[260];
    frame[0] = 0x82;  /* FIN=1, opcode=binary */
    frame[1] = 0x7e;  /* 126 indicates 16-bit extended length */
    frame[2] = 0x01;  /* Length high byte */
    frame[3] = 0x00;  /* Length low byte = 256 */
    memset(frame + 4, 'A', 256);

    ws_frame_t parsed;
    int consumed = ws_parse_frame(frame, sizeof(frame), &parsed);

    if (consumed != 260) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrong consumed: %d (expected 260)", consumed);
        FAIL(buf);
        return;
    }

    if (parsed.payload_len != 256) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrong length: %lu (expected 256)", (unsigned long)parsed.payload_len);
        FAIL(buf);
        return;
    }

    if (parsed.header_len != 4) {
        FAIL("Wrong header length");
        return;
    }

    PASS();
}

static void test_parse_64bit_length(void) {
    TEST("ws_parse_frame 64-bit length header");

    /* Frame header for 64-bit extended length (we won't allocate that much data) */
    uint8_t frame[20];
    frame[0] = 0x82;  /* FIN=1, opcode=binary */
    frame[1] = 0x7f;  /* 127 indicates 64-bit extended length */
    /* 8-byte length encoding for value 100 */
    frame[2] = 0x00; frame[3] = 0x00; frame[4] = 0x00; frame[5] = 0x00;
    frame[6] = 0x00; frame[7] = 0x00; frame[8] = 0x00; frame[9] = 0x64; /* 100 */
    memset(frame + 10, 'B', 10);  /* Only partial payload */

    ws_frame_t parsed;
    /* Need more data - only have 20 bytes but need 10 (header) + 100 (payload) = 110 */
    int consumed = ws_parse_frame(frame, sizeof(frame), &parsed);

    if (consumed != 0) {
        FAIL("Should return 0 (need more data)");
        return;
    }

    /* Now test with enough data */
    uint8_t *full_frame = malloc(110);
    full_frame[0] = 0x82;
    full_frame[1] = 0x7f;
    full_frame[2] = 0x00; full_frame[3] = 0x00; full_frame[4] = 0x00; full_frame[5] = 0x00;
    full_frame[6] = 0x00; full_frame[7] = 0x00; full_frame[8] = 0x00; full_frame[9] = 0x64;
    memset(full_frame + 10, 'B', 100);

    consumed = ws_parse_frame(full_frame, 110, &parsed);
    free(full_frame);

    if (consumed != 110) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrong consumed: %d (expected 110)", consumed);
        FAIL(buf);
        return;
    }

    if (parsed.payload_len != 100) {
        FAIL("Wrong payload length");
        return;
    }

    if (parsed.header_len != 10) {
        FAIL("Wrong header length for 64-bit encoding");
        return;
    }

    PASS();
}

/*============================================================================
 * Control Frame Tests
 *============================================================================*/

static void test_parse_ping_frame(void) {
    TEST("ws_parse_frame PING");

    /* PING frame with "ping" payload */
    uint8_t frame[] = { 0x89, 0x04, 'p', 'i', 'n', 'g' };

    ws_frame_t parsed;
    int consumed = ws_parse_frame(frame, sizeof(frame), &parsed);

    if (consumed != 6) {
        FAIL("Wrong consumed length");
        return;
    }

    if (parsed.opcode != WS_OPCODE_PING) {
        FAIL("Wrong opcode");
        return;
    }

    if (!parsed.fin) {
        FAIL("PING must have FIN=1");
        return;
    }

    PASS();
}

static void test_parse_pong_frame(void) {
    TEST("ws_parse_frame PONG");

    /* PONG frame with "pong" payload */
    uint8_t frame[] = { 0x8a, 0x04, 'p', 'o', 'n', 'g' };

    ws_frame_t parsed;
    int consumed = ws_parse_frame(frame, sizeof(frame), &parsed);

    if (consumed != 6) {
        FAIL("Wrong consumed length");
        return;
    }

    if (parsed.opcode != WS_OPCODE_PONG) {
        FAIL("Wrong opcode");
        return;
    }

    PASS();
}

static void test_parse_close_frame(void) {
    TEST("ws_parse_frame CLOSE");

    /* CLOSE frame with code 1000 (normal) and reason "goodbye" */
    uint8_t frame[] = {
        0x88, 0x09,             /* FIN=1, opcode=close, len=9 */
        0x03, 0xe8,             /* Status code 1000 (big-endian) */
        'g', 'o', 'o', 'd', 'b', 'y', 'e'
    };

    ws_frame_t parsed;
    int consumed = ws_parse_frame(frame, sizeof(frame), &parsed);

    if (consumed != 11) {
        FAIL("Wrong consumed length");
        return;
    }

    if (parsed.opcode != WS_OPCODE_CLOSE) {
        FAIL("Wrong opcode");
        return;
    }

    if (parsed.close_code != 1000) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrong close code: %d", parsed.close_code);
        FAIL(buf);
        return;
    }

    if (strcmp(parsed.close_reason, "goodbye") != 0) {
        FAIL("Wrong close reason");
        return;
    }

    PASS();
}

static void test_parse_close_no_reason(void) {
    TEST("ws_parse_frame CLOSE no reason");

    /* CLOSE frame with only status code */
    uint8_t frame[] = { 0x88, 0x02, 0x03, 0xea };  /* Code 1002 */

    ws_frame_t parsed;
    int consumed = ws_parse_frame(frame, sizeof(frame), &parsed);

    if (consumed != 4) {
        FAIL("Wrong consumed length");
        return;
    }

    if (parsed.close_code != 1002) {
        FAIL("Wrong close code");
        return;
    }

    if (parsed.close_reason[0] != '\0') {
        FAIL("Close reason should be empty");
        return;
    }

    PASS();
}

/*============================================================================
 * Fragmentation Tests
 *============================================================================*/

static void test_parse_fragment_first(void) {
    TEST("ws_parse_frame first fragment");

    /* First fragment: FIN=0, opcode=text */
    uint8_t frame[] = { 0x01, 0x05, 'H', 'e', 'l', 'l', 'o' };

    ws_frame_t parsed;
    int consumed = ws_parse_frame(frame, sizeof(frame), &parsed);

    if (consumed != 7) {
        FAIL("Wrong consumed length");
        return;
    }

    if (parsed.fin) {
        FAIL("FIN should be false for first fragment");
        return;
    }

    if (parsed.opcode != WS_OPCODE_TEXT) {
        FAIL("First fragment should have data opcode");
        return;
    }

    PASS();
}

static void test_parse_fragment_continuation(void) {
    TEST("ws_parse_frame continuation fragment");

    /* Continuation fragment: FIN=0, opcode=0 (continuation) */
    uint8_t frame[] = { 0x00, 0x05, ' ', 'W', 'o', 'r', 'l' };

    ws_frame_t parsed;
    int consumed = ws_parse_frame(frame, sizeof(frame), &parsed);

    if (consumed != 7) {
        FAIL("Wrong consumed length");
        return;
    }

    if (parsed.fin) {
        FAIL("FIN should be false");
        return;
    }

    if (parsed.opcode != WS_OPCODE_CONTINUATION) {
        FAIL("Should be continuation opcode");
        return;
    }

    PASS();
}

static void test_parse_fragment_final(void) {
    TEST("ws_parse_frame final fragment");

    /* Final fragment: FIN=1, opcode=0 (continuation) */
    uint8_t frame[] = { 0x80, 0x02, 'd', '!' };

    ws_frame_t parsed;
    int consumed = ws_parse_frame(frame, sizeof(frame), &parsed);

    if (consumed != 4) {
        FAIL("Wrong consumed length");
        return;
    }

    if (!parsed.fin) {
        FAIL("FIN should be true for final fragment");
        return;
    }

    if (parsed.opcode != WS_OPCODE_CONTINUATION) {
        FAIL("Should be continuation opcode");
        return;
    }

    PASS();
}

/*============================================================================
 * Unmask Tests
 *============================================================================*/

static void test_unmask_payload(void) {
    TEST("ws_unmask_payload");

    uint8_t mask_key[] = { 0x37, 0xfa, 0x21, 0x3d };
    uint8_t masked[] = { 0x7f, 0x9f, 0x4d, 0x51, 0x58 };

    ws_unmask_payload(masked, 5, mask_key);

    if (memcmp(masked, "Hello", 5) != 0) {
        FAIL("Unmasking failed");
        return;
    }

    /* Unmasking is its own inverse */
    ws_unmask_payload(masked, 5, mask_key);

    if (memcmp(masked, "\x7f\x9f\x4d\x51\x58", 5) != 0) {
        FAIL("Re-masking failed");
        return;
    }

    PASS();
}

static void test_unmask_null_handling(void) {
    TEST("ws_unmask_payload NULL handling");

    uint8_t mask_key[] = { 0x01, 0x02, 0x03, 0x04 };
    uint8_t data[] = { 0x00, 0x00, 0x00, 0x00 };

    /* Should not crash */
    ws_unmask_payload(NULL, 5, mask_key);
    ws_unmask_payload(data, 4, NULL);

    PASS();
}

/*============================================================================
 * ws_is_frame Validation Tests
 *============================================================================*/

static void test_is_frame_valid(void) {
    TEST("ws_is_frame valid frames");

    /* Text frame */
    uint8_t text[] = { 0x81, 0x05 };
    if (!ws_is_frame(text, sizeof(text))) {
        FAIL("Text frame rejected");
        return;
    }

    /* Binary frame */
    uint8_t binary[] = { 0x82, 0x10 };
    if (!ws_is_frame(binary, sizeof(binary))) {
        FAIL("Binary frame rejected");
        return;
    }

    /* PING frame */
    uint8_t ping[] = { 0x89, 0x04 };
    if (!ws_is_frame(ping, sizeof(ping))) {
        FAIL("PING frame rejected");
        return;
    }

    /* CLOSE frame */
    uint8_t close[] = { 0x88, 0x02 };
    if (!ws_is_frame(close, sizeof(close))) {
        FAIL("CLOSE frame rejected");
        return;
    }

    PASS();
}

static void test_is_frame_invalid(void) {
    TEST("ws_is_frame invalid frames");

    /* Invalid opcode 0x05 (reserved) */
    uint8_t reserved[] = { 0x85, 0x05 };
    if (ws_is_frame(reserved, sizeof(reserved))) {
        FAIL("Reserved opcode should be rejected");
        return;
    }

    /* Control frame with FIN=0 (not allowed) */
    uint8_t control_nofin[] = { 0x09, 0x05 };  /* PING without FIN */
    if (ws_is_frame(control_nofin, sizeof(control_nofin))) {
        FAIL("Control frame without FIN should be rejected");
        return;
    }

    /* Control frame with length > 125 (not allowed) */
    uint8_t control_long[] = { 0x89, 0x7e };  /* PING with 16-bit length */
    if (ws_is_frame(control_long, sizeof(control_long))) {
        FAIL("Control frame with extended length should be rejected");
        return;
    }

    /* Too short */
    uint8_t tooshort[] = { 0x81 };
    if (ws_is_frame(tooshort, sizeof(tooshort))) {
        FAIL("Single byte should be rejected");
        return;
    }

    PASS();
}

/*============================================================================
 * Name Helper Tests
 *============================================================================*/

static void test_opcode_name(void) {
    TEST("ws_opcode_name");

    if (strcmp(ws_opcode_name(WS_OPCODE_TEXT), "TEXT") != 0) {
        FAIL("Wrong name for TEXT");
        return;
    }
    if (strcmp(ws_opcode_name(WS_OPCODE_BINARY), "BIN") != 0) {
        FAIL("Wrong name for BINARY");
        return;
    }
    if (strcmp(ws_opcode_name(WS_OPCODE_PING), "PING") != 0) {
        FAIL("Wrong name for PING");
        return;
    }
    if (strcmp(ws_opcode_name(WS_OPCODE_PONG), "PONG") != 0) {
        FAIL("Wrong name for PONG");
        return;
    }
    if (strcmp(ws_opcode_name(WS_OPCODE_CLOSE), "CLOSE") != 0) {
        FAIL("Wrong name for CLOSE");
        return;
    }
    if (strcmp(ws_opcode_name(WS_OPCODE_CONTINUATION), "CONT") != 0) {
        FAIL("Wrong name for CONTINUATION");
        return;
    }
    if (strcmp(ws_opcode_name(99), "UNKNOWN") != 0) {
        FAIL("Wrong name for unknown opcode");
        return;
    }

    PASS();
}

static void test_close_code_name(void) {
    TEST("ws_close_code_name");

    if (strcmp(ws_close_code_name(1000), "Normal closure") != 0) {
        FAIL("Wrong name for 1000");
        return;
    }
    if (strcmp(ws_close_code_name(1001), "Going away") != 0) {
        FAIL("Wrong name for 1001");
        return;
    }
    if (strcmp(ws_close_code_name(1002), "Protocol error") != 0) {
        FAIL("Wrong name for 1002");
        return;
    }
    if (strcmp(ws_close_code_name(9999), "Unknown") != 0) {
        FAIL("Wrong name for unknown code");
        return;
    }

    PASS();
}

/*============================================================================
 * Upgrade Detection Tests
 *============================================================================*/

static void test_is_upgrade_request(void) {
    TEST("ws_is_upgrade_request");

    /* Valid WebSocket upgrade request headers (name/value pairs) */
    const char *valid_headers[] = {
        "Upgrade", "websocket",
        "Connection", "Upgrade",
        "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version", "13"
    };

    if (!ws_is_upgrade_request(valid_headers, 8)) {
        FAIL("Valid upgrade request rejected");
        return;
    }

    /* Missing Sec-WebSocket-Key */
    const char *missing_key[] = {
        "Upgrade", "websocket",
        "Connection", "Upgrade",
        "Sec-WebSocket-Version", "13"
    };

    if (ws_is_upgrade_request(missing_key, 6)) {
        FAIL("Request without key should be rejected");
        return;
    }

    /* Missing Upgrade header */
    const char *missing_upgrade[] = {
        "Connection", "Upgrade",
        "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version", "13"
    };

    if (ws_is_upgrade_request(missing_upgrade, 6)) {
        FAIL("Request without Upgrade should be rejected");
        return;
    }

    PASS();
}

static void test_is_upgrade_response(void) {
    TEST("ws_is_upgrade_response");

    /* Valid WebSocket upgrade response headers */
    const char *valid_headers[] = {
        "Upgrade", "websocket",
        "Connection", "Upgrade",
        "Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    };

    if (!ws_is_upgrade_response(101, valid_headers, 6)) {
        FAIL("Valid upgrade response rejected");
        return;
    }

    /* Wrong status code */
    if (ws_is_upgrade_response(200, valid_headers, 6)) {
        FAIL("Response with wrong status should be rejected");
        return;
    }

    /* Missing Sec-WebSocket-Accept */
    const char *missing_accept[] = {
        "Upgrade", "websocket",
        "Connection", "Upgrade"
    };

    if (ws_is_upgrade_response(101, missing_accept, 4)) {
        FAIL("Response without Accept should be rejected");
        return;
    }

    PASS();
}

/*============================================================================
 * Edge Cases
 *============================================================================*/

static void test_parse_incomplete_frame(void) {
    TEST("ws_parse_frame incomplete data");

    /* Only 1 byte (need at least 2) */
    uint8_t one_byte[] = { 0x81 };
    ws_frame_t parsed;

    if (ws_parse_frame(one_byte, 1, &parsed) != 0) {
        FAIL("Should return 0 for 1 byte");
        return;
    }

    /* Header says len=5 but only 4 bytes of payload */
    uint8_t truncated[] = { 0x81, 0x05, 'H', 'e', 'l', 'l' };
    if (ws_parse_frame(truncated, 6, &parsed) != 0) {
        FAIL("Should return 0 for truncated payload");
        return;
    }

    /* 16-bit length encoding with only 3 bytes total */
    uint8_t short_16bit[] = { 0x81, 0x7e, 0x01 };
    if (ws_parse_frame(short_16bit, 3, &parsed) != 0) {
        FAIL("Should return 0 for incomplete 16-bit length");
        return;
    }

    PASS();
}

static void test_parse_null_handling(void) {
    TEST("ws_parse_frame NULL handling");

    ws_frame_t parsed;
    uint8_t data[] = { 0x81, 0x05 };

    /* NULL data */
    if (ws_parse_frame(NULL, 10, &parsed) != 0) {
        FAIL("NULL data should return 0");
        return;
    }

    /* NULL frame output */
    if (ws_parse_frame(data, sizeof(data), NULL) != 0) {
        FAIL("NULL frame should return 0");
        return;
    }

    PASS();
}

/*============================================================================
 * Main
 *============================================================================*/

int main(void) {
    printf("\n=== WebSocket Parser Tests (RFC 6455) ===\n\n");

    /* Frame parsing */
    test_parse_text_frame_unmasked();
    test_parse_text_frame_masked();
    test_parse_binary_frame();
    test_parse_16bit_length();
    test_parse_64bit_length();

    /* Control frames */
    test_parse_ping_frame();
    test_parse_pong_frame();
    test_parse_close_frame();
    test_parse_close_no_reason();

    /* Fragmentation */
    test_parse_fragment_first();
    test_parse_fragment_continuation();
    test_parse_fragment_final();

    /* Unmasking */
    test_unmask_payload();
    test_unmask_null_handling();

    /* Validation */
    test_is_frame_valid();
    test_is_frame_invalid();

    /* Name helpers */
    test_opcode_name();
    test_close_code_name();

    /* Upgrade detection */
    test_is_upgrade_request();
    test_is_upgrade_response();

    /* Edge cases */
    test_parse_incomplete_frame();
    test_parse_null_handling();

    printf("\n");
    if (failures == 0) {
        printf("\033[32mAll tests passed!\033[0m\n");
        return 0;
    } else {
        printf("\033[31m%d test(s) failed\033[0m\n", failures);
        return 1;
    }
}
