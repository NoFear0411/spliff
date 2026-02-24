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
 * test_decompressor.c - Unit tests for HTTP body decompression
 *
 * Tests cover:
 * - Compression type detection from magic bytes
 * - gzip/deflate decompression
 * - zstd decompression
 * - brotli decompression
 * - decompress_body() unified API
 * - Edge cases and error handling
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "../src/content/decompressor.h"

#define TEST(name) printf("TEST: %s... ", name)
#define PASS() printf("\033[32mPASS\033[0m\n")
#define FAIL(msg) do { printf("\033[31mFAIL: %s\033[0m\n", msg); failures++; } while(0)

static int failures = 0;

/*----------------------------------------------------------------------------
 * Test Data: Pre-compressed payloads
 *
 * These are actual compressed representations of "Hello, World!" (or similar)
 * created with standard compression tools.
 *----------------------------------------------------------------------------*/

/* "Hello, World!" gzip-compressed (gzip -cn)
 * Generated with: printf 'Hello, World!' > hello.txt && gzip -cn hello.txt | xxd -i
 */
static const uint8_t GZIP_HELLO[] = {
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xf3, 0x48,
    0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04,
    0x00, 0xd0, 0xc3, 0x4a, 0xec, 0x0d, 0x00, 0x00, 0x00
};
static const size_t GZIP_HELLO_LEN = sizeof(GZIP_HELLO);
static const char *GZIP_HELLO_EXPECTED = "Hello, World!";

/* "Hello, World!" zstd-compressed
 * Generated with: printf 'Hello, World!' > hello.txt && zstd -c hello.txt | xxd -i
 */
static const uint8_t ZSTD_HELLO[] = {
    0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x0d, 0x69, 0x00, 0x00, 0x48, 0x65, 0x6c,
    0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x7f, 0xe4,
    0x0f, 0x08
};
static const size_t ZSTD_HELLO_LEN = sizeof(ZSTD_HELLO);

/* "Hello, World!" brotli-compressed
 * Generated with: printf 'Hello, World!' > hello.txt && brotli -c hello.txt | xxd -i
 */
static const uint8_t BROTLI_HELLO[] = {
    0x21, 0x30, 0x00, 0x04, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57,
    0x6f, 0x72, 0x6c, 0x64, 0x21, 0x03
};
static const size_t BROTLI_HELLO_LEN = sizeof(BROTLI_HELLO);

/* Raw deflate (zlib) header: 78 9c
 * Generated with: python3 -c "import zlib;open('hello.zlib','wb').write(zlib.compress(b'Hello, World!'))" && xxd -i hello.zlib
 */
static const uint8_t DEFLATE_HELLO[] = {
    0x78, 0x9c, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08, 0xcf, 0x2f,
    0xca, 0x49, 0x51, 0x04, 0x00, 0x1f, 0x9e, 0x04, 0x6a
};
static const size_t DEFLATE_HELLO_LEN = sizeof(DEFLATE_HELLO);

/*----------------------------------------------------------------------------
 * Compression Detection Tests
 *----------------------------------------------------------------------------*/

static void test_detect_compression_gzip(void) {
    TEST("detect_compression gzip");

    compress_type_t type = detect_compression(GZIP_HELLO, (int)GZIP_HELLO_LEN);
    if (type != COMPRESS_GZIP) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Expected COMPRESS_GZIP, got %d", type);
        FAIL(buf);
        return;
    }

    /* Minimal gzip header (just magic bytes) */
    uint8_t minimal[] = { 0x1f, 0x8b };
    type = detect_compression(minimal, 2);
    if (type != COMPRESS_GZIP) {
        FAIL("Failed to detect minimal gzip header");
        return;
    }

    PASS();
}

static void test_detect_compression_zstd(void) {
    TEST("detect_compression zstd");

    compress_type_t type = detect_compression(ZSTD_HELLO, (int)ZSTD_HELLO_LEN);
    if (type != COMPRESS_ZSTD) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Expected COMPRESS_ZSTD, got %d", type);
        FAIL(buf);
        return;
    }

    /* Zstd magic bytes */
    uint8_t magic[] = { 0x28, 0xb5, 0x2f, 0xfd };
    type = detect_compression(magic, 4);
    if (type != COMPRESS_ZSTD) {
        FAIL("Failed to detect zstd magic");
        return;
    }

    PASS();
}

static void test_detect_compression_deflate(void) {
    TEST("detect_compression deflate");

    compress_type_t type = detect_compression(DEFLATE_HELLO, (int)DEFLATE_HELLO_LEN);
    if (type != COMPRESS_DEFLATE) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Expected COMPRESS_DEFLATE, got %d", type);
        FAIL(buf);
        return;
    }

    /* Various deflate headers */
    uint8_t deflate_9c[] = { 0x78, 0x9c }; /* default compression */
    uint8_t deflate_da[] = { 0x78, 0xda }; /* best compression */
    uint8_t deflate_01[] = { 0x78, 0x01 }; /* fast compression */
    uint8_t deflate_5e[] = { 0x78, 0x5e }; /* level 1-5 */

    if (detect_compression(deflate_9c, 2) != COMPRESS_DEFLATE ||
        detect_compression(deflate_da, 2) != COMPRESS_DEFLATE ||
        detect_compression(deflate_01, 2) != COMPRESS_DEFLATE ||
        detect_compression(deflate_5e, 2) != COMPRESS_DEFLATE) {
        FAIL("Failed to detect deflate variants");
        return;
    }

    PASS();
}

static void test_detect_compression_none(void) {
    TEST("detect_compression none");

    /* Plain text */
    const char *text = "Hello, World!";
    compress_type_t type = detect_compression((const uint8_t *)text, (int)strlen(text));
    if (type != COMPRESS_NONE) {
        FAIL("Plain text detected as compressed");
        return;
    }

    /* JSON */
    const char *json = "{\"key\": \"value\"}";
    type = detect_compression((const uint8_t *)json, (int)strlen(json));
    if (type != COMPRESS_NONE) {
        FAIL("JSON detected as compressed");
        return;
    }

    /* HTTP response */
    const char *http = "HTTP/1.1 200 OK\r\n";
    type = detect_compression((const uint8_t *)http, (int)strlen(http));
    if (type != COMPRESS_NONE) {
        FAIL("HTTP detected as compressed");
        return;
    }

    PASS();
}

static void test_detect_compression_edge_cases(void) {
    TEST("detect_compression edge cases");

    /* Empty data */
    compress_type_t type = detect_compression(NULL, 0);
    if (type != COMPRESS_NONE) {
        FAIL("NULL data should return COMPRESS_NONE");
        return;
    }

    /* Single byte (too short for any magic) */
    uint8_t single = 0x1f;
    type = detect_compression(&single, 1);
    if (type != COMPRESS_NONE) {
        FAIL("Single byte should return COMPRESS_NONE");
        return;
    }

    /* Partial zstd magic (only 3 bytes) */
    uint8_t partial_zstd[] = { 0x28, 0xb5, 0x2f };
    type = detect_compression(partial_zstd, 3);
    if (type == COMPRESS_ZSTD) {
        FAIL("Partial zstd magic incorrectly detected");
        return;
    }

    PASS();
}

/*----------------------------------------------------------------------------
 * Decompression Tests
 *----------------------------------------------------------------------------*/

static void test_decompress_gzip(void) {
    TEST("decompress_gzip");

    uint8_t out[256];
    int result = decompress_gzip(GZIP_HELLO, (int)GZIP_HELLO_LEN, out, sizeof(out));

    if (result < 0) {
        FAIL("decompress_gzip returned error");
        return;
    }

    if (result != 13) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrong output length: %d (expected 13)", result);
        FAIL(buf);
        return;
    }

    out[result] = '\0';
    if (strcmp((char *)out, GZIP_HELLO_EXPECTED) != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "Wrong output: '%.64s'", out);
        FAIL(buf);
        return;
    }

    PASS();
}

static void test_decompress_deflate(void) {
    TEST("decompress_gzip (deflate)");

    uint8_t out[256];
    /* decompress_gzip handles both gzip and deflate via auto-detect */
    int result = decompress_gzip(DEFLATE_HELLO, (int)DEFLATE_HELLO_LEN, out, sizeof(out));

    if (result < 0) {
        FAIL("decompress_gzip returned error for deflate data");
        return;
    }

    if (result != 13) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrong output length: %d (expected 13)", result);
        FAIL(buf);
        return;
    }

    out[result] = '\0';
    if (strcmp((char *)out, GZIP_HELLO_EXPECTED) != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "Wrong output: '%.64s'", out);
        FAIL(buf);
        return;
    }

    PASS();
}

static void test_decompress_zstd(void) {
    TEST("decompress_zstd");

    if (!have_zstd_support()) {
        printf("\033[33mSKIP (no zstd support)\033[0m\n");
        return;
    }

    uint8_t out[256];
    int result = decompress_zstd(ZSTD_HELLO, (int)ZSTD_HELLO_LEN, out, sizeof(out));

    if (result < 0) {
        FAIL("decompress_zstd returned error");
        return;
    }

    if (result != 13) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrong output length: %d (expected 13)", result);
        FAIL(buf);
        return;
    }

    out[result] = '\0';
    if (strcmp((char *)out, GZIP_HELLO_EXPECTED) != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "Wrong output: '%.64s'", out);
        FAIL(buf);
        return;
    }

    PASS();
}

static void test_decompress_brotli(void) {
    TEST("decompress_brotli");

    if (!have_brotli_support()) {
        printf("\033[33mSKIP (no brotli support)\033[0m\n");
        return;
    }

    uint8_t out[256];
    int result = decompress_brotli(BROTLI_HELLO, (int)BROTLI_HELLO_LEN, out, sizeof(out));

    if (result < 0) {
        FAIL("decompress_brotli returned error");
        return;
    }

    if (result != 13) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrong output length: %d (expected 13)", result);
        FAIL(buf);
        return;
    }

    out[result] = '\0';
    if (strcmp((char *)out, GZIP_HELLO_EXPECTED) != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "Wrong output: '%.64s'", out);
        FAIL(buf);
        return;
    }

    PASS();
}

/*----------------------------------------------------------------------------
 * decompress_body() Unified API Tests
 *----------------------------------------------------------------------------*/

static void test_decompress_body_gzip(void) {
    TEST("decompress_body gzip encoding");

    uint8_t out[256];
    int result = decompress_body(GZIP_HELLO, (int)GZIP_HELLO_LEN, "gzip", out, sizeof(out));

    if (result < 0) {
        FAIL("decompress_body returned error");
        return;
    }

    if (result != 13) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrong output length: %d", result);
        FAIL(buf);
        return;
    }

    PASS();
}

static void test_decompress_body_deflate(void) {
    TEST("decompress_body deflate encoding");

    uint8_t out[256];
    int result = decompress_body(DEFLATE_HELLO, (int)DEFLATE_HELLO_LEN, "deflate", out, sizeof(out));

    if (result < 0) {
        FAIL("decompress_body returned error");
        return;
    }

    if (result != 13) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrong output length: %d", result);
        FAIL(buf);
        return;
    }

    PASS();
}

static void test_decompress_body_zstd(void) {
    TEST("decompress_body zstd encoding");

    if (!have_zstd_support()) {
        printf("\033[33mSKIP (no zstd support)\033[0m\n");
        return;
    }

    uint8_t out[256];
    int result = decompress_body(ZSTD_HELLO, (int)ZSTD_HELLO_LEN, "zstd", out, sizeof(out));

    if (result < 0) {
        FAIL("decompress_body returned error");
        return;
    }

    if (result != 13) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrong output length: %d", result);
        FAIL(buf);
        return;
    }

    PASS();
}

static void test_decompress_body_brotli(void) {
    TEST("decompress_body br encoding");

    if (!have_brotli_support()) {
        printf("\033[33mSKIP (no brotli support)\033[0m\n");
        return;
    }

    uint8_t out[256];
    int result = decompress_body(BROTLI_HELLO, (int)BROTLI_HELLO_LEN, "br", out, sizeof(out));

    if (result < 0) {
        FAIL("decompress_body returned error");
        return;
    }

    if (result != 13) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Wrong output length: %d", result);
        FAIL(buf);
        return;
    }

    PASS();
}

static void test_decompress_body_auto_detect(void) {
    TEST("decompress_body auto-detect");

    uint8_t out[256];

    /* No encoding header, but data has gzip magic */
    int result = decompress_body(GZIP_HELLO, (int)GZIP_HELLO_LEN, NULL, out, sizeof(out));
    if (result != 13) {
        FAIL("Failed to auto-detect gzip");
        return;
    }

    /* No encoding header, but data has zstd magic */
    if (have_zstd_support()) {
        result = decompress_body(ZSTD_HELLO, (int)ZSTD_HELLO_LEN, "", out, sizeof(out));
        if (result != 13) {
            FAIL("Failed to auto-detect zstd");
            return;
        }
    }

    PASS();
}

static void test_decompress_body_no_compression(void) {
    TEST("decompress_body no compression needed");

    uint8_t out[256];
    const char *plain = "Hello, World!";

    /* Plain text with no encoding header should return -1 (no decompression) */
    int result = decompress_body((const uint8_t *)plain, (int)strlen(plain), NULL, out, sizeof(out));
    if (result > 0) {
        FAIL("Plain text should not be decompressed");
        return;
    }

    /* Unknown encoding should return -1 */
    result = decompress_body((const uint8_t *)plain, (int)strlen(plain), "identity", out, sizeof(out));
    if (result > 0) {
        FAIL("Identity encoding should not decompress");
        return;
    }

    PASS();
}

static void test_decompress_body_case_insensitive(void) {
    TEST("decompress_body case insensitive");

    uint8_t out[256];

    /* Mixed case encoding */
    int result = decompress_body(GZIP_HELLO, (int)GZIP_HELLO_LEN, "GZIP", out, sizeof(out));
    if (result != 13) {
        FAIL("Failed with uppercase GZIP");
        return;
    }

    result = decompress_body(GZIP_HELLO, (int)GZIP_HELLO_LEN, "GzIp", out, sizeof(out));
    if (result != 13) {
        FAIL("Failed with mixed case GzIp");
        return;
    }

    PASS();
}

/*----------------------------------------------------------------------------
 * Error Handling Tests
 *----------------------------------------------------------------------------*/

static void test_decompress_buffer_too_small(void) {
    TEST("decompress buffer too small");

    uint8_t out[5]; /* Too small for "Hello, World!" */
    int result = decompress_gzip(GZIP_HELLO, (int)GZIP_HELLO_LEN, out, sizeof(out));

    /* Should return partial data or error */
    if (result == 13) {
        FAIL("Should fail with buffer too small");
        return;
    }

    PASS();
}

static void test_decompress_invalid_data(void) {
    TEST("decompress invalid data");

    uint8_t out[256];

    /* Invalid gzip (wrong magic) */
    uint8_t bad_gzip[] = { 0x1f, 0x8b, 0xff, 0xff, 0xff };
    int result = decompress_gzip(bad_gzip, sizeof(bad_gzip), out, sizeof(out));
    if (result > 0) {
        FAIL("Should fail on invalid gzip");
        return;
    }

    /* Invalid zstd (right magic, wrong data) */
    if (have_zstd_support()) {
        uint8_t bad_zstd[] = { 0x28, 0xb5, 0x2f, 0xfd, 0xff, 0xff };
        result = decompress_zstd(bad_zstd, sizeof(bad_zstd), out, sizeof(out));
        if (result > 0) {
            FAIL("Should fail on invalid zstd");
            return;
        }
    }

    PASS();
}

/*----------------------------------------------------------------------------
 * Compression Type Name Tests
 *----------------------------------------------------------------------------*/

static void test_compress_type_name(void) {
    TEST("compress_type_name");

    if (strcmp(compress_type_name(COMPRESS_GZIP), "gzip") != 0) {
        FAIL("Wrong name for COMPRESS_GZIP");
        return;
    }

    if (strcmp(compress_type_name(COMPRESS_DEFLATE), "deflate") != 0) {
        FAIL("Wrong name for COMPRESS_DEFLATE");
        return;
    }

    if (strcmp(compress_type_name(COMPRESS_ZSTD), "zstd") != 0) {
        FAIL("Wrong name for COMPRESS_ZSTD");
        return;
    }

    if (strcmp(compress_type_name(COMPRESS_BROTLI), "brotli") != 0) {
        FAIL("Wrong name for COMPRESS_BROTLI");
        return;
    }

    if (compress_type_name(COMPRESS_NONE) != NULL) {
        FAIL("COMPRESS_NONE should return NULL");
        return;
    }

    PASS();
}

/*----------------------------------------------------------------------------
 * Support Availability Tests
 *----------------------------------------------------------------------------*/

static void test_support_availability(void) {
    TEST("compression support availability");

    /* These should always succeed (just return true/false) */
    bool zstd = have_zstd_support();
    bool brotli = have_brotli_support();

    printf("(zstd=%s, brotli=%s) ",
           zstd ? "yes" : "no",
           brotli ? "yes" : "no");

    PASS();
}

/*----------------------------------------------------------------------------
 * Init/Cleanup Tests
 *----------------------------------------------------------------------------*/

static void test_init_cleanup(void) {
    TEST("decompressor_init/cleanup");

    /* Should always succeed */
    int result = decompressor_init();
    if (result != 0) {
        FAIL("decompressor_init failed");
        return;
    }

    /* Cleanup should not crash */
    decompressor_cleanup();

    /* Multiple init/cleanup cycles should work */
    decompressor_init();
    decompressor_init();
    decompressor_cleanup();
    decompressor_cleanup();

    PASS();
}

/*----------------------------------------------------------------------------
 * Main
 *----------------------------------------------------------------------------*/

int main(void) {
    printf("\n=== Decompressor Tests ===\n\n");

    decompressor_init();

    /* Compression detection */
    test_detect_compression_gzip();
    test_detect_compression_zstd();
    test_detect_compression_deflate();
    test_detect_compression_none();
    test_detect_compression_edge_cases();

    /* Individual decompressors */
    test_decompress_gzip();
    test_decompress_deflate();
    test_decompress_zstd();
    test_decompress_brotli();

    /* Unified API */
    test_decompress_body_gzip();
    test_decompress_body_deflate();
    test_decompress_body_zstd();
    test_decompress_body_brotli();
    test_decompress_body_auto_detect();
    test_decompress_body_no_compression();
    test_decompress_body_case_insensitive();

    /* Error handling */
    test_decompress_buffer_too_small();
    test_decompress_invalid_data();

    /* Utility functions */
    test_compress_type_name();
    test_support_availability();
    test_init_cleanup();

    decompressor_cleanup();

    printf("\n");
    if (failures == 0) {
        printf("\033[32mAll tests passed!\033[0m\n");
        return 0;
    } else {
        printf("\033[31m%d test(s) failed\033[0m\n", failures);
        return 1;
    }
}
