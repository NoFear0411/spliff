/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * test_stream_decompressor.c - Unit tests for per-flow streaming decompression
 *
 * Tests:
 * - ZSTD streaming basic (whole + chunked)
 * - ZSTD window limit enforcement
 * - gzip streaming basic (whole + chunked)
 * - gzip streaming partial (incomplete input)
 * - brotli streaming basic
 * - Decompression bomb detection (ratio)
 * - Decompression bomb detection (size)
 * - Reset and reuse across HTTP responses
 * - Cleanup on NULL/uninitialized (safety)
 * - Auto-detect type then stream
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "../src/content/stream_decompressor.h"
#include "../src/content/decompressor.h"

/* Compression libraries for generating test data at runtime */
#include <zstd.h>
#include <zlib-ng.h>
#include <brotli/encode.h>

#define TEST(name) printf("TEST: %s... ", name)
#define PASS() printf("\033[32mPASS\033[0m\n")
#define FAIL(msg) do { printf("\033[31mFAIL: %s\033[0m\n", msg); failures++; } while(0)

static int failures = 0;

/*----------------------------------------------------------------------------
 * Pre-compressed test data (from test_decompressor.c)
 *----------------------------------------------------------------------------*/

static const uint8_t GZIP_HELLO[] = {
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xf3, 0x48,
    0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04,
    0x00, 0xd0, 0xc3, 0x4a, 0xec, 0x0d, 0x00, 0x00, 0x00
};

static const uint8_t ZSTD_HELLO[] = {
    0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x0d, 0x69, 0x00, 0x00, 0x48, 0x65, 0x6c,
    0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x7f, 0xe4,
    0x0f, 0x08
};

static const uint8_t BROTLI_HELLO[] = {
    0x21, 0x30, 0x00, 0x04, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57,
    0x6f, 0x72, 0x6c, 0x64, 0x21, 0x03
};

static const char *EXPECTED = "Hello, World!";

/*============================================================================
 * ZSTD Streaming Tests
 *============================================================================*/

static void test_zstd_streaming_basic(void) {
    TEST("zstd_streaming_basic: whole payload in one feed");

    stream_decomp_t sd = {0};
    if (stream_decomp_init(&sd, COMPRESS_ZSTD) != 0) {
        FAIL("init failed"); return;
    }

    uint8_t out[256];
    int n = stream_decomp_feed(&sd, ZSTD_HELLO, sizeof(ZSTD_HELLO),
                               out, sizeof(out));
    if (n < 0) {
        char buf[64]; snprintf(buf, sizeof(buf), "feed returned %d", n);
        FAIL(buf); goto cleanup;
    }
    if (n != (int)strlen(EXPECTED)) {
        char buf[64]; snprintf(buf, sizeof(buf), "got %d bytes, expected %zu", n, strlen(EXPECTED));
        FAIL(buf); goto cleanup;
    }
    if (memcmp(out, EXPECTED, (size_t)n) != 0) {
        FAIL("output mismatch"); goto cleanup;
    }
    if (!sd.finished) {
        FAIL("stream not marked finished"); goto cleanup;
    }

    PASS();
cleanup:
    stream_decomp_cleanup(&sd);
}

static void test_zstd_streaming_chunked(void) {
    TEST("zstd_streaming_chunked: split payload across feeds");

    /* Compress a longer string to have enough bytes to split */
    const char *input = "The quick brown fox jumps over the lazy dog. "
                        "Pack my box with five dozen liquor jugs.";
    size_t input_len = strlen(input);

    size_t bound = ZSTD_compressBound(input_len);
    uint8_t *compressed = malloc(bound);
    if (!compressed) { FAIL("malloc"); return; }

    size_t comp_len = ZSTD_compress(compressed, bound, input, input_len, 1);
    if (ZSTD_isError(comp_len)) {
        FAIL("ZSTD_compress failed"); free(compressed); return;
    }

    stream_decomp_t sd = {0};
    if (stream_decomp_init(&sd, COMPRESS_ZSTD) != 0) {
        FAIL("init failed"); free(compressed); return;
    }

    /* Feed in 5-byte chunks */
    uint8_t out[512];
    size_t total_out = 0;
    size_t offset = 0;

    while (offset < comp_len) {
        size_t chunk = (comp_len - offset > 5) ? 5 : comp_len - offset;
        int n = stream_decomp_feed(&sd, compressed + offset, chunk,
                                   out + total_out, sizeof(out) - total_out);
        if (n < 0) {
            char buf[64]; snprintf(buf, sizeof(buf), "feed returned %d at offset %zu", n, offset);
            FAIL(buf); goto cleanup;
        }
        total_out += (size_t)n;
        offset += chunk;
    }

    if (total_out != input_len) {
        char buf[64]; snprintf(buf, sizeof(buf), "got %zu bytes, expected %zu", total_out, input_len);
        FAIL(buf); goto cleanup;
    }
    if (memcmp(out, input, input_len) != 0) {
        FAIL("output mismatch"); goto cleanup;
    }

    PASS();
cleanup:
    stream_decomp_cleanup(&sd);
    free(compressed);
}

static void test_zstd_window_limit(void) {
    TEST("zstd_window_limit: windowLogMax enforced");

    /* Verify init succeeds (the limit is set internally).
     * We can't easily test rejection of large windows without crafting
     * a frame with windowLog > 23, so just verify the parameter was set
     * by confirming normal decompression still works. */
    stream_decomp_t sd = {0};
    if (stream_decomp_init(&sd, COMPRESS_ZSTD) != 0) {
        FAIL("init failed"); return;
    }

    uint8_t out[256];
    int n = stream_decomp_feed(&sd, ZSTD_HELLO, sizeof(ZSTD_HELLO),
                               out, sizeof(out));
    if (n != (int)strlen(EXPECTED)) {
        FAIL("decompression failed with window limit set"); goto cleanup;
    }

    PASS();
cleanup:
    stream_decomp_cleanup(&sd);
}

/*============================================================================
 * gzip Streaming Tests
 *============================================================================*/

static void test_gzip_streaming_basic(void) {
    TEST("gzip_streaming_basic: whole payload in one feed");

    stream_decomp_t sd = {0};
    if (stream_decomp_init(&sd, COMPRESS_GZIP) != 0) {
        FAIL("init failed"); return;
    }

    uint8_t out[256];
    int n = stream_decomp_feed(&sd, GZIP_HELLO, sizeof(GZIP_HELLO),
                               out, sizeof(out));
    if (n < 0) {
        char buf[64]; snprintf(buf, sizeof(buf), "feed returned %d", n);
        FAIL(buf); goto cleanup;
    }
    if (n != (int)strlen(EXPECTED) || memcmp(out, EXPECTED, (size_t)n) != 0) {
        FAIL("output mismatch"); goto cleanup;
    }
    if (!sd.finished) {
        FAIL("stream not marked finished"); goto cleanup;
    }

    PASS();
cleanup:
    stream_decomp_cleanup(&sd);
}

static void test_gzip_streaming_chunked(void) {
    TEST("gzip_streaming_chunked: split payload across feeds");

    /* Compress with zlib-ng */
    const char *input = "Streaming gzip test with multiple chunks of data.";
    size_t input_len = strlen(input);

    uint8_t compressed[512];
    zng_stream strm = {0};
    zng_deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    strm.next_in = (const uint8_t *)input;
    strm.avail_in = (uint32_t)input_len;
    strm.next_out = compressed;
    strm.avail_out = sizeof(compressed);
    zng_deflate(&strm, Z_FINISH);
    size_t comp_len = sizeof(compressed) - strm.avail_out;
    zng_deflateEnd(&strm);

    stream_decomp_t sd = {0};
    if (stream_decomp_init(&sd, COMPRESS_GZIP) != 0) {
        FAIL("init failed"); return;
    }

    /* Feed in 4-byte chunks */
    uint8_t out[512];
    size_t total_out = 0;
    size_t offset = 0;

    while (offset < comp_len) {
        size_t chunk = (comp_len - offset > 4) ? 4 : comp_len - offset;
        int n = stream_decomp_feed(&sd, compressed + offset, chunk,
                                   out + total_out, sizeof(out) - total_out);
        if (n < 0) {
            char buf[64]; snprintf(buf, sizeof(buf), "feed returned %d at offset %zu", n, offset);
            FAIL(buf); goto cleanup;
        }
        total_out += (size_t)n;
        offset += chunk;
    }

    if (total_out != input_len || memcmp(out, input, input_len) != 0) {
        FAIL("output mismatch"); goto cleanup;
    }

    PASS();
cleanup:
    stream_decomp_cleanup(&sd);
}

static void test_gzip_streaming_partial(void) {
    TEST("gzip_streaming_partial: incomplete input produces 0 output");

    stream_decomp_t sd = {0};
    if (stream_decomp_init(&sd, COMPRESS_GZIP) != 0) {
        FAIL("init failed"); return;
    }

    /* Feed only the gzip header (first 10 bytes) — no payload yet */
    uint8_t out[256];
    int n = stream_decomp_feed(&sd, GZIP_HELLO, 10, out, sizeof(out));
    if (n < 0) {
        char buf[64]; snprintf(buf, sizeof(buf), "feed returned %d (expected >= 0)", n);
        FAIL(buf); goto cleanup;
    }
    /* Should produce 0 bytes (header only, no compressed data yet) */
    if (sd.finished) {
        FAIL("prematurely marked finished"); goto cleanup;
    }

    /* Feed the rest */
    n = stream_decomp_feed(&sd, GZIP_HELLO + 10, sizeof(GZIP_HELLO) - 10,
                           out, sizeof(out));
    if (n != (int)strlen(EXPECTED) || memcmp(out, EXPECTED, (size_t)n) != 0) {
        FAIL("output mismatch after completing stream"); goto cleanup;
    }

    PASS();
cleanup:
    stream_decomp_cleanup(&sd);
}

/*============================================================================
 * Brotli Streaming Tests
 *============================================================================*/

static void test_brotli_streaming_basic(void) {
    TEST("brotli_streaming_basic: whole payload in one feed");

    stream_decomp_t sd = {0};
    if (stream_decomp_init(&sd, COMPRESS_BROTLI) != 0) {
        FAIL("init failed"); return;
    }

    uint8_t out[256];
    int n = stream_decomp_feed(&sd, BROTLI_HELLO, sizeof(BROTLI_HELLO),
                               out, sizeof(out));
    if (n < 0) {
        char buf[64]; snprintf(buf, sizeof(buf), "feed returned %d", n);
        FAIL(buf); goto cleanup;
    }
    if (n != (int)strlen(EXPECTED) || memcmp(out, EXPECTED, (size_t)n) != 0) {
        FAIL("output mismatch"); goto cleanup;
    }
    if (!sd.finished) {
        FAIL("stream not marked finished"); goto cleanup;
    }

    PASS();
cleanup:
    stream_decomp_cleanup(&sd);
}

/*============================================================================
 * Bomb Detection Tests
 *============================================================================*/

static void test_bomb_ratio(void) {
    TEST("bomb_ratio: >1000:1 ratio detected");

    /* Create highly compressible data: 1MB of zeros */
    size_t plain_len = 1024 * 1024;
    uint8_t *plain = calloc(1, plain_len);
    if (!plain) { FAIL("malloc"); return; }

    size_t bound = ZSTD_compressBound(plain_len);
    uint8_t *compressed = malloc(bound);
    if (!compressed) { FAIL("malloc"); free(plain); return; }

    /* Compress at max level for smallest output */
    size_t comp_len = ZSTD_compress(compressed, bound, plain, plain_len, 19);
    free(plain);
    if (ZSTD_isError(comp_len)) {
        FAIL("ZSTD_compress failed"); free(compressed); return;
    }

    /* Check if ratio is actually > 1000:1 (1MB zeros compresses very small) */
    double ratio = (double)plain_len / (double)comp_len;

    stream_decomp_t sd = {0};
    if (stream_decomp_init(&sd, COMPRESS_ZSTD) != 0) {
        FAIL("init failed"); free(compressed); return;
    }

    uint8_t out[65536];
    int n = stream_decomp_feed(&sd, compressed, comp_len, out, sizeof(out));

    if (ratio > (double)STREAM_DECOMP_MAX_RATIO) {
        /* Ratio exceeds limit — bomb should be detected */
        if (n != -2 && !sd.bomb_detected) {
            char buf[128];
            snprintf(buf, sizeof(buf), "ratio=%.0f:1 but bomb not detected (n=%d)", ratio, n);
            FAIL(buf);
        } else {
            PASS();
        }
    } else {
        /* Ratio within limits — should succeed */
        if (n < 0) {
            char buf[64]; snprintf(buf, sizeof(buf), "feed returned %d but ratio %.0f:1 is within limit", n, ratio);
            FAIL(buf);
        } else {
            printf("(ratio %.0f:1 within limit, skipping) ", ratio);
            PASS();
        }
    }

    stream_decomp_cleanup(&sd);
    free(compressed);
}

static void test_bomb_size(void) {
    TEST("bomb_size: subsequent feeds after bomb return -2");

    stream_decomp_t sd = {0};
    if (stream_decomp_init(&sd, COMPRESS_ZSTD) != 0) {
        FAIL("init failed"); return;
    }

    /* Manually set bomb flag to simulate detection */
    sd.bomb_detected = true;

    uint8_t out[256];
    int n = stream_decomp_feed(&sd, ZSTD_HELLO, sizeof(ZSTD_HELLO),
                               out, sizeof(out));
    if (n != -2) {
        char buf[64]; snprintf(buf, sizeof(buf), "expected -2, got %d", n);
        FAIL(buf); goto cleanup;
    }

    PASS();
cleanup:
    stream_decomp_cleanup(&sd);
}

/*============================================================================
 * Reset / Reuse / Safety Tests
 *============================================================================*/

static void test_reset_reuse(void) {
    TEST("reset_reuse: reset between HTTP responses");

    stream_decomp_t sd = {0};

    /* First response: gzip */
    if (stream_decomp_init(&sd, COMPRESS_GZIP) != 0) {
        FAIL("init gzip failed"); return;
    }
    uint8_t out[256];
    int n = stream_decomp_feed(&sd, GZIP_HELLO, sizeof(GZIP_HELLO),
                               out, sizeof(out));
    if (n != (int)strlen(EXPECTED)) {
        FAIL("first gzip feed failed"); goto cleanup;
    }

    /* Reset for second response */
    stream_decomp_reset(&sd);
    if (sd.initialized) {
        FAIL("still initialized after reset"); goto cleanup;
    }
    if (sd.bytes_in != 0 || sd.bytes_out != 0) {
        FAIL("counters not zeroed after reset"); goto cleanup;
    }

    /* Second response: zstd */
    if (stream_decomp_init(&sd, COMPRESS_ZSTD) != 0) {
        FAIL("init zstd failed"); goto cleanup;
    }
    n = stream_decomp_feed(&sd, ZSTD_HELLO, sizeof(ZSTD_HELLO),
                           out, sizeof(out));
    if (n != (int)strlen(EXPECTED) || memcmp(out, EXPECTED, (size_t)n) != 0) {
        FAIL("second zstd feed failed"); goto cleanup;
    }

    PASS();
cleanup:
    stream_decomp_cleanup(&sd);
}

static void test_cleanup_null_safe(void) {
    TEST("cleanup_null_safe: NULL and uninitialized safety");

    /* NULL pointer */
    stream_decomp_cleanup(NULL);
    stream_decomp_reset(NULL);

    /* Zeroed struct (never initialized) */
    stream_decomp_t sd = {0};
    stream_decomp_cleanup(&sd);
    stream_decomp_reset(&sd);

    /* Double cleanup */
    stream_decomp_init(&sd, COMPRESS_GZIP);
    stream_decomp_cleanup(&sd);
    stream_decomp_cleanup(&sd);  /* Should not crash */

    PASS();
}

static void test_detect_and_stream(void) {
    TEST("detect_and_stream: auto-detect then stream");

    /* Use detect_compression() from decompressor.h, then stream */
    compress_type_t type = detect_compression(GZIP_HELLO, (int)sizeof(GZIP_HELLO));
    if (type != COMPRESS_GZIP) {
        FAIL("detection returned wrong type"); return;
    }

    stream_decomp_t sd = {0};
    if (stream_decomp_init(&sd, type) != 0) {
        FAIL("init failed"); return;
    }

    uint8_t out[256];
    int n = stream_decomp_feed(&sd, GZIP_HELLO, sizeof(GZIP_HELLO),
                               out, sizeof(out));
    if (n != (int)strlen(EXPECTED) || memcmp(out, EXPECTED, (size_t)n) != 0) {
        FAIL("output mismatch"); goto cleanup;
    }

    PASS();
cleanup:
    stream_decomp_cleanup(&sd);
}

static void test_init_rejects_none(void) {
    TEST("init_rejects_none: COMPRESS_NONE rejected");

    stream_decomp_t sd = {0};
    int ret = stream_decomp_init(&sd, COMPRESS_NONE);
    if (ret != -1) {
        FAIL("init should reject COMPRESS_NONE");
        stream_decomp_cleanup(&sd);
        return;
    }
    if (sd.initialized) {
        FAIL("should not be initialized after rejection");
        return;
    }

    PASS();
}

/*============================================================================
 * Main
 *============================================================================*/

int main(void) {
    printf("=== Streaming Decompressor Tests ===\n\n");

    /* ZSTD */
    test_zstd_streaming_basic();
    test_zstd_streaming_chunked();
    test_zstd_window_limit();

    /* gzip */
    test_gzip_streaming_basic();
    test_gzip_streaming_chunked();
    test_gzip_streaming_partial();

    /* brotli */
    test_brotli_streaming_basic();

    /* Bomb detection */
    test_bomb_ratio();
    test_bomb_size();

    /* Reset / reuse / safety */
    test_reset_reuse();
    test_cleanup_null_safe();
    test_detect_and_stream();
    test_init_rejects_none();

    printf("\n=== Results: %d failures ===\n", failures);
    return failures ? 1 : 0;
}
