/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * test_safe_str.c - Unit tests for memory-safe string operations
 *
 * Tests all functions in safe_str.h for:
 * - Normal operation
 * - Edge cases (NULL, zero-length, exact fit)
 * - Truncation detection
 * - Security-critical behavior
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/util/safe_str.h"

#define TEST(name) printf("TEST: %s... ", name)
#define PASS() printf("\033[32mPASS\033[0m\n")
#define FAIL(msg) do { printf("\033[31mFAIL: %s\033[0m\n", msg); failures++; } while(0)

static int failures = 0;

/*============================================================================
 * safe_strcpy tests
 *============================================================================*/

static void test_safe_strcpy_normal(void) {
    TEST("safe_strcpy normal copy");

    char dst[32];
    size_t len = safe_strcpy(dst, sizeof(dst), "hello");

    if (len != 5) {
        FAIL("wrong return length");
        return;
    }
    if (strcmp(dst, "hello") != 0) {
        FAIL("wrong content");
        return;
    }
    PASS();
}

static void test_safe_strcpy_exact_fit(void) {
    TEST("safe_strcpy exact fit");

    char dst[6];  /* "hello" + null = 6 bytes */
    size_t len = safe_strcpy(dst, sizeof(dst), "hello");

    if (len != 5) {
        FAIL("wrong return length");
        return;
    }
    if (strcmp(dst, "hello") != 0) {
        FAIL("wrong content");
        return;
    }
    PASS();
}

static void test_safe_strcpy_truncation(void) {
    TEST("safe_strcpy truncation");

    char dst[6];
    size_t len = safe_strcpy(dst, sizeof(dst), "hello world");

    /* Should truncate to "hello" (5 chars + null) */
    if (len != 5) {
        FAIL("wrong return length on truncation");
        return;
    }
    if (strcmp(dst, "hello") != 0) {
        FAIL("wrong truncated content");
        return;
    }
    /* Verify null termination */
    if (dst[5] != '\0') {
        FAIL("not null terminated");
        return;
    }
    PASS();
}

static void test_safe_strcpy_empty_src(void) {
    TEST("safe_strcpy empty source");

    char dst[32] = "garbage";
    size_t len = safe_strcpy(dst, sizeof(dst), "");

    if (len != 0) {
        FAIL("wrong return length for empty");
        return;
    }
    if (dst[0] != '\0') {
        FAIL("not empty after copy");
        return;
    }
    PASS();
}

static void test_safe_strcpy_null_src(void) {
    TEST("safe_strcpy NULL source");

    char dst[32] = "garbage";
    size_t len = safe_strcpy(dst, sizeof(dst), NULL);

    if (len != 0) {
        FAIL("wrong return for NULL src");
        return;
    }
    if (dst[0] != '\0') {
        FAIL("dst not cleared on NULL src");
        return;
    }
    PASS();
}

static void test_safe_strcpy_null_dst(void) {
    TEST("safe_strcpy NULL destination");

    size_t len = safe_strcpy(NULL, 32, "hello");

    if (len != 0) {
        FAIL("wrong return for NULL dst");
        return;
    }
    PASS();
}

static void test_safe_strcpy_zero_size(void) {
    TEST("safe_strcpy zero size");

    char dst[32] = "unchanged";
    size_t len = safe_strcpy(dst, 0, "hello");

    if (len != 0) {
        FAIL("wrong return for zero size");
        return;
    }
    /* dst should be unchanged */
    if (strcmp(dst, "unchanged") != 0) {
        FAIL("dst modified with zero size");
        return;
    }
    PASS();
}

static void test_safe_strcpy_size_one(void) {
    TEST("safe_strcpy size 1 (null only)");

    char dst[1];
    size_t len = safe_strcpy(dst, sizeof(dst), "hello");

    if (len != 0) {
        FAIL("wrong return for size 1");
        return;
    }
    if (dst[0] != '\0') {
        FAIL("not null terminated with size 1");
        return;
    }
    PASS();
}

/*============================================================================
 * safe_strncpy tests
 *============================================================================*/

static void test_safe_strncpy_normal(void) {
    TEST("safe_strncpy normal copy");

    char dst[32];
    size_t len = safe_strncpy(dst, sizeof(dst), "hello world", 5);

    if (len != 5) {
        FAIL("wrong return length");
        return;
    }
    if (strcmp(dst, "hello") != 0) {
        FAIL("wrong content");
        return;
    }
    PASS();
}

static void test_safe_strncpy_src_shorter(void) {
    TEST("safe_strncpy source shorter than limit");

    char dst[32];
    size_t len = safe_strncpy(dst, sizeof(dst), "hi", 10);

    if (len != 2) {
        FAIL("wrong return length");
        return;
    }
    if (strcmp(dst, "hi") != 0) {
        FAIL("wrong content");
        return;
    }
    PASS();
}

static void test_safe_strncpy_dst_truncation(void) {
    TEST("safe_strncpy destination truncation");

    char dst[4];
    size_t len = safe_strncpy(dst, sizeof(dst), "hello", 10);

    /* Should truncate to dst_size - 1 = 3 chars */
    if (len != 3) {
        FAIL("wrong return length");
        return;
    }
    if (strcmp(dst, "hel") != 0) {
        FAIL("wrong truncated content");
        return;
    }
    PASS();
}

static void test_safe_strncpy_zero_src_len(void) {
    TEST("safe_strncpy zero source length");

    char dst[32] = "garbage";
    size_t len = safe_strncpy(dst, sizeof(dst), "hello", 0);

    if (len != 0) {
        FAIL("wrong return for zero src_len");
        return;
    }
    if (dst[0] != '\0') {
        FAIL("dst not empty");
        return;
    }
    PASS();
}

static void test_safe_strncpy_null_handling(void) {
    TEST("safe_strncpy NULL handling");

    char dst[32] = "test";

    if (safe_strncpy(dst, sizeof(dst), NULL, 5) != 0) {
        FAIL("wrong return for NULL src");
        return;
    }
    if (dst[0] != '\0') {
        FAIL("dst not cleared on NULL src");
        return;
    }

    if (safe_strncpy(NULL, 32, "hello", 5) != 0) {
        FAIL("wrong return for NULL dst");
        return;
    }

    PASS();
}

/*============================================================================
 * safe_memcpy tests
 *============================================================================*/

static void test_safe_memcpy_normal(void) {
    TEST("safe_memcpy normal copy");

    uint8_t dst[32];
    uint8_t src[] = {0x01, 0x02, 0x03, 0x04, 0x05};

    size_t copied = safe_memcpy(dst, sizeof(dst), src, sizeof(src));

    if (copied != 5) {
        FAIL("wrong return length");
        return;
    }
    if (memcmp(dst, src, 5) != 0) {
        FAIL("content mismatch");
        return;
    }
    PASS();
}

static void test_safe_memcpy_truncation(void) {
    TEST("safe_memcpy truncation");

    uint8_t dst[4];
    uint8_t src[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    size_t copied = safe_memcpy(dst, sizeof(dst), src, sizeof(src));

    if (copied != 4) {
        FAIL("wrong return length");
        return;
    }
    if (memcmp(dst, src, 4) != 0) {
        FAIL("content mismatch");
        return;
    }
    PASS();
}

static void test_safe_memcpy_zero_src(void) {
    TEST("safe_memcpy zero source length");

    uint8_t dst[32] = {0xFF};
    uint8_t src[] = {0x01, 0x02};

    size_t copied = safe_memcpy(dst, sizeof(dst), src, 0);

    if (copied != 0) {
        FAIL("wrong return for zero src");
        return;
    }
    /* dst[0] should be unchanged */
    if (dst[0] != 0xFF) {
        FAIL("dst modified with zero src");
        return;
    }
    PASS();
}

static void test_safe_memcpy_null_handling(void) {
    TEST("safe_memcpy NULL handling");

    uint8_t dst[32];
    uint8_t src[] = {0x01};

    if (safe_memcpy(dst, sizeof(dst), NULL, 5) != 0) {
        FAIL("wrong return for NULL src");
        return;
    }
    if (safe_memcpy(NULL, 32, src, sizeof(src)) != 0) {
        FAIL("wrong return for NULL dst");
        return;
    }
    if (safe_memcpy(dst, 0, src, sizeof(src)) != 0) {
        FAIL("wrong return for zero dst_size");
        return;
    }
    PASS();
}

/*============================================================================
 * safe_strcat tests
 *============================================================================*/

static void test_safe_strcat_normal(void) {
    TEST("safe_strcat normal concat");

    char dst[32] = "Hello";
    size_t total = safe_strcat(dst, sizeof(dst), " World");

    if (total != 11) {
        FAIL("wrong return length");
        return;
    }
    if (strcmp(dst, "Hello World") != 0) {
        FAIL("wrong content");
        return;
    }
    PASS();
}

static void test_safe_strcat_truncation(void) {
    TEST("safe_strcat truncation");

    char dst[10] = "Hello";
    size_t total = safe_strcat(dst, sizeof(dst), " World!");

    /* Total would be 12 (5 + 7), but truncated to 9 chars + null */
    if (total != 12) {
        FAIL("wrong theoretical length");
        return;
    }
    if (strcmp(dst, "Hello Wor") != 0) {
        FAIL("wrong truncated content");
        return;
    }
    if (dst[9] != '\0') {
        FAIL("not null terminated");
        return;
    }
    PASS();
}

static void test_safe_strcat_dst_full(void) {
    TEST("safe_strcat destination already full");

    char dst[6] = "Hello";  /* Already 5 chars + null */
    size_t total = safe_strcat(dst, sizeof(dst), " World");

    /* No room to append, but return value shows theoretical length */
    if (total != 11) {
        FAIL("wrong theoretical length");
        return;
    }
    /* dst should be unchanged (or just null terminated) */
    if (strcmp(dst, "Hello") != 0) {
        FAIL("dst modified when full");
        return;
    }
    PASS();
}

static void test_safe_strcat_empty_append(void) {
    TEST("safe_strcat empty append");

    char dst[32] = "Hello";
    size_t total = safe_strcat(dst, sizeof(dst), "");

    if (total != 5) {
        FAIL("wrong length for empty append");
        return;
    }
    if (strcmp(dst, "Hello") != 0) {
        FAIL("content changed on empty append");
        return;
    }
    PASS();
}

static void test_safe_strcat_null_handling(void) {
    TEST("safe_strcat NULL handling");

    char dst[32] = "test";

    if (safe_strcat(dst, sizeof(dst), NULL) != 0) {
        FAIL("wrong return for NULL src");
        return;
    }
    if (safe_strcat(NULL, 32, "hello") != 0) {
        FAIL("wrong return for NULL dst");
        return;
    }
    if (safe_strcat(dst, 0, "hello") != 0) {
        FAIL("wrong return for zero size");
        return;
    }
    PASS();
}

/*============================================================================
 * safe_memclear tests
 *============================================================================*/

static void test_safe_memclear_normal(void) {
    TEST("safe_memclear normal clear");

    char sensitive[32] = "secret_password_123";
    safe_memclear(sensitive, sizeof(sensitive));

    /* Verify all bytes are zero */
    for (size_t i = 0; i < sizeof(sensitive); i++) {
        if (sensitive[i] != 0) {
            FAIL("byte not cleared");
            return;
        }
    }
    PASS();
}

static void test_safe_memclear_partial(void) {
    TEST("safe_memclear partial clear");

    char data[32] = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    safe_memclear(data, 16);  /* Clear only first 16 bytes */

    /* First 16 should be zero */
    for (size_t i = 0; i < 16; i++) {
        if (data[i] != 0) {
            FAIL("first half not cleared");
            return;
        }
    }
    /* Rest should be unchanged */
    for (size_t i = 16; i < 32; i++) {
        if (data[i] != 'X') {
            FAIL("second half modified");
            return;
        }
    }
    PASS();
}

static void test_safe_memclear_null_handling(void) {
    TEST("safe_memclear NULL handling");

    /* Should not crash */
    safe_memclear(NULL, 100);

    char data[8] = "test";
    safe_memclear(data, 0);
    /* data should be unchanged */
    if (strcmp(data, "test") != 0) {
        FAIL("data changed with zero len");
        return;
    }

    PASS();
}

/*============================================================================
 * safe_memmove tests
 *============================================================================*/

static void test_safe_memmove_normal(void) {
    TEST("safe_memmove normal move");

    uint8_t dst[32];
    uint8_t src[] = {1, 2, 3, 4, 5};

    size_t moved = safe_memmove(dst, sizeof(dst), src, sizeof(src));

    if (moved != 5) {
        FAIL("wrong return length");
        return;
    }
    if (memcmp(dst, src, 5) != 0) {
        FAIL("content mismatch");
        return;
    }
    PASS();
}

static void test_safe_memmove_overlap_forward(void) {
    TEST("safe_memmove overlapping forward");

    char buf[] = "Hello World";
    /* Move "World" to beginning (overlapping) */
    size_t moved = safe_memmove(buf, sizeof(buf), buf + 6, 5);

    if (moved != 5) {
        FAIL("wrong return length");
        return;
    }
    if (memcmp(buf, "World", 5) != 0) {
        FAIL("overlap move failed");
        return;
    }
    PASS();
}

static void test_safe_memmove_overlap_backward(void) {
    TEST("safe_memmove overlapping backward");

    char buf[32] = "Hello";
    /* Move content forward (src < dst overlap) */
    memmove(buf + 2, buf, 5);  /* Setup: "HeHello" */
    strcpy(buf, "Hello");       /* Reset */

    /* Now test safe_memmove with backward overlap */
    size_t moved = safe_memmove(buf + 2, 30, buf, 5);

    if (moved != 5) {
        FAIL("wrong return length");
        return;
    }
    if (memcmp(buf + 2, "Hello", 5) != 0) {
        FAIL("backward overlap failed");
        return;
    }
    PASS();
}

static void test_safe_memmove_truncation(void) {
    TEST("safe_memmove truncation");

    uint8_t dst[4];
    uint8_t src[] = {1, 2, 3, 4, 5, 6};

    size_t moved = safe_memmove(dst, sizeof(dst), src, sizeof(src));

    if (moved != 4) {
        FAIL("wrong return length");
        return;
    }
    if (memcmp(dst, src, 4) != 0) {
        FAIL("truncated content wrong");
        return;
    }
    PASS();
}

static void test_safe_memmove_null_handling(void) {
    TEST("safe_memmove NULL handling");

    uint8_t dst[32];
    uint8_t src[] = {1};

    if (safe_memmove(dst, sizeof(dst), NULL, 5) != 0) {
        FAIL("wrong return for NULL src");
        return;
    }
    if (safe_memmove(NULL, 32, src, sizeof(src)) != 0) {
        FAIL("wrong return for NULL dst");
        return;
    }
    if (safe_memmove(dst, 0, src, sizeof(src)) != 0) {
        FAIL("wrong return for zero dst_size");
        return;
    }
    PASS();
}

/*============================================================================
 * Main
 *============================================================================*/

int main(void) {
    printf("\n=== Safe String Operations Tests ===\n\n");

    /* safe_strcpy tests */
    test_safe_strcpy_normal();
    test_safe_strcpy_exact_fit();
    test_safe_strcpy_truncation();
    test_safe_strcpy_empty_src();
    test_safe_strcpy_null_src();
    test_safe_strcpy_null_dst();
    test_safe_strcpy_zero_size();
    test_safe_strcpy_size_one();

    /* safe_strncpy tests */
    test_safe_strncpy_normal();
    test_safe_strncpy_src_shorter();
    test_safe_strncpy_dst_truncation();
    test_safe_strncpy_zero_src_len();
    test_safe_strncpy_null_handling();

    /* safe_memcpy tests */
    test_safe_memcpy_normal();
    test_safe_memcpy_truncation();
    test_safe_memcpy_zero_src();
    test_safe_memcpy_null_handling();

    /* safe_strcat tests */
    test_safe_strcat_normal();
    test_safe_strcat_truncation();
    test_safe_strcat_dst_full();
    test_safe_strcat_empty_append();
    test_safe_strcat_null_handling();

    /* safe_memclear tests */
    test_safe_memclear_normal();
    test_safe_memclear_partial();
    test_safe_memclear_null_handling();

    /* safe_memmove tests */
    test_safe_memmove_normal();
    test_safe_memmove_overlap_forward();
    test_safe_memmove_overlap_backward();
    test_safe_memmove_truncation();
    test_safe_memmove_null_handling();

    printf("\n=== Results: %d failures ===\n\n", failures);
    return failures > 0 ? 1 : 0;
}
