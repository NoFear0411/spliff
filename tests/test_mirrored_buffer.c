/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * spliff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 spliff authors
 *
 * test_mirrored_buffer.c - Unit tests for mirrored virtual memory buffers
 *
 * Tests the core functionality of the mirrored buffer implementation:
 * - Buffer creation with valid/invalid sizes
 * - Virtual memory mirroring (wrap-around without branching)
 * - State machine for data race protection
 * - NULL handling and edge cases
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../src/memory/mirrored_buffer.h"
#include "../src/memory/alignment.h"

#define TEST(name) printf("TEST: %s... ", name)
#define PASS() printf("\033[32mPASS\033[0m\n")
#define FAIL(msg) do { printf("\033[31mFAIL: %s\033[0m\n", msg); failures++; } while(0)

static int failures = 0;

/*============================================================================
 * Buffer Creation Tests
 *============================================================================*/

static void test_create_valid_size(void) {
    TEST("create with valid power-of-2 size");

    mirrored_buffer_t *buf = mirrored_buffer_create(MIN_BUFFER_SIZE);

    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }
    if (buf->size != MIN_BUFFER_SIZE) {
        mirrored_buffer_destroy(buf);
        FAIL("wrong size");
        return;
    }
    if (buf->mask != (MIN_BUFFER_SIZE - 1)) {
        mirrored_buffer_destroy(buf);
        FAIL("wrong mask");
        return;
    }
    if (!buf->base) {
        mirrored_buffer_destroy(buf);
        FAIL("base is NULL");
        return;
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

static void test_create_default_size(void) {
    TEST("create with default 256KB size");

    mirrored_buffer_t *buf = mirrored_buffer_create(DEFAULT_BUFFER_SIZE);

    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }
    if (buf->size != DEFAULT_BUFFER_SIZE) {
        mirrored_buffer_destroy(buf);
        FAIL("wrong size");
        return;
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

static void test_create_max_size(void) {
    TEST("create with max 512KB size");

    mirrored_buffer_t *buf = mirrored_buffer_create(MAX_BUFFER_SIZE);

    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }
    if (buf->size != MAX_BUFFER_SIZE) {
        mirrored_buffer_destroy(buf);
        FAIL("wrong size");
        return;
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

static void test_create_invalid_not_power_of_2(void) {
    TEST("create with non-power-of-2 size (should fail)");

    /* 100KB is not a power of 2 */
    mirrored_buffer_t *buf = mirrored_buffer_create(100 * 1024);

    if (buf != NULL) {
        mirrored_buffer_destroy(buf);
        FAIL("should have returned NULL for non-power-of-2");
        return;
    }

    PASS();
}

static void test_create_invalid_too_small(void) {
    TEST("create with too small size (should fail)");

    /* 32KB is below MIN_BUFFER_SIZE (64KB) */
    mirrored_buffer_t *buf = mirrored_buffer_create(32 * 1024);

    if (buf != NULL) {
        mirrored_buffer_destroy(buf);
        FAIL("should have returned NULL for size below minimum");
        return;
    }

    PASS();
}

static void test_create_invalid_too_large(void) {
    TEST("create with too large size (should fail)");

    /* 1MB is above MAX_BUFFER_SIZE (512KB) */
    mirrored_buffer_t *buf = mirrored_buffer_create(1024 * 1024);

    if (buf != NULL) {
        mirrored_buffer_destroy(buf);
        FAIL("should have returned NULL for size above maximum");
        return;
    }

    PASS();
}

static void test_create_invalid_zero(void) {
    TEST("create with zero size (should fail)");

    mirrored_buffer_t *buf = mirrored_buffer_create(0);

    if (buf != NULL) {
        mirrored_buffer_destroy(buf);
        FAIL("should have returned NULL for zero size");
        return;
    }

    PASS();
}

/*============================================================================
 * Virtual Memory Mirroring Tests (Core Feature)
 *============================================================================*/

static void test_mirror_basic_write_read(void) {
    TEST("basic write and read");

    mirrored_buffer_t *buf = mirrored_buffer_create(MIN_BUFFER_SIZE);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }

    /* Claim buffer for writing */
    if (!mirrored_buffer_claim(buf)) {
        mirrored_buffer_destroy(buf);
        FAIL("failed to claim buffer");
        return;
    }

    /* Write test data */
    const char *test_data = "Hello, mirrored world!";
    size_t len = strlen(test_data);
    size_t written = mirrored_buffer_write(buf, 0, test_data, len);

    if (written != len) {
        mirrored_buffer_destroy(buf);
        FAIL("wrong number of bytes written");
        return;
    }

    /* Commit and verify state */
    mirrored_buffer_commit(buf, 0, len);

    if (!mirrored_buffer_is_ready(buf)) {
        mirrored_buffer_destroy(buf);
        FAIL("buffer not ready after commit");
        return;
    }

    /* Read back and verify */
    char read_buf[64] = {0};
    size_t read = mirrored_buffer_read(buf, 0, read_buf, len);

    if (read != len) {
        mirrored_buffer_destroy(buf);
        FAIL("wrong number of bytes read");
        return;
    }
    if (memcmp(read_buf, test_data, len) != 0) {
        mirrored_buffer_destroy(buf);
        FAIL("data mismatch");
        return;
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

static void test_mirror_wraparound(void) {
    TEST("wrap-around write/read (core mirroring feature)");

    mirrored_buffer_t *buf = mirrored_buffer_create(MIN_BUFFER_SIZE);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }

    if (!mirrored_buffer_claim(buf)) {
        mirrored_buffer_destroy(buf);
        FAIL("failed to claim buffer");
        return;
    }

    /*
     * Write data that wraps around the buffer boundary.
     * Start at (size - 50) and write 100 bytes.
     * Without mirroring, this would require split memcpy.
     * With mirroring, single memcpy handles wrap-around automatically.
     */
    size_t offset = buf->size - 50;
    uint8_t test_data[100];
    for (int i = 0; i < 100; i++) {
        test_data[i] = (uint8_t)(i + 1);
    }

    size_t written = mirrored_buffer_write(buf, offset, test_data, sizeof(test_data));
    if (written != sizeof(test_data)) {
        mirrored_buffer_destroy(buf);
        FAIL("wrong number of bytes written");
        return;
    }

    mirrored_buffer_commit(buf, offset, sizeof(test_data));

    /* Read back the wrapped data */
    uint8_t read_buf[100];
    size_t read = mirrored_buffer_read(buf, offset, read_buf, sizeof(read_buf));

    if (read != sizeof(read_buf)) {
        mirrored_buffer_destroy(buf);
        FAIL("wrong number of bytes read");
        return;
    }
    if (memcmp(read_buf, test_data, sizeof(test_data)) != 0) {
        mirrored_buffer_destroy(buf);
        FAIL("wrap-around data mismatch");
        return;
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

static void test_mirror_direct_access(void) {
    TEST("direct pointer access across boundary");

    mirrored_buffer_t *buf = mirrored_buffer_create(MIN_BUFFER_SIZE);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }

    if (!mirrored_buffer_claim(buf)) {
        mirrored_buffer_destroy(buf);
        FAIL("failed to claim buffer");
        return;
    }

    /*
     * Test that writing at base + (size - 10) and reading 20 bytes
     * gives contiguous data due to mirroring.
     */
    size_t offset = buf->size - 10;
    uint8_t *ptr = (uint8_t *)mirrored_buffer_at(buf, offset);

    if (!ptr) {
        mirrored_buffer_destroy(buf);
        FAIL("mirrored_buffer_at returned NULL");
        return;
    }

    /* Write 20 bytes directly - crosses boundary */
    for (int i = 0; i < 20; i++) {
        ptr[i] = (uint8_t)(0xA0 + i);
    }

    mirrored_buffer_commit(buf, offset, 20);

    /* Verify first 10 bytes are at end of first mapping */
    uint8_t *base = (uint8_t *)buf->base;
    for (int i = 0; i < 10; i++) {
        if (base[offset + i] != (uint8_t)(0xA0 + i)) {
            mirrored_buffer_destroy(buf);
            FAIL("first half mismatch");
            return;
        }
    }

    /* Verify last 10 bytes wrapped to beginning */
    for (int i = 0; i < 10; i++) {
        if (base[i] != (uint8_t)(0xAA + i)) {
            mirrored_buffer_destroy(buf);
            FAIL("wrapped half mismatch");
            return;
        }
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

static void test_mirror_physical_identity(void) {
    TEST("mirrored regions share physical memory");

    mirrored_buffer_t *buf = mirrored_buffer_create(MIN_BUFFER_SIZE);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }

    if (!mirrored_buffer_claim(buf)) {
        mirrored_buffer_destroy(buf);
        FAIL("failed to claim buffer");
        return;
    }

    /*
     * Write to first mapping, verify it appears in mirrored region.
     * base[0] should equal base[size] due to physical page sharing.
     */
    uint8_t *base = (uint8_t *)buf->base;
    base[0] = 0x42;
    base[100] = 0x99;

    /* Read from mirrored region (offset + size) */
    if (base[buf->size] != 0x42) {
        mirrored_buffer_destroy(buf);
        FAIL("write to first mapping not visible in mirror");
        return;
    }
    if (base[buf->size + 100] != 0x99) {
        mirrored_buffer_destroy(buf);
        FAIL("second write not visible in mirror");
        return;
    }

    /* Write to mirror, verify in first mapping */
    base[buf->size + 200] = 0xAB;
    if (base[200] != 0xAB) {
        mirrored_buffer_destroy(buf);
        FAIL("write to mirror not visible in first mapping");
        return;
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

/*============================================================================
 * State Machine Tests (Data Race Protection)
 *============================================================================*/

static void test_state_initial(void) {
    TEST("initial state is IDLE");

    mirrored_buffer_t *buf = mirrored_buffer_create(MIN_BUFFER_SIZE);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }

    if (mirrored_buffer_get_state(buf) != BUF_STATE_IDLE) {
        mirrored_buffer_destroy(buf);
        FAIL("initial state not IDLE");
        return;
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

static void test_state_claim_success(void) {
    TEST("claim transitions IDLE -> WRITING");

    mirrored_buffer_t *buf = mirrored_buffer_create(MIN_BUFFER_SIZE);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }

    if (!mirrored_buffer_claim(buf)) {
        mirrored_buffer_destroy(buf);
        FAIL("claim failed on IDLE buffer");
        return;
    }

    if (mirrored_buffer_get_state(buf) != BUF_STATE_WRITING) {
        mirrored_buffer_destroy(buf);
        FAIL("state not WRITING after claim");
        return;
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

static void test_state_claim_already_writing(void) {
    TEST("claim fails if already WRITING");

    mirrored_buffer_t *buf = mirrored_buffer_create(MIN_BUFFER_SIZE);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }

    /* First claim should succeed */
    if (!mirrored_buffer_claim(buf)) {
        mirrored_buffer_destroy(buf);
        FAIL("first claim failed");
        return;
    }

    /* Second claim should fail (already WRITING) */
    if (mirrored_buffer_claim(buf)) {
        mirrored_buffer_destroy(buf);
        FAIL("second claim should have failed");
        return;
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

static void test_state_commit_ready(void) {
    TEST("commit transitions WRITING -> READY");

    mirrored_buffer_t *buf = mirrored_buffer_create(MIN_BUFFER_SIZE);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }

    mirrored_buffer_claim(buf);
    mirrored_buffer_commit(buf, 0, 100);

    if (mirrored_buffer_get_state(buf) != BUF_STATE_READY) {
        mirrored_buffer_destroy(buf);
        FAIL("state not READY after commit");
        return;
    }

    if (!mirrored_buffer_is_ready(buf)) {
        mirrored_buffer_destroy(buf);
        FAIL("is_ready returned false");
        return;
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

static void test_state_release_idle(void) {
    TEST("release transitions READY -> IDLE");

    mirrored_buffer_t *buf = mirrored_buffer_create(MIN_BUFFER_SIZE);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }

    mirrored_buffer_claim(buf);
    mirrored_buffer_commit(buf, 0, 100);
    mirrored_buffer_release(buf);

    if (mirrored_buffer_get_state(buf) != BUF_STATE_IDLE) {
        mirrored_buffer_destroy(buf);
        FAIL("state not IDLE after release");
        return;
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

static void test_state_full_cycle(void) {
    TEST("full state cycle: IDLE -> WRITING -> READY -> IDLE");

    mirrored_buffer_t *buf = mirrored_buffer_create(MIN_BUFFER_SIZE);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }

    /* Cycle 1 */
    if (!mirrored_buffer_claim(buf)) {
        mirrored_buffer_destroy(buf);
        FAIL("cycle 1: claim failed");
        return;
    }
    mirrored_buffer_commit(buf, 0, 50);
    mirrored_buffer_release(buf);

    /* Cycle 2 - should work again */
    if (!mirrored_buffer_claim(buf)) {
        mirrored_buffer_destroy(buf);
        FAIL("cycle 2: claim failed");
        return;
    }
    mirrored_buffer_commit(buf, 50, 75);
    mirrored_buffer_release(buf);

    /* Cycle 3 */
    if (!mirrored_buffer_claim(buf)) {
        mirrored_buffer_destroy(buf);
        FAIL("cycle 3: claim failed");
        return;
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

static void test_state_write_info(void) {
    TEST("get_write_info returns committed offset and length");

    mirrored_buffer_t *buf = mirrored_buffer_create(MIN_BUFFER_SIZE);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }

    mirrored_buffer_claim(buf);
    mirrored_buffer_commit(buf, 12345, 9876);

    uint64_t offset = 0, len = 0;
    mirrored_buffer_get_write_info(buf, &offset, &len);

    if (offset != 12345) {
        mirrored_buffer_destroy(buf);
        FAIL("wrong offset");
        return;
    }
    if (len != 9876) {
        mirrored_buffer_destroy(buf);
        FAIL("wrong length");
        return;
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

/*============================================================================
 * NULL and Edge Case Handling Tests
 *============================================================================*/

static void test_destroy_null(void) {
    TEST("destroy NULL buffer (should not crash)");

    /* This should be a no-op, not crash */
    mirrored_buffer_destroy(NULL);

    PASS();
}

static void test_claim_null(void) {
    TEST("claim NULL buffer returns false");

    if (mirrored_buffer_claim(NULL)) {
        FAIL("claim should return false for NULL");
        return;
    }

    PASS();
}

static void test_commit_null(void) {
    TEST("commit NULL buffer (should not crash)");

    /* Should be a no-op */
    mirrored_buffer_commit(NULL, 0, 100);

    PASS();
}

static void test_release_null(void) {
    TEST("release NULL buffer (should not crash)");

    /* Should be a no-op */
    mirrored_buffer_release(NULL);

    PASS();
}

static void test_is_ready_null(void) {
    TEST("is_ready NULL buffer returns false");

    if (mirrored_buffer_is_ready(NULL)) {
        FAIL("is_ready should return false for NULL");
        return;
    }

    PASS();
}

static void test_get_state_null(void) {
    TEST("get_state NULL buffer returns IDLE");

    if (mirrored_buffer_get_state(NULL) != BUF_STATE_IDLE) {
        FAIL("get_state should return IDLE for NULL");
        return;
    }

    PASS();
}

static void test_write_null_buf(void) {
    TEST("write to NULL buffer returns 0");

    char data[] = "test";
    size_t written = mirrored_buffer_write(NULL, 0, data, sizeof(data));

    if (written != 0) {
        FAIL("write should return 0 for NULL buffer");
        return;
    }

    PASS();
}

static void test_write_null_data(void) {
    TEST("write NULL data returns 0");

    mirrored_buffer_t *buf = mirrored_buffer_create(MIN_BUFFER_SIZE);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }

    mirrored_buffer_claim(buf);
    size_t written = mirrored_buffer_write(buf, 0, NULL, 100);

    if (written != 0) {
        mirrored_buffer_destroy(buf);
        FAIL("write should return 0 for NULL data");
        return;
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

static void test_write_zero_len(void) {
    TEST("write zero length returns 0");

    mirrored_buffer_t *buf = mirrored_buffer_create(MIN_BUFFER_SIZE);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }

    mirrored_buffer_claim(buf);
    char data[] = "test";
    size_t written = mirrored_buffer_write(buf, 0, data, 0);

    if (written != 0) {
        mirrored_buffer_destroy(buf);
        FAIL("write should return 0 for zero length");
        return;
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

static void test_read_null_buf(void) {
    TEST("read from NULL buffer returns 0");

    char dest[32];
    size_t read = mirrored_buffer_read(NULL, 0, dest, sizeof(dest));

    if (read != 0) {
        FAIL("read should return 0 for NULL buffer");
        return;
    }

    PASS();
}

static void test_at_null(void) {
    TEST("mirrored_buffer_at NULL returns NULL");

    if (mirrored_buffer_at(NULL, 0) != NULL) {
        FAIL("at should return NULL for NULL buffer");
        return;
    }

    PASS();
}

static void test_has_hugepages_null(void) {
    TEST("has_hugepages NULL returns false");

    if (mirrored_buffer_has_hugepages(NULL)) {
        FAIL("has_hugepages should return false for NULL");
        return;
    }

    PASS();
}

/*============================================================================
 * Hugepage Tests
 *============================================================================*/

static void test_create_ex_no_hugepages(void) {
    TEST("create_ex without hugepages");

    mirrored_buffer_t *buf = mirrored_buffer_create_ex(MIN_BUFFER_SIZE, false);

    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }

    /* Should work regardless of hugepage setting */
    if (buf->size != MIN_BUFFER_SIZE) {
        mirrored_buffer_destroy(buf);
        FAIL("wrong size");
        return;
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

static void test_create_ex_prefer_hugepages(void) {
    TEST("create_ex with prefer_hugepages (may fall back)");

    mirrored_buffer_t *buf = mirrored_buffer_create_ex(MIN_BUFFER_SIZE, true);

    if (!buf) {
        /*
         * This is acceptable - hugepages may not be configured.
         * The test verifies the API doesn't crash.
         */
        printf("\033[33mSKIP (hugepages unavailable)\033[0m\n");
        return;
    }

    /* Buffer created successfully (with or without hugepages) */
    if (buf->size != MIN_BUFFER_SIZE) {
        mirrored_buffer_destroy(buf);
        FAIL("wrong size");
        return;
    }

    /* Log whether hugepages were actually used */
    if (buf->use_hugepages) {
        printf("\033[32mPASS (using hugepages)\033[0m\n");
    } else {
        printf("\033[32mPASS (fell back to regular pages)\033[0m\n");
    }

    mirrored_buffer_destroy(buf);
}

/*============================================================================
 * Wrap Mask Tests
 *============================================================================*/

static void test_wrap_mask(void) {
    TEST("wrap mask calculation");

    mirrored_buffer_t *buf = mirrored_buffer_create(MIN_BUFFER_SIZE);
    if (!buf) {
        FAIL("failed to create buffer");
        return;
    }

    /* Test various offsets */
    size_t offset = buf->size + 1000;
    size_t wrapped = mirrored_buffer_wrap(buf, offset);

    if (wrapped != 1000) {
        mirrored_buffer_destroy(buf);
        FAIL("wrap calculation wrong");
        return;
    }

    /* Offset exactly at size should wrap to 0 */
    wrapped = mirrored_buffer_wrap(buf, buf->size);
    if (wrapped != 0) {
        mirrored_buffer_destroy(buf);
        FAIL("wrap at size should be 0");
        return;
    }

    /* Large offset */
    offset = buf->size * 5 + 42;
    wrapped = mirrored_buffer_wrap(buf, offset);
    if (wrapped != 42) {
        mirrored_buffer_destroy(buf);
        FAIL("large offset wrap wrong");
        return;
    }

    mirrored_buffer_destroy(buf);
    PASS();
}

/*============================================================================
 * Main
 *============================================================================*/

int main(void) {
    printf("\n=== Mirrored Buffer Tests ===\n\n");

    printf("--- Buffer Creation ---\n");
    test_create_valid_size();
    test_create_default_size();
    test_create_max_size();
    test_create_invalid_not_power_of_2();
    test_create_invalid_too_small();
    test_create_invalid_too_large();
    test_create_invalid_zero();

    printf("\n--- Virtual Memory Mirroring ---\n");
    test_mirror_basic_write_read();
    test_mirror_wraparound();
    test_mirror_direct_access();
    test_mirror_physical_identity();

    printf("\n--- State Machine ---\n");
    test_state_initial();
    test_state_claim_success();
    test_state_claim_already_writing();
    test_state_commit_ready();
    test_state_release_idle();
    test_state_full_cycle();
    test_state_write_info();

    printf("\n--- NULL Handling ---\n");
    test_destroy_null();
    test_claim_null();
    test_commit_null();
    test_release_null();
    test_is_ready_null();
    test_get_state_null();
    test_write_null_buf();
    test_write_null_data();
    test_write_zero_len();
    test_read_null_buf();
    test_at_null();
    test_has_hugepages_null();

    printf("\n--- Hugepage Support ---\n");
    test_create_ex_no_hugepages();
    test_create_ex_prefer_hugepages();

    printf("\n--- Wrap Mask ---\n");
    test_wrap_mask();

    printf("\n=== Results: %d failures ===\n\n", failures);
    return failures > 0 ? 1 : 0;
}
