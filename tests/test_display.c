/**
 * @file test_display.c
 * @brief Unit tests for display module (P3: Output/Display)
 *
 * Tests:
 * - display_init/cleanup lifecycle
 * - display_color toggle (colors on/off)
 * - display_format_latency (ns/us/ms/s ranges)
 * - display_get_timestamp format validation
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license GPL-3.0-only
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include "../src/output/display.h"

/* Test framework macros */
#define TEST(name) printf("TEST: %s... ", name)
#define PASS() printf("\033[32mPASS\033[0m\n")
#define FAIL(msg) do { printf("\033[31mFAIL\033[0m: %s\n", msg); exit(1); } while(0)

static int tests_run = 0;

/* ============================================================================
 * display_init / display_cleanup Tests
 * ============================================================================ */

static void test_display_init_colors_enabled(void) {
    TEST("display_init colors enabled");

    int ret = display_init(true);
    if (ret != 0) FAIL("display_init returned non-zero");

    /* Verify colors are enabled */
    const char *color = display_color(C_RED);
    if (strlen(color) == 0) FAIL("color should be non-empty when enabled");
    if (strcmp(color, C_RED) != 0) FAIL("color should match C_RED");

    display_cleanup();
    tests_run++;
    PASS();
}

static void test_display_init_colors_disabled(void) {
    TEST("display_init colors disabled");

    int ret = display_init(false);
    if (ret != 0) FAIL("display_init returned non-zero");

    /* Verify colors are disabled */
    const char *color = display_color(C_RED);
    if (strlen(color) != 0) FAIL("color should be empty when disabled");

    display_cleanup();
    tests_run++;
    PASS();
}

static void test_display_cleanup_idempotent(void) {
    TEST("display_cleanup idempotent");

    display_init(true);
    display_cleanup();
    display_cleanup(); /* Should not crash */

    tests_run++;
    PASS();
}

/* ============================================================================
 * display_color Tests
 * ============================================================================ */

static void test_display_color_all_codes(void) {
    TEST("display_color all ANSI codes");

    display_init(true);

    /* Test all color macros */
    if (strcmp(display_color(C_RESET), C_RESET) != 0) FAIL("C_RESET mismatch");
    if (strcmp(display_color(C_BOLD), C_BOLD) != 0) FAIL("C_BOLD mismatch");
    if (strcmp(display_color(C_DIM), C_DIM) != 0) FAIL("C_DIM mismatch");
    if (strcmp(display_color(C_RED), C_RED) != 0) FAIL("C_RED mismatch");
    if (strcmp(display_color(C_GREEN), C_GREEN) != 0) FAIL("C_GREEN mismatch");
    if (strcmp(display_color(C_YELLOW), C_YELLOW) != 0) FAIL("C_YELLOW mismatch");
    if (strcmp(display_color(C_BLUE), C_BLUE) != 0) FAIL("C_BLUE mismatch");
    if (strcmp(display_color(C_MAGENTA), C_MAGENTA) != 0) FAIL("C_MAGENTA mismatch");
    if (strcmp(display_color(C_CYAN), C_CYAN) != 0) FAIL("C_CYAN mismatch");
    if (strcmp(display_color(C_WHITE), C_WHITE) != 0) FAIL("C_WHITE mismatch");

    display_cleanup();
    tests_run++;
    PASS();
}

static void test_display_color_toggle(void) {
    TEST("display_color toggle behavior");

    /* Enable colors */
    display_init(true);
    const char *enabled = display_color(C_GREEN);
    if (strlen(enabled) == 0) FAIL("should have color when enabled");

    /* Disable colors */
    display_init(false);
    const char *disabled = display_color(C_GREEN);
    if (strlen(disabled) != 0) FAIL("should be empty when disabled");

    /* Re-enable colors */
    display_init(true);
    const char *reenabled = display_color(C_GREEN);
    if (strlen(reenabled) == 0) FAIL("should have color when re-enabled");

    display_cleanup();
    tests_run++;
    PASS();
}

static void test_display_color_null_safe(void) {
    TEST("display_color NULL handling");

    display_init(true);

    /* NULL should be returned as-is when colors enabled (passthrough) */
    const char *result = display_color(NULL);
    /* The function returns the input when colors are enabled */
    if (result != NULL) FAIL("NULL should pass through");

    display_init(false);
    /* When colors disabled, still returns empty string for non-NULL */
    /* NULL input returns empty string per implementation */

    display_cleanup();
    tests_run++;
    PASS();
}

/* ============================================================================
 * display_format_latency Tests
 * ============================================================================ */

static void test_format_latency_nanoseconds(void) {
    TEST("display_format_latency nanoseconds");

    char buf[32];

    /* Edge case: 0ns */
    display_format_latency(0, buf, sizeof(buf));
    if (strstr(buf, "ns") == NULL) FAIL("should contain 'ns'");
    if (strstr(buf, "0") == NULL) FAIL("should contain '0'");

    /* Small value: 500ns */
    display_format_latency(500, buf, sizeof(buf));
    if (strstr(buf, "500") == NULL) FAIL("should contain '500'");
    if (strstr(buf, "ns") == NULL) FAIL("should contain 'ns'");

    /* Edge case: 999ns */
    display_format_latency(999, buf, sizeof(buf));
    if (strstr(buf, "999") == NULL) FAIL("should contain '999'");
    if (strstr(buf, "ns") == NULL) FAIL("should contain 'ns'");

    tests_run++;
    PASS();
}

static void test_format_latency_microseconds(void) {
    TEST("display_format_latency microseconds");

    char buf[32];

    /* Boundary: 1000ns = 1.0us */
    display_format_latency(1000, buf, sizeof(buf));
    if (strstr(buf, "us") == NULL) FAIL("should contain 'us'");
    if (strstr(buf, "1") == NULL) FAIL("should contain '1'");

    /* Middle value: 500us */
    display_format_latency(500000, buf, sizeof(buf));
    if (strstr(buf, "us") == NULL) FAIL("should contain 'us'");
    if (strstr(buf, "500") == NULL) FAIL("should contain '500'");

    /* Edge: 999.9us */
    display_format_latency(999900, buf, sizeof(buf));
    if (strstr(buf, "us") == NULL) FAIL("should contain 'us'");

    tests_run++;
    PASS();
}

static void test_format_latency_milliseconds(void) {
    TEST("display_format_latency milliseconds");

    char buf[32];

    /* Boundary: 1ms */
    display_format_latency(1000000, buf, sizeof(buf));
    if (strstr(buf, "ms") == NULL) FAIL("should contain 'ms'");

    /* Typical latency: 45.2ms */
    display_format_latency(45200000, buf, sizeof(buf));
    if (strstr(buf, "ms") == NULL) FAIL("should contain 'ms'");
    if (strstr(buf, "45") == NULL) FAIL("should contain '45'");

    /* Edge: 999ms */
    display_format_latency(999000000, buf, sizeof(buf));
    if (strstr(buf, "ms") == NULL) FAIL("should contain 'ms'");

    tests_run++;
    PASS();
}

static void test_format_latency_seconds(void) {
    TEST("display_format_latency seconds");

    char buf[32];

    /* Boundary: 1s */
    display_format_latency(1000000000ULL, buf, sizeof(buf));
    if (strstr(buf, "s") == NULL) FAIL("should contain 's'");
    /* Should NOT contain 'ms' or 'us' or 'ns' */
    if (strstr(buf, "ms") != NULL) FAIL("should not be ms");
    if (strstr(buf, "us") != NULL) FAIL("should not be us");
    if (strstr(buf, "ns") != NULL) FAIL("should not be ns");

    /* Large value: 5.5s */
    display_format_latency(5500000000ULL, buf, sizeof(buf));
    if (strstr(buf, "5.5") == NULL && strstr(buf, "5.50") == NULL)
        FAIL("should show ~5.5s");

    /* Very large: 60s */
    display_format_latency(60000000000ULL, buf, sizeof(buf));
    if (strstr(buf, "60") == NULL) FAIL("should contain '60'");

    tests_run++;
    PASS();
}

static void test_format_latency_buffer_edge_cases(void) {
    TEST("display_format_latency buffer edge cases");

    char buf[4]; /* Very small buffer */

    /* Should not overflow */
    display_format_latency(1234567890ULL, buf, sizeof(buf));
    /* Just verify no crash, buffer may be truncated */
    if (strlen(buf) >= sizeof(buf)) FAIL("buffer overflow");

    /* Zero-size buffer */
    char buf2[1] = {0};
    display_format_latency(1000, buf2, 0);
    /* Should not crash, result undefined but no overflow */

    tests_run++;
    PASS();
}

/* ============================================================================
 * display_get_timestamp Tests
 * ============================================================================ */

static void test_get_timestamp_format(void) {
    TEST("display_get_timestamp format HH:MM:SS.mmm");

    char buf[32];
    display_get_timestamp(buf, sizeof(buf));

    /* Verify length: HH:MM:SS.mmm = 12 characters */
    size_t len = strlen(buf);
    if (len != 12) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected len 12, got %zu: '%s'", len, buf);
        FAIL(msg);
    }

    /* Verify format: digits at expected positions */
    if (!isdigit(buf[0]) || !isdigit(buf[1])) FAIL("HH not digits");
    if (buf[2] != ':') FAIL("missing colon after HH");
    if (!isdigit(buf[3]) || !isdigit(buf[4])) FAIL("MM not digits");
    if (buf[5] != ':') FAIL("missing colon after MM");
    if (!isdigit(buf[6]) || !isdigit(buf[7])) FAIL("SS not digits");
    if (buf[8] != '.') FAIL("missing dot after SS");
    if (!isdigit(buf[9]) || !isdigit(buf[10]) || !isdigit(buf[11]))
        FAIL("mmm not digits");

    tests_run++;
    PASS();
}

static void test_get_timestamp_valid_ranges(void) {
    TEST("display_get_timestamp valid time ranges");

    char buf[32];
    display_get_timestamp(buf, sizeof(buf));

    /* Parse and validate ranges */
    int hour, min, sec, ms;
    if (sscanf(buf, "%d:%d:%d.%d", &hour, &min, &sec, &ms) != 4) {
        FAIL("failed to parse timestamp");
    }

    if (hour < 0 || hour > 23) FAIL("hour out of range");
    if (min < 0 || min > 59) FAIL("minute out of range");
    if (sec < 0 || sec > 59) FAIL("second out of range");
    if (ms < 0 || ms > 999) FAIL("millisecond out of range");

    tests_run++;
    PASS();
}

static void test_get_timestamp_buffer_edge_cases(void) {
    TEST("display_get_timestamp buffer edge cases");

    /* Very small buffer - should truncate safely */
    char buf[8] = {0};
    display_get_timestamp(buf, sizeof(buf));
    if (strlen(buf) >= sizeof(buf)) FAIL("buffer overflow");

    /* Exact size buffer */
    char buf2[13] = {0}; /* 12 chars + null */
    display_get_timestamp(buf2, sizeof(buf2));
    if (strlen(buf2) != 12) FAIL("expected full timestamp");

    /* Zero size buffer - should not crash */
    char buf3[1] = {0};
    display_get_timestamp(buf3, 0);
    /* Function should handle size=0 gracefully */

    tests_run++;
    PASS();
}

static void test_get_timestamp_sequential(void) {
    TEST("display_get_timestamp sequential calls");

    char buf1[32], buf2[32];

    display_get_timestamp(buf1, sizeof(buf1));
    /* Small delay to ensure time may have changed */
    for (volatile int i = 0; i < 1000000; i++);
    display_get_timestamp(buf2, sizeof(buf2));

    /* Both should be valid timestamps (may or may not be equal) */
    if (strlen(buf1) != 12) FAIL("first timestamp invalid");
    if (strlen(buf2) != 12) FAIL("second timestamp invalid");

    /* Parse both to verify format */
    int h1, m1, s1, ms1, h2, m2, s2, ms2;
    if (sscanf(buf1, "%d:%d:%d.%d", &h1, &m1, &s1, &ms1) != 4)
        FAIL("failed to parse first timestamp");
    if (sscanf(buf2, "%d:%d:%d.%d", &h2, &m2, &s2, &ms2) != 4)
        FAIL("failed to parse second timestamp");

    tests_run++;
    PASS();
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    printf("=== Display Module Tests ===\n\n");

    /* display_init/cleanup tests */
    test_display_init_colors_enabled();
    test_display_init_colors_disabled();
    test_display_cleanup_idempotent();

    /* display_color tests */
    test_display_color_all_codes();
    test_display_color_toggle();
    test_display_color_null_safe();

    /* display_format_latency tests */
    test_format_latency_nanoseconds();
    test_format_latency_microseconds();
    test_format_latency_milliseconds();
    test_format_latency_seconds();
    test_format_latency_buffer_edge_cases();

    /* display_get_timestamp tests */
    test_get_timestamp_format();
    test_get_timestamp_valid_ranges();
    test_get_timestamp_buffer_edge_cases();
    test_get_timestamp_sequential();

    printf("\n\033[32mAll tests passed!\033[0m (%d tests)\n", tests_run);
    return 0;
}
