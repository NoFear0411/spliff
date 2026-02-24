/**
 * @file test_http1.c
 * @brief Unit tests for HTTP/1.x protocol parsing (llhttp)
 *
 * Tests the HTTP/1 module's public API:
 * - http1_is_request/http1_is_response detection
 * - http1_parse message parsing (auto-detect direction)
 * - Request/response field extraction
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license LGPL-3.0-only
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "../src/include/spliff.h"
#include "../src/protocol/http1.h"

#define TEST(name) printf("TEST: %s... ", name)
#define PASS() printf("\033[32mPASS\033[0m\n")
#define FAIL(msg) do { printf("\033[31mFAIL: %s\033[0m\n", msg); failures++; } while(0)

static int failures = 0;

/* ============================================================================
 * Detection Tests
 * ============================================================================ */

static void test_is_request(void) {
    TEST("http1_is_request");

    const char *requests[] = {
        "GET / HTTP/1.1\r\n",
        "POST /api HTTP/1.0\r\n",
        "PUT /resource HTTP/1.1\r\n",
        "DELETE /item HTTP/1.1\r\n",
        "HEAD /check HTTP/1.1\r\n",
        "OPTIONS * HTTP/1.1\r\n",
        "PATCH /update HTTP/1.1\r\n",
        "CONNECT host:443 HTTP/1.1\r\n",
    };

    for (size_t i = 0; i < sizeof(requests)/sizeof(requests[0]); i++) {
        if (!http1_is_request((const uint8_t *)requests[i], strlen(requests[i]))) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Failed to detect: %.40s", requests[i]);
            FAIL(buf);
            return;
        }
    }

    /* Not requests */
    const char *not_requests[] = {
        "HTTP/1.1 200 OK\r\n",
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        "random garbage data",
        "\x16\x03\x01",  /* TLS */
    };

    for (size_t i = 0; i < sizeof(not_requests)/sizeof(not_requests[0]); i++) {
        if (http1_is_request((const uint8_t *)not_requests[i], strlen(not_requests[i]))) {
            FAIL("False positive on non-request");
            return;
        }
    }

    PASS();
}

static void test_is_response(void) {
    TEST("http1_is_response");

    const char *responses[] = {
        "HTTP/1.1 200 OK\r\n",
        "HTTP/1.0 404 Not Found\r\n",
        "HTTP/1.1 301 Moved Permanently\r\n",
        "HTTP/1.1 500 Internal Server Error\r\n",
        "HTTP/1.1 204 No Content\r\n",
    };

    for (size_t i = 0; i < sizeof(responses)/sizeof(responses[0]); i++) {
        if (!http1_is_response((const uint8_t *)responses[i], strlen(responses[i]))) {
            char buf[128];
            snprintf(buf, sizeof(buf), "Failed to detect: %.40s", responses[i]);
            FAIL(buf);
            return;
        }
    }

    /* Not responses */
    const char *not_responses[] = {
        "GET / HTTP/1.1\r\n",
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        "random data",
    };

    for (size_t i = 0; i < sizeof(not_responses)/sizeof(not_responses[0]); i++) {
        if (http1_is_response((const uint8_t *)not_responses[i], strlen(not_responses[i]))) {
            FAIL("False positive on non-response");
            return;
        }
    }

    PASS();
}

static void test_detection_short_data(void) {
    TEST("http1 detection short data");

    if (http1_is_request((const uint8_t *)"GET", 3)) {
        FAIL("Matched incomplete request");
        return;
    }

    if (http1_is_response((const uint8_t *)"HTTP", 4)) {
        FAIL("Matched incomplete response");
        return;
    }

    if (http1_is_request((const uint8_t *)"", 0)) {
        FAIL("Matched empty as request");
        return;
    }

    if (http1_is_response((const uint8_t *)"", 0)) {
        FAIL("Matched empty as response");
        return;
    }

    PASS();
}

/* ============================================================================
 * Parsing Tests
 * ============================================================================ */

static void test_parse_get_request(void) {
    TEST("http1_parse GET request");

    const char *request =
        "GET /api/users?id=123 HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: test/1.0\r\n"
        "Accept: application/json\r\n"
        "\r\n";

    http_message_t msg = {0};
    uint8_t body_buf[1024];
    size_t body_len = 0;

    int result = http1_parse((const uint8_t *)request, strlen(request),
                             &msg, body_buf, sizeof(body_buf), &body_len);

    if (result < 0) {
        FAIL("Parse failed");
        return;
    }

    if (strcmp(msg.method, "GET") != 0) {
        FAIL("Wrong method");
        return;
    }

    if (strcmp(msg.path, "/api/users?id=123") != 0) {
        FAIL("Wrong path");
        return;
    }

    if (msg.direction != DIR_REQUEST) {
        FAIL("Wrong direction");
        return;
    }

    PASS();
}

static void test_parse_post_request(void) {
    TEST("http1_parse POST request with body");

    const char *request =
        "POST /api/data HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "{\"key\":\"val\"}";

    http_message_t msg = {0};
    uint8_t body_buf[1024];
    size_t body_len = 0;

    int result = http1_parse((const uint8_t *)request, strlen(request),
                             &msg, body_buf, sizeof(body_buf), &body_len);

    if (result < 0) {
        FAIL("Parse failed");
        return;
    }

    if (strcmp(msg.method, "POST") != 0) {
        FAIL("Wrong method");
        return;
    }

    if (msg.content_length != 13) {
        FAIL("Wrong content length");
        return;
    }

    if (body_len != 13) {
        FAIL("Wrong body_len");
        return;
    }

    PASS();
}

static void test_parse_response(void) {
    TEST("http1_parse response");

    const char *response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "Hello";

    http_message_t msg = {0};
    uint8_t body_buf[1024];
    size_t body_len = 0;

    int result = http1_parse((const uint8_t *)response, strlen(response),
                             &msg, body_buf, sizeof(body_buf), &body_len);

    if (result < 0) {
        FAIL("Parse failed");
        return;
    }

    if (msg.status_code != 200) {
        FAIL("Wrong status code");
        return;
    }

    if (msg.direction != DIR_RESPONSE) {
        FAIL("Wrong direction");
        return;
    }

    if (msg.content_length != 5) {
        FAIL("Wrong content length");
        return;
    }

    PASS();
}

static void test_parse_chunked_response(void) {
    TEST("http1_parse chunked response");

    const char *response =
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "5\r\n"
        "Hello\r\n"
        "6\r\n"
        " World\r\n"
        "0\r\n"
        "\r\n";

    http_message_t msg = {0};
    uint8_t body_buf[1024];
    size_t body_len = 0;

    int result = http1_parse((const uint8_t *)response, strlen(response),
                             &msg, body_buf, sizeof(body_buf), &body_len);

    if (result < 0) {
        FAIL("Parse failed");
        return;
    }

    if (msg.status_code != 200) {
        FAIL("Wrong status code");
        return;
    }

    PASS();
}

static void test_parse_status_codes(void) {
    TEST("http1_parse various status codes");

    struct {
        const char *response;
        int expected_code;
    } tests[] = {
        { "HTTP/1.1 100 Continue\r\n\r\n", 100 },
        { "HTTP/1.1 201 Created\r\n\r\n", 201 },
        { "HTTP/1.1 301 Moved\r\n\r\n", 301 },
        { "HTTP/1.1 400 Bad Request\r\n\r\n", 400 },
        { "HTTP/1.1 404 Not Found\r\n\r\n", 404 },
        { "HTTP/1.1 500 Server Error\r\n\r\n", 500 },
        { "HTTP/1.1 503 Unavailable\r\n\r\n", 503 },
    };

    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        http_message_t msg = {0};
        uint8_t body_buf[256];
        size_t body_len = 0;

        int result = http1_parse((const uint8_t *)tests[i].response,
                                 strlen(tests[i].response),
                                 &msg, body_buf, sizeof(body_buf), &body_len);

        if (result < 0 || msg.status_code != tests[i].expected_code) {
            char buf[64];
            snprintf(buf, sizeof(buf), "Status %d: got %d",
                     tests[i].expected_code, msg.status_code);
            FAIL(buf);
            return;
        }
    }

    PASS();
}

static void test_parse_headers(void) {
    TEST("http1_parse header extraction");

    const char *request =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/json\r\n"
        "X-Custom: value\r\n"
        "\r\n";

    http_message_t msg = {0};
    uint8_t body_buf[256];
    size_t body_len = 0;

    int result = http1_parse((const uint8_t *)request, strlen(request),
                             &msg, body_buf, sizeof(body_buf), &body_len);

    if (result < 0) {
        FAIL("Parse failed");
        return;
    }

    if (msg.header_count < 3) {
        FAIL("Not enough headers parsed");
        return;
    }

    /* Check host was extracted to authority */
    if (strcmp(msg.authority, "example.com") != 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "Wrong authority: '%s'", msg.authority);
        FAIL(buf);
        return;
    }

    PASS();
}

static void test_parse_null_body_buf(void) {
    TEST("http1_parse NULL body buffer");

    const char *request = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
    http_message_t msg = {0};

    /* Should work with NULL body buffer */
    int result = http1_parse((const uint8_t *)request, strlen(request),
                             &msg, NULL, 0, NULL);

    if (result < 0) {
        FAIL("Parse failed with NULL body buffer");
        return;
    }

    if (msg.direction != DIR_REQUEST) {
        FAIL("Wrong direction");
        return;
    }

    PASS();
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    printf("=== HTTP/1.x Parser Tests (llhttp) ===\n\n");

    /* Detection tests */
    test_is_request();
    test_is_response();
    test_detection_short_data();

    /* Parsing tests */
    test_parse_get_request();
    test_parse_post_request();
    test_parse_response();
    test_parse_chunked_response();
    test_parse_status_codes();
    test_parse_headers();
    test_parse_null_body_buf();

    printf("\n");
    if (failures == 0) {
        printf("\033[32mAll tests passed!\033[0m\n");
        return 0;
    } else {
        printf("\033[31m%d test(s) failed\033[0m\n", failures);
        return 1;
    }
}
