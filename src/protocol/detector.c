/**
 * @file detector.c
 * @brief Vectorscan-powered protocol detection implementation
 *
 * @copyright Copyright (C) 2025-2026 spliff authors
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * This module implements O(n) linear-time protocol detection using vectorscan's
 * NFA-based pattern matching. All patterns are compiled into a single database
 * at startup, and each thread uses its own scratch space for lock-free scanning.
 *
 * @par Pattern Design
 * Patterns are anchored to the start of data (^) to match the beginning of
 * packets. This is efficient because vectorscan can fail fast if the first
 * few bytes don't match any pattern.
 *
 * @par Thread Safety
 * - g_proto_db: Read-only after init, safe for concurrent access
 * - tls_scratch: Thread-local, no sharing
 * - No locks needed during scanning
 */

#include "detector.h"
#include "http1.h"
#include "http2.h"
#include <stdio.h>
#include <string.h>

/** @cond INTERNAL */
/*----------------------------------------------------------------------------
 * Branch Prediction Macros
 *
 * Use __builtin_expect for portable branch hints. GCC/Clang support this
 * while [[likely]]/[[unlikely]] C23 attributes have inconsistent support.
 *----------------------------------------------------------------------------*/
#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
/** @endcond */

#if defined(HAVE_VECTORSCAN) || defined(HAVE_HYPERSCAN)
#include <hs/hs.h>
#include <threads.h>  /* C23 thread-local storage */

/*============================================================================
 * Vectorscan/Hyperscan Implementation
 *============================================================================*/

/**
 * @brief Global pattern database (read-only after init)
 *
 * Compiled from PROTO_PATTERNS at startup. Thread-safe for concurrent reads.
 */
static hs_database_t *g_proto_db = NULL;

/**
 * @brief Thread-local scratch space
 *
 * Vectorscan requires per-thread scratch for thread safety. Using C23
 * thread_local ensures each worker thread gets its own scratch automatically.
 */
static thread_local hs_scratch_t *tls_scratch = NULL;

/*----------------------------------------------------------------------------
 * Pattern Definitions
 *----------------------------------------------------------------------------*/

/**
 * @brief Protocol detection patterns
 *
 * These patterns are compiled into a single NFA for O(n) matching.
 * Order matters for pattern IDs - they map to proto_detect_result_t.
 *
 * @note Patterns use PCRE syntax but vectorscan compiles them to NFA,
 *       so there's no backtracking performance penalty.
 */
static const char *PROTO_PATTERNS[] = {
    /* ID 0: HTTP/1.x Response - "HTTP/1.0 200" or "HTTP/1.1 404" etc. */
    "^HTTP/1\\.[01] [0-9]{3}",

    /* ID 1: HTTP/1.x Request - common methods followed by space */
    "^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) [^ ]+ HTTP/1\\.[01]",

    /* ID 2: HTTP/2 Connection Preface (24 bytes magic string) */
    "^PRI \\* HTTP/2\\.0\r\n\r\nSM\r\n\r\n",

    /* ID 3: TLS Record Header - ContentType (22=Handshake, 23=AppData) + Version */
    "^[\\x16\\x17]\\x03[\\x00-\\x03]",

    /* ID 4: WebSocket Frame - FIN+Opcode with mask bit set */
    "^[\\x81\\x82\\x88\\x89\\x8a][\\x80-\\xff]",
};

/** Number of patterns */
static const size_t PROTO_PATTERN_COUNT = sizeof(PROTO_PATTERNS) / sizeof(PROTO_PATTERNS[0]);

/** Pattern IDs matching proto_detect_result_t values */
static const unsigned int PROTO_PATTERN_IDS[] = {
    PROTO_DETECT_HTTP1_RSP,   /* Pattern 0 */
    PROTO_DETECT_HTTP1_REQ,   /* Pattern 1 */
    PROTO_DETECT_HTTP2,       /* Pattern 2 */
    PROTO_DETECT_TLS,         /* Pattern 3 */
    PROTO_DETECT_WEBSOCKET,   /* Pattern 4 */
};

/** Pattern flags - stop after first match */
static const unsigned int PROTO_PATTERN_FLAGS[] = {
    HS_FLAG_SINGLEMATCH,
    HS_FLAG_SINGLEMATCH,
    HS_FLAG_SINGLEMATCH,
    HS_FLAG_SINGLEMATCH,
    HS_FLAG_SINGLEMATCH,
};

/*----------------------------------------------------------------------------
 * Match Callback
 *----------------------------------------------------------------------------*/

/**
 * @brief Match context for callback
 */
struct match_ctx {
    proto_detect_result_t result;  /**< Detection result */
};

/**
 * @brief Vectorscan match callback
 *
 * Called when a pattern matches. Sets the result and stops scanning.
 *
 * @param id       Pattern ID (maps to proto_detect_result_t)
 * @param from     Match start offset (unused)
 * @param to       Match end offset (unused)
 * @param flags    Match flags (unused)
 * @param context  Pointer to match_ctx
 *
 * @return 1 to stop scanning (we only need first match)
 */
static int on_match(unsigned int id,
                    unsigned long long from [[maybe_unused]],
                    unsigned long long to [[maybe_unused]],
                    unsigned int flags [[maybe_unused]],
                    void *context) {
    struct match_ctx *ctx = (struct match_ctx *)context;
    ctx->result = (proto_detect_result_t)id;
    return 1;  /* Stop scanning - first match wins */
}

/*----------------------------------------------------------------------------
 * Public API
 *----------------------------------------------------------------------------*/

int proto_detector_init(void) {
    hs_compile_error_t *error = NULL;

    hs_error_t ret = hs_compile_multi(
        PROTO_PATTERNS,
        PROTO_PATTERN_FLAGS,
        PROTO_PATTERN_IDS,
        (unsigned int)PROTO_PATTERN_COUNT,
        HS_MODE_BLOCK,
        NULL,  /* Use default platform tuning */
        &g_proto_db,
        &error
    );

    if (unlikely(ret != HS_SUCCESS)) {
        fprintf(stderr, "[DETECTOR] Pattern compile failed: %s\n",
                error ? error->message : "unknown error");
        hs_free_compile_error(error);
        return -1;
    }

    /* Success - no output in release mode (engine name available via proto_detector_engine_name()) */
    return 0;
}

void proto_detector_cleanup(void) {
    /* Clean up main thread's scratch (if any) */
    proto_detector_thread_cleanup();

    if (g_proto_db) {
        hs_free_database(g_proto_db);
        g_proto_db = NULL;
    }
}

void proto_detector_thread_cleanup(void) {
    /* Free this thread's scratch space */
    if (tls_scratch) {
        hs_free_scratch(tls_scratch);
        tls_scratch = NULL;
    }
}

/**
 * @brief Get or allocate thread-local scratch
 *
 * @return Scratch pointer, or NULL on allocation failure
 */
static hs_scratch_t *get_scratch(void) {
    if (unlikely(!tls_scratch && g_proto_db)) {
        if (hs_alloc_scratch(g_proto_db, &tls_scratch) != HS_SUCCESS) {
            fprintf(stderr, "[DETECTOR] Failed to allocate scratch for thread\n");
            return NULL;
        }
    }
    return tls_scratch;
}

proto_detect_result_t proto_detect(const uint8_t *restrict data, size_t len) {
    /* Early exit for invalid input */
    if (unlikely(!g_proto_db || !data || len == 0)) {
        return PROTO_DETECT_UNKNOWN;
    }

    hs_scratch_t *scratch = get_scratch();
    if (unlikely(!scratch)) {
        return PROTO_DETECT_UNKNOWN;
    }

    struct match_ctx ctx = { .result = PROTO_DETECT_UNKNOWN };

    /* Scan - O(n) linear time */
    hs_scan(g_proto_db, (const char *)data, (unsigned int)len, 0,
            scratch, on_match, &ctx);

    return ctx.result;
}

flow_proto_t proto_detect_and_init(flow_context_t *restrict ctx,
                                    const uint8_t *restrict data,
                                    size_t len) {
    if (!ctx) {
        return FLOW_PROTO_UNKNOWN;
    }

    /* Already detected - return cached value (hot path) */
    if (likely(ctx->proto != FLOW_PROTO_UNKNOWN)) {
        return ctx->proto;
    }

    /* Run vectorscan detection */
    proto_detect_result_t result = proto_detect(data, len);

    /* Map detection result to flow protocol */
    switch (result) {
        case PROTO_DETECT_HTTP1_REQ:
        case PROTO_DETECT_HTTP1_RSP:
            ctx->proto = FLOW_PROTO_HTTP1;
            break;

        case PROTO_DETECT_HTTP2:
            ctx->proto = FLOW_PROTO_HTTP2;
            break;

        case PROTO_DETECT_TLS:
        case PROTO_DETECT_WEBSOCKET:
        case PROTO_DETECT_UNKNOWN:
        default:
            /* Leave as UNKNOWN - might be encrypted or binary */
            break;
    }

    return ctx->proto;
}

const char *proto_detector_engine_name(void) {
#if defined(HAVE_VECTORSCAN)
    return "vectorscan";
#else
    return "hyperscan";
#endif
}

bool proto_detector_is_nfa_engine(void) {
    return true;
}

#else /* Fallback: No vectorscan/hyperscan */

/*============================================================================
 * Manual Fallback Implementation
 *============================================================================*/

/**
 * @brief Fallback initialization (no-op)
 */
int proto_detector_init(void) {
    fprintf(stderr, "[DETECTOR] Using manual fallback (vectorscan not available)\n");
    return 0;
}

/**
 * @brief Fallback cleanup (no-op)
 */
void proto_detector_cleanup(void) {
    /* Nothing to clean up in fallback mode */
}

/**
 * @brief Fallback thread cleanup (no-op)
 */
void proto_detector_thread_cleanup(void) {
    /* Nothing to clean up in fallback mode */
}

/**
 * @brief Manual protocol detection
 *
 * Uses existing http1_is_request(), http2_is_preface() etc.
 * This is O(n) but not as optimized as vectorscan's NFA.
 */
proto_detect_result_t proto_detect(const uint8_t *restrict data, size_t len) {
    if (!data || len == 0) {
        return PROTO_DETECT_UNKNOWN;
    }

    /* HTTP/1.x detection */
    if (http1_is_request(data, len)) {
        return PROTO_DETECT_HTTP1_REQ;
    }
    if (http1_is_response(data, len)) {
        return PROTO_DETECT_HTTP1_RSP;
    }

    /* HTTP/2 detection */
    if (http2_is_preface(data, len)) {
        return PROTO_DETECT_HTTP2;
    }

    /* TLS detection (simple check for ContentType + Version) */
    if (len >= 3 &&
        (data[0] == 0x16 || data[0] == 0x17) &&  /* Handshake or AppData */
        data[1] == 0x03 &&                        /* SSL/TLS major version */
        data[2] <= 0x03) {                        /* Minor version 0-3 */
        return PROTO_DETECT_TLS;
    }

    /* WebSocket frame detection (FIN + opcode with mask) */
    if (len >= 2 &&
        (data[0] >= 0x81 && data[0] <= 0x8a) &&  /* FIN + text/binary/ping/pong */
        (data[1] & 0x80)) {                       /* Mask bit set */
        return PROTO_DETECT_WEBSOCKET;
    }

    return PROTO_DETECT_UNKNOWN;
}

flow_proto_t proto_detect_and_init(flow_context_t *restrict ctx,
                                    const uint8_t *restrict data,
                                    size_t len) {
    if (!ctx) {
        return FLOW_PROTO_UNKNOWN;
    }

    /* Already detected - return cached value */
    if (ctx->proto != FLOW_PROTO_UNKNOWN) {
        return ctx->proto;
    }

    /* Run manual detection */
    proto_detect_result_t result = proto_detect(data, len);

    /* Map to flow protocol */
    switch (result) {
        case PROTO_DETECT_HTTP1_REQ:
        case PROTO_DETECT_HTTP1_RSP:
            ctx->proto = FLOW_PROTO_HTTP1;
            break;

        case PROTO_DETECT_HTTP2:
            ctx->proto = FLOW_PROTO_HTTP2;
            break;

        default:
            break;
    }

    return ctx->proto;
}

const char *proto_detector_engine_name(void) {
    return "manual";
}

bool proto_detector_is_nfa_engine(void) {
    return false;
}

#endif /* HAVE_VECTORSCAN || HAVE_HYPERSCAN */
