/**
 * @file deferred.c
 * @brief Per-worker deferred display queue for XDP correlation
 *
 * Implements the "Slide & Flush" strategy with adaptive timeout for
 * guaranteed XDP correlation on all HTTP output. Messages wait up to
 * 100ms for XDP data (20ms under load); if it doesn't arrive, they're
 * displayed with XDP_NOT_FOUND status.
 *
 * @par Design Rationale
 * The User-space Probe (SSL) and XDP program run on different CPU cores
 * and feed into different ring buffers. HTTP data often arrives in
 * user-space before XDP updates the flow. This queue synchronizes the
 * two asynchronous streams.
 *
 * @par Thread Safety
 * Each worker owns its queue (SPSC pattern) - no locks needed.
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license LGPL-3.0-only
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

#include "deferred.h"
#include "../correlation/ck_cookie_index.h"
#include "../output/display.h"
#include "../output/logger.h"
#include "../util/safe_str.h"

#include <stdlib.h>
#include <string.h>
#include <stddef.h>  /* For offsetof */

/**
 * @brief Allocate entry from free list or heap
 *
 * FIX L3: Use cache-line aligned allocation to prevent false sharing
 * when multiple workers operate on adjacent entries.
 *
 * @param[in] q Queue with free list
 * @return Allocated entry or NULL (cache-line aligned)
 */
static deferred_msg_t *deferred_alloc(deferred_queue_t *q) {
    deferred_msg_t *entry = q->free_list;
    if (entry) {
        q->free_list = entry->next;
        entry->next = NULL;
        return entry;
    }
    /* FIX L3: Use aligned_alloc for cache-line alignment (64 bytes)
     * to prevent false sharing between adjacent entries */
    entry = aligned_alloc(64, sizeof(deferred_msg_t));
    if (entry) {
        memset(entry, 0, sizeof(deferred_msg_t));
    }
    return entry;
}

/**
 * @brief Return entry to free list
 *
 * @param[in] q     Queue owning the free list
 * @param[in] entry Entry to return
 */
static void deferred_free(deferred_queue_t *q, deferred_msg_t *entry) {
    if (entry) {
        entry->next = q->free_list;
        q->free_list = entry;
    }
}

/**
 * @brief Calculate adaptive timeout based on queue fullness
 *
 * When queue exceeds 80% capacity, reduce timeout from 100ms to 20ms.
 * This is a "backpressure valve" that flushes logs faster under load,
 * reducing memory pressure and keeping the analyzer responsive.
 *
 * @param[in] q Queue to check
 * @return Timeout in nanoseconds
 */
static inline uint64_t deferred_get_timeout(const deferred_queue_t *q) {
    if (q->count > (size_t)(DEFERRED_QUEUE_MAX_ENTRIES * DEFERRED_LOAD_THRESHOLD)) {
        return DEFERRED_TIMEOUT_LOAD_NS;
    }
    return DEFERRED_TIMEOUT_NORMAL_NS;
}

/**
 * @brief Display a deferred message
 *
 * If XDP matched, copies latest flow info from flow context.
 * Uses the async logger for atomic output.
 *
 * @param[in] entry  Deferred entry to display
 * @param[in] status XDP correlation status
 */
static void deferred_display_msg(deferred_msg_t *entry, xdp_status_t status) {
    http_message_t *msg = &entry->msg;

    /* Copy XDP flow info if matched and context still valid */
    if (status == XDP_MATCHED && entry->flow_ctx &&
        entry->flow_ctx->generation == entry->expected_gen) {
        flow_context_t *fc = entry->flow_ctx;

        /* Populate flow info in message */
        msg->has_flow_info = true;
        msg->flow_src_ip = fc->flow.saddr;
        msg->flow_dst_ip = fc->flow.daddr;
        msg->flow_src_port = fc->flow.sport;
        msg->flow_dst_port = fc->flow.dport;
        msg->flow_ip_version = fc->flow.ip_version;
        msg->flow_category = fc->xdp_category;
        msg->flow_direction = fc->xdp_direction;
        safe_strcpy(msg->flow_ifname, sizeof(msg->flow_ifname), fc->ifname);
    }

    /* Display via standard functions (they use async logger internally) */
    if (msg->direction == DIR_REQUEST) {
        display_http_request(msg);
    } else {
        display_http_response(msg);
    }
}

int deferred_queue_init(deferred_queue_t *q, size_t prealloc) {
    if (!q) {
        return -1;
    }

    memset(q, 0, sizeof(*q));

    /* Pre-allocate free list entries to avoid malloc in hot path.
     * aligned_alloc requires size to be a multiple of alignment (C11 7.22.3.1). */
    size_t alloc_size = (sizeof(deferred_msg_t) + 63) & ~(size_t)63;
    for (size_t i = 0; i < prealloc; i++) {
        deferred_msg_t *entry = aligned_alloc(64, alloc_size);
        if (entry) {
            memset(entry, 0, sizeof(deferred_msg_t));
            entry->next = q->free_list;
            q->free_list = entry;
        }
    }

    return 0;
}

int deferred_enqueue(deferred_queue_t *q, const http_message_t *msg,
                     flow_context_t *flow_ctx, uint64_t now_ns) {
    if (!q || !msg) {
        return -1;
    }

    /* Force flush if queue is too full */
    if (q->count >= DEFERRED_QUEUE_MAX_ENTRIES) {
        deferred_force_flush(q);
    }

    deferred_msg_t *entry = deferred_alloc(q);
    if (!entry) {
        return -1;
    }

    /* Copy message data */
    memcpy(&entry->msg, msg, sizeof(http_message_t));
    entry->enqueue_ts = now_ns;
    entry->flow_ctx = flow_ctx;
    entry->expected_gen = flow_ctx ? flow_ctx->generation : 0;
    entry->next = NULL;

    /* Append to tail (FIFO order) */
    if (q->tail) {
        q->tail->next = entry;
    } else {
        q->head = entry;
    }
    q->tail = entry;
    q->count++;

    atomic_fetch_add(&q->stats.total_deferred, 1);

    return 0;
}

/**
 * @brief Try to find XDP data from cookie_index for a flow without XDP flag
 *
 * When XDP arrives after SSL flow is promoted, a separate XDP-only flow may
 * exist in cookie_index. This function looks for it and copies XDP metadata
 * into the message for display.
 *
 * @param[in]  flow_ctx  The SSL flow context
 * @param[out] msg       Message to populate with XDP data
 * @return true if XDP data was found and copied, false otherwise
 */
static bool deferred_try_xdp_lookup(flow_context_t *flow_ctx, http_message_t *msg) {
    if (!flow_ctx || flow_ctx->socket_cookie == 0) {
        return false;
    }

    threading_mgr_t *mgr = threading_get_manager();
    if (!mgr) {
        return false;
    }

    /* Look up cookie_index for a separate XDP flow with same cookie */
    flow_context_t *xdp_flow = ck_cookie_index_lookup(
        &mgr->dispatcher.flow_mgr.cookie_idx, flow_ctx->socket_cookie);

    if (!xdp_flow || xdp_flow == flow_ctx) {
        return false;  /* Same flow or not found */
    }

    /* Check if the other flow has XDP data */
    if (!(atomic_load(&xdp_flow->flags) & FLOW_FLAG_HAS_XDP)) {
        return false;
    }

    /* Copy XDP metadata to the message */
    msg->has_flow_info = true;
    msg->flow_src_ip = xdp_flow->flow.saddr;
    msg->flow_dst_ip = xdp_flow->flow.daddr;
    msg->flow_src_port = xdp_flow->flow.sport;
    msg->flow_dst_port = xdp_flow->flow.dport;
    msg->flow_ip_version = xdp_flow->flow.ip_version;
    msg->flow_category = xdp_flow->xdp_category;
    msg->flow_direction = xdp_flow->xdp_direction;
    safe_strcpy(msg->flow_ifname, sizeof(msg->flow_ifname), xdp_flow->ifname);

    return true;
}

size_t deferred_drain(deferred_queue_t *q, uint64_t now_ns) {
    if (!q || !q->head) {
        return 0;
    }

    const uint64_t timeout_ns = deferred_get_timeout(q);
    size_t displayed = 0;
    deferred_msg_t **pp = &q->head;

    while (*pp) {
        deferred_msg_t *entry = *pp;

        /* Check if flow context is still valid (generation match) */
        bool valid_ctx = entry->flow_ctx &&
                         entry->flow_ctx->generation == entry->expected_gen;

        /* Check if XDP data has arrived AND classification is complete.
         * We need both:
         * 1. FLOW_FLAG_HAS_XDP set (5-tuple info available)
         * 2. xdp_category != UNKNOWN (classification complete, not just AMBIGUOUS)
         *
         * This prevents the race where AMBIGUOUS events set HAS_XDP with category=0,
         * causing premature display before FLOW_NEW with proper category arrives. */
        bool has_xdp = valid_ctx &&
                       (atomic_load_explicit(&entry->flow_ctx->flags, memory_order_acquire) & FLOW_FLAG_HAS_XDP) &&
                       (entry->flow_ctx->xdp_category != XDP_CAT_UNKNOWN);

        /*
         * XDP Late Arrival Fix:
         * If SSL flow doesn't have XDP flag but has socket_cookie, a separate
         * XDP-only flow may exist in cookie_index (created when XDP arrived
         * after SSL was already promoted). Check for it and copy XDP data.
         */
        bool xdp_from_lookup = false;
        if (!has_xdp && valid_ctx && entry->flow_ctx->socket_cookie != 0) {
            xdp_from_lookup = deferred_try_xdp_lookup(entry->flow_ctx, &entry->msg);
        }

        /* Check if timeout exceeded */
        bool timed_out = (now_ns - entry->enqueue_ts) > timeout_ns;

        if (has_xdp || xdp_from_lookup) {
            /* XDP arrived in time - display with correlation */
            atomic_fetch_add(&q->stats.matched_xdp, 1);
            deferred_display_msg(entry, XDP_MATCHED);

            /* Remove from queue */
            *pp = entry->next;
            if (q->tail == entry) q->tail = (*pp == NULL) ? NULL : q->tail;
            if (!q->head) q->tail = NULL;
            q->count--;
            deferred_free(q, entry);
            displayed++;

        } else if (timed_out) {
            /* Timeout - display without XDP correlation */
            atomic_fetch_add(&q->stats.timed_out, 1);
            deferred_display_msg(entry, XDP_NOT_FOUND);

            /* Remove from queue */
            *pp = entry->next;
            if (q->tail == entry) q->tail = (*pp == NULL) ? NULL : q->tail;
            if (!q->head) q->tail = NULL;
            q->count--;
            deferred_free(q, entry);
            displayed++;

        } else {
            /* Still waiting - advance to next */
            pp = &entry->next;
        }
    }

    /* Fix tail pointer if queue became empty */
    if (!q->head) {
        q->tail = NULL;
    }

    return displayed;
}

size_t deferred_force_flush(deferred_queue_t *q) {
    if (!q || q->count < DEFERRED_QUEUE_MAX_ENTRIES) {
        return 0;
    }

    size_t flushed = 0;

    /* Flush oldest DEFERRED_FLUSH_BATCH entries */
    while (q->head && flushed < DEFERRED_FLUSH_BATCH) {
        deferred_msg_t *entry = q->head;

        atomic_fetch_add(&q->stats.forced_flush, 1);
        deferred_display_msg(entry, XDP_FORCED_FLUSH);

        q->head = entry->next;
        if (!q->head) q->tail = NULL;
        q->count--;
        deferred_free(q, entry);
        flushed++;
    }

    return flushed;
}

void deferred_get_stats(const worker_ctx_t *workers, int num_workers,
                        deferred_stats_t *out) {
    if (!workers || !out) {
        return;
    }

    memset(out, 0, sizeof(*out));

    for (int i = 0; i < num_workers; i++) {
        const deferred_stats_t *s = &workers[i].deferred.stats;
        atomic_fetch_add(&out->matched_xdp, atomic_load(&s->matched_xdp));
        atomic_fetch_add(&out->timed_out, atomic_load(&s->timed_out));
        atomic_fetch_add(&out->forced_flush, atomic_load(&s->forced_flush));
        atomic_fetch_add(&out->total_deferred, atomic_load(&s->total_deferred));
    }
}

void deferred_queue_cleanup(deferred_queue_t *q) {
    if (!q) {
        return;
    }

    /* Free all queued messages */
    while (q->head) {
        deferred_msg_t *entry = q->head;
        q->head = entry->next;
        free(entry);
    }

    /* Free all pre-allocated entries in free list */
    while (q->free_list) {
        deferred_msg_t *entry = q->free_list;
        q->free_list = entry->next;
        free(entry);
    }

    q->tail = NULL;
    q->count = 0;
}

/**
 * @brief container_of macro for getting parent structure
 *
 * Given a pointer to a member of a struct, returns a pointer to the
 * containing struct.
 */
#ifndef container_of
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#endif

deferred_queue_t *deferred_get_current_queue(void) {
    worker_state_t *state = get_current_worker_state();
    if (!state) {
        return NULL;
    }

    /* worker_state_t is embedded in worker_ctx_t at offset 'state' */
    worker_ctx_t *ctx = container_of(state, worker_ctx_t, state);
    return &ctx->deferred;
}

int deferred_display_or_enqueue(const http_message_t *msg,
                                flow_context_t *flow_ctx) {
    if (!msg) {
        return -1;
    }

    /* Check if XDP data is already available (acquire for visibility) */
    bool has_xdp = flow_ctx && (atomic_load_explicit(&flow_ctx->flags, memory_order_acquire) & FLOW_FLAG_HAS_XDP);

    if (has_xdp) {
        /* XDP ready - display immediately */
        if (msg->direction == DIR_REQUEST) {
            display_http_request(msg);
        } else {
            display_http_response(msg);
        }
        return 0;
    }

    /* No XDP yet - try to defer for later correlation */
    deferred_queue_t *q = deferred_get_current_queue();
    if (!q) {
        /* Not in worker thread - display immediately without XDP */
        if (msg->direction == DIR_REQUEST) {
            display_http_request(msg);
        } else {
            display_http_response(msg);
        }
        return 0;
    }

    /* Enqueue for deferred display */
    uint64_t now_ns = get_time_ns();
    return deferred_enqueue(q, msg, flow_ctx, now_ns);
}
