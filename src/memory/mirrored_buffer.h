/**
 * @file mirrored_buffer.h
 * @brief Zero-copy ring buffer with mirrored virtual memory
 *
 * @details Implements virtual memory mirroring to eliminate wrap-around
 * branching in ring buffer operations. The same physical pages are mapped
 * twice consecutively in virtual address space, so reads across the
 * boundary succeed without special-case code.
 *
 * @par How It Works:
 * @code
 * Virtual Address Space:
 * +------------------+------------------+
 * |   First Half     |   Second Half    |
 * |   (Base)         |   (Mirror)       |
 * +------------------+------------------+
 *         |                   |
 *         v                   v
 * Physical Pages:   [Same Pages Mapped Twice]
 *
 * Writing at offset >= size automatically wraps to beginning:
 *   memcpy(base + offset, data, len)  // No branch needed!
 * @endcode
 *
 * @par Data Race Protection:
 * Atomic counters only protect the index values, NOT the payload data.
 * To prevent data races on the 256KB payload, use the buffer state machine:
 *
 * @code
 * State Machine:
 * IDLE ──(claim)──► WRITING ──(commit)──► READY ──(consume)──► IDLE
 *
 * Producer (eBPF):
 *   1. Atomically set state: IDLE → WRITING (claim buffer)
 *   2. Copy payload data
 *   3. Atomically set state: WRITING → READY (signal completion)
 *
 * Consumer (Userspace):
 *   1. Check state == READY before reading
 *   2. Read payload data
 *   3. Atomically set state: READY → IDLE (release buffer)
 * @endcode
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef SPLIFF_MIRRORED_BUFFER_H
#define SPLIFF_MIRRORED_BUFFER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @defgroup mirrored_buffer Mirrored Ring Buffer
 * @brief Zero-copy ring buffer implementation using virtual memory mirroring
 * @{
 */

/**
 * @brief Buffer state for data race protection
 *
 * Ensures producer completes payload write before consumer reads.
 * State transitions must use atomic exchange operations.
 */
typedef enum {
    BUF_STATE_IDLE = 0,    /**< Buffer available for producer to claim */
    BUF_STATE_WRITING,     /**< Producer is writing payload (do not read) */
    BUF_STATE_READY,       /**< Payload complete, ready for consumer */
    BUF_STATE_READING      /**< Consumer is reading (optional, for debugging) */
} buf_state_t;

/**
 * @brief Mirrored virtual memory buffer
 *
 * This structure holds a ring buffer backed by mirrored virtual memory.
 * The same physical pages are mapped twice consecutively, allowing
 * wrap-around operations without branching.
 *
 * @warning Atomics protect state transitions, NOT payload data.
 *          Always check state == BUF_STATE_READY before reading payload.
 *
 * @note The structure itself does not contain the buffer data; it holds
 *       metadata and a pointer to the mapped memory region.
 */
typedef struct {
    void *base;           /**< Base address of the buffer (first mapping) */
    size_t size;          /**< Size of the buffer in bytes (power of 2) */
    size_t mask;          /**< Wrap-around mask: size - 1 */
    int memfd;            /**< File descriptor for memfd backing */
    bool use_hugepages;   /**< True if allocated with hugepages */

    /* Data race protection */
    uint32_t state;       /**< Current buffer state (use atomic access) */
    uint32_t _pad;        /**< Padding for alignment */

    /* Producer/consumer coordination */
    uint64_t write_offset; /**< Current write position (atomic) */
    uint64_t write_len;    /**< Length of current write (set before READY) */
} mirrored_buffer_t;

/**
 * @brief Create a mirrored virtual memory buffer
 *
 * Allocates a ring buffer using virtual memory mirroring. The buffer is
 * backed by anonymous memory (memfd) and mapped twice consecutively.
 *
 * @param size Buffer size in bytes. Must be:
 *             - Power of 2 (enforced)
 *             - Multiple of system page size (enforced)
 *             - Between MIN_BUFFER_SIZE and MAX_BUFFER_SIZE (validated)
 *
 * @return Pointer to mirrored_buffer_t on success, NULL on failure
 *
 * @retval NULL If size is not power of 2
 * @retval NULL If size < MIN_BUFFER_SIZE or > MAX_BUFFER_SIZE
 * @retval NULL If memfd_create() fails
 * @retval NULL If mmap() fails for either mapping
 *
 * @note Caller must call mirrored_buffer_destroy() to free resources.
 * @note Buffer is initialized in BUF_STATE_IDLE state.
 */
mirrored_buffer_t *mirrored_buffer_create(size_t size);

/**
 * @brief Create a mirrored buffer with hugepage support
 *
 * Attempts to create the buffer using 2MB hugepages for reduced TLB
 * pressure. Falls back to regular pages if hugepages are unavailable.
 *
 * @param size Buffer size in bytes (must be power of 2)
 * @param prefer_hugepages If true, attempt hugepage allocation first
 *
 * @return Pointer to mirrored_buffer_t on success, NULL on failure
 *
 * @note Check buf->use_hugepages to determine if hugepages were used.
 */
mirrored_buffer_t *mirrored_buffer_create_ex(size_t size, bool prefer_hugepages);

/**
 * @brief Destroy a mirrored buffer and free all resources
 *
 * Unmaps both virtual memory mappings, closes the memfd file descriptor,
 * and frees the mirrored_buffer_t structure.
 *
 * @param buf Pointer to buffer to destroy (may be NULL, no-op)
 *
 * @note Safe to call with NULL pointer.
 * @note After this call, the buf pointer is invalid.
 */
void mirrored_buffer_destroy(mirrored_buffer_t *buf);

/*============================================================================
 * State Machine Operations (Data Race Protection)
 *============================================================================*/

/**
 * @brief Claim buffer for writing (IDLE → WRITING)
 *
 * Producer must call this before writing any payload data.
 * Uses atomic compare-exchange to prevent race conditions.
 *
 * @param buf Pointer to mirrored buffer
 * @return true if successfully claimed, false if buffer not idle
 *
 * @note If this returns false, another producer is writing or
 *       consumer hasn't finished reading. Retry or use another buffer.
 */
static inline bool mirrored_buffer_claim(mirrored_buffer_t *buf) {
    if (!buf) return false;
    uint32_t expected = BUF_STATE_IDLE;
    return __atomic_compare_exchange_n(&buf->state, &expected, BUF_STATE_WRITING,
                                       false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
}

/**
 * @brief Commit buffer after writing (WRITING → READY)
 *
 * Producer must call this AFTER all payload data is written.
 * This signals to consumers that the payload is complete.
 *
 * @param buf Pointer to mirrored buffer
 * @param offset Write position where data starts
 * @param len    Length of data written
 *
 * @note Uses release semantics to ensure all prior writes are visible
 *       to consumers who see the READY state.
 */
static inline void mirrored_buffer_commit(mirrored_buffer_t *buf,
                                          uint64_t offset,
                                          uint64_t len) {
    if (!buf) return;
    /* Store offset and length before signaling ready */
    __atomic_store_n(&buf->write_offset, offset, __ATOMIC_RELAXED);
    __atomic_store_n(&buf->write_len, len, __ATOMIC_RELAXED);
    /* Release fence + state change ensures payload writes are visible */
    __atomic_store_n(&buf->state, BUF_STATE_READY, __ATOMIC_RELEASE);
}

/**
 * @brief Check if buffer is ready for reading
 *
 * Consumer should poll this before accessing payload data.
 *
 * @param buf Pointer to mirrored buffer
 * @return true if state == READY, false otherwise
 *
 * @note Uses acquire semantics to ensure payload writes are visible
 *       after seeing READY state.
 */
static inline bool mirrored_buffer_is_ready(const mirrored_buffer_t *buf) {
    if (!buf) return false;
    return __atomic_load_n(&buf->state, __ATOMIC_ACQUIRE) == BUF_STATE_READY;
}

/**
 * @brief Release buffer after reading (READY → IDLE)
 *
 * Consumer must call this AFTER reading payload data.
 * This returns the buffer to the producer pool.
 *
 * @param buf Pointer to mirrored buffer
 *
 * @note Only call after confirming state was READY.
 */
static inline void mirrored_buffer_release(mirrored_buffer_t *buf) {
    if (!buf) return;
    __atomic_store_n(&buf->state, BUF_STATE_IDLE, __ATOMIC_RELEASE);
}

/**
 * @brief Get current buffer state
 *
 * @param buf Pointer to mirrored buffer
 * @return Current state, or BUF_STATE_IDLE if buf is NULL
 */
static inline buf_state_t mirrored_buffer_get_state(const mirrored_buffer_t *buf) {
    if (!buf) return BUF_STATE_IDLE;
    return (buf_state_t)__atomic_load_n(&buf->state, __ATOMIC_ACQUIRE);
}

/*============================================================================
 * Buffer Access Operations
 *============================================================================*/

/**
 * @brief Get wrapped offset within buffer bounds
 *
 * Applies the wrap-around mask to convert any offset to a valid
 * position within the buffer. Uses fast bitwise AND.
 *
 * @param buf    Pointer to mirrored buffer
 * @param offset Raw offset (may exceed buffer size)
 *
 * @return Wrapped offset in range [0, size)
 *
 * @note Equivalent to: offset % size, but faster for power-of-2 sizes
 */
static inline size_t mirrored_buffer_wrap(const mirrored_buffer_t *buf,
                                          size_t offset) {
    return offset & buf->mask;
}

/**
 * @brief Write data to buffer at offset (handles wrap-around)
 *
 * Copies data to the buffer starting at the given offset. Because the
 * buffer is mirrored, writes that cross the buffer boundary automatically
 * wrap to the beginning without special handling.
 *
 * @param buf    Pointer to mirrored buffer
 * @param offset Write position (will be wrapped if >= size)
 * @param data   Source data to copy
 * @param len    Number of bytes to write
 *
 * @return Number of bytes written (always len if buf is valid)
 *
 * @warning Caller MUST have claimed the buffer first (state == WRITING)
 * @warning len must not exceed buf->size, or data will be overwritten
 */
static inline size_t mirrored_buffer_write(mirrored_buffer_t *buf,
                                           size_t offset,
                                           const void *data,
                                           size_t len) {
    if (!buf || !data || len == 0) {
        return 0;
    }
    /* Wrap offset to valid range, then write using mirror property */
    size_t pos = offset & buf->mask;
    __builtin_memcpy((char *)buf->base + pos, data, len);
    return len;
}

/**
 * @brief Read data from buffer at offset (handles wrap-around)
 *
 * Copies data from the buffer starting at the given offset. Because the
 * buffer is mirrored, reads that cross the buffer boundary automatically
 * wrap to the beginning without special handling.
 *
 * @param buf    Pointer to mirrored buffer
 * @param offset Read position (will be wrapped if >= size)
 * @param dest   Destination buffer for data
 * @param len    Number of bytes to read
 *
 * @return Number of bytes read (always len if buf is valid)
 *
 * @warning Caller MUST verify state == READY before reading
 * @warning len must not exceed buf->size
 */
static inline size_t mirrored_buffer_read(const mirrored_buffer_t *buf,
                                          size_t offset,
                                          void *dest,
                                          size_t len) {
    if (!buf || !dest || len == 0) {
        return 0;
    }
    size_t pos = offset & buf->mask;
    __builtin_memcpy(dest, (const char *)buf->base + pos, len);
    return len;
}

/**
 * @brief Get pointer to data at offset (valid for mirrored access)
 *
 * Returns a pointer to the buffer location at the given offset.
 * For reads up to buf->size bytes, the mirrored region handles wrap-around.
 *
 * @param buf    Pointer to mirrored buffer
 * @param offset Position in buffer (will be wrapped)
 *
 * @return Pointer to data at wrapped offset, or NULL if buf is NULL
 *
 * @warning Caller MUST verify state == READY before dereferencing
 * @note The returned pointer remains valid until buffer is destroyed.
 */
static inline void *mirrored_buffer_at(const mirrored_buffer_t *buf,
                                       size_t offset) {
    if (!buf) {
        return NULL;
    }
    return (char *)buf->base + (offset & buf->mask);
}

/**
 * @brief Get committed write info (after state == READY)
 *
 * Retrieves the offset and length of the last committed write.
 *
 * @param buf    Pointer to mirrored buffer
 * @param offset Output: write offset (may be NULL)
 * @param len    Output: write length (may be NULL)
 *
 * @note Only valid when state == READY
 */
static inline void mirrored_buffer_get_write_info(const mirrored_buffer_t *buf,
                                                  uint64_t *offset,
                                                  uint64_t *len) {
    if (!buf) return;
    if (offset) *offset = __atomic_load_n(&buf->write_offset, __ATOMIC_RELAXED);
    if (len) *len = __atomic_load_n(&buf->write_len, __ATOMIC_RELAXED);
}

/**
 * @brief Pre-fault all pages and optionally lock against swapping
 *
 * Touches every page in the buffer to force the kernel to allocate
 * physical pages immediately. When @p lock is true, also calls mlock()
 * to prevent the kernel from evicting these pages under memory pressure.
 *
 * @par Why Pre-Fault?
 * After mmap(), pages are demand-allocated on first access. A page fault
 * during the hot path adds ~2-4us latency (minor fault) or worse if the
 * page must be read from disk. Pre-faulting moves this cost to init time.
 *
 * @par SPMC Ring Note
 * spmc_ring_create() already pre-faults slot pages via the Vyukov sequence
 * init loop (writing seq=i to every slot). This function is for standalone
 * mirrored buffer users (e.g., future metadata slabs, payload staging).
 *
 * @param buf   Mirrored buffer to pre-fault (must not be NULL)
 * @param lock  If true, also mlock() pages against swapping (best-effort)
 * @return true on success, false if buf is NULL or has no base mapping
 */
bool mirrored_buffer_prefault(mirrored_buffer_t *buf, bool lock);

/**
 * @brief Check if buffer was allocated with hugepages
 *
 * @param buf Pointer to mirrored buffer
 * @return true if hugepages are in use, false otherwise
 */
static inline bool mirrored_buffer_has_hugepages(const mirrored_buffer_t *buf) {
    return buf ? buf->use_hugepages : false;
}

/** @} */ /* end of mirrored_buffer group */

#endif /* SPLIFF_MIRRORED_BUFFER_H */
