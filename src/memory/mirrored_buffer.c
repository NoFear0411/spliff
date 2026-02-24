/**
 * @file mirrored_buffer.c
 * @brief Implementation of zero-copy ring buffer with mirrored virtual memory
 *
 * @details Uses Linux memfd_create() to create anonymous file-backed memory,
 * then maps the same file twice consecutively in virtual address space.
 * This enables wrap-around operations without branching.
 *
 * @par Implementation Strategy (Thread-Safe):
 * 1. Reserve 2×size virtual space with MAP_ANONYMOUS | PROT_NONE
 * 2. Punch through first mapping with MAP_FIXED at base
 * 3. Punch through second mapping with MAP_FIXED at base+size
 * 4. Seal the memfd to prevent resizing (EDR safety)
 *
 * @par Memory Layout:
 * @code
 * Virtual:   [First Mapping][Second Mapping]
 *            |             ||             |
 * Physical:  [  Same Pages  ]
 * @endcode
 *
 * @par Why Mirrored Buffers Matter for the Dispatcher:
 * Standard buffer: 100-byte packet at offset 1000 (buffer size 1024)
 *   → Must split: 24 bytes at end, 76 bytes at beginning (2 memcpy)
 *
 * Mirrored buffer: Write 100 bytes at base + 1000
 *   → Hardware handles wrap (base+1024 maps to base+0)
 *   → Single memcpy, no branching
 *
 * @see mirrored_buffer.h for API documentation
 *
 * @author spliff authors
 * @copyright 2025-2026 spliff authors
 * @license LGPL-3.0-only
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

/* _GNU_SOURCE defined via CMake for memfd_create, MAP_FIXED, fcntl seals */

#include "mirrored_buffer.h"
#include "alignment.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/memfd.h>  /* For MFD_* and F_SEAL_* constants */

/*
 * memfd and seal constants - define if not available in headers
 */
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC       0x0001U
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

#ifndef MFD_HUGETLB
#define MFD_HUGETLB       0x0004U
#endif

/*
 * MFD_HUGE_2MB: Explicitly request 2MB hugepages
 * This is the "sweet spot" - 1GB pages are brittle due to memory fragmentation.
 * 2MB provides 99% TLB reduction while remaining reliable across server fleets.
 *
 * Encoding: (log2(2MB) - log2(4KB)) << MFD_HUGE_SHIFT = (21 - 12) << 26
 */
#ifndef MFD_HUGE_SHIFT
#define MFD_HUGE_SHIFT    26
#endif

#ifndef MFD_HUGE_2MB
#define MFD_HUGE_2MB      (21U << MFD_HUGE_SHIFT)  /* 2^21 = 2MB */
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS       (1024 + 9)
#endif

#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK     0x0002
#endif

#ifndef F_SEAL_GROW
#define F_SEAL_GROW       0x0004
#endif

/**
 * @brief Validate buffer size constraints
 *
 * Checks that size is:
 * - Non-zero
 * - Power of two (required for bitwise wrap-around)
 * - Within allowed range [MIN_BUFFER_SIZE, MAX_BUFFER_SIZE]
 *
 * @param size Size to validate
 * @return true if valid, false otherwise
 */
static bool validate_size(size_t size) {
    if (size == 0) {
        return false;
    }
    if (!IS_POWER_OF_TWO(size)) {
        return false;
    }
    if (size < MIN_BUFFER_SIZE || size > MAX_BUFFER_SIZE) {
        return false;
    }
    return true;
}

/**
 * @brief Get system page size (cached)
 *
 * @return Page size in bytes
 */
static size_t get_page_size(void) {
    static size_t page_size = 0;
    if (page_size == 0) {
        long ps = sysconf(_SC_PAGESIZE);
        page_size = (ps > 0) ? (size_t)ps : 4096;
    }
    return page_size;
}

/**
 * @brief Align size up to page boundary
 *
 * @param size Size to align
 * @return Size rounded up to next page boundary
 */
static size_t align_to_page(size_t size) {
    size_t page_size = get_page_size();
    return (size + page_size - 1) & ~(page_size - 1);
}

/**
 * @brief Seal memfd to prevent resizing
 *
 * Critical for EDR safety: prevents other processes (or even the same
 * process in another thread) from resizing the underlying memory, which
 * would invalidate our virtual address mappings.
 *
 * @param memfd File descriptor to seal
 * @return 0 on success, -1 on failure (check errno)
 */
static int seal_memfd(int memfd) {
    /*
     * F_SEAL_SHRINK: Prevent truncate to smaller size
     * F_SEAL_GROW:   Prevent extending the file
     *
     * These seals ensure the memfd size is immutable, protecting
     * our virtual address mappings from invalidation.
     */
    return fcntl(memfd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW);
}

mirrored_buffer_t *mirrored_buffer_create(size_t size) {
    return mirrored_buffer_create_ex(size, false);
}

mirrored_buffer_t *mirrored_buffer_create_ex(size_t size, bool prefer_hugepages) {
    /* Validate size constraints */
    if (!validate_size(size)) {
        return NULL;
    }

    /* Ensure size is page-aligned (always true for power-of-2 >= 64KB) */
    size_t aligned_size = align_to_page(size);
    if (aligned_size != size) {
        size = aligned_size;
    }

    /* Allocate the control structure */
    mirrored_buffer_t *buf = calloc(1, sizeof(mirrored_buffer_t));
    if (!buf) {
        return NULL;
    }

    buf->size = size;
    buf->mask = size - 1;  /* For fast wrap: offset & mask */
    buf->memfd = -1;
    buf->state = BUF_STATE_IDLE;
    buf->use_hugepages = false;

    /*
     * Step 1: Create anonymous file with memfd_create()
     *
     * MFD_CLOEXEC:       Close on exec - prevents hugepage leaks to child
     *                    processes; critical for EDR stability (if 128
     *                    hugepages are "lost," other services may fail)
     * MFD_ALLOW_SEALING: Required to add seals later
     * MFD_HUGETLB:       Use hugepages for reduced TLB pressure
     * MFD_HUGE_2MB:      Explicitly request 2MB pages (the "sweet spot")
     *                    - 1GB pages are brittle due to memory fragmentation
     *                    - 2MB provides 99% TLB reduction with high reliability
     */
    unsigned int mfd_flags = MFD_CLOEXEC | MFD_ALLOW_SEALING;
    if (prefer_hugepages) {
        mfd_flags |= MFD_HUGETLB | MFD_HUGE_2MB;
    }

    buf->memfd = memfd_create("spliff_mirrored", mfd_flags);
    if (buf->memfd < 0) {
        if (prefer_hugepages && (errno == EINVAL || errno == ENOMEM)) {
            /*
             * Hugepages not available or insufficient, retry without.
             * Common causes:
             * - /proc/sys/vm/nr_hugepages not configured
             * - All hugepages already in use by other services
             * - Kernel built without CONFIG_HUGETLB_PAGE
             */
            mfd_flags &= ~(MFD_HUGETLB | MFD_HUGE_2MB);
            buf->memfd = memfd_create("spliff_mirrored", mfd_flags);
        }
        if (buf->memfd < 0) {
            free(buf);
            return NULL;
        }
    } else if (prefer_hugepages) {
        buf->use_hugepages = true;
    }

    /*
     * Step 2: Size the anonymous file
     */
    if (ftruncate(buf->memfd, (off_t)size) < 0) {
        close(buf->memfd);
        free(buf);
        return NULL;
    }

    /*
     * Step 3: Seal the memfd (EDR safety)
     *
     * This MUST happen after ftruncate and before mapping.
     * Sealing prevents any process from resizing the underlying memory,
     * which would invalidate our carefully constructed virtual mappings.
     */
    if (seal_memfd(buf->memfd) < 0) {
        /*
         * Sealing failed — continue for older kernels (< 3.17) that
         * lack F_ADD_SEALS support. For EDR use, this means another
         * thread or process could ftruncate the memfd and corrupt
         * our mappings. Always warn, not just in debug builds.
         */
        fprintf(stderr, "[WARN] memfd sealing failed (errno=%d): "
                        "ring memory not protected against resize\n", errno);
    }

    /*
     * Step 4: Reserve virtual address space for 2×size
     *
     * Use PROT_NONE to "claim" the contiguous virtual space.
     * No other thread or kernel allocation can use this range.
     * The mmap base address will be page-aligned (4KB), which
     * satisfies our 128-byte cache line alignment requirement.
     */
    void *reserved = mmap(NULL, size * 2, PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reserved == MAP_FAILED) {
        close(buf->memfd);
        free(buf);
        return NULL;
    }

    /*
     * Step 5: Map the memfd at the start of reserved region
     *
     * MAP_FIXED: "I know what I'm doing, use exactly this address"
     * MAP_SHARED: Changes visible to both mappings (required for mirroring)
     *
     * This is the "first half" - the primary buffer where reads happen.
     */
    void *first = mmap(reserved, size, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_FIXED, buf->memfd, 0);
    if (first == MAP_FAILED) {
        munmap(reserved, size * 2);
        close(buf->memfd);
        free(buf);
        return NULL;
    }

    /*
     * Step 6: Map the SAME memfd immediately after
     *
     * This is the "mirror" - the second mapping of the same physical pages.
     * Accessing base + size + X is the same as accessing base + X.
     */
    void *second = mmap((char *)reserved + size, size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_FIXED, buf->memfd, 0);
    if (second == MAP_FAILED) {
        /* munmap(reserved, size * 2) cleans up both reservation and first mapping */
        munmap(reserved, size * 2);
        close(buf->memfd);
        free(buf);
        return NULL;
    }

    buf->base = first;

    /*
     * Verify the mirroring works by writing/reading a canary value.
     * This catches kernel bugs or configuration issues early.
     */
#ifdef DEBUG
    {
        /* Write at end of first mapping */
        volatile uint64_t *write_ptr = (volatile uint64_t *)
            ((char *)first + size - sizeof(uint64_t));
        /* Read from mirror (same location via second mapping) */
        volatile uint64_t *read_ptr = (volatile uint64_t *)
            ((char *)second + size - sizeof(uint64_t));

        const uint64_t canary = 0xDEADBEEFCAFEBABEULL;
        *write_ptr = canary;

        if (*read_ptr != canary) {
            /* Mirroring failed - critical error */
            fprintf(stderr, "[FATAL] Mirrored buffer verification failed!\n");
            munmap(reserved, size * 2);
            close(buf->memfd);
            free(buf);
            return NULL;
        }

        /* Clear canary */
        *write_ptr = 0;
    }
#endif

    return buf;
}

bool mirrored_buffer_prefault(mirrored_buffer_t *buf, bool lock) {
    if (!buf || !buf->base || buf->size == 0)
        return false;

    size_t page_size = get_page_size();
    volatile char *p = (volatile char *)buf->base;

    /*
     * Touch one byte per page to trigger minor faults now rather than
     * on the hot path. Reading (not writing) is sufficient to allocate
     * the physical page via the existing MAP_SHARED mapping.
     */
    for (size_t off = 0; off < buf->size; off += page_size) {
        (void)p[off];
    }

    if (lock) {
        /*
         * Best-effort: mlock only the first mapping (buf->size bytes).
         * The mirror mapping shares the same physical pages, so locking
         * the first half locks all underlying pages.
         */
        (void)mlock(buf->base, buf->size);
    }

    return true;
}

void mirrored_buffer_destroy(mirrored_buffer_t *buf) {
    if (!buf) {
        return;
    }

    if (buf->base) {
        /*
         * Unmap both mappings. Since they're contiguous in virtual
         * address space, a single munmap(base, 2*size) handles both.
         */
        munmap(buf->base, buf->size * 2);
        buf->base = NULL;
    }

    if (buf->memfd >= 0) {
        close(buf->memfd);
        buf->memfd = -1;
    }

    buf->size = 0;
    buf->mask = 0;
    buf->state = BUF_STATE_IDLE;

    free(buf);
}
