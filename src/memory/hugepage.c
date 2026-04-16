/**
 * @file hugepage.c
 * @brief Implementation of hugepage availability checking and allocation
 *
 * @details Uses high-performance /proc/meminfo parsing to check hugepage
 * availability without heap allocations. This is critical for EDR-grade
 * performance where we need to make allocation decisions quickly.
 *
 * @par Implementation Notes:
 * - Uses fixed-size stack buffer for /proc/meminfo (typically ~1.2KB)
 * - Simple strstr() pointer-walk instead of heavy parsing libraries
 * - No fscanf/stdio overhead in hot paths
 *
 * @see hugepage.h for API documentation
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/* _GNU_SOURCE defined via CMake for mmap flags */

#include "hugepage.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/*
 * MAP_HUGETLB and MAP_HUGE_2MB for general hugepage allocation
 */
#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif

#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif

#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#endif

/**
 * @brief Parse a numeric value from /proc/meminfo format
 *
 * Expects format: "KeyName:     12345 kB\n"
 * Returns the numeric value (ignoring the " kB" suffix).
 *
 * @param buf   Buffer containing meminfo contents
 * @param key   Key to search for (e.g., "HugePages_Free:")
 * @return Numeric value, or 0 if not found
 */
static size_t parse_meminfo_value(const char *buf, const char *key) {
    const char *pos = strstr(buf, key);
    if (!pos) {
        return 0;
    }

    /* Move past the key to the start of the value */
    pos += strlen(key);

    /* Skip whitespace */
    while (*pos == ' ' || *pos == '\t') {
        pos++;
    }

    /* Parse the number - use strtoul for safety */
    char *endptr;
    unsigned long val = strtoul(pos, &endptr, 10);

    /* Validate we actually parsed something */
    if (endptr == pos) {
        return 0;
    }

    return (size_t)val;
}

/**
 * @brief Read /proc/meminfo into a stack buffer
 *
 * @param buf     Output buffer
 * @param bufsize Size of buffer
 * @return true on success, false on failure
 */
static bool read_meminfo(char *buf, size_t bufsize) {
    int fd = open("/proc/meminfo", O_RDONLY);
    if (fd < 0) {
        return false;
    }

    ssize_t bytes = read(fd, buf, bufsize - 1);
    close(fd);

    if (bytes <= 0) {
        return false;
    }

    buf[bytes] = '\0';
    return true;
}

size_t hugepage_free_count(void) {
    /*
     * /proc/meminfo is typically ~1.2KB.
     * Use 2KB stack buffer to stay safe and fast.
     */
    char buf[2048];

    if (!read_meminfo(buf, sizeof(buf))) {
        return 0;
    }

    return parse_meminfo_value(buf, "HugePages_Free:");
}

size_t hugepage_total_count(void) {
    char buf[2048];

    if (!read_meminfo(buf, sizeof(buf))) {
        return 0;
    }

    return parse_meminfo_value(buf, "HugePages_Total:");
}

bool hugepage_check_available(size_t size_bytes) {
    size_t pages_needed = hugepage_pages_needed(size_bytes);
    size_t pages_free = hugepage_free_count();

    return pages_free >= pages_needed;
}

void hugepage_log_status(void) {
    char buf[2048];

    if (!read_meminfo(buf, sizeof(buf))) {
        fprintf(stderr, "[ERROR] HUGEPAGE_STATUS: Failed to read /proc/meminfo\n");
        return;
    }

    size_t total = parse_meminfo_value(buf, "HugePages_Total:");
    size_t free_pages = parse_meminfo_value(buf, "HugePages_Free:");
    size_t reserved = parse_meminfo_value(buf, "HugePages_Rsvd:");

    if (total == 0) {
        fprintf(stderr, "[WARN] HUGEPAGE_STATUS: Not configured "
                        "(echo N > /proc/sys/vm/nr_hugepages). "
                        "Performance will be degraded (4KB pages).\n");
    } else if (free_pages == 0) {
        fprintf(stderr, "[WARN] HUGEPAGE_STATUS: Exhausted (%zu total, 0 free). "
                        "Check if other services (databases) claimed them all.\n",
                total);
    } else {
        fprintf(stderr, "[INFO] HUGEPAGE_STATUS: %zu/%zu free (2MB pages). "
                        "Ready for high-speed mirroring.\n",
                free_pages, total);

        /* Additional context if pages are reserved */
        if (reserved > 0) {
            fprintf(stderr, "[INFO] HUGEPAGE_STATUS: %zu pages reserved "
                            "(pending allocation).\n", reserved);
        }
    }
}

void *hugepage_alloc(size_t size) {
    return hugepage_alloc_ex(size, true, NULL);
}

void *hugepage_alloc_ex(size_t size, bool allow_fallback, bool *used_hugepages) {
    if (size == 0) {
        return NULL;
    }

    /* Round up to 2MB boundary */
    size_t aligned_size = hugepage_align(size);

    if (used_hugepages) {
        *used_hugepages = false;
    }

    /*
     * Attempt hugepage allocation with MAP_HUGETLB | MAP_HUGE_2MB.
     * MAP_ANONYMOUS: No file backing
     * MAP_PRIVATE: Changes are private to this process
     */
    void *ptr = mmap(NULL, aligned_size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_2MB,
                     -1, 0);

    if (ptr != MAP_FAILED) {
        if (used_hugepages) {
            *used_hugepages = true;
        }
        return ptr;
    }

    /* Hugepage allocation failed */
    if (!allow_fallback) {
        return NULL;
    }

    /*
     * Fallback to regular pages.
     * This is better than crashing - the agent continues working,
     * just with higher TLB pressure.
     */
    ptr = mmap(NULL, aligned_size,
               PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS,
               -1, 0);

    if (ptr == MAP_FAILED) {
        return NULL;
    }

    return ptr;
}

void hugepage_free(void *ptr, size_t size) {
    if (!ptr || size == 0) {
        return;
    }

    /* Round up to same boundary used during allocation */
    size_t aligned_size = hugepage_align(size);
    munmap(ptr, aligned_size);
}
