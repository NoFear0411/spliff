/**
 * @file process.c
 * @brief Process information utilities implementation
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

#include "process.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

bool proc_get_name(uint32_t pid, char *buf, size_t bufsize) {
    /* Defensive input validation */
    if (!buf || bufsize == 0) {
        return false;
    }
    buf[0] = '\0';  /* Ensure null-terminated on all paths */

    if (pid == 0) {
        return false;
    }

    /* Build path to /proc/PID/comm */
    char path[32];  /* "/proc/4294967295/comm" = 22 chars max */
    int written = snprintf(path, sizeof(path), "/proc/%u/comm", pid);
    if (written < 0 || (size_t)written >= sizeof(path)) {
        return false;  /* Path truncated (shouldn't happen) */
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        return false;  /* Process doesn't exist or no permission */
    }

    bool success = false;
    if (fgets(buf, (int)bufsize, f)) {
        /* Strip trailing newline */
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            buf[len - 1] = '\0';
            len--;
        }
        success = (len > 0);
    }

    fclose(f);
    return success;
}

bool proc_exists(uint32_t pid) {
    if (pid == 0) {
        return false;
    }

    char path[24];  /* "/proc/4294967295" = 17 chars max */
    snprintf(path, sizeof(path), "/proc/%u", pid);

    return access(path, F_OK) == 0;
}
