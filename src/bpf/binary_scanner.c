/*
 * binary_scanner.c - BoringSSL function detection via build ID lookup
 *
 * Uses ELF build ID to look up SSL_read/SSL_write offsets from an embedded
 * database. This is much more reliable than heuristic-based scanning.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <stdbool.h>
#include <stdint.h>

#include "binary_scanner.h"
#include "boringssl_offsets.h"

/* BoringSSL signature string to search for (quick presence check) */
#define BORINGSSL_SIG_THIRD_PARTY "third_party/boringssl"

/* Chrome binary paths to check */
static const char *chrome_paths[] = {
    "/opt/google/chrome/chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/google-chrome",
    "/usr/lib/google-chrome/chrome",
    NULL
};

/* Chromium binary paths to check */
static const char *chromium_paths[] = {
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
    "/usr/lib/chromium-browser/chromium-browser",
    "/usr/lib64/chromium-browser/chromium-browser",
    "/usr/lib/chromium/chromium",
    NULL
};

/*
 * Memory-map a file for reading
 */
static uint8_t *mmap_file(const char *path, size_t *size_out)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return NULL;
    }

    uint8_t *data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (data == MAP_FAILED)
        return NULL;

    *size_out = st.st_size;
    return data;
}

/*
 * Search for a string in binary data
 */
static bool find_string(const uint8_t *data, size_t size, const char *needle)
{
    size_t needle_len = strlen(needle);

    for (size_t i = 0; i <= size - needle_len; i++) {
        if (memcmp(data + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

/*
 * Check if binary contains BoringSSL signatures
 */
bool binary_has_boringssl(const char *binary_path)
{
    size_t size;
    uint8_t *data = mmap_file(binary_path, &size);
    if (!data)
        return false;

    bool found = find_string(data, size, BORINGSSL_SIG_THIRD_PARTY);

    munmap(data, size);
    return found;
}

/*
 * Convert bytes to hex string
 */
static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex_out)
{
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex_out[i * 2] = hex_chars[(bytes[i] >> 4) & 0xf];
        hex_out[i * 2 + 1] = hex_chars[bytes[i] & 0xf];
    }
    hex_out[len * 2] = '\0';
}

/*
 * Extract build ID from ELF .note.gnu.build-id section
 *
 * The build-id note has the format:
 *   - n_namesz: 4 (length of "GNU\0")
 *   - n_descsz: build ID length (usually 20 for SHA-1)
 *   - n_type: NT_GNU_BUILD_ID (3)
 *   - name: "GNU\0" (4-byte aligned)
 *   - desc: build ID bytes
 */
static bool extract_build_id(const uint8_t *data, size_t size, char *build_id_hex)
{
    if (size < sizeof(Elf64_Ehdr))
        return false;

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data;

    /* Verify ELF magic */
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
        return false;

    /* Only support 64-bit ELF */
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
        return false;

    /* Get section header string table */
    if (ehdr->e_shstrndx == SHN_UNDEF || ehdr->e_shstrndx >= ehdr->e_shnum)
        return false;

    if (ehdr->e_shoff + ehdr->e_shnum * sizeof(Elf64_Shdr) > size)
        return false;

    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(data + ehdr->e_shoff);
    const Elf64_Shdr *shstrtab_hdr = &shdrs[ehdr->e_shstrndx];

    if (shstrtab_hdr->sh_offset + shstrtab_hdr->sh_size > size)
        return false;

    const char *shstrtab = (const char *)(data + shstrtab_hdr->sh_offset);

    /* Find .note.gnu.build-id section */
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = &shdrs[i];

        if (shdr->sh_name >= shstrtab_hdr->sh_size)
            continue;

        const char *name = shstrtab + shdr->sh_name;

        if (strcmp(name, ".note.gnu.build-id") == 0) {
            if (shdr->sh_offset + shdr->sh_size > size)
                return false;

            const uint8_t *note_data = data + shdr->sh_offset;
            size_t note_size = shdr->sh_size;

            /* Parse note header */
            if (note_size < 12)  /* Minimum: 3 x 4-byte fields */
                return false;

            uint32_t n_namesz, n_descsz, n_type;
            memcpy(&n_namesz, note_data, 4);
            memcpy(&n_descsz, note_data + 4, 4);
            memcpy(&n_type, note_data + 8, 4);

            /* Verify it's a GNU build ID note */
            if (n_type != 3)  /* NT_GNU_BUILD_ID */
                return false;

            /* Name should be "GNU\0" (4 bytes) */
            if (n_namesz != 4)
                return false;

            /* Calculate aligned offsets */
            size_t name_offset = 12;
            size_t name_aligned = (n_namesz + 3) & ~3;  /* Align to 4 bytes */
            size_t desc_offset = name_offset + name_aligned;

            if (desc_offset + n_descsz > note_size)
                return false;

            /* Verify name is "GNU" */
            if (memcmp(note_data + name_offset, "GNU", 3) != 0)
                return false;

            /* Extract build ID - limit to what we can store */
            size_t build_id_len = n_descsz;
            if (build_id_len > 32)  /* Max SHA-256 */
                build_id_len = 32;

            bytes_to_hex(note_data + desc_offset, build_id_len, build_id_hex);
            return true;
        }
    }

    return false;
}

/*
 * Look up offsets by build ID in the embedded database
 */
static const struct boringssl_offset_entry *lookup_offsets_by_build_id(const char *build_id)
{
    for (size_t i = 0; i < BORINGSSL_OFFSET_DB_COUNT; i++) {
        const struct boringssl_offset_entry *entry = &boringssl_offset_db[i];
        if (entry->build_id && strcmp(entry->build_id, build_id) == 0) {
            return entry;
        }
    }
    return NULL;
}

/*
 * Scan a binary for BoringSSL SSL_read/SSL_write function offsets
 *
 * Uses build-ID based database lookup for reliable detection.
 */
int scan_binary_for_boringssl(const char *binary_path,
                               struct boringssl_offsets *offsets,
                               bool debug)
{
    if (!binary_path || !offsets)
        return -1;

    memset(offsets, 0, sizeof(*offsets));
    strncpy(offsets->binary_path, binary_path, sizeof(offsets->binary_path) - 1);

    size_t size;
    uint8_t *data = mmap_file(binary_path, &size);
    if (!data) {
        if (debug)
            fprintf(stderr, "[scanner] Failed to open %s\n", binary_path);
        return -1;
    }

    /* Extract build ID */
    if (!extract_build_id(data, size, offsets->build_id)) {
        if (debug)
            fprintf(stderr, "[scanner] Failed to extract build ID from %s\n", binary_path);
        munmap(data, size);
        return -1;
    }

    if (debug) {
        fprintf(stderr, "[scanner] Build ID: %s\n", offsets->build_id);
    }

    munmap(data, size);

    /* Look up in database */
    const struct boringssl_offset_entry *entry = lookup_offsets_by_build_id(offsets->build_id);

    if (!entry) {
        fprintf(stderr, "[scanner] Unknown build ID: %s\n", offsets->build_id);
        fprintf(stderr, "[scanner] \n");
        fprintf(stderr, "[scanner] To add support for this binary:\n");
        fprintf(stderr, "[scanner]   1. Download debug symbols for this browser version\n");
        fprintf(stderr, "[scanner]   2. Run: nm -C <debug-symbols> | grep -E ' t SSL_read$| t SSL_write$'\n");
        fprintf(stderr, "[scanner]   3. Add entry to src/bpf/boringssl_offsets.h\n");
        fprintf(stderr, "[scanner] \n");
        fprintf(stderr, "[scanner] Example entry:\n");
        fprintf(stderr, "[scanner]   {\n");
        fprintf(stderr, "[scanner]       .build_id = \"%s\",\n", offsets->build_id);
        fprintf(stderr, "[scanner]       .version_info = \"Browser X.Y.Z\",\n");
        fprintf(stderr, "[scanner]       .ssl_read_offset = 0x????????,\n");
        fprintf(stderr, "[scanner]       .ssl_write_offset = 0x????????,\n");
        fprintf(stderr, "[scanner]   },\n");
        return -1;
    }

    /* Found in database - populate offsets */
    offsets->ssl_read_offset = entry->ssl_read_offset;
    offsets->ssl_write_offset = entry->ssl_write_offset;
    offsets->ssl_read_impl_offset = entry->ssl_read_impl_offset;
    offsets->ssl_write_impl_offset = entry->ssl_write_impl_offset;
    offsets->socket_read_offset = entry->socket_read_offset;
    offsets->on_read_ready_offset = entry->on_read_ready_offset;
    offsets->do_payload_read_offset = entry->do_payload_read_offset;
    offsets->version_info = entry->version_info;
    offsets->found = true;

    if (debug) {
        fprintf(stderr, "[scanner] Matched: %s\n", entry->version_info);
        fprintf(stderr, "[scanner] SSL_read at file offset 0x%lx\n", offsets->ssl_read_offset);
        fprintf(stderr, "[scanner] SSL_write at file offset 0x%lx\n", offsets->ssl_write_offset);
        if (offsets->ssl_read_impl_offset) {
            fprintf(stderr, "[scanner] ssl_read_impl (Golden Hook) at 0x%lx\n", offsets->ssl_read_impl_offset);
        }
        if (offsets->ssl_write_impl_offset) {
            fprintf(stderr, "[scanner] DoPayloadWrite (Golden Hook) at 0x%lx\n", offsets->ssl_write_impl_offset);
        }
        if (offsets->socket_read_offset) {
            fprintf(stderr, "[scanner] SSLClientSocketImpl::ReadIfReady at 0x%lx\n", offsets->socket_read_offset);
        }
        if (offsets->on_read_ready_offset) {
            fprintf(stderr, "[scanner] SSLClientSocketImpl::OnReadReady at 0x%lx\n", offsets->on_read_ready_offset);
        }
        if (offsets->do_payload_read_offset) {
            fprintf(stderr, "[scanner] SSLClientSocketImpl::DoPayloadRead at 0x%lx\n", offsets->do_payload_read_offset);
        }
    }

    return 0;
}

/*
 * Find Chrome binary
 */
const char *find_chrome_binary(void)
{
    for (int i = 0; chrome_paths[i] != NULL; i++) {
        if (access(chrome_paths[i], R_OK) == 0) {
            return chrome_paths[i];
        }
    }
    return NULL;
}

/*
 * Find Chromium binary
 */
const char *find_chromium_binary(void)
{
    for (int i = 0; chromium_paths[i] != NULL; i++) {
        if (access(chromium_paths[i], R_OK) == 0) {
            return chromium_paths[i];
        }
    }
    return NULL;
}
