/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * sslsniff - eBPF-based SSL/TLS traffic sniffer
 * Copyright (C) 2025-2026 sslsniff authors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "signatures.h"
#include <string.h>
#include <stdlib.h>

/*
 * Magic byte signatures - web-relevant formats only.
 * Organized by category for maintainability.
 * Longest signatures should match first (handled by qsort at init).
 */

/* === Images === */
static const uint8_t SIG_PNG[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
static const uint8_t SIG_PNG_TRAILER[] = {0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82}; /* IEND chunk */
static const uint8_t SIG_GIF87[] = {'G', 'I', 'F', '8', '7', 'a'};
static const uint8_t SIG_GIF89[] = {'G', 'I', 'F', '8', '9', 'a'};
static const uint8_t SIG_GIF_TRAILER[] = {0x00, 0x3B}; /* GIF trailer */
static const uint8_t SIG_JPEG_JFIF[] = {0xFF, 0xD8, 0xFF, 0xE0};
static const uint8_t SIG_JPEG_EXIF[] = {0xFF, 0xD8, 0xFF, 0xE1};
static const uint8_t SIG_JPEG[] = {0xFF, 0xD8, 0xFF};
static const uint8_t SIG_JPEG_TRAILER[] = {0xFF, 0xD9}; /* EOI marker */
static const uint8_t SIG_BMP[] = {'B', 'M'};
static const uint8_t SIG_ICO[] = {0x00, 0x00, 0x01, 0x00};
static const uint8_t SIG_CUR[] = {0x00, 0x00, 0x02, 0x00}; /* Cursor file */
static const uint8_t SIG_WEBP[] = {'R', 'I', 'F', 'F'}; /* Handled specially */
static const uint8_t SIG_TIFF_LE[] = {0x49, 0x49, 0x2A, 0x00}; /* Little-endian */
static const uint8_t SIG_TIFF_BE[] = {0x4D, 0x4D, 0x00, 0x2A}; /* Big-endian */
static const uint8_t SIG_PSD[] = {'8', 'B', 'P', 'S'};

/* === Video === */
static const uint8_t SIG_WEBM[] = {0x1A, 0x45, 0xDF, 0xA3}; /* Matroska/WebM */
static const uint8_t SIG_FLV[] = {'F', 'L', 'V', 0x01};
/* MP4/MOV/AVIF/HEIC handled by ISOBMFF detector */

/* === Audio === */
static const uint8_t SIG_MP3_ID3[] = {'I', 'D', '3'};
static const uint8_t SIG_MP3_SYNC[] = {0xFF, 0xFB};
static const uint8_t SIG_MP3_SYNC2[] = {0xFF, 0xFA};
static const uint8_t SIG_MP3_SYNC3[] = {0xFF, 0xF3};
static const uint8_t SIG_OGG[] = {'O', 'g', 'g', 'S'};
static const uint8_t SIG_FLAC[] = {'f', 'L', 'a', 'C'};
static const uint8_t SIG_MIDI[] = {'M', 'T', 'h', 'd'};
/* WAV handled by RIFF detector */

/* === Archives === */
static const uint8_t SIG_ZIP[] = {'P', 'K', 0x03, 0x04};
static const uint8_t SIG_ZIP_EMPTY[] = {'P', 'K', 0x05, 0x06}; /* Empty archive */
static const uint8_t SIG_ZIP_SPAN[] = {'P', 'K', 0x07, 0x08}; /* Spanned archive */
static const uint8_t SIG_GZIP[] = {0x1F, 0x8B};
static const uint8_t SIG_ZSTD[] = {0x28, 0xB5, 0x2F, 0xFD};
static const uint8_t SIG_BZIP2[] = {'B', 'Z', 'h'};
static const uint8_t SIG_XZ[] = {0xFD, '7', 'z', 'X', 'Z', 0x00};
static const uint8_t SIG_7Z[] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
static const uint8_t SIG_RAR5[] = {'R', 'a', 'r', '!', 0x1A, 0x07, 0x01, 0x00};
static const uint8_t SIG_RAR[] = {'R', 'a', 'r', '!', 0x1A, 0x07, 0x00};
static const uint8_t SIG_LZ4[] = {0x04, 0x22, 0x4D, 0x18};
/* TAR handled specially at offset 257 */

/* === Documents === */
static const uint8_t SIG_PDF[] = {'%', 'P', 'D', 'F', '-'};
static const uint8_t SIG_PDF_TRAILER[] = {'%', '%', 'E', 'O', 'F'}; /* %%EOF */
static const uint8_t SIG_PS[] = {'%', '!'};
static const uint8_t SIG_RTF[] = {'{', '\\', 'r', 't', 'f'};
static const uint8_t SIG_XML[] = {'<', '?', 'x', 'm', 'l'};

/* === Fonts === */
static const uint8_t SIG_WOFF[] = {'w', 'O', 'F', 'F'};
static const uint8_t SIG_WOFF2[] = {'w', 'O', 'F', '2'};
static const uint8_t SIG_TTF[] = {0x00, 0x01, 0x00, 0x00};
static const uint8_t SIG_OTF[] = {'O', 'T', 'T', 'O'};

/* === Executables/Binary === */
static const uint8_t SIG_WASM[] = {0x00, 'a', 's', 'm'};
static const uint8_t SIG_ELF[] = {0x7F, 'E', 'L', 'F'};
static const uint8_t SIG_MACH_O_32[] = {0xFE, 0xED, 0xFA, 0xCE};
static const uint8_t SIG_MACH_O_64[] = {0xFE, 0xED, 0xFA, 0xCF};
static const uint8_t SIG_MACH_O_32_REV[] = {0xCE, 0xFA, 0xED, 0xFE};
static const uint8_t SIG_MACH_O_64_REV[] = {0xCF, 0xFA, 0xED, 0xFE};
static const uint8_t SIG_CLASS[] = {0xCA, 0xFE, 0xBA, 0xBE};
static const uint8_t SIG_DEX[] = {'d', 'e', 'x', '\n'};

/* === Database === */
static const uint8_t SIG_SQLITE[] = {'S', 'Q', 'L', 'i', 't', 'e', ' ', 'f', 'o', 'r', 'm', 'a', 't', ' ', '3', 0x00};

/* === TAR at offset 257 === */
static const uint8_t SIG_TAR_USTAR[] = {'u', 's', 't', 'a', 'r', 0x00};
static const uint8_t SIG_TAR_USTAR_SP[] = {'u', 's', 't', 'a', 'r', ' ', ' ', 0x00};

/*
 * Signature table - entries are sorted by magic_len (descending) at init time.
 * This ensures "most specific wins" - longer matches are checked first.
 */
static file_signature_t signatures[] = {
    /* Images */
    {SIG_PNG, 8, 0, "PNG image", FILE_CLASS_IMAGE, true, SIG_PNG_TRAILER, 8},
    {SIG_GIF89, 6, 0, "GIF image", FILE_CLASS_IMAGE, true, SIG_GIF_TRAILER, 2},
    {SIG_GIF87, 6, 0, "GIF image", FILE_CLASS_IMAGE, true, SIG_GIF_TRAILER, 2},
    {SIG_JPEG_JFIF, 4, 0, "JPEG image", FILE_CLASS_IMAGE, true, SIG_JPEG_TRAILER, 2},
    {SIG_JPEG_EXIF, 4, 0, "JPEG image", FILE_CLASS_IMAGE, true, SIG_JPEG_TRAILER, 2},
    {SIG_JPEG, 3, 0, "JPEG image", FILE_CLASS_IMAGE, true, SIG_JPEG_TRAILER, 2},
    {SIG_BMP, 2, 0, "BMP image", FILE_CLASS_IMAGE, true, NULL, 0},
    {SIG_ICO, 4, 0, "ICO icon", FILE_CLASS_IMAGE, true, NULL, 0},
    {SIG_CUR, 4, 0, "CUR cursor", FILE_CLASS_IMAGE, true, NULL, 0},
    {SIG_TIFF_LE, 4, 0, "TIFF image", FILE_CLASS_IMAGE, true, NULL, 0},
    {SIG_TIFF_BE, 4, 0, "TIFF image", FILE_CLASS_IMAGE, true, NULL, 0},
    {SIG_PSD, 4, 0, "PSD image", FILE_CLASS_IMAGE, true, NULL, 0},

    /* Video */
    {SIG_WEBM, 4, 0, "WebM video", FILE_CLASS_VIDEO, true, NULL, 0},
    {SIG_FLV, 4, 0, "FLV video", FILE_CLASS_VIDEO, true, NULL, 0},

    /* Audio */
    {SIG_FLAC, 4, 0, "FLAC audio", FILE_CLASS_AUDIO, true, NULL, 0},
    {SIG_OGG, 4, 0, "OGG audio", FILE_CLASS_AUDIO, true, NULL, 0},
    {SIG_MIDI, 4, 0, "MIDI audio", FILE_CLASS_AUDIO, true, NULL, 0},
    {SIG_MP3_ID3, 3, 0, "MP3 audio", FILE_CLASS_AUDIO, true, NULL, 0},
    {SIG_MP3_SYNC, 2, 0, "MP3 audio", FILE_CLASS_AUDIO, true, NULL, 0},
    {SIG_MP3_SYNC2, 2, 0, "MP3 audio", FILE_CLASS_AUDIO, true, NULL, 0},
    {SIG_MP3_SYNC3, 2, 0, "MP3 audio", FILE_CLASS_AUDIO, true, NULL, 0},

    /* Archives */
    {SIG_RAR5, 8, 0, "RAR archive", FILE_CLASS_ARCHIVE, true, NULL, 0},
    {SIG_RAR, 7, 0, "RAR archive", FILE_CLASS_ARCHIVE, true, NULL, 0},
    {SIG_7Z, 6, 0, "7-Zip archive", FILE_CLASS_ARCHIVE, true, NULL, 0},
    {SIG_XZ, 6, 0, "XZ archive", FILE_CLASS_ARCHIVE, true, NULL, 0},
    {SIG_ZIP, 4, 0, "ZIP archive", FILE_CLASS_ARCHIVE, true, NULL, 0},
    {SIG_ZIP_EMPTY, 4, 0, "ZIP archive", FILE_CLASS_ARCHIVE, true, NULL, 0},
    {SIG_ZIP_SPAN, 4, 0, "ZIP archive", FILE_CLASS_ARCHIVE, true, NULL, 0},
    {SIG_ZSTD, 4, 0, "ZSTD compressed", FILE_CLASS_ARCHIVE, true, NULL, 0},
    {SIG_LZ4, 4, 0, "LZ4 compressed", FILE_CLASS_ARCHIVE, true, NULL, 0},
    {SIG_BZIP2, 3, 0, "BZIP2 compressed", FILE_CLASS_ARCHIVE, true, NULL, 0},
    {SIG_GZIP, 2, 0, "GZIP compressed", FILE_CLASS_ARCHIVE, true, NULL, 0},

    /* Documents */
    {SIG_PDF, 5, 0, "PDF document", FILE_CLASS_DOCUMENT, true, SIG_PDF_TRAILER, 5},
    {SIG_RTF, 5, 0, "RTF document", FILE_CLASS_DOCUMENT, false, NULL, 0},
    {SIG_XML, 5, 0, "XML document", FILE_CLASS_DOCUMENT, false, NULL, 0},
    {SIG_PS, 2, 0, "PostScript", FILE_CLASS_DOCUMENT, true, NULL, 0},

    /* Fonts */
    {SIG_WOFF2, 4, 0, "WOFF2 font", FILE_CLASS_FONT, true, NULL, 0},
    {SIG_WOFF, 4, 0, "WOFF font", FILE_CLASS_FONT, true, NULL, 0},
    {SIG_OTF, 4, 0, "OpenType font", FILE_CLASS_FONT, true, NULL, 0},
    {SIG_TTF, 4, 0, "TrueType font", FILE_CLASS_FONT, true, NULL, 0},

    /* Executables (mostly for filtering non-HTTP traffic) */
    {SIG_WASM, 4, 0, "WebAssembly", FILE_CLASS_EXECUTABLE, true, NULL, 0},
    {SIG_ELF, 4, 0, "ELF binary", FILE_CLASS_EXECUTABLE, true, NULL, 0},
    {SIG_MACH_O_64, 4, 0, "Mach-O binary", FILE_CLASS_EXECUTABLE, true, NULL, 0},
    {SIG_MACH_O_32, 4, 0, "Mach-O binary", FILE_CLASS_EXECUTABLE, true, NULL, 0},
    {SIG_MACH_O_64_REV, 4, 0, "Mach-O binary", FILE_CLASS_EXECUTABLE, true, NULL, 0},
    {SIG_MACH_O_32_REV, 4, 0, "Mach-O binary", FILE_CLASS_EXECUTABLE, true, NULL, 0},
    {SIG_CLASS, 4, 0, "Java class", FILE_CLASS_EXECUTABLE, true, NULL, 0},
    {SIG_DEX, 4, 0, "Android DEX", FILE_CLASS_EXECUTABLE, true, NULL, 0},

    /* Database */
    {SIG_SQLITE, 16, 0, "SQLite database", FILE_CLASS_DATABASE, true, NULL, 0},

    /* RIFF container - needs deeper inspection but include for basic detection */
    {SIG_WEBP, 4, 0, "RIFF container", FILE_CLASS_CONTAINER, true, NULL, 0},

    /* Terminator */
    {NULL, 0, 0, NULL, FILE_CLASS_UNKNOWN, false, NULL, 0}
};

/* Sorted index for efficient lookup */
static int *sorted_index = NULL;
static int signature_count = 0;

/* Comparison function for qsort - sort by magic_len descending (longest first) */
static int compare_by_magic_len(const void *a, const void *b) {
    int idx_a = *(const int *)a;
    int idx_b = *(const int *)b;
    /* Descending order: longer magic_len first */
    return signatures[idx_b].magic_len - signatures[idx_a].magic_len;
}

/* Check for MP4/MOV/AVIF/HEIC (ISO Base Media File Format) at offset 4 */
static bool detect_isobmff(const uint8_t *data, size_t len, signature_result_t *result) {
    if (len < 12) return false;

    /* Check for 'ftyp' at offset 4 */
    if (data[4] != 'f' || data[5] != 't' || data[6] != 'y' || data[7] != 'p') {
        return false;
    }

    /* Check brand at offset 8 */
    result->is_binary = true;
    result->trailer_valid = true; /* No trailer check for ISOBMFF */
    result->confidence = 8; /* ftyp + brand = 8 bytes checked */

    if (memcmp(data + 8, "avif", 4) == 0) {
        result->description = "AVIF image";
        result->file_class = FILE_CLASS_IMAGE;
    } else if (memcmp(data + 8, "avis", 4) == 0) {
        result->description = "AVIF image sequence";
        result->file_class = FILE_CLASS_IMAGE;
    } else if (memcmp(data + 8, "heic", 4) == 0 || memcmp(data + 8, "heix", 4) == 0) {
        result->description = "HEIC image";
        result->file_class = FILE_CLASS_IMAGE;
    } else if (memcmp(data + 8, "hevc", 4) == 0 || memcmp(data + 8, "hevx", 4) == 0) {
        result->description = "HEVC image sequence";
        result->file_class = FILE_CLASS_IMAGE;
    } else if (memcmp(data + 8, "mif1", 4) == 0) {
        result->description = "HEIF image";
        result->file_class = FILE_CLASS_IMAGE;
    } else if (memcmp(data + 8, "mp41", 4) == 0 || memcmp(data + 8, "mp42", 4) == 0 ||
               memcmp(data + 8, "isom", 4) == 0 || memcmp(data + 8, "iso2", 4) == 0 ||
               memcmp(data + 8, "avc1", 4) == 0 || memcmp(data + 8, "mp71", 4) == 0) {
        result->description = "MP4 video";
        result->file_class = FILE_CLASS_VIDEO;
    } else if (memcmp(data + 8, "M4V ", 4) == 0 || memcmp(data + 8, "m4v ", 4) == 0) {
        result->description = "M4V video";
        result->file_class = FILE_CLASS_VIDEO;
    } else if (memcmp(data + 8, "M4A ", 4) == 0 || memcmp(data + 8, "m4a ", 4) == 0) {
        result->description = "M4A audio";
        result->file_class = FILE_CLASS_AUDIO;
    } else if (memcmp(data + 8, "M4B ", 4) == 0) {
        result->description = "M4B audiobook";
        result->file_class = FILE_CLASS_AUDIO;
    } else if (memcmp(data + 8, "qt  ", 4) == 0) {
        result->description = "QuickTime video";
        result->file_class = FILE_CLASS_VIDEO;
    } else if (memcmp(data + 8, "3gp", 3) == 0 || memcmp(data + 8, "3g2", 3) == 0) {
        result->description = "3GP video";
        result->file_class = FILE_CLASS_VIDEO;
    } else if (memcmp(data + 8, "dash", 4) == 0) {
        result->description = "DASH segment";
        result->file_class = FILE_CLASS_VIDEO;
    } else {
        result->description = "ISO media";
        result->file_class = FILE_CLASS_CONTAINER;
    }
    return true;
}

/* Check RIFF container type (WEBP, WAV, AVI) at offset 8 */
static bool detect_riff(const uint8_t *data, size_t len, signature_result_t *result) {
    if (len < 12) return false;
    if (data[0] != 'R' || data[1] != 'I' || data[2] != 'F' || data[3] != 'F') {
        return false;
    }

    result->is_binary = true;
    result->trailer_valid = true;
    result->confidence = 8; /* RIFF + type = 8 bytes checked */

    if (memcmp(data + 8, "WEBP", 4) == 0) {
        result->description = "WebP image";
        result->file_class = FILE_CLASS_IMAGE;
    } else if (memcmp(data + 8, "WAVE", 4) == 0) {
        result->description = "WAV audio";
        result->file_class = FILE_CLASS_AUDIO;
    } else if (memcmp(data + 8, "AVI ", 4) == 0) {
        result->description = "AVI video";
        result->file_class = FILE_CLASS_VIDEO;
    } else {
        result->description = "RIFF container";
        result->file_class = FILE_CLASS_CONTAINER;
    }
    return true;
}

/* Check for TAR at offset 257 */
static bool detect_tar(const uint8_t *data, size_t len, signature_result_t *result) {
    if (len < 265) return false;

    if (memcmp(data + 257, SIG_TAR_USTAR, 6) == 0 ||
        memcmp(data + 257, SIG_TAR_USTAR_SP, 8) == 0) {
        result->description = "TAR archive";
        result->file_class = FILE_CLASS_ARCHIVE;
        result->is_binary = true;
        result->trailer_valid = true;
        result->confidence = 6;
        return true;
    }
    return false;
}

/* Initialize signature detection - builds sorted index */
int signatures_init(void) {
    /* Count signatures */
    signature_count = 0;
    while (signatures[signature_count].magic != NULL) {
        signature_count++;
    }

    if (signature_count == 0) return 0;

    /* Allocate and build sorted index */
    sorted_index = malloc(signature_count * sizeof(int));
    if (!sorted_index) return -1;

    for (int i = 0; i < signature_count; i++) {
        sorted_index[i] = i;
    }

    /* Sort by magic_len descending (longest first = most specific) */
    qsort(sorted_index, signature_count, sizeof(int), compare_by_magic_len);

    return 0;
}

/* Cleanup */
void signatures_cleanup(void) {
    free(sorted_index);
    sorted_index = NULL;
    signature_count = 0;
}

/* Full detection with metadata */
bool signature_detect_full(const uint8_t *data, size_t len,
                           bool validate_trailer,
                           signature_result_t *result) {
    if (!data || len < 2 || !result) return false;

    /* Initialize result */
    memset(result, 0, sizeof(*result));

    /* Check special formats first (need deeper inspection) */
    if (detect_isobmff(data, len, result)) return true;
    if (detect_riff(data, len, result)) return true;
    if (detect_tar(data, len, result)) return true;

    /* Check signature table using sorted index (longest matches first) */
    for (int i = 0; i < signature_count; i++) {
        int idx = sorted_index ? sorted_index[i] : i;
        const file_signature_t *sig = &signatures[idx];

        if (len < (size_t)(sig->offset + sig->magic_len)) continue;

        if (memcmp(data + sig->offset, sig->magic, sig->magic_len) == 0) {
            result->description = sig->description;
            result->file_class = sig->file_class;
            result->is_binary = sig->is_binary;
            result->confidence = sig->magic_len;

            /* Validate trailer if requested and available */
            if (validate_trailer && sig->trailer && sig->trailer_len > 0) {
                if (len >= (size_t)sig->trailer_len) {
                    result->trailer_valid =
                        (memcmp(data + len - sig->trailer_len,
                               sig->trailer, sig->trailer_len) == 0);
                } else {
                    result->trailer_valid = false;
                }
            } else {
                result->trailer_valid = true; /* No trailer to check */
            }
            return true;
        }
    }

    return false;
}

/* Legacy API - returns description or NULL */
const char *signature_detect(const uint8_t *data, size_t len) {
    signature_result_t result;
    if (signature_detect_full(data, len, false, &result)) {
        return result.description;
    }
    return NULL;
}

/* Get human-readable class name */
const char *signature_class_name(file_class_t file_class) {
    switch (file_class) {
        case FILE_CLASS_IMAGE:      return "Image";
        case FILE_CLASS_VIDEO:      return "Video";
        case FILE_CLASS_AUDIO:      return "Audio";
        case FILE_CLASS_ARCHIVE:    return "Archive";
        case FILE_CLASS_DOCUMENT:   return "Document";
        case FILE_CLASS_FONT:       return "Font";
        case FILE_CLASS_EXECUTABLE: return "Executable";
        case FILE_CLASS_DATABASE:   return "Database";
        case FILE_CLASS_CONTAINER:  return "Container";
        default:                    return "Unknown";
    }
}

/* Check if content is binary based on description */
bool signature_is_binary(const char *description) {
    if (!description) return false;

    /* Search signature table */
    for (int i = 0; signatures[i].magic != NULL; i++) {
        if (strcmp(signatures[i].description, description) == 0) {
            return signatures[i].is_binary;
        }
    }

    /* Special detections (ISOBMFF, RIFF, TAR) are all binary */
    return true;
}

/* Check if content is local file I/O (not HTTP traffic) */
bool signature_is_local_file(const char *description) {
    if (!description) return false;

    /* These are clearly local file reads, not HTTP traffic */
    return (strcmp(description, "ELF binary") == 0 ||
            strcmp(description, "Mach-O binary") == 0 ||
            strcmp(description, "SQLite database") == 0 ||
            strcmp(description, "Java class") == 0);
}
