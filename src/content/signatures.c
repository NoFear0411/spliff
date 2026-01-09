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

/* Magic byte signatures */
static const uint8_t SIG_JPEG[] = {0xFF, 0xD8, 0xFF};
static const uint8_t SIG_PNG[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
static const uint8_t SIG_GIF87[] = {'G', 'I', 'F', '8', '7', 'a'};
static const uint8_t SIG_GIF89[] = {'G', 'I', 'F', '8', '9', 'a'};
static const uint8_t SIG_WEBP[] = {'R', 'I', 'F', 'F'};
static const uint8_t SIG_BMP[] = {'B', 'M'};
static const uint8_t SIG_ICO[] = {0x00, 0x00, 0x01, 0x00};
static const uint8_t SIG_PDF[] = {'%', 'P', 'D', 'F', '-'};
static const uint8_t SIG_ZIP[] = {'P', 'K', 0x03, 0x04};
static const uint8_t SIG_GZIP[] = {0x1F, 0x8B, 0x08};
static const uint8_t SIG_ZSTD[] = {0x28, 0xB5, 0x2F, 0xFD};
static const uint8_t SIG_MP3_ID3[] = {'I', 'D', '3'};
static const uint8_t SIG_MP3_SYNC[] = {0xFF, 0xFB};
static const uint8_t SIG_MP3_SYNC2[] = {0xFF, 0xFA};
static const uint8_t SIG_OGG[] = {'O', 'g', 'g', 'S'};
static const uint8_t SIG_FLAC[] = {'f', 'L', 'a', 'C'};
static const uint8_t SIG_WOFF[] = {'w', 'O', 'F', 'F'};
static const uint8_t SIG_WOFF2[] = {'w', 'O', 'F', '2'};
static const uint8_t SIG_TTF[] = {0x00, 0x01, 0x00, 0x00};
static const uint8_t SIG_OTF[] = {'O', 'T', 'T', 'O'};
static const uint8_t SIG_WASM[] = {0x00, 'a', 's', 'm'};
static const uint8_t SIG_ELF[] = {0x7F, 'E', 'L', 'F'};
static const uint8_t SIG_MACH_O_32[] = {0xFE, 0xED, 0xFA, 0xCE};
static const uint8_t SIG_MACH_O_64[] = {0xFE, 0xED, 0xFA, 0xCF};
static const uint8_t SIG_CLASS[] = {0xCA, 0xFE, 0xBA, 0xBE};
static const uint8_t SIG_7Z[] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
static const uint8_t SIG_RAR[] = {'R', 'a', 'r', '!', 0x1A, 0x07};
static const uint8_t SIG_SQLITE[] = {'S', 'Q', 'L', 'i', 't', 'e', ' ', 'f', 'o', 'r', 'm', 'a', 't'};
static const uint8_t SIG_WEBM[] = {0x1A, 0x45, 0xDF, 0xA3};
static const uint8_t SIG_JFIF[] = {0xFF, 0xD8, 0xFF, 0xE0};
static const uint8_t SIG_EXIF[] = {0xFF, 0xD8, 0xFF, 0xE1};

/* Signature table - checked in order, first match wins */
static const file_signature_t signatures[] = {
    /* Images (most common first) */
    {SIG_JPEG, 3, 0, "JPEG image", true},
    {SIG_JFIF, 4, 0, "JPEG image", true},
    {SIG_EXIF, 4, 0, "JPEG image", true},
    {SIG_PNG, 8, 0, "PNG image", true},
    {SIG_GIF89, 6, 0, "GIF image", true},
    {SIG_GIF87, 6, 0, "GIF image", true},
    {SIG_BMP, 2, 0, "BMP image", true},
    {SIG_ICO, 4, 0, "Icon", true},
    {SIG_WEBM, 4, 0, "WebM video", true},

    /* Documents */
    {SIG_PDF, 5, 0, "PDF document", true},

    /* Archives */
    {SIG_ZIP, 4, 0, "ZIP archive", true},
    {SIG_GZIP, 3, 0, "gzip compressed", true},
    {SIG_ZSTD, 4, 0, "zstd compressed", true},
    {SIG_7Z, 6, 0, "7-Zip archive", true},
    {SIG_RAR, 6, 0, "RAR archive", true},

    /* Audio */
    {SIG_MP3_ID3, 3, 0, "MP3 audio", true},
    {SIG_MP3_SYNC, 2, 0, "MP3 audio", true},
    {SIG_MP3_SYNC2, 2, 0, "MP3 audio", true},
    {SIG_OGG, 4, 0, "OGG audio", true},
    {SIG_FLAC, 4, 0, "FLAC audio", true},

    /* Fonts */
    {SIG_WOFF2, 4, 0, "WOFF2 font", true},
    {SIG_WOFF, 4, 0, "WOFF font", true},
    {SIG_OTF, 4, 0, "OpenType font", true},
    {SIG_TTF, 4, 0, "TrueType font", true},

    /* Executables/Binary */
    {SIG_WASM, 4, 0, "WebAssembly", true},
    {SIG_ELF, 4, 0, "ELF binary", true},
    {SIG_MACH_O_64, 4, 0, "Mach-O binary", true},
    {SIG_MACH_O_32, 4, 0, "Mach-O binary", true},
    {SIG_CLASS, 4, 0, "Java class", true},

    /* Database */
    {SIG_SQLITE, 13, 0, "SQLite database", true},

    /* RIFF container (WEBP, WAV, AVI) - check content at offset 8 */
    {SIG_WEBP, 4, 0, "RIFF container", true},

    /* Terminator */
    {NULL, 0, 0, NULL, false}
};

/* Check for MP4/MOV/AVIF/HEIC (ISO Base Media File Format) */
static const char *detect_isobmff(const uint8_t *data, int len) {
    if (len < 12) return NULL;

    /* Check for 'ftyp' at offset 4 */
    if (data[4] == 'f' && data[5] == 't' && data[6] == 'y' && data[7] == 'p') {
        /* Check brand at offset 8 */
        if (len >= 12) {
            if (memcmp(data + 8, "avif", 4) == 0) return "AVIF image";
            if (memcmp(data + 8, "heic", 4) == 0) return "HEIC image";
            if (memcmp(data + 8, "mif1", 4) == 0) return "HEIF image";
            if (memcmp(data + 8, "mp41", 4) == 0) return "MP4 video";
            if (memcmp(data + 8, "mp42", 4) == 0) return "MP4 video";
            if (memcmp(data + 8, "isom", 4) == 0) return "MP4 video";
            if (memcmp(data + 8, "M4V ", 4) == 0) return "M4V video";
            if (memcmp(data + 8, "M4A ", 4) == 0) return "M4A audio";
            if (memcmp(data + 8, "qt  ", 4) == 0) return "QuickTime video";
        }
        return "ISO media file";
    }
    return NULL;
}

/* Check RIFF container type (WEBP, WAV, AVI) */
static const char *detect_riff(const uint8_t *data, int len) {
    if (len < 12) return NULL;
    if (data[0] != 'R' || data[1] != 'I' || data[2] != 'F' || data[3] != 'F') return NULL;

    if (memcmp(data + 8, "WEBP", 4) == 0) return "WebP image";
    if (memcmp(data + 8, "WAVE", 4) == 0) return "WAV audio";
    if (memcmp(data + 8, "AVI ", 4) == 0) return "AVI video";

    return "RIFF container";
}

/* Initialize signature detection */
int signatures_init(void) {
    /* No initialization needed for now */
    return 0;
}

/* Cleanup */
void signatures_cleanup(void) {
    /* No cleanup needed for now */
}

/* Detect file type from data - returns description or NULL */
const char *signature_detect(const uint8_t *data, size_t len) {
    if (len < 2) return NULL;

    /* Check special formats first (ISO BMFF and RIFF need deeper inspection) */
    const char *isobmff = detect_isobmff(data, len);
    if (isobmff) return isobmff;

    const char *riff = detect_riff(data, len);
    if (riff) return riff;

    /* Check signature table */
    for (int i = 0; signatures[i].magic != NULL; i++) {
        const file_signature_t *sig = &signatures[i];

        if ((int)len < sig->offset + sig->magic_len) continue;

        if (memcmp(data + sig->offset, sig->magic, sig->magic_len) == 0) {
            return sig->description;
        }
    }

    /* Check for TAR at offset 257 */
    if (len > 262 && memcmp(data + 257, "ustar", 5) == 0) {
        return "TAR archive";
    }

    return NULL;
}

/* Check if content is binary based on description */
bool signature_is_binary(const char *description) {
    if (description == NULL) return false;

    /* Check signature table to see if marked as binary */
    for (int i = 0; signatures[i].magic != NULL; i++) {
        if (strcmp(signatures[i].description, description) == 0) {
            return signatures[i].is_binary;
        }
    }

    /* Special detections are all binary */
    return true;
}
